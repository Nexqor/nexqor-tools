#!/usr/bin/env python3
"""
prompt_scan.py - flag likely prompt-injection payloads in text, files or web pages
before they reach an LLM (RAG ingestion, browsing agents, email assistants).

Heuristic, dependency-free, defensive. It will not catch everything; use it as a
cheap first filter in front of a real classifier and least-privilege agents.

Usage:
  python prompt_scan.py file1.md page.html ...
  python prompt_scan.py --dir ./docs
  cat email.txt | python prompt_scan.py -
  python prompt_scan.py --json report.json --dir ./kb

Exit code: 0 = clean, 1 = findings at or above --fail-on severity.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, asdict

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# (rule_id, severity, description, regex)
RULES: list[tuple[str, str, str, str]] = [
    ("override", "high", "Instruction override",
     r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|messages?|context)\b"),
    ("new-role", "medium", "Role / persona reassignment",
     r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as)\b"),
    ("mode-switch", "medium", "Fake privileged mode",
     r"\b(developer|debug|admin|god|jailbreak|DAN|unrestricted)\s+mode\b"),
    ("prompt-leak", "high", "System prompt extraction",
     r"\b(reveal|print|show|repeat|output|leak)\b[^.\n]{0,40}\b(system prompt|hidden instructions|initial instructions|your instructions)\b"),
    ("agent-address", "high", "Text addressed to AI agents",
     r"\b(attention|note|message|instructions?)\s+((to|for)\s+)?(the\s+)?(ai|llm|assistant|agent|language model|chatbot)s?\b"),
    ("exfil-url", "critical", "Exfiltration via URL / image",
     r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=\s*[{<$]"),
    ("exfil-verb", "critical", "Instruction to send data out",
     r"\b(send|post|upload|forward|exfiltrate|transmit|email)\b[^.\n]{0,60}\b(api[_ -]?keys?|tokens?|passwords?|secrets?|credentials|\.env|ssh keys?|cookies|conversation|chat history)\b"),
    ("secret-read", "critical", "Instruction to read secrets",
     r"(cat|type|read|open|print)\s+[^\n]{0,20}(\.env\b|id_rsa|\.aws/credentials|\.ssh/|/etc/passwd|\.git-credentials)"),
    ("shell-exec", "high", "Instruction to run shell commands",
     r"\b(run|execute|eval)\b[^.\n]{0,30}\b(command|shell|bash|powershell|curl|wget)\b|\b(curl|wget)\s+[^\n]*\|\s*(ba)?sh\b"),
    ("tool-hijack", "high", "Tool / function call hijack",
     r"\b(call|invoke|use)\s+(the\s+)?(tool|function|plugin)\b[^.\n]{0,40}\b(without|don't|do not)\b[^.\n]{0,20}\b(ask|confirm|tell|notify)\b"),
    ("secrecy", "medium", "Asks to hide actions from the user",
     r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show)\s+(this\s+)?(to\s+)?(the\s+)?user\b"),
    ("delimiter-spoof", "medium", "Fake chat delimiters",
     r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<<SYS>>|^\s*(system|assistant)\s*:)"),
]

INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿",  # zero-width
    "‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩",  # bidi
}

HIDDEN_HTML = [
    ("hidden-css", "high", "Text hidden with CSS",
     r"style\s*=\s*\"[^\"]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(#fff(fff)?|white)\b)[^\"]*\"[^>]*>[^<]{12,}"),
    ("html-comment", "low", "Long HTML comment (check content)", r"<!--[\s\S]{80,}?-->"),
]


@dataclass
class Finding:
    source: str
    line: int
    rule: str
    severity: str
    description: str
    excerpt: str


def _excerpt(text: str, start: int, end: int, width: int = 60) -> str:
    s = max(0, start - width // 2)
    e = min(len(text), end + width // 2)
    return " ".join(text[s:e].split())[:160]


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text(text: str, source: str = "<stdin>") -> list[Finding]:
    findings: list[Finding] = []

    # 1) invisible / bidi characters (used to hide payloads)
    for i, ch in enumerate(text):
        if ch in INVISIBLE or unicodedata.category(ch) == "Co" or 0xE0000 <= ord(ch) <= 0xE007F:
            findings.append(Finding(source, _line_of(text, i), "invisible-unicode", "high",
                                    f"Invisible/tag character U+{ord(ch):04X}", _excerpt(text, i, i + 1)))
            break  # one finding per file is enough

    # 2) hidden HTML tricks (raw markup)
    for rid, sev, desc, rx in HIDDEN_HTML:
        for m in re.finditer(rx, text, re.IGNORECASE):
            findings.append(Finding(source, _line_of(text, m.start()), rid, sev, desc,
                                    _excerpt(text, m.start(), m.end())))

    # 3) semantic rules on normalized text
    norm = unicodedata.normalize("NFKC", html.unescape(text))
    norm = "".join(c for c in norm if c not in INVISIBLE)
    for rid, sev, desc, rx in RULES:
        for m in re.finditer(rx, norm, re.IGNORECASE | re.MULTILINE):
            findings.append(Finding(source, _line_of(norm, m.start()), rid, sev, desc,
                                    _excerpt(norm, m.start(), m.end())))
    return findings


def iter_paths(paths: list[str], directory: str | None):
    exts = {".txt", ".md", ".html", ".htm", ".json", ".csv", ".xml", ".eml", ".yaml", ".yml", ".py", ".js"}
    for p in paths:
        yield p
    if directory:
        for root, _, files in os.walk(directory):
            for f in files:
                if os.path.splitext(f)[1].lower() in exts:
                    yield os.path.join(root, f)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan content for prompt-injection payloads.")
    ap.add_argument("paths", nargs="*", help="files to scan, or - for stdin")
    ap.add_argument("--dir", help="scan a directory recursively")
    ap.add_argument("--json", metavar="FILE", help="write findings as JSON")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY, help="exit 1 at or above this severity")
    args = ap.parse_args(argv)

    if not args.paths and not args.dir:
        ap.print_help()
        return 0

    findings: list[Finding] = []
    for p in iter_paths(args.paths, args.dir):
        try:
            text = sys.stdin.read() if p == "-" else open(p, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"[!] cannot read {p}: {e}", file=sys.stderr)
            continue
        findings += scan_text(text, "<stdin>" if p == "-" else p)

    colors = {"low": "\033[37m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;31m"}
    tty = sys.stdout.isatty()
    for f in sorted(findings, key=lambda f: -SEVERITY[f.severity]):
        tag = f"[{f.severity.upper()}]"
        if tty:
            tag = colors[f.severity] + tag + "\033[0m"
        print(f"{tag} {f.source}:{f.line}  {f.rule}  {f.description}\n      > {f.excerpt}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2, ensure_ascii=False)

    worst = max((SEVERITY[f.severity] for f in findings), default=0)
    print(f"\n{len(findings)} finding(s).", "Clean." if not findings else "")
    return 1 if worst >= SEVERITY[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
