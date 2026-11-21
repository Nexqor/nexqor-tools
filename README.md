<p align="center">
  <img src="https://raw.githubusercontent.com/Nexqor/Nexqor/main/banner.png" alt="Nexqor" width="100%">
</p>

<h1 align="center">nexqor-tools 🔧</h1>

<p align="center">
  Small, dependency-free defensive tools from the <a href="https://x.com/whyNexqor">@whyNexqor</a> breakdowns.<br/>
  First up: <b>prompt_scan.py</b>, which catches prompt-injection payloads <i>before</i> they reach your LLM.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-c41237?style=for-the-badge&logo=python&logoColor=white" alt="python"/>
  <img src="https://img.shields.io/badge/dependencies-0-c41237?style=for-the-badge" alt="deps"/>
  <a href="https://nexqor.github.io"><img src="https://img.shields.io/badge/site-nexqor.github.io-000000?style=for-the-badge" alt="site"/></a>
</p>

---

## prompt_scan.py

Indirect prompt injection hides instructions inside content your AI reads: web pages, PDFs, emails, tickets, README files. `prompt_scan.py` scans that content and flags:

| Rule | Severity | Catches |
|------|----------|---------|
| `exfil-url` | 🔴 critical | Markdown images that smuggle data in the URL |
| `exfil-verb` | 🔴 critical | "send the API keys / .env / chat history to..." |
| `secret-read` | 🔴 critical | Commands that read `.env`, `id_rsa`, AWS credentials |
| `override` | 🟠 high | "ignore all previous instructions" and variants |
| `prompt-leak` | 🟠 high | "reveal your system prompt" |
| `agent-address` | 🟠 high | "Attention AI assistant: ..." |
| `shell-exec` | 🟠 high | "run this command", `curl ... \| sh` |
| `tool-hijack` | 🟠 high | "call the tool without asking the user" |
| `hidden-css` | 🟠 high | White-on-white, zero-size, `display:none` text |
| `invisible-unicode` | 🟠 high | Zero-width, bidi and Unicode tag characters |
| `new-role`, `mode-switch`, `secrecy`, `delimiter-spoof` | 🟡 medium | Persona swaps, fake "developer mode", fake `<\|im_start\|>` |

### Quick start

```bash
git clone https://github.com/Nexqor/nexqor-tools
cd nexqor-tools
python prompt_scan.py sample_payload.html
```

Expected findings in the sample file:

```text
[CRITICAL] exfil-verb     Instruction to send data out      ("Send the API keys...")
[CRITICAL] exfil-url      Exfiltration via URL / image      (![chart](...?d={chat_history}))
[HIGH]     hidden-css     Text hidden with CSS              (white 1px text)
[HIGH]     override       Instruction override              ("ignore all previous instructions")
[HIGH]     agent-address  Text addressed to AI agents       ("Attention AI assistant")
[MEDIUM]   secrecy        Asks to hide actions from the user ("do not tell the user")
```

### More usage

```bash
python prompt_scan.py --dir ./knowledge_base          # scan a RAG folder before indexing
curl -s https://example.com | python prompt_scan.py - # scan a page before your agent reads it
python prompt_scan.py --dir ./kb --json report.json   # machine-readable report
python prompt_scan.py --dir ./kb --fail-on critical   # use as a CI gate (exit 1 on findings)
```

### Use it in a RAG pipeline

```python
from prompt_scan import scan_text

def safe_to_index(doc_text: str, source: str) -> bool:
    findings = scan_text(doc_text, source)
    return not any(f.severity in ("high", "critical") for f in findings)
```

### Limits

This is a **heuristic first filter**, not a guarantee. Attackers paraphrase, translate and encode. Combine it with:
- least-privilege agents and human approval for outbound actions ([playbook 05](https://github.com/Nexqor/ai-attack-playbook/blob/main/05-excessive-agency.md)),
- a model-based classifier such as LLM Guard or Llama Guard ([awesome-ai-security](https://github.com/Nexqor/awesome-ai-security)).

## Related

- [ai-attack-playbook](https://github.com/Nexqor/ai-attack-playbook): how each AI attack works and how to stop it
- [awesome-ai-security](https://github.com/Nexqor/awesome-ai-security): tools, papers, 2026 incident timeline

---

MIT License · Educational and defensive use.
