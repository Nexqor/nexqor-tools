# Changelog

All notable changes to this project are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-21

### Added
- `prompt_scan.py` with 15 rules: `exfil-url`, `exfil-verb`, `secret-read`, `override`, `prompt-leak`, `agent-address`, `shell-exec`, `tool-hijack`, `hidden-css`, `invisible-unicode`, `new-role`, `mode-switch`, `secrecy`, `delimiter-spoof`, plus `html-comment`.
- Directory scanning, stdin input, `--json` report and `--fail-on` CI gate.
- `scan_text()` API for RAG ingestion pipelines.
- Harmless `sample_payload.html` for testing.
- Browser version of the scanner at https://nexqor.github.io/tools.html
