<div align="center">

# DCAP

**Security analysis for AI-generated Python code.**

Find dangerous patterns before they reach production.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-491%20passing-brightgreen.svg)](#)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

</div>

---

## What it does

Scans your Python code for security issues that AI generators (ChatGPT, Claude, Copilot, Cursor) commonly introduce — and explains them in plain English.

```bash
pip install dcap
dcap check ./my_project
```

**Output:**

```
────────────────────────────────────────────────────
  DCAP Security Scan
────────────────────────────────────────────────────
  Score     35 / 100   🔴  DANGER
  Grade     F
  Files     3 analyzed

  Do not ship — 3 critical issues found that attackers can exploit.

────────────────────────────────────────────────────
  Issues Found
────────────────────────────────────────────────────

  💀  CRITICAL   payment.py line 6
  External data flows directly into code execution
  Network/user data reaches eval() — this is a critical attack surface.
  Fix: Remove eval(). Parse data with json.loads() or a schema validator.

  💀  CRITICAL   payment.py line 9
  Shell commands built from external input
  A semicolon or pipe in user input runs arbitrary system commands.
  Fix: Remove shell=True. Use: subprocess.run(['cmd', arg])

  💀  CRITICAL   auth.py line 18
  Weak random numbers used for security tokens
  Python's random is predictable. An attacker can guess your tokens.
  Fix: Replace random.hex() with secrets.token_hex(32)
────────────────────────────────────────────────────
  Most Important Fix Right Now
  Remove eval(). Parse data with json.loads() or a schema validator.
────────────────────────────────────────────────────
```

---

## Install

```bash
pip install dcap
```

Requires Python 3.12+. No external dependencies.

---

## Usage

```bash
# Scan a project (human-readable output)
dcap check ./my_project

# Generate HTML report
dcavp check ./my_project --format html --output report.html

# CI mode: fail if critical issues exist
dcap check . --fail-on critical

# Stricter analysis
dcap check . --tier YELLOW

# Show dependency risks
dcap catalog
```

---

## GitHub Actions

```yaml
name: DCAP Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install dcavp
      - run: dcap check . --fail-on critical --format html --output report.html
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: report.html
```

---

## What it catches

| Pattern | Risk | Example |
|---|---|---|
| `eval()` / `exec()` with external input | Remote code execution | `eval(request.body)` |
| `pickle.loads()` from network | Attacker controls your server | `pickle.loads(socket.recv())` |
| `subprocess` with `shell=True` | OS command injection | `subprocess.run(cmd, shell=True)` |
| `random` for security tokens | Forgeable session tokens | `random.hex(32)` |
| User-controlled file paths | Directory traversal | `open(request.args['file'])` |
| Global state in request handlers | Data leaks between users | `global _session_store` |

---

## Analysis tiers

| Tier | Speed | Strictness | Use case |
|---|---|---|---|
| GREEN | Fastest | Basic | Quick check, education |
| BLUE | Fast | Standard | CI/CD default |
| YELLOW | Moderate | Strict | Regulated software |
| RED | Thorough | Maximum | Safety-critical systems |

---

## Trust Score

Every scan produces a score (0–100):

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | A | Ready to ship |
| 75–89 | B | Minor issues — review recommended |
| 60–74 | C | Warnings present — fix before production |
| 40–59 | D | Critical issues found |
| 0–39 | F | Do not ship |

---

## Proof Certificate

Every scan produces a cryptographic Proof Certificate — a verifiable record that you ran the analysis on a specific codebase, shareable with auditors without revealing source code.

```
certificate:b01709a9f8d5fe8d878de09ef23e87...
commitment: commitment:c71a6442418e03a7d571f...
trust_band: high · 91/100
```

---

## How it's different

| Feature | DCAP | Snyk | SonarQube |
|---|---|---|---|
| Deterministic results | ✅ Always | ❌ No | ❌ No |
| Plain-English findings | ✅ Yes | Partial | Partial |
| No external dependencies | ✅ Zero | ❌ API | ❌ Server |
| Proof Certificate | ✅ Yes | ❌ No | ❌ No |
| AI-generated code patterns | ✅ Yes | Partial | ❌ No |
| Self-verification | ✅ Yes | ❌ No | ❌ No |

---

## Current limitations

- **Python only** — Java, JavaScript, Go support planned
- **Static analysis** — no runtime monitoring
- **Local execution** — no cloud component required (and none exists yet)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require tests.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<div align="center">
Built for the AI-generated code era.
</div>
