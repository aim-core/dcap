# 🏛️ DCAP

**Deterministic Code Analysis Platform**

*The only security tool that admits when it fails.*

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Self-Verified 6/6](https://img.shields.io/badge/self--verification-6%2F6-brightgreen.svg)](SELF_VERIFICATION.md)

---

## What is DCAP?

DCAP is not a scanner. It is a **deterministic audit platform** for AI-generated Python code.

- **Zero false positives** — deterministic AST pattern matching only
- **Self-verifying** — 6/6 governance gates before analyzing your code
- **Honest** — admits when analysis is incomplete (Pattern Vacuum)
- **Local-first** — your code never leaves your machine
- **Cryptographically verifiable** — every report has a Proof Signature

---
## Usage

```bash
# Basic analysis (Community Edition)
dcap analyze ./my_project --tier GREEN

# Professional analysis
dcap analyze ./my_project --tier BLUE

# Enterprise governance
dcap analyze ./my_project --tier YELLOW --format html

# Forensic audit (RED tier)
dcap analyze ./my_project --tier RED --format json

# Self-verification
dcap verify

# Show catalog information
dcap catalog

# Activate Pro license
dcap activate --key <license_key>

# Upgrade to Pro
dcap upgrade
## Quick Start

```bash
pip install dcap
dcap analyze ./my_project --tier GREEN
dcap verify
The Four Tiers
Tier	Audience	Policy
🟢 GREEN	Beginners, students	Educational — warnings only
🔵 BLUE	Professional developers	Standard CI/CD
🟡 YELLOW	Companies, enterprises	Enterprise governance
🔴 RED	Defense, aerospace, medical	Zero-trust forensic
What DCAP Detects
Pattern	Severity	CWE
eval()	CRITICAL	CWE-94
exec()	CRITICAL	CWE-94
subprocess with shell=True	CRITICAL	CWE-78
pickle.loads()	CRITICAL	CWE-502
os.system()	CRITICAL	CWE-78
SQL injection	CRITICAL	CWE-89
open() with user path	CRITICAL	CWE-22
yaml.load()	ERROR	CWE-502
requests.get() SSRF	ERROR	CWE-918
os.remove()	ERROR	CWE-22
random for security tokens	WARNING	CWE-338
debug=True in Flask	WARNING	CWE-489
Pro Edition adds: AI Hallucinated Package, Security Theater, JWT Algorithm None, Crypto ECB Mode, Template Injection, and more.

Why DCAP?
Capability	DCAP	Bandit	Snyk	SonarQube
Deterministic results	✅	✅	❌	❌
Self-verification	✅ 6/6	❌	❌	❌
Admits analysis failure	✅	❌	❌	❌
Proof Certificate	✅	❌	❌	❌
Root Cause Intelligence	✅	❌	❌	❌
Correlation Analysis	✅	❌	❌	❌
Zero dependencies	✅	✅	❌	❌
Self-Verification
bash
$ dcap verify
6/6 checks passed. RELEASE ELIGIBLE.
DCAP verifies itself before it verifies you. Every commit must pass 6 governance checks under the strictest RED tier.

Deterministic Evidence
Every report includes:

text
Proof Sig      : 0eedf0fa64baa5d5
Replay FP      : b21ff115e828
Catalog Ver    : 2026.05.12
Same code + Same catalog + Same seed = Same result. Always.

Current Limitations
Python only (Java, JavaScript planned)

Pattern-based analysis — no dataflow engine yet

Community Edition: 6 patterns. Pro Edition: 17 patterns.

Philosophy
Determinism — Same input = Same output. Always.

Honesty — We admit what we cannot see.

Self-Governance — We verify ourselves before we verify you.

License
Apache 2.0 — see LICENSE.

Pro Edition: https://dcap.dev/pro

<div align="center"> Built for the AI-generated code era. </div> ```
