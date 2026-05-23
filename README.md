
<div align="center">

# 🛡️ DCAVP

**Deterministic Code Analysis & Verification Platform**

Security analysis for AI-generated Python code.
Find dangerous patterns before they reach production.
> **DCAVP v0.1.0 is an early-stage deterministic security pattern extraction kernel.**
> It detects 11 high-confidence Python security patterns. It does NOT perform dataflow
> analysis or taint tracking. It is NOT a replacement for Bandit/Snyk — it is a
> complement that adds determinism, self-verification, and honesty guarantees.
> **Every result is reproducible. Every failure is admitted.**

## What is ANALYSIS VACUUM?

When DCAVP analyzes code that contains no registered dangerous patterns, it does NOT
give a false "PASS". Instead, it reports **ANALYSIS VACUUM** — meaning:

- ✅ "I found nothing dangerous"
- ⚠️ "But I also didn't analyze everything"
- 🔒 "Results should not be trusted as comprehensive"

This is honesty, not failure. No other security tool does this.
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Self-Verified](https://img.shields.io/badge/self--verification-6%2F6-brightgreen.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)

</div>

---

## What it does

Scans your Python code for security issues that AI generators (ChatGPT, Claude, Copilot, Cursor) commonly introduce — and explains them in plain English.

```bash
pip install dcavp
dcavp analyze ./my_project
Quick Start
bash
# Basic analysis (human-readable output)
dcavp analyze ./my_project

# Generate HTML report
dcavp analyze ./my_project --format html

# Generate JSON report for CI/CD
dcavp analyze ./my_project --format json

# Strict analysis (military-grade)
dcavp analyze ./my_project --tier RED

# Run self-verification (the platform verifies itself)
dcavp verify
Analysis Tiers
Four tiers for every stage of the development lifecycle:

Tier	Speed	Strictness	Use Case
🟢 GREEN	Fastest	Basic warnings	Education, quick checks
🔵 BLUE	Fast	Standard	CI/CD default, teams
🟡 YELLOW	Moderate	Industrial	Regulated software, supply chain
🔴 RED	Thorough	Military-Grade	Aerospace, defense, safety-critical
Each tier progressively unlocks deeper analysis. Choose the right level for your risk profile.

What it catches
Pattern	Risk	CWE
eval() / exec()	Remote code execution	CWE-94
subprocess with shell=True	OS command injection	CWE-78
open() without context manager	Resource leak, path traversal	CWE-22
Mutable global state	Data corruption, non-determinism	CWE-1108
__import__ dynamic imports	Hidden code execution	CWE-94
Every finding includes:

Exact file location (file:line:column)

Detected state (e.g., external_source_arg)

Plain-English explanation

Recommended fix

CWE reference

HTML Reports
Generate standalone, shareable security reports:

bash
dcavp analyze ./my_project --tier RED --format html
Each HTML report includes:

Trust Score with verification badges

Executive Summary (files, nodes, findings, scan time)

Detailed Findings with fix recommendations and CWE references

Tier Comparison showing what deeper analysis unlocks

Enterprise Features Preview with upgrade path

Cryptographic Verification Certificate

Reports are self-contained HTML files — no server, no dependencies. Share them with auditors, clients, or your team.

Trust Score
Every analysis produces a Trust Score (0–1000):

text
Trust: 1000/1000 ████████████████████ 100%
✅ Analysis Integrity    ✅ Catalog Verified
✅ Triple Replay Match   ✅ Artifact Signed
The Trust Score reflects the honesty of the analysis itself — not your code quality. A score of 1000 means the analysis is cryptographically verifiable and reproducible.

Proof Certificate
Every scan produces a cryptographic artifact:

text
Artifact Hash: sha256:3a14975bbfe73f7d0cacad7afa0b9bd12a5a11986...
This hash uniquely identifies this exact analysis. Given the same source code, catalog version, and execution seed, anyone can reproduce the identical artifact. This is your audit trail — shareable without revealing source code.

Self-Verification
DCAVP verifies itself before it verifies you:

bash
dcavp verify
The platform runs 6 governance checks on its own source code under RED tier:

Check	Purpose
CHECK-SV-001	Catalog Merkle Integrity
CHECK-SV-002	Policy Source References
CHECK-SV-003	Dependency Whitelist
CHECK-SV-004	RED Tier Self-Analysis
CHECK-SV-005	Triple Replay Validation
CHECK-SV-006	Governance Gates
6/6 must pass. A platform that cannot verify itself cannot verify other software.

GitHub Actions
yaml
name: DCAVP Security Scan
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
      - run: dcavp analyze . --tier RED --format html
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: dcavp-report.html
How it's different
Feature	DCAVP	Snyk	SonarQube	Bandit
Deterministic results	✅ Always	❌ No	❌ No	✅ Yes
Plain-English findings	✅ Yes	Partial	Partial	❌ No
Self-verification	✅ 6/6 Gates	❌ No	❌ No	❌ No
Proof Certificate	✅ Yes	❌ No	❌ No	❌ No
AI code patterns	✅ Yes	Partial	❌ No	❌ No
Cross-platform	✅ Win/Lin/Mac	✅ Yes	✅ Yes	✅ Yes
Zero dependencies	✅ Stdlib only	❌ API	❌ Server	✅ Yes
Tiered governance	✅ 4 Tiers	❌ No	❌ No	❌ No
HTML reports	✅ Standalone	✅ Yes	✅ Yes	❌ No
Install
bash
pip install dcavp
Requires Python 3.12+. No external dependencies. The entire platform runs on Python standard library.

Commands
bash
dcavp analyze <path>     # Run security analysis
dcavp verify             # Run self-verification
dcavp catalog            # Show catalog information
Options for analyze:

Flag	Values	Default	Description
--tier	GREEN, BLUE, YELLOW, RED	BLUE	Analysis depth
--format	human, json, html	human	Output format
--output-bundle	PATH	—	Save replay bundle
--seed	hex string	0xdeadbeef0000	Execution seed for replay
--quiet	—	—	Suppress progress output
Current limitations
Python only — Java, JavaScript, Go support planned

Static analysis — no runtime monitoring

v0.1.0 — supply chain analysis and AI hallucination detection in development

Architecture
DCAVP is built on three architectural pillars:

Determinism — Same input produces identical output, always. Every analysis is reproducible.

Zero Trust — The platform verifies itself (6/6 governance gates) before analyzing your code.

Tiered Governance — GREEN warns, BLUE blocks, YELLOW investigates, RED eliminates.

No cloud. No telemetry. No API calls. Everything runs locally.

Contributing
See CONTRIBUTING.md. All contributions require tests and must pass dcavp verify under RED tier.

License
Apache 2.0 — see LICENSE.

<div align="center">
Built for the AI-generated code era.

Website · Docs · Upgrade

</div> ```