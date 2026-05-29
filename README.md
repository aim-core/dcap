# 🏛️ DCAP

**Deterministic Code Analysis Platform**

*The only security tool that admits when it fails.*

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Self-Verified 6/6](https://img.shields.io/badge/self--verification-6%2F6-brightgreen.svg)](SELF_VERIFICATION.md)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

---

## What is DCAP?

DCAP is a **deterministic forensic audit platform** for AI-generated Python code.

It does not guess. It does not use AI to analyze AI. It uses **deterministic AST pattern matching** with cryptographic proof that every result is reproducible.

- **Zero false positives** — exact pattern matching only
- **Self-verifying** — 6/6 governance gates before analyzing your code
- **Honest** — admits when analysis is incomplete (Pattern Vacuum)
- **Local-first** — your code never leaves your machine
- **Cryptographically verifiable** — every report has a Proof Signature and Replay Fingerprint

---

## Quick Start

```bash
pip install dcap

# Basic analysis (Community Edition)
dcap analyze ./my_project --tier GREEN

# Self-verification — does the platform trust itself?
dcap verify
Output:

text
============================================================
  DCAP RED TIER - FORENSIC AUDIT REPORT
============================================================
  Report ID      : DCAP-RED-20260529-77C967
  Detection      : COMPLETE - 8 findings in 92 files
  Tier Policy    : BLOCKED - Zero-trust forensic policy.
  Security Score  : 20/100 - F

  EXECUTIVE VERDICT
  CRITICAL: Multiple attack chains detected.
  Deployment prohibited without full remediation.

  F-00008 CRITICAL eval [TAINTED]
     Root Cause: User-controlled input reaches this execution sink

  CORRELATION ALERT: Execution Chain Detected
     5 constructs form an attack chain: os.system -> subprocess -> eval -> exec -> eval

  DETERMINISTIC EVIDENCE
  Proof Sig      : 0eedf0fa64baa5d5
  Replay FP      : b21ff115e828
  This analysis is cryptographically verifiable.
  Same code + Same catalog + Same seed = Same result.

  FINAL DECISION: RESTRICTED under RED tier policy
Commands
bash
# Basic analysis
dcap analyze ./my_project --tier GREEN

# Professional analysis with JSON export
dcap analyze ./my_project --tier BLUE --format json

# Enterprise governance with HTML report
dcap analyze ./my_project --tier YELLOW --format html

# Forensic audit
dcap analyze ./my_project --tier RED

# Self-verification
dcap verify

# Show catalog information
dcap catalog

# Activate Pro license
dcap activate --key <license_key>

# Upgrade information
dcap upgrade
Command	Description
dcap analyze <path>	Analyze a project
dcap verify	Self-verification (6/6 governance gates)
dcap catalog	Show detection catalog
dcap upgrade	Upgrade to Pro information
dcap activate --key <key>	Activate Pro license
Flag	Values	Description
--tier	GREEN, BLUE, YELLOW, RED	Analysis depth (default: BLUE)
--format	human, json, html	Output format (default: human)
--output	PATH	Save replay bundle
--quiet	—	Suppress progress output
Analysis Tiers
Tier	Audience	Policy	Score	Reports
🟢 GREEN	Students, beginners	PERMITTED — Educational only. NOT a safety rating.	—	Terminal
🔵 BLUE	Professional developers	PERMITTED — Standard CI/CD	—	Terminal + JSON
🟡 YELLOW	Enterprises, DevSecOps	RESTRICTED — Enterprise governance	✅	Terminal + JSON + HTML
🔴 RED	Defense, aerospace, medical	BLOCKED — Zero-trust forensic	✅	Terminal + JSON + HTML + Signed
Community vs Pro
Feature	Community	Pro
Patterns	6 basic	17 advanced
AI Hallucination Detection	❌	✅
Security Theater Detection	❌	✅
JWT Algorithm None	❌	✅
Crypto ECB Mode	❌	✅
Template Injection (SSTI)	❌	✅
TAINTED Input Detection	❌	✅
Correlation Intelligence	❌	✅
Root Cause Analysis	❌	✅
Proof Signature	✅	✅
Replay Fingerprint	✅	✅
Tiers	GREEN only	All 4 tiers
License	Apache 2.0	Commercial
Upgrade to Pro →

What DCAP Detects
Pattern	Severity	CWE	Community	Pro
eval()	CRITICAL	CWE-94	✅	✅
exec()	CRITICAL	CWE-94	✅	✅
subprocess with shell=True	CRITICAL	CWE-78	✅	✅
pickle.loads()	CRITICAL	CWE-502	✅	✅
os.system()	CRITICAL	CWE-78	❌	✅
SQL injection	CRITICAL	CWE-89	❌	✅
open() with user path	CRITICAL	CWE-22	✅	✅
yaml.load()	ERROR	CWE-502	❌	✅
requests.get() SSRF	ERROR	CWE-918	❌	✅
os.remove()	ERROR	CWE-22	❌	✅
random for security tokens	WARNING	CWE-338	✅	✅
debug=True in Flask	WARNING	CWE-489	❌	✅
AI Hallucinated Package	CRITICAL	CWE-1104	❌	✅
Security Theater	ERROR	CWE-916	❌	✅
JWT Algorithm None	ERROR	CWE-347	❌	✅
Crypto ECB Mode	ERROR	CWE-327	❌	✅
Template Injection	CRITICAL	CWE-94	❌	✅
Why DCAP?
Capability	DCAP	Bandit	Snyk	SonarQube
Deterministic results	✅ Always	✅ Yes	❌ No	❌ No
Self-verification (6/6)	✅	❌	❌	❌
Admits analysis failure	✅ Pattern Vacuum	❌	❌	❌
Proof Certificate	✅ SHA-256	❌	❌	❌
Replay Fingerprint	✅	❌	❌	❌
Root Cause Intelligence	✅	❌	❌	❌
Correlation Analysis	✅	❌	❌	❌
TAINTED Input Detection	✅	❌	❌	❌
Zero external dependencies	✅	✅	❌	❌
Local-first (no cloud)	✅	✅	❌	❌
AI-specific patterns	✅	❌	❌	❌
Self-Verification
DCAP verifies itself before it verifies you. Every commit must pass 6 governance checks under RED tier.

bash
$ dcap verify

6/6 checks passed. RELEASE ELIGIBLE.
Check	Purpose
CHECK-SV-001	Catalog Merkle Integrity
CHECK-SV-002	Policy Source References
CHECK-SV-003	Dependency Whitelist
CHECK-SV-004	RED Tier Self-Analysis
CHECK-SV-005	Triple Replay Validation
CHECK-SV-006	Governance Gates
A platform that cannot verify itself cannot verify other software.

Deterministic Evidence
Every report includes cryptographic proof:

text
Proof Sig      : 0eedf0fa64baa5d5    (SHA-256 of all findings)
Replay FP      : b21ff115e828        (Replay fingerprint)
Catalog Ver    : 2026.05.12
Engine Ver     : dcavp-kernel/0.1.0
Same code + Same catalog + Same seed = Same result. Always.

Current Scope
Implemented:

Deterministic AST pattern matching

Correlation-aware scoring

Governance policy enforcement (4 tiers)

Replay-safe evaluation

Cryptographic proof signatures

TAINTED input detection

Root cause intelligence

AI-specific pattern detection (Pro)

Not yet implemented:

Taint propagation engine

Symbolic execution

Interprocedural reasoning

Exploit path simulation

Philosophy
DCAP does not attempt to simulate human intuition.
It provides reproducible evidence, deterministic reasoning,
and operationally explainable security analysis
for the AI-generated software era.

Determinism — Same input = Same output. Always.

Honesty — We admit what we cannot see.

Self-Governance — We verify ourselves before we verify you.

License
Community Edition: Apache 2.0

Pro Edition: Commercial license — https://dcap.dev/pro

Enterprise: Custom licensing for on-prem, air-gapped, and government deployments.

<div align="center"> Built for the AI-generated code era. </div> ```