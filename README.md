
<div align="center">

# 🏛️ DCAVP

**Deterministic Code Analysis & Verification Platform**

*The only security tool that admits when it fails.*

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Self-Verified](https://img.shields.io/badge/self--verification-6%2F6-brightgreen.svg)](SELF_VERIFICATION.md)
[![Coverage](https://img.shields.io/badge/coverage-86%25-yellow.svg)](COVERAGE.md)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)

</div>

---

## What is DCAVP?

DCAVP is not a scanner. It is a **verification platform**.

Most security tools give you a score. DCAVP gives you a **proof**.

Most security tools hide their failures. DCAVP **admits them**.

Most security tools ask for your trust. DCAVP **verifies itself** before verifying you.

---

## Quick Start

```bash
pip install dcavp

# Analyze your code
dcavp analyze ./my_project

# See how deep the analysis goes
dcavp analyze ./my_project --tier RED

# Verify the platform itself
dcavp verify
What makes DCAVP different?
Capability	DCAVP	Bandit	Snyk	SonarQube
Deterministic results	✅ Always	✅ Yes	❌ No	❌ No
Self-verification	✅ 6/6 gates	❌ No	❌ No	❌ No
Admits analysis failure	✅ ANALYSIS VACUUM	❌ No	❌ No	❌ No
Proof Certificate	✅ Cryptographically verifiable	❌ No	❌ No	❌ No
Tiered governance	✅ 4 tiers	❌ No	❌ No	❌ No
Cross-platform	✅ Win/Lin/Mac	✅ Yes	✅ Yes	✅ Yes
Zero dependencies	✅ Stdlib only	✅ Yes	❌ API	❌ Server
HTML reports	✅ Standalone	❌ No	✅ Yes	✅ Yes
The Four Tiers
DCAVP offers four analysis tiers. Each tier unlocks deeper analysis — and produces reports tailored to its audience.

Tier	Audience	Depth	Reports	Free Limit
🟢 GREEN	Beginners, hobbyists	Basic patterns	Plain English, actionable	Unlimited*
🔵 BLUE	Professional developers	Standard CI/CD	Technical, precise	10 analyses
🟡 YELLOW	Companies, enterprises	Supply chain, dependencies	Executive, comprehensive	5 analyses
🔴 RED	Defense, aerospace, medical	Military-grade	Proof Certificate, audit-ready	2 analyses
*GREEN tier is free forever after GitHub login. Higher tiers offer limited free trials.

What DCAVP Detects
DCAVP detects 12 of 14 targeted security patterns (86% coverage). Every finding includes exact file location, CWE reference, and a recommended fix.

<details> <summary>Click to see full detection table</summary>
Pattern	Severity	CWE	Example
eval()	CRITICAL	CWE-94	eval(request.body)
exec()	CRITICAL	CWE-94	exec(user_code)
subprocess with shell=True	CRITICAL	CWE-78	subprocess.run(cmd, shell=True)
pickle.loads()	CRITICAL	CWE-502	pickle.loads(network_data)
os.system()	CRITICAL	CWE-78	os.system(user_cmd)
SQL injection	CRITICAL	CWE-89	cursor.execute(f"SELECT {user}")
open() with user path	CRITICAL	CWE-22	open(request.args['file'])
yaml.load()	HIGH	CWE-502	yaml.load(untrusted_data)
requests.get() with user URL	HIGH	CWE-918	requests.get(user_url)
os.remove() with user path	HIGH	CWE-22	os.remove(user_input)
random for security tokens	HIGH	CWE-338	random.hex(32)
debug=True in Flask	WARNING	CWE-489	app.run(debug=True)
See COVERAGE.md for the complete list including what is not yet detected.

</details>
ANALYSIS VACUUM — The Most Honest Error in Security
When DCAVP analyzes code that contains no registered dangerous patterns, it does NOT give a false "PASS".

Instead, it reports:

text
⚠ ANALYSIS VACUUM — Zero nodes produced.
  This code may be safe. Or it may contain patterns
  DCAVP cannot yet detect. We don't know. So we don't
  pretend to know.
No other security tool does this.

Why? Because a false "PASS" is more dangerous than a honest "I don't know".

Self-Verification
DCAVP verifies itself before it verifies you.

bash
$ dcavp verify

Self-verification: 6/6 checks passed. RELEASE ELIGIBLE.
Check	Purpose
CHECK-SV-001	Catalog Merkle Integrity
CHECK-SV-002	Policy Source References
CHECK-SV-003	Dependency Whitelist
CHECK-SV-004	RED Tier Self-Analysis
CHECK-SV-005	Triple Replay Validation
CHECK-SV-006	Governance Gates
A platform that cannot verify itself cannot verify other software. DCAVP verifies itself under the strictest RED tier on every commit.

See SELF_VERIFICATION.md for the latest report.

Determinism — Same Input = Same Output, Always
DCAVP produces byte-identical results for the same codebase, regardless of:

Operating system (Windows, Linux, macOS)

Time of day

Machine it runs on

This is proven via Triple Replay Validation — three independent runs must produce identical artifact hashes.

text
Run 1: sha256:a1b2c3d4...
Run 2: sha256:a1b2c3d4...  ← identical
Run 3: sha256:a1b2c3d4...  ← identical
Proof Certificate
Every analysis produces a cryptographically verifiable Proof Certificate:

json
{
  "artifact_hash": "sha256:a1b2c3d4e5f6...",
  "catalog_version": "2026.05.12",
  "tier": "RED",
  "triple_replay": "VERIFIED",
  "self_verification": "6/6 PASSED"
}
Share this with auditors. It proves:

What was analyzed

When it was analyzed

Which rules were applied

That the platform was verified before analysis

No source code is revealed. Only the cryptographic proof.

Installation
bash
pip install dcavp
Requires Python 3.12+. Zero external dependencies. The entire platform runs on Python standard library.

Commands
bash
dcavp analyze <path>     # Analyze a project
dcavp verify             # Self-verification
dcavp catalog            # Show detection catalog
dcavp login              # GitHub authentication
Flag	Values	Description
--tier	GREEN, BLUE, YELLOW, RED	Analysis depth
--format	human, json, html	Output format
--output-bundle	PATH	Save replay bundle
--quiet	—	Suppress progress
GitHub Actions
yaml
name: DCAVP Security Gate
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
      - run: dcavp analyze . --tier BLUE --format html
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: dcavp-report.html
Current Limitations — Honest Disclosure
Limitation	Status
Hardcoded secrets detection	🚧 v0.4.0
Exception swallowing detection	🚧 v0.4.0
Dataflow / taint analysis	📅 v0.5.0
Framework awareness (Flask, Django, FastAPI)	📅 v0.6.0
Interprocedural analysis	📅 v1.0.0
DCAVP does not claim to be a complete security solution. It claims to be a deterministic, self-verifying, honest analysis kernel. We tell you what we can see — and what we cannot.

Roadmap
Version	Milestone
v0.2.0 ✅	12 patterns, 86% coverage, ANALYSIS VACUUM
v0.4.0 🚧	100% coverage, Severity model, Engine health
v0.5.0 📅	Taint awareness, Context tags
v0.6.0 📅	Framework awareness (Flask, Django)
v1.0.0 📅	Dataflow engine, Dashboard, Enterprise ready
Philosophy
DCAVP is built on three principles:

Determinism — Same input produces identical output. Always.

Honesty — We admit what we cannot see. ANALYSIS VACUUM is our promise.

Self-Governance — We verify ourselves before we verify you. 6/6 or nothing.

No cloud. No telemetry. No API calls. Everything runs locally. Your code never leaves your machine.

Contributing
See CONTRIBUTING.md. All contributions must pass dcavp verify under RED tier.

License
Apache 2.0 — see LICENSE.

<div align="center">
DCAVP — Because a tool that cannot verify itself cannot verify you.

Website · Docs · Coverage · Self-Verification

</div> ```