# 🏛️ DCAP

## Deterministic Code Analysis Platform

Deterministic security analysis for AI-generated software systems.

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Deterministic](https://img.shields.io/badge/analysis-deterministic-critical)
![Local First](https://img.shields.io/badge/runtime-local--first-orange)

---

# What is DCAP?

DCAP is a deterministic audit platform designed to analyze
AI-generated software using evidence-driven mathematical analysis.

DCAP does not rely on:

* probabilistic AI guesses
* hidden heuristics
* opaque scoring
* remote cloud inference

Instead, it relies on:

* deterministic AST analysis
* replay-safe evaluation
* rule-governed scoring
* mathematically reproducible execution paths

The platform is intentionally:

* local-first
* deterministic
* governance-oriented
* operationally explainable

---

# Why DCAP Exists

AI-generated software introduced a new category of problems:

* hallucinated logic
* fake fixes
* hidden execution paths
* insecure dependency chains
* deterministic violations
* silent recovery corruption
* inconsistent security behavior

Traditional scanners detect syntax-level issues.

DCAP attempts to evaluate:

* execution risk
* deterministic integrity
* operational trust boundaries
* governance posture
* correlation between dangerous constructs

---

# Core Principles

## Determinism

Same input.
Same catalog.
Same execution path.
Same result.

Always.

---

## Honest Analysis

DCAP explicitly reports:

* unsupported constructs
* degraded rule execution
* partial visibility
* incomplete deterministic guarantees

The platform never fabricates certainty.

---

## Self-Governance

DCAP verifies itself before analyzing target code.

Every release must pass deterministic governance checks.

---

# Supported Platforms

## Windows

```bash id="2yxv8r"
pip install dcap

dcap analyze . --tier GREEN
```

PowerShell:

```powershell id="h2m7x1"
dcap analyze "C:\project" --tier BLUE
```

---

## Linux

```bash id="f9e3zq"
pip install dcap

dcap analyze /opt/project --tier YELLOW
```

---

## macOS

```bash id="o6k8cn"
pip3 install dcap

dcap analyze ~/project --tier GREEN
```

---

# Analysis Modes

| Mode                    | Purpose                           |
| ----------------------- | --------------------------------- |
| Deterministic Scan      | Mathematical rule evaluation      |
| Correlation Analysis    | Dangerous construct relationships |
| Governance Verification | Self-integrity validation         |
| Replay Validation       | Deterministic replay proof        |
| Tier Enforcement        | Operational deployment policy     |
| Forensic Audit          | Zero-trust security posture       |

---

# The Four Tiers

## 🟢 GREEN — Community

Designed for:

* students
* local developers
* educational usage

Characteristics:

* CLI-only reporting
* lightweight deterministic scanning
* operational warnings
* limited governance depth

Deployment policy:

* permissive

---

## 🔵 BLUE — Professional

Designed for:

* professional developers
* CI/CD environments
* production engineering teams

Characteristics:

* enhanced reporting
* correlation analysis
* deterministic score model
* replay verification
* exportable reports

Deployment policy:

* operational governance

---

## 🟡 YELLOW — Enterprise

Designed for:

* enterprises
* fintech
* regulated environments
* security teams

Characteristics:

* advanced governance enforcement
* forensic reporting
* deeper policy controls
* operational restrictions
* structured export formats

Deployment policy:

* enterprise-grade review enforcement

---

## 🔴 RED — Forensic

Designed for:

* defense
* aerospace
* critical infrastructure
* medical systems
* zero-trust environments

Characteristics:

* forensic enforcement
* catastrophic risk escalation
* replay integrity enforcement
* aggressive deployment blocking
* maximum deterministic scrutiny

Deployment policy:

* zero-trust forensic posture

---

# Example Analysis

```bash id="k4zq1m"
dcap analyze ./project --tier RED
```

Example output:

```text id="v1x2nb"
============================================================
DCAP Analysis Report
============================================================

Status          : BLOCKED
Tier            : RED
Files           : 91
Findings        : 4
Security Score  : 55/100
Grade           : D — High Operational Risk

Replay Proof    : VERIFIED
Catalog Version : 2026.05.12
Engine Trust    : VERIFIED

Findings:
- eval() detected
- exec() detected
- subprocess(shell=True)
- pickle.loads()

Deployment:
RESTRICTED under RED tier policy
```

---

# Analysis Performance

DCAP is designed for deterministic local execution.

Typical scan time:

| Project Size       | Approximate Time |
| ------------------ | ---------------- |
| Small scripts      | 20–80ms          |
| Medium projects    | 80–300ms         |
| Large repositories | 300–1500ms       |

Performance depends on:

* file count
* AST complexity
* enabled governance layers
* replay verification depth

No cloud processing is required.

Your code never leaves your machine.

---

# Deterministic Scoring Model

DCAP uses weighted mathematical evaluation.

The scoring engine evaluates:

```text id="i31m7g"
Severity × Confidence × Reachability × Exposure
```

Additional adjustments:

* correlation penalties
* deterministic degradation
* runtime execution surfaces
* catastrophic escalation

The engine intentionally avoids:

* AI-generated scores
* random weighting
* probabilistic guessing

---

# Self Verification

```bash id="vf91ap"
dcap verify
```

Example:

```text id="q8z4ca"
6/6 governance checks passed.
RELEASE ELIGIBLE.
```

Verification includes:

* replay consistency
* rule integrity
* catalog integrity
* deterministic constraints
* governance validation
* execution trust verification

---

# Current Detection Coverage

| Pattern                | Severity | CWE     |
| ---------------------- | -------- | ------- |
| eval()                 | CRITICAL | CWE-94  |
| exec()                 | CRITICAL | CWE-94  |
| subprocess(shell=True) | CRITICAL | CWE-78  |
| pickle.loads()         | CRITICAL | CWE-502 |
| os.system()            | CRITICAL | CWE-78  |
| SQL injection patterns | CRITICAL | CWE-89  |
| yaml.load()            | ERROR    | CWE-502 |
| SSRF patterns          | ERROR    | CWE-918 |
| insecure randomness    | WARNING  | CWE-338 |

---

# Pro Edition

Professional tiers add:

* AI hallucinated logic detection
* security theater detection
* deterministic integrity analysis
* governance policy enforcement
* architectural contradiction analysis
* replay-aware forensic reporting
* enhanced export systems

---

# Current Scope and Limitations

DCAP currently focuses on:

* deterministic static analysis
* AST evidence correlation
* governance-oriented enforcement

Not yet implemented:

* taint propagation graphs
* symbolic execution
* runtime flow reconstruction
* interprocedural reasoning
* probabilistic exploit simulation
* memory corruption propagation analysis

The platform intentionally reports these boundaries openly.

---

# Philosophy

DCAP does not attempt to imitate intuition.

It attempts to provide:

* deterministic reasoning
* mathematically reproducible analysis
* explainable operational evidence
* governance-aware security decisions

for the era of AI-generated software.

---

# License

Apache 2.0

Community edition:

* local-first
* deterministic
* transparent

Professional and enterprise modules:
https://dcap.dev/pro

---

<div align="center">

Built for the AI-generated software era.

Deterministic by design.

</div>
