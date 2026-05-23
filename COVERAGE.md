# Detection Coverage — v0.3.0

**Last updated:** 2026-05-23  
**Self-verification:** 6/6 passed  
**Coverage:** 12/14 patterns (86%)

---

## Detected Patterns

| # | Pattern | Severity | CWE | Since |
|:--|:--------|:---------|:----|:------|
| 1 | `eval()` | CRITICAL | CWE-94 | v0.1.0 |
| 2 | `exec()` | CRITICAL | CWE-94 | v0.1.0 |
| 3 | `subprocess` with `shell=True` | CRITICAL | CWE-78 | v0.1.0 |
| 4 | `pickle.loads()` | CRITICAL | CWE-502 | v0.1.0 |
| 5 | `os.system()` | CRITICAL | CWE-78 | v0.2.0 |
| 6 | SQL injection | CRITICAL | CWE-89 | v0.3.0 |
| 7 | `open()` with user path | CRITICAL | CWE-22 | v0.1.0 |
| 8 | `yaml.load()` | HIGH | CWE-502 | v0.2.0 |
| 9 | `requests.get()` SSRF | HIGH | CWE-918 | v0.2.0 |
| 10 | `os.remove()` with user path | HIGH | CWE-22 | v0.2.0 |
| 11 | `random` for security tokens | HIGH | CWE-338 | v0.1.0 |
| 12 | `debug=True` in Flask | WARNING | CWE-489 | v0.2.0 |

---

## Not Yet Detected

| # | Pattern | CWE | Planned |
|:--|:--------|:----|:--------|
| 1 | Hardcoded secrets | CWE-798 | v0.4.0 |
| 2 | Exception swallowing | CWE-390 | v0.4.0 |

---

## Will Not Detect (by design)

| Pattern | Reason |
|:--------|:-------|
| Dataflow-based injection | Requires taint engine (v0.5.0) |
| Business logic flaws | Not pattern-detectable |
| Zero-day exploits | Requires runtime monitoring |
| Obfuscated code | Beyond static analysis scope |

---

## Methodology

DCAVP uses **deterministic pattern matching** on Python AST (Abstract Syntax Tree). Each pattern is registered as a **Construct** in the Knowledge Catalog. The catalog is Merkle-tree verified before every analysis.

- **Precision:** 100% (zero false positives in test suite)
- **Recall:** 86% (12/14 targeted patterns detected)
- **Determinism:** 100% (identical results across platforms)

---

## How to Add Coverage

New patterns are added via `constructs_extended.py`. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

*This document is updated with every release. We publish our limitations because honesty is our core value.*