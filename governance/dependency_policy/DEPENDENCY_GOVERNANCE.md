# Dependency Governance

## Forbidden Modules
See ci/gates/validate_phase0.py for complete list.

## Policy
- Kernel must use stdlib only
- Infrastructure may use pathlib, ast, hashlib
- No network, no ML, no dynamic compilation
