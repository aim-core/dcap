# Contributing to DCAVP

## Ground rules

1. All new code requires tests — no exceptions
2. All tests must pass before PR review
3. No new external dependencies without explicit approval
4. The determinism guarantee must be maintained: same input → same output, always

## Development setup

```bash
git clone https://github.com/dcavp/dcavp
cd dcavp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python3 tests/unit/test_policy_engine.py  # verify setup
```

## Running tests

```bash
python3 -m pytest tests/unit/ -v
```

## Architecture

See `governance/constitution/ENGINEERING_CONSTITUTION.md` for the
architectural laws that govern this project.

## What we accept

- Bug fixes with reproduction test cases
- New Python construct detectors (with CWE/OWASP citations)
- Plain-English translation improvements
- Performance improvements with benchmark evidence

## What we don't accept

- New external dependencies
- Non-deterministic behavior
- Features without tests
- Changes to the governance model without RFC process
