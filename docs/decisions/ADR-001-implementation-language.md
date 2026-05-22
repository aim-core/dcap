# ADR-001: Implementation Language

## Status
Accepted

## Context
DCAVP requires deterministic, cross-platform execution.

## Decision
Python 3.12+ is the sole implementation language.

## Consequences
- Single language reduces attack surface
- pathlib ensures cross-platform paths
- No compiled dependencies
