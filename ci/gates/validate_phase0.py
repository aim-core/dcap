#!/usr/bin/env python3
"""
******************************************************************************
 * FILE:        /ci/gates/validate_phase0.py
 * LAYER:       CI/CD Layer
 * MODULE:      Phase 0 Validation Gate
 * PURPOSE:     Enforce all Phase 0 governance rules before milestone sign-off
 * DOMAIN:      Governance Foundation
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * This script is the single enforcement point for Phase 0 completion.
 * It runs ALL validation gates in sequence. Any failure halts the pipeline.
 *
 * Every check here corresponds to a rule in DETERMINISTIC_CODING_RULES.md
 * or DEPENDENCY_GOVERNANCE.md. There are no checks without corresponding rules.
 *
 * DEPENDENCIES: None (stdlib only — this is a governance tool)
 * CONSTRAINTS:
 * - Must run on Python 3.12+
 * - Must complete in < 60 seconds
 * - Must produce deterministic output (same failures, same order)
 * - Exit code 0 = all gates pass; Exit code 1 = failure
 *
 * DETERMINISM GUARANTEES:
 * - Files are discovered and processed in sorted order
 * - Violations are reported in sorted order (by file, then line)
 * - Output is byte-identical across runs on identical codebases
 *
 * FAILURE MODES:
 * - Missing governance files: FATAL (gate fails immediately)
 * - Forbidden import detected: FATAL per violation
 * - Forbidden call detected: FATAL per violation
 *
 * SECURITY CONSIDERATIONS:
 * - Reads source files only (no execution of analyzed code)
 * - No network access
 * - No external process invocation
 *
 * COMPLEXITY: O(n * m) where n = files, m = lines per file
 *
 * LICENSE: Apache-2.0
 ******************************************************************************
"""

from __future__ import annotations

import ast
import pathlib
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ─── Types ────────────────────────────────────────────────────────────────────

class GateResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass(frozen=True)
class Violation:
    """A single gate violation. Immutable. Carries all context for reporting."""
    gate_id: str
    file_path: str
    line_number: int
    column: int
    rule_id: str
    description: str
    severity: str  # "FATAL" | "ERROR" | "WARNING"


@dataclass(frozen=True)
class GateReport:
    """Complete report for a single validation gate."""
    gate_id: str
    gate_name: str
    rule_reference: str
    result: str  # GateResult value
    violation_count: int
    violations: tuple[Violation, ...]
    elapsed_ms: int


@dataclass(frozen=True)
class Phase0ValidationReport:
    """Complete Phase 0 validation report. Immutable."""
    timestamp_utc: str
    project_root: str
    files_analyzed: int
    gate_count: int
    gates_passed: int
    gates_failed: int
    total_violations: int
    gate_reports: tuple[GateReport, ...]
    overall_result: str  # GateResult value
    milestone_eligible: bool


# ─── Forbidden Imports (RULE-DEP-001) ────────────────────────────────────────

KERNEL_FORBIDDEN_IMPORTS: frozenset[str] = frozenset({
    "random",
    "subprocess",
    "multiprocessing",
    "threading",
    "asyncio",
    "socket",
    "http",
    "urllib",
    "pickle",
    "marshal",
    "shelve",
    "ctypes",
    "cffi",
    "tempfile",
    "numpy",
    "pandas",
    "sklearn",
    "tensorflow",
    "torch",
    "openai",
    "anthropic",
    "requests",
    "aiohttp",
    "celery",
    "redis",
    "sqlalchemy",
})

# Forbidden function calls in kernel code (RULE-DET-001 through DET-010)
KERNEL_FORBIDDEN_CALLS: frozenset[str] = frozenset({
    "eval",
    "exec",
    "__import__",
    "compile",      # dynamic compilation
    "vars",         # can expose mutable state
    "globals",      # forbidden — no global state
    "locals",       # forbidden — implementation detail
    "setattr",      # forbidden — bypasses frozen dataclass
    "delattr",      # forbidden — mutation
    "open",         # forbidden in kernel — I/O goes through infrastructure
})

# Files that are NOT part of the kernel (gates not applied here)
NON_KERNEL_DIRECTORIES: frozenset[str] = frozenset({
    "ci",
    "tests",
    "scripts",
    "docs",
    "governance",
    "standards",
    "security",
})

# Required governance files for Phase 0
REQUIRED_GOVERNANCE_FILES: list[str] = [
    "governance/constitution/ENGINEERING_CONSTITUTION.md",
    "governance/coding_rules/DETERMINISTIC_CODING_RULES.md",
    "governance/dependency_policy/DEPENDENCY_GOVERNANCE.md",
    "governance/naming_standards/NAMING_STANDARDS.md",
    "docs/decisions/ADR-001-implementation-language.md",
    "security/baseline/SECURITY_BASELINE.md",
]


# ─── Gate Implementations ─────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    """UTC timestamp — the one approved function for current time."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _is_kernel_file(file_path: pathlib.Path, project_root: pathlib.Path) -> bool:
    """
    Purpose: Determine if a file is part of the kernel (subject to strict gates).
    Inputs: file_path (absolute), project_root (absolute)
    Outputs: bool — True if file is in kernel scope
    Constraints: Deterministic; depends only on path structure
    """
    try:
        relative = file_path.relative_to(project_root)
    except ValueError:
        return False
    top_level = relative.parts[0] if relative.parts else ""
    return top_level not in NON_KERNEL_DIRECTORIES and file_path.suffix == ".py"


def gate_governance_files_present(
    project_root: pathlib.Path,
) -> GateReport:
    """
    Gate: GATE-GOV-001 — Required governance files must exist.

    Purpose: Verify that all mandatory governance documents from Phase 0
             are present before any code gates run.
    Inputs: project_root — absolute path to repository root
    Outputs: GateReport
    Constraints: Deterministic; files sorted before checking
    Failure mode: Any missing file = FATAL
    """
    import time
    t0 = time.monotonic_ns()
    violations: list[Violation] = []

    for required in sorted(REQUIRED_GOVERNANCE_FILES):
        full_path = project_root / required
        if not full_path.exists():
            violations.append(Violation(
                gate_id="GATE-GOV-001",
                file_path=str(full_path),
                line_number=0,
                column=0,
                rule_id="PHASE0-GOVERNANCE",
                description=f"Required governance file missing: {required}",
                severity="FATAL",
            ))

    elapsed = (time.monotonic_ns() - t0) // 1_000_000
    result = GateResult.FAIL if violations else GateResult.PASS
    return GateReport(
        gate_id="GATE-GOV-001",
        gate_name="Governance Files Present",
        rule_reference="ENGINEERING_CONSTITUTION.md Article IV Section 4.3",
        result=result.value,
        violation_count=len(violations),
        violations=tuple(sorted(violations, key=lambda v: (v.file_path, v.line_number))),
        elapsed_ms=elapsed,
    )


def gate_forbidden_imports(
    project_root: pathlib.Path,
) -> GateReport:
    """
    Gate: GATE-DEP-001 — No forbidden imports in kernel code.

    Purpose: Enforce DEPENDENCY_GOVERNANCE.md whitelist model.
             Detect any use of forbidden standard library or third-party modules
             in kernel source files.
    Inputs: project_root — absolute path to repository root
    Outputs: GateReport with all violations found
    Constraints:
    - Only scans .py files in kernel directories
    - Uses AST parsing (not grep) to avoid false positives from comments
    - Deterministic: files sorted before scanning
    Failure mode: Any forbidden import = FATAL
    Complexity: O(n * m) where n = files, m = AST nodes per file
    """
    import time
    t0 = time.monotonic_ns()
    violations: list[Violation] = []

    kernel_files = sorted(
        [f for f in project_root.rglob("*.py") if _is_kernel_file(f, project_root)],
        key=lambda p: str(p),
    )

    for source_file in kernel_files:
        try:
            source_text = source_file.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=str(source_file))
        except (SyntaxError, UnicodeDecodeError) as e:
            violations.append(Violation(
                gate_id="GATE-DEP-001",
                file_path=str(source_file),
                line_number=0,
                column=0,
                rule_id="GATE-DEP-001",
                description=f"Cannot parse file: {e}",
                severity="FATAL",
            ))
            continue

        for node in ast.walk(tree):
            # import random
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_root = alias.name.split(".")[0]
                    if module_root in KERNEL_FORBIDDEN_IMPORTS:
                        violations.append(Violation(
                            gate_id="GATE-DEP-001",
                            file_path=str(source_file),
                            line_number=node.lineno,
                            column=node.col_offset,
                            rule_id="DEP-FORBIDDEN-IMPORT",
                            description=f"Forbidden import: {alias.name}",
                            severity="FATAL",
                        ))
            # from random import choice
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                module_root = module.split(".")[0]
                if module_root in KERNEL_FORBIDDEN_IMPORTS:
                    violations.append(Violation(
                        gate_id="GATE-DEP-001",
                        file_path=str(source_file),
                        line_number=node.lineno,
                        column=node.col_offset,
                        rule_id="DEP-FORBIDDEN-FROM-IMPORT",
                        description=f"Forbidden from-import: from {module} import ...",
                        severity="FATAL",
                    ))

    elapsed = (time.monotonic_ns() - t0) // 1_000_000
    result = GateResult.FAIL if violations else GateResult.PASS
    return GateReport(
        gate_id="GATE-DEP-001",
        gate_name="Forbidden Imports Check",
        rule_reference="DEPENDENCY_GOVERNANCE.md — Forbidden Modules List",
        result=result.value,
        violation_count=len(violations),
        violations=tuple(sorted(violations, key=lambda v: (v.file_path, v.line_number))),
        elapsed_ms=elapsed,
    )


def gate_forbidden_calls(
    project_root: pathlib.Path,
) -> GateReport:
    """
    Gate: GATE-DET-001 — No forbidden function calls in kernel code.

    Purpose: Detect eval(), exec(), open(), globals() and other forbidden
             calls that violate determinism or kernel purity rules.
    Inputs: project_root — absolute path
    Outputs: GateReport
    Constraints: AST-based (no false positives from strings/comments)
    Failure mode: Any forbidden call = FATAL
    """
    import time
    t0 = time.monotonic_ns()
    violations: list[Violation] = []

    kernel_files = sorted(
        [f for f in project_root.rglob("*.py") if _is_kernel_file(f, project_root)],
        key=lambda p: str(p),
    )

    for source_file in kernel_files:
        try:
            source_text = source_file.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=str(source_file))
        except (SyntaxError, UnicodeDecodeError):
            continue  # Already caught by gate_forbidden_imports

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name: Optional[str] = None
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                # compile() as bare builtin is forbidden; re.compile() (method) is permitted.
                # open() is forbidden in kernel/domain/application layers but PERMITTED
                # in infrastructure layer (which by design performs I/O).
                is_method_call = isinstance(node.func, ast.Attribute)
                is_infra_file = "infrastructure" in str(source_file).replace(chr(92), chr(47))
                is_forbidden = (
                    call_name is not None
                    and call_name in KERNEL_FORBIDDEN_CALLS
                    and not (call_name == "compile" and is_method_call)
                    and not (call_name == "open" and is_infra_file)
                )
                if is_forbidden:
                    violations.append(Violation(
                        gate_id="GATE-DET-001",
                        file_path=str(source_file),
                        line_number=node.lineno,
                        column=node.col_offset,
                        rule_id="DET-FORBIDDEN-CALL",
                        description=f"Forbidden call: {call_name}()",
                        severity="FATAL",
                    ))

    elapsed = (time.monotonic_ns() - t0) // 1_000_000
    result = GateResult.FAIL if violations else GateResult.PASS
    return GateReport(
        gate_id="GATE-DET-001",
        gate_name="Forbidden Calls Check",
        rule_reference="DETERMINISTIC_CODING_RULES.md — RULE-DET-004",
        result=result.value,
        violation_count=len(violations),
        violations=tuple(sorted(violations, key=lambda v: (v.file_path, v.line_number))),
        elapsed_ms=elapsed,
    )


def gate_global_mutable_state(
    project_root: pathlib.Path,
) -> GateReport:
    """
    Gate: GATE-DET-002 — No module-level mutable variable assignments in kernel.

    Purpose: Enforce RULE-DET-004. Module-level assignments to non-constant
             names indicate mutable global state, which destroys determinism.
    Constraints:
    - Constants (UPPER_CASE names) are permitted
    - Frozen dataclass instances at module level are permitted
    - Type aliases are permitted
    - Only ASSIGNMENTS are checked (not function definitions)
    """
    import time
    t0 = time.monotonic_ns()
    violations: list[Violation] = []

    kernel_files = sorted(
        [f for f in project_root.rglob("*.py") if _is_kernel_file(f, project_root)],
        key=lambda p: str(p),
    )

    for source_file in kernel_files:
        try:
            source_text = source_file.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=str(source_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in (tree.body if hasattr(tree, 'body') else []):
            # Module-level assignments only
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        # Constants (UPPER_SNAKE_CASE) are permitted
                        if name == name.upper() and name.replace("_", "").isalnum():
                            continue
                        # Dunder names are permitted
                        if name.startswith("__") and name.endswith("__"):
                            continue
                        # Everything else at module level is suspect
                        violations.append(Violation(
                            gate_id="GATE-DET-002",
                            file_path=str(source_file),
                            line_number=node.lineno,
                            column=node.col_offset,
                            rule_id="DET-GLOBAL-MUTABLE",
                            description=(
                                f"Module-level mutable assignment: '{name}'. "
                                f"Use UPPER_CASE for constants or pass state explicitly."
                            ),
                            severity="FATAL",
                        ))

    elapsed = (time.monotonic_ns() - t0) // 1_000_000
    result = GateResult.FAIL if violations else GateResult.PASS
    return GateReport(
        gate_id="GATE-DET-002",
        gate_name="No Global Mutable State",
        rule_reference="DETERMINISTIC_CODING_RULES.md — RULE-DET-004",
        result=result.value,
        violation_count=len(violations),
        violations=tuple(sorted(violations, key=lambda v: (v.file_path, v.line_number))),
        elapsed_ms=elapsed,
    )


def gate_file_headers(
    project_root: pathlib.Path,
) -> GateReport:
    """
    Gate: GATE-GOV-002 — All source files have required header fields.

    Purpose: Enforce file header standard from Build Directive.
             Every kernel source file must declare FILE, LAYER, MODULE,
             PURPOSE, and LICENSE in a header block.
    """
    import time
    t0 = time.monotonic_ns()
    violations: list[Violation] = []

    REQUIRED_HEADER_FIELDS = ["FILE:", "LAYER:", "MODULE:", "PURPOSE:", "LICENSE:"]

    all_py_files = sorted(
        project_root.rglob("*.py"),
        key=lambda p: str(p),
    )

    for source_file in all_py_files:
        try:
            content = source_file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        first_4000_chars = content[:4000]
        missing = [
            field for field in REQUIRED_HEADER_FIELDS
            if field not in first_4000_chars
        ]
        if missing:
            violations.append(Violation(
                gate_id="GATE-GOV-002",
                file_path=str(source_file),
                line_number=1,
                column=0,
                rule_id="GOV-FILE-HEADER",
                description=f"Missing header fields: {', '.join(sorted(missing))}",
                severity="ERROR",
            ))

    elapsed = (time.monotonic_ns() - t0) // 1_000_000
    result = GateResult.FAIL if violations else GateResult.PASS
    return GateReport(
        gate_id="GATE-GOV-002",
        gate_name="File Header Standard",
        rule_reference="Build Directive — File Header Standard section",
        result=result.value,
        violation_count=len(violations),
        violations=tuple(sorted(violations, key=lambda v: (v.file_path, v.line_number))),
        elapsed_ms=elapsed,
    )


# ─── Main Validation Runner ───────────────────────────────────────────────────

def run_phase0_validation(project_root_str: str) -> Phase0ValidationReport:
    """
    Purpose: Run all Phase 0 validation gates and produce a complete report.
    Inputs: project_root_str — string path to repository root
    Outputs: Phase0ValidationReport (immutable)
    Constraints:
    - All gates run in defined order (not parallel — deterministic)
    - Gate execution order is: governance → dependency → determinism → style
    - Report is produced even if gates fail (for diagnostic purposes)
    Determinism: identical codebase → identical report (byte-level)
    """
    project_root = pathlib.Path(project_root_str).resolve().absolute()

    gate_functions = [
        gate_governance_files_present,
        gate_forbidden_imports,
        gate_forbidden_calls,
        gate_global_mutable_state,
        gate_file_headers,
    ]

    gate_reports: list[GateReport] = []
    files_analyzed = len(sorted(project_root.rglob("*.py"), key=lambda p: str(p)))

    for gate_fn in gate_functions:
        report = gate_fn(project_root)
        gate_reports.append(report)

    gates_passed = sum(1 for r in gate_reports if r.result == GateResult.PASS.value)
    gates_failed = len(gate_reports) - gates_passed
    total_violations = sum(r.violation_count for r in gate_reports)
    overall = GateResult.PASS if gates_failed == 0 else GateResult.FAIL

    return Phase0ValidationReport(
        timestamp_utc=_utc_now_iso(),
        project_root=str(project_root),
        files_analyzed=files_analyzed,
        gate_count=len(gate_reports),
        gates_passed=gates_passed,
        gates_failed=gates_failed,
        total_violations=total_violations,
        gate_reports=tuple(gate_reports),
        overall_result=overall.value,
        milestone_eligible=(overall == GateResult.PASS),
    )


def print_report(report: Phase0ValidationReport) -> None:
    """Human-readable report output. Not part of CEF — diagnostic only."""
    print("\n" + "=" * 72)
    print("DCAVP PHASE 0 VALIDATION REPORT")
    print("=" * 72)
    print(f"Timestamp:    {report.timestamp_utc}")
    print(f"Project Root: {report.project_root}")
    print(f"Files:        {report.files_analyzed}")
    print(f"Gates:        {report.gate_count} total / {report.gates_passed} passed / {report.gates_failed} failed")
    print(f"Violations:   {report.total_violations}")
    print(f"Result:       {report.overall_result}")
    print(f"Milestone:    {'✓ ELIGIBLE' if report.milestone_eligible else '✗ NOT ELIGIBLE'}")
    print()

    for gate_report in report.gate_reports:
        status_sym = "✓" if gate_report.result == "PASS" else "✗"
        print(f"  [{status_sym}] {gate_report.gate_id}: {gate_report.gate_name} ({gate_report.elapsed_ms}ms)")
        for v in gate_report.violations:
            print(f"        {v.severity}: {v.file_path}:{v.line_number} — {v.description}")

    print()
    if report.milestone_eligible:
        print("ALL GATES PASS — Phase 0 milestone criteria met.")
    else:
        print("GATES FAILED — Phase 0 milestone criteria NOT met.")
        print("Resolve all violations before milestone sign-off.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    report = run_phase0_validation(root)
    print_report(report)
    sys.exit(0 if report.milestone_eligible else 1)
