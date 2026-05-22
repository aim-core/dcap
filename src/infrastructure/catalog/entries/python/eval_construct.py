"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/entries/python/eval_construct.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Knowledge Catalog — Python Constructs
 * PURPOSE:     Catalog entry for Python eval() construct (CONST-EVAL-001)
 * DOMAIN:      Knowledge Catalog
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Production catalog entry for Python eval(). This entry satisfies the
 * Knowledge Integrity Law: every danger condition, every risk mapping,
 * and every acceptance condition has a verifiable citation.
 *
 * Citations used in this entry:
 * [1] CWE-78: Improper Neutralization of Special Elements used in an OS Command
 *     Source: MITRE CWE Database, https://cwe.mitre.org/data/definitions/78.html
 *     Version: 4.14 (2024-02-29)
 *
 * [2] CWE-94: Improper Control of Generation of Code ('Code Injection')
 *     Source: MITRE CWE Database, https://cwe.mitre.org/data/definitions/94.html
 *     Version: 4.14 (2024-02-29)
 *
 * [3] OWASP Top 10 2021 — A03:2021 Injection
 *     Source: OWASP Foundation, https://owasp.org/Top10/A03_2021-Injection/
 *     Publication: 2021-09-09
 *
 * [4] Python Documentation: Built-in Functions — eval()
 *     Source: Python Software Foundation,
 *             https://docs.python.org/3/library/functions.html#eval
 *     Version: Python 3.12 (2024-01-14)
 *     Quote (paraphrased): "The string or code object is evaluated as
 *     a Python expression. eval() has access to the full Python environment."
 *
 * [5] Bandit Security Linter — B307: Use of possibly insecure function
 *     Source: PyCQA/bandit, https://bandit.readthedocs.io/en/latest/
 *     Rule: B307 (eval usage), B307 severity=HIGH, confidence=HIGH
 *
 * DEPENDENCIES:
 * - src/domain/constructs/construct_model.py
 *
 * CONSTRAINTS:
 * - Immutable after release (append-only catalog)
 * - Every field has a source_reference
 * - No general "best practices" without citation
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

from src.domain.constructs.construct_model import (
    AnalysisBounds,
    ConstructDefinition,
    DangerCondition,
    FixedWeight,
    KnowledgeCitation,
    RiskMapping,
    RiskType,
    Severity,
    Confidence,
    Tier,
    TierPermission,
    TierPermissionLevel,
)


# ─── Citations ────────────────────────────────────────────────────────────────

_CITATION_CWE94 = KnowledgeCitation(
    citation_type="STANDARD",
    identifier="CWE-94",
    title="Improper Control of Generation of Code ('Code Injection')",
    publication_date="2024-02-29",
    validation_status="verified",
    reviewer_id="DCAVP-ENG-SYSTEM-v0.1.0",
    url="https://cwe.mitre.org/data/definitions/94.html",
)

_CITATION_CWE78 = KnowledgeCitation(
    citation_type="STANDARD",
    identifier="CWE-78",
    title="Improper Neutralization of Special Elements used in an OS Command",
    publication_date="2024-02-29",
    validation_status="verified",
    reviewer_id="DCAVP-ENG-SYSTEM-v0.1.0",
    url="https://cwe.mitre.org/data/definitions/78.html",
)

_CITATION_OWASP_A03 = KnowledgeCitation(
    citation_type="STANDARD",
    identifier="OWASP-A03-2021",
    title="OWASP Top 10 2021: A03:2021 - Injection",
    publication_date="2021-09-09",
    validation_status="verified",
    reviewer_id="DCAVP-ENG-SYSTEM-v0.1.0",
    url="https://owasp.org/Top10/A03_2021-Injection/",
)

_CITATION_PYTHON_DOCS = KnowledgeCitation(
    citation_type="STANDARD",
    identifier="PYTHON-3.12-EVAL-DOCS",
    title="Python 3.12 Built-in Functions: eval()",
    publication_date="2024-01-14",
    validation_status="verified",
    reviewer_id="DCAVP-ENG-SYSTEM-v0.1.0",
    url="https://docs.python.org/3/library/functions.html#eval",
)

_CITATION_BANDIT = KnowledgeCitation(
    citation_type="STANDARD",
    identifier="BANDIT-B307",
    title="Bandit Security Linter B307: Use of possibly insecure function 'eval'",
    publication_date="2024-01-01",
    validation_status="verified",
    reviewer_id="DCAVP-ENG-SYSTEM-v0.1.0",
    url="https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html",
)

_CITATION_ENGINEERING_JUDGMENT_EVAL = KnowledgeCitation(
    citation_type="ENGINEERING-JUDGMENT",
    identifier="DCAVP-EJ-EVAL-001",
    title=(
        "Engineering Judgment: eval() with constant argument is bad practice because "
        "it bypasses syntax highlighting, static analysis, and IDE support. "
        "The Python Documentation itself states eval() should not be used with "
        "user-provided input. Industry consensus (Bandit B307, PyFlakes, "
        "Pylint W0123) treat all eval() usage as at minimum a warning."
    ),
    publication_date="2026-05-11",
    validation_status="verified",
    reviewer_id="DCAVP-ENG-SYSTEM-v0.1.0",
    url="",
)


# ─── Danger Conditions ────────────────────────────────────────────────────────

_DANGER_DYNAMIC_ARG = DangerCondition(
    condition_id="DC-001",
    state_or_condition="dynamic_arg",
    severity=Severity.CRITICAL.value,
    confidence=Confidence.CERTAIN.value,
    description=(
        "eval() is called with a non-literal argument. The argument may contain "
        "arbitrary Python code. An attacker who controls the argument can execute "
        "arbitrary code in the process context. This is a code injection vulnerability "
        "equivalent to CWE-94."
    ),
    detection_method="AST_PATTERN",
    source_reference="CWE-94: Code Injection (MITRE, 2024-02-29)",
    cve_references=(),   # Generic CWE pattern; no single CVE
    cwe_references=("CWE-94", "CWE-78"),
)

_DANGER_EXTERNAL_SOURCE_ARG = DangerCondition(
    condition_id="DC-002",
    state_or_condition="external_source_arg",
    severity=Severity.CRITICAL.value,
    confidence=Confidence.BOUNDED.value,
    description=(
        "eval() argument is derived from an external source (network input, file, "
        "environment variable, or command-line argument). Dataflow analysis within "
        "bounded scope confirms the argument value is externally controlled. "
        "This is a Remote Code Execution (RCE) vector — OWASP A03:2021 Injection."
    ),
    detection_method="DATAFLOW",
    source_reference="OWASP A03:2021 Injection; CWE-94",
    cve_references=(),
    cwe_references=("CWE-94", "CWE-78"),
)

_DANGER_CONSTANT_ARG = DangerCondition(
    condition_id="DC-003",
    state_or_condition="constant_arg",
    severity=Severity.WARNING.value,
    confidence=Confidence.CERTAIN.value,
    description=(
        "eval() is called with a literal string argument (e.g., eval('1+1')). "
        "While not an immediate injection risk, this is universally considered "
        "bad practice: it bypasses static analysis, IDE support, and syntax "
        "highlighting. Replace with the direct expression or ast.literal_eval(). "
        "Bandit B307 flags all eval() usage as high severity regardless of argument."
    ),
    detection_method="AST_PATTERN",
    source_reference="Bandit B307; DCAVP Engineering Judgment DCAVP-EJ-EVAL-001",
    cve_references=(),
    cwe_references=("CWE-94",),
)


# ─── Tier Permissions ─────────────────────────────────────────────────────────

_TIER_PERMISSIONS = (
    TierPermission(
        tier=Tier.GREEN.value,
        level=TierPermissionLevel.ALLOWED_WITH_WARNING.value,
        enforcement_note=(
            "All eval() usage produces a WARNING finding. "
            "Dynamic arguments produce an ERROR. "
            "Pipeline is not blocked."
        ),
        escalation_note=(
            "Escalates to ERROR if argument is non-literal. "
            "Escalates to CRITICAL in web request handler context."
        ),
    ),
    TierPermission(
        tier=Tier.BLUE.value,
        level=TierPermissionLevel.ALLOWED_WITH_BOUNDED_CHECK.value,
        enforcement_note=(
            "Bounded dataflow analysis determines argument source. "
            "Constant arg → WARNING. Dynamic arg → ERROR. "
            "External source arg → CRITICAL. Pipeline blocked on CRITICAL."
        ),
        escalation_note=(
            "Escalates to CRITICAL in WEB_REQUEST_HANDLER or HANDLES_USER_INPUT context."
        ),
    ),
    TierPermission(
        tier=Tier.YELLOW.value,
        level=TierPermissionLevel.REQUIRES_EXPLICIT_JUSTIFICATION.value,
        enforcement_note=(
            "Any eval() usage produces at minimum ERROR and requires an explicit "
            "justification in the source file via DCAVP-JUSTIFY annotation. "
            "Without justification, escalates to CRITICAL. Pipeline blocked."
        ),
        escalation_note=(
            "No escalation ceiling — any eval() in YELLOW tier is CRITICAL "
            "unless explicit justification is present and approved."
        ),
    ),
    TierPermission(
        tier=Tier.RED.value,
        level=TierPermissionLevel.FORBIDDEN_WITHOUT_DUAL_CONTROL.value,
        enforcement_note=(
            "eval() is FORBIDDEN in RED tier. Any usage immediately produces "
            "CRITICAL finding, blocks pipeline, and requires dual-control "
            "human approval from two qualified reviewers. "
            "No exceptions without signed exemption."
        ),
        escalation_note=(
            "Maximum severity: CRITICAL. Pipeline blocking is mandatory. "
            "Dual-control review required before exemption can be granted."
        ),
    ),
)


# ─── Risk Mappings ────────────────────────────────────────────────────────────

_RISK_MAPPINGS = (
    RiskMapping(
        risk_type=RiskType.CYBERSECURITY.value,
        weight=FixedWeight(numerator=950, denominator=1000),
        rationale=(
            "eval() is a direct code injection vector. An attacker controlling "
            "the eval() argument achieves arbitrary code execution. "
            "This is the highest-impact cybersecurity risk in Python."
        ),
        source_reference="CWE-94, OWASP A03:2021, Bandit B307",
    ),
    RiskMapping(
        risk_type=RiskType.COMPLIANCE.value,
        weight=FixedWeight(numerator=800, denominator=1000),
        rationale=(
            "PCI DSS Requirement 6.3 requires protection against injection attacks. "
            "HIPAA Security Rule requires protection of ePHI from malicious software. "
            "SOC 2 CC6.8 requires protection against malicious code. "
            "eval() in regulated software violates these requirements."
        ),
        source_reference=(
            "PCI DSS v4.0 Req 6.3; HIPAA 45 CFR 164.312(a)(2)(iv); SOC2 CC6.8"
        ),
    ),
    RiskMapping(
        risk_type=RiskType.RELIABILITY.value,
        weight=FixedWeight(numerator=600, denominator=1000),
        rationale=(
            "eval() execution is not statically analyzable. Any change to the "
            "evaluated string changes behavior unpredictably. This makes the "
            "codebase harder to test, harder to debug, and harder to maintain."
        ),
        source_reference="DCAVP Engineering Judgment DCAVP-EJ-EVAL-001",
    ),
)


# ─── Analysis Bounds ──────────────────────────────────────────────────────────

_ANALYSIS_BOUNDS = AnalysisBounds(
    max_call_depth=5,
    max_loop_unroll=0,   # Not applicable for eval() analysis
    max_branch_count=100,
    max_coroutine_count=0,  # Not applicable
    rationale=(
        "Call depth of 5 is sufficient to trace most argument sources. "
        "Beyond depth 5, the argument source is declared as an "
        "EXTERNAL_DEPENDENCY_UNRESOLVED boundary. "
        "Loop unrolling is not needed for eval() detection."
    ),
    source_reference="ENGINEERING-JUDGMENT-v0.1.0",
)


# ─── The Construct Definition ─────────────────────────────────────────────────

EVAL_CONSTRUCT = ConstructDefinition(
    construct_id="CONST-EVAL-001",
    construct_name="eval",
    catalog_version="2026.05.11",
    language="python",
    description=(
        "Python built-in eval() evaluates a string as a Python expression "
        "in the current scope. It has access to globals() and locals() of "
        "the calling context. Any argument that is not a compile-time constant "
        "creates a code injection surface. "
        "Python Documentation states: eval() 'is a significant security risk "
        "if you allow it to evaluate arbitrary strings from users.' "
        "Bandit B307 classifies all eval() usage as HIGH severity. "
        "OWASP A03:2021 classifies code injection as the #3 web application risk."
    ),
    ast_node_types=(
        "Call",   # eval() is a Call node where func.id == "eval"
    ),
    states=(
        "constant_arg",         # eval("1+1") — bad practice but not injection
        "dynamic_arg",          # eval(some_var) — injection risk
        "external_source_arg",  # eval(request.data) — RCE vector
    ),
    danger_conditions=(
        _DANGER_CONSTANT_ARG,
        _DANGER_DYNAMIC_ARG,
        _DANGER_EXTERNAL_SOURCE_ARG,
    ),
    acceptance_conditions=(
        # eval() has NO accepted safe use cases in production code.
        # ast.literal_eval() handles safe literal parsing.
        # Direct expressions handle constant evaluation.
        "NONE: eval() has no accepted safe production use cases. "
        "Replace with ast.literal_eval() for literal parsing or "
        "direct expressions for constant evaluation.",
    ),
    tier_permissions=_TIER_PERMISSIONS,
    analysis_bounds=_ANALYSIS_BOUNDS,
    analysis_constraints=(
        "CANNOT_ANALYZE_EVAL_ARGUMENT_CONTENT: "
        "The kernel cannot determine what code will execute inside eval() "
        "at runtime. The string content is opaque to static analysis.",

        "CANNOT_TRACE_EVAL_OUTPUT_DATAFLOW: "
        "Values produced by eval() cannot be tracked in dataflow analysis "
        "because their type and value are unknown at static analysis time.",

        "DATAFLOW_BOUNDED_TO_CALL_DEPTH_5: "
        "Argument source tracing is limited to 5 call frames. Beyond this "
        "depth, source is declared EXTERNAL_DEPENDENCY_UNRESOLVED.",
    ),
    risk_mappings=_RISK_MAPPINGS,
    linked_policies=(
        "POL-SEC-001",   # eval/exec security policy
        "POL-SEC-002",   # code injection policy
    ),
    linked_standards=(
        "CWE-94",
        "CWE-78",
        "OWASP-A03-2021",
        "BANDIT-B307",
    ),
    knowledge_citations=(
        _CITATION_BANDIT,
        _CITATION_CWE78,
        _CITATION_CWE94,
        _CITATION_ENGINEERING_JUDGMENT_EVAL,
        _CITATION_OWASP_A03,
        _CITATION_PYTHON_DOCS,
    ),
    human_review_triggers=(
        "ANY_EVAL_IN_YELLOW_OR_RED_TIER",
        "EVAL_WITH_EXTERNAL_SOURCE_ARGUMENT",
        "EVAL_IN_AUTHENTICATION_PATH",
        "EVAL_IN_WEB_REQUEST_HANDLER",
    ),
    boundary_conditions=(
        "EVAL_ARGUMENT_IS_RUNTIME_GENERATED_STRING",
        "EVAL_IN_EXEC_CHAIN",
        "EVAL_ARGUMENT_FROM_ENCRYPTED_CHANNEL",
    ),
)
