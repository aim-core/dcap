"""
******************************************************************************
 * FILE:        /src/application/policy/policy_engine.py
 * LAYER:       Application Layer
 * MODULE:      Policy Engine
 * PURPOSE:     Deterministic policy evaluation: (Node, Context, Tier) → Evidence
 * DOMAIN:      Policy Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The PolicyEngine is the central decision-making component of DCAVP.
 * It is a pure deterministic function:
 *
 *   evaluate(node, context, tier, catalog) → PolicyDecision
 *
 * For every AnalyzedNode, the engine:
 *   1. Looks up the construct definition in the catalog
 *   2. Retrieves the danger condition matching detected_state
 *   3. Retrieves the tier permission for the requested tier
 *   4. Runs the escalation pipeline (context-aware escalation rules)
 *   5. Determines boundary status
 *   6. Constructs the ExplainabilityGraph
 *   7. Computes the evidence hash
 *   8. Returns a PolicyDecision
 *
 * ESCALATION PIPELINE (deterministic, ordered):
 *   Rule E-001: If tier is RED and construct is FORBIDDEN_WITHOUT_DUAL_CONTROL
 *               → escalate to CRITICAL, outcome = BLOCK_PIPELINE
 *   Rule E-002: If call_context.has_tainted_input() and severity >= WARNING
 *               → escalate severity by one level, confidence = BOUNDED
 *   Rule E-003: If context has ISR_CONTEXT or SAFETY_CRITICAL tag
 *               → escalate to CRITICAL, human_review_required = True
 *   Rule E-004: If call_context.is_in_test_function()
 *               → downgrade to INFO (test code exemption)
 *   Rule E-005: If call_context.is_boundary_reached()
 *               → set confidence = UNKNOWN, boundary_status = boundary_reached
 *
 * Rule priority: E-001 > E-002 > E-003 > E-004 > E-005
 * E-004 (test exemption) is overridden by E-003 (safety critical)
 *
 * WHAT THE ENGINE DOES NOT DO:
 *   - Read source files (receives AnalyzedNode already parsed)
 *   - Use ML or probabilistic inference
 *   - Modify the catalog or registry
 *   - Produce side effects (pure function)
 *
 * REFERENCES:
 *   Foundation Document Section 8 — Policy Engine Design
 *   Foundation Document Section 9 — Tier System
 *   Engineering Constitution Article IV — Clean Architecture
 *
 * DEPENDENCIES:
 *   - src/domain/policies/ast_node.py
 *   - src/domain/policies/policy_model.py
 *   - src/domain/evidence/evidence_model.py
 *   - src/domain/constructs/construct_model.py
 *   - src/domain/context/context_model.py
 *   - src/infrastructure/catalog/registry/catalog_registry.py
 *
 * CONSTRAINTS:
 *   - Pure function: no I/O, no global state, no side effects
 *   - No float arithmetic (all severity is enum-based; weights are FixedWeight)
 *   - Bounded: evaluation is O(1) per node (all lookups are O(1))
 *   - Escalation rules are fixed; no runtime mutation
 *
 * DETERMINISM GUARANTEES:
 *   - Same (node, context, tier, catalog) → identical PolicyDecision
 *   - Escalation rules applied in fixed priority order
 *   - evidence_hash is SHA-256 of canonical fields
 *
 * FAILURE MODES:
 *   - ConstructNotInCatalog: node references unknown construct_id
 *   - StateNotInConstruct: detected_state not defined in construct
 *   - PolicyEngineError: any internal consistency violation
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.domain.constructs.construct_model import (
    Confidence, ConstructDefinition, DangerCondition,
    Severity, Tier, TierPermissionLevel,
)
from src.domain.context.context_model import ContextFingerprint
from src.domain.evidence.evidence_model import (
    BoundaryDeclaration, EvidenceStep, ExplainabilityGraph,
    Finding, FindingRiskMapping,
)
from src.domain.policies.ast_node import AnalyzedNode
from src.infrastructure.catalog.registry.catalog_registry import CatalogRegistry


# ─── Errors ───────────────────────────────────────────────────────────────────

class PolicyEngineError(Exception):
    """Base class for policy engine errors."""


class ConstructNotInCatalog(PolicyEngineError):
    """
    Purpose: The AnalyzedNode references a construct_id not in the catalog.
    This indicates a parser error or catalog version mismatch.
    """


class StateNotInConstruct(PolicyEngineError):
    """
    Purpose: The detected_state is not defined in the construct definition.
    The policy engine cannot evaluate an unknown state.
    """


# ─── Escalation Rule IDs (canonical names) ────────────────────────────────────

_ESC_FORBIDDEN_DUAL_CONTROL  = "ESC-001:FORBIDDEN_TIER_DUAL_CONTROL"
_ESC_TAINTED_INPUT           = "ESC-002:TAINTED_INPUT_SEVERITY_UPGRADE"
_ESC_SAFETY_CRITICAL_CONTEXT = "ESC-003:SAFETY_CRITICAL_CONTEXT"
_ESC_TEST_EXEMPTION          = "ESC-004:TEST_FUNCTION_EXEMPTION"
_ESC_BOUNDARY_REACHED        = "ESC-005:ANALYSIS_BOUNDARY_REACHED"


# ─── Severity Escalation (integer-based, no floats) ──────────────────────────

_SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO.value:     0,
    Severity.WARNING.value:  1,
    Severity.ERROR.value:    2,
    Severity.CRITICAL.value: 3,
}

_SEVERITY_FROM_LEVEL: dict[int, str] = {v: k for k, v in _SEVERITY_ORDER.items()}


def _escalate_severity(current: str, by: int = 1) -> str:
    """
    Purpose: Escalate a severity string by a fixed integer number of levels.
    Inputs: current — current Severity value string; by — levels to escalate
    Outputs: escalated Severity value string (capped at CRITICAL)
    Constraints: Integer arithmetic only; no floats
    Determinism: pure function
    """
    current_level = _SEVERITY_ORDER.get(current, 0)
    new_level = min(current_level + by, 3)   # Cap at CRITICAL (level 3)
    return _SEVERITY_FROM_LEVEL[new_level]


def _downgrade_severity(current: str, to: str = Severity.INFO.value) -> str:
    """
    Purpose: Downgrade severity to a specific level.
    Inputs: current — current severity; to — target severity (must be lower)
    Outputs: the lower of current and to
    """
    current_level = _SEVERITY_ORDER.get(current, 0)
    target_level  = _SEVERITY_ORDER.get(to, 0)
    result_level  = min(current_level, target_level)
    return _SEVERITY_FROM_LEVEL[result_level]


# ─── Policy Decision ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PolicyDecision:
    """
    Purpose: The output of one PolicyEngine.evaluate() call.
    Carries the complete, self-contained decision for one AnalyzedNode.

    Inputs:
    - node: The input AnalyzedNode
    - finding: The produced Finding (None if no finding — e.g. suppressed)
    - is_suppressed: True if the finding was suppressed (test exemption, etc.)
    - suppression_reason: Why the finding was suppressed ("" if not suppressed)
    - escalation_chain: Sorted tuple of escalation rule IDs that fired
    - blocks_pipeline: True if this finding should block CI/CD pipeline
    - requires_dual_control: True if dual-control human approval required

    Constraints:
    - finding is None iff is_suppressed is True
    - blocks_pipeline implies severity == CRITICAL
    - requires_dual_control implies tier == RED and level == FORBIDDEN_WITHOUT_DUAL_CONTROL
    """
    node: AnalyzedNode
    finding: Optional[Finding]
    is_suppressed: bool
    suppression_reason: str
    escalation_chain: tuple[str, ...]
    blocks_pipeline: bool
    requires_dual_control: bool

    def has_finding(self) -> bool:
        return self.finding is not None and not self.is_suppressed


# ─── Policy Engine ────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Purpose: Deterministic policy evaluator — the core decision engine.

    Usage:
        engine = PolicyEngine(catalog)
        decision = engine.evaluate(node, context, tier)

    The engine is STATELESS. It holds only the catalog reference (immutable).
    All evaluation state is local to each evaluate() call.
    The same engine instance can be called many times; results are independent.

    Constraints:
    - No I/O inside evaluate()
    - No global state mutation
    - All severity arithmetic uses integer operations
    - Escalation rules applied in fixed priority order (E-001 first)
    """

    def __init__(self, catalog: CatalogRegistry) -> None:
        """
        Purpose: Initialize the PolicyEngine with an immutable catalog.
        Inputs: catalog — a verified, frozen CatalogRegistry
        Constraints: catalog must be verified before passing to engine
        """
        self._catalog = catalog

    def evaluate(
        self,
        node: AnalyzedNode,
        context: ContextFingerprint,
        tier: Tier,
    ) -> PolicyDecision:
        """
        Purpose: Evaluate one AnalyzedNode and produce a PolicyDecision.

        Algorithm:
        1. Look up construct in catalog → ConstructDefinition
        2. Look up danger condition for detected_state → DangerCondition (or None)
        3. Get tier permission → TierPermission
        4. If no danger condition: produce INFO finding (construct seen, no danger)
        5. Run escalation pipeline (E-001 through E-005, priority order)
        6. Build ExplainabilityGraph
        7. Build Finding
        8. Return PolicyDecision

        Inputs:
        - node: The AnalyzedNode to evaluate
        - context: The ContextFingerprint of the project
        - tier: The analysis tier (determines strictness)

        Outputs: PolicyDecision (immutable)

        Failure:
        - ConstructNotInCatalog: node.construct_id not in catalog
        - StateNotInConstruct: detected_state not valid for this construct

        Determinism: same inputs → identical PolicyDecision
        Complexity: O(1) — all operations are constant-time lookups
        """
        # ── Step 1: Catalog lookup ─────────────────────────────────────────
        construct = self._catalog.get_construct(node.construct_id)
        if construct is None:
            raise ConstructNotInCatalog(
                f"Construct '{node.construct_id}' not found in catalog "
                f"(version: {self._catalog.metadata.catalog_version}). "
                f"Registered: {list(self._catalog.list_all_ids())}"
            )

        # ── Step 2: Danger condition lookup ───────────────────────────────
        danger_condition = construct.get_danger_condition(node.detected_state)

        # ── Step 3: Tier permission ────────────────────────────────────────
        tier_permission = construct.get_tier_permission(tier)

        # ── Step 4: Base severity and confidence ──────────────────────────
        if danger_condition is not None:
            base_severity   = danger_condition.severity
            base_confidence = danger_condition.confidence
        else:
            # Construct seen in non-dangerous state → INFO
            base_severity   = Severity.INFO.value
            base_confidence = Confidence.CERTAIN.value

        # ── Step 5: Escalation pipeline ───────────────────────────────────
        (
            final_severity,
            final_confidence,
            escalation_chain,
            is_suppressed,
            suppression_reason,
            human_review_required,
            blocks_pipeline,
            requires_dual_control,
            boundaries,
            boundary_status,
        ) = self._run_escalation_pipeline(
            node=node,
            construct=construct,
            danger_condition=danger_condition,
            base_severity=base_severity,
            base_confidence=base_confidence,
            tier=tier,
            tier_permission_level=tier_permission.level,
            context=context,
        )

        # ── Step 6: Build ExplainabilityGraph ─────────────────────────────
        evidence_chain = self._build_evidence_chain(node, danger_condition, escalation_chain)
        logic_expr = self._build_logic_expression(node, context, escalation_chain)

        graph = ExplainabilityGraph(
            base_policy=f"POL-{construct.construct_id.split('-')[1]}-001",
            base_policy_rationale=(
                f"Construct '{construct.construct_name}' is defined in catalog "
                f"v{construct.catalog_version}. "
                + (danger_condition.description if danger_condition else "No dangerous state detected.")
            ),
            triggered_by_policy=f"POL-{construct.construct_id.split('-')[1]}-001",
            triggered_by_version=construct.catalog_version,
            escalated_by_rules=tuple(sorted(escalation_chain)),
            escalation_conditions=tuple(sorted(
                self._escalation_conditions(node, context, tier, tier_permission.level)
            )),
            mapped_standards=construct.linked_standards,
            evidence_chain=tuple(evidence_chain),
            logic_expression=logic_expr,
        )

        # ── Step 7: Build Finding ──────────────────────────────────────────
        finding_id = self._next_finding_id()
        risk_mappings = tuple(
            FindingRiskMapping(
                risk_type=rm.risk_type,
                weight=rm.weight,
                context_note=f"Via {construct.construct_id} in {tier.value} tier",
            )
            for rm in sorted(construct.risk_mappings, key=lambda r: r.risk_type)
        )

        evidence_hash = self._compute_evidence_hash(
            node.canonical_location, final_severity, final_confidence, logic_expr
        )

        reviewer_qualification = ""
        if human_review_required:
            reviewer_qualification = "SAFETY-ENGINEER" if (
                "ISR_CONTEXT" in context.context_tags or
                "SAFETY_CRITICAL" in context.context_tags
            ) else "SENIOR-DEVELOPER"

        finding = Finding(
            finding_id=finding_id,
            canonical_location=node.canonical_location,
            construct_id=node.construct_id,
            construct_name=construct.construct_name,
            detected_state=node.detected_state,
            severity=final_severity,
            confidence=final_confidence,
            policy=graph.triggered_by_policy,
            policy_version=construct.catalog_version,
            escalation_chain=tuple(escalation_chain),
            risk_mappings=risk_mappings,
            standards=construct.linked_standards,
            explainability_graph=graph,
            boundary_status=boundary_status,
            boundaries=tuple(boundaries),
            human_review_required=human_review_required,
            reviewer_qualification=reviewer_qualification,
            evidence_hash=evidence_hash,
        )

        return PolicyDecision(
            node=node,
            finding=None if is_suppressed else finding,
            is_suppressed=is_suppressed,
            suppression_reason=suppression_reason,
            escalation_chain=tuple(escalation_chain),
            blocks_pipeline=blocks_pipeline,
            requires_dual_control=requires_dual_control,
        )

    # ─── Escalation Pipeline ──────────────────────────────────────────────────

    def _run_escalation_pipeline(
        self,
        node: AnalyzedNode,
        construct: ConstructDefinition,
        danger_condition: Optional[DangerCondition],
        base_severity: str,
        base_confidence: str,
        tier: Tier,
        tier_permission_level: str,
        context: ContextFingerprint,
    ) -> tuple:
        """
        Purpose: Run the full escalation pipeline and return all decision fields.
        Rules are applied in priority order (E-001 first; E-004 can be overridden by E-003).

        Returns: (severity, confidence, chain, is_suppressed, suppression_reason,
                  human_review, blocks_pipeline, dual_control, boundaries, boundary_status)
        """
        severity    = base_severity
        confidence  = base_confidence
        chain: list[str] = []
        is_suppressed       = False
        suppression_reason  = ""
        human_review        = False
        blocks_pipeline     = False
        dual_control        = False
        boundaries: list[BoundaryDeclaration] = []
        boundary_status     = "resolved"

        # E-001: FORBIDDEN tier — dual-control required ────────────────────
        if tier_permission_level == TierPermissionLevel.FORBIDDEN_WITHOUT_DUAL_CONTROL.value:
            if danger_condition is not None:
                severity       = Severity.CRITICAL.value
                confidence     = Confidence.CERTAIN.value
                human_review   = True
                blocks_pipeline = True
                dual_control   = True
                chain.append(_ESC_FORBIDDEN_DUAL_CONTROL)

        # E-004: Test exemption (applied BEFORE E-003; E-003 will override) ─
        test_exemption_applied = False
        if node.call_context.is_in_test_function and danger_condition is not None:
            if severity not in (Severity.CRITICAL.value,):
                severity = _downgrade_severity(severity, to=Severity.INFO.value)
                is_suppressed = True
                suppression_reason = (
                    f"Finding in test function '{node.call_context.enclosing_function_name}' "
                    f"downgraded to INFO (test code exemption). "
                    f"Exemption does NOT apply in CRITICAL or safety-critical contexts."
                )
                chain.append(_ESC_TEST_EXEMPTION)
                test_exemption_applied = True

        # E-003: Safety-critical context — overrides test exemption ─────────
        safety_tags = frozenset({"ISR_CONTEXT", "SAFETY_CRITICAL", "KERNEL_CONTEXT",
                                 "IEC_61508_SCOPE", "ISO_26262_SCOPE", "DO_178C_SCOPE"})
        if safety_tags & frozenset(context.context_tags):
            if danger_condition is not None:
                severity      = Severity.CRITICAL.value
                confidence    = Confidence.CERTAIN.value if confidence == Confidence.CERTAIN.value \
                                else Confidence.BOUNDED.value
                human_review  = True
                blocks_pipeline = True
                # Override test exemption
                if test_exemption_applied:
                    is_suppressed = False
                    suppression_reason = ""
                chain.append(_ESC_SAFETY_CRITICAL_CONTEXT)

        # E-002: Tainted input — escalate severity ─────────────────────────
        if (not is_suppressed
                and node.call_context.has_tainted_input()
                and danger_condition is not None
                and _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER[Severity.CRITICAL.value]):
            severity   = _escalate_severity(severity, by=1)
            confidence = Confidence.BOUNDED.value
            chain.append(_ESC_TAINTED_INPUT)

        # E-005: Boundary reached — downgrade confidence ───────────────────
        if node.call_context.is_boundary_reached():
            if confidence == Confidence.CERTAIN.value:
                confidence = Confidence.BOUNDED.value
            boundary_status = "boundary_reached"
            chain.append(_ESC_BOUNDARY_REACHED)
            boundaries.append(BoundaryDeclaration(
                boundary_type="ANALYSIS_BOUNDARY_REACHED",
                location=node.canonical_location,
                impact=(
                    "Argument source could not be fully traced. "
                    "Confidence downgraded from CERTAIN to BOUNDED."
                ),
                recommendation=(
                    "Provide type annotations or explicit variable assignments "
                    "to enable deeper dataflow analysis."
                ),
                human_review_required=tier.is_at_least(Tier.YELLOW),
            ))

        return (
            severity, confidence, chain,
            is_suppressed, suppression_reason,
            human_review, blocks_pipeline, dual_control,
            boundaries, boundary_status,
        )

    # ─── Evidence Helpers ─────────────────────────────────────────────────────

    def _build_evidence_chain(
        self,
        node: AnalyzedNode,
        danger_condition: Optional[DangerCondition],
        escalation_chain: list[str],
    ) -> list[EvidenceStep]:
        """
        Purpose: Construct the ordered evidence chain for the ExplainabilityGraph.
        Each step represents one deterministic observation during analysis.
        """
        steps: list[EvidenceStep] = []

        # Step 0: Node detected
        step0_hash = hashlib.sha256(
            f"step:0:{node.canonical_location}:{node.construct_id}:{node.detected_state}"
            .encode('utf-8')
        ).hexdigest()
        steps.append(EvidenceStep(
            step_index=0,
            location=node.canonical_location,
            description=(
                f"Construct '{node.construct_id}' detected in state '{node.detected_state}'. "
                f"AST node type: {node.ast_node_type}."
            ),
            ast_node_type=node.ast_node_type,
            evidence_hash=f"sha256:{step0_hash}",
        ))

        # Step 1: Danger condition matched (if any)
        if danger_condition is not None:
            step1_hash = hashlib.sha256(
                f"step:1:{node.canonical_location}:{danger_condition.condition_id}"
                .encode('utf-8')
            ).hexdigest()
            steps.append(EvidenceStep(
                step_index=1,
                location=node.canonical_location,
                description=(
                    f"Danger condition '{danger_condition.condition_id}' matched: "
                    f"{danger_condition.description[:200]}"
                ),
                ast_node_type=node.ast_node_type,
                evidence_hash=f"sha256:{step1_hash}",
            ))

        # Step 2: Escalation applied (if any)
        if escalation_chain:
            step2_hash = hashlib.sha256(
                f"step:2:{node.canonical_location}:{','.join(sorted(escalation_chain))}"
                .encode('utf-8')
            ).hexdigest()
            steps.append(EvidenceStep(
                step_index=2,
                location=node.canonical_location,
                description=f"Escalation rules applied: {', '.join(escalation_chain)}",
                ast_node_type=node.ast_node_type,
                evidence_hash=f"sha256:{step2_hash}",
            ))

        return steps

    def _build_logic_expression(
        self,
        node: AnalyzedNode,
        context: ContextFingerprint,
        escalation_chain: list[str],
    ) -> str:
        """
        Purpose: Build the boolean logic expression that produced the finding.
        Format: UPPER_SNAKE_CASE tokens joined by AND/OR/NOT operators.
        This is human-readable and machine-parseable for audit purposes.
        """
        parts = [
            f"CONSTRUCT_ID_IS_{node.construct_id.replace('-', '_')}",
            f"DETECTED_STATE_IS_{node.detected_state.upper()}",
            f"TIER_IS_{context.recommended_tier().value}",
        ]
        if node.call_context.has_tainted_input():
            parts.append("TAINTED_INPUT_PRESENT")
        if node.call_context.is_in_test_function:
            parts.append("IN_TEST_FUNCTION")
        for tag in sorted(context.context_tags):
            if tag in ("ISR_CONTEXT", "SAFETY_CRITICAL", "KERNEL_CONTEXT"):
                parts.append(f"CONTEXT_TAG_{tag}")
        for rule in escalation_chain:
            rule_token = rule.split(":")[0].replace("-", "_")
            parts.append(f"ESCALATION_{rule_token}")
        return " AND ".join(parts)

    def _escalation_conditions(
        self,
        node: AnalyzedNode,
        context: ContextFingerprint,
        tier: Tier,
        tier_permission_level: str,
    ) -> list[str]:
        """Collect human-readable escalation condition descriptions."""
        conditions = []
        if tier_permission_level == TierPermissionLevel.FORBIDDEN_WITHOUT_DUAL_CONTROL.value:
            conditions.append(f"Tier {tier.value}: construct is FORBIDDEN_WITHOUT_DUAL_CONTROL")
        if node.call_context.has_tainted_input():
            conditions.append(f"Tainted input sources: {list(node.call_context.argument_sources)}")
        safety_tags = frozenset({"ISR_CONTEXT", "SAFETY_CRITICAL", "KERNEL_CONTEXT"})
        active = safety_tags & frozenset(context.context_tags)
        if active:
            conditions.append(f"Safety-critical context tags active: {sorted(active)}")
        if node.call_context.is_in_test_function:
            conditions.append("Enclosing function is a test function")
        if node.call_context.is_boundary_reached():
            conditions.append("Analysis boundary reached in argument source tracing")
        return conditions

    def _compute_evidence_hash(
        self,
        location: str,
        severity: str,
        confidence: str,
        logic_expression: str,
    ) -> str:
        """
        Purpose: Compute the finding's evidence hash.
        Deterministic: same inputs → same hash.
        """
        canonical = json.dumps(
            {"loc": location, "sev": severity, "conf": confidence, "expr": logic_expression},
            sort_keys=True, separators=(',', ':'), ensure_ascii=False,
        ).encode('utf-8')
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def _next_finding_id(self) -> str:
        """
        Purpose: Generate a finding ID.
        In Phase 4, IDs are UUID-based (finding_count not available here).
        The CEFArtifact builder re-sequences IDs to F-00001..F-NNNNN.
        Returns F-00001 as placeholder (re-sequenced by artifact builder).
        """
        return "F-00001"
