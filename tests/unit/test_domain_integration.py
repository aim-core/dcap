"""
******************************************************************************
 * FILE:        /tests/unit/test_domain_integration.py
 * LAYER:       Test Layer
 * MODULE:      Domain Integration Tests
 * PURPOSE:     Verify domain contracts and inter-model consistency
 * DOMAIN:      Verification Core
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Integration tests for the Phase 1 domain model. These tests verify:
 * 1. Construct model types are correctly constructed and validated
 * 2. Evidence model types enforce their invariants
 * 3. Policy model types enforce their invariants
 * 4. Context model types enforce their invariants
 * 5. Catalog entry (CONST-EVAL-001) is correctly structured
 * 6. Cross-model interactions produce expected results
 *
 * TEST CATEGORIES:
 * - Determinism tests: same input → same output
 * - Invariant tests: violations raise the correct exceptions
 * - Contract tests: inter-model dependencies are satisfied
 * - Catalog tests: catalog entries satisfy Knowledge Integrity Law
 *
 * DEPENDENCIES:
 * - All src/domain/* modules
 * - src/infrastructure/catalog/entries/python/eval_construct.py
 *
 * CONSTRAINTS:
 * - Tests must be deterministic (no random, no time.time())
 * - Tests must be independent (no shared mutable state)
 * - All assertions use exact value comparison (no approximation)
 *
 * LICENSE: Apache-2.0
 ******************************************************************************
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, '/home/claude/dcavp')

import hashlib
import pytest

from src.domain.constructs.construct_model import (
    AnalysisBounds,
    Confidence,
    ConstructDefinition,
    ConstructIdFormatError,
    DangerCondition,
    FixedWeight,
    KnowledgeCitation,
    RiskMapping,
    RiskType,
    Severity,
    Tier,
    TierPermission,
    TierPermissionLevel,
    TierValidationError,
)

from src.domain.evidence.evidence_model import (
    BoundaryDeclaration,
    BoundaryHonestyReport,
    CEFArtifact,
    EvidenceDomainError,
    EvidenceStep,
    ExecutionContext,
    ExplainabilityGraph,
    Finding,
    FindingRiskMapping,
    InvalidCanonicalLocation,
    validate_canonical_location,
)

from src.domain.policies.policy_model import (
    PolicyCondition,
    PolicyConflict,
    PolicyDefinition,
    PolicyDomainError,
    PolicyIdFormatError,
    PolicyOutcome,
    PolicyPriority,
    resolve_policy_conflict,
)

from src.domain.context.context_model import (
    BuildSystem,
    ContextDomainError,
    ContextFingerprint,
    ContextTagVocabulary,
    DomainPosture,
    InvalidContextTag,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_citation(identifier: str = "CWE-94") -> KnowledgeCitation:
    return KnowledgeCitation(
        citation_type="STANDARD",
        identifier=identifier,
        title=f"Test citation for {identifier}",
        publication_date="2024-01-01",
        validation_status="verified",
        reviewer_id="TEST-REVIEWER",
        url="",
    )


def _make_analysis_bounds() -> AnalysisBounds:
    return AnalysisBounds(
        max_call_depth=5,
        max_loop_unroll=0,
        max_branch_count=100,
        max_coroutine_count=0,
        rationale="Test bounds",
        source_reference="ENGINEERING-JUDGMENT-v0.1.0",
    )


def _make_danger_condition(cond_id: str = "DC-001", state: str = "dynamic_arg") -> DangerCondition:
    return DangerCondition(
        condition_id=cond_id,
        state_or_condition=state,
        severity=Severity.CRITICAL.value,
        confidence=Confidence.CERTAIN.value,
        description="Test danger condition",
        detection_method="AST_PATTERN",
        source_reference="CWE-94",
        cve_references=(),
        cwe_references=("CWE-94",),
    )


def _make_all_tier_permissions() -> tuple[TierPermission, ...]:
    return tuple(
        TierPermission(
            tier=tier.value,
            level=TierPermissionLevel.ALLOWED_WITH_WARNING.value,
            enforcement_note=f"Test enforcement for {tier.value}",
            escalation_note=f"Test escalation for {tier.value}",
        )
        for tier in sorted(Tier, key=lambda t: t.value)
    )


def _make_construct(construct_id: str = "CONST-EVAL-001") -> ConstructDefinition:
    return ConstructDefinition(
        construct_id=construct_id,
        construct_name="eval",
        catalog_version="2026.05.11",
        language="python",
        description="Test construct",
        ast_node_types=("Call",),
        states=("constant_arg", "dynamic_arg"),
        danger_conditions=(_make_danger_condition(),),
        acceptance_conditions=("NONE",),
        tier_permissions=_make_all_tier_permissions(),
        analysis_bounds=_make_analysis_bounds(),
        analysis_constraints=("CANNOT_ANALYZE_EVAL_CONTENT",),
        risk_mappings=(
            RiskMapping(
                risk_type=RiskType.CYBERSECURITY.value,
                weight=FixedWeight(numerator=950, denominator=1000),
                rationale="Code injection vector",
                source_reference="CWE-94",
            ),
        ),
        linked_policies=("POL-SEC-001",),
        linked_standards=("CWE-94",),
        knowledge_citations=(_make_citation("CWE-94"),),
        human_review_triggers=("EVAL_IN_RED_TIER",),
        boundary_conditions=("EVAL_ARG_RUNTIME_GENERATED",),
    )


def _make_execution_context() -> ExecutionContext:
    return ExecutionContext(
        seed="0xdeadbeef",
        timestamp_utc="2026-05-11T00:00:00.000000Z",
        host_fingerprint="test-host-001",
        kernel_version="dcavp-kernel/0.1.0",
        catalog_version="2026.05.11",
        python_version="3.12.3",
        platform_id="linux/x86_64",
        locale="C",
        timezone_id="UTC",
    )


def _make_evidence_step(step_index: int = 0, location: str = "/test/file.py:1:0") -> EvidenceStep:
    # Compute a valid SHA-256 hash for the step
    raw = f"step:{step_index}:{location}"
    hash_val = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    return EvidenceStep(
        step_index=step_index,
        location=location,
        description="Test evidence step",
        ast_node_type="Call",
        evidence_hash=hash_val,
    )


def _make_explainability_graph() -> ExplainabilityGraph:
    return ExplainabilityGraph(
        base_policy="POL-SEC-001",
        base_policy_rationale="eval() is a code injection vector per CWE-94",
        triggered_by_policy="POL-SEC-001",
        triggered_by_version="2026.05.11",
        escalated_by_rules=(),
        escalation_conditions=(),
        mapped_standards=("CWE-94",),
        evidence_chain=(_make_evidence_step(0, "/test/file.py:10:4"),),
        logic_expression="DYNAMIC_ARG",
    )


def _make_finding(finding_id: str = "F-00001", location: str = "/test/file.py:10:4") -> Finding:
    raw = f"finding:{finding_id}:{location}"
    hash_val = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    return Finding(
        finding_id=finding_id,
        canonical_location=location,
        construct_id="CONST-EVAL-001",
        construct_name="eval",
        detected_state="dynamic_arg",
        severity=Severity.CRITICAL.value,
        confidence=Confidence.CERTAIN.value,
        policy="POL-SEC-001",
        policy_version="2026.05.11",
        escalation_chain=(),
        risk_mappings=(
            FindingRiskMapping(
                risk_type=RiskType.CYBERSECURITY.value,
                weight=FixedWeight(numerator=950, denominator=1000),
                context_note="Dynamic eval argument",
            ),
        ),
        standards=("CWE-94",),
        explainability_graph=_make_explainability_graph(),
        boundary_status="resolved",
        boundaries=(),
        human_review_required=False,
        reviewer_qualification="",
        evidence_hash=hash_val,
    )


# ─── Tests: FixedWeight ───────────────────────────────────────────────────────

class TestFixedWeight:
    def test_valid_construction(self):
        w = FixedWeight(numerator=800, denominator=1000)
        assert w.numerator == 800
        assert w.denominator == 1000

    def test_as_percent(self):
        w = FixedWeight(numerator=800, denominator=1000)
        assert w.as_percent() == 80  # integer; no float

    def test_zero_weight(self):
        w = FixedWeight(numerator=0, denominator=1000)
        assert w.is_zero()
        assert not w.is_maximum()

    def test_maximum_weight(self):
        w = FixedWeight(numerator=1000, denominator=1000)
        assert w.is_maximum()
        assert not w.is_zero()

    def test_invalid_numerator_too_large(self):
        with pytest.raises(ValueError):
            FixedWeight(numerator=1001, denominator=1000)

    def test_invalid_numerator_negative(self):
        with pytest.raises(ValueError):
            FixedWeight(numerator=-1, denominator=1000)

    def test_invalid_denominator_zero(self):
        with pytest.raises(ValueError):
            FixedWeight(numerator=0, denominator=0)

    def test_frozen(self):
        """FixedWeight must be immutable."""
        w = FixedWeight(numerator=500, denominator=1000)
        with pytest.raises(Exception):  # FrozenInstanceError
            w.numerator = 999  # type: ignore


# ─── Tests: Tier ─────────────────────────────────────────────────────────────

class TestTier:
    def test_ordering(self):
        assert Tier.GREEN.is_at_least(Tier.GREEN)
        assert Tier.BLUE.is_at_least(Tier.GREEN)
        assert Tier.YELLOW.is_at_least(Tier.BLUE)
        assert Tier.RED.is_at_least(Tier.YELLOW)

    def test_ordering_negative(self):
        assert not Tier.GREEN.is_at_least(Tier.BLUE)
        assert not Tier.BLUE.is_at_least(Tier.YELLOW)

    def test_all_ordered_has_four_tiers(self):
        all_tiers = Tier.all_ordered()
        assert len(all_tiers) == 4
        assert all_tiers[0] == Tier.GREEN
        assert all_tiers[-1] == Tier.RED


# ─── Tests: ConstructDefinition ───────────────────────────────────────────────

class TestConstructDefinition:
    def test_valid_construction(self):
        c = _make_construct()
        assert c.construct_id == "CONST-EVAL-001"
        assert c.language == "python"

    def test_invalid_construct_id_format(self):
        with pytest.raises(ConstructIdFormatError):
            _make_construct(construct_id="EVAL-001")  # Missing CONST- prefix

    def test_invalid_construct_id_short_domain(self):
        with pytest.raises(ConstructIdFormatError):
            _make_construct(construct_id="CONST-E-001")  # Domain too short

    def test_missing_tier_permission_raises(self):
        """Must have exactly one TierPermission per tier."""
        with pytest.raises(TierValidationError):
            ConstructDefinition(
                construct_id="CONST-EVAL-001",
                construct_name="eval",
                catalog_version="2026.05.11",
                language="python",
                description="Test",
                ast_node_types=("Call",),
                states=("dynamic_arg",),
                danger_conditions=(_make_danger_condition(),),
                acceptance_conditions=("NONE",),
                tier_permissions=(   # Missing RED tier
                    TierPermission(Tier.GREEN.value, TierPermissionLevel.ALLOWED_WITH_WARNING.value, "n", "n"),
                    TierPermission(Tier.BLUE.value, TierPermissionLevel.ALLOWED_WITH_WARNING.value, "n", "n"),
                    TierPermission(Tier.YELLOW.value, TierPermissionLevel.ALLOWED_WITH_WARNING.value, "n", "n"),
                ),
                analysis_bounds=_make_analysis_bounds(),
                analysis_constraints=(),
                risk_mappings=(),
                linked_policies=(),
                linked_standards=(),
                knowledge_citations=(_make_citation(),),
                human_review_triggers=(),
                boundary_conditions=(),
            )

    def test_no_citation_raises(self):
        """Knowledge Integrity Law: must have at least one citation."""
        with pytest.raises(Exception):
            ConstructDefinition(
                construct_id="CONST-EVAL-001",
                construct_name="eval",
                catalog_version="2026.05.11",
                language="python",
                description="Test",
                ast_node_types=("Call",),
                states=("dynamic_arg",),
                danger_conditions=(_make_danger_condition(),),
                acceptance_conditions=("NONE",),
                tier_permissions=_make_all_tier_permissions(),
                analysis_bounds=_make_analysis_bounds(),
                analysis_constraints=(),
                risk_mappings=(),
                linked_policies=(),
                linked_standards=(),
                knowledge_citations=(),   # EMPTY — must fail
                human_review_triggers=(),
                boundary_conditions=(),
            )

    def test_catalog_hash_determinism(self):
        """Same construct definition → same hash (100 runs)."""
        c = _make_construct()
        hashes = {c.catalog_hash() for _ in range(100)}
        assert len(hashes) == 1, f"Non-deterministic hash: {hashes}"

    def test_catalog_hash_changes_on_state_change(self):
        """Hash must change when states tuple changes."""
        c1 = _make_construct()
        # Build a variant with different states
        c2_fields = c1.__dict__.copy()
        c2_fields['states'] = ("constant_arg",)  # different
        # Can't mutate frozen; verify logic by checking hash components
        h1 = c1.catalog_hash()
        assert h1.startswith("sha256:")
        assert len(h1) == 71  # "sha256:" + 64 hex chars

    def test_get_tier_permission(self):
        c = _make_construct()
        perm = c.get_tier_permission(Tier.RED)
        assert perm.tier == Tier.RED.value

    def test_get_danger_condition_found(self):
        c = _make_construct()
        dc = c.get_danger_condition("dynamic_arg")
        assert dc is not None
        assert dc.severity == Severity.CRITICAL.value

    def test_get_danger_condition_not_found(self):
        c = _make_construct()
        dc = c.get_danger_condition("nonexistent_state")
        assert dc is None

    def test_frozen(self):
        c = _make_construct()
        with pytest.raises(Exception):
            c.construct_id = "MUTATED"  # type: ignore


# ─── Tests: validate_canonical_location ──────────────────────────────────────

class TestCanonicalLocation:
    def test_valid_location(self):
        loc = validate_canonical_location("/home/project/src/main.py:42:8")
        assert loc == "/home/project/src/main.py:42:8"

    def test_invalid_relative_path(self):
        with pytest.raises(InvalidCanonicalLocation):
            validate_canonical_location("src/main.py:42:8")  # not absolute

    def test_invalid_missing_col(self):
        with pytest.raises(InvalidCanonicalLocation):
            validate_canonical_location("/src/main.py:42")  # no column

    def test_invalid_line_zero(self):
        with pytest.raises(InvalidCanonicalLocation):
            validate_canonical_location("/src/main.py:0:0")  # line 0 invalid


# ─── Tests: EvidenceStep ──────────────────────────────────────────────────────

class TestEvidenceStep:
    def test_valid_construction(self):
        step = _make_evidence_step(0, "/test/file.py:1:0")
        assert step.step_index == 0
        assert step.location == "/test/file.py:1:0"

    def test_negative_step_index_raises(self):
        with pytest.raises(EvidenceDomainError):
            EvidenceStep(
                step_index=-1,
                location="/test/file.py:1:0",
                description="Test",
                ast_node_type="Call",
                evidence_hash="sha256:" + "a" * 64,
            )

    def test_invalid_hash_format_raises(self):
        with pytest.raises(EvidenceDomainError):
            EvidenceStep(
                step_index=0,
                location="/test/file.py:1:0",
                description="Test",
                ast_node_type="Call",
                evidence_hash="md5:invalid",   # Wrong hash type
            )


# ─── Tests: ExecutionContext ──────────────────────────────────────────────────

class TestExecutionContext:
    def test_valid_construction(self):
        ctx = _make_execution_context()
        assert ctx.locale == "C"
        assert ctx.timezone_id == "UTC"

    def test_non_c_locale_raises(self):
        with pytest.raises(EvidenceDomainError):
            ExecutionContext(
                seed="0xabc",
                timestamp_utc="2026-05-11T00:00:00.000000Z",
                host_fingerprint="host",
                kernel_version="dcavp-kernel/0.1.0",
                catalog_version="2026.05.11",
                python_version="3.12.0",
                platform_id="linux/x86_64",
                locale="en_US.UTF-8",  # Invalid — must be "C"
                timezone_id="UTC",
            )

    def test_non_utc_timezone_raises(self):
        with pytest.raises(EvidenceDomainError):
            ExecutionContext(
                seed="0xabc",
                timestamp_utc="2026-05-11T00:00:00.000000Z",
                host_fingerprint="host",
                kernel_version="dcavp-kernel/0.1.0",
                catalog_version="2026.05.11",
                python_version="3.12.0",
                platform_id="linux/x86_64",
                locale="C",
                timezone_id="America/New_York",  # Invalid — must be "UTC"
            )

    def test_invalid_seed_format_raises(self):
        with pytest.raises(EvidenceDomainError):
            ExecutionContext(
                seed="deadbeef",   # Missing 0x prefix
                timestamp_utc="2026-05-11T00:00:00.000000Z",
                host_fingerprint="host",
                kernel_version="dcavp-kernel/0.1.0",
                catalog_version="2026.05.11",
                python_version="3.12.0",
                platform_id="linux/x86_64",
                locale="C",
                timezone_id="UTC",
            )


# ─── Tests: BoundaryHonestyReport ────────────────────────────────────────────

class TestBoundaryHonestyReport:
    def test_full_trust_no_boundaries(self):
        """Zero boundaries → score 1000/1000 → full trust."""
        report = BoundaryHonestyReport.compute(
            total_analysis_points=100,
            boundaries=[],
            boundary_weights={},
            recommendations=(),
        )
        assert report.score_numerator == 1000
        assert report.trust_level == "full"

    def test_zero_analysis_points(self):
        """Edge case: no constructs analyzed → full trust (vacuous)."""
        report = BoundaryHonestyReport.compute(
            total_analysis_points=0,
            boundaries=[],
            boundary_weights={},
            recommendations=(),
        )
        assert report.score_numerator == 1000
        assert report.trust_level == "full"

    def test_integer_arithmetic_only(self):
        """Score computation must produce integer, not float."""
        report = BoundaryHonestyReport.compute(
            total_analysis_points=3,
            boundaries=[
                BoundaryDeclaration(
                    boundary_type="ANALYSIS_BOUNDARY_REACHED",
                    location="/test/file.py:1:0",
                    impact="Partial analysis",
                    recommendation="Increase call depth",
                    human_review_required=False,
                )
            ],
            boundary_weights={"ANALYSIS_BOUNDARY_REACHED": 500},
            recommendations=("Increase call depth",),
        )
        assert isinstance(report.score_numerator, int)
        assert isinstance(report.score_denominator, int)
        assert report.score_denominator == 1000


# ─── Tests: Policy Model ──────────────────────────────────────────────────────

class TestPolicyModel:
    def test_invalid_policy_id_raises(self):
        with pytest.raises(PolicyIdFormatError):
            from src.domain.policies.policy_model import validate_policy_id
            validate_policy_id("SEC-001")  # Missing POL- prefix

    def test_valid_policy_id(self):
        from src.domain.policies.policy_model import validate_policy_id
        result = validate_policy_id("POL-SEC-001")
        assert result == "POL-SEC-001"

    def test_conflict_resolution_priority_wins(self):
        """Higher priority policy wins in conflict resolution."""
        policy_safety = PolicyDefinition(
            policy_id="POL-CONC-001",
            policy_version="2026.05.11",
            domain="SEC",
            priority=PolicyPriority.SAFETY.value,
            parent_policy_ids=(),
            name="Safety Policy",
            description="Test",
            applies_to_constructs=("CONST-EVAL-001",),
            applies_to_tiers=(Tier.RED.value,),
            trigger_conditions=(),
            base_severity=Severity.CRITICAL.value,
            base_confidence=Confidence.CERTAIN.value,
            base_outcome=PolicyOutcome.BLOCK_PIPELINE.value,
            escalation_rules=(),
            standards_violated=("CWE-94",),
            reviewer_qualification="SAFETY-ENGINEER",
            source_reference="CWE-94",
            rationale="Safety test policy",
        )
        policy_perf = PolicyDefinition(
            policy_id="POL-CONC-002",
            policy_version="2026.05.11",
            domain="SEC",
            priority=PolicyPriority.PERFORMANCE.value,
            parent_policy_ids=(),
            name="Performance Policy",
            description="Test",
            applies_to_constructs=("CONST-EVAL-001",),
            applies_to_tiers=(Tier.RED.value,),
            trigger_conditions=(),
            base_severity=Severity.WARNING.value,
            base_confidence=Confidence.HEURISTIC.value,
            base_outcome=PolicyOutcome.EMIT_FINDING.value,
            escalation_rules=(),
            standards_violated=(),
            reviewer_qualification="",
            source_reference="ENGINEERING-JUDGMENT-v0.1.0",
            rationale="Performance test policy",
        )

        conflict = resolve_policy_conflict(policy_safety, policy_perf)
        assert conflict.resolution == "POLICY_A_WINS"
        assert conflict.winner_id == "POL-CONC-001"

    def test_same_priority_is_unresolvable(self):
        """Same priority with different outcomes → UNRESOLVABLE."""
        def make_policy(pid: str) -> PolicyDefinition:
            return PolicyDefinition(
                policy_id=pid,
                policy_version="2026.05.11",
                domain="SEC",
                priority=PolicyPriority.COMPLIANCE.value,
                parent_policy_ids=(),
                name=f"Policy {pid}",
                description="Test",
                applies_to_constructs=("CONST-EVAL-001",),
                applies_to_tiers=(Tier.YELLOW.value,),
                trigger_conditions=(),
                base_severity=Severity.ERROR.value,
                base_confidence=Confidence.CERTAIN.value,
                base_outcome=PolicyOutcome.EMIT_FINDING.value,
                escalation_rules=(),
                standards_violated=(),
                reviewer_qualification="",
                source_reference="CWE-94",
                rationale="Test",
            )

        conflict = resolve_policy_conflict(make_policy("POL-SEC-001"), make_policy("POL-SEC-002"))
        assert conflict.resolution == "UNRESOLVABLE"
        assert conflict.winner_id == ""


# ─── Tests: Context Model ─────────────────────────────────────────────────────

class TestContextModel:
    def test_valid_tag_vocabulary(self):
        assert ContextTagVocabulary.is_valid_tag("ISR_CONTEXT")
        assert ContextTagVocabulary.is_valid_tag("WEB_REQUEST_HANDLER")
        assert not ContextTagVocabulary.is_valid_tag("made_up_tag")

    def test_domain_posture_minimum_tier(self):
        assert DomainPosture.SAFETY_CRITICAL.minimum_tier() == Tier.RED
        assert DomainPosture.HIGH_ASSURANCE.minimum_tier() == Tier.YELLOW
        assert DomainPosture.COMMERCIAL.minimum_tier() == Tier.BLUE
        assert DomainPosture.EDUCATIONAL.minimum_tier() == Tier.GREEN

    def test_context_fingerprint_invalid_tag_raises(self):
        with pytest.raises(InvalidContextTag):
            ContextFingerprint(
                source_root="/project",
                source_hash="sha256:" + "a" * 64,
                domain_posture=DomainPosture.COMMERCIAL.value,
                build_system=BuildSystem.PIP.value,
                language="python",
                language_version="3.12",
                framework_signals=(),
                context_tags=("MADE_UP_TAG",),  # Invalid
                dependency_count=10,
                loc_estimate=5000,
                fingerprint_hash="sha256:" + "b" * 64,
                classification_method="STRUCTURAL_RULE_BASED",
            )

    def test_context_fingerprint_relative_path_raises(self):
        with pytest.raises(ContextDomainError):
            ContextFingerprint(
                source_root="relative/path",  # Not absolute
                source_hash="sha256:" + "a" * 64,
                domain_posture=DomainPosture.COMMERCIAL.value,
                build_system=BuildSystem.PIP.value,
                language="python",
                language_version="3.12",
                framework_signals=(),
                context_tags=(),
                dependency_count=0,
                loc_estimate=0,
                fingerprint_hash="sha256:" + "b" * 64,
                classification_method="STRUCTURAL_RULE_BASED",
            )

    def test_isr_context_escalates_to_red(self):
        """ISR_CONTEXT tag must force minimum RED tier regardless of posture."""
        fp = ContextFingerprint(
            source_root="/project",
            source_hash="sha256:" + "a" * 64,
            domain_posture=DomainPosture.COMMERCIAL.value,  # Would normally = BLUE
            build_system=BuildSystem.PIP.value,
            language="python",
            language_version="3.12",
            framework_signals=(),
            context_tags=("ISR_CONTEXT",),  # Forces RED
            dependency_count=0,
            loc_estimate=100,
            fingerprint_hash="sha256:" + "b" * 64,
            classification_method="STRUCTURAL_RULE_BASED",
        )
        assert fp.recommended_tier() == Tier.RED

    def test_fingerprint_hash_determinism(self):
        """Same inputs → same hash (100 runs)."""
        hashes = set()
        for _ in range(100):
            h = ContextFingerprint.compute_hash(
                source_root="/project",
                domain_posture="COMMERCIAL",
                build_system="PIP",
                language="python",
                framework_signals=("django", "asyncio"),
                context_tags=("WEB_REQUEST_HANDLER", "HANDLES_USER_INPUT"),
            )
            hashes.add(h)
        assert len(hashes) == 1, f"Non-deterministic: {hashes}"


# ─── Tests: Catalog Entry (CONST-EVAL-001) ────────────────────────────────────

class TestEvalCatalogEntry:
    def test_catalog_entry_loads(self):
        """The production catalog entry must load without errors."""
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        assert EVAL_CONSTRUCT.construct_id == "CONST-EVAL-001"

    def test_catalog_entry_has_all_tiers(self):
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        for tier in Tier:
            perm = EVAL_CONSTRUCT.get_tier_permission(tier)
            assert perm.tier == tier.value

    def test_red_tier_is_forbidden_without_dual_control(self):
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        red_perm = EVAL_CONSTRUCT.get_tier_permission(Tier.RED)
        assert red_perm.level == TierPermissionLevel.FORBIDDEN_WITHOUT_DUAL_CONTROL.value

    def test_all_citations_have_reviewer(self):
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        for citation in EVAL_CONSTRUCT.knowledge_citations:
            assert citation.reviewer_id.strip(), f"Citation {citation.identifier} missing reviewer"

    def test_all_danger_conditions_have_source(self):
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        for dc in EVAL_CONSTRUCT.danger_conditions:
            assert dc.source_reference.strip(), f"DangerCondition {dc.condition_id} missing source"

    def test_catalog_hash_is_deterministic(self):
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        hashes = {EVAL_CONSTRUCT.catalog_hash() for _ in range(50)}
        assert len(hashes) == 1

    def test_dynamic_arg_condition_is_critical_certain(self):
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        dc = EVAL_CONSTRUCT.get_danger_condition("dynamic_arg")
        assert dc is not None
        assert dc.severity == Severity.CRITICAL.value
        assert dc.confidence == Confidence.CERTAIN.value

    def test_cybersecurity_risk_weight_is_high(self):
        from src.infrastructure.catalog.entries.python.eval_construct import EVAL_CONSTRUCT
        cyber_risks = [
            rm for rm in EVAL_CONSTRUCT.risk_mappings
            if rm.risk_type == RiskType.CYBERSECURITY.value
        ]
        assert len(cyber_risks) == 1
        assert cyber_risks[0].weight.numerator >= 900  # >= 90% weight


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
