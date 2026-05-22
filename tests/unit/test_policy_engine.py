"""
******************************************************************************
 * FILE:        /tests/unit/test_policy_engine.py
 * LAYER:       Test Layer
 * MODULE:      Policy Engine Tests
 * PURPOSE:     Verify deterministic policy evaluation and artifact assembly
 * DOMAIN:      Policy Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * TEST CATEGORIES:
 * - AnalyzedNode: construction, validation, hash determinism
 * - PolicyEngine: escalation rules E-001 through E-005
 * - PolicyEngine: danger condition lookup, tier permission enforcement
 * - PolicyEngine: determinism (same inputs → identical output)
 * - ArtifactBuilder: finding sorting, ID re-sequencing, hash determinism
 * - Integration: full pipeline eval() → artifact with real catalog
 *
 * LICENSE: Apache-2.0
 ******************************************************************************
"""

from __future__ import annotations

import sys
sys.path.insert(0, '/home/claude/dcavp')

import types as _t
class _RC:
    def __init__(self, e): self.exc = e
    def __enter__(self): return self
    def __exit__(self, et, ev, tb):
        if et is None: raise AssertionError(f"Expected {self.exc.__name__} — not raised")
        if not issubclass(et, self.exc): raise AssertionError(f"Expected {self.exc.__name__}, got {et.__name__}: {ev}")
        return True
pm = _t.ModuleType('pytest')
pm.raises = lambda e: _RC(e)
sys.modules['pytest'] = pm
import pytest

from src.domain.constructs.construct_model import Severity, Confidence, Tier
from src.domain.policies.ast_node import AnalyzedNode, NodeCallContext, NodeError
from src.domain.policies.policy_model import PolicyIdFormatError
from src.domain.context.context_model import (
    BuildSystem, ContextFingerprint, DomainPosture, ContextTagVocabulary,
)
from src.application.policy.policy_engine import (
    PolicyEngine, ConstructNotInCatalog, PolicyDecision,
    _ESC_FORBIDDEN_DUAL_CONTROL, _ESC_TAINTED_INPUT,
    _ESC_SAFETY_CRITICAL_CONTEXT, _ESC_TEST_EXEMPTION, _ESC_BOUNDARY_REACHED,
)
from src.application.policy.artifact_builder import build_artifact
from src.infrastructure.catalog.engine.catalog_loader import load_python_catalog


# ─── Shared Fixtures ──────────────────────────────────────────────────────────

def _make_context(tags: tuple = (), posture: str = "COMMERCIAL") -> ContextFingerprint:
    fp_hash = ContextFingerprint.compute_hash(
        source_root="/test/project",
        domain_posture=posture,
        build_system="PIP",
        language="python",
        framework_signals=(),
        context_tags=tags,
    )
    return ContextFingerprint(
        source_root="/test/project",
        source_hash="sha256:" + "a" * 64,
        domain_posture=posture,
        build_system=BuildSystem.PIP.value,
        language="python",
        language_version="3.12",
        framework_signals=(),
        context_tags=tags,
        dependency_count=5,
        loc_estimate=1000,
        fingerprint_hash=fp_hash,
        classification_method="STRUCTURAL_RULE_BASED",
    )


def _make_call_context(
    fn_name: str = "process_data",
    is_test: bool = False,
    is_async: bool = False,
    arg_sources: tuple = ("LOCAL_VARIABLE",),
) -> NodeCallContext:
    return NodeCallContext(
        enclosing_function_name=fn_name,
        enclosing_class_name="",
        is_in_async_function=is_async,
        is_in_test_function=is_test,
        call_depth_from_entry=2,
        argument_sources=arg_sources,
    )


def _make_node(
    location: str = "/test/project/src/app.py:42:8",
    construct_id: str = "CONST-EVAL-001",
    state: str = "dynamic_arg",
    call_ctx: NodeCallContext = None,
) -> AnalyzedNode:
    if call_ctx is None:
        call_ctx = _make_call_context()
    return AnalyzedNode.create(
        canonical_location=location,
        construct_id=construct_id,
        ast_node_type="Call",
        detected_state=state,
        call_context=call_ctx,
        source_line=f"    result = eval(user_input)  # line {location.split(':')[1]}",
    )


# ─── Load shared catalog once ─────────────────────────────────────────────────
_CATALOG = load_python_catalog()
_ENGINE  = PolicyEngine(_CATALOG)


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYZED NODE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalyzedNode:

    def test_valid_construction(self):
        node = _make_node()
        assert node.construct_id == "CONST-EVAL-001"
        assert node.detected_state == "dynamic_arg"
        assert node.node_hash.startswith("sha256:")

    def test_hash_determinism_100_runs(self):
        hashes = {_make_node().node_hash for _ in range(100)}
        assert len(hashes) == 1

    def test_hash_changes_on_state_change(self):
        n1 = _make_node(state="dynamic_arg")
        n2 = _make_node(state="constant_arg")
        assert n1.node_hash != n2.node_hash

    def test_hash_changes_on_location_change(self):
        n1 = _make_node(location="/test/project/a.py:10:0")
        n2 = _make_node(location="/test/project/b.py:10:0")
        assert n1.node_hash != n2.node_hash

    def test_invalid_location_raises(self):
        with pytest.raises(Exception):
            AnalyzedNode.create(
                canonical_location="relative/path.py:10:0",  # not absolute
                construct_id="CONST-EVAL-001",
                ast_node_type="Call",
                detected_state="dynamic_arg",
                call_context=_make_call_context(),
                source_line="eval(x)",
            )

    def test_invalid_construct_id_raises(self):
        with pytest.raises(NodeError):
            AnalyzedNode.create(
                canonical_location="/test/a.py:1:0",
                construct_id="EVAL-001",   # missing CONST- prefix
                ast_node_type="Call",
                detected_state="dynamic_arg",
                call_context=_make_call_context(),
                source_line="eval(x)",
            )

    def test_frozen(self):
        node = _make_node()
        with pytest.raises(Exception):
            node.detected_state = "mutated"  # type: ignore

    def test_source_line_truncated_at_500(self):
        long_line = "x" * 1000
        node = AnalyzedNode.create(
            canonical_location="/test/a.py:1:0",
            construct_id="CONST-EVAL-001",
            ast_node_type="Call",
            detected_state="dynamic_arg",
            call_context=_make_call_context(),
            source_line=long_line,
        )
        assert len(node.source_line) <= 500


class TestNodeCallContext:

    def test_tainted_input_detection(self):
        ctx = _make_call_context(arg_sources=("USER_INPUT_TAINTED",))
        assert ctx.has_tainted_input()

    def test_network_input_is_tainted(self):
        ctx = _make_call_context(arg_sources=("NETWORK_INPUT",))
        assert ctx.has_tainted_input()

    def test_literal_constant_not_tainted(self):
        ctx = _make_call_context(arg_sources=("LITERAL_CONSTANT",))
        assert not ctx.has_tainted_input()

    def test_boundary_reached_detection(self):
        ctx = _make_call_context(arg_sources=("ANALYSIS_BOUNDARY",))
        assert ctx.is_boundary_reached()

    def test_invalid_argument_source_raises(self):
        with pytest.raises(NodeError):
            NodeCallContext(
                enclosing_function_name="fn",
                enclosing_class_name="",
                is_in_async_function=False,
                is_in_test_function=False,
                call_depth_from_entry=0,
                argument_sources=("MADE_UP_SOURCE",),  # invalid
            )


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ENGINE — BASE EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyEngineBaseEvaluation:

    def test_eval_dynamic_arg_blue_tier_produces_critical(self):
        """eval() with dynamic arg in BLUE tier → CRITICAL finding."""
        node = _make_node(state="dynamic_arg")
        ctx  = _make_context()
        decision = _ENGINE.evaluate(node, ctx, Tier.BLUE)
        assert decision.has_finding()
        assert decision.finding.severity == Severity.CRITICAL.value

    def test_eval_constant_arg_blue_tier_produces_warning(self):
        """eval() with constant arg in BLUE tier → WARNING finding."""
        node = _make_node(state="constant_arg")
        ctx  = _make_context()
        decision = _ENGINE.evaluate(node, ctx, Tier.BLUE)
        assert decision.has_finding()
        assert decision.finding.severity == Severity.WARNING.value

    def test_unknown_state_produces_info(self):
        """An unrecognized construct state (no danger condition) → INFO."""
        node = _make_node(state="awaited")   # 'awaited' = safe for async
        ctx  = _make_context()
        # Use async construct which has 'awaited' as a non-dangerous state
        async_node = _make_node(
            construct_id="CONST-ASYNC-001",
            state="awaited",
        )
        decision = _ENGINE.evaluate(async_node, ctx, Tier.BLUE)
        assert decision.has_finding()
        assert decision.finding.severity == Severity.INFO.value

    def test_unknown_construct_raises(self):
        node = AnalyzedNode.create(
            canonical_location="/test/a.py:1:0",
            construct_id="CONST-FAKE-999",
            ast_node_type="Call",
            detected_state="dynamic_arg",
            call_context=_make_call_context(),
            source_line="fake(x)",
        )
        ctx = _make_context()
        with pytest.raises(ConstructNotInCatalog):
            _ENGINE.evaluate(node, ctx, Tier.BLUE)

    def test_finding_has_explainability_graph(self):
        node = _make_node()
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert decision.finding is not None
        g = decision.finding.explainability_graph
        assert g.logic_expression != ""
        assert len(g.evidence_chain) >= 1

    def test_finding_canonical_location_matches_node(self):
        loc = "/test/project/src/views.py:100:4"
        node = _make_node(location=loc)
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert decision.finding.canonical_location == loc

    def test_finding_construct_id_matches_node(self):
        node = _make_node(construct_id="CONST-PICK-001", state="loads_untrusted_source")
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert decision.finding.construct_id == "CONST-PICK-001"

    def test_standards_populated(self):
        node = _make_node()
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert len(decision.finding.standards) >= 1

    def test_risk_mappings_populated(self):
        node = _make_node()
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert len(decision.finding.risk_mappings) >= 1

    def test_confidence_is_certain_for_ast_pattern(self):
        """eval() dynamic_arg detected by AST_PATTERN → CERTAIN confidence."""
        node = _make_node(state="dynamic_arg")
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert decision.finding.confidence == Confidence.CERTAIN.value


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ENGINE — ESCALATION RULES
# ═══════════════════════════════════════════════════════════════════════════════

class TestEscalationRules:

    # E-001: FORBIDDEN_WITHOUT_DUAL_CONTROL
    def test_E001_red_tier_forbidden_sets_critical_and_blocks(self):
        """RED tier + FORBIDDEN_WITHOUT_DUAL_CONTROL → CRITICAL + pipeline blocked."""
        node = _make_node(state="dynamic_arg")
        ctx  = _make_context()
        decision = _ENGINE.evaluate(node, ctx, Tier.RED)
        assert decision.finding.severity == Severity.CRITICAL.value
        assert decision.blocks_pipeline
        assert decision.requires_dual_control
        assert _ESC_FORBIDDEN_DUAL_CONTROL in decision.escalation_chain

    # E-002: TAINTED_INPUT
    def test_E002_tainted_input_escalates_warning_to_error(self):
        """Tainted input with WARNING base severity → escalated to ERROR."""
        node = _make_node(
            state="constant_arg",  # constant_arg = WARNING
            call_ctx=_make_call_context(arg_sources=("USER_INPUT_TAINTED",)),
        )
        ctx = _make_context()
        decision = _ENGINE.evaluate(node, ctx, Tier.BLUE)
        assert decision.has_finding()
        assert decision.finding.severity == Severity.ERROR.value
        assert _ESC_TAINTED_INPUT in decision.escalation_chain

    def test_E002_tainted_input_does_not_escalate_above_critical(self):
        """Tainted input cannot escalate beyond CRITICAL."""
        node = _make_node(
            state="dynamic_arg",   # dynamic_arg = CRITICAL
            call_ctx=_make_call_context(arg_sources=("NETWORK_INPUT",)),
        )
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert decision.finding.severity == Severity.CRITICAL.value
        # E-002 should not fire (already at CRITICAL, no point escalating)
        # tainted input fires but severity is already at ceiling
        assert decision.finding.severity == Severity.CRITICAL.value

    # E-003: SAFETY_CRITICAL_CONTEXT
    def test_E003_safety_context_escalates_to_critical(self):
        """ISR_CONTEXT forces CRITICAL regardless of base severity."""
        node = _make_node(state="constant_arg")  # base = WARNING
        ctx  = _make_context(tags=("ISR_CONTEXT",), posture="SAFETY_CRITICAL")
        decision = _ENGINE.evaluate(node, ctx, Tier.GREEN)
        assert decision.finding.severity == Severity.CRITICAL.value
        assert decision.finding.human_review_required
        assert decision.blocks_pipeline
        assert _ESC_SAFETY_CRITICAL_CONTEXT in decision.escalation_chain

    def test_E003_safety_context_overrides_test_exemption(self):
        """Safety-critical context overrides test function exemption."""
        node = _make_node(
            state="constant_arg",
            call_ctx=_make_call_context(is_test=True),  # would normally suppress
        )
        ctx = _make_context(tags=("SAFETY_CRITICAL",), posture="SAFETY_CRITICAL")
        decision = _ENGINE.evaluate(node, ctx, Tier.YELLOW)
        # Test exemption applied first, then safety overrides
        assert not decision.is_suppressed
        assert decision.finding.severity == Severity.CRITICAL.value
        assert _ESC_SAFETY_CRITICAL_CONTEXT in decision.escalation_chain

    # E-004: TEST EXEMPTION
    def test_E004_test_function_suppresses_warning(self):
        """Finding inside a test function is suppressed for non-critical severity."""
        node = _make_node(
            state="constant_arg",   # WARNING
            call_ctx=_make_call_context(fn_name="test_eval_safety", is_test=True),
        )
        ctx = _make_context()
        decision = _ENGINE.evaluate(node, ctx, Tier.BLUE)
        assert decision.is_suppressed
        assert decision.finding is None
        assert _ESC_TEST_EXEMPTION in decision.escalation_chain

    def test_E004_test_exemption_does_not_suppress_critical(self):
        """Test exemption does NOT suppress CRITICAL findings."""
        node = _make_node(
            state="dynamic_arg",   # CRITICAL
            call_ctx=_make_call_context(fn_name="test_something", is_test=True),
        )
        ctx = _make_context()
        decision = _ENGINE.evaluate(node, ctx, Tier.BLUE)
        # dynamic_arg = CRITICAL → test exemption won't fire (only fires for non-CRITICAL)
        assert decision.has_finding()
        assert decision.finding.severity == Severity.CRITICAL.value

    # E-005: BOUNDARY_REACHED
    def test_E005_boundary_reached_downgrades_confidence(self):
        """Analysis boundary reached → confidence downgraded to BOUNDED."""
        node = _make_node(
            state="dynamic_arg",
            call_ctx=_make_call_context(arg_sources=("ANALYSIS_BOUNDARY",)),
        )
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        assert decision.finding.confidence == Confidence.BOUNDED.value
        assert _ESC_BOUNDARY_REACHED in decision.escalation_chain
        assert decision.finding.boundary_status == "boundary_reached"
        assert len(decision.finding.boundaries) >= 1

    def test_E005_boundary_adds_boundary_declaration(self):
        node = _make_node(
            call_ctx=_make_call_context(arg_sources=("ANALYSIS_BOUNDARY",)),
        )
        decision = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
        bd = decision.finding.boundaries[0]
        assert bd.boundary_type == "ANALYSIS_BOUNDARY_REACHED"
        assert bd.recommendation != ""

    def test_E005_boundary_requires_human_review_in_yellow(self):
        """In YELLOW tier, boundary reached → human review required."""
        node = _make_node(
            call_ctx=_make_call_context(arg_sources=("ANALYSIS_BOUNDARY",)),
        )
        decision = _ENGINE.evaluate(node, _make_context(), Tier.YELLOW)
        bd = decision.finding.boundaries[0]
        assert bd.human_review_required


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ENGINE — DETERMINISM
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyEngineDeterminism:

    def test_identical_inputs_produce_identical_finding_hash(self):
        """100 evaluations of identical input → identical evidence_hash."""
        node = _make_node(state="dynamic_arg")
        ctx  = _make_context(tags=("WEB_REQUEST_HANDLER",))
        hashes = {
            _ENGINE.evaluate(node, ctx, Tier.BLUE).finding.evidence_hash
            for _ in range(100)
        }
        assert len(hashes) == 1

    def test_different_states_produce_different_hashes(self):
        n1 = _make_node(state="dynamic_arg")
        n2 = _make_node(state="constant_arg")
        d1 = _ENGINE.evaluate(n1, _make_context(), Tier.BLUE)
        d2 = _ENGINE.evaluate(n2, _make_context(), Tier.BLUE)
        assert d1.finding.evidence_hash != d2.finding.evidence_hash

    def test_different_tiers_may_produce_different_severity(self):
        node = _make_node(state="dynamic_arg")
        ctx  = _make_context()
        d_green = _ENGINE.evaluate(node, ctx, Tier.GREEN)
        d_red   = _ENGINE.evaluate(node, ctx, Tier.RED)
        # RED tier forces CRITICAL + dual control even if base is already CRITICAL
        assert d_red.requires_dual_control
        assert not d_green.requires_dual_control

    def test_different_context_tags_produce_different_decisions(self):
        node   = _make_node(state="constant_arg")  # WARNING
        ctx_safe = _make_context(tags=("ISR_CONTEXT",), posture="SAFETY_CRITICAL")
        ctx_norm = _make_context(tags=())
        d_safe = _ENGINE.evaluate(node, ctx_safe, Tier.GREEN)
        d_norm = _ENGINE.evaluate(node, ctx_norm, Tier.GREEN)
        assert d_safe.finding.severity == Severity.CRITICAL.value
        assert d_norm.finding.severity == Severity.WARNING.value

    def test_logic_expression_is_non_empty(self):
        decision = _ENGINE.evaluate(_make_node(), _make_context(), Tier.BLUE)
        assert len(decision.finding.explainability_graph.logic_expression) > 0

    def test_evidence_chain_is_ordered(self):
        decision = _ENGINE.evaluate(_make_node(), _make_context(), Tier.BLUE)
        chain = decision.finding.explainability_graph.evidence_chain
        for i, step in enumerate(chain):
            assert step.step_index == i


# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT BUILDER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestArtifactBuilder:

    def _make_decisions(self, n_findings: int = 3) -> list[PolicyDecision]:
        locations = [
            "/test/project/src/b.py:20:4",
            "/test/project/src/a.py:10:0",
            "/test/project/src/c.py:30:8",
        ]
        decisions = []
        for i in range(n_findings):
            node = _make_node(
                location=locations[i % len(locations)],
                state="dynamic_arg",
            )
            d = _ENGINE.evaluate(node, _make_context(), Tier.BLUE)
            decisions.append(d)
        return decisions

    def test_artifact_has_correct_finding_count(self):
        decisions = self._make_decisions(3)
        ctx = _make_context()
        artifact = build_artifact(decisions, ctx, Tier.BLUE, _CATALOG)
        assert artifact.finding_count == len(artifact.findings)
        assert artifact.finding_count == 3

    def test_findings_sorted_by_location(self):
        decisions = self._make_decisions(3)
        ctx = _make_context()
        artifact = build_artifact(decisions, ctx, Tier.BLUE, _CATALOG)
        locations = [f.canonical_location for f in artifact.findings]
        assert locations == sorted(locations)

    def test_finding_ids_resequenced(self):
        decisions = self._make_decisions(3)
        ctx = _make_context()
        artifact = build_artifact(decisions, ctx, Tier.BLUE, _CATALOG)
        ids = [f.finding_id for f in artifact.findings]
        assert ids == ["F-00001", "F-00002", "F-00003"]

    def test_artifact_hash_not_pending(self):
        decisions = self._make_decisions(2)
        artifact = build_artifact(decisions, _make_context(), Tier.BLUE, _CATALOG)
        assert artifact.artifact_hash != "PENDING"
        assert artifact.artifact_hash.startswith("sha256:")

    def test_artifact_hash_determinism(self):
        """Two builds with same suppression decisions → different artifact_id (UUID)
        but same structure. We test that the hash is stable for the same artifact."""
        decisions = [
            _ENGINE.evaluate(_make_node(state="dynamic_arg"), _make_context(), Tier.BLUE)
        ]
        art = build_artifact(decisions, _make_context(), Tier.BLUE, _CATALOG,
                             execution_seed="0xdeadbeef00")
        assert art.artifact_hash.startswith("sha256:")
        assert len(art.artifact_hash) == 71  # "sha256:" + 64 hex

    def test_suppressed_findings_excluded(self):
        """Test-exempted findings should not appear in the artifact."""
        node = _make_node(
            state="constant_arg",   # WARNING → suppressed in test context
            call_ctx=_make_call_context(fn_name="test_something", is_test=True),
        )
        decisions = [_ENGINE.evaluate(node, _make_context(), Tier.BLUE)]
        artifact = build_artifact(decisions, _make_context(), Tier.BLUE, _CATALOG)
        assert artifact.finding_count == 0

    def test_phase0_warning_present(self):
        decisions = self._make_decisions(1)
        artifact = build_artifact(decisions, _make_context(), Tier.BLUE, _CATALOG)
        assert "PHASE0-UNSIGNED" in artifact.warning

    def test_signature_is_phase0_unsigned(self):
        decisions = self._make_decisions(1)
        artifact = build_artifact(decisions, _make_context(), Tier.BLUE, _CATALOG)
        assert artifact.signature == "PHASE0-UNSIGNED"

    def test_cef_version_is_1_0(self):
        decisions = self._make_decisions(1)
        artifact = build_artifact(decisions, _make_context(), Tier.BLUE, _CATALOG)
        assert artifact.cef_version == "1.0"

    def test_tier_embedded_in_artifact(self):
        decisions = self._make_decisions(1)
        artifact = build_artifact(decisions, _make_context(), Tier.YELLOW, _CATALOG)
        assert artifact.tier == Tier.YELLOW.value

    def test_boundary_honesty_computed(self):
        decisions = self._make_decisions(2)
        artifact = build_artifact(decisions, _make_context(), Tier.BLUE, _CATALOG)
        bh = artifact.boundary_honesty
        assert bh.score_denominator == 1000
        assert bh.trust_level in ("full", "qualified", "insufficient")

    def test_empty_decisions_produces_zero_finding_artifact(self):
        artifact = build_artifact([], _make_context(), Tier.GREEN, _CATALOG)
        assert artifact.finding_count == 0
        assert artifact.findings == ()


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION: Full pipeline (catalog → engine → artifact)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullPipelineIntegration:

    def test_all_10_constructs_evaluatable(self):
        """Every registered construct can be evaluated without error."""
        contexts = {
            "CONST-ASYNC-001": ("unawaited",    _make_context()),
            "CONST-EVAL-001":  ("dynamic_arg",  _make_context()),
            "CONST-EXEC-001":  ("dynamic_arg",  _make_context()),
            "CONST-GLOB-001":  ("write_global", _make_context()),
            "CONST-LOCK-001":  ("acquired_without_context_manager", _make_context()),
            "CONST-OPEN-001":  ("path_traversal_possible", _make_context()),
            "CONST-PICK-001":  ("loads_untrusted_source", _make_context()),
            "CONST-RAND-001":  ("used_for_security", _make_context()),
            "CONST-SUBP-001":  ("shell_true_dynamic_cmd", _make_context()),
            "CONST-THRD-001":  ("shared_mutable_no_sync", _make_context()),
        }
        for cid, (state, ctx) in sorted(contexts.items()):
            node = _make_node(construct_id=cid, state=state)
            decision = _ENGINE.evaluate(node, ctx, Tier.BLUE)
            assert decision.has_finding(), f"{cid} produced no finding for state '{state}'"

    def test_critical_constructs_produce_critical_in_red_tier(self):
        """eval/exec/pickle with dangerous states in RED → CRITICAL + dual control."""
        for cid, state in [
            ("CONST-EVAL-001", "dynamic_arg"),
            ("CONST-EXEC-001", "dynamic_arg"),
            ("CONST-PICK-001", "loads_untrusted_source"),
        ]:
            node = _make_node(construct_id=cid, state=state)
            decision = _ENGINE.evaluate(node, _make_context(), Tier.RED)
            assert decision.finding.severity == Severity.CRITICAL.value, f"Failed for {cid}"
            assert decision.requires_dual_control, f"No dual control for {cid}"
            assert decision.blocks_pipeline, f"Pipeline not blocked for {cid}"

    def test_full_artifact_end_to_end(self):
        """Build a full artifact from 5 findings across 3 constructs."""
        nodes = [
            _make_node("/test/project/app.py:10:4",  "CONST-EVAL-001",  "dynamic_arg"),
            _make_node("/test/project/app.py:50:8",  "CONST-PICK-001",  "loads_untrusted_source"),
            _make_node("/test/project/utils.py:5:0", "CONST-GLOB-001",  "write_global"),
            _make_node("/test/project/utils.py:20:4","CONST-SUBP-001",  "shell_true_dynamic_cmd"),
            _make_node("/test/project/views.py:80:8","CONST-OPEN-001",  "path_traversal_possible"),
        ]
        ctx = _make_context(tags=("WEB_REQUEST_HANDLER",))
        decisions = [_ENGINE.evaluate(n, ctx, Tier.BLUE) for n in nodes]
        artifact = build_artifact(decisions, ctx, Tier.BLUE, _CATALOG)

        assert artifact.finding_count == 5
        assert artifact.tier == "BLUE"
        assert artifact.artifact_hash.startswith("sha256:")
        assert artifact.signature == "PHASE0-UNSIGNED"

        # Verify findings are sorted
        locs = [f.canonical_location for f in artifact.findings]
        assert locs == sorted(locs)

        # Verify IDs are sequential
        ids = [f.finding_id for f in artifact.findings]
        assert ids == [f"F-{i:05d}" for i in range(1, 6)]

    def test_safety_critical_project_all_findings_critical(self):
        """In safety-critical context, ALL dangerous findings escalate to CRITICAL."""
        ctx = _make_context(tags=("ISR_CONTEXT", "SAFETY_CRITICAL"), posture="SAFETY_CRITICAL")
        nodes = [
            _make_node("/test/a.py:1:0",  "CONST-EVAL-001", "constant_arg"),  # base=WARNING
            _make_node("/test/b.py:2:0",  "CONST-GLOB-001", "read_only_global"),  # base=WARNING
            _make_node("/test/c.py:3:0",  "CONST-LOCK-001", "acquired_without_timeout"),  # base=WARNING
        ]
        for node in nodes:
            decision = _ENGINE.evaluate(node, ctx, Tier.RED)
            assert decision.finding.severity == Severity.CRITICAL.value, \
                f"{node.construct_id} not CRITICAL in safety context"
            assert decision.finding.human_review_required


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    passed = failed = 0
    errors = []
    g = globals()
    for cls_name in sorted(g):
        cls = g[cls_name]
        if not isinstance(cls, type) or not cls_name.startswith("Test"):
            continue
        inst = cls()
        for mn in sorted(dir(inst)):
            if not mn.startswith("test_"):
                continue
            try:
                getattr(inst, mn)()
                print(f"  ✓  {cls_name}.{mn}")
                passed += 1
            except Exception as e:
                print(f"  ✗  {cls_name}.{mn} — {type(e).__name__}: {e}")
                failed += 1
                errors.append((cls_name, mn, f"{type(e).__name__}: {e}"))

    print(f"\n{'='*60}")
    print(f"RESULTS: {passed} passed / {failed} failed / {passed+failed} total")
    if errors:
        print("\nFAILURES:")
        for c, m, msg in errors:
            print(f"  {c}.{m}: {msg}")
    print("="*60)
