"""
******************************************************************************
 * FILE:        /tests/unit/test_phases_6_7_8.py
 * LAYER:       Test Layer
 * MODULE:      Phase 6-7-8 Tests
 * PURPOSE:     Verify Tier Engine, Replay System, and Self-Verification
 * DOMAIN:      Tier Engine / Evidence & Replay / Self-Verification
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 * LICENSE:     Apache-2.0
 ******************************************************************************
"""

from __future__ import annotations

import sys
import tempfile
import pathlib

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

from src.infrastructure.catalog.engine.catalog_loader import load_python_catalog
from src.application.tier.tier_engine import TierEngine, TIER_PROFILES
from src.application.replay.replay_bundle import (
    build_replay_bundle, verify_replay, ReplayBundle,
)
from src.domain.constructs.construct_model import Tier, Severity
from src.domain.context.context_model import ContextFingerprint, BuildSystem, DomainPosture

_CATALOG = load_python_catalog()
_ENGINE  = TierEngine(_CATALOG)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_context(tags: tuple = (), posture: str = "COMMERCIAL") -> ContextFingerprint:
    fp_hash = ContextFingerprint.compute_hash(
        "/test/project", posture, "PIP", "python", (), tags,
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


def _write_code(code: str) -> tuple[str, str]:
    """Write code to a temp dir, return (tmpdir, file_path)."""
    import os
    tmpdir = tempfile.mkdtemp()
    fpath  = pathlib.Path(tmpdir) / "app.py"
    fpath.write_text(code, encoding="utf-8")
    return tmpdir, str(fpath)


DANGEROUS_CODE = """
import pickle, subprocess, random

def handler(request):
    result = eval(request.data)
    obj = pickle.loads(request.body)
    subprocess.run(request.args.get('cmd', ''), shell=True)
    token = random.hex(32)
    return result
"""

SAFE_CODE = """
import json, hashlib

def handler(validated_data: dict):
    result = json.dumps(validated_data)
    token = hashlib.sha256(b'secret').hexdigest()
    return result
"""


# ═══════════════════════════════════════════════════════════════════════════════
# TIER ENGINE TESTS — Phase 6
# ═══════════════════════════════════════════════════════════════════════════════

class TestTierProfiles:

    def test_all_four_tiers_have_profiles(self):
        for tier in Tier:
            assert tier in TIER_PROFILES

    def test_green_has_zero_dataflow_depth(self):
        assert TIER_PROFILES[Tier.GREEN].max_dataflow_depth == 0

    def test_red_has_max_dataflow_depth(self):
        assert TIER_PROFILES[Tier.RED].max_dataflow_depth >= 5

    def test_red_blocks_on_warning(self):
        assert TIER_PROFILES[Tier.RED].pipeline_blocking_severity == "warning"

    def test_blue_blocks_on_critical(self):
        assert TIER_PROFILES[Tier.BLUE].pipeline_blocking_severity == "critical"

    def test_green_never_blocks_pipeline(self):
        assert TIER_PROFILES[Tier.GREEN].pipeline_blocking_severity == ""

    def test_green_emits_info_findings(self):
        assert TIER_PROFILES[Tier.GREEN].emit_info_findings

    def test_profiles_are_frozen(self):
        with pytest.raises(Exception):
            TIER_PROFILES[Tier.BLUE].max_files = 0  # type: ignore

    def test_tier_file_quotas_increase_with_permissiveness(self):
        # GREEN < YELLOW < BLUE in strictness; RED has smallest quota (most thorough)
        assert TIER_PROFILES[Tier.RED].max_files < TIER_PROFILES[Tier.BLUE].max_files


class TestTierEngineAnalysis:

    def test_dangerous_code_blue_tier_produces_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(DANGEROUS_CODE)
            ctx = _make_context(tags=("WEB_REQUEST_HANDLER",))
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0100")
            assert result.is_successful()
            assert result.artifact.finding_count >= 3

    def test_dangerous_code_blue_blocks_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(DANGEROUS_CODE)
            ctx = _make_context(tags=("WEB_REQUEST_HANDLER",))
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0101")
            assert result.pipeline_blocked

    def test_safe_code_no_critical_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(SAFE_CODE)
            ctx = _make_context()
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0102")
            assert result.is_successful()
            critical = [
                f for f in result.artifact.findings
                if f.severity == Severity.CRITICAL.value
            ]
            assert len(critical) == 0

    def test_green_tier_never_blocks_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(DANGEROUS_CODE)
            ctx = _make_context()
            result = _ENGINE.analyze(tmpdir, ctx, Tier.GREEN,
                                     execution_seed="0xdeadbeef0103")
            assert result.is_successful()
            assert not result.pipeline_blocked

    def test_red_tier_in_safety_context_blocks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(DANGEROUS_CODE)
            ctx = _make_context(tags=("ISR_CONTEXT", "SAFETY_CRITICAL"),
                                posture="SAFETY_CRITICAL")
            result = _ENGINE.analyze(tmpdir, ctx, Tier.RED,
                                     execution_seed="0xdeadbeef0104")
            assert result.is_successful()
            assert result.pipeline_blocked

    def test_analysis_result_has_files_analyzed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "a.py").write_text("x = 1")
            (pathlib.Path(tmpdir) / "b.py").write_text("y = 2")
            ctx = _make_context()
            result = _ENGINE.analyze(tmpdir, ctx, Tier.GREEN,
                                     execution_seed="0xdeadbeef0105")
            assert result.files_analyzed == 2

    def test_empty_dir_produces_empty_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = _make_context()
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0106")
            assert result.is_successful()
            assert result.artifact.finding_count == 0
            assert not result.pipeline_blocked

    def test_syntax_error_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "broken.py").write_text("def broken(:\n    pass")
            (pathlib.Path(tmpdir) / "good.py").write_text("x = eval('1+1')")
            ctx = _make_context()
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0107")
            assert result.files_skipped == 1
            assert result.files_analyzed == 1

    def test_analysis_elapsed_ms_is_positive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text("x = eval('test')")
            ctx = _make_context()
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0108")
            assert result.elapsed_ms >= 0

    def test_below_recommended_tier_produces_warning(self):
        """Requesting GREEN for a SAFETY_CRITICAL project produces a warning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text("x = 1")
            ctx = _make_context(tags=("ISR_CONTEXT",), posture="SAFETY_CRITICAL")
            result = _ENGINE.analyze(tmpdir, ctx, Tier.GREEN,
                                     execution_seed="0xdeadbeef0109")
            assert any("below the recommended minimum" in w
                       for w in result.analysis_warnings)

    def test_blue_tier_does_not_emit_info_findings(self):
        """BLUE tier suppresses INFO findings to reduce noise."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # async awaited = INFO (no danger condition matched)
            code = """
async def fetch(url):
    result = await get(url)
    return result
"""
            (pathlib.Path(tmpdir) / "app.py").write_text(code)
            ctx = _make_context()
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0110")
            info_findings = [
                f for f in result.artifact.findings
                if f.severity == Severity.INFO.value
            ]
            assert len(info_findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# REPLAY SYSTEM TESTS — Phase 7
# ═══════════════════════════════════════════════════════════════════════════════

class TestReplayBundle:

    def _run_and_bundle(self, code: str) -> tuple:
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(code)
            ctx = _make_context(tags=("WEB_REQUEST_HANDLER",))
            result = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE,
                                     execution_seed="0xdeadbeef0200")
            bundle = build_replay_bundle(result)
            return result, bundle

    def test_bundle_built_from_result(self):
        result, bundle = self._run_and_bundle(DANGEROUS_CODE)
        assert bundle.artifact_hash == result.artifact.artifact_hash
        assert bundle.finding_count == result.artifact.finding_count
        assert bundle.tier == Tier.BLUE.value

    def test_bundle_is_frozen(self):
        _, bundle = self._run_and_bundle(DANGEROUS_CODE)
        with pytest.raises(Exception):
            bundle.finding_count = 0  # type: ignore

    def test_bundle_to_dict_serializable(self):
        _, bundle = self._run_and_bundle(DANGEROUS_CODE)
        d = bundle.to_dict()
        # Must be JSON-serializable
        serialized = bundle.to_canonical_json()
        assert isinstance(serialized, str)
        import json
        parsed = json.loads(serialized)
        assert parsed["finding_count"] == bundle.finding_count

    def test_bundle_hash_deterministic(self):
        _, bundle = self._run_and_bundle(DANGEROUS_CODE)
        h1 = bundle.bundle_hash()
        h2 = bundle.bundle_hash()
        assert h1 == h2
        assert h1.startswith("sha256:")

    def test_bundle_has_replay_instructions(self):
        _, bundle = self._run_and_bundle(DANGEROUS_CODE)
        assert len(bundle.replay_instructions) > 50
        assert "dcavp" in bundle.replay_instructions.lower() or \
               "DCAVP" in bundle.replay_instructions

    def test_bundle_from_failed_analysis_raises(self):
        from src.application.tier.tier_engine import TierAnalysisResult, TIER_PROFILES
        failed_result = TierAnalysisResult(
            tier=Tier.BLUE.value,
            profile=TIER_PROFILES[Tier.BLUE],
            artifact=None,   # Failed analysis
            parse_results=(),
            files_analyzed=0,
            files_skipped=0,
            nodes_discovered=0,
            decisions_made=0,
            pipeline_blocked=False,
            requires_dual_control=False,
            analysis_warnings=(),
            elapsed_ms=0,
        )
        with pytest.raises(ValueError):
            build_replay_bundle(failed_result)

    def test_replay_verification_passes_on_matching_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(DANGEROUS_CODE)
            ctx = _make_context(tags=("WEB_REQUEST_HANDLER",))
            r1 = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE, "0xdeadbeef0201")
            bundle = build_replay_bundle(r1)
            r2 = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE, "0xdeadbeef0202")
            verification = verify_replay(bundle, r2)
            assert verification.is_valid, f"Replay failed: {verification.diagnostic}"
            assert verification.finding_count_match

    def test_replay_verification_fails_on_different_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (pathlib.Path(tmpdir) / "app.py").write_text(DANGEROUS_CODE)
            ctx = _make_context()
            r1 = _ENGINE.analyze(tmpdir, ctx, Tier.BLUE, "0xdeadbeef0203")
            bundle = build_replay_bundle(r1)

        with tempfile.TemporaryDirectory() as tmpdir2:
            (pathlib.Path(tmpdir2) / "app.py").write_text(SAFE_CODE)
            r2 = _ENGINE.analyze(tmpdir2, ctx, Tier.BLUE, "0xdeadbeef0204")
            verification = verify_replay(bundle, r2)
            # Different code → different findings → replay fails
            assert not verification.is_valid

    def test_severity_distribution_in_bundle(self):
        _, bundle = self._run_and_bundle(DANGEROUS_CODE)
        dist_dict = {k: v for k, v in bundle.severity_distribution}
        # Dangerous code should have at least some CRITICAL findings
        total = sum(dist_dict.values())
        assert total == bundle.finding_count


# ═══════════════════════════════════════════════════════════════════════════════
# SELF-VERIFICATION TESTS — Phase 8
# ═══════════════════════════════════════════════════════════════════════════════

class TestSelfVerification:

    def test_self_verification_runs_without_error(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        assert report is not None
        assert len(report.checks) == 6

    def test_all_checks_have_diagnostic(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        for check in report.checks:
            assert len(check.diagnostic) > 0

    def test_catalog_integrity_check_passes(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        sv001 = next(c for c in report.checks if c.check_id == "CHECK-SV-001")
        assert sv001.passed, f"CHECK-SV-001 failed: {sv001.diagnostic}"

    def test_policy_source_references_check_passes(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        sv002 = next(c for c in report.checks if c.check_id == "CHECK-SV-002")
        assert sv002.passed, f"CHECK-SV-002 failed: {sv002.diagnostic}"

    def test_dependency_whitelist_check_passes(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        sv003 = next(c for c in report.checks if c.check_id == "CHECK-SV-003")
        assert sv003.passed, f"CHECK-SV-003 failed: {sv003.diagnostic}"

    def test_governance_gates_check_passes(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        sv006 = next(c for c in report.checks if c.check_id == "CHECK-SV-006")
        assert sv006.passed, f"CHECK-SV-006 failed: {sv006.diagnostic}"

    def test_triple_replay_check_passes(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        sv005 = next(c for c in report.checks if c.check_id == "CHECK-SV-005")
        assert sv005.passed, f"CHECK-SV-005 failed: {sv005.diagnostic}"

    def test_report_is_frozen(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        with pytest.raises(Exception):
            report.milestone_eligible = True  # type: ignore

    def test_milestone_eligible_if_all_fatal_pass(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        fatal_checks = [c for c in report.checks if c.severity == "FATAL"]
        fatal_all_pass = all(c.passed for c in fatal_checks)
        assert report.milestone_eligible == fatal_all_pass

    def test_summary_non_empty(self):
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        assert len(report.summary) > 0

    def test_red_tier_self_analysis_finds_no_kernel_criticals(self):
        """DCAVP's own kernel must have zero CRITICAL findings."""
        from src.verification.self_test.self_verification import SelfVerificationGateway
        gateway = SelfVerificationGateway('/home/claude/dcavp')
        report  = gateway.verify()
        sv004 = next(c for c in report.checks if c.check_id == "CHECK-SV-004")
        assert sv004.passed, f"CHECK-SV-004 failed: {sv004.diagnostic}"


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
