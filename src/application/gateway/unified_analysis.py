"""
******************************************************************************
 * FILE:        /src/application/gateway/unified_analysis.py
 * LAYER:       Application Layer
 * MODULE:      Unified Analysis Engine
 * PURPOSE:     Orchestrate all analysis components into one unified result
 * DOMAIN:      Trust Infrastructure
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-14
 * UPDATED:     2026-05-14
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * DELTA EXTENSION — composes all new extensions with existing TierEngine.
 * Does NOT modify any existing Phase 0-8 component.
 *
 * Unified Analysis Pipeline:
 *   1. Gateway resource quota check (GatewayConfig)
 *   2. Context classification (ClassificationPipeline — existing Phase 3)
 *   3. Tier analysis — findings + artifact (TierEngine — existing Phase 6)
 *   4. Hallucination detection (HallucinationDetector — new)
 *   5. Supply chain analysis (SupplyChainAnalyzer — new)
 *   6. Trust score computation (TrustScoreEngine — new)
 *   7. Multi-audience explanation (ExplainabilityEngine — new)
 *   8. Replay bundle generation (ReplayBundle — existing Phase 7)
 *
 * All existing components are called AS-IS with no modification.
 * New components receive results from existing components — never vice versa.
 *
 * DEPENDENCIES (all existing, read-only):
 *   - src/application/tier/tier_engine.py
 *   - src/application/classification/classification_pipeline.py
 *   - src/application/replay/replay_bundle.py
 * NEW (extensions, no kernel impact):
 *   - src/application/trust/trust_score_engine.py
 *   - src/application/explainability/explainability_engine.py
 *   - src/application/hallucination/hallucination_detector.py
 *   - src/application/supply_chain/supply_chain_analyzer.py
 *   - src/application/gateway/gateway_config.py
 *
 * CONSTRAINTS:
 *   - Gateway resource check happens BEFORE any analysis (fail-fast)
 *   - TierEngine result is immutable — new components only READ it
 *   - All new results are frozen dataclasses
 *
 * DETERMINISM: same source + gateway → same UnifiedAnalysisResult
 *   (except artifact_hash which includes timestamp — Phase 1+ fix)
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from src.domain.constructs.construct_model import Tier
from src.application.tier.tier_engine import TierAnalysisResult
from src.application.replay.replay_bundle import ReplayBundle, build_replay_bundle
from src.application.trust.trust_score_engine import TrustScoreReport, compute_trust_score
from src.application.explainability.explainability_engine import ExplainedFinding, explain_all
from src.application.hallucination.hallucination_detector import HallucinationReport
from src.application.supply_chain.supply_chain_analyzer import SupplyChainReport
from src.application.gateway.gateway_config import (
    GatewayProfile, GATEWAY_PROFILES, check_resource_quota,
    GatewayQuotaExceeded,
)


# ─── Unified Result ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class UnifiedAnalysisResult:
    """
    Purpose: Complete analysis result integrating all platform components.
    The single object that represents a full DCAVP analysis.

    Inputs:
    - gateway_id: The gateway used
    - gateway_profile: The GatewayProfile applied
    - tier_result: The core TierAnalysisResult (existing Phase 6)
    - trust_score: The 5-dimension TrustScoreReport (new Phase 9)
    - explained_findings: Gateway-appropriate explanations (new Phase 9)
    - hallucination_reports: Hallucination analysis per file (new Phase 9)
    - supply_chain: Supply chain risk analysis (new Phase 9)
    - replay_bundle: Replay bundle for this analysis (existing Phase 7)
    - hallucination_count: Total hallucinations across all files
    - overall_ai_reliability_score: Min score across all files
    - pipeline_decision: "PASS" | "BLOCKED" | "BLOCKED_DUAL_CONTROL"
    """
    gateway_id: str
    gateway_profile: GatewayProfile
    tier_result: TierAnalysisResult
    trust_score: TrustScoreReport
    explained_findings: tuple[ExplainedFinding, ...]
    hallucination_reports: tuple[HallucinationReport, ...]
    supply_chain: SupplyChainReport
    replay_bundle: ReplayBundle
    hallucination_count: int
    overall_ai_reliability_score: int
    pipeline_decision: str     # "PASS" | "BLOCKED" | "BLOCKED_DUAL_CONTROL"

    def is_production_ready(self) -> bool:
        return (
            self.pipeline_decision == "PASS"
            and self.trust_score.production_ready
            and not self.supply_chain.has_critical_risks()
            and self.hallucination_count == 0
        )

    def critical_finding_count(self) -> int:
        if self.tier_result.artifact is None:
            return 0
        from src.domain.constructs.construct_model import Severity
        return sum(
            1 for f in self.tier_result.artifact.findings
            if f.severity == Severity.CRITICAL.value
        )


# ─── Unified Engine ───────────────────────────────────────────────────────────

class UnifiedAnalysisEngine:
    """
    Purpose: Orchestrate the complete unified analysis pipeline.

    Usage:
        engine = UnifiedAnalysisEngine(catalog)
        result = engine.analyze(
            source_root="/path/to/project",
            gateway_id="BLUE",
            execution_seed="0xdeadbeef0000",
        )
        print(result.trust_score.format_summary())

    The engine is stateless after initialization.
    All analysis state is local to each analyze() call.
    """

    def __init__(self, catalog) -> None:
        from src.application.tier.tier_engine import TierEngine
        from src.application.classification.classification_pipeline import ClassificationPipeline
        self._catalog    = catalog
        self._tier_engine = TierEngine(catalog)
        self._classifier  = ClassificationPipeline()

    def analyze(
        self,
        source_root: str,
        gateway_id: str,
        execution_seed: str = "0xdeadbeef0000",
    ) -> UnifiedAnalysisResult:
        """
        Purpose: Run the complete unified analysis pipeline.

        Steps:
        1. Load gateway profile
        2. Classify project (Phase 3 — existing)
        3. Resource quota check (new)
        4. Run tier analysis (Phase 6 — existing)
        5. Detect hallucinations (new)
        6. Analyze supply chain (new)
        7. Compute trust score (new)
        8. Generate explanations (new)
        9. Build replay bundle (Phase 7 — existing)

        Inputs:
        - source_root: Project root path
        - gateway_id: "GREEN" | "YELLOW" | "BLUE" | "RED"
        - execution_seed: Hex seed for replay

        Failure: GatewayQuotaExceeded if resource limits exceeded
        """
        # ── Step 1: Gateway profile ──────────────────────────────────────
        profile = GATEWAY_PROFILES.get(gateway_id)
        if profile is None:
            raise ValueError(f"Unknown gateway_id '{gateway_id}'")

        # ── Step 2: Classify project ─────────────────────────────────────
        cls_result = self._classifier.classify(source_root)
        context    = cls_result.fingerprint

        # ── Step 3: Resource quota check (BEFORE analysis) ───────────────
        quota_check = check_resource_quota(
            gateway_id=gateway_id,
            file_count=cls_result.fs_result.file_count,
            loc_estimate=context.loc_estimate,
        )
        if not quota_check.approved:
            raise GatewayQuotaExceeded(quota_check.message)

        # ── Step 4: Tier analysis (existing Phase 6) ──────────────────────
        tier_result = self._tier_engine.analyze(
            source_root=source_root,
            context=context,
            tier=profile.tier,
            execution_seed=execution_seed,
        )

        # ── Step 5: Hallucination detection (new) ────────────────────────
        from src.application.hallucination.hallucination_detector import (
            detect_in_directory, aggregate_reports,
        )
        hall_reports_list = detect_in_directory(source_root, max_files=profile.max_files)
        hall_agg = aggregate_reports(hall_reports_list)
        total_hallucinations = hall_agg["total_hallucinations"]
        ai_score = hall_agg["overall_ai_reliability_score"]

        # ── Step 6: Supply chain analysis (new) ──────────────────────────
        from src.application.supply_chain.supply_chain_analyzer import analyze_supply_chain
        supply_chain = analyze_supply_chain(source_root)

        # ── Step 7: Trust score (new) ─────────────────────────────────────
        if tier_result.artifact is not None:
            trust_score = compute_trust_score(tier_result.artifact)
        else:
            # Fallback if analysis failed — zero score
            from src.application.trust.trust_score_engine import (
                TrustScoreReport, DimensionScore,
            )
            zero_dim = lambda name, w: DimensionScore(
                dimension=name, score_numerator=0, weight_numerator=w,
                finding_count=0, penalty_applied=0, band="weak",
                rationale="Analysis failed to complete.",
            )
            trust_score = TrustScoreReport(
                artifact_hash="", tier=gateway_id, overall_score=0,
                overall_band="weak",
                security=zero_dim("Security", 300),
                determinism=zero_dim("Determinism", 250),
                maintainability=zero_dim("Maintainability", 200),
                ai_reliability=zero_dim("AI Reliability", 150),
                dependency_health=zero_dim("Dependency Health", 100),
                total_findings=0, boundary_count=0,
                production_ready=False, top_concerns=(),
                recommendations=("Analysis failed to complete.",),
            )

        # ── Step 8: Explanations (new) ────────────────────────────────────
        explained: tuple[ExplainedFinding, ...] = ()
        if tier_result.artifact is not None:
            explained = explain_all(tier_result.artifact, gateway_id)

        # ── Step 9: Replay bundle (existing Phase 7) ──────────────────────
        bundle = build_replay_bundle(tier_result)

        # ── Pipeline decision ──────────────────────────────────────────────
        if tier_result.requires_dual_control:
            pipeline_decision = "BLOCKED_DUAL_CONTROL"
        elif tier_result.pipeline_blocked:
            pipeline_decision = "BLOCKED"
        else:
            pipeline_decision = "PASS"

        return UnifiedAnalysisResult(
            gateway_id=gateway_id,
            gateway_profile=profile,
            tier_result=tier_result,
            trust_score=trust_score,
            explained_findings=explained,
            hallucination_reports=tuple(hall_reports_list),
            supply_chain=supply_chain,
            replay_bundle=bundle,
            hallucination_count=total_hallucinations,
            overall_ai_reliability_score=ai_score,
            pipeline_decision=pipeline_decision,
        )
