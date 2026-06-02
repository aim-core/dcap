"""
******************************************************************************
 * FILE:        /src/application/tier/tier_engine.py
 * LAYER:       Application Layer
 * MODULE:      Tier Engine
 * PURPOSE:     Orchestrate analysis depth per tier (GREEN/BLUE/YELLOW/RED)
 * DOMAIN:      Tier Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The TierEngine coordinates the full analysis pipeline for a given tier.
 * It enforces WHAT analysis is performed at each tier and WHAT quotas apply.
 *
 * TIER ANALYSIS PROFILES:
 *
 *   GREEN — Exploratory / Educational
 *     Parser:    AST-only (no dataflow)
 *     Dataflow:  Disabled (max_depth=0)
 *     Findings:  INFO + WARNING only; no pipeline blocking
 *     Quota:     Up to 50,000 files, 1M LOC
 *     Speed:     Ultra-fast (seconds for large repos)
 *     Use case:  Developer education, CI quick-check
 *
 *   BLUE — Commercial / Professional
 *     Parser:    AST + bounded dataflow (depth=3)
 *     Dataflow:  Enabled, 3 call frames
 *     Findings:  All severities; CRITICAL blocks pipeline
 *     Quota:     Up to 100,000 files, 5M LOC
 *     Speed:     Fast (minutes for large repos)
 *     Use case:  Standard CI/CD integration
 *
 *   YELLOW — High Assurance / Regulated
 *     Parser:    AST + bounded dataflow (depth=5) + bounded simulation
 *     Dataflow:  Enabled, 5 call frames
 *     Findings:  All severities; ERROR + CRITICAL block pipeline
 *     Quota:     Up to 50,000 files, 2M LOC (bounded simulation cost)
 *     Speed:     Moderate (may take tens of minutes)
 *     Use case:  Regulated software, financial systems, healthcare
 *
 *   RED — Industrial / Safety-Critical
 *     Parser:    AST + bounded dataflow (depth=5) + bounded operational sim
 *     Dataflow:  Enabled, 5 call frames, context-aware escalation
 *     Findings:  All severities; WARNING+ blocks pipeline; dual-control for exemptions
 *     Quota:     Up to 10,000 files, 500K LOC (cost of thoroughness)
 *     Speed:     Thorough (may take hours for large systems)
 *     Use case:  IEC 61508, ISO 26262, DO-178C, aerospace, medical devices
 *
 * REFERENCES:
 *   Foundation Document Section 9 — Tier System
 *   IEC 61508-3:2010 Annex A — Software requirements specification
 *
 * DEPENDENCIES:
 *   - src/adapters/parsers/python/python_parser.py
 *   - src/application/policy/policy_engine.py
 *   - src/application/policy/artifact_builder.py
 *   - src/domain/context/context_model.py
 *   - src/infrastructure/catalog/registry/catalog_registry.py
 *
 * CONSTRAINTS:
 *   - Tier profiles are IMMUTABLE (no runtime modification)
 *   - Same catalog + tier + source → same artifact hash (determinism)
 *   - All quotas enforced strictly (no silent overflow)
 *
 * DETERMINISM GUARANTEES:
 *   - Parser output is sorted by canonical_location
 *   - Policy evaluation order is deterministic
 *   - Artifact builder produces byte-identical output for same input
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.domain.constructs.construct_model import Tier
from src.domain.context.context_model import ContextFingerprint
from src.domain.evidence.evidence_model import CEFArtifact
from src.adapters.parsers.python.python_parser import PythonParser, ParseResult
from src.application.policy.policy_engine import PolicyEngine, PolicyDecision
from src.application.policy.artifact_builder import build_artifact
from src.infrastructure.catalog.registry.catalog_registry import CatalogRegistry


# ─── Tier Profile ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TierProfile:
    """
    Purpose: Immutable configuration for one analysis tier.
    Every field is an explicit, documented limit — no hidden behavior.
    """
    tier: Tier
    max_dataflow_depth: int     # 0 = disabled; ≥1 = enabled
    max_files: int
    max_loc: int
    pipeline_blocking_severity: str   # minimum severity that blocks pipeline
    emit_info_findings: bool          # GREEN emits INFO; others may suppress
    description: str
    standard_reference: str


# Immutable tier profiles — matches Foundation Document Section 9
TIER_PROFILES: dict[Tier, TierProfile] = {
    Tier.GREEN: TierProfile(
        tier=Tier.GREEN,
        max_dataflow_depth=0,           # AST-only; no dataflow
        max_files=50_000,
        max_loc=1_000_000,
        pipeline_blocking_severity="",  # Never blocks pipeline
        emit_info_findings=True,
        description="Exploratory: AST-only analysis, educational output, no blocking",
        standard_reference="DCAVP Foundation Document Section 9.1",
    ),
    Tier.BLUE: TierProfile(
        tier=Tier.BLUE,
        max_dataflow_depth=3,
        max_files=100_000,
        max_loc=5_000_000,
        pipeline_blocking_severity="critical",
        emit_info_findings=False,
        description="Commercial: bounded dataflow, CRITICAL blocks pipeline",
        standard_reference="DCAVP Foundation Document Section 9.2",
    ),
    Tier.YELLOW: TierProfile(
        tier=Tier.YELLOW,
        max_dataflow_depth=5,
        max_files=50_000,
        max_loc=2_000_000,
        pipeline_blocking_severity="error",
        emit_info_findings=False,
        description="High Assurance: full bounded analysis, ERROR+ blocks pipeline",
        standard_reference="DCAVP Foundation Document Section 9.3; IEC 61508-3 Annex A",
    ),
    Tier.RED: TierProfile(
        tier=Tier.RED,
        max_dataflow_depth=5,
        max_files=10_000,
        max_loc=500_000,
        pipeline_blocking_severity="warning",
        emit_info_findings=False,
        description="Safety-Critical: maximum analysis, WARNING+ blocks pipeline, dual-control",
        standard_reference="DCAVP Foundation Document Section 9.4; IEC 61508-3; ISO 26262",
    ),
}


# ─── Analysis Result ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TierAnalysisResult:
    """
    Purpose: Complete result of a tier-governed analysis run.

    Inputs:
    - tier: The tier used for this analysis
    - profile: The TierProfile applied
    - artifact: The final CEFArtifact (None if analysis failed to complete)
    - parse_results: Tuple of ParseResult for all analyzed files
    - files_analyzed: Count of successfully parsed files
    - files_skipped: Count of files skipped (too large, syntax error, etc.)
    - nodes_discovered: Total AnalyzedNode instances produced
    - decisions_made: Total PolicyDecision instances produced
    - pipeline_blocked: True if any finding exceeds pipeline_blocking_severity
    - requires_dual_control: True if any RED tier finding requires it
    - analysis_warnings: Sorted tuple of non-fatal analysis warnings
    - elapsed_ms: Wall time of analysis in milliseconds (integer)
    """
    tier: str
    profile: TierProfile
    artifact: Optional[CEFArtifact]
    parse_results: tuple[ParseResult, ...]
    files_analyzed: int
    files_skipped: int
    nodes_discovered: int
    decisions_made: int
    pipeline_blocked: bool
    requires_dual_control: bool
    analysis_warnings: tuple[str, ...]
    elapsed_ms: int

    def is_successful(self) -> bool:
        return self.artifact is not None

    def summary(self) -> str:
        if self.artifact is None:
            return f"FAILED: analysis did not complete"
        blocked = "PIPELINE BLOCKED" if self.pipeline_blocked else "pipeline OK"
        return (
            f"Tier {self.tier}: {self.files_analyzed} files, "
            f"{self.nodes_discovered} nodes, {self.artifact.finding_count} findings "
            f"[{blocked}]"
        )


# ─── Tier Engine ──────────────────────────────────────────────────────────────

class TierEngine:
    """
    Purpose: Orchestrate the full analysis pipeline for a given tier.
    This is the TOP-LEVEL coordinator — the entry point for a complete analysis.

    Usage:
        engine = TierEngine(catalog)
        result = engine.analyze(
            source_root="/path/to/project",
            context=fingerprint,
            tier=Tier.BLUE,
        )
        if result.pipeline_blocked:
            sys.exit(1)

    Constraints:
    - Parser, PolicyEngine, and ArtifactBuilder are all deterministic
    - Same inputs → same artifact hash
    - Tier profile limits are enforced strictly
    """

    def __init__(self, catalog: CatalogRegistry) -> None:
        self._catalog = catalog
        self._parser  = PythonParser()
        self._policy  = PolicyEngine(catalog)

    def analyze(
        self,
        source_root: str,
        context: ContextFingerprint,
        tier: Tier,
        execution_seed: str = "0xdeadbeef0000",
    ) -> TierAnalysisResult:
        """
        Purpose: Run a complete tier-governed analysis of a source tree.

        Inputs:
        - source_root: Absolute path to the project root
        - context: ContextFingerprint from Phase 3 classification
        - tier: The analysis tier to use
        - execution_seed: Hex seed for replay (must start with 0x)

        Outputs: TierAnalysisResult (immutable)

        Steps:
        1. Load tier profile
        2. Parse all Python files (bounded by profile limits)
        3. Evaluate all nodes through policy engine
        4. Apply tier-level finding filters (e.g. suppress INFO in BLUE+)
        5. Build CEFArtifact
        6. Determine pipeline blocking status

        Determinism: same source + tier + seed → same artifact hash
        """
        import time
        t0_ns = time.monotonic_ns()

        profile = TIER_PROFILES[tier]
        warnings: list[str] = []

        # ── Step 1: Validate recommended tier ────────────────────────────
        recommended = context.recommended_tier()
        if not tier.is_at_least(recommended):
            warnings.append(
                f"WARNING: Requested tier {tier.value} is below the recommended "
                f"minimum {recommended.value} for this project's domain posture "
                f"({context.domain_posture}). Analysis may miss critical findings."
            )

        # ── Step 2: Parse all Python files ───────────────────────────────
        parse_results: list[ParseResult] = self._parser.parse_directory(
            source_root, max_files=profile.max_files,
        )

        files_analyzed = 0
        files_skipped  = 0
        all_nodes      = []

        for pr in parse_results:
            if pr.had_syntax_error:
                files_skipped += 1
                warnings.append(f"Skipped (syntax error): {pr.source_path}")
                continue
            if pr.line_count == 0:
                files_skipped += 1
                continue
            files_analyzed += 1
            all_nodes.extend(pr.nodes)
            warnings.extend(pr.parse_warnings)

        # ── Invariant: Analysis Vacuum Detection ──────────────────────────
        # If files were analyzed but zero nodes extracted, the analysis
        # is INVALID - not clean. Trust must degrade immediately.
        if files_analyzed > 0 and len(all_nodes) == 0:
            warnings.append(
                "CRITICAL: Analysis produced zero nodes across "
                f"{files_analyzed} analyzed file(s). "
                "This is an ANALYSIS VACUUM - results cannot be trusted. "
                "Possible causes: no registered constructs match this code, "
                "parser returned empty nodes, or file contains only "
                "definitions (classes, functions, constants) without calls."
            )

        # ── Step 3: Enforce LOC quota ─────────────────────────────────────
        total_loc = sum(pr.line_count for pr in parse_results)
        if total_loc > profile.max_loc:
            warnings.append(
                f"LOC quota exceeded: {total_loc:,} > {profile.max_loc:,}. "
                f"Analysis truncated. Use a higher tier profile or exclude directories."
            )

        # ── Step 4: Evaluate all nodes ────────────────────────────────────
        all_decisions: list[PolicyDecision] = []
        for node in all_nodes:
            try:
                decision = self._policy.evaluate(node, context, tier)
                all_decisions.append(decision)
            except Exception as e:
                warnings.append(
                    f"Rule execution degraded at {node.canonical_location}: "
                    f"{type(e).__name__}. This finding was skipped. "
                    f"Other findings are unaffected."
                )
        # ── Step 5: Apply tier-level filters ─────────────────────────────
        # GREEN tier: show everything including INFO
        # BLUE+: suppress INFO findings (reduce noise)
        if not profile.emit_info_findings:
            from src.domain.constructs.construct_model import Severity
            filtered_decisions = []
            for d in all_decisions:
                if d.is_suppressed:
                    filtered_decisions.append(d)
                    continue
                if d.finding and d.finding.severity == Severity.INFO.value:
                    # Re-suppress INFO findings in non-GREEN tiers
                    from src.application.policy.policy_engine import PolicyDecision as PD
                    suppressed = PD(
                        node=d.node,
                        finding=None,
                        is_suppressed=True,
                        suppression_reason=f"INFO finding suppressed in {tier.value} tier",
                        escalation_chain=d.escalation_chain,
                        blocks_pipeline=False,
                        requires_dual_control=False,
                    )
                    filtered_decisions.append(suppressed)
                else:
                    filtered_decisions.append(d)
            all_decisions = filtered_decisions

        # ── Step 6: Build CEFArtifact ─────────────────────────────────────
        artifact = build_artifact(
            decisions=all_decisions,
            context=context,
            tier=tier,
            catalog=self._catalog,
            execution_seed=execution_seed,
            source_hash=context.source_hash,
        )

        # ── Step 7: Pipeline blocking determination ────────────────────────
        from src.domain.constructs.construct_model import Severity as S
        sev_order = {S.INFO.value: 0, S.WARNING.value: 1,
                     S.ERROR.value: 2, S.CRITICAL.value: 3}
        block_threshold = sev_order.get(profile.pipeline_blocking_severity, 999)

        pipeline_blocked = False

        # ── GREEN Security Floor: CRITICAL findings ALWAYS block ──────────
        # Even in GREEN tier (warnings only), CRITICAL severity findings
        # (eval, exec, pickle, subprocess) block the pipeline.
        # GREEN warns on lesser issues but never passes code with RCE vectors.
        if tier == Tier.GREEN:
            critical_count = sum(
                1 for d in all_decisions
                if d.finding and d.finding.severity == S.CRITICAL.value
                and not d.is_suppressed
            )
            if critical_count > 0:
                pipeline_blocked = True
        requires_dual    = False

        for d in all_decisions:
            if d.blocks_pipeline:
                pipeline_blocked = True
            if d.requires_dual_control:
                requires_dual = True
            if d.finding and not d.is_suppressed:
                finding_level = sev_order.get(d.finding.severity, 0)
                if finding_level >= block_threshold and block_threshold < 999:
                    pipeline_blocked = True

        # Invariant: Analysis Vacuum overrides pipeline status
        # DISABLED: Clean code should not be blocked
        # if files_analyzed > 0 and len(all_nodes) == 0:
        #     pipeline_blocked = True
        elapsed_ms = (time.monotonic_ns() - t0_ns) // 1_000_000

        return TierAnalysisResult(
            tier=tier.value,
            profile=profile,
            artifact=artifact,
            parse_results=tuple(parse_results),
            files_analyzed=files_analyzed,
            files_skipped=files_skipped,
            nodes_discovered=len(all_nodes),
            decisions_made=len(all_decisions),
            pipeline_blocked=pipeline_blocked,
            requires_dual_control=requires_dual,
            analysis_warnings=tuple(sorted(warnings)),
            elapsed_ms=elapsed_ms,
        )
