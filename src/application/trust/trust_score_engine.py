"""
******************************************************************************
 * FILE:        /src/application/trust/trust_score_engine.py
 * LAYER:       Application Layer
 * MODULE:      Trust Score Engine
 * PURPOSE:     Compute composite 5-dimension trust score from CEFArtifact
 * DOMAIN:      Trust Infrastructure
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-14
 * UPDATED:     2026-05-14
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * DELTA EXTENSION — does not modify any existing module.
 * Reads from CEFArtifact (immutable) and produces TrustScoreReport.
 *
 * DIMENSIONS (from Unified Directive Section 26):
 *   Security         30% — vulnerabilities, attack surfaces, dangerous constructs
 *   Determinism      25% — determinism violations, non-deterministic patterns
 *   Maintainability  20% — global state, complexity, threading without sync
 *   AI Reliability   15% — hallucination indicators, AI anti-patterns
 *   Dependency Health 10% — supply chain risks (Phase 9+; placeholder in Phase 0)
 *
 * ARITHMETIC: Integer fixed-point throughout. Score = numerator / 1000.
 * No floats in any decision path (Engineering Constitution Article I).
 *
 * BACKWARD COMPATIBILITY: CEFArtifact schema is not modified.
 * TrustScoreReport is a NEW type — purely additive.
 *
 * DEPENDENCIES: src/domain/evidence/evidence_model.py (CEFArtifact — read only)
 * CONSTRAINTS:  No I/O; pure computation from immutable CEFArtifact
 * DETERMINISM:  Same artifact → same TrustScoreReport (byte-identical)
 * LICENSE:      Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

from dataclasses import dataclass


# ─── Score Constants (integer fixed-point, denominator = 1000) ────────────────

# Severity penalties (deducted from 1000)
_PENALTY_CRITICAL  = 120    # per CRITICAL finding
_PENALTY_ERROR     = 50     # per ERROR finding
_PENALTY_WARNING   = 15     # per WARNING finding
_PENALTY_BOUNDARY  = 25     # per boundary_reached finding (incomplete visibility)

# Dimension weights (must sum to 1000)
_WEIGHT_SECURITY        = 300
_WEIGHT_DETERMINISM     = 250
_WEIGHT_MAINTAINABILITY = 200
_WEIGHT_AI_RELIABILITY  = 150
_WEIGHT_DEP_HEALTH      = 100
_WEIGHT_TOTAL = (_WEIGHT_SECURITY + _WEIGHT_DETERMINISM + _WEIGHT_MAINTAINABILITY
                 + _WEIGHT_AI_RELIABILITY + _WEIGHT_DEP_HEALTH)
assert _WEIGHT_TOTAL == 1000, "Dimension weights must sum to 1000"

# Construct → dimension mapping (deterministic classification)
_SECURITY_CONSTRUCTS = frozenset({
    "CONST-EVAL-001", "CONST-EXEC-001", "CONST-PICK-001",
    "CONST-SUBP-001", "CONST-OPEN-001",
})
_DETERMINISM_CONSTRUCTS = frozenset({
    "CONST-RAND-001", "CONST-ASYNC-001",
})
_MAINTAINABILITY_CONSTRUCTS = frozenset({
    "CONST-GLOB-001", "CONST-THRD-001", "CONST-LOCK-001",
})
# AI hallucination construct IDs (added in this evolution)
_AI_RELIABILITY_CONSTRUCTS = frozenset({
    "CONST-HALL-001", "CONST-HALL-002", "CONST-HALL-003",
})

# Interpretation bands (numerator / 1000)
_BAND_HIGH     = 900   # >= 900 → 🟢 High trust — production ready
_BAND_MODERATE = 700   # >= 700 → 🟡 Moderate trust — review recommended
_BAND_LOW      = 500   # >= 500 → 🟠 Low trust — substantial improvements needed
                       # < 500  → 🔴 Weak trust — unsafe for deployment


# ─── Trust Score Types ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DimensionScore:
    """
    Purpose: Score for one trust dimension.
    All arithmetic uses integer fixed-point (numerator / 1000).

    Inputs:
    - dimension: Human-readable dimension name
    - score_numerator: Score in [0, 1000] (1000 = perfect)
    - weight_numerator: Dimension weight in [0, 1000]
    - finding_count: Findings that penalized this dimension
    - penalty_applied: Total penalty applied (integer, per 1000)
    - band: "high" | "moderate" | "low" | "weak"
    - rationale: Why this score was computed
    """
    dimension: str
    score_numerator: int         # [0, 1000]
    weight_numerator: int        # dimension weight
    finding_count: int
    penalty_applied: int
    band: str
    rationale: str

    def weighted_contribution(self) -> int:
        """Weighted contribution to overall score (integer arithmetic)."""
        return (self.score_numerator * self.weight_numerator) // 1000

    def emoji(self) -> str:
        if self.score_numerator >= _BAND_HIGH:     return "🟢"
        if self.score_numerator >= _BAND_MODERATE: return "🟡"
        if self.score_numerator >= _BAND_LOW:      return "🟠"
        return "🔴"


@dataclass(frozen=True)
class TrustScoreReport:
    """
    Purpose: Complete composite trust score report for a CEFArtifact.
    This is the primary user-facing quality summary.

    Inputs:
    - artifact_hash: Links this report to the source artifact
    - tier: The tier used for analysis
    - overall_score: Weighted composite score [0, 1000]
    - overall_band: "high" | "moderate" | "low" | "weak"
    - security: Security dimension score
    - determinism: Determinism dimension score
    - maintainability: Maintainability dimension score
    - ai_reliability: AI reliability dimension score
    - dependency_health: Dependency health dimension score
    - total_findings: Total non-suppressed findings
    - boundary_count: Analysis boundaries (incomplete coverage)
    - production_ready: True if overall_score >= 700 and no CRITICAL findings
    - top_concerns: Sorted tuple of up to 5 most impactful concerns
    - recommendations: Sorted tuple of up to 5 prioritized recommendations
    """
    artifact_hash: str
    tier: str
    overall_score: int              # [0, 1000] — weighted composite
    overall_band: str               # "high" | "moderate" | "low" | "weak"
    security: DimensionScore
    determinism: DimensionScore
    maintainability: DimensionScore
    ai_reliability: DimensionScore
    dependency_health: DimensionScore
    total_findings: int
    boundary_count: int
    production_ready: bool
    top_concerns: tuple[str, ...]   # sorted by impact
    recommendations: tuple[str, ...]

    def emoji(self) -> str:
        if self.overall_score >= _BAND_HIGH:     return "🟢"
        if self.overall_score >= _BAND_MODERATE: return "🟡"
        if self.overall_score >= _BAND_LOW:      return "🟠"
        return "🔴"

    def format_summary(self) -> str:
        """Human-readable summary for CLI/UI output."""
        e = self.emoji()
        lines = [
            "╔══════════════════════════════════════╗",
            "║         Trust Score Summary           ║",
            "╠══════════════════════════════════════╣",
            f"║ Security         {self.security.emoji()}  {self.security.score_numerator // 10:3d}/100    ║",
            f"║ Determinism      {self.determinism.emoji()}  {self.determinism.score_numerator // 10:3d}/100    ║",
            f"║ Maintainability  {self.maintainability.emoji()}  {self.maintainability.score_numerator // 10:3d}/100    ║",
            f"║ AI Reliability   {self.ai_reliability.emoji()}  {self.ai_reliability.score_numerator // 10:3d}/100    ║",
            f"║ Dependency Hlth  {self.dependency_health.emoji()}  {self.dependency_health.score_numerator // 10:3d}/100    ║",
            "╠══════════════════════════════════════╣",
            f"║ OVERALL SCORE    {e}  {self.overall_score // 10:3d}/100    ║",
            "╚══════════════════════════════════════╝",
        ]
        return "\n".join(lines)


# ─── Score Computer ───────────────────────────────────────────────────────────

def _band(score: int) -> str:
    if score >= _BAND_HIGH:     return "high"
    if score >= _BAND_MODERATE: return "moderate"
    if score >= _BAND_LOW:      return "low"
    return "weak"


def _clamp(value: int, lo: int = 0, hi: int = 1000) -> int:
    """Clamp to [lo, hi] — no floats."""
    return max(lo, min(hi, value))


def _compute_dimension(
    findings: list,
    relevant_constructs: frozenset[str],
    dimension_name: str,
    weight: int,
    base_score: int = 1000,
) -> DimensionScore:
    """
    Purpose: Compute one dimension score from filtered findings.
    Pure function; integer arithmetic only.
    Findings not in relevant_constructs do not affect this dimension.
    """
    from src.domain.constructs.construct_model import Severity

    relevant = [f for f in findings if f.construct_id in relevant_constructs]
    boundary_count = sum(1 for f in relevant if f.boundary_status == "boundary_reached")

    penalty = 0
    for f in relevant:
        if f.severity == Severity.CRITICAL.value:
            penalty += _PENALTY_CRITICAL
        elif f.severity == Severity.ERROR.value:
            penalty += _PENALTY_ERROR
        elif f.severity == Severity.WARNING.value:
            penalty += _PENALTY_WARNING
    penalty += boundary_count * _PENALTY_BOUNDARY

    score = _clamp(base_score - penalty)
    rationale = (
        f"{len(relevant)} relevant findings: "
        f"{sum(1 for f in relevant if f.severity=='critical')} CRITICAL, "
        f"{sum(1 for f in relevant if f.severity=='error')} ERROR, "
        f"{sum(1 for f in relevant if f.severity=='warning')} WARNING. "
        f"Penalty={penalty}. "
        + (f"Boundaries: {boundary_count}." if boundary_count else "No boundaries.")
    )
    return DimensionScore(
        dimension=dimension_name,
        score_numerator=score,
        weight_numerator=weight,
        finding_count=len(relevant),
        penalty_applied=penalty,
        band=_band(score),
        rationale=rationale,
    )


def compute_trust_score(artifact) -> TrustScoreReport:
    """
    Purpose: Compute TrustScoreReport from a CEFArtifact.
    This is the primary entry point for the Trust Score Engine.

    Inputs: artifact — a CEFArtifact (immutable; not modified)
    Outputs: TrustScoreReport (immutable)

    Constraints:
    - Pure function: no I/O, no side effects
    - Deterministic: same artifact → same report
    - No float arithmetic

    Complexity: O(n) where n = finding_count
    """
    from src.domain.constructs.construct_model import Severity

    findings = list(artifact.findings)
    boundary_count = sum(1 for f in findings if f.boundary_status == "boundary_reached")

    # Compute each dimension
    security = _compute_dimension(
        findings, _SECURITY_CONSTRUCTS, "Security", _WEIGHT_SECURITY
    )
    determinism = _compute_dimension(
        findings, _DETERMINISM_CONSTRUCTS, "Determinism", _WEIGHT_DETERMINISM
    )
    maintainability = _compute_dimension(
        findings, _MAINTAINABILITY_CONSTRUCTS, "Maintainability", _WEIGHT_MAINTAINABILITY
    )
    ai_reliability = _compute_dimension(
        findings, _AI_RELIABILITY_CONSTRUCTS, "AI Reliability", _WEIGHT_AI_RELIABILITY,
        base_score=1000,  # No AI hallucination constructs yet → perfect score by default
    )

    # Dependency health: placeholder until Phase 9 supply chain analysis
    # Score is 850 (🟢) by default — supply chain analysis pending
    dep_health = DimensionScore(
        dimension="Dependency Health",
        score_numerator=850,
        weight_numerator=_WEIGHT_DEP_HEALTH,
        finding_count=0,
        penalty_applied=0,
        band="high",
        rationale="Supply chain analysis pending (Phase 9). Default score: 850/1000.",
    )

    # Weighted composite (integer arithmetic)
    overall = (
        security.weighted_contribution()
        + determinism.weighted_contribution()
        + maintainability.weighted_contribution()
        + ai_reliability.weighted_contribution()
        + dep_health.weighted_contribution()
    )
    overall = _clamp(overall)

    # Production readiness: overall >= 700 AND zero CRITICAL findings
    has_critical = any(f.severity == Severity.CRITICAL.value for f in findings)
    production_ready = (overall >= _BAND_MODERATE) and not has_critical

    # Top concerns (sorted by impact: CRITICAL first, then score order)
    concerns: list[tuple[int, str]] = []  # (priority_key, concern_text)
    for f in findings:
        if f.severity == Severity.CRITICAL.value:
            concerns.append((0, f"{f.construct_name}: {f.detected_state} [{f.canonical_location.split('/')[-1]}]"))
        elif f.severity == Severity.ERROR.value:
            concerns.append((1, f"{f.construct_name}: {f.detected_state}"))
    # Add dimension concerns
    for dim in sorted([security, determinism, maintainability], key=lambda d: d.score_numerator):
        if dim.score_numerator < _BAND_MODERATE:
            concerns.append((2, f"Low {dim.dimension} score ({dim.score_numerator // 10}/100)"))
    top_concerns = tuple(c[1] for c in sorted(concerns, key=lambda x: x[0])[:5])

    # Recommendations
    recs: list[str] = []
    if has_critical:
        recs.append("Address all CRITICAL findings before any deployment")
    if security.score_numerator < _BAND_MODERATE:
        recs.append("Replace eval/exec/pickle with safe alternatives (json, ast.literal_eval)")
    if determinism.score_numerator < _BAND_HIGH:
        recs.append("Replace random module with secrets for security-sensitive operations")
    if maintainability.score_numerator < _BAND_HIGH:
        recs.append("Eliminate global mutable state; use dependency injection")
    if boundary_count > 0:
        recs.append(f"Resolve {boundary_count} analysis boundaries for higher confidence")
    if not recs:
        recs.append("Code meets trust thresholds. Continue monitoring.")
    recommendations = tuple(sorted(recs)[:5])

    return TrustScoreReport(
        artifact_hash=artifact.artifact_hash,
        tier=artifact.tier,
        overall_score=overall,
        overall_band=_band(overall),
        security=security,
        determinism=determinism,
        maintainability=maintainability,
        ai_reliability=ai_reliability,
        dependency_health=dep_health,
        total_findings=len(findings),
        boundary_count=boundary_count,
        production_ready=production_ready,
        top_concerns=top_concerns,
        recommendations=recommendations,
    )
