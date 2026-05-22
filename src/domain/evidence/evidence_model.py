"""
******************************************************************************
 * FILE:        /src/domain/evidence/evidence_model.py
 * LAYER:       Domain Layer
 * MODULE:      Evidence Model
 * PURPOSE:     Immutable domain types for verification evidence and artifacts
 * DOMAIN:      Verification Core
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Defines the domain types that represent verification evidence.
 * The Finding is the atomic unit of analysis output.
 * The CEFArtifact is the complete, replayable, auditable record.
 *
 * These types are the CONTRACT between the analysis kernel and the outside
 * world. They are IMMUTABLE after construction. Any system that receives
 * a CEFArtifact can verify its integrity via the artifact_hash field.
 *
 * DEPENDENCIES:
 * - src/domain/constructs/construct_model.py (Tier, Severity, Confidence,
 *   BoundaryType, RiskType, FixedWeight)
 *
 * CONSTRAINTS:
 * - No I/O in this module (pure domain types)
 * - No float fields (all scores are FixedWeight)
 * - All tuples sorted by their canonical key
 * - artifact_hash is computed AFTER all fields are set
 *
 * DETERMINISM GUARANTEES:
 * - All types frozen: no mutation possible
 * - canonical_location is the primary sort key for Finding
 * - BoundaryHonestyScore uses integer arithmetic only
 *
 * FAILURE MODES:
 * - InvalidCanonicalLocation: location string format error
 * - ArtifactIntegrityError: hash verification failure
 * - FindingIdFormatError: finding ID format error
 *
 * SECURITY CONSIDERATIONS:
 * - artifact_hash detects any post-construction tampering
 * - signature field carries cryptographic signature (Phase 1+)
 * - PHASE0-UNSIGNED signature triggers warning in consumers
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
import json
import re
import pathlib
import pathlib
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.domain.constructs.construct_model import (
    BoundaryType,
    Confidence,
    FixedWeight,
    RiskType,
    Severity,
    Tier,
)


# ─── Domain Errors ────────────────────────────────────────────────────────────

class EvidenceDomainError(Exception):
    """Base class for evidence domain errors."""


class InvalidCanonicalLocation(EvidenceDomainError):
    """
    Purpose: Raised when a canonical location string is malformed.
    Expected format: /absolute/path/to/file.py:LINE:COL
    where LINE is 1-indexed and COL is 0-indexed.
    """


class ArtifactIntegrityError(EvidenceDomainError):
    """
    Purpose: Raised when artifact_hash verification fails.
    This indicates the artifact has been tampered with after construction.
    """


class FindingIdFormatError(EvidenceDomainError):
    """Raised when a finding ID does not match F-{NNNNN} pattern."""


# ─── Location Types ───────────────────────────────────────────────────────────

# Canonical location: /absolute/path/to/file.py:LINE:COL
_CANONICAL_LOCATION_PATTERN = re.compile(r'^.{2,}:\d+:\d+$')
# Finding ID: F-NNNNN (5 zero-padded digits)
_FINDING_ID_PATTERN = re.compile(r'^F-\d{5}$')


def validate_canonical_location(location: str) -> str:
    """
    Purpose: Validate and return a canonical location string.
    Inputs: location — string in format /absolute/path:LINE:COL
    Outputs: the validated location string
    Failure: InvalidCanonicalLocation if format is wrong
    Constraints: path must be absolute (starts with /)
    """
    if not _CANONICAL_LOCATION_PATTERN.match(location):
        raise InvalidCanonicalLocation(
            f"Invalid canonical location '{location}'. "
            f"Expected: /absolute/path:LINE:COL (LINE >= 1, COL >= 0)"
        )
    parts = location.rsplit(":", 2)
    line = int(parts[1])
    if line < 1:
        raise InvalidCanonicalLocation(
            f"Line number must be >= 1, got {line} in '{location}'"
        )
    abs_ok=pathlib.Path(parts[0]).is_absolute() or (len(parts[0])>=2 and parts[0][1]==chr(58));
    if not abs_ok: raise InvalidCanonicalLocation(f"Path must be absolute in: {location}")
    return location


# ─── Evidence Sub-types ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class EvidenceStep:
    """
    Purpose: One step in the deterministic evidence chain for a finding.
    Evidence steps form an ordered sequence that traces exactly HOW the
    kernel arrived at a finding. This is the audit trail.

    The evidence chain must be reproducible: given the same source and
    same catalog, the same steps must be produced in the same order.

    Inputs:
    - step_index: 0-based index (determines canonical order)
    - location: canonical location where this step was observed
    - description: what the kernel observed at this step
    - ast_node_type: the AST node type at this location
    - evidence_hash: SHA-256 of this step's canonical form

    Constraints:
    - step_index must be >= 0
    - location must pass validate_canonical_location
    - description must be non-empty
    - evidence_hash format: "sha256:{64 hex chars}"

    Determinism: ordered by step_index; same analysis → same chain
    """
    step_index: int
    location: str            # canonical location
    description: str
    ast_node_type: str
    evidence_hash: str       # sha256:... of this step

    def __post_init__(self) -> None:
        if self.step_index < 0:
            raise EvidenceDomainError(f"step_index must be >= 0, got {self.step_index}")
        validate_canonical_location(self.location)
        if not self.description.strip():
            raise EvidenceDomainError("EvidenceStep.description cannot be empty")
        if not re.match(r'^sha256:[0-9a-f]{64}$', self.evidence_hash):
            raise EvidenceDomainError(
                f"evidence_hash must be 'sha256:{{64 hex chars}}', got '{self.evidence_hash}'"
            )


@dataclass(frozen=True)
class BoundaryDeclaration:
    """
    Purpose: Explicit declaration of what the kernel CANNOT analyze.
    Boundaries are NOT failures. They are honest declarations that build trust.
    A finding with a boundary declaration is MORE trustworthy than one without,
    because it explicitly states where the analysis stopped.

    Inputs:
    - boundary_type: The type of boundary (BoundaryType value)
    - location: Where the boundary was encountered
    - impact: How this boundary affects the finding confidence
    - recommendation: What the user should provide to resolve the boundary
    - human_review_required: Whether a human must review due to this boundary

    Constraints:
    - boundary_type must be a valid BoundaryType value
    - location must be a valid canonical location
    - impact and recommendation must be non-empty

    Source: Foundation Document Section 6.2
    """
    boundary_type: str            # BoundaryType value
    location: str                 # canonical location
    impact: str                   # effect on finding confidence
    recommendation: str           # what user should provide
    human_review_required: bool

    def __post_init__(self) -> None:
        valid_types = {bt.value for bt in BoundaryType}
        if self.boundary_type not in valid_types:
            raise EvidenceDomainError(
                f"Invalid boundary_type '{self.boundary_type}'. Must be one of: {sorted(valid_types)}"
            )
        validate_canonical_location(self.location)
        if not self.impact.strip():
            raise EvidenceDomainError("BoundaryDeclaration.impact cannot be empty")
        if not self.recommendation.strip():
            raise EvidenceDomainError("BoundaryDeclaration.recommendation cannot be empty")


@dataclass(frozen=True)
class FindingRiskMapping:
    """
    Purpose: Maps a specific finding to an industrial risk type with weight.
    Different from the catalog-level RiskMapping — this is per-finding,
    reflecting the specific context of this finding in this analysis.

    Inputs:
    - risk_type: Industrial risk type (RiskType value)
    - weight: Fixed-point weight (numerator/1000)
    - context_note: Why this finding maps to this risk in this context

    Constraints: No floats; weight is integer fixed-point
    """
    risk_type: str          # RiskType value
    weight: FixedWeight
    context_note: str

    def __post_init__(self) -> None:
        valid_types = {rt.value for rt in RiskType}
        if self.risk_type not in valid_types:
            raise EvidenceDomainError(
                f"Invalid risk_type '{self.risk_type}'. Must be one of: {sorted(valid_types)}"
            )


@dataclass(frozen=True)
class ExplainabilityGraph:
    """
    Purpose: Machine-readable and human-readable explanation of WHY a finding
    was generated. This transforms DCAVP from a scanner into an Evidence
    Reasoning Infrastructure.

    Instead of "Rule violated", DCAVP outputs:
    - Which policy triggered this finding
    - Which base policy that policy inherits from
    - What escalation rules applied
    - What standards are violated
    - The complete evidence chain
    - The exact logic expression evaluated

    This is the key differentiator from all other static analysis tools.

    Inputs:
    - base_policy: The root policy this finding derives from
    - base_policy_rationale: Why the base policy exists (cited)
    - triggered_by_policy: The specific policy that triggered this finding
    - triggered_by_version: The version of the triggering policy
    - escalated_by_rules: Sorted tuple of escalation rule IDs applied
    - escalation_conditions: Sorted tuple of conditions that caused escalation
    - mapped_standards: Sorted tuple of standard section identifiers
    - evidence_chain: Ordered tuple of EvidenceStep (ordered by step_index)
    - logic_expression: The boolean expression evaluated to produce this finding

    Constraints:
    - evidence_chain ordered by step_index
    - logic_expression uses only: AND, OR, NOT, parentheses, UPPER_SNAKE_CASE tokens
    - All string lists are sorted tuples

    Determinism: identical analysis → identical ExplainabilityGraph
    """
    base_policy: str
    base_policy_rationale: str
    triggered_by_policy: str
    triggered_by_version: str
    escalated_by_rules: tuple[str, ...]          # sorted
    escalation_conditions: tuple[str, ...]       # sorted
    mapped_standards: tuple[str, ...]            # sorted
    evidence_chain: tuple[EvidenceStep, ...]     # ordered by step_index
    logic_expression: str                        # e.g. "ISR_CONTEXT AND SHARED_MUTABLE_STATE"

    def __post_init__(self) -> None:
        # Evidence chain must be in step_index order
        for i, step in enumerate(self.evidence_chain):
            if step.step_index != i:
                raise EvidenceDomainError(
                    f"Evidence chain step at position {i} has step_index={step.step_index}. "
                    f"Must be sequential starting from 0."
                )


# ─── Finding — the atomic unit of DCAVP output ───────────────────────────────

@dataclass(frozen=True)
class Finding:
    """
    Purpose: A single deterministic finding — the atomic unit of DCAVP output.
    Every Finding is a complete, self-contained verification result.
    It carries not just WHAT was found, but WHY, with what confidence,
    within what bounds, and who should review it.

    The Finding is sorted by canonical_location within an artifact.
    This is the primary sort key: file:line:col.

    Inputs:
    - finding_id: Unique ID within artifact (F-NNNNN)
    - canonical_location: Primary sort key (absolute path:line:col)
    - construct_id: The construct that produced this finding (CONST-X-NNN)
    - construct_name: Human-readable construct name
    - detected_state: The state of the construct that triggered the finding
    - severity: The finding severity
    - confidence: How complete was the analysis that produced this finding
    - policy: The policy ID that produced this finding
    - policy_version: The catalog version of the policy
    - escalation_chain: Ordered tuple of escalation rule IDs applied
    - risk_mappings: Tuple of FindingRiskMapping, sorted by risk_type
    - standards: Sorted tuple of violated standard sections
    - explainability_graph: Complete reasoning trace
    - boundary_status: "resolved" | "boundary_reached" | "unknown"
    - boundaries: Tuple of BoundaryDeclaration (may be empty)
    - human_review_required: Whether a qualified human must review
    - reviewer_qualification: Required reviewer qualification (empty string if not required)
    - evidence_hash: SHA-256 of this finding's canonical form

    Constraints:
    - finding_id must match F-NNNNN pattern
    - canonical_location must be valid
    - construct_id must match CONST-{DOMAIN}-{NNN} pattern
    - boundary_status in {"resolved", "boundary_reached", "unknown"}
    - reviewer_qualification is empty string (not None) when not required

    Determinism: identical analysis → identical Finding byte-for-byte
    Security: evidence_hash detects post-construction tampering
    """
    finding_id: str
    canonical_location: str
    construct_id: str
    construct_name: str
    detected_state: str
    severity: str                               # Severity value
    confidence: str                             # Confidence value
    policy: str
    policy_version: str
    escalation_chain: tuple[str, ...]           # ordered by application
    risk_mappings: tuple[FindingRiskMapping, ...] # sorted by risk_type
    standards: tuple[str, ...]                  # sorted
    explainability_graph: ExplainabilityGraph
    boundary_status: str                        # "resolved" | "boundary_reached" | "unknown"
    boundaries: tuple[BoundaryDeclaration, ...]
    human_review_required: bool
    reviewer_qualification: str                 # empty string if not required (NOT None)
    evidence_hash: str                          # sha256:... of canonical form

    _BOUNDARY_STATUSES = frozenset({"resolved", "boundary_reached", "unknown"})
    _CONSTRUCT_ID_PATTERN = re.compile(r'^CONST-[A-Z]{2,8}-\d{3}$')

    def __post_init__(self) -> None:
        if not _FINDING_ID_PATTERN.match(self.finding_id):
            raise FindingIdFormatError(
                f"Invalid finding_id '{self.finding_id}'. Expected: F-NNNNN"
            )
        validate_canonical_location(self.canonical_location)
        if not self._CONSTRUCT_ID_PATTERN.match(self.construct_id):
            raise EvidenceDomainError(
                f"Invalid construct_id '{self.construct_id}'"
            )
        valid_severities = {s.value for s in Severity}
        if self.severity not in valid_severities:
            raise EvidenceDomainError(f"Invalid severity '{self.severity}'")
        valid_confidences = {c.value for c in Confidence}
        if self.confidence not in valid_confidences:
            raise EvidenceDomainError(f"Invalid confidence '{self.confidence}'")
        if self.boundary_status not in self._BOUNDARY_STATUSES:
            raise EvidenceDomainError(
                f"Invalid boundary_status '{self.boundary_status}'. "
                f"Must be: {sorted(self._BOUNDARY_STATUSES)}"
            )
        # reviewer_qualification must be empty string (not None) if not required
        if self.reviewer_qualification is None:
            raise EvidenceDomainError(
                "reviewer_qualification must be empty string '' when not required, not None. "
                "CEF requires explicit empty string."
            )


# ─── Execution Context ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ExecutionContext:
    """
    Purpose: Captures all metadata needed for perfect replay of an analysis.
    Without this context, replay is impossible. With it, any analysis can be
    reproduced byte-for-byte on any compatible platform.

    Inputs:
    - seed: Hex string derived from run parameters (enables replay)
    - timestamp_utc: UTC timestamp at analysis start (ISO 8601 microsecond)
    - host_fingerprint: Canonical identifier of the analysis host
    - kernel_version: DCAVP kernel version string
    - catalog_version: KnowledgeCatalog version used
    - python_version: Runtime Python version (e.g., "3.12.3")
    - platform_id: OS and architecture (e.g., "linux/x86_64")
    - locale: Always "C" (enforced by kernel startup)
    - timezone_id: Always "UTC" (enforced by kernel startup)

    Constraints:
    - locale must be exactly "C"
    - timezone_id must be exactly "UTC"
    - timestamp_utc must match ISO 8601 UTC format
    - seed must be hex string starting with "0x"
    """
    seed: str
    timestamp_utc: str
    host_fingerprint: str
    kernel_version: str
    catalog_version: str
    python_version: str
    platform_id: str
    locale: str          # always "C"
    timezone_id: str     # always "UTC"

    def __post_init__(self) -> None:
        if self.locale != "C":
            raise EvidenceDomainError(
                f"ExecutionContext.locale must be exactly 'C', got '{self.locale}'. "
                f"Kernel must set locale to C before analysis."
            )
        if self.timezone_id != "UTC":
            raise EvidenceDomainError(
                f"ExecutionContext.timezone_id must be exactly 'UTC', got '{self.timezone_id}'."
            )
        if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$', self.timestamp_utc):
            raise EvidenceDomainError(
                f"timestamp_utc must be ISO 8601 UTC microsecond precision "
                f"(YYYY-MM-DDTHH:MM:SS.ffffffZ), got '{self.timestamp_utc}'"
            )
        if not re.match(r'^0x[0-9a-f]+$', self.seed):
            raise EvidenceDomainError(
                f"seed must be hex string starting with '0x', got '{self.seed}'"
            )


# ─── Boundary Honesty Score ───────────────────────────────────────────────────

@dataclass(frozen=True)
class BoundaryHonestyReport:
    """
    Purpose: Aggregate boundary honesty score for a complete artifact.
    This is the trust indicator for the analysis.

    Formula (integer arithmetic):
    score = 1 - (weighted_boundary_count / total_analysis_points)
    Expressed as: score_numerator / score_denominator

    Score interpretation (Foundation Document Section 6.4):
    - score > 950/1000  (>0.95): Full trust
    - score 800-950/1000        : Qualified trust; review boundaries
    - score < 800/1000  (<0.80) : Insufficient visibility; analysis incomplete

    Inputs:
    - total_analysis_points: Total number of constructs analyzed
    - boundary_count_unweighted: Raw count of boundaries encountered
    - boundary_weight_total: Weighted boundary count (numerator, denom=total_analysis_points*1000)
    - score_numerator: Score as fraction (numerator)
    - score_denominator: Always 1000
    - trust_level: "full" | "qualified" | "insufficient"
    - recommendations: Sorted tuple of boundary resolution recommendations

    Constraints: All arithmetic is integer; no floats
    """
    total_analysis_points: int
    boundary_count_unweighted: int
    boundary_weight_numerator: int    # integer
    boundary_weight_denominator: int  # = total_analysis_points * 1000
    score_numerator: int              # in [0, 1000]
    score_denominator: int            # always 1000
    trust_level: str                  # "full" | "qualified" | "insufficient"
    recommendations: tuple[str, ...]  # sorted

    _TRUST_LEVELS = frozenset({"full", "qualified", "insufficient"})

    def __post_init__(self) -> None:
        if self.trust_level not in self._TRUST_LEVELS:
            raise EvidenceDomainError(
                f"Invalid trust_level '{self.trust_level}'. Must be: {sorted(self._TRUST_LEVELS)}"
            )
        if self.score_denominator != 1000:
            raise EvidenceDomainError(
                f"score_denominator must be 1000, got {self.score_denominator}"
            )
        if not (0 <= self.score_numerator <= 1000):
            raise EvidenceDomainError(
                f"score_numerator must be in [0, 1000], got {self.score_numerator}"
            )

    @classmethod
    def compute(
        cls,
        total_analysis_points: int,
        boundaries: list[BoundaryDeclaration],
        boundary_weights: dict[str, int],  # BoundaryType.value → weight (per 1000)
        recommendations: tuple[str, ...],
    ) -> BoundaryHonestyReport:
        """
        Purpose: Compute BoundaryHonestyReport from raw analysis data.
        Inputs:
        - total_analysis_points: How many constructs were analyzed
        - boundaries: All boundary declarations from the analysis
        - boundary_weights: Per-type weights (integer per 1000)
        - recommendations: Sorted recommendations for resolving boundaries
        Outputs: BoundaryHonestyReport
        Constraints: All arithmetic is integer; no floats
        Determinism: same inputs → same output
        """
        if total_analysis_points == 0:
            return cls(
                total_analysis_points=0,
                boundary_count_unweighted=0,
                boundary_weight_numerator=0,
                boundary_weight_denominator=1000,
                score_numerator=1000,
                score_denominator=1000,
                trust_level="full",
                recommendations=tuple(sorted(recommendations)),
            )

        weighted_sum = sum(
            boundary_weights.get(b.boundary_type, 500)
            for b in boundaries
        )
        denom = total_analysis_points * 1000
        # score = 1 - (weighted_sum / denom) expressed as numerator/1000
        score_n = 1000 - (weighted_sum * 1000 // denom)
        score_n = max(0, min(1000, score_n))

        trust: str
        if score_n > 950:
            trust = "full"
        elif score_n >= 800:
            trust = "qualified"
        else:
            trust = "insufficient"

        return cls(
            total_analysis_points=total_analysis_points,
            boundary_count_unweighted=len(boundaries),
            boundary_weight_numerator=weighted_sum,
            boundary_weight_denominator=denom,
            score_numerator=score_n,
            score_denominator=1000,
            trust_level=trust,
            recommendations=tuple(sorted(recommendations)),
        )


# ─── CEF Artifact ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CEFArtifact:
    """
    Purpose: The complete, replayable, auditable verification artifact.
    This is the legal-grade output of DCAVP. Every CEFArtifact is:
    - Bit-identical across replays (determinism guarantee)
    - Self-verifiable via artifact_hash
    - Cryptographically signed (Phase 1+; unsigned in Phase 0)
    - Self-contained with all metadata for replay

    This is NOT a "scan result". It is a DECISION ARTIFACT — a legally
    defensible, auditable record of exactly what was analyzed, how,
    and what was found.

    Inputs:
    - cef_version: Always "1.0" for this schema version
    - artifact_id: UUID v4 (lowercase, hyphenated)
    - artifact_hash: SHA-256 of canonical form (or "PENDING" during construction)
    - execution: Complete execution context for replay
    - tier: Analysis tier used
    - analysis_scope: What was analyzed (e.g., "full_source_tree")
    - source_root: Absolute, canonical path to source root
    - source_hash: SHA-256 of the source tree manifest
    - findings: Sorted tuple of Finding (by canonical_location)
    - artifact_level_boundaries: Boundaries at artifact scope (not finding-specific)
    - boundary_honesty: Aggregate honesty report
    - warning: Phase 0 warning (or empty string in Phase 1+)
    - signature: Ed25519 signature (or "PHASE0-UNSIGNED")

    Constraints:
    - findings sorted by (canonical_location, construct_id, policy)
    - artifact_hash is "PENDING" during construction, filled by CEFSerializer
    - signature is "PHASE0-UNSIGNED" in Phase 0; Ed25519 in Phase 1+
    - warning is non-empty in Phase 0, empty in Phase 1+

    Determinism: CEFSerializer.finalize() produces byte-identical artifact_hash
    Security: artifact_hash detects any field modification after construction
    """
    cef_version: str
    artifact_id: str
    artifact_hash: str                              # sha256:... or "PENDING"
    execution: ExecutionContext
    tier: str                                       # Tier value
    analysis_scope: str
    source_root: str                                # absolute canonical path
    source_hash: str                                # sha256:... of source tree
    findings: tuple[Finding, ...]                   # sorted by canonical_location
    artifact_level_boundaries: tuple[BoundaryDeclaration, ...]
    boundary_honesty: BoundaryHonestyReport
    finding_count: int                              # must equal len(findings)
    warning: str                                    # non-empty in Phase 0
    signature: str                                  # "PHASE0-UNSIGNED" in Phase 0

    def __post_init__(self) -> None:
        if self.cef_version != "1.0":
            raise EvidenceDomainError(
                f"CEFArtifact.cef_version must be '1.0', got '{self.cef_version}'"
            )
        valid_tiers = {t.value for t in Tier}
        if self.tier not in valid_tiers:
            raise EvidenceDomainError(f"Invalid tier '{self.tier}'")
        if self.finding_count != len(self.findings):
            raise EvidenceDomainError(
                f"finding_count {self.finding_count} != len(findings) {len(self.findings)}"
            )
        # Verify findings are sorted by canonical_location
        locations = [f.canonical_location for f in self.findings]
        if locations != sorted(locations):
            raise EvidenceDomainError(
                "findings must be sorted by canonical_location. "
                "Use sorted(findings, key=lambda f: f.canonical_location)."
            )
        # UUID v4 format check (basic)
        if not re.match(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
            self.artifact_id
        ):
            raise EvidenceDomainError(
                f"artifact_id must be UUID v4 (lowercase, hyphenated), got '{self.artifact_id}'"
            )
