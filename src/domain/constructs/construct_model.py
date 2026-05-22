"""
******************************************************************************
 * FILE:        /src/domain/constructs/construct_model.py
 * LAYER:       Domain Layer
 * MODULE:      Construct System
 * PURPOSE:     Immutable domain types for code construct classification
 * DOMAIN:      Verification Core
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Defines the immutable domain types that represent code constructs.
 * A Construct is an identifiable code pattern (async, eval, lock, etc.)
 * that has documented states, danger conditions, and tier permissions.
 *
 * This module contains ZERO I/O, ZERO external dependencies, ZERO runtime
 * state. It is pure domain logic — the stable core of DCAVP.
 *
 * Every type here is frozen (immutable after construction). Any attempt
 * to mutate a construct definition raises FrozenInstanceError at runtime.
 *
 * DEPENDENCIES:
 * - Python stdlib: dataclasses, enum, typing (no external packages)
 *
 * CONSTRAINTS:
 * - Deterministic execution only
 * - No runtime mutation of any field
 * - No hidden heuristics
 * - No AI/ML/probabilistic logic
 * - All collections are tuples (immutable) not lists
 * - All float fields forbidden (use FixedPoint for scores)
 *
 * DETERMINISM GUARANTEES:
 * - All types are frozen dataclasses: no mutation possible
 * - All collection fields are tuple (immutable, ordered)
 * - Equality comparison is value-based (not identity)
 * - Hashing is deterministic (frozen dataclasses auto-hash)
 *
 * FAILURE MODES:
 * - Invalid construct_id format: ConstructIdFormatError
 * - Unknown tier in permission: TierValidationError
 * - Severity not in allowed set: SeverityValidationError
 *
 * SECURITY CONSIDERATIONS:
 * - Types are immutable; catalog cannot be modified after load
 * - No dynamic attribute access; all fields are statically typed
 *
 * COMPLEXITY: O(1) construction; O(1) field access
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ─── Domain Errors ────────────────────────────────────────────────────────────

class ConstructDomainError(Exception):
    """Base class for all construct domain errors."""


class ConstructIdFormatError(ConstructDomainError):
    """
    Purpose: Raised when a construct ID does not conform to the canonical format.
    Format: CONST-{DOMAIN}-{NNN} where DOMAIN is 4 uppercase letters,
            NNN is a zero-padded 3-digit integer.
    Example: CONST-ASYNC-001, CONST-EVAL-042
    """


class TierValidationError(ConstructDomainError):
    """Raised when an unknown tier string is encountered."""


class SeverityValidationError(ConstructDomainError):
    """Raised when a severity string is not in the allowed set."""


class ConfidenceValidationError(ConstructDomainError):
    """Raised when a confidence string is not in the allowed set."""


# ─── Canonical Enumerations ───────────────────────────────────────────────────

class Tier(str, Enum):
    """
    Purpose: Represents the analysis tier — determines analysis depth and
             policy strictness.
    Constraints: Fixed set; no dynamic member creation.
    Determinism: Enum members are ordered by definition order.

    GREEN:  Exploratory / Educational — AST only, ultra-fast
    BLUE:   Commercial / Professional — bounded dataflow
    YELLOW: High Assurance / Regulated — bounded simulation
    RED:    Industrial / Critical — full bounded operational simulation
    """
    GREEN  = "GREEN"
    BLUE   = "BLUE"
    YELLOW = "YELLOW"
    RED    = "RED"

    @classmethod
    def all_ordered(cls) -> tuple[Tier, ...]:
        """Returns all tiers in strictness order (least to most strict)."""
        return (cls.GREEN, cls.BLUE, cls.YELLOW, cls.RED)

    def is_at_least(self, minimum: Tier) -> bool:
        """
        Purpose: Check if this tier meets a minimum strictness requirement.
        Inputs: minimum — the minimum required tier
        Outputs: bool — True if this tier is at least as strict as minimum
        """
        order = {cls: i for i, cls in enumerate(Tier.all_ordered())}
        return order[self] >= order[minimum]


class Severity(str, Enum):
    """
    Purpose: Represents the severity of a finding.
    Constraints: Fixed 4-level scale; no intermediate levels.
    Determinism: Members ordered by increasing severity.

    INFO:     Informational; no action required
    WARNING:  Attention recommended; review before production
    ERROR:    Action required; should not reach production
    CRITICAL: Must fix immediately; may block pipeline in YELLOW/RED
    """
    INFO     = "info"
    WARNING  = "warning"
    ERROR    = "error"
    CRITICAL = "critical"

    @classmethod
    def ordered(cls) -> tuple[Severity, ...]:
        """Returns severities in ascending order."""
        return (cls.INFO, cls.WARNING, cls.ERROR, cls.CRITICAL)

    def numeric_level(self) -> int:
        """
        Purpose: Return integer severity level for comparison.
        Outputs: int (0=info, 1=warning, 2=error, 3=critical)
        Constraints: No float; integer comparison only.
        """
        return {
            Severity.INFO:     0,
            Severity.WARNING:  1,
            Severity.ERROR:    2,
            Severity.CRITICAL: 3,
        }[self]


class Confidence(str, Enum):
    """
    Purpose: Represents the confidence level of a finding.
    This is NOT a probability. It is a deterministic classification
    of how much of the analysis was within the bounded scope.

    CERTAIN:   Analysis fully resolved; no boundary reached
    BOUNDED:   Analysis completed within bounds; result is sound within bounds
    HEURISTIC: Analysis used a documented, bounded heuristic; result is approximate
    UNKNOWN:   Analysis boundary reached; result may be incomplete
    """
    CERTAIN   = "certain"
    BOUNDED   = "bounded"
    HEURISTIC = "heuristic"
    UNKNOWN   = "unknown"


class BoundaryType(str, Enum):
    """
    Purpose: Classifies the type of analysis boundary encountered.
    Constraints: Fixed set; matches Section 6.2 of Foundation Document.

    Boundaries are NOT errors. They are HONEST declarations of what
    the system cannot analyze. They are part of the artifact.
    """
    ANALYSIS_BOUNDARY_REACHED        = "ANALYSIS_BOUNDARY_REACHED"
    UNRESOLVED_DYNAMIC_DISPATCH      = "UNRESOLVED_DYNAMIC_DISPATCH"
    INCOMPLETE_VISIBILITY            = "INCOMPLETE_VISIBILITY"
    SIMULATION_DEPTH_EXCEEDED        = "SIMULATION_DEPTH_EXCEEDED"
    SYMBOLIC_LIMIT_REACHED           = "SYMBOLIC_LIMIT_REACHED"
    EXTERNAL_DEPENDENCY_UNRESOLVED   = "EXTERNAL_DEPENDENCY_UNRESOLVED"
    RUNTIME_BEHAVIOR_UNKNOWN         = "RUNTIME_BEHAVIOR_UNKNOWN"
    CONCURRENCY_INTERLEAVING_UNKNOWN = "CONCURRENCY_INTERLEAVING_UNKNOWN"


class RiskType(str, Enum):
    """
    Purpose: Industrial risk taxonomy for finding classification.
    Source: Foundation Document Section 7.1.
    Citation: Aligned with IEC 61508 hazard classification framework.

    SAFETY:        Physical harm potential
    FINANCIAL:     Monetary loss potential
    OPERATIONAL:   System unavailability potential
    COMPLIANCE:    Regulatory standard violation
    CYBERSECURITY: Unauthorized access potential
    RELIABILITY:   Silent failure potential
    DETERMINISM:   Non-reproducible behavior potential
    """
    SAFETY        = "Safety Risk"
    FINANCIAL     = "Financial Risk"
    OPERATIONAL   = "Operational Risk"
    COMPLIANCE    = "Compliance Risk"
    CYBERSECURITY = "Cybersecurity Risk"
    RELIABILITY   = "Reliability Risk"
    DETERMINISM   = "Determinism Risk"


class TierPermissionLevel(str, Enum):
    """
    Purpose: Classifies what is permitted for a construct at a given tier.
    Constraints: Fixed 4-level permission scale matching Foundation Document Section 9.
    """
    ALLOWED_WITH_WARNING              = "allowed_with_warning"
    ALLOWED_WITH_BOUNDED_CHECK        = "allowed_with_bounded_check"
    REQUIRES_EXPLICIT_JUSTIFICATION   = "requires_explicit_justification"
    FORBIDDEN_WITHOUT_DUAL_CONTROL    = "forbidden_without_dual_control"


# ─── Fixed-Point Arithmetic (No Floats) ──────────────────────────────────────

@dataclass(frozen=True)
class FixedWeight:
    """
    Purpose: Represents a weight or score as a rational number (integer/integer).
    This avoids all floating-point arithmetic in the decision path.

    Inputs:
    - numerator: integer in range [0, denominator]
    - denominator: always 1000 (convention)

    Constraints:
    - No float fields
    - denominator must be positive
    - numerator must be in [0, denominator]
    - Arithmetic via integer operations only

    Example:
    - Weight of 0.8 → FixedWeight(numerator=800, denominator=1000)
    - Weight of 1.0 → FixedWeight(numerator=1000, denominator=1000)
    - Weight of 0.0 → FixedWeight(numerator=0, denominator=1000)
    """
    numerator: int
    denominator: int = 1000

    def __post_init__(self) -> None:
        if self.denominator <= 0:
            raise ValueError(f"FixedWeight denominator must be positive, got {self.denominator}")
        if not (0 <= self.numerator <= self.denominator):
            raise ValueError(
                f"FixedWeight numerator {self.numerator} out of range [0, {self.denominator}]"
            )

    def as_percent(self) -> int:
        """Returns weight as integer percentage (0-100). No floats."""
        return (self.numerator * 100) // self.denominator

    def is_zero(self) -> bool:
        return self.numerator == 0

    def is_maximum(self) -> bool:
        return self.numerator == self.denominator


# ─── Construct Sub-types ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class AnalysisBounds:
    """
    Purpose: Defines the explicit analysis limits for a construct.
    These bounds prevent unbounded recursion, infinite loops, and
    path explosion. They are NOT implementation details — they are
    knowledge catalog entries that determine what analysis is sound.

    Inputs:
    - max_call_depth: Maximum call graph traversal depth
    - max_loop_unroll: Maximum number of loop iterations to unroll
    - max_branch_count: Maximum number of CFG branches to explore
    - max_coroutine_count: Maximum coroutines tracked simultaneously
    - rationale: Human-readable explanation of why these bounds exist
    - source_reference: Citation for the bound values if from literature

    Constraints:
    - All bounds are positive integers
    - Bound of 0 means "this analysis is not performed"
    - No dynamic adjustment of bounds at runtime
    - Bounds are per-tier (different tier = different AnalysisBounds)

    Determinism guarantee: bounds are constants; analysis always terminates
    """
    max_call_depth: int
    max_loop_unroll: int
    max_branch_count: int
    max_coroutine_count: int
    rationale: str
    source_reference: str    # Citation or "ENGINEERING-JUDGMENT-v0.1.0"

    def __post_init__(self) -> None:
        for field_name, value in [
            ("max_call_depth", self.max_call_depth),
            ("max_loop_unroll", self.max_loop_unroll),
            ("max_branch_count", self.max_branch_count),
            ("max_coroutine_count", self.max_coroutine_count),
        ]:
            if value < 0:
                raise ValueError(f"AnalysisBounds.{field_name} must be >= 0, got {value}")


@dataclass(frozen=True)
class DangerCondition:
    """
    Purpose: Describes a specific dangerous state or condition for a construct.
    A DangerCondition is a deterministic rule: if this condition is detected,
    emit a finding with the specified severity and confidence.

    Inputs:
    - condition_id: Unique identifier within construct (e.g., "DC-001")
    - state_or_condition: The specific state or condition name
    - severity: The severity to emit when this condition is detected
    - confidence: The confidence level when this condition is detected
    - description: Human-readable explanation of the danger
    - detection_method: How this condition is detected (AST pattern, dataflow, etc.)
    - source_reference: Citation for why this is dangerous
    - cve_references: Relevant CVE IDs if applicable (sorted tuple)
    - cwe_references: Relevant CWE IDs if applicable (sorted tuple)

    Constraints:
    - condition_id must be unique within a construct's danger_conditions
    - source_reference is mandatory (Knowledge Integrity Law)
    - No inference; condition is detected by deterministic rule only

    Determinism guarantee: identical construct state → identical DangerCondition match
    """
    condition_id: str
    state_or_condition: str
    severity: str          # Severity value
    confidence: str        # Confidence value
    description: str
    detection_method: str  # "AST_PATTERN" | "DATAFLOW" | "BOUNDED_HEURISTIC"
    source_reference: str  # Mandatory citation
    cve_references: tuple[str, ...]  # sorted
    cwe_references: tuple[str, ...]  # sorted

    def __post_init__(self) -> None:
        # Validate severity
        valid_severities = {s.value for s in Severity}
        if self.severity not in valid_severities:
            raise SeverityValidationError(
                f"Invalid severity '{self.severity}'. Must be one of: {sorted(valid_severities)}"
            )
        # Validate confidence
        valid_confidences = {c.value for c in Confidence}
        if self.confidence not in valid_confidences:
            raise ConfidenceValidationError(
                f"Invalid confidence '{self.confidence}'. Must be one of: {sorted(valid_confidences)}"
            )
        # Validate detection method
        valid_methods = {"AST_PATTERN", "DATAFLOW", "BOUNDED_HEURISTIC", "STRUCTURAL"}
        if self.detection_method not in valid_methods:
            raise ConstructDomainError(
                f"Invalid detection_method '{self.detection_method}'. Must be: {sorted(valid_methods)}"
            )
        # CVE format: CVE-YYYY-NNNNN
        for cve in self.cve_references:
            if not re.match(r'^CVE-\d{4}-\d{4,}$', cve):
                raise ConstructDomainError(f"Invalid CVE format: '{cve}'. Expected: CVE-YYYY-NNNNN")
        # CWE format: CWE-NNN
        for cwe in self.cwe_references:
            if not re.match(r'^CWE-\d+$', cwe):
                raise ConstructDomainError(f"Invalid CWE format: '{cwe}'. Expected: CWE-NNN")


@dataclass(frozen=True)
class TierPermission:
    """
    Purpose: Defines what is permitted for a construct at a specific tier.

    Inputs:
    - tier: The tier this permission applies to
    - level: The permission level
    - enforcement_note: What the kernel does when this construct is found
    - escalation_note: When/how this finding escalates to higher severity

    Constraints:
    - One TierPermission per tier per construct
    - enforcement_note must be non-empty
    """
    tier: str               # Tier value
    level: str              # TierPermissionLevel value
    enforcement_note: str
    escalation_note: str

    def __post_init__(self) -> None:
        valid_tiers = {t.value for t in Tier}
        if self.tier not in valid_tiers:
            raise TierValidationError(f"Invalid tier '{self.tier}'")
        valid_levels = {l.value for l in TierPermissionLevel}
        if self.level not in valid_levels:
            raise ConstructDomainError(f"Invalid permission level '{self.level}'")


@dataclass(frozen=True)
class RiskMapping:
    """
    Purpose: Maps a construct to an industrial risk type with a weight.
    Weight represents how strongly this construct contributes to the risk.

    Inputs:
    - risk_type: The industrial risk type
    - weight: Fixed-point weight (no floats)
    - rationale: Why this construct maps to this risk type
    - source_reference: Citation supporting this mapping

    Constraints:
    - source_reference is mandatory (Knowledge Integrity Law)
    - weight must be > 0 to be meaningful

    Determinism: weight is integer fixed-point; no float accumulation errors
    """
    risk_type: str          # RiskType value
    weight: FixedWeight
    rationale: str
    source_reference: str

    def __post_init__(self) -> None:
        valid_risk_types = {r.value for r in RiskType}
        if self.risk_type not in valid_risk_types:
            raise ConstructDomainError(f"Invalid risk_type '{self.risk_type}'")
        if not self.source_reference.strip():
            raise ConstructDomainError("RiskMapping.source_reference cannot be empty")


@dataclass(frozen=True)
class KnowledgeCitation:
    """
    Purpose: A fully-cited reference satisfying the Knowledge Integrity Law.
    Every rule, danger condition, and risk mapping must have a citation.

    Inputs:
    - citation_type: "STANDARD" | "CVE" | "ACADEMIC" | "REGULATORY" | "ENGINEERING-JUDGMENT"
    - identifier: The standard number, CVE-ID, DOI, etc.
    - title: Human-readable title of the source
    - publication_date: ISO 8601 date (YYYY-MM-DD)
    - validation_status: "verified" | "pending_review" | "disputed"
    - reviewer_id: ID of the engineer who verified this citation
    - url: Optional URL for reference (not used by kernel; for human review)

    Constraints:
    - publication_date must be YYYY-MM-DD format
    - validation_status must be one of the allowed values
    - reviewer_id must be non-empty
    - ENGINEERING-JUDGMENT citations require explicit rationale in title

    Security consideration: citations are informational; they do not affect
    the deterministic analysis path
    """
    citation_type: str       # "STANDARD" | "CVE" | "ACADEMIC" | "REGULATORY" | "ENGINEERING-JUDGMENT"
    identifier: str          # e.g. "IEC-61508-3", "CVE-2023-1234", "DOI:10.1145/xxx"
    title: str
    publication_date: str    # ISO 8601 YYYY-MM-DD
    validation_status: str   # "verified" | "pending_review" | "disputed"
    reviewer_id: str
    url: str                 # Empty string if not available (never None — CEF requires explicit null)

    ALLOWED_TYPES = frozenset({"STANDARD", "CVE", "ACADEMIC", "REGULATORY", "ENGINEERING-JUDGMENT"})
    ALLOWED_STATUSES = frozenset({"verified", "pending_review", "disputed"})

    def __post_init__(self) -> None:
        if self.citation_type not in self.ALLOWED_TYPES:
            raise ConstructDomainError(f"Invalid citation_type '{self.citation_type}'")
        if self.validation_status not in self.ALLOWED_STATUSES:
            raise ConstructDomainError(f"Invalid validation_status '{self.validation_status}'")
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', self.publication_date):
            raise ConstructDomainError(
                f"publication_date must be YYYY-MM-DD, got '{self.publication_date}'"
            )
        if not self.reviewer_id.strip():
            raise ConstructDomainError("KnowledgeCitation.reviewer_id cannot be empty")


# ─── Construct Definition — the core domain type ──────────────────────────────

# Canonical construct ID pattern: CONST-{DOMAIN}-{NNN}
_CONSTRUCT_ID_PATTERN = re.compile(r'^CONST-[A-Z]{2,8}-\d{3}$')


@dataclass(frozen=True)
class ConstructDefinition:
    """
    Purpose: The complete, immutable definition of a code construct.
    This is the primary entity in the Knowledge Catalog. Once emitted
    and signed, it cannot be modified — a new version must be issued.

    A ConstructDefinition answers:
    - What AST node types represent this construct?
    - What states can this construct be in?
    - Which states are dangerous, and why?
    - What conditions make the construct acceptable?
    - What is permitted at each tier?
    - What are the analysis bounds (where does analysis stop)?
    - What industrial risks does this construct map to?
    - What standards reference this construct?

    Inputs:
    - construct_id: Canonical ID (CONST-{DOMAIN}-{NNN})
    - construct_name: Human-readable name (e.g., "async", "eval")
    - catalog_version: The catalog version this definition belongs to (YYYY.MM.DD)
    - language: Target language (e.g., "python", "c", "cpp")
    - description: Precise technical description
    - ast_node_types: Sorted tuple of AST node type strings
    - states: Sorted tuple of possible state identifiers
    - danger_conditions: Tuple of DangerCondition, ordered by condition_id
    - acceptance_conditions: Sorted tuple of conditions that make construct safe
    - tier_permissions: Tuple of TierPermission, one per tier, sorted by tier
    - analysis_bounds: AnalysisBounds for GREEN tier (strictest; others have wider bounds)
    - analysis_constraints: Sorted tuple of explicit analysis limitations
    - risk_mappings: Tuple of RiskMapping, sorted by risk_type
    - linked_policies: Sorted tuple of policy IDs
    - linked_standards: Sorted tuple of standard identifiers
    - knowledge_citations: Tuple of KnowledgeCitation, sorted by identifier
    - human_review_triggers: Sorted tuple of conditions that mandate human review
    - boundary_conditions: Sorted tuple of conditions that cause ANALYSIS_BOUNDARY_REACHED

    Constraints:
    - construct_id must match CONST-{DOMAIN}-{NNN} pattern
    - All tuples are sorted (deterministic ordering)
    - tier_permissions must have exactly one entry per tier
    - Every danger_condition must have a source_reference
    - Every risk_mapping must have a source_reference
    - No float in any field

    Determinism guarantee:
    - Frozen dataclass: immutable after construction
    - All collections are tuples: stable ordering
    - catalog_hash() is deterministic: same definition → same hash

    Failure modes:
    - ConstructIdFormatError: invalid construct_id format
    - TierValidationError: missing or duplicate tier in tier_permissions
    - ConstructDomainError: any other validation failure
    """
    construct_id: str
    construct_name: str
    catalog_version: str       # YYYY.MM.DD
    language: str
    description: str
    ast_node_types: tuple[str, ...]      # sorted
    states: tuple[str, ...]              # sorted
    danger_conditions: tuple[DangerCondition, ...]   # sorted by condition_id
    acceptance_conditions: tuple[str, ...]           # sorted
    tier_permissions: tuple[TierPermission, ...]     # sorted by tier, one per tier
    analysis_bounds: AnalysisBounds
    analysis_constraints: tuple[str, ...]            # sorted
    risk_mappings: tuple[RiskMapping, ...]           # sorted by risk_type
    linked_policies: tuple[str, ...]                 # sorted
    linked_standards: tuple[str, ...]                # sorted
    knowledge_citations: tuple[KnowledgeCitation, ...]  # sorted by identifier
    human_review_triggers: tuple[str, ...]           # sorted
    boundary_conditions: tuple[str, ...]             # sorted

    def __post_init__(self) -> None:
        # Validate construct_id format
        if not _CONSTRUCT_ID_PATTERN.match(self.construct_id):
            raise ConstructIdFormatError(
                f"Invalid construct_id '{self.construct_id}'. "
                f"Required format: CONST-{{DOMAIN}}-{{NNN}} "
                f"(DOMAIN: 2-8 uppercase letters, NNN: 3 digits)"
            )
        # Validate catalog_version format (YYYY.MM.DD)
        if not re.match(r'^\d{4}\.\d{2}\.\d{2}$', self.catalog_version):
            raise ConstructDomainError(
                f"catalog_version must be YYYY.MM.DD, got '{self.catalog_version}'"
            )
        # Validate tier permissions: exactly one per tier
        tier_values = sorted(t.value for t in Tier)
        permission_tiers = sorted(p.tier for p in self.tier_permissions)
        if permission_tiers != tier_values:
            raise TierValidationError(
                f"tier_permissions must have exactly one entry per tier. "
                f"Expected: {tier_values}, got: {permission_tiers}"
            )
        # Validate danger conditions have unique IDs
        condition_ids = [dc.condition_id for dc in self.danger_conditions]
        if len(condition_ids) != len(set(condition_ids)):
            raise ConstructDomainError(
                f"Duplicate condition_id in danger_conditions: {condition_ids}"
            )
        # Validate at least one citation
        if not self.knowledge_citations:
            raise ConstructDomainError(
                f"ConstructDefinition '{self.construct_id}' must have at least one "
                f"knowledge_citation (Knowledge Integrity Law)"
            )

    def get_tier_permission(self, tier: Tier) -> TierPermission:
        """
        Purpose: Retrieve the permission for a specific tier.
        Inputs: tier — the tier to query
        Outputs: TierPermission for the given tier
        Constraints: Always succeeds (tier_permissions validated to cover all tiers)
        Determinism: deterministic lookup; same tier → same permission
        """
        for perm in self.tier_permissions:
            if perm.tier == tier.value:
                return perm
        # Should never happen due to __post_init__ validation
        raise TierValidationError(f"No permission found for tier {tier.value} in {self.construct_id}")

    def get_danger_condition(self, state: str) -> Optional[DangerCondition]:
        """
        Purpose: Retrieve the danger condition matching a detected state.
        Inputs: state — the detected state string
        Outputs: DangerCondition if state is dangerous, None otherwise
        Constraints: Deterministic lookup; None = state is not dangerous by itself
        Complexity: O(n) where n = number of danger conditions
        """
        for dc in sorted(self.danger_conditions, key=lambda d: d.condition_id):
            if dc.state_or_condition == state:
                return dc
        return None

    def catalog_hash(self) -> str:
        """
        Purpose: Compute a deterministic hash of this construct definition.
        This hash changes when ANY field of the construct changes.
        Used for catalog integrity verification.

        Outputs: "sha256:{hex}" string
        Constraints: Deterministic; byte-identical across platforms
        Determinism: all fields reduced to sorted canonical form before hashing
        """
        import hashlib
        import json

        canonical = {
            "construct_id": self.construct_id,
            "catalog_version": self.catalog_version,
            "language": self.language,
            "ast_node_types": sorted(self.ast_node_types),
            "states": sorted(self.states),
            "danger_conditions": sorted([
                {"id": dc.condition_id, "state": dc.state_or_condition,
                 "severity": dc.severity, "confidence": dc.confidence}
                for dc in self.danger_conditions
            ], key=lambda d: d["id"]),
            "tier_permissions": sorted([
                {"tier": tp.tier, "level": tp.level}
                for tp in self.tier_permissions
            ], key=lambda p: p["tier"]),
        }
        canonical_bytes = json.dumps(
            canonical,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False,
        ).encode('utf-8')
        return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
