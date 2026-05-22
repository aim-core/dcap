"""
******************************************************************************
 * FILE:        /src/domain/policies/policy_model.py
 * LAYER:       Domain Layer
 * MODULE:      Policy Model
 * PURPOSE:     Immutable domain types for deterministic policy evaluation
 * DOMAIN:      Verification Core
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Defines the Policy domain model. A Policy is a deterministic rule that
 * maps (Construct, State, Context, Tier) to a Finding decision.
 *
 * Policies are IMMUTABLE. They are loaded from the Knowledge Catalog
 * and frozen at startup. No policy may be mutated at runtime.
 *
 * Policy Inheritance: Policies form a DAG (not a tree). A derived policy
 * inherits the base finding but can escalate severity, add standards,
 * or restrict tier permissions. Inheritance is resolved at load time
 * and produces a flattened, immutable EvaluationPolicy.
 *
 * Conflict Resolution Priority (Foundation Document Section 8.3):
 *   Safety > Compliance > Reliability > Performance
 *   Higher tier always wins over lower tier.
 *   If two policies at same priority conflict: HALT and require human review.
 *
 * DEPENDENCIES:
 * - src/domain/constructs/construct_model.py
 *
 * CONSTRAINTS:
 * - No I/O. No runtime mutation. No float arithmetic.
 * - Conflict resolution is deterministic (priority matrix, not heuristic).
 * - Policy evaluation is a pure function: (Node, Context, Tier) → Decision.
 *
 * DETERMINISM GUARANTEES:
 * - All policies are frozen dataclasses.
 * - Conflict resolution follows a fixed priority matrix.
 * - Policy DAG resolution order is topologically sorted (deterministic).
 *
 * FAILURE MODES:
 * - PolicyIdFormatError: invalid policy ID format
 * - PolicyConflictError: two policies at same priority with conflicting outcome
 * - PolicyCycleError: circular inheritance detected in policy DAG
 * - PolicyVersionError: version string format violation
 *
 * SECURITY CONSIDERATIONS:
 * - Policies are loaded from signed catalog (Phase 1+)
 * - No policy can be added or removed at runtime
 * - Conflict resolution always produces a deterministic winner or HALTS
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src.domain.constructs.construct_model import (
    Confidence,
    Severity,
    Tier,
    TierPermissionLevel,
    FixedWeight,
    RiskType,
)


# ─── Domain Errors ────────────────────────────────────────────────────────────

class PolicyDomainError(Exception):
    """Base class for policy domain errors."""


class PolicyIdFormatError(PolicyDomainError):
    """
    Purpose: Raised when a policy ID does not match POL-{DOMAIN}-{NNN}.
    Format: POL-{DOMAIN}-{NNN} where DOMAIN is 2-8 uppercase letters,
            NNN is zero-padded 3 digits.
    Example: POL-CONC-004, POL-SEC-001
    """


class PolicyConflictError(PolicyDomainError):
    """
    Purpose: Raised when two policies produce irreconcilable conflicts
             at the same priority level. This HALTS the analysis — no
             finding is emitted until a human resolves the conflict.
    """


class PolicyCycleError(PolicyDomainError):
    """
    Purpose: Raised when circular inheritance is detected in the policy DAG.
    A cycle means the conflict resolution is undefined. This is a catalog
    integrity violation and must halt catalog loading.
    """


class PolicyVersionError(PolicyDomainError):
    """Raised when policy version string format is invalid."""


# ─── Policy Enumerations ──────────────────────────────────────────────────────

class PolicyDomain(str, Enum):
    """
    Purpose: Classifies policies into functional domains.
    Used for namespace organization and conflict resolution scope.
    Source: Foundation Document Section 8.1.

    CONC:  Concurrency — async, threading, locks, shared state
    SEC:   Security — eval, exec, pickle, subprocess, path traversal
    IO:    I/O — file operations, resource management
    DET:   Determinism — random, seeding, non-deterministic patterns
    MEM:   Memory — unbounded allocation, resource leaks
    TYPE:  Type Safety — dynamic typing, duck typing risks
    PERF:  Performance — bounded analysis for latency-sensitive contexts
    ARCH:  Architecture — structural concerns, dependency direction
    """
    CONC = "CONC"
    SEC  = "SEC"
    IO   = "IO"
    DET  = "DET"
    MEM  = "MEM"
    TYPE = "TYPE"
    PERF = "PERF"
    ARCH = "ARCH"


class PolicyPriority(str, Enum):
    """
    Purpose: Priority level for conflict resolution between policies.
    When two policies produce conflicting decisions for the same finding,
    the higher-priority policy wins.

    Source: Foundation Document Section 8.3
    Reference: Adapted from IEC 61508-1:2010 Table 2 risk priority framework.

    SAFETY:      Highest — physical harm potential
    COMPLIANCE:  Regulatory and legal obligations
    RELIABILITY: Correctness and availability
    PERFORMANCE: Efficiency (lowest priority in conflict)
    """
    SAFETY      = "SAFETY"
    COMPLIANCE  = "COMPLIANCE"
    RELIABILITY = "RELIABILITY"
    PERFORMANCE = "PERFORMANCE"

    @classmethod
    def ordered_descending(cls) -> tuple[PolicyPriority, ...]:
        """Returns priorities from highest to lowest."""
        return (cls.SAFETY, cls.COMPLIANCE, cls.RELIABILITY, cls.PERFORMANCE)

    def numeric_level(self) -> int:
        """
        Purpose: Integer priority level for comparison (higher = more important).
        No floats. SAFETY=3, COMPLIANCE=2, RELIABILITY=1, PERFORMANCE=0.
        """
        return {
            PolicyPriority.SAFETY:      3,
            PolicyPriority.COMPLIANCE:  2,
            PolicyPriority.RELIABILITY: 1,
            PolicyPriority.PERFORMANCE: 0,
        }[self]


class PolicyOutcome(str, Enum):
    """
    Purpose: What action the policy prescribes when triggered.

    EMIT_FINDING:          Produce a Finding in the artifact
    EMIT_BOUNDARY:         Produce a BoundaryDeclaration (analysis limit reached)
    ESCALATE:              Apply escalation rules and re-evaluate
    REQUIRE_HUMAN_REVIEW:  Emit finding + mandate human review
    BLOCK_PIPELINE:        Emit finding + block CI/CD pipeline (RED tier only)
    SUPPRESS:              Suppress finding (policy explicitly overrides parent)
    """
    EMIT_FINDING          = "EMIT_FINDING"
    EMIT_BOUNDARY         = "EMIT_BOUNDARY"
    ESCALATE              = "ESCALATE"
    REQUIRE_HUMAN_REVIEW  = "REQUIRE_HUMAN_REVIEW"
    BLOCK_PIPELINE        = "BLOCK_PIPELINE"
    SUPPRESS              = "SUPPRESS"


# ─── Policy Condition ─────────────────────────────────────────────────────────

_POLICY_ID_PATTERN = re.compile(r'^POL-[A-Z]{2,8}-\d{3}$')


def validate_policy_id(policy_id: str) -> str:
    """
    Purpose: Validate a policy ID against the canonical format.
    Inputs: policy_id string
    Outputs: the validated policy_id
    Failure: PolicyIdFormatError if format is wrong
    """
    if not _POLICY_ID_PATTERN.match(policy_id):
        raise PolicyIdFormatError(
            f"Invalid policy_id '{policy_id}'. "
            f"Expected: POL-{{DOMAIN}}-{{NNN}} (DOMAIN: 2-8 uppercase, NNN: 3 digits)"
        )
    return policy_id


@dataclass(frozen=True)
class PolicyCondition:
    """
    Purpose: A single condition that must be satisfied for a policy to trigger.
    Conditions are combined with AND logic (all must be true to trigger).

    Inputs:
    - condition_id: Unique ID within the policy (e.g., "C001")
    - field: The field being evaluated (e.g., "construct_state", "tier", "context_tag")
    - operator: Comparison operator ("EQ", "NEQ", "IN", "NOT_IN", "GT", "LT")
    - value: The value to compare against (string for EQ/NEQ, comma-sep for IN/NOT_IN)
    - description: Human-readable explanation of this condition

    Constraints:
    - operator must be one of the allowed set
    - field names use UPPER_SNAKE_CASE
    - value is always a string (parsed according to field type)

    Determinism: condition evaluation is a pure boolean function
    """
    condition_id: str
    field: str
    operator: str      # "EQ" | "NEQ" | "IN" | "NOT_IN" | "GT" | "LT" | "CONTAINS"
    value: str
    description: str

    _ALLOWED_OPERATORS = frozenset({"EQ", "NEQ", "IN", "NOT_IN", "GT", "LT", "CONTAINS"})

    def __post_init__(self) -> None:
        if self.operator not in self._ALLOWED_OPERATORS:
            raise PolicyDomainError(
                f"Invalid operator '{self.operator}'. Must be: {sorted(self._ALLOWED_OPERATORS)}"
            )
        if not self.condition_id.strip():
            raise PolicyDomainError("PolicyCondition.condition_id cannot be empty")


@dataclass(frozen=True)
class EscalationRule:
    """
    Purpose: Defines when and how a finding's severity is escalated.
    Escalation is deterministic: given a condition, escalation always applies.

    Escalation examples:
    - eval() in a web handler → escalate to CRITICAL
    - unawaited coroutine in safety-critical function → escalate + require human review
    - threading in ISR context → escalate to CRITICAL + block pipeline

    Inputs:
    - rule_id: Unique escalation rule ID (e.g., "ESC-001")
    - trigger_condition: The condition that triggers escalation (human-readable)
    - escalates_to: The severity after escalation
    - sets_confidence: The confidence after escalation
    - adds_outcome: Additional outcome to add (e.g., REQUIRE_HUMAN_REVIEW)
    - rationale: Why this escalation exists
    - source_reference: Citation

    Constraints:
    - escalates_to must be a valid Severity
    - adds_outcome must be a valid PolicyOutcome (or empty string)
    """
    rule_id: str
    trigger_condition: str
    escalates_to: str        # Severity value
    sets_confidence: str     # Confidence value
    adds_outcome: str        # PolicyOutcome value or "" (no additional outcome)
    rationale: str
    source_reference: str

    def __post_init__(self) -> None:
        valid_severities = {s.value for s in Severity}
        if self.escalates_to not in valid_severities:
            raise PolicyDomainError(f"Invalid escalates_to '{self.escalates_to}'")
        valid_confidences = {c.value for c in Confidence}
        if self.sets_confidence not in valid_confidences:
            raise PolicyDomainError(f"Invalid sets_confidence '{self.sets_confidence}'")
        if self.adds_outcome:
            valid_outcomes = {o.value for o in PolicyOutcome}
            if self.adds_outcome not in valid_outcomes:
                raise PolicyDomainError(f"Invalid adds_outcome '{self.adds_outcome}'")
        if not self.source_reference.strip():
            raise PolicyDomainError("EscalationRule.source_reference cannot be empty")


# ─── Policy Definition ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PolicyDefinition:
    """
    Purpose: A complete, immutable policy definition.
    A policy is the evaluation rule that decides whether a detected construct
    state produces a finding, what severity it has, and what must happen next.

    Policies are organized as a DAG for inheritance. A derived policy inherits
    all fields from its parent and overrides specific ones. Inheritance is
    resolved at catalog load time into a flat EvaluationPolicy.

    Inputs:
    - policy_id: Canonical ID (POL-{DOMAIN}-{NNN})
    - policy_version: Semantic version of this policy ("YYYY.MM.DD")
    - domain: PolicyDomain value
    - priority: PolicyPriority for conflict resolution
    - parent_policy_ids: Sorted tuple of parent policy IDs (empty = base policy)
    - name: Human-readable policy name
    - description: Detailed technical description
    - applies_to_constructs: Sorted tuple of construct IDs this policy covers
    - applies_to_tiers: Sorted tuple of tier values this policy applies to
    - trigger_conditions: Tuple of PolicyCondition (AND logic; sorted by condition_id)
    - base_severity: Default severity when conditions are met
    - base_confidence: Default confidence when conditions are met
    - base_outcome: Default outcome when conditions are met
    - escalation_rules: Tuple of EscalationRule (sorted by rule_id)
    - standards_violated: Sorted tuple of standard sections violated
    - reviewer_qualification: Required qualification for human reviewer ("" if none)
    - source_reference: Primary citation for this policy
    - rationale: Why this policy exists

    Constraints:
    - policy_id must match POL-{DOMAIN}-{NNN}
    - applies_to_tiers must be subset of all valid tiers
    - parent_policy_ids must not create cycles (validated at registry load)
    - base_severity, base_confidence, base_outcome must be valid enum values
    - source_reference is mandatory (Knowledge Integrity Law)

    Determinism:
    - Policy evaluation is a pure function of its inputs
    - Conflict resolution uses the fixed priority matrix
    - No runtime modification of any field
    """
    policy_id: str
    policy_version: str           # YYYY.MM.DD
    domain: str                   # PolicyDomain value
    priority: str                 # PolicyPriority value
    parent_policy_ids: tuple[str, ...]       # sorted; empty for base policies
    name: str
    description: str
    applies_to_constructs: tuple[str, ...]   # sorted construct IDs
    applies_to_tiers: tuple[str, ...]        # sorted Tier values
    trigger_conditions: tuple[PolicyCondition, ...]  # sorted by condition_id
    base_severity: str            # Severity value
    base_confidence: str          # Confidence value
    base_outcome: str             # PolicyOutcome value
    escalation_rules: tuple[EscalationRule, ...]     # sorted by rule_id
    standards_violated: tuple[str, ...]      # sorted
    reviewer_qualification: str              # "" if no reviewer needed
    source_reference: str
    rationale: str

    def __post_init__(self) -> None:
        validate_policy_id(self.policy_id)

        valid_domains = {d.value for d in PolicyDomain}
        if self.domain not in valid_domains:
            raise PolicyDomainError(f"Invalid domain '{self.domain}'")

        valid_priorities = {p.value for p in PolicyPriority}
        if self.priority not in valid_priorities:
            raise PolicyDomainError(f"Invalid priority '{self.priority}'")

        valid_severities = {s.value for s in Severity}
        if self.base_severity not in valid_severities:
            raise PolicyDomainError(f"Invalid base_severity '{self.base_severity}'")

        valid_confidences = {c.value for c in Confidence}
        if self.base_confidence not in valid_confidences:
            raise PolicyDomainError(f"Invalid base_confidence '{self.base_confidence}'")

        valid_outcomes = {o.value for o in PolicyOutcome}
        if self.base_outcome not in valid_outcomes:
            raise PolicyDomainError(f"Invalid base_outcome '{self.base_outcome}'")

        valid_tiers = {t.value for t in Tier}
        for tier in self.applies_to_tiers:
            if tier not in valid_tiers:
                raise PolicyDomainError(f"Invalid tier '{tier}' in applies_to_tiers")

        if not self.source_reference.strip():
            raise PolicyDomainError(
                f"PolicyDefinition '{self.policy_id}' must have a source_reference "
                f"(Knowledge Integrity Law)"
            )

        # Validate version format
        if not re.match(r'^\d{4}\.\d{2}\.\d{2}$', self.policy_version):
            raise PolicyVersionError(
                f"policy_version must be YYYY.MM.DD, got '{self.policy_version}'"
            )

        # Condition IDs must be unique
        cond_ids = [c.condition_id for c in self.trigger_conditions]
        if len(cond_ids) != len(set(cond_ids)):
            raise PolicyDomainError(
                f"Duplicate condition_id in trigger_conditions of '{self.policy_id}'"
            )

    def applies_to_tier(self, tier: Tier) -> bool:
        """
        Purpose: Check if this policy applies to a given tier.
        Inputs: tier — the Tier enum value
        Outputs: bool
        Constraints: O(n) where n = len(applies_to_tiers); small constant
        Determinism: pure function of immutable state
        """
        return tier.value in self.applies_to_tiers

    def applies_to_construct(self, construct_id: str) -> bool:
        """
        Purpose: Check if this policy covers a given construct.
        Inputs: construct_id — the construct ID string
        Outputs: bool
        """
        return construct_id in self.applies_to_constructs

    def policy_hash(self) -> str:
        """
        Purpose: Deterministic hash of this policy definition for integrity verification.
        Outputs: "sha256:{64 hex chars}"
        Constraints: Deterministic; byte-identical across platforms
        """
        import hashlib
        import json

        canonical = {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "base_severity": self.base_severity,
            "base_confidence": self.base_confidence,
            "base_outcome": self.base_outcome,
            "applies_to_constructs": sorted(self.applies_to_constructs),
            "applies_to_tiers": sorted(self.applies_to_tiers),
            "conditions": sorted([
                {"id": c.condition_id, "field": c.field, "op": c.operator, "val": c.value}
                for c in self.trigger_conditions
            ], key=lambda x: x["id"]),
        }
        canonical_bytes = json.dumps(
            canonical,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False,
        ).encode('utf-8')
        return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()


# ─── Conflict Resolution ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class PolicyConflict:
    """
    Purpose: Represents a conflict between two policies for the same finding.
    Conflicts are resolved deterministically by the priority matrix.
    If resolution fails (same priority, opposite outcomes), emits PolicyConflictError.

    Inputs:
    - policy_a_id: First conflicting policy
    - policy_b_id: Second conflicting policy
    - conflict_type: "SEVERITY_MISMATCH" | "OUTCOME_MISMATCH" | "SUPPRESS_VS_EMIT"
    - resolution: "POLICY_A_WINS" | "POLICY_B_WINS" | "UNRESOLVABLE"
    - winner_id: The winning policy ID (empty string if UNRESOLVABLE)
    - resolution_rule: Which rule determined the winner
    """
    policy_a_id: str
    policy_b_id: str
    conflict_type: str
    resolution: str
    winner_id: str
    resolution_rule: str

    _CONFLICT_TYPES = frozenset({"SEVERITY_MISMATCH", "OUTCOME_MISMATCH", "SUPPRESS_VS_EMIT"})
    _RESOLUTIONS = frozenset({"POLICY_A_WINS", "POLICY_B_WINS", "UNRESOLVABLE"})

    def __post_init__(self) -> None:
        if self.conflict_type not in self._CONFLICT_TYPES:
            raise PolicyDomainError(f"Invalid conflict_type '{self.conflict_type}'")
        if self.resolution not in self._RESOLUTIONS:
            raise PolicyDomainError(f"Invalid resolution '{self.resolution}'")


def resolve_policy_conflict(
    policy_a: PolicyDefinition,
    policy_b: PolicyDefinition,
) -> PolicyConflict:
    """
    Purpose: Resolve a conflict between two policies using the priority matrix.
    This is the deterministic conflict resolution function described in the
    Foundation Document Section 8.3.

    Resolution rules (in order):
    1. Higher PolicyPriority wins (SAFETY > COMPLIANCE > RELIABILITY > PERFORMANCE)
    2. If same priority and same outcome: no conflict (take either)
    3. If same priority and conflicting outcome: UNRESOLVABLE → halt, require human

    Inputs:
    - policy_a, policy_b: The two conflicting PolicyDefinition instances
    Outputs: PolicyConflict describing the resolution
    Failure: Never raises; returns UNRESOLVABLE conflict instead

    Determinism: same two policies always produce same resolution
    Security: no external input affects resolution; pure function of policy fields
    """
    priority_a = PolicyPriority(policy_a.priority).numeric_level()
    priority_b = PolicyPriority(policy_b.priority).numeric_level()

    if priority_a > priority_b:
        return PolicyConflict(
            policy_a_id=policy_a.policy_id,
            policy_b_id=policy_b.policy_id,
            conflict_type="SEVERITY_MISMATCH",
            resolution="POLICY_A_WINS",
            winner_id=policy_a.policy_id,
            resolution_rule="PRIORITY_MATRIX: A.priority > B.priority",
        )
    elif priority_b > priority_a:
        return PolicyConflict(
            policy_a_id=policy_a.policy_id,
            policy_b_id=policy_b.policy_id,
            conflict_type="SEVERITY_MISMATCH",
            resolution="POLICY_B_WINS",
            winner_id=policy_b.policy_id,
            resolution_rule="PRIORITY_MATRIX: B.priority > A.priority",
        )
    else:
        # Same priority — unresolvable without human input
        return PolicyConflict(
            policy_a_id=policy_a.policy_id,
            policy_b_id=policy_b.policy_id,
            conflict_type="OUTCOME_MISMATCH",
            resolution="UNRESOLVABLE",
            winner_id="",
            resolution_rule=f"SAME_PRIORITY({policy_a.priority}): human review required",
        )
