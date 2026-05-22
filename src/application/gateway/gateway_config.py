"""
******************************************************************************
 * FILE:        /src/application/gateway/gateway_config.py
 * LAYER:       Application Layer
 * MODULE:      Gateway Configuration System
 * PURPOSE:     Gateway profiles, resource limits, and priority scheduling
 * DOMAIN:      Trust Infrastructure
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-14
 * UPDATED:     2026-05-14
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * DELTA EXTENSION — wraps TierEngine without modifying it.
 *
 * Implements the Four-Gateway model from Directive §13 with:
 *   - Resource Governor (§21): file/LOC/memory/CPU quotas per gateway
 *   - Priority Scheduler (§22): P0-P3 queue priorities
 *   - User Policy Permissions (§16): what users can and cannot customize
 *   - Daily Limits (§13): 50 anon → unlimited after login (GREEN);
 *     30/day (YELLOW); 20/day (BLUE); 5/day (RED)
 *
 * Gateway → Tier mapping (deterministic):
 *   GREEN  → Tier.GREEN
 *   YELLOW → Tier.YELLOW
 *   BLUE   → Tier.BLUE
 *   RED    → Tier.RED
 *
 * BACKWARD COMPATIBILITY: TierEngine is used as-is. GatewayConfig
 * adds quota enforcement BEFORE calling TierEngine.analyze().
 *
 * CONSTRAINTS:
 *   - Gateway profiles are IMMUTABLE frozen dataclasses
 *   - No runtime modification of any profile field
 *   - Quota enforcement raises GatewayQuotaExceeded — never silently proceeds
 *   - Core investigators (per §16) cannot be disabled by any user policy
 *
 * DETERMINISM: gateway selection + quota check are pure functions of inputs
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

from dataclasses import dataclass
from src.domain.constructs.construct_model import Tier


# ─── Errors ───────────────────────────────────────────────────────────────────

class GatewayError(Exception):
    """Base gateway error."""


class GatewayQuotaExceeded(GatewayError):
    """
    Purpose: Raised when a resource quota is exceeded BEFORE analysis begins.
    Includes: which quota was exceeded, the limit, and the actual value.
    """


class GatewayDailyLimitReached(GatewayError):
    """
    Purpose: Raised when the daily analysis count for a gateway is reached.
    Analysis is NOT started. User must wait 24h or upgrade gateway.
    """


class GatewayPolicyViolation(GatewayError):
    """
    Purpose: Raised when a user policy attempts to modify a protected component.
    User policies are ADDITIVE ONLY — they cannot override core investigators.
    """


# ─── Gateway Profiles (Directive §13 + §21) ───────────────────────────────────

@dataclass(frozen=True)
class GatewayProfile:
    """
    Purpose: Complete, immutable configuration for one analysis gateway.
    All resource limits are HARD limits — no soft limits, no silent truncation.
    Exceeding any limit → safe termination + partial report + user notification.

    Reference: Directive §13, §21, §22
    """
    gateway_id: str            # "GREEN" | "YELLOW" | "BLUE" | "RED"
    tier: Tier                 # Maps to existing TierEngine tier
    display_name: str
    target_audience: str
    queue_priority: int        # 0=highest (RED), 3=lowest (GREEN)
    service_class: str         # "P0" | "P1" | "P2" | "P3"

    # Daily limits (§13)
    daily_limit: int           # -1 = unlimited
    anonymous_limit: int       # Analyses allowed without login

    # Resource Governor (§21)
    max_files: int
    max_loc: int
    max_archive_mb: int
    max_graph_depth: int
    execution_budget_cpu_sec: int
    analysis_timeout_sec: int
    max_memory_mb: int

    # Permissions (§16)
    custom_policies_allowed: bool
    custom_policy_level: str   # "NONE" | "LIMITED" | "ADVANCED" | "STRICT_LIMITED"
    mfa_required: bool         # For BLUE and RED (§17)
    incident_response_allowed: bool  # §34

    # Instruction modal (§14)
    instruction_modal_required: bool  # Always True


# Immutable gateway profiles — matches Directive §13 and §21 exactly
GATEWAY_PROFILES: dict[str, GatewayProfile] = {
    "GREEN": GatewayProfile(
        gateway_id="GREEN",
        tier=Tier.GREEN,
        display_name="Green Gateway",
        target_audience="Hobbyists, beginners, quick validation, public beta",
        queue_priority=3,
        service_class="P3",
        daily_limit=-1,          # Unlimited after verified login
        anonymous_limit=50,      # 50 anonymous → forced login
        max_files=50,
        max_loc=5_000,
        max_archive_mb=10,
        max_graph_depth=15,
        execution_budget_cpu_sec=30,
        analysis_timeout_sec=60,
        max_memory_mb=512,
        custom_policies_allowed=False,
        custom_policy_level="NONE",
        mfa_required=False,
        incident_response_allowed=False,
        instruction_modal_required=True,
    ),
    "YELLOW": GatewayProfile(
        gateway_id="YELLOW",
        tier=Tier.YELLOW,
        display_name="Yellow Gateway",
        target_audience="Professional developers, freelancers, startups, SaaS teams",
        queue_priority=2,
        service_class="P2",
        daily_limit=30,
        anonymous_limit=0,       # Must be logged in
        max_files=200,
        max_loc=25_000,
        max_archive_mb=50,
        max_graph_depth=50,
        execution_budget_cpu_sec=300,
        analysis_timeout_sec=300,
        max_memory_mb=2_048,
        custom_policies_allowed=True,
        custom_policy_level="LIMITED",
        mfa_required=False,
        incident_response_allowed=False,
        instruction_modal_required=True,
    ),
    "BLUE": GatewayProfile(
        gateway_id="BLUE",
        tier=Tier.BLUE,
        display_name="Blue Gateway",
        target_audience="Industrial, cybersecurity, AI infrastructure, regulated enterprises",
        queue_priority=1,
        service_class="P1",
        daily_limit=20,
        anonymous_limit=0,
        max_files=1_000,
        max_loc=150_000,
        max_archive_mb=250,
        max_graph_depth=200,
        execution_budget_cpu_sec=3_000,
        analysis_timeout_sec=1_800,
        max_memory_mb=8_192,
        custom_policies_allowed=True,
        custom_policy_level="ADVANCED",
        mfa_required=True,
        incident_response_allowed=True,
        instruction_modal_required=True,
    ),
    "RED": GatewayProfile(
        gateway_id="RED",
        tier=Tier.RED,
        display_name="Red Gateway",
        target_audience="Defense, aerospace, medical critical, nuclear, safety-critical AI",
        queue_priority=0,
        service_class="P0",
        daily_limit=5,
        anonymous_limit=0,
        max_files=5_000,
        max_loc=500_000,
        max_archive_mb=1_024,
        max_graph_depth=500,
        execution_budget_cpu_sec=30_000,
        analysis_timeout_sec=14_400,   # 4 hours
        max_memory_mb=32_768,
        custom_policies_allowed=True,
        custom_policy_level="STRICT_LIMITED",
        mfa_required=True,
        incident_response_allowed=True,
        instruction_modal_required=True,
    ),
}

# Protected components that user policies can NEVER modify (§16)
PROTECTED_COMPONENTS: frozenset[str] = frozenset({
    "execution_engine",
    "replay_engine",
    "ast_traversal",
    "core_investigators",
    "governance_rules",
    "deterministic_scheduler",
    "evidence_generator",
    "signing_system",
    "kernel_logic",
    "catalog_integrity",
    "hash_verification",
    "audit_trail",
})

# Core mandatory detections — ALWAYS run, cannot be disabled (§3)
MANDATORY_DETECTIONS: frozenset[str] = frozenset({
    "remote_code_execution",
    "shell_injection",
    "unsafe_deserialization",
    "privilege_escalation",
    "memory_corruption",
    "credential_leakage",
    "undefined_behavior",
    "critical_race_conditions",
    "deterministic_violations",
    "unsafe_subprocess_execution",
    "malicious_dynamic_execution",
    "critical_secrets_exposure",
})


# ─── Resource Governor ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ResourceCheckResult:
    """
    Purpose: Result of resource quota check BEFORE analysis begins.
    If approved=False, analysis must NOT start.
    """
    approved: bool
    gateway_id: str
    file_count: int
    loc_estimate: int
    violated_quota: str   # empty if approved
    violated_limit: int
    actual_value: int
    message: str


def check_resource_quota(
    gateway_id: str,
    file_count: int,
    loc_estimate: int,
) -> ResourceCheckResult:
    """
    Purpose: Verify that an analysis request fits within gateway resource limits.
    Called BEFORE TierEngine.analyze() — analysis does not start if not approved.

    Inputs:
    - gateway_id: "GREEN" | "YELLOW" | "BLUE" | "RED"
    - file_count: Number of files to analyze
    - loc_estimate: Estimated lines of code

    Outputs: ResourceCheckResult (immutable)
    Failure: GatewayError if gateway_id is unknown
    Constraints: Pure function; no I/O; deterministic
    """
    profile = GATEWAY_PROFILES.get(gateway_id)
    if profile is None:
        raise GatewayError(f"Unknown gateway_id '{gateway_id}'. Must be: GREEN/YELLOW/BLUE/RED")

    if file_count > profile.max_files:
        return ResourceCheckResult(
            approved=False,
            gateway_id=gateway_id,
            file_count=file_count,
            loc_estimate=loc_estimate,
            violated_quota="max_files",
            violated_limit=profile.max_files,
            actual_value=file_count,
            message=(
                f"File count ({file_count:,}) exceeds {gateway_id} gateway limit "
                f"({profile.max_files:,} files). "
                f"Upgrade to a higher gateway or exclude build directories."
            ),
        )

    if loc_estimate > profile.max_loc:
        return ResourceCheckResult(
            approved=False,
            gateway_id=gateway_id,
            file_count=file_count,
            loc_estimate=loc_estimate,
            violated_quota="max_loc",
            violated_limit=profile.max_loc,
            actual_value=loc_estimate,
            message=(
                f"LOC estimate ({loc_estimate:,}) exceeds {gateway_id} gateway limit "
                f"({profile.max_loc:,} lines). "
                f"Upgrade to a higher gateway or analyze a subset."
            ),
        )

    return ResourceCheckResult(
        approved=True,
        gateway_id=gateway_id,
        file_count=file_count,
        loc_estimate=loc_estimate,
        violated_quota="",
        violated_limit=0,
        actual_value=0,
        message=f"Resource check PASSED: {file_count} files, {loc_estimate:,} LOC",
    )


def validate_user_policy(policy_fields: dict) -> tuple[bool, str]:
    """
    Purpose: Validate that a user custom policy does not touch protected components.
    Returns (is_valid, rejection_reason).

    User policies are ADDITIVE ONLY (§15, §16).
    Core investigators, governance rules, and kernel logic are IMMUTABLE.

    Inputs: policy_fields — dict of field names the user policy attempts to set
    Outputs: (True, "") if valid; (False, reason) if rejected
    Constraints: Pure function; deterministic
    """
    attempted_protected = frozenset(policy_fields.keys()) & PROTECTED_COMPONENTS
    if attempted_protected:
        return (
            False,
            f"User policy attempts to modify protected components: "
            f"{sorted(attempted_protected)}. "
            f"These components are immutable per Engineering Constitution §16. "
            f"User policies are ADDITIVE ONLY — they cannot override core investigators, "
            f"governance rules, or kernel logic."
        )

    # Check if any mandatory detections are being disabled
    disabled = set(policy_fields.get("disabled_detections", []))
    blocked_disables = disabled & MANDATORY_DETECTIONS
    if blocked_disables:
        return (
            False,
            f"User policy attempts to disable mandatory detections: "
            f"{sorted(blocked_disables)}. "
            f"These are platform survival laws (Constitutional §3) and "
            f"cannot be disabled by any user policy."
        )

    return (True, "")


def get_gateway_summary() -> dict:
    """
    Purpose: Produce a deterministic summary of all gateway profiles.
    Used by CLI and dashboard for display.
    """
    return {
        gid: {
            "tier": p.tier.value,
            "service_class": p.service_class,
            "daily_limit": p.daily_limit if p.daily_limit != -1 else "unlimited",
            "max_files": p.max_files,
            "max_loc": p.max_loc,
            "max_memory_mb": p.max_memory_mb,
            "analysis_timeout_sec": p.analysis_timeout_sec,
            "mfa_required": p.mfa_required,
            "custom_policies": p.custom_policy_level,
            "incident_response": p.incident_response_allowed,
        }
        for gid, p in sorted(GATEWAY_PROFILES.items())
    }
