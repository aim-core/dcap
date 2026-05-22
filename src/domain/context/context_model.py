"""
******************************************************************************
 * FILE:        /src/domain/context/context_model.py
 * LAYER:       Domain Layer
 * MODULE:      Context Model
 * PURPOSE:     Immutable domain types for deterministic context classification
 * DOMAIN:      Verification Core
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Defines the Context domain model. Context is the structured description
 * of WHAT kind of codebase is being analyzed — not WHAT the code does,
 * but WHERE it runs and WHAT domain it belongs to.
 *
 * Context classification is:
 * - STRUCTURAL (based on filesystem, build system, API signatures)
 * - RULE-BASED (deterministic pattern matching)
 * - DETERMINISTIC (same codebase → same context, always)
 *
 * Context is NOT:
 * - Semantic inference ("this looks like it might be...")
 * - Intent detection ("the developer probably meant...")
 * - ML classification (anything probabilistic)
 *
 * Context determines which policies apply and at what tier.
 * The same construct in a web server context vs. an ISR context
 * triggers completely different policies.
 *
 * Context fingerprinting is described in Foundation Document Section 5.
 *
 * DEPENDENCIES:
 * - src/domain/constructs/construct_model.py (Tier only)
 *
 * CONSTRAINTS:
 * - No I/O. No runtime mutation. No semantic guessing.
 * - All tags are structural (derived from code structure, not behavior)
 * - Classification is replayable: same input → same context
 *
 * DETERMINISM GUARANTEES:
 * - All types are frozen dataclasses
 * - Context tags are sorted tuples of strings
 * - Domain posture is determined by fixed rule set
 * - Context fingerprint hash is SHA-256 of canonical form
 *
 * FAILURE MODES:
 * - InvalidContextTag: tag doesn't match naming convention
 * - ContextFingerprintError: fingerprint computation failure
 * - IncompatibleDomainPosture: conflicting domain signals detected
 *
 * SECURITY CONSIDERATIONS:
 * - Context is derived from source structure only; no execution
 * - Fingerprint hash enables context integrity verification
 * - No external signals (env vars, network) influence context
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
import pathlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src.domain.constructs.construct_model import Tier


# ─── Domain Errors ────────────────────────────────────────────────────────────

class ContextDomainError(Exception):
    """Base class for context domain errors."""


class InvalidContextTag(ContextDomainError):
    """
    Purpose: Raised when a context tag doesn't match the canonical format.
    Format: UPPER_SNAKE_CASE, no spaces, no special chars except underscore.
    Example: ISR_CONTEXT, SAFETY_CRITICAL, WEB_REQUEST_HANDLER
    """


class IncompatibleDomainPosture(ContextDomainError):
    """
    Purpose: Raised when contradictory domain signals are detected.
    Example: Both SAFETY_CRITICAL and PROTOTYPE signals present.
    Resolution: Requires human clarification — cannot proceed without it.
    """


# ─── Context Tag Validation ───────────────────────────────────────────────────

_CONTEXT_TAG_PATTERN = re.compile(r'^[A-Z][A-Z0-9_]{1,63}$')


def validate_context_tag(tag: str) -> str:
    """
    Purpose: Validate a context tag string.
    Inputs: tag — the context tag to validate
    Outputs: the validated tag
    Failure: InvalidContextTag if format is wrong
    """
    if not _CONTEXT_TAG_PATTERN.match(tag):
        raise InvalidContextTag(
            f"Invalid context tag '{tag}'. "
            f"Required: UPPER_SNAKE_CASE, 2-64 chars, alphanumeric + underscore, "
            f"must start with uppercase letter."
        )
    return tag


# ─── Domain Posture ───────────────────────────────────────────────────────────

class DomainPosture(str, Enum):
    """
    Purpose: High-level classification of the software domain being analyzed.
    This is the primary context signal that determines which tier is appropriate
    and which policy families are activated.

    Source: Foundation Document Section 5.2
    Reference: Aligned with IEC 61508 SIL classification domains.

    SAFETY_CRITICAL:    Software where failure can cause physical harm
                        (medical devices, industrial control, automotive)
    HIGH_ASSURANCE:     Software where failure causes significant economic
                        or operational harm (financial systems, infrastructure)
    COMMERCIAL:         Standard business software (web apps, APIs, services)
    EDUCATIONAL:        Prototypes, examples, learning code
    UNKNOWN:            Cannot determine domain from structural analysis
    """
    SAFETY_CRITICAL  = "SAFETY_CRITICAL"
    HIGH_ASSURANCE   = "HIGH_ASSURANCE"
    COMMERCIAL       = "COMMERCIAL"
    EDUCATIONAL      = "EDUCATIONAL"
    UNKNOWN          = "UNKNOWN"

    def minimum_tier(self) -> Tier:
        """
        Purpose: Returns the minimum analysis tier appropriate for this domain.
        A safety-critical system must use at least RED tier.
        A commercial system should use at least BLUE tier.

        Outputs: Tier enum value (minimum required tier)
        Determinism: pure function of enum value
        """
        return {
            DomainPosture.SAFETY_CRITICAL: Tier.RED,
            DomainPosture.HIGH_ASSURANCE:  Tier.YELLOW,
            DomainPosture.COMMERCIAL:      Tier.BLUE,
            DomainPosture.EDUCATIONAL:     Tier.GREEN,
            DomainPosture.UNKNOWN:         Tier.BLUE,  # Err on the side of caution
        }[self]


# ─── Build System Detection ───────────────────────────────────────────────────

class BuildSystem(str, Enum):
    """
    Purpose: Identifies the build system of the analyzed project.
    Build system affects which constructs are relevant (e.g., Makefile-based
    C projects may have different concerns than pip-based Python).

    Detection: structural (presence of characteristic files).
    Source: Engineering judgment; no external standard citation required.

    Structural signals per build system:
    - CARGO:   Cargo.toml present
    - CMAKE:   CMakeLists.txt present
    - MAKE:    Makefile present (and not overridden by more specific signal)
    - PIP:     setup.py, setup.cfg, or pyproject.toml + pip backend
    - POETRY:  pyproject.toml with [tool.poetry] section
    - GRADLE:  build.gradle or build.gradle.kts present
    - MAVEN:   pom.xml present
    - UNKNOWN: no recognized build system signal
    """
    CARGO   = "CARGO"
    CMAKE   = "CMAKE"
    MAKE    = "MAKE"
    PIP     = "PIP"
    POETRY  = "POETRY"
    GRADLE  = "GRADLE"
    MAVEN   = "MAVEN"
    UNKNOWN = "UNKNOWN"


# ─── Context Tags (structured vocabulary) ────────────────────────────────────

class ContextTagVocabulary:
    """
    Purpose: Defines the canonical vocabulary of context tags.
    Tags are assigned during context classification based on structural signals.
    Only tags from this vocabulary are valid in a context fingerprint.

    These are NOT inferred from semantics. They are detected from:
    - File system structure (directory names, file patterns)
    - API signatures (function names, decorator names, class names)
    - Build system configuration
    - Dependency manifests
    - Source file naming conventions

    Source: Foundation Document Section 5.3
    Citation: MISRA-C:2012 Section 5 (context-dependent rule applicability)
    """

    # Execution context tags — WHERE the code runs
    EXECUTION_CONTEXT = frozenset({
        "ISR_CONTEXT",           # Interrupt Service Routine context detected
        "KERNEL_CONTEXT",        # OS kernel module context
        "EMBEDDED_CONTEXT",      # Embedded system (no OS or RTOS)
        "RTOS_CONTEXT",          # Real-time OS context (FreeRTOS, Zephyr, etc.)
        "WEB_REQUEST_HANDLER",   # HTTP request handler function
        "BACKGROUND_WORKER",     # Background/daemon process
        "CLI_ENTRYPOINT",        # Command-line tool entry point
        "TEST_CONTEXT",          # Inside a test file/function
        "SCRIPT_CONTEXT",        # Standalone script (not library)
    })

    # Safety and assurance tags
    SAFETY_TAGS = frozenset({
        "SAFETY_CRITICAL",       # Explicit safety-critical annotation or directory name
        "SAFETY_VERIFIED",       # Pre-verified safety component
        "PROTOTYPE_CODE",        # Prototype/proof-of-concept marker
        "EXPERIMENTAL",          # Explicitly experimental
    })

    # Concurrency context tags
    CONCURRENCY_TAGS = frozenset({
        "ASYNC_CODEBASE",        # asyncio-based codebase detected
        "THREAD_POOL_USAGE",     # ThreadPoolExecutor or similar
        "MULTIPROCESS_USAGE",    # multiprocessing module usage
        "SHARED_MEMORY_USAGE",   # shared memory IPC patterns
        "LOCK_HEAVY",            # High lock usage density
    })

    # I/O context tags
    IO_TAGS = frozenset({
        "NETWORK_IO_PRESENT",    # Socket/HTTP/network I/O detected
        "FILE_IO_HEAVY",         # Heavy file system operations
        "DATABASE_PRESENT",      # Database driver imports detected
        "EXTERNAL_API_CALLS",    # External HTTP API calls detected
    })

    # Security context tags
    SECURITY_TAGS = frozenset({
        "HANDLES_USER_INPUT",    # User-controlled data enters the codebase
        "CRYPTO_OPERATIONS",     # Cryptographic operations detected
        "AUTH_LOGIC",            # Authentication/authorization logic present
        "SERIALIZATION_PRESENT", # Serialization/deserialization operations
        "DYNAMIC_CODE_EXEC",     # eval/exec patterns detected (also a finding)
    })

    # Regulatory context tags
    REGULATORY_TAGS = frozenset({
        "IEC_61508_SCOPE",       # IEC 61508 functional safety scope
        "ISO_26262_SCOPE",       # ISO 26262 automotive safety scope
        "DO_178C_SCOPE",         # DO-178C avionics software scope
        "IEC_62443_SCOPE",       # IEC 62443 industrial cybersecurity scope
        "HIPAA_SCOPE",           # HIPAA healthcare data scope
        "PCI_DSS_SCOPE",         # PCI DSS payment card scope
        "SOC2_SCOPE",            # SOC 2 audit scope
    })

    @classmethod
    def all_valid_tags(cls) -> frozenset[str]:
        """Returns the union of all valid context tags."""
        return (
            cls.EXECUTION_CONTEXT
            | cls.SAFETY_TAGS
            | cls.CONCURRENCY_TAGS
            | cls.IO_TAGS
            | cls.SECURITY_TAGS
            | cls.REGULATORY_TAGS
        )

    @classmethod
    def is_valid_tag(cls, tag: str) -> bool:
        """Purpose: Check if a tag is in the canonical vocabulary."""
        return tag in cls.all_valid_tags()


# ─── Context Fingerprint ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class ContextFingerprint:
    """
    Purpose: The complete, canonical, deterministic description of an analyzed
    codebase's context. This fingerprint determines which policies apply and
    how findings are escalated.

    The fingerprint is NOT an analysis result — it is the INPUT to the policy
    engine. It describes the environment the code runs in.

    Inputs:
    - source_root: Absolute canonical path to analyzed source root
    - source_hash: SHA-256 of the source tree manifest
    - domain_posture: High-level domain classification
    - build_system: Detected build system
    - language: Primary programming language
    - language_version: Minimum detected language version
    - framework_signals: Sorted tuple of detected frameworks (e.g., "django", "asyncio")
    - context_tags: Sorted tuple of ContextTagVocabulary tags (validated)
    - dependency_count: Number of external dependencies
    - loc_estimate: Lines of code estimate (integer, for quota calculation)
    - fingerprint_hash: SHA-256 of the canonical fingerprint
    - classification_method: Always "STRUCTURAL_RULE_BASED" (not semantic)

    Constraints:
    - All context_tags must be in ContextTagVocabulary.all_valid_tags()
    - source_root must be absolute (starts with /)
    - classification_method must be "STRUCTURAL_RULE_BASED"
    - fingerprint_hash is computed by ContextFingerprintBuilder

    Determinism: same source → same fingerprint (byte-identical hash)
    """
    source_root: str
    source_hash: str
    domain_posture: str           # DomainPosture value
    build_system: str             # BuildSystem value
    language: str
    language_version: str
    framework_signals: tuple[str, ...]   # sorted
    context_tags: tuple[str, ...]        # sorted; all in ContextTagVocabulary
    dependency_count: int
    loc_estimate: int
    fingerprint_hash: str         # sha256:... of canonical form
    classification_method: str    # always "STRUCTURAL_RULE_BASED"

    _CLASSIFICATION_METHOD = "STRUCTURAL_RULE_BASED"

    def __post_init__(self) -> None:
        # Validate domain posture
        valid_postures = {dp.value for dp in DomainPosture}
        if self.domain_posture not in valid_postures:
            raise ContextDomainError(f"Invalid domain_posture '{self.domain_posture}'")

        # Validate build system
        valid_build_systems = {bs.value for bs in BuildSystem}
        if self.build_system not in valid_build_systems:
            raise ContextDomainError(f"Invalid build_system '{self.build_system}'")

        # Validate context tags
        valid_tags = ContextTagVocabulary.all_valid_tags()
        for tag in self.context_tags:
            if tag not in valid_tags:
                raise InvalidContextTag(
                    f"Context tag '{tag}' is not in ContextTagVocabulary. "
                    f"Only tags from the canonical vocabulary are permitted."
                )

        # Validate source root is absolute
        if not (pathlib.Path(self.source_root).is_absolute() or (len(self.source_root)>=2 and self.source_root[1]==chr(58))):
            raise ContextDomainError(
                f"source_root must be absolute path, got '{self.source_root}'"
            )

        # Validate classification method
        if self.classification_method != self._CLASSIFICATION_METHOD:
            raise ContextDomainError(
                f"classification_method must be '{self._CLASSIFICATION_METHOD}', "
                f"got '{self.classification_method}'. "
                f"Context classification is always structural and rule-based."
            )

        # Validate non-negative counts
        if self.dependency_count < 0:
            raise ContextDomainError(f"dependency_count must be >= 0")
        if self.loc_estimate < 0:
            raise ContextDomainError(f"loc_estimate must be >= 0")

    def has_tag(self, tag: str) -> bool:
        """
        Purpose: Check if a specific context tag is present.
        Inputs: tag — the tag to check
        Outputs: bool
        Constraints: O(n) binary search on sorted tuple
        Determinism: pure function
        """
        return tag in self.context_tags

    def recommended_tier(self) -> Tier:
        """
        Purpose: Compute the recommended analysis tier from the context.
        The recommended tier is the maximum of: domain posture minimum tier
        and any tier-escalating tags.

        Outputs: Tier enum value
        Constraints: Deterministic; depends only on frozen fields
        """
        base_tier = DomainPosture(self.domain_posture).minimum_tier()

        # Safety-critical tags force minimum RED tier
        safety_escalating = frozenset({
            "ISR_CONTEXT", "KERNEL_CONTEXT", "SAFETY_CRITICAL",
            "IEC_61508_SCOPE", "ISO_26262_SCOPE", "DO_178C_SCOPE",
        })
        if any(tag in safety_escalating for tag in self.context_tags):
            return Tier.RED

        # High assurance tags force minimum YELLOW tier
        high_assurance_escalating = frozenset({
            "IEC_62443_SCOPE", "HIPAA_SCOPE", "PCI_DSS_SCOPE",
            "AUTH_LOGIC", "CRYPTO_OPERATIONS",
        })
        if any(tag in high_assurance_escalating for tag in self.context_tags):
            if base_tier == Tier.GREEN or base_tier == Tier.BLUE:
                return Tier.YELLOW

        return base_tier

    @staticmethod
    def compute_hash(
        source_root: str,
        domain_posture: str,
        build_system: str,
        language: str,
        framework_signals: tuple[str, ...],
        context_tags: tuple[str, ...],
    ) -> str:
        """
        Purpose: Compute the deterministic fingerprint hash.
        Called by ContextFingerprintBuilder before constructing the fingerprint.

        Inputs: The key identifying fields of the fingerprint
        Outputs: "sha256:{64 hex chars}"
        Constraints: No I/O; pure computation; byte-identical across platforms
        """
        canonical = {
            "source_root": source_root,
            "domain_posture": domain_posture,
            "build_system": build_system,
            "language": language,
            "framework_signals": sorted(framework_signals),
            "context_tags": sorted(context_tags),
        }
        canonical_bytes = json.dumps(
            canonical,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False,
        ).encode('utf-8')
        return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
