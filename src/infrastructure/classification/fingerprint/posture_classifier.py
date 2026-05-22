"""
******************************************************************************
 * FILE:        /src/infrastructure/classification/fingerprint/posture_classifier.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Context Classification — Domain Posture Classifier
 * PURPOSE:     Derive DomainPosture from combined structural signals
 * DOMAIN:      Context Classification Pipeline
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Combines signals from FilesystemWalkResult, BuildSystemDetectionResult,
 * and DependencyMapResult to produce a deterministic DomainPosture
 * classification and a final ContextFingerprint.
 *
 * POSTURE CLASSIFICATION RULES (deterministic, priority-ordered):
 *
 *   SAFETY_CRITICAL (highest):
 *     - SAFETY_CRITICAL tag present, OR
 *     - Any of: ISR_CONTEXT, KERNEL_CONTEXT, RTOS_CONTEXT, EMBEDDED_CONTEXT
 *       combined with SAFETY_CRITICAL tag, OR
 *     - Any regulatory scope tag: IEC_61508_SCOPE, ISO_26262_SCOPE, DO_178C_SCOPE
 *
 *   HIGH_ASSURANCE:
 *     - Any of: IEC_62443_SCOPE, HIPAA_SCOPE, PCI_DSS_SCOPE, SOC2_SCOPE
 *     - Or: CRYPTO_OPERATIONS + AUTH_LOGIC (combined signal)
 *
 *   COMMERCIAL (default for recognized projects):
 *     - WEB_REQUEST_HANDLER, or DATABASE_PRESENT, or EXTERNAL_API_CALLS
 *     - Or: any recognized framework detected
 *
 *   EDUCATIONAL:
 *     - PROTOTYPE_CODE or EXPERIMENTAL tag
 *     - Or: TEST_CONTEXT dominant (>80% test files by count)
 *
 *   UNKNOWN:
 *     - No recognized signals
 *
 * CONFLICT RESOLUTION:
 *   If PROTOTYPE_CODE/EXPERIMENTAL AND SAFETY_CRITICAL signals both present:
 *   → IncompatibleDomainPosture raised (requires human clarification)
 *
 * REFERENCES:
 *   IEC 61508-1:2010 Table 3 — SIL determination methodology
 *   ENGINEERING-JUDGMENT-v0.1.0 for all rule definitions
 *
 * DEPENDENCIES:
 *   - src/domain/context/context_model.py
 *   - src/infrastructure/classification/filesystem/fs_fingerprinter.py
 *   - src/infrastructure/classification/buildsystem/build_detector.py
 *   - src/infrastructure/classification/dependencies/dep_mapper.py
 *
 * CONSTRAINTS:
 *   - Pure function: no I/O; inputs are already-computed results
 *   - No ML; no probabilistic inference; rule-based only
 *   - Deterministic: same inputs → same DomainPosture
 *
 * DETERMINISM GUARANTEES:
 *   - Rule evaluation order is fixed and immutable
 *   - Tag set operations use sorted() before comparison
 *   - ContextFingerprint hash is deterministic
 *
 * FAILURE MODES:
 *   - IncompatibleDomainPosture: contradictory safety+prototype signals
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from src.domain.context.context_model import (
    BuildSystem,
    ContextFingerprint,
    ContextTagVocabulary,
    DomainPosture,
    IncompatibleDomainPosture,
)
from src.infrastructure.classification.filesystem.fs_fingerprinter import (
    FilesystemWalkResult,
)
from src.infrastructure.classification.buildsystem.build_detector import (
    BuildSystemDetectionResult,
)
from src.infrastructure.classification.dependencies.dep_mapper import (
    DependencyMapResult,
)


# ─── Classification Result ────────────────────────────────────────────────────

@dataclass(frozen=True)
class PostureClassificationResult:
    """
    Purpose: Intermediate result of domain posture classification.
    Carried alongside the final ContextFingerprint for auditability.

    Inputs:
    - domain_posture: The determined DomainPosture
    - applied_rules: Sorted tuple of rule IDs that fired
    - conflicting_signals: Sorted tuple of conflicting tags (empty if none)
    - confidence: "certain" | "heuristic"
    - rationale: Human-readable explanation of the classification
    """
    domain_posture: str           # DomainPosture value
    applied_rules: tuple[str, ...]
    conflicting_signals: tuple[str, ...]
    confidence: str
    rationale: str


# ─── Posture Classifier ───────────────────────────────────────────────────────

def classify_domain_posture(
    fs_result: FilesystemWalkResult,
    build_result: BuildSystemDetectionResult,
    dep_result: DependencyMapResult,
) -> PostureClassificationResult:
    """
    Purpose: Derive DomainPosture from combined structural signals.
    This is a pure function — no I/O, no side effects.

    Inputs:
    - fs_result: Filesystem walk result (tags from directory structure)
    - build_result: Build system detection result
    - dep_result: Dependency mapping result (tags from manifests)

    Outputs: PostureClassificationResult (immutable)

    Failure: IncompatibleDomainPosture if contradictory signals detected

    Rule priority (evaluated in order, first match wins):
    1. SAFETY_CRITICAL signals
    2. HIGH_ASSURANCE signals
    3. Conflict detection (SAFETY + PROTOTYPE)
    4. COMMERCIAL signals
    5. EDUCATIONAL signals
    6. UNKNOWN (default)

    Determinism: same inputs → same result
    Complexity: O(n) where n = total tag count
    """
    # Merge all tags from both sources
    all_tags: frozenset[str] = frozenset(fs_result.detected_tags) | frozenset(dep_result.additional_tags)

    applied_rules: list[str] = []

    # ── Rule 1: SAFETY_CRITICAL detection ─────────────────────────────────────
    safety_critical_tags = frozenset({
        "SAFETY_CRITICAL", "ISR_CONTEXT", "KERNEL_CONTEXT",
        "IEC_61508_SCOPE", "ISO_26262_SCOPE", "DO_178C_SCOPE",
    })
    safety_signals = all_tags & safety_critical_tags

    # ── Rule 2: HIGH_ASSURANCE detection ──────────────────────────────────────
    high_assurance_tags = frozenset({
        "IEC_62443_SCOPE", "HIPAA_SCOPE", "PCI_DSS_SCOPE", "SOC2_SCOPE",
    })
    high_assurance_signals = all_tags & high_assurance_tags
    crypto_auth_combo = ("CRYPTO_OPERATIONS" in all_tags and "AUTH_LOGIC" in all_tags)

    # ── Rule 3: Conflict detection ────────────────────────────────────────────
    prototype_signals = all_tags & frozenset({"PROTOTYPE_CODE", "EXPERIMENTAL"})
    if safety_signals and prototype_signals:
        raise IncompatibleDomainPosture(
            f"Contradictory domain signals detected. "
            f"Safety signals: {sorted(safety_signals)}. "
            f"Prototype signals: {sorted(prototype_signals)}. "
            f"A safety-critical system cannot also be a prototype. "
            f"Resolve this contradiction before analysis can proceed."
        )

    # ── Rule 4: SAFETY_CRITICAL classification ────────────────────────────────
    if safety_signals:
        applied_rules.append("RULE-POSTURE-001:SAFETY_CRITICAL_SIGNALS")
        return PostureClassificationResult(
            domain_posture=DomainPosture.SAFETY_CRITICAL.value,
            applied_rules=tuple(sorted(applied_rules)),
            conflicting_signals=(),
            confidence="certain" if len(safety_signals) >= 2 else "heuristic",
            rationale=(
                f"Safety-critical signals detected: {sorted(safety_signals)}. "
                f"Minimum tier: RED. "
                f"Source: IEC 61508-1:2010 Table 3 — SIL determination."
            ),
        )

    # ── Rule 5: HIGH_ASSURANCE classification ─────────────────────────────────
    if high_assurance_signals:
        applied_rules.append("RULE-POSTURE-002:HIGH_ASSURANCE_REGULATORY")
        return PostureClassificationResult(
            domain_posture=DomainPosture.HIGH_ASSURANCE.value,
            applied_rules=tuple(sorted(applied_rules)),
            conflicting_signals=(),
            confidence="certain",
            rationale=(
                f"High-assurance regulatory signals detected: {sorted(high_assurance_signals)}. "
                f"Minimum tier: YELLOW."
            ),
        )

    if crypto_auth_combo:
        applied_rules.append("RULE-POSTURE-003:CRYPTO_PLUS_AUTH_COMBO")
        return PostureClassificationResult(
            domain_posture=DomainPosture.HIGH_ASSURANCE.value,
            applied_rules=tuple(sorted(applied_rules)),
            conflicting_signals=(),
            confidence="heuristic",
            rationale=(
                "CRYPTO_OPERATIONS and AUTH_LOGIC both detected. "
                "Combined signal indicates high-assurance context. "
                "Minimum tier: YELLOW."
            ),
        )

    # ── Rule 6: EDUCATIONAL / PROTOTYPE classification ────────────────────────
    if prototype_signals:
        applied_rules.append("RULE-POSTURE-004:PROTOTYPE_EXPERIMENTAL")
        return PostureClassificationResult(
            domain_posture=DomainPosture.EDUCATIONAL.value,
            applied_rules=tuple(sorted(applied_rules)),
            conflicting_signals=(),
            confidence="heuristic",
            rationale=(
                f"Prototype/experimental signals detected: {sorted(prototype_signals)}. "
                f"Minimum tier: GREEN. "
                f"Note: upgrade to COMMERCIAL or higher for production deployment."
            ),
        )

    # ── Rule 7: COMMERCIAL classification ─────────────────────────────────────
    commercial_tags = frozenset({
        "WEB_REQUEST_HANDLER", "DATABASE_PRESENT", "EXTERNAL_API_CALLS",
        "BACKGROUND_WORKER", "AUTH_LOGIC", "SERIALIZATION_PRESENT",
    })
    commercial_signals = all_tags & commercial_tags
    has_frameworks = len(dep_result.framework_signals) > 0

    if commercial_signals or has_frameworks:
        applied_rules.append("RULE-POSTURE-005:COMMERCIAL_SIGNALS")
        return PostureClassificationResult(
            domain_posture=DomainPosture.COMMERCIAL.value,
            applied_rules=tuple(sorted(applied_rules)),
            conflicting_signals=(),
            confidence="certain" if commercial_signals else "heuristic",
            rationale=(
                f"Commercial software signals: tags={sorted(commercial_signals)}, "
                f"frameworks={sorted(dep_result.framework_signals)}. "
                f"Minimum tier: BLUE."
            ),
        )

    # ── Rule 8: UNKNOWN (default) ─────────────────────────────────────────────
    applied_rules.append("RULE-POSTURE-006:NO_RECOGNIZED_SIGNALS")
    return PostureClassificationResult(
        domain_posture=DomainPosture.UNKNOWN.value,
        applied_rules=tuple(sorted(applied_rules)),
        conflicting_signals=(),
        confidence="heuristic",
        rationale=(
            "No recognized domain signals detected. "
            "Defaulting to UNKNOWN → minimum tier BLUE (conservative). "
            "Add directory naming or dependency signals to improve classification."
        ),
    )


def build_context_fingerprint(
    fs_result: FilesystemWalkResult,
    build_result: BuildSystemDetectionResult,
    dep_result: DependencyMapResult,
    posture_result: PostureClassificationResult,
    language_version: str = "unknown",
) -> ContextFingerprint:
    """
    Purpose: Assemble the final ContextFingerprint from all classification results.
    This is the single object that summarizes all context knowledge.

    Inputs:
    - fs_result, build_result, dep_result: Classification component results
    - posture_result: Domain posture classification result
    - language_version: Detected language version string

    Outputs: ContextFingerprint (immutable, hashable)

    Constraints: Pure function; no I/O; deterministic
    Determinism: same inputs → same fingerprint hash
    """
    # Merge all context tags from all sources
    all_tags: set[str] = set(fs_result.detected_tags) | set(dep_result.additional_tags)
    valid_vocab = ContextTagVocabulary.all_valid_tags()
    final_tags = tuple(sorted(t for t in all_tags if t in valid_vocab))

    # Compute fingerprint hash
    fingerprint_hash = ContextFingerprint.compute_hash(
        source_root=fs_result.source_root,
        domain_posture=posture_result.domain_posture,
        build_system=build_result.build_system,
        language=fs_result.primary_language(),
        framework_signals=tuple(dep_result.framework_signals),
        context_tags=final_tags,
    )

    return ContextFingerprint(
        source_root=fs_result.source_root,
        source_hash=fs_result.source_hash,
        domain_posture=posture_result.domain_posture,
        build_system=build_result.build_system,
        language=fs_result.primary_language(),
        language_version=language_version,
        framework_signals=tuple(sorted(dep_result.framework_signals)),
        context_tags=final_tags,
        dependency_count=dep_result.dependency_count,
        loc_estimate=fs_result.loc_estimate,
        fingerprint_hash=fingerprint_hash,
        classification_method="STRUCTURAL_RULE_BASED",
    )
