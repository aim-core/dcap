"""
******************************************************************************
 * FILE:        /src/application/classification/classification_pipeline.py
 * LAYER:       Application Layer
 * MODULE:      Classification Pipeline
 * PURPOSE:     Orchestrate the full context classification pipeline
 * DOMAIN:      Context Classification Pipeline
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The ClassificationPipeline orchestrates all Phase 3 components in sequence:
 *
 *   Step 1: FilesystemFingerprinter  → FilesystemWalkResult
 *   Step 2: BuildSystemDetector      → BuildSystemDetectionResult
 *   Step 3: DependencyMapper         → DependencyMapResult
 *   Step 4: PostureClassifier        → PostureClassificationResult
 *   Step 5: build_context_fingerprint → ContextFingerprint
 *
 * This is the APPLICATION LAYER coordinator. It:
 *   - Accepts a source root path
 *   - Runs all infrastructure components in defined order
 *   - Returns a complete ContextClassificationArtifact
 *   - Never performs classification itself (delegates to infrastructure)
 *
 * CLEAN ARCHITECTURE COMPLIANCE:
 *   - Application layer → Infrastructure layer (permitted)
 *   - Application layer → Domain layer (permitted via domain types)
 *   - No domain → application or infrastructure → application (prohibited)
 *
 * DEPENDENCIES:
 *   - src/infrastructure/classification/* (all classifiers)
 *   - src/domain/context/context_model.py (domain types)
 *
 * CONSTRAINTS:
 *   - Pipeline steps are sequential (not parallel — determinism)
 *   - Each step result is immutable before next step begins
 *   - Any step failure aborts the pipeline with ClassificationError
 *
 * DETERMINISM GUARANTEES:
 *   - Steps run in fixed order
 *   - Each step is deterministic (same inputs → same outputs)
 *   - ContextFingerprint hash is deterministic across pipeline runs
 *
 * FAILURE MODES:
 *   - ClassificationError: any pipeline step fails
 *   - IncompatibleDomainPosture: contradictory signals (from posture step)
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

from dataclasses import dataclass

from src.domain.context.context_model import ContextFingerprint, IncompatibleDomainPosture
from src.infrastructure.classification.filesystem.fs_fingerprinter import (
    FilesystemFingerprinter, FingerprintConfig, FilesystemWalkResult,
)
from src.infrastructure.classification.buildsystem.build_detector import (
    BuildSystemDetectionResult, detect_build_system,
)
from src.infrastructure.classification.dependencies.dep_mapper import (
    DependencyMapper, DependencyMapResult,
)
from src.infrastructure.classification.fingerprint.posture_classifier import (
    PostureClassificationResult, classify_domain_posture, build_context_fingerprint,
)


# ─── Error ────────────────────────────────────────────────────────────────────

class ClassificationError(Exception):
    """
    Purpose: Raised when the classification pipeline fails at any step.
    Wraps the underlying error with step context for diagnostics.
    """


# ─── Artifact ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ContextClassificationArtifact:
    """
    Purpose: Complete, immutable result of the classification pipeline.
    This is the output of Phase 3 and the input to Phase 4 (Policy Engine).

    Inputs:
    - fingerprint: The final ContextFingerprint (canonical summary)
    - fs_result: Raw filesystem walk result
    - build_result: Build system detection result
    - dep_result: Dependency mapping result
    - posture_result: Domain posture classification result
    - pipeline_warnings: Sorted tuple of non-fatal warnings from all steps

    Constraints:
    - All fields are immutable
    - fingerprint.fingerprint_hash is deterministic
    """
    fingerprint: ContextFingerprint
    fs_result: FilesystemWalkResult
    build_result: BuildSystemDetectionResult
    dep_result: DependencyMapResult
    posture_result: PostureClassificationResult
    pipeline_warnings: tuple[str, ...]   # sorted


# ─── Pipeline ─────────────────────────────────────────────────────────────────

class ClassificationPipeline:
    """
    Purpose: Orchestrate the complete context classification pipeline.

    Usage:
        pipeline = ClassificationPipeline()
        artifact = pipeline.classify("/path/to/project")
        # artifact.fingerprint contains the complete context summary
        # artifact.fingerprint.recommended_tier() returns the analysis tier

    Constraints:
    - Sequential execution (not parallel) for determinism
    - Each step result frozen before next step begins
    - Pipeline aborts on any step failure
    """

    def __init__(
        self,
        fingerprint_config: FingerprintConfig = FingerprintConfig(),
    ) -> None:
        self._fp_config = fingerprint_config
        self._fs_fingerprinter = FilesystemFingerprinter(fingerprint_config)
        self._dep_mapper = DependencyMapper()

    def classify(self, source_root: str) -> ContextClassificationArtifact:
        """
        Purpose: Run the complete classification pipeline on a source root.

        Inputs: source_root — path to the project root directory
        Outputs: ContextClassificationArtifact (immutable)

        Failure:
        - ClassificationError: any step fails
        - IncompatibleDomainPosture: contradictory signals (propagated as-is)

        Steps:
        1. Filesystem fingerprinting (structure, tags, file counts)
        2. Build system detection (Cargo.toml, CMakeLists.txt, etc.)
        3. Dependency mapping (requirements.txt, pyproject.toml, etc.)
        4. Domain posture classification (rule-based, priority-ordered)
        5. Context fingerprint assembly (canonical, hashable)

        Determinism: same source tree → same artifact (hash-identical fingerprint)
        Complexity: O(n) files + O(d) dependencies (both bounded)
        """
        warnings: list[str] = []

        # ── Step 1: Filesystem Fingerprinting ─────────────────────────────────
        try:
            fs_result = self._fs_fingerprinter.fingerprint(source_root)
        except Exception as e:
            raise ClassificationError(
                f"Step 1 (Filesystem Fingerprinting) failed: {type(e).__name__}: {e}"
            ) from e

        # ── Step 2: Build System Detection ────────────────────────────────────
        try:
            build_result = detect_build_system(source_root)
        except Exception as e:
            raise ClassificationError(
                f"Step 2 (Build System Detection) failed: {type(e).__name__}: {e}"
            ) from e

        # ── Step 3: Dependency Mapping ────────────────────────────────────────
        try:
            dep_result = self._dep_mapper.map_dependencies(source_root)
            warnings.extend(dep_result.parse_warnings)
        except Exception as e:
            raise ClassificationError(
                f"Step 3 (Dependency Mapping) failed: {type(e).__name__}: {e}"
            ) from e

        # ── Step 4: Domain Posture Classification ─────────────────────────────
        # IncompatibleDomainPosture is NOT caught here — it propagates to caller
        # because it requires human intervention, not a retry
        try:
            posture_result = classify_domain_posture(fs_result, build_result, dep_result)
        except IncompatibleDomainPosture:
            raise   # Propagate — human must resolve
        except Exception as e:
            raise ClassificationError(
                f"Step 4 (Domain Posture Classification) failed: {type(e).__name__}: {e}"
            ) from e

        # ── Step 5: Context Fingerprint Assembly ──────────────────────────────
        try:
            fingerprint = build_context_fingerprint(
                fs_result=fs_result,
                build_result=build_result,
                dep_result=dep_result,
                posture_result=posture_result,
            )
        except Exception as e:
            raise ClassificationError(
                f"Step 5 (Context Fingerprint Assembly) failed: {type(e).__name__}: {e}"
            ) from e

        return ContextClassificationArtifact(
            fingerprint=fingerprint,
            fs_result=fs_result,
            build_result=build_result,
            dep_result=dep_result,
            posture_result=posture_result,
            pipeline_warnings=tuple(sorted(warnings)),
        )
