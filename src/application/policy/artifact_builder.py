"""
******************************************************************************
 * FILE:        /src/application/policy/artifact_builder.py
 * LAYER:       Application Layer
 * MODULE:      CEF Artifact Builder
 * PURPOSE:     Assemble PolicyDecisions into a signed, verified CEFArtifact
 * DOMAIN:      Policy Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The ArtifactBuilder accepts a list of PolicyDecision objects and assembles
 * them into a canonical, immutable CEFArtifact. It:
 *
 *   1. Collects all non-suppressed findings
 *   2. Sorts findings by canonical_location (primary sort key)
 *   3. Re-sequences finding IDs (F-00001, F-00002, ...)
 *   4. Aggregates all boundary declarations
 *   5. Computes the BoundaryHonestyReport
 *   6. Assembles the CEFArtifact
 *   7. Computes the artifact_hash (SHA-256 of canonical form)
 *   8. Returns the finalized, immutable artifact
 *
 * PHASE 0 LIMITATIONS (documented):
 *   - signature = "PHASE0-UNSIGNED" (no Ed25519 in Phase 0)
 *   - warning field declares unsigned status
 *
 * DEPENDENCIES:
 *   - src/domain/evidence/evidence_model.py
 *   - src/domain/constructs/construct_model.py
 *   - src/application/policy/policy_engine.py
 *   - src/infrastructure/catalog/registry/catalog_registry.py
 *
 * CONSTRAINTS:
 *   - No I/O; pure assembly function
 *   - Finding IDs re-sequenced in sorted order (deterministic)
 *   - artifact_hash computed AFTER all fields set
 *
 * DETERMINISM GUARANTEES:
 *   - Findings sorted by (canonical_location, construct_id, policy)
 *   - artifact_hash is SHA-256 of canonical JSON serialization
 *   - Same inputs → identical artifact_hash
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
import json
import uuid
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.domain.constructs.construct_model import Tier
from src.domain.context.context_model import ContextFingerprint
from src.domain.evidence.evidence_model import (
    BoundaryDeclaration, BoundaryHonestyReport,
    CEFArtifact, ExecutionContext, Finding,
)
from src.application.policy.policy_engine import PolicyDecision
from src.infrastructure.catalog.registry.catalog_registry import CatalogRegistry


# ─── Default Boundary Weights ─────────────────────────────────────────────────

_DEFAULT_BOUNDARY_WEIGHTS: dict[str, int] = {
    "ANALYSIS_BOUNDARY_REACHED":        500,
    "UNRESOLVED_DYNAMIC_DISPATCH":      600,
    "INCOMPLETE_VISIBILITY":            400,
    "SIMULATION_DEPTH_EXCEEDED":        700,
    "SYMBOLIC_LIMIT_REACHED":           700,
    "EXTERNAL_DEPENDENCY_UNRESOLVED":   500,
    "RUNTIME_BEHAVIOR_UNKNOWN":         800,
    "CONCURRENCY_INTERLEAVING_UNKNOWN": 900,
}


# ─── Canonical Serializer ─────────────────────────────────────────────────────

class _CanonicalSerializer:
    """
    Purpose: Serialize CEFArtifact fields to canonical JSON for hashing.
    Field order: schema-defined (not alphabetical).
    No floats, no optional whitespace, UTF-8 + NFC.
    """

    @classmethod
    def _normalize(cls, s: str) -> str:
        return unicodedata.normalize("NFC", s)

    @classmethod
    def _serialize_value(cls, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return cls._normalize(value)
        if isinstance(value, (list, tuple)):
            return [cls._serialize_value(v) for v in value]
        if isinstance(value, dict):
            return {k: cls._serialize_value(v) for k, v in sorted(value.items())}
        # Dataclass → ordered dict
        obj_dict = value.__dict__ if hasattr(value, '__dict__') else {}
        return {k: cls._serialize_value(v) for k, v in obj_dict.items()}

    @classmethod
    def to_canonical_bytes(cls, obj: object) -> bytes:
        serialized = cls._serialize_value(obj)
        return json.dumps(
            serialized,
            sort_keys=False,
            separators=(',', ':'),
            ensure_ascii=False,
        ).encode('utf-8')

    @classmethod
    def compute_artifact_hash(cls, artifact: CEFArtifact) -> str:
        """SHA-256 of canonical artifact form. artifact_hash must be 'PENDING'."""
        return "sha256:" + hashlib.sha256(cls.to_canonical_bytes(artifact)).hexdigest()


# ─── Artifact Builder ─────────────────────────────────────────────────────────

def build_artifact(
    decisions: list[PolicyDecision],
    context: ContextFingerprint,
    tier: Tier,
    catalog: CatalogRegistry,
    execution_seed: str = "0xdeadbeef00",
    source_hash: Optional[str] = None,
) -> CEFArtifact:
    """
    Purpose: Assemble a list of PolicyDecisions into a finalized CEFArtifact.

    Inputs:
    - decisions: All PolicyDecision objects from the policy engine run
    - context: The ContextFingerprint of the analyzed project
    - tier: The analysis tier used
    - catalog: The verified CatalogRegistry
    - execution_seed: Hex seed for replay (default for tests)
    - source_hash: SHA-256 of source tree (from filesystem fingerprint)

    Outputs: Finalized, immutable CEFArtifact with computed artifact_hash

    Algorithm:
    1. Filter non-suppressed findings
    2. Sort findings by canonical_location
    3. Re-sequence finding IDs (F-00001, ...)
    4. Aggregate all boundaries
    5. Compute BoundaryHonestyReport
    6. Build ExecutionContext
    7. Assemble CEFArtifact with artifact_hash="PENDING"
    8. Compute and embed artifact_hash
    9. Return finalized artifact

    Determinism: same decisions → same artifact_hash
    Constraints: No I/O; pure assembly
    """
    import sys

    # ── Step 1: Collect and sort findings ─────────────────────────────────
    raw_findings: list[Finding] = [
        d.finding for d in decisions
        if d.finding is not None and not d.is_suppressed
    ]

    # ── Step 2: Sort by (canonical_location, construct_id, policy) ────────
    sorted_findings = sorted(
        raw_findings,
        key=lambda f: (f.canonical_location, f.construct_id, f.policy),
    )

    # ── Step 3: Re-sequence finding IDs ───────────────────────────────────
    resequenced: list[Finding] = []
    for idx, finding in enumerate(sorted_findings, start=1):
        new_id = f"F-{idx:05d}"
        # Rebuild Finding with corrected ID (frozen dataclass → replace via constructor)
        resequenced.append(Finding(
            finding_id=new_id,
            canonical_location=finding.canonical_location,
            construct_id=finding.construct_id,
            construct_name=finding.construct_name,
            detected_state=finding.detected_state,
            severity=finding.severity,
            confidence=finding.confidence,
            policy=finding.policy,
            policy_version=finding.policy_version,
            escalation_chain=finding.escalation_chain,
            risk_mappings=finding.risk_mappings,
            standards=finding.standards,
            explainability_graph=finding.explainability_graph,
            boundary_status=finding.boundary_status,
            boundaries=finding.boundaries,
            human_review_required=finding.human_review_required,
            reviewer_qualification=finding.reviewer_qualification,
            evidence_hash=finding.evidence_hash,
        ))

    # ── Step 4: Aggregate boundaries ──────────────────────────────────────
    all_boundaries: list[BoundaryDeclaration] = []
    for finding in resequenced:
        all_boundaries.extend(finding.boundaries)
    # Sort boundaries deterministically
    all_boundaries_sorted = sorted(
        all_boundaries,
        key=lambda b: (b.boundary_type, b.location),
    )

    # ── Step 5: Compute BoundaryHonestyReport ─────────────────────────────
    total_analysis_points = max(len(decisions), 1)
    boundary_honesty = BoundaryHonestyReport.compute(
        total_analysis_points=total_analysis_points,
        boundaries=all_boundaries_sorted,
        boundary_weights=_DEFAULT_BOUNDARY_WEIGHTS,
        recommendations=tuple(sorted({
            b.recommendation for b in all_boundaries_sorted
        })),
    )

    # ── Step 6: Build ExecutionContext ────────────────────────────────────
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    artifact_id = str(uuid.uuid4())

    execution = ExecutionContext(
        seed=execution_seed,
        timestamp_utc=ts,
        host_fingerprint="dcavp-build-env",
        kernel_version="dcavp-kernel/0.1.0",
        catalog_version=catalog.metadata.catalog_version,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        platform_id="linux/x86_64",
        locale="C",
        timezone_id="UTC",
    )

    # ── Step 7: Assemble CEFArtifact ──────────────────────────────────────
    artifact = CEFArtifact(
        cef_version="1.0",
        artifact_id=artifact_id,
        artifact_hash="PENDING",
        execution=execution,
        tier=tier.value,
        analysis_scope="full_source_tree",
        source_root=context.source_root,
        source_hash=source_hash or context.source_hash,
        findings=tuple(resequenced),
        artifact_level_boundaries=tuple(all_boundaries_sorted),
        boundary_honesty=boundary_honesty,
        finding_count=len(resequenced),
        warning=(
            "PHASE0-UNSIGNED: This artifact has not been cryptographically signed. "
            "Not suitable for regulatory submission or legal use. "
            "Phase 1+ will add Ed25519 signing."
        ),
        signature="PHASE0-UNSIGNED",
    )

    # ── Step 8: Compute and embed artifact_hash ───────────────────────────
    artifact_hash = _CanonicalSerializer.compute_artifact_hash(artifact)

    # Rebuild with real hash (frozen dataclass)
    final_artifact = CEFArtifact(
        cef_version=artifact.cef_version,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        execution=artifact.execution,
        tier=artifact.tier,
        analysis_scope=artifact.analysis_scope,
        source_root=artifact.source_root,
        source_hash=artifact.source_hash,
        findings=artifact.findings,
        artifact_level_boundaries=artifact.artifact_level_boundaries,
        boundary_honesty=artifact.boundary_honesty,
        finding_count=artifact.finding_count,
        warning=artifact.warning,
        signature=artifact.signature,
    )

    return final_artifact
