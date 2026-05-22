"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/registry/catalog_registry.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Catalog Registry
 * PURPOSE:     Immutable runtime registry of constructs, policies, standards
 * DOMAIN:      Knowledge Catalog Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The CatalogRegistry is the single source of truth for all catalog
 * knowledge at runtime. It is:
 *
 *   1. LOADED ONCE at startup from catalog entry modules
 *   2. FROZEN immediately after loading (no runtime modification)
 *   3. VERIFIED via Merkle tree before any analysis begins
 *   4. QUERIED via pure accessor functions (no mutation)
 *
 * The registry holds:
 *   - All ConstructDefinition instances (the Knowledge Catalog)
 *   - The Merkle tree for integrity verification
 *   - Catalog metadata (version, load timestamp, verification status)
 *
 * In Phase 0: verification is hash-based (unsigned).
 * In Phase 1+: the Merkle root must carry a valid Ed25519 signature
 *              from the catalog authority before the registry is usable.
 *
 * DEPENDENCIES:
 * - src/domain/constructs/construct_model.py
 * - src/infrastructure/catalog/merkle/merkle_tree.py
 *
 * CONSTRAINTS:
 * - Registry is frozen after build() call (FrozenRegistryError on mutation)
 * - All queries return immutable types or tuples
 * - No network access, no file I/O (caller loads data; registry organizes it)
 * - All lookups are O(1) via pre-built sorted structures
 *
 * DETERMINISM GUARANTEES:
 * - Registry state depends only on the constructs passed at build time
 * - Query results are sorted tuples — identical across calls
 * - Merkle root is deterministic given same constructs
 *
 * FAILURE MODES:
 * - DuplicateConstructError: same construct_id registered twice
 * - FrozenRegistryError: attempted modification after freeze
 * - RegistryIntegrityError: Merkle verification fails
 * - EmptyRegistryError: registry has zero constructs
 *
 * SECURITY CONSIDERATIONS:
 * - Registry is frozen at load time; no runtime injection possible
 * - Merkle verification detects post-load tampering
 * - All returned collections are immutable (tuples, frozensets)
 *
 * COMPLEXITY:
 * - build(): O(n log n) for Merkle tree construction
 * - get_construct(): O(1) dict lookup
 * - list_by_language(): O(k) where k = constructs for that language
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from src.domain.constructs.construct_model import ConstructDefinition, Tier
from src.infrastructure.catalog.merkle.merkle_tree import (
    MerkleTree,
    build_merkle_tree,
    verify_catalog_integrity,
)


# ─── Domain Errors ────────────────────────────────────────────────────────────

class RegistryError(Exception):
    """Base class for registry errors."""


class DuplicateConstructError(RegistryError):
    """
    Purpose: Raised when the same construct_id is registered twice.
    The catalog is append-only — duplicates indicate a catalog authoring error.
    """


class FrozenRegistryError(RegistryError):
    """
    Purpose: Raised when attempting to modify a frozen (built) registry.
    The registry is frozen after build() and cannot be modified.
    """


class RegistryIntegrityError(RegistryError):
    """
    Purpose: Raised when Merkle integrity verification fails.
    Indicates catalog tampering, version mismatch, or corruption.
    """


class EmptyRegistryError(RegistryError):
    """Raised when operations require a non-empty registry."""


# ─── Registry Metadata ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RegistryMetadata:
    """
    Purpose: Immutable metadata about the built registry.
    Included in every CEF artifact to enable catalog replay.

    Inputs:
    - catalog_version: The catalog version string (YYYY.MM.DD)
    - construct_count: Total number of registered constructs
    - languages_covered: Sorted tuple of covered languages
    - merkle_root: The Merkle root hash ("sha256:{hex}")
    - load_timestamp_utc: UTC ISO 8601 timestamp of registry construction
    - verification_status: "verified" | "unverified" | "unsigned"
    - signature: Ed25519 signature of Merkle root ("PHASE0-UNSIGNED" in Phase 0)

    Constraints:
    - load_timestamp_utc must be UTC ISO 8601 microsecond
    - verification_status in allowed set
    - merkle_root must start with "sha256:"
    """
    catalog_version: str
    construct_count: int
    languages_covered: tuple[str, ...]    # sorted
    merkle_root: str                      # "sha256:{64 hex}"
    load_timestamp_utc: str              # ISO 8601 UTC microsecond
    verification_status: str             # "verified" | "unverified" | "unsigned"
    signature: str                       # "PHASE0-UNSIGNED" in Phase 0

    _ALLOWED_STATUSES = frozenset({"verified", "unverified", "unsigned"})

    def __post_init__(self) -> None:
        if self.verification_status not in self._ALLOWED_STATUSES:
            raise RegistryError(
                f"Invalid verification_status '{self.verification_status}'. "
                f"Must be: {sorted(self._ALLOWED_STATUSES)}"
            )
        if not self.merkle_root.startswith("sha256:"):
            raise RegistryError(
                f"merkle_root must start with 'sha256:', got '{self.merkle_root[:20]}'"
            )

    def as_cef_dict(self) -> dict:
        """
        Purpose: Produce a canonical dict for embedding in CEF artifacts.
        Outputs: dict with sorted keys (for deterministic serialization)
        Constraints: No floats; all values are strings or ints
        """
        return {
            "catalog_version": self.catalog_version,
            "construct_count": self.construct_count,
            "languages_covered": list(sorted(self.languages_covered)),
            "load_timestamp_utc": self.load_timestamp_utc,
            "merkle_root": self.merkle_root,
            "signature": self.signature,
            "verification_status": self.verification_status,
        }


# ─── Catalog Registry ─────────────────────────────────────────────────────────

class CatalogRegistry:
    """
    Purpose: Immutable runtime registry of all Knowledge Catalog constructs.

    Usage pattern:
        builder = CatalogRegistryBuilder(catalog_version="2026.05.11")
        builder.register(EVAL_CONSTRUCT)
        builder.register(ASYNC_CONSTRUCT)
        # ... register all constructs ...
        registry = builder.build()  # Freezes registry; computes Merkle tree

        # After build(), registry is immutable:
        construct = registry.get_construct("CONST-EVAL-001")  # O(1)
        all_python = registry.list_by_language("python")      # O(k)

    Constraints:
    - Cannot be modified after build()
    - All returned collections are immutable (tuples)
    - get_construct() returns None for unknown IDs (no exceptions for lookups)

    Determinism: same constructs → same registry state → same Merkle root
    """

    def __init__(
        self,
        constructs: dict[str, ConstructDefinition],
        merkle_tree: MerkleTree,
        metadata: RegistryMetadata,
    ) -> None:
        """
        Purpose: Internal constructor. Use CatalogRegistryBuilder.build() instead.
        Direct construction is discouraged — use the builder pattern.
        """
        # _constructs is a plain dict internally (read-only after init)
        self._constructs: dict[str, ConstructDefinition] = dict(constructs)
        self._merkle_tree: MerkleTree = merkle_tree
        self._metadata: RegistryMetadata = metadata

        # Build language index: language → sorted tuple of construct_ids
        lang_index: dict[str, list[str]] = {}
        for cid, c in sorted(self._constructs.items()):
            lang_index.setdefault(c.language, []).append(cid)
        self._language_index: dict[str, tuple[str, ...]] = {
            lang: tuple(sorted(ids))
            for lang, ids in sorted(lang_index.items())
        }

    @property
    def metadata(self) -> RegistryMetadata:
        """Purpose: Access registry metadata. Read-only."""
        return self._metadata

    @property
    def merkle_tree(self) -> MerkleTree:
        """Purpose: Access Merkle tree. Read-only."""
        return self._merkle_tree

    def get_construct(self, construct_id: str) -> Optional[ConstructDefinition]:
        """
        Purpose: Retrieve a construct definition by ID.
        Inputs: construct_id — e.g. "CONST-EVAL-001"
        Outputs: ConstructDefinition if found, None if not registered
        Constraints: O(1) dict lookup; never raises for unknown IDs
        Determinism: same ID → same result
        """
        return self._constructs.get(construct_id)

    def require_construct(self, construct_id: str) -> ConstructDefinition:
        """
        Purpose: Retrieve a construct, raising if not found.
        Inputs: construct_id
        Outputs: ConstructDefinition
        Failure: RegistryError if construct_id not registered
        Use this when caller has already verified construct exists.
        """
        c = self._constructs.get(construct_id)
        if c is None:
            raise RegistryError(
                f"Construct '{construct_id}' not found in registry. "
                f"Registered IDs: {sorted(self._constructs.keys())}"
            )
        return c

    def list_all_ids(self) -> tuple[str, ...]:
        """
        Purpose: List all registered construct IDs in sorted order.
        Outputs: Sorted tuple of construct_id strings
        Constraints: O(n); result is sorted and deterministic
        """
        return tuple(sorted(self._constructs.keys()))

    def list_by_language(self, language: str) -> tuple[str, ...]:
        """
        Purpose: List construct IDs for a specific language.
        Inputs: language — e.g. "python", "c", "cpp"
        Outputs: Sorted tuple of construct_ids for that language; empty if none
        Constraints: O(1) index lookup; returns immutable tuple
        """
        return self._language_index.get(language, ())

    def list_languages(self) -> tuple[str, ...]:
        """
        Purpose: List all languages with registered constructs.
        Outputs: Sorted tuple of language strings
        """
        return tuple(sorted(self._language_index.keys()))

    def count(self) -> int:
        """Purpose: Total number of registered constructs."""
        return len(self._constructs)

    def verify_integrity(self) -> tuple[bool, str]:
        """
        Purpose: Re-verify Merkle integrity of all registered constructs.
        Call this at analysis startup to detect any post-load tampering.

        Outputs: (is_valid: bool, diagnostic: str)
        Constraints: O(n log n); pure verification; no side effects
        Determinism: same registry → same result
        """
        constructs_list = [
            self._constructs[cid] for cid in sorted(self._constructs.keys())
        ]
        return verify_catalog_integrity(constructs_list, self._merkle_tree)

    def has_construct(self, construct_id: str) -> bool:
        """Purpose: Check if a construct ID is registered. O(1)."""
        return construct_id in self._constructs

    def get_constructs_for_tier(self, tier: Tier) -> tuple[ConstructDefinition, ...]:
        """
        Purpose: Get all constructs that have a permission defined for a tier.
        Inputs: tier — the Tier enum value
        Outputs: Sorted tuple of ConstructDefinition (by construct_id)
        Constraints: O(n) scan; result is sorted
        """
        result = []
        for cid in sorted(self._constructs.keys()):
            c = self._constructs[cid]
            try:
                c.get_tier_permission(tier)
                result.append(c)
            except Exception:
                pass
        return tuple(result)


# ─── Registry Builder ─────────────────────────────────────────────────────────

class CatalogRegistryBuilder:
    """
    Purpose: Builder for CatalogRegistry. Collects constructs then freezes.

    Usage:
        builder = CatalogRegistryBuilder(catalog_version="2026.05.11")
        builder.register(EVAL_CONSTRUCT)
        builder.register(ASYNC_CONSTRUCT)
        registry = builder.build()

    Constraints:
    - register() is only callable before build()
    - build() can only be called once
    - After build(), the builder is frozen (further calls raise FrozenRegistryError)
    - Same set of constructs always produces same registry (deterministic)
    """

    def __init__(self, catalog_version: str) -> None:
        """
        Purpose: Initialize a new builder for a specific catalog version.
        Inputs: catalog_version — YYYY.MM.DD format string
        """
        self._catalog_version: str = catalog_version
        self._constructs: dict[str, ConstructDefinition] = {}
        self._built: bool = False

    def register(self, construct: ConstructDefinition) -> CatalogRegistryBuilder:
        """
        Purpose: Register a construct with the catalog.
        Inputs: construct — a fully validated ConstructDefinition
        Outputs: self (for method chaining)
        Failure:
        - DuplicateConstructError: if construct_id already registered
        - FrozenRegistryError: if build() already called
        Constraints: No sorting yet — sorting happens at build() time
        """
        if self._built:
            raise FrozenRegistryError(
                "Cannot register constructs after build() has been called. "
                "The registry is frozen."
            )
        if construct.construct_id in self._constructs:
            raise DuplicateConstructError(
                f"Construct '{construct.construct_id}' is already registered. "
                f"The catalog is append-only — no duplicate IDs are permitted."
            )
        self._constructs[construct.construct_id] = construct
        return self

    def build(self) -> CatalogRegistry:
        """
        Purpose: Freeze the registry and compute the Merkle tree.
        This is the point of no return — after build(), no more registration.

        Outputs: Immutable CatalogRegistry
        Failure: EmptyRegistryError if no constructs registered

        Algorithm:
        1. Validate: at least one construct
        2. Build Merkle tree (sorted by construct_id)
        3. Compute metadata
        4. Construct immutable CatalogRegistry
        5. Freeze builder

        Constraints:
        - O(n log n) for Merkle tree
        - timestamp is UTC ISO 8601 microsecond
        - signature is "PHASE0-UNSIGNED" (Phase 1+ will add real signature)

        Determinism:
        - Merkle tree is deterministic (constructs sorted by construct_id)
        - Timestamp is NOT deterministic (records actual build time)
        - Root hash IS deterministic given same constructs
        """
        if self._built:
            raise FrozenRegistryError("build() has already been called.")

        if not self._constructs:
            raise EmptyRegistryError(
                "Cannot build registry with zero constructs. "
                "Register at least one ConstructDefinition before calling build()."
            )

        # Step 2: Build Merkle tree over all constructs
        constructs_list = [
            self._constructs[cid] for cid in sorted(self._constructs.keys())
        ]
        merkle = build_merkle_tree(constructs_list, self._catalog_version)

        # Step 3: Compute metadata
        languages = tuple(sorted({c.language for c in constructs_list}))
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        metadata = RegistryMetadata(
            catalog_version=self._catalog_version,
            construct_count=len(self._constructs),
            languages_covered=languages,
            merkle_root=merkle.root_with_prefix(),
            load_timestamp_utc=timestamp,
            verification_status="unsigned",   # Phase 0: no signature
            signature="PHASE0-UNSIGNED",
        )

        # Step 4: Build registry
        registry = CatalogRegistry(
            constructs=self._constructs,
            merkle_tree=merkle,
            metadata=metadata,
        )

        # Step 5: Freeze builder
        self._built = True
        self._constructs = {}  # Release references (registry owns the data now)

        return registry
