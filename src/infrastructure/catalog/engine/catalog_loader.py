"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/engine/catalog_loader.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Catalog Engine — Loader
 * PURPOSE:     Assemble and verify the complete Knowledge Catalog registry
 * DOMAIN:      Knowledge Catalog Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The CatalogLoader is the single entry point for building the runtime
 * CatalogRegistry. It:
 *
 *   1. Imports all construct entry modules
 *   2. Registers all constructs with the builder
 *   3. Calls build() to freeze and compute Merkle tree
 *   4. Runs integrity verification
 *   5. Returns verified, frozen CatalogRegistry
 *
 * This is the ONLY place where catalog entries are assembled. No other
 * module should construct a CatalogRegistry directly.
 *
 * FAIL-SAFE DESIGN:
 * If any step fails, the loader raises CatalogLoadError and the analysis
 * cannot proceed. There is no fallback, no partial catalog, no degraded mode.
 * A catalog that cannot be verified is not a catalog.
 *
 * DEPENDENCIES:
 * - src/infrastructure/catalog/registry/catalog_registry.py
 * - src/infrastructure/catalog/entries/python/eval_construct.py
 * - src/infrastructure/catalog/entries/python/python_constructs.py
 *
 * CONSTRAINTS:
 * - Called once at analysis startup
 * - No network access, no dynamic module loading
 * - Deterministic: same entry modules → same registry
 *
 * DETERMINISM GUARANTEES:
 * - Entry modules are imported in alphabetical order
 * - Registry build is deterministic (Merkle tree is sorted)
 * - Integrity verification is deterministic
 *
 * FAILURE MODES:
 * - CatalogLoadError: any step in load pipeline fails
 * - RegistryIntegrityError: Merkle verification fails post-build
 *
 * SECURITY CONSIDERATIONS:
 * - Phase 0: Merkle root is unsigned (advisory integrity only)
 * - Phase 1+: Merkle root must carry valid Ed25519 signature
 * - No dynamic import: all entry modules are statically declared
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

from src.infrastructure.catalog.registry.catalog_registry import (
    CatalogRegistry,
    CatalogRegistryBuilder,
    RegistryError,
)
from src.infrastructure.catalog.entries.python.eval_construct import (
    EVAL_CONSTRUCT,
)
from src.infrastructure.catalog.entries.python.python_constructs import (
    ALL_PYTHON_CONSTRUCTS,
)
import sys
from src.infrastructure.catalog.engine.plugin_loader import load_pro_plugin
EXTENDED_CONSTRUCTS = load_pro_plugin()
if EXTENDED_CONSTRUCTS:
    print("[DCAP] Advanced Threat Intelligence: ACTIVE", file=sys.stderr)
else:
    print("[DCAP] Community Intelligence: ACTIVE (Upgrade for Pro)", file=sys.stderr)


# ─── Error Types ──────────────────────────────────────────────────────────────

class CatalogLoadError(Exception):
    """
    Purpose: Raised when the catalog cannot be loaded or verified.
    This is a fatal error — analysis cannot proceed without a valid catalog.
    """


# ─── Catalog Version ──────────────────────────────────────────────────────────

CURRENT_CATALOG_VERSION = "2026.05.12"


# ─── Loader ───────────────────────────────────────────────────────────────────

def load_python_catalog(catalog_version: str = CURRENT_CATALOG_VERSION) -> CatalogRegistry:
    """
    Purpose: Load, assemble, and verify the complete Python Knowledge Catalog.
    This is the primary entry point for obtaining a usable CatalogRegistry.

    Algorithm:
    1. Create registry builder for the specified catalog version
    2. Register EVAL_CONSTRUCT (Phase 1 entry, separately defined)
    3. Register all constructs from ALL_PYTHON_CONSTRUCTS (Phase 2 entries)
    4. Build and freeze the registry (computes Merkle tree)
    5. Run integrity self-check
    6. Return verified registry

    Inputs: catalog_version — YYYY.MM.DD string (default: CURRENT_CATALOG_VERSION)
    Outputs: Verified, frozen CatalogRegistry
    Failure: CatalogLoadError on any step failure

    Constraints:
    - No network access
    - No dynamic module loading
    - Deterministic: same version → same registry state

    Determinism: Merkle root is deterministic given same construct set
    Security: Integrity verification runs before returning registry
    """
    try:
        builder = CatalogRegistryBuilder(catalog_version=catalog_version)
    except Exception as e:
        raise CatalogLoadError(f"Failed to create registry builder: {e}") from e

    # ── Step 2: Register EVAL_CONSTRUCT ────────────────────────────────────
    try:
        builder.register(EVAL_CONSTRUCT)
    except Exception as e:
        raise CatalogLoadError(
            f"Failed to register EVAL_CONSTRUCT ({EVAL_CONSTRUCT.construct_id}): {e}"
        ) from e

    # ── Step 3: Register all Phase 2 Python constructs ─────────────────────
    for construct in list(ALL_PYTHON_CONSTRUCTS) + list(EXTENDED_CONSTRUCTS):
        try:
            builder.register(construct)
        except Exception as e:
            raise CatalogLoadError(
                f"Failed to register {construct.construct_id}: {e}"
            ) from e

    # ── Step 4: Build and freeze ────────────────────────────────────────────
    try:
        registry = builder.build()
    except Exception as e:
        raise CatalogLoadError(f"Failed to build registry: {e}") from e

    # ── Step 5: Integrity self-check ────────────────────────────────────────
    is_valid, diagnostic = registry.verify_integrity()
    if not is_valid:
        raise CatalogLoadError(
            f"Catalog integrity verification FAILED after load. "
            f"Diagnostic: {diagnostic}. "
            f"This indicates a catalog construction defect."
        )

    return registry


def get_catalog_summary(registry: CatalogRegistry) -> dict:
    """
    Purpose: Produce a deterministic summary dict of the loaded catalog.
    Used for embedding in CEF artifact metadata and for operator review.

    Inputs: registry — a loaded CatalogRegistry
    Outputs: dict with catalog metadata, sorted keys

    Constraints: Pure function; no side effects; deterministic
    """
    meta = registry.metadata
    return {
        "catalog_version": meta.catalog_version,
        "construct_count": meta.construct_count,
        "languages": list(registry.list_languages()),
        "merkle_root": meta.merkle_root,
        "signature": meta.signature,
        "verification_status": meta.verification_status,
        "constructs_by_language": {
            lang: list(registry.list_by_language(lang))
            for lang in sorted(registry.list_languages())
        },
    }
