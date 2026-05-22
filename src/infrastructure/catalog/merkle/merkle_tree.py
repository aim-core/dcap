"""
******************************************************************************
 * FILE:        /src/infrastructure/catalog/merkle/merkle_tree.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Catalog Merkle Tree
 * PURPOSE:     Deterministic Merkle tree for catalog integrity verification
 * DOMAIN:      Knowledge Catalog Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Implements a deterministic Merkle tree over the Knowledge Catalog.
 * Every construct definition is a leaf node. The Merkle root summarizes
 * the entire catalog in a single SHA-256 hash. Any modification to any
 * construct — even one byte — changes the root.
 *
 * This is the tamper-detection foundation for the catalog integrity system.
 * In Phase 0 the root is stored unsigned. In Phase 1+ it is signed with
 * Ed25519 by the catalog authority.
 *
 * TREE STRUCTURE:
 *   Leaves  : SHA-256(canonical_json(construct_definition))
 *   Internal: SHA-256("NODE:" + left_hash + right_hash)
 *   Padding : If leaf count is odd, last leaf is doubled (standard Merkle)
 *   Ordering: Leaves sorted by construct_id (deterministic)
 *
 * REFERENCES:
 *   Merkle, R. (1987). "A Digital Signature Based on a Conventional
 *   Encryption Function." CRYPTO 1987. DOI:10.1007/3-540-48184-2_32
 *
 *   Bitcoin Developer Guide — Merkle Trees:
 *   https://developer.bitcoin.org/devguide/block_chain.html#merkle-trees
 *   (used as standard reference for padding convention)
 *
 * DEPENDENCIES:
 * - src/domain/constructs/construct_model.py (ConstructDefinition)
 *
 * CONSTRAINTS:
 * - Deterministic: same catalog → same root (byte-identical)
 * - No external dependencies (hashlib only)
 * - Bounded: O(n log n) time, O(n) space
 * - No float arithmetic
 *
 * DETERMINISM GUARANTEES:
 * - Leaves sorted by construct_id before tree construction
 * - Hash function: SHA-256 only (no MD5, no SHA-1)
 * - Node hash prefix: "NODE:" prevents length-extension attacks
 * - Leaf hash prefix: "LEAF:" distinguishes leaves from nodes
 *
 * FAILURE MODES:
 * - EmptyCatalogError: cannot build tree with zero constructs
 * - MerkleVerificationError: root mismatch during verification
 *
 * SECURITY CONSIDERATIONS:
 * - Prefix separation prevents second-preimage attacks
 * - Deterministic ordering prevents ordering attacks
 * - In Phase 1+, root is signed; unsigned root is advisory only
 *
 * COMPLEXITY: O(n) leaves → O(n) tree nodes → O(n log n) total hashing
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from src.domain.constructs.construct_model import ConstructDefinition


# ─── Domain Errors ────────────────────────────────────────────────────────────

class MerkleError(Exception):
    """Base class for Merkle tree errors."""


class EmptyCatalogError(MerkleError):
    """
    Purpose: Raised when attempting to build a Merkle tree over zero constructs.
    A catalog with zero constructs is a configuration error, not a valid state.
    """


class MerkleVerificationError(MerkleError):
    """
    Purpose: Raised when Merkle root verification fails.
    Indicates catalog tampering or version mismatch.
    """


# ─── Merkle Node ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MerkleNode:
    """
    Purpose: A single node in the Merkle tree.

    Inputs:
    - hash_value: SHA-256 hex digest of this node's content
    - left_child_hash: Hash of left child (empty string for leaves)
    - right_child_hash: Hash of right child (empty string for leaves)
    - is_leaf: True if this node is a leaf (represents a construct)
    - construct_id: The construct_id if is_leaf, empty string otherwise

    Constraints:
    - hash_value must be exactly 64 hex characters (SHA-256)
    - is_leaf XOR (left_child_hash == "" AND right_child_hash == "")
    """
    hash_value: str          # 64 hex chars (no "sha256:" prefix here — internal use)
    left_child_hash: str     # empty for leaves
    right_child_hash: str    # empty for leaves
    is_leaf: bool
    construct_id: str        # empty for internal nodes

    def __post_init__(self) -> None:
        if len(self.hash_value) != 64 or not all(c in "0123456789abcdef" for c in self.hash_value):
            raise MerkleError(f"Invalid hash_value: must be 64 lowercase hex chars")
        if self.is_leaf and (self.left_child_hash or self.right_child_hash):
            raise MerkleError("Leaf nodes must have empty child hashes")
        if not self.is_leaf and not (self.left_child_hash and self.right_child_hash):
            raise MerkleError("Internal nodes must have both child hashes")


@dataclass(frozen=True)
class MerkleTree:
    """
    Purpose: Complete Merkle tree over a set of catalog constructs.
    Immutable after construction. Used to verify catalog integrity.

    Inputs:
    - root_hash: SHA-256 hex of the Merkle root (64 chars, no prefix)
    - leaf_count: Number of leaf nodes (= number of constructs)
    - leaf_hashes: Sorted tuple of (construct_id, leaf_hash) pairs
    - tree_depth: Depth of the tree (ceil(log2(leaf_count)) + 1)
    - catalog_version: The catalog version this tree covers

    Constraints:
    - leaf_hashes sorted by construct_id (deterministic)
    - root_hash is deterministic for a given set of constructs
    """
    root_hash: str                           # 64 hex chars
    leaf_count: int
    leaf_hashes: tuple[tuple[str, str], ...]  # sorted (construct_id, leaf_hash)
    tree_depth: int
    catalog_version: str

    def root_with_prefix(self) -> str:
        """Returns root hash with 'sha256:' prefix for CEF embedding."""
        return "sha256:" + self.root_hash

    def verify_construct(self, construct_id: str, expected_hash: str) -> bool:
        """
        Purpose: Verify that a specific construct's hash matches the catalog.
        Inputs: construct_id, expected_hash (64 hex chars)
        Outputs: bool — True if hash matches, False if tampered or not found
        Constraints: O(n) scan; n = leaf_count (small for catalog)
        Determinism: pure function; same inputs → same result
        """
        for cid, h in self.leaf_hashes:
            if cid == construct_id:
                return h == expected_hash
        return False


# ─── Merkle Tree Builder ──────────────────────────────────────────────────────

def _sha256_hex(data: bytes) -> str:
    """
    Purpose: Compute SHA-256 hex digest.
    Inputs: raw bytes
    Outputs: 64-char lowercase hex string (no prefix)
    Constraints: deterministic; no side effects
    """
    return hashlib.sha256(data).hexdigest()


def _leaf_hash(construct_id: str, construct_hash: str) -> str:
    """
    Purpose: Compute deterministic leaf hash for a construct.
    Prefix "LEAF:" prevents length-extension attacks and distinguishes
    leaf hashes from internal node hashes.

    Inputs:
    - construct_id: The construct's canonical ID
    - construct_hash: The construct's catalog_hash() value (with "sha256:" prefix)
    Outputs: 64-char hex SHA-256 of prefixed content
    """
    content = f"LEAF:{construct_id}:{construct_hash}".encode("utf-8")
    return _sha256_hex(content)


def _node_hash(left: str, right: str) -> str:
    """
    Purpose: Compute deterministic internal node hash.
    Prefix "NODE:" distinguishes internal nodes from leaves.

    Inputs: left, right — 64-char hex hashes of children
    Outputs: 64-char hex SHA-256 of prefixed concatenation
    """
    content = f"NODE:{left}{right}".encode("utf-8")
    return _sha256_hex(content)


def build_merkle_tree(
    constructs: list[ConstructDefinition],
    catalog_version: str,
) -> MerkleTree:
    """
    Purpose: Build a deterministic Merkle tree over a set of constructs.

    Algorithm:
    1. Sort constructs by construct_id (deterministic leaf ordering)
    2. Compute leaf hash for each construct
    3. If leaf count is odd, duplicate the last leaf (standard Merkle padding)
    4. Build tree bottom-up until single root remains
    5. Return immutable MerkleTree

    Inputs:
    - constructs: List of ConstructDefinition (may be unsorted)
    - catalog_version: The catalog version string (YYYY.MM.DD)
    Outputs: MerkleTree (immutable)
    Failure: EmptyCatalogError if constructs is empty

    Constraints:
    - Constructs sorted by construct_id before hashing
    - No mutation of input constructs
    - Bounded: O(n log n) where n = len(constructs)

    Determinism: same constructs (any order) → same MerkleTree
    Security: prefix separation prevents second-preimage attacks
    """
    if not constructs:
        raise EmptyCatalogError(
            "Cannot build Merkle tree over empty catalog. "
            "At least one construct is required."
        )

    # Step 1: Sort by construct_id → deterministic leaf ordering
    sorted_constructs = sorted(constructs, key=lambda c: c.construct_id)

    # Step 2: Compute leaf hashes
    # catalog_hash() returns "sha256:{hex}" — we use it as-is in the leaf
    leaf_data: list[tuple[str, str]] = []  # (construct_id, leaf_hash_64)
    for c in sorted_constructs:
        catalog_h = c.catalog_hash()  # "sha256:{64 hex}"
        lh = _leaf_hash(c.construct_id, catalog_h)
        leaf_data.append((c.construct_id, lh))

    # Step 3: Build working level (list of hashes at current level)
    current_level: list[str] = [h for _, h in leaf_data]

    # Record depth
    depth = 1

    # Step 4: Build tree bottom-up
    while len(current_level) > 1:
        next_level: list[str] = []
        i = 0
        while i < len(current_level):
            left = current_level[i]
            # Merkle padding: if odd count, duplicate last node
            right = current_level[i + 1] if (i + 1) < len(current_level) else left
            next_level.append(_node_hash(left, right))
            i += 2
        current_level = next_level
        depth += 1

    root = current_level[0]

    return MerkleTree(
        root_hash=root,
        leaf_count=len(sorted_constructs),
        leaf_hashes=tuple(leaf_data),
        tree_depth=depth,
        catalog_version=catalog_version,
    )


def verify_catalog_integrity(
    constructs: list[ConstructDefinition],
    expected_tree: MerkleTree,
) -> tuple[bool, str]:
    """
    Purpose: Verify that a set of constructs matches an expected Merkle tree.
    Used at catalog load time to detect tampering or version mismatch.

    Inputs:
    - constructs: The constructs to verify
    - expected_tree: The expected MerkleTree (from trusted source)
    Outputs: (is_valid: bool, diagnostic: str)
    - is_valid=True: catalog matches expected tree
    - is_valid=False: catalog has been tampered with or mismatched

    Constraints:
    - No side effects; pure verification function
    - Raises MerkleVerificationError only for structural errors
    Determinism: same inputs → same result
    """
    if not constructs:
        return (False, "Catalog is empty — cannot verify against non-empty tree")

    try:
        actual_tree = build_merkle_tree(constructs, expected_tree.catalog_version)
    except EmptyCatalogError as e:
        return (False, str(e))

    if actual_tree.root_hash != expected_tree.root_hash:
        return (
            False,
            f"Merkle root mismatch. "
            f"Expected: {expected_tree.root_hash[:16]}... "
            f"Got: {actual_tree.root_hash[:16]}... "
            f"Catalog has been modified or is the wrong version."
        )

    if actual_tree.leaf_count != expected_tree.leaf_count:
        return (
            False,
            f"Leaf count mismatch. "
            f"Expected {expected_tree.leaf_count} constructs, "
            f"got {actual_tree.leaf_count}."
        )

    return (True, f"Catalog verified: root={actual_tree.root_hash[:16]}... leaves={actual_tree.leaf_count}")
