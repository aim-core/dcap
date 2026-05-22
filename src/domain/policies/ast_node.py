"""
******************************************************************************
 * FILE:        /src/domain/policies/ast_node.py
 * LAYER:       Domain Layer
 * MODULE:      Policy Engine — AST Node Representation
 * PURPOSE:     Canonical, immutable representation of an analyzed AST node
 * DOMAIN:      Policy Engine
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Defines the AnalyzedNode — the canonical, immutable representation of
 * a code construct instance found during AST traversal.
 *
 * An AnalyzedNode is NOT the raw AST node from Python's ast module.
 * It is a domain object that captures:
 *   - WHERE the construct was found (canonical location)
 *   - WHAT construct type it is (construct_id from catalog)
 *   - WHAT state it is in (detected_state)
 *   - WHAT dataflow evidence surrounds it (argument sources, call depth)
 *   - WHAT context it is called in (enclosing function type, etc.)
 *
 * The policy engine receives AnalyzedNode and produces Evidence.
 * The parser (Phase 5) produces AnalyzedNode from raw source.
 * In Phase 4 (this phase), AnalyzedNode is constructed synthetically
 * for policy evaluation testing.
 *
 * DEPENDENCIES: src/domain/constructs/construct_model.py
 * CONSTRAINTS:  Frozen dataclass; no mutation after construction
 * DETERMINISM:  node_hash is SHA-256 of canonical fields
 * LICENSE:      Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Optional

from src.domain.evidence.evidence_model import validate_canonical_location


# ─── Errors ───────────────────────────────────────────────────────────────────

class NodeError(Exception):
    """Base error for AnalyzedNode construction."""


# ─── Node Call Context ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class NodeCallContext:
    """
    Purpose: Describes the call context surrounding an AnalyzedNode.
    This is the structural information the policy engine uses to determine
    escalation (e.g., eval() inside a web handler is worse than in a script).

    Inputs:
    - enclosing_function_name: Name of the innermost enclosing function ("" = module level)
    - enclosing_class_name: Name of the enclosing class ("" = not in class)
    - is_in_async_function: True if the enclosing function is async
    - is_in_test_function: True if enclosing function name starts with test_
    - call_depth_from_entry: Approximate call depth from module entry point (integer)
    - argument_sources: Sorted tuple of argument source classifications
      e.g. ("LITERAL_CONSTANT", "USER_INPUT_TAINTED", "EXTERNAL_API_RETURN")

    Constraints:
    - call_depth_from_entry >= 0
    - argument_sources sorted for determinism
    """
    enclosing_function_name: str
    enclosing_class_name: str
    is_in_async_function: bool
    is_in_test_function: bool
    call_depth_from_entry: int
    argument_sources: tuple[str, ...]   # sorted

    _VALID_ARG_SOURCES = frozenset({
        "LITERAL_CONSTANT",
        "LOCAL_VARIABLE",
        "FUNCTION_PARAMETER",
        "EXTERNAL_API_RETURN",
        "FILE_READ",
        "NETWORK_INPUT",
        "USER_INPUT_TAINTED",
        "DATABASE_QUERY_RESULT",
        "ENVIRONMENT_VARIABLE",
        "UNKNOWN",
        "ANALYSIS_BOUNDARY",
    })

    def __post_init__(self) -> None:
        if self.call_depth_from_entry < 0:
            raise NodeError(f"call_depth_from_entry must be >= 0, got {self.call_depth_from_entry}")
        for src in self.argument_sources:
            if src not in self._VALID_ARG_SOURCES:
                raise NodeError(
                    f"Invalid argument_source '{src}'. "
                    f"Must be one of: {sorted(self._VALID_ARG_SOURCES)}"
                )

    def has_tainted_input(self) -> bool:
        """Returns True if any argument source is tainted (user/network/env input)."""
        tainted = frozenset({"USER_INPUT_TAINTED", "NETWORK_INPUT", "EXTERNAL_API_RETURN",
                             "DATABASE_QUERY_RESULT", "ENVIRONMENT_VARIABLE"})
        return bool(set(self.argument_sources) & tainted)

    def is_boundary_reached(self) -> bool:
        """Returns True if dataflow analysis reached a boundary."""
        return "ANALYSIS_BOUNDARY" in self.argument_sources


# ─── Analyzed Node ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AnalyzedNode:
    """
    Purpose: Canonical, immutable representation of an analyzed code construct.
    This is the PRIMARY INPUT to the policy engine.

    The policy engine is a pure function:
        evaluate(node: AnalyzedNode, context: ContextFingerprint,
                 tier: Tier, catalog: CatalogRegistry) → list[PolicyDecision]

    Inputs:
    - canonical_location: "absolute_path:line:col"
    - construct_id: e.g. "CONST-EVAL-001"
    - ast_node_type: e.g. "Call", "AsyncFunctionDef"
    - detected_state: The state detected by the parser (e.g. "dynamic_arg")
    - call_context: NodeCallContext with surrounding call information
    - source_line: The actual source line text (for explainability)
    - node_hash: SHA-256 of canonical fields (for evidence chain)

    Constraints:
    - canonical_location must pass validate_canonical_location
    - construct_id must match CONST-{DOMAIN}-{NNN}
    - detected_state must be non-empty
    - node_hash: "sha256:{64 hex}"
    - source_line: NFC-normalized, max 500 chars (truncated)

    Determinism: node_hash is deterministic for same field values
    """
    canonical_location: str
    construct_id: str
    ast_node_type: str
    detected_state: str
    call_context: NodeCallContext
    source_line: str        # the actual source line (for reporting)
    node_hash: str          # sha256:... of canonical fields

    _CONSTRUCT_ID_RE = re.compile(r'^CONST-[A-Z]{2,8}-\d{3}$')

    def __post_init__(self) -> None:
        validate_canonical_location(self.canonical_location)
        if not self._CONSTRUCT_ID_RE.match(self.construct_id):
            raise NodeError(f"Invalid construct_id format: '{self.construct_id}'")
        if not self.detected_state.strip():
            raise NodeError("detected_state cannot be empty")
        if not re.match(r'^sha256:[0-9a-f]{64}$', self.node_hash):
            raise NodeError(f"node_hash must be 'sha256:{{64 hex}}', got '{self.node_hash[:20]}'")

    @staticmethod
    def compute_hash(
        canonical_location: str,
        construct_id: str,
        detected_state: str,
    ) -> str:
        """
        Purpose: Compute the canonical node hash.
        Inputs: Three primary identifying fields
        Outputs: "sha256:{64 hex}"
        Determinism: byte-identical for same inputs
        """
        canonical = json.dumps(
            {"loc": canonical_location, "cid": construct_id, "state": detected_state},
            sort_keys=True, separators=(',', ':'), ensure_ascii=False,
        ).encode('utf-8')
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    @classmethod
    def create(
        cls,
        canonical_location: str,
        construct_id: str,
        ast_node_type: str,
        detected_state: str,
        call_context: NodeCallContext,
        source_line: str,
    ) -> AnalyzedNode:
        """
        Purpose: Factory method — creates AnalyzedNode with auto-computed hash.
        Inputs: All fields except node_hash (computed automatically)
        Outputs: AnalyzedNode with valid node_hash
        """
        import unicodedata
        safe_line = unicodedata.normalize("NFC", source_line[:500])
        node_hash = cls.compute_hash(canonical_location, construct_id, detected_state)
        return cls(
            canonical_location=canonical_location,
            construct_id=construct_id,
            ast_node_type=ast_node_type,
            detected_state=detected_state,
            call_context=call_context,
            source_line=safe_line,
            node_hash=node_hash,
        )
