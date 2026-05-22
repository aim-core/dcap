"""
******************************************************************************
 * FILE:        /src/adapters/parsers/shared/dataflow.py
 * LAYER:       Adapters Layer
 * MODULE:      Parser — Bounded Dataflow Analyzer
 * PURPOSE:     Trace argument sources within bounded call depth
 * DOMAIN:      Static Analysis
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Implements bounded dataflow analysis for Python AST nodes.
 * Given an AST node argument, traces back to its ultimate source
 * (literal constant, function parameter, external input, etc.)
 * within a fixed call depth limit.
 *
 * This is NOT full symbolic execution. It is a bounded, conservative
 * approximation that reports ANALYSIS_BOUNDARY when it cannot resolve.
 *
 * DATAFLOW RESOLUTION RULES (applied in order):
 *   1. ast.Constant → LITERAL_CONSTANT
 *   2. ast.Name where id in function parameters → FUNCTION_PARAMETER
 *   3. ast.Call where func resolves to known taint source → (taint source)
 *   4. ast.Attribute access on known taint objects → (parent taint)
 *   5. ast.Name where assigned from taint source in scope → (taint source)
 *   6. Depth limit reached → ANALYSIS_BOUNDARY
 *   7. Unresolvable → UNKNOWN
 *
 * TAINT SOURCES (patterns that indicate external/user-controlled data):
 *   request.*, req.*, form.*, data.*, body.* → USER_INPUT_TAINTED
 *   socket.recv, response.read, urllib.*     → NETWORK_INPUT
 *   os.environ, sys.argv                     → ENVIRONMENT_VARIABLE
 *   open(...).read(), file.*                 → FILE_READ
 *   cursor.fetchone, session.query           → DATABASE_QUERY_RESULT
 *   requests.get, httpx.get, aiohttp.*       → EXTERNAL_API_RETURN
 *
 * CONSTRAINTS:
 *   - Max resolution depth: configurable, default 5 (from AnalysisBounds)
 *   - No cross-file dataflow in Phase 5 (bounded to single module)
 *   - No loop unrolling
 *   - Conservative: when uncertain → UNKNOWN or ANALYSIS_BOUNDARY
 *
 * DETERMINISM GUARANTEES:
 *   - Same AST → same result (no random, no time)
 *   - Results are frozensets of string constants
 *   - Processing order is deterministic (sorted)
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional


# ─── Taint Patterns ───────────────────────────────────────────────────────────

# (attribute_prefix_or_exact, argument_source_tag)
# Applied in order; first match wins
_ATTRIBUTE_TAINT_PATTERNS: tuple[tuple[str, str], ...] = (
    # Web request objects
    ("request.",        "USER_INPUT_TAINTED"),
    ("req.",            "USER_INPUT_TAINTED"),
    ("form.",           "USER_INPUT_TAINTED"),
    ("args.",           "USER_INPUT_TAINTED"),
    ("kwargs.",         "USER_INPUT_TAINTED"),
    ("data.",           "USER_INPUT_TAINTED"),
    ("body.",           "USER_INPUT_TAINTED"),
    ("payload.",        "USER_INPUT_TAINTED"),
    ("params.",         "USER_INPUT_TAINTED"),
    ("POST.",           "USER_INPUT_TAINTED"),
    ("GET.",            "USER_INPUT_TAINTED"),
    # Network I/O
    ("socket.",         "NETWORK_INPUT"),
    ("response.",       "NETWORK_INPUT"),
    ("recv.",           "NETWORK_INPUT"),
    # Environment
    ("os.environ",      "ENVIRONMENT_VARIABLE"),
    ("environ.",        "ENVIRONMENT_VARIABLE"),
    ("sys.argv",        "ENVIRONMENT_VARIABLE"),
    # File I/O
    ("file.",           "FILE_READ"),
    (".read(",          "FILE_READ"),
    (".readline(",      "FILE_READ"),
    (".readlines(",     "FILE_READ"),
    # Database
    ("cursor.",         "DATABASE_QUERY_RESULT"),
    ("session.",        "DATABASE_QUERY_RESULT"),
    ("queryset.",       "DATABASE_QUERY_RESULT"),
    (".fetchone(",      "DATABASE_QUERY_RESULT"),
    (".fetchall(",      "DATABASE_QUERY_RESULT"),
    (".first(",         "DATABASE_QUERY_RESULT"),
    (".filter(",        "DATABASE_QUERY_RESULT"),
    # External APIs
    ("requests.",       "EXTERNAL_API_RETURN"),
    ("httpx.",          "EXTERNAL_API_RETURN"),
    ("aiohttp.",        "EXTERNAL_API_RETURN"),
    ("urllib.",         "EXTERNAL_API_RETURN"),
    ("boto3.",          "EXTERNAL_API_RETURN"),
)

# Function names that indicate tainted return values
_FUNC_TAINT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("input",           "USER_INPUT_TAINTED"),
    ("raw_input",       "USER_INPUT_TAINTED"),
    ("getpass",         "USER_INPUT_TAINTED"),
    ("recv",            "NETWORK_INPUT"),
    ("read",            "FILE_READ"),
    ("readline",        "FILE_READ"),
    ("getenv",          "ENVIRONMENT_VARIABLE"),
    ("get_secret",      "ENVIRONMENT_VARIABLE"),
)


# ─── Dataflow Result ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DataflowResult:
    """
    Purpose: Result of bounded dataflow analysis for one argument.

    Inputs:
    - sources: Frozenset of argument source tags (from NodeCallContext vocabulary)
    - depth_reached: Maximum depth traversed during analysis
    - boundary_reached: True if analysis stopped due to depth limit
    - resolution_path: Ordered tuple of resolution steps (for explainability)
    """
    sources: frozenset[str]
    depth_reached: int
    boundary_reached: bool
    resolution_path: tuple[str, ...]


def _unparse_node(node: ast.AST) -> str:
    """
    Purpose: Convert an AST node to a canonical string for pattern matching.
    Uses ast.unparse (Python 3.9+) or a fallback for older versions.
    """
    try:
        return ast.unparse(node)
    except AttributeError:
        # Fallback: dump the node type and key fields
        return type(node).__name__


def _match_taint_patterns(text: str) -> Optional[str]:
    """
    Purpose: Check if a text matches any known taint pattern.
    Inputs: text — unparsed AST node string
    Outputs: argument source tag string, or None if no match
    Determinism: patterns applied in fixed order; first match wins
    """
    for pattern, tag in _ATTRIBUTE_TAINT_PATTERNS:
        if pattern in text:
            return tag
    return None


def analyze_argument(
    arg_node: ast.AST,
    func_params: frozenset[str],
    local_scope: dict[str, str],   # name → source_tag (from previous assignments)
    max_depth: int = 5,
    current_depth: int = 0,
) -> DataflowResult:
    """
    Purpose: Trace the source of an argument AST node within bounded depth.

    Inputs:
    - arg_node: The AST node representing the argument to analyze
    - func_params: Frozenset of parameter names of the enclosing function
    - local_scope: Dict mapping local variable names to their source tags
    - max_depth: Maximum resolution depth (from catalog AnalysisBounds)
    - current_depth: Current recursion depth (starts at 0)

    Outputs: DataflowResult (immutable)

    Rules (applied in priority order):
    1. Constant node → LITERAL_CONSTANT (certain, no recursion needed)
    2. Name node in func_params → FUNCTION_PARAMETER
    3. Name node in local_scope → use tracked source from scope
    4. Name node unknown → UNKNOWN
    5. Call node → check func name against taint patterns
    6. Attribute node → check attribute chain against taint patterns
    7. depth >= max_depth → ANALYSIS_BOUNDARY
    8. Unrecognized → UNKNOWN

    Complexity: O(max_depth) recursive calls, each O(1)
    Determinism: pure function; same inputs → same result
    """
    path: list[str] = []

    # Depth guard (RULE-DET-008 compliance)
    if current_depth >= max_depth:
        path.append(f"depth_limit_reached:{max_depth}")
        return DataflowResult(
            sources=frozenset({"ANALYSIS_BOUNDARY"}),
            depth_reached=current_depth,
            boundary_reached=True,
            resolution_path=tuple(path),
        )

    # Rule 1: Literal constant
    if isinstance(arg_node, ast.Constant):
        path.append("literal_constant")
        return DataflowResult(
            sources=frozenset({"LITERAL_CONSTANT"}),
            depth_reached=current_depth,
            boundary_reached=False,
            resolution_path=tuple(path),
        )

    # Rule 2 & 3: Name node
    if isinstance(arg_node, ast.Name):
        name = arg_node.id
        if name in func_params:
            path.append(f"function_parameter:{name}")
            return DataflowResult(
                sources=frozenset({"FUNCTION_PARAMETER"}),
                depth_reached=current_depth,
                boundary_reached=False,
                resolution_path=tuple(path),
            )
        if name in local_scope:
            tag = local_scope[name]
            path.append(f"local_var:{name}→{tag}")
            return DataflowResult(
                sources=frozenset({tag}),
                depth_reached=current_depth,
                boundary_reached=False,
                resolution_path=tuple(path),
            )
        path.append(f"unresolved_name:{name}")
        return DataflowResult(
            sources=frozenset({"UNKNOWN"}),
            depth_reached=current_depth,
            boundary_reached=False,
            resolution_path=tuple(path),
        )

    # Rule 4: Joined string (f-string) — conservative: UNKNOWN
    if isinstance(arg_node, ast.JoinedStr):
        path.append("fstring:conservative_unknown")
        return DataflowResult(
            sources=frozenset({"UNKNOWN"}),
            depth_reached=current_depth,
            boundary_reached=False,
            resolution_path=tuple(path),
        )

    # Rule 5: Call node — check function name
    if isinstance(arg_node, ast.Call):
        func_text = _unparse_node(arg_node.func)
        path.append(f"call:{func_text[:60]}")

        # Check against taint function patterns
        for pattern, tag in _FUNC_TAINT_PATTERNS:
            if func_text.endswith(pattern) or func_text == pattern:
                return DataflowResult(
                    sources=frozenset({tag}),
                    depth_reached=current_depth,
                    boundary_reached=False,
                    resolution_path=tuple(path),
                )

        # Check attribute taint patterns on the full call text
        full_text = _unparse_node(arg_node)
        taint = _match_taint_patterns(full_text)
        if taint:
            return DataflowResult(
                sources=frozenset({taint}),
                depth_reached=current_depth,
                boundary_reached=False,
                resolution_path=tuple(path),
            )

        # Unknown call — recurse into first argument if present
        if arg_node.args:
            return analyze_argument(
                arg_node.args[0], func_params, local_scope,
                max_depth, current_depth + 1,
            )

        path.append("unknown_call_no_args")
        return DataflowResult(
            sources=frozenset({"UNKNOWN"}),
            depth_reached=current_depth,
            boundary_reached=False,
            resolution_path=tuple(path),
        )

    # Rule 6: Attribute node — check taint patterns
    if isinstance(arg_node, ast.Attribute):
        full_text = _unparse_node(arg_node)
        path.append(f"attribute:{full_text[:60]}")
        taint = _match_taint_patterns(full_text)
        if taint:
            return DataflowResult(
                sources=frozenset({taint}),
                depth_reached=current_depth,
                boundary_reached=False,
                resolution_path=tuple(path),
            )
        # No match → trace the value
        return analyze_argument(
            arg_node.value, func_params, local_scope,
            max_depth, current_depth + 1,
        )

    # Rule 6b: Subscript node (e.g. os.environ['KEY'], request.args['x'])
    # Treat as equivalent to the subscripted value for taint purposes
    if isinstance(arg_node, ast.Subscript):
        full_text = _unparse_node(arg_node)
        path.append(f"subscript:{full_text[:60]}")
        taint = _match_taint_patterns(full_text)
        if taint:
            return DataflowResult(
                sources=frozenset({taint}),
                depth_reached=current_depth,
                boundary_reached=False,
                resolution_path=tuple(path),
            )
        # Trace the subscripted object (e.g. os.environ in os.environ['KEY'])
        return analyze_argument(
            arg_node.value, func_params, local_scope,
            max_depth, current_depth + 1,
        )

    # Rule 7: BinOp (concatenation) — any tainted operand taints result
    if isinstance(arg_node, ast.BinOp):
        path.append("binop:analyze_operands")
        left  = analyze_argument(arg_node.left,  func_params, local_scope, max_depth, current_depth + 1)
        right = analyze_argument(arg_node.right, func_params, local_scope, max_depth, current_depth + 1)
        combined_sources = left.sources | right.sources
        combined_path    = path + list(left.resolution_path) + list(right.resolution_path)
        boundary = left.boundary_reached or right.boundary_reached
        return DataflowResult(
            sources=combined_sources,
            depth_reached=max(left.depth_reached, right.depth_reached),
            boundary_reached=boundary,
            resolution_path=tuple(combined_path),
        )

    # Default: unrecognized node type
    node_type = type(arg_node).__name__
    path.append(f"unrecognized_node:{node_type}")
    return DataflowResult(
        sources=frozenset({"UNKNOWN"}),
        depth_reached=current_depth,
        boundary_reached=False,
        resolution_path=tuple(path),
    )


def build_local_scope(func_body: list[ast.stmt]) -> dict[str, str]:
    """
    Purpose: Build a local scope map by scanning assignment statements.
    Maps variable names to their source tags based on the RHS of assignments.

    This is a CONSERVATIVE, BOUNDED scan — only direct assignments are tracked.
    Assignments inside loops, conditionals, or nested functions are NOT tracked
    (they would require full symbolic execution).

    Inputs: func_body — list of statements in a function body
    Outputs: dict mapping variable name → source tag string
    Constraints: O(n) where n = statements; no recursion
    Determinism: deterministic iteration (list order is AST order)
    """
    scope: dict[str, str] = {}

    for stmt in func_body:
        # Handle augmented assignments (x += ...) as well
        if isinstance(stmt, ast.AugAssign):
            if stmt.value:
                rhs_text = _unparse_node(stmt.value)
                taint = _match_taint_patterns(rhs_text)
                if taint and isinstance(stmt.target, ast.Name):
                    scope[stmt.target.id] = taint
            continue

        if not isinstance(stmt, ast.Assign):
            continue
        # Analyze RHS
        if not stmt.value:
            continue
        rhs_text = _unparse_node(stmt.value)
        taint = _match_taint_patterns(rhs_text)
        if taint is None:
            continue
        # Assign taint to all LHS targets
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                scope[target.id] = taint
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        scope[elt.id] = taint

    return scope
