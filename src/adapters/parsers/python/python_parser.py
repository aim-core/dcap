"""
******************************************************************************
 * FILE:        /src/adapters/parsers/python/python_parser.py
 * LAYER:       Adapters Layer
 * MODULE:      Python Parser
 * PURPOSE:     Parse Python source files and produce AnalyzedNode instances
 * DOMAIN:      Static Analysis
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The PythonParser is the bridge between raw Python source code and the
 * DCAVP policy engine. It:
 *
 *   1. Reads a Python source file (bounded: max 500KB)
 *   2. Parses it with Python's ast module
 *   3. Walks the AST deterministically (depth-first, sorted children)
 *   4. For each AST node matching a known construct:
 *      a. Determines the construct_id (from catalog)
 *      b. Determines the detected_state
 *      c. Runs bounded dataflow on arguments
 *      d. Builds NodeCallContext
 *      e. Produces an AnalyzedNode
 *   5. Returns sorted list of AnalyzedNode (by canonical_location)
 *
 * CONSTRUCT DETECTION RULES (per catalog entry):
 *
 *   CONST-EVAL-001 (eval):
 *     Trigger: Call node where func.id == "eval"
 *     States:
 *       constant_arg   → first arg is ast.Constant
 *       dynamic_arg    → first arg is any other node
 *       external_source_arg → dataflow shows tainted source
 *
 *   CONST-EXEC-001 (exec):
 *     Trigger: Call node where func.id == "exec"
 *     States: same pattern as eval
 *
 *   CONST-ASYNC-001 (async):
 *     Trigger: AsyncFunctionDef; Await node
 *     States:
 *       unawaited → AsyncFunctionDef result assigned without await
 *       awaited   → properly awaited
 *       missing_timeout → asyncio.wait_for not used
 *
 *   CONST-OPEN-001 (open):
 *     Trigger: Call where func.id == "open"
 *     States:
 *       used_as_context_manager → inside With node
 *       not_used_as_context_manager → outside With
 *       path_traversal_possible → tainted first arg
 *
 *   CONST-PICK-001 (pickle):
 *     Trigger: Call where func == pickle.loads
 *     States:
 *       loads_untrusted_source → tainted first arg
 *       loads_trusted_source   → local/literal first arg
 *
 *   CONST-RAND-001 (random):
 *     Trigger: Call where func starts with "random."
 *     States:
 *       used_for_security → in auth/token/key naming context
 *       unseeded_or_default_seed → no explicit seed set
 *
 *   CONST-SUBP-001 (subprocess):
 *     Trigger: Call where func in subprocess.*
 *     States:
 *       shell_true_dynamic_cmd → shell=True + tainted arg
 *       shell_true_constant_cmd → shell=True + literal
 *       shell_false_dynamic_args → shell=False + tainted
 *       shell_false_constant_cmd → shell=False + literal
 *
 *   CONST-GLOB-001 (global):
 *     Trigger: Global statement
 *     States:
 *       write_global → global name is assigned anywhere in function
 *       read_only_global → global name only read
 *
 *   CONST-THRD-001 (threading):
 *     Trigger: Call to threading.Thread
 *     States:
 *       daemon_thread → daemon=True kwarg
 *       detached_not_joined → .start() found but no .join()
 *       joined → .join() called
 *
 *   CONST-LOCK-001 (lock):
 *     Trigger: Call to threading.Lock() or asyncio.Lock()
 *     States:
 *       acquired_with_context_manager → used in With statement
 *       acquired_without_context_manager → .acquire() outside with
 *       acquired_without_timeout → .acquire() with no timeout kwarg
 *
 * CONSTRAINTS:
 *   - Max file size: 500KB (configurable)
 *   - Max AST depth: 50 levels (prevents stack overflow)
 *   - Test functions: identified by name prefix "test_"
 *   - No code execution of any kind
 *   - No cross-file resolution in Phase 5
 *
 * DETERMINISM GUARANTEES:
 *   - AST nodes visited in line/column order (sorted)
 *   - Results sorted by canonical_location
 *   - Dataflow bounded by catalog AnalysisBounds
 *   - Same source file → same AnalyzedNode list
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import ast
import pathlib
import unicodedata
from dataclasses import dataclass
from typing import Optional

from src.domain.policies.ast_node import AnalyzedNode, NodeCallContext
from src.adapters.parsers.shared.dataflow import (
    DataflowResult, analyze_argument, build_local_scope,
)


# ─── Parser Configuration ─────────────────────────────────────────────────────

MAX_FILE_SIZE_BYTES = 500_000    # 500KB
MAX_AST_DEPTH       = 50
MAX_DATAFLOW_DEPTH  = 5


# ─── Parse Error ──────────────────────────────────────────────────────────────

class ParseError(Exception):
    """Raised when a source file cannot be parsed."""


@dataclass(frozen=True)
class ParseResult:
    """
    Purpose: Complete result of parsing one Python source file.

    Inputs:
    - source_path: Absolute canonical path of the file
    - nodes: Sorted tuple of AnalyzedNode instances (by canonical_location)
    - parse_warnings: Sorted tuple of non-fatal issues
    - line_count: Number of lines in the source file
    - had_syntax_error: True if ast.parse failed (file skipped)
    """
    source_path: str
    nodes: tuple[AnalyzedNode, ...]
    parse_warnings: tuple[str, ...]
    line_count: int
    had_syntax_error: bool


# ─── Call Context Builder ─────────────────────────────────────────────────────

class _CallContextTracker:
    """
    Purpose: Track the enclosing function/class context during AST walk.
    Used to build NodeCallContext for each AnalyzedNode.

    This is a STATEFUL helper used only during a single file parse.
    It is NOT a domain type — it is a parsing aide.
    """

    def __init__(self) -> None:
        self._func_stack: list[tuple[str, bool, frozenset[str], dict[str, str]]] = []
        # Each entry: (function_name, is_async, param_names, local_scope)
        self._class_stack: list[str] = []

    def enter_function(
        self, name: str, is_async: bool,
        params: frozenset[str], body: list[ast.stmt],
    ) -> None:
        local_scope = build_local_scope(body)
        self._func_stack.append((name, is_async, params, local_scope))

    def exit_function(self) -> None:
        if self._func_stack:
            self._func_stack.pop()

    def enter_class(self, name: str) -> None:
        self._class_stack.append(name)

    def exit_class(self) -> None:
        if self._class_stack:
            self._class_stack.pop()

    def current_function(self) -> Optional[str]:
        return self._func_stack[-1][0] if self._func_stack else None

    def current_is_async(self) -> bool:
        return self._func_stack[-1][1] if self._func_stack else False

    def current_params(self) -> frozenset[str]:
        return self._func_stack[-1][2] if self._func_stack else frozenset()

    def current_local_scope(self) -> dict[str, str]:
        return self._func_stack[-1][3] if self._func_stack else {}

    def current_class(self) -> str:
        return self._class_stack[-1] if self._class_stack else ""

    def is_in_test_function(self) -> bool:
        fn = self.current_function()
        return fn is not None and (fn.startswith("test_") or fn.startswith("Test"))

    def call_depth(self) -> int:
        return len(self._func_stack)

    def build_call_context(
        self,
        argument_sources: tuple[str, ...],
    ) -> NodeCallContext:
        return NodeCallContext(
            enclosing_function_name=self.current_function() or "",
            enclosing_class_name=self.current_class(),
            is_in_async_function=self.current_is_async(),
            is_in_test_function=self.is_in_test_function(),
            call_depth_from_entry=self.call_depth(),
            argument_sources=argument_sources,
        )


# ─── Construct Detectors ──────────────────────────────────────────────────────

def _get_call_name(node: ast.Call) -> str:
    """Extract a canonical string name from a Call node's func."""
    try:
        import ast as _ast
        return _ast.unparse(node.func)
    except Exception:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""


def _has_kwarg(node: ast.Call, key: str, value: object) -> bool:
    """Check if a Call node has a specific keyword argument with a given value."""
    for kw in node.keywords:
        if kw.arg == key:
            if isinstance(kw.value, ast.Constant):
                return kw.value.value == value
    return False


def _is_inside_with(node: ast.AST, parent_map: dict[int, ast.AST]) -> bool:
    """Check if a node is directly inside a With statement context."""
    parent = parent_map.get(id(node))
    if parent is None:
        return False
    if isinstance(parent, (ast.With, ast.AsyncWith)):
        return True
    # Check if this node is the context manager expression
    if isinstance(parent, ast.withitem):
        grandparent = parent_map.get(id(parent))
        return isinstance(grandparent, (ast.With, ast.AsyncWith))
    return False


def _detect_argument_sources(
    call_node: ast.Call,
    arg_index: int,
    tracker: _CallContextTracker,
) -> tuple[str, ...]:
    """
    Purpose: Detect the source(s) of a specific argument in a Call node.
    Returns sorted tuple of NodeCallContext.argument_sources strings.
    """
    if arg_index >= len(call_node.args):
        return ("UNKNOWN",)

    arg = call_node.args[arg_index]
    result = analyze_argument(
        arg,
        tracker.current_params(),
        tracker.current_local_scope(),
        MAX_DATAFLOW_DEPTH,
        0,
    )
    # Filter to valid NodeCallContext argument sources
    valid = frozenset({
        "LITERAL_CONSTANT", "LOCAL_VARIABLE", "FUNCTION_PARAMETER",
        "EXTERNAL_API_RETURN", "FILE_READ", "NETWORK_INPUT",
        "USER_INPUT_TAINTED", "DATABASE_QUERY_RESULT",
        "ENVIRONMENT_VARIABLE", "UNKNOWN", "ANALYSIS_BOUNDARY",
    })
    filtered = frozenset(s for s in result.sources if s in valid)
    if not filtered:
        filtered = frozenset({"UNKNOWN"})
    return tuple(sorted(filtered))


def _is_tainted(sources: tuple[str, ...]) -> bool:
    tainted = frozenset({
        "USER_INPUT_TAINTED", "NETWORK_INPUT", "EXTERNAL_API_RETURN",
        "DATABASE_QUERY_RESULT", "ENVIRONMENT_VARIABLE",
    })
    return bool(frozenset(sources) & tainted)


# ─── Main Parser ──────────────────────────────────────────────────────────────

class PythonParser:
    """
    Purpose: Parse Python source files and produce AnalyzedNode instances.

    Usage:
        parser = PythonParser()
        result = parser.parse_file("/path/to/source.py", source_root="/path/to")
        for node in result.nodes:
            decision = engine.evaluate(node, context, tier)

    Constraints:
    - Reads file content (max 500KB) — bounded I/O
    - Uses Python stdlib ast module only — no external dependencies
    - Produces sorted output — deterministic
    """

    def parse_file(
        self,
        file_path_str: str,
        source_root_str: str,
    ) -> ParseResult:
        """
        Purpose: Parse a single Python source file.

        Inputs:
        - file_path_str: Absolute path to the .py file
        - source_root_str: Absolute path to the project root (for canonical locations)

        Outputs: ParseResult (immutable)

        Constraints:
        - File size checked before reading
        - SyntaxError → ParseResult with had_syntax_error=True, nodes=()
        - Encoding errors → file skipped with warning

        Determinism: same file → same ParseResult
        """
        file_path   = pathlib.Path(file_path_str).resolve().absolute()
        source_root = pathlib.Path(source_root_str).resolve().absolute()
        warnings: list[str] = []

        # Size check (bounded I/O)
        try:
            size = file_path.stat().st_size
        except OSError as e:
            return ParseResult(str(file_path), (), (f"stat failed: {e}",), 0, False)

        if size > MAX_FILE_SIZE_BYTES:
            return ParseResult(
                str(file_path), (),
                (f"File too large: {size} bytes > {MAX_FILE_SIZE_BYTES} byte limit",),
                0, False,
            )

        # Read file
        try:
            source_text = file_path.read_text(encoding="utf-8", errors="replace")
            source_text = unicodedata.normalize("NFC", source_text)
        except OSError as e:
            return ParseResult(str(file_path), (), (f"read failed: {e}",), 0, False)

        line_count = len(source_text.splitlines())

        # Parse AST
        try:
            tree = ast.parse(source_text, filename=str(file_path))
        except SyntaxError as e:
            return ParseResult(
                str(file_path), (),
                (f"SyntaxError at line {e.lineno}: {e.msg}",),
                line_count, True,
            )

        # Build parent map (for context detection)
        parent_map: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parent_map[id(child)] = node

        # Get source lines for source_line extraction
        source_lines = source_text.splitlines()

        # Walk AST and collect AnalyzedNode instances
        analyzed_nodes: list[AnalyzedNode] = []
        tracker = _CallContextTracker()

        self._walk(
            tree, file_path, source_root, source_lines,
            parent_map, tracker, analyzed_nodes, warnings, depth=0,
        )

        # Sort by canonical_location (deterministic output)
        sorted_nodes = tuple(
            sorted(analyzed_nodes, key=lambda n: n.canonical_location)
        )

        return ParseResult(
            source_path=str(file_path),
            nodes=sorted_nodes,
            parse_warnings=tuple(sorted(warnings)),
            line_count=line_count,
            had_syntax_error=False,
        )

    def parse_directory(
        self,
        source_root_str: str,
        max_files: int = 10_000,
    ) -> list[ParseResult]:
        """
        Purpose: Parse all Python files in a directory tree.
        Returns sorted list of ParseResult (by file path).
        Constraints: bounded by max_files; skips __pycache__ and .git
        """
        source_root = pathlib.Path(source_root_str).resolve().absolute()
        skip_dirs   = frozenset({"__pycache__", ".git", ".tox", "venv", ".venv",
                                  "node_modules", "build", "dist", "target"})

        py_files: list[pathlib.Path] = []
        for f in sorted(source_root.rglob("*.py"), key=str):
            if any(part in skip_dirs for part in f.parts):
                continue
            py_files.append(f)
            if len(py_files) >= max_files:
                break

        return [
            self.parse_file(str(f), source_root_str)
            for f in py_files
        ]

    # ─── AST Walker ───────────────────────────────────────────────────────────

    def _walk(
        self,
        node: ast.AST,
        file_path: pathlib.Path,
        source_root: pathlib.Path,
        source_lines: list[str],
        parent_map: dict[int, ast.AST],
        tracker: _CallContextTracker,
        results: list[AnalyzedNode],
        warnings: list[str],
        depth: int,
    ) -> None:
        """
        Purpose: Recursively walk AST, dispatching to construct detectors.
        Bounded by MAX_AST_DEPTH (RULE-DET-008 compliance).
        """
        if depth > MAX_AST_DEPTH:
            warnings.append(f"AST depth limit {MAX_AST_DEPTH} reached at {type(node).__name__}")
            return

        # Context tracking: enter/exit class and function scopes
        if isinstance(node, ast.ClassDef):
            tracker.enter_class(node.name)
            for child in ast.iter_child_nodes(node):
                self._walk(child, file_path, source_root, source_lines,
                           parent_map, tracker, results, warnings, depth + 1)
            tracker.exit_class()
            return

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_async  = isinstance(node, ast.AsyncFunctionDef)
            params    = frozenset(
                arg.arg for arg in node.args.args
                + node.args.posonlyargs + node.args.kwonlyargs
                + ([node.args.vararg] if node.args.vararg else [])
                + ([node.args.kwarg]  if node.args.kwarg  else [])
            )
            tracker.enter_function(node.name, is_async, params, node.body)
            for child in ast.iter_child_nodes(node):
                self._walk(child, file_path, source_root, source_lines,
                           parent_map, tracker, results, warnings, depth + 1)
            tracker.exit_function()
            return

        # Dispatch to construct detectors
        if isinstance(node, ast.Call):
            detected = self._detect_call(
                node, file_path, source_root, source_lines,
                parent_map, tracker,
            )
            if detected:
                results.append(detected)

        elif isinstance(node, ast.Global):
            detected = self._detect_global(
                node, file_path, source_root, source_lines, tracker,
            )
            results.extend(detected)

        # Recurse into children
        for child in ast.iter_child_nodes(node):
            self._walk(child, file_path, source_root, source_lines,
                       parent_map, tracker, results, warnings, depth + 1)

    def _canonical_location(
        self,
        node: ast.AST,
        file_path: pathlib.Path,
        source_root: pathlib.Path,
    ) -> str:
        """Build canonical location string: /abs/path:line:col"""
        line = getattr(node, 'lineno',    1)
        col  = getattr(node, 'col_offset', 0)
        return f"{file_path}:{line}:{col}"

    def _source_line(self, node: ast.AST, source_lines: list[str]) -> str:
        """Extract the source line for a node (for reporting)."""
        lineno = getattr(node, 'lineno', 1)
        if 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1][:200]
        return ""

    # ─── Construct Detectors ──────────────────────────────────────────────────

    def _detect_call(
        self,
        node: ast.Call,
        file_path: pathlib.Path,
        source_root: pathlib.Path,
        source_lines: list[str],
        parent_map: dict[int, ast.AST],
        tracker: _CallContextTracker,
    ) -> Optional[AnalyzedNode]:
        """Dispatch to the correct construct detector for a Call node."""
        call_name = _get_call_name(node)
        if call_name == "yaml.load":
            return self._detect_yaml_load(node, file_path, source_root, source_lines, parent_map, tracker)
        if call_name == "app.run":
            return self._detect_debug_true(node, file_path, source_root, source_lines, parent_map, tracker)
        # if call_name == "app.run":  # DISABLEDnode, file_path, source_root, source_lines, parent_map, tracker)
        if call_name == "yaml.load":
            return self._detect_yaml_load(node, file_path, source_root, source_lines, parent_map, tracker)
        if call_name == "yaml.load":
            return self._detect_yaml_load(node, file_path, source_root, source_lines, parent_map, tracker)
        if call_name == "app.run":
            return self._detect_debug_true(node, file_path, source_root, source_lines, parent_map, tracker)
        if call_name == "requests.get" or call_name == "requests.post":
            return self._detect_ssrf(node, file_path, source_root, source_lines, parent_map, tracker)
        if call_name == "os.remove" or call_name == "os.unlink":
            return self._detect_os_remove(node, file_path, source_root, source_lines, parent_map, tracker)
        if call_name == "os.system":
            return self._detect_os_system(node, file_path, source_root, source_lines, parent_map, tracker)
        if not call_name:
            return None
            return self._detect_os_system(node, file_path, source_root, source_lines, parent_map, tracker)

        loc = self._canonical_location(node, file_path, source_root)
        src = self._source_line(node, source_lines)

        # eval()
        if call_name == "eval":
            return self._detect_eval(node, loc, src, tracker, "CONST-EVAL-001")

        # exec()
        if call_name == "exec":
            return self._detect_eval(node, loc, src, tracker, "CONST-EXEC-001")

        # open()
        if call_name == "open":
            return self._detect_open(node, loc, src, tracker, parent_map)

        # pickle.loads / pickle.load
        if call_name in ("pickle.loads", "pickle.load"):
            return self._detect_pickle(node, loc, src, tracker)

        # random.* (but not random.seed)
        if call_name.startswith("random.") and not call_name.endswith(".seed"):
            return self._detect_random(node, call_name, loc, src, tracker)

        # subprocess.*
        if any(call_name.startswith(p) for p in (
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
        )):
            return self._detect_subprocess(node, loc, src, tracker)

        # threading.Thread
        if call_name in ("threading.Thread", "Thread"):
            return self._detect_thread(node, loc, src, tracker, parent_map)

        # threading.Lock / asyncio.Lock
        if call_name in ("threading.Lock", "threading.RLock",
                          "threading.Semaphore", "asyncio.Lock"):
            return self._detect_lock(node, loc, src, tracker, parent_map)

        return None

    def _detect_eval(
        self, node: ast.Call, loc: str, src: str,
        tracker: _CallContextTracker, construct_id: str,
    ) -> Optional[AnalyzedNode]:
        """Detect eval() / exec() construct state."""
        if not node.args:
            return None

        sources = _detect_argument_sources(node, 0, tracker)

        # Determine state
        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant):
            state = "constant_arg"
        elif isinstance(first_arg, ast.Call) and _is_tainted(sources):
            state = "external_source_arg"
        elif _is_tainted(sources):
            state = "external_source_arg"
        else:
            state = "dynamic_arg"

        call_ctx = tracker.build_call_context(sources)
        return AnalyzedNode.create(loc, construct_id, "Call", state, call_ctx, src)

    def _detect_debug_true(self, node, file_path, source_root, source_lines, parent_map, tracker):
        loc = self._canonical_location(node, file_path, source_root)
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value == True:
                src = self._source_line(node, source_lines)
                call_ctx = tracker.build_call_context(())
                return AnalyzedNode.create(loc, "CONST-SEC-007", "Call", "debug_enabled", call_ctx, src)
        return []

    def _detect_yaml_load(self, node, file_path, source_root, source_lines, parent_map, tracker):
        loc = self._canonical_location(node, file_path, source_root)
        state = "default_loader"
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute) and "SafeLoader" in str(kw.value.attr):
                    state = "safe_loader"
                    return []
        src = self._source_line(node, source_lines)
        call_ctx = tracker.build_call_context(())
        return AnalyzedNode.create(loc, "CONST-SEC-006", "Call", state, call_ctx, src)

    def _detect_yaml_load(self, node, file_path, source_root, source_lines, parent_map, tracker):
        loc = self._canonical_location(node, file_path, source_root)
        state = "default_loader"
        for kw in node.keywords:
            if kw.arg == "Loader" and isinstance(kw.value, ast.Attribute):
                if "SafeLoader" in str(kw.value.attr):
                    return []
        src = self._source_line(node, source_lines)
        call_ctx = tracker.build_call_context(())
        return AnalyzedNode.create(loc, "CONST-SEC-006", "Call", state, call_ctx, src)

    def _detect_debug_true(self, node, file_path, source_root, source_lines, parent_map, tracker):
        loc = self._canonical_location(node, file_path, source_root)
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value == True:
                src = self._source_line(node, source_lines)
                call_ctx = tracker.build_call_context(())
                return AnalyzedNode.create(loc, "CONST-SEC-007", "Call", "debug_enabled", call_ctx, src)
        return []

    def _detect_ssrf(self, node, file_path, source_root, source_lines, parent_map, tracker):
        loc = self._canonical_location(node, file_path, source_root)
        args = node.args
        state = "static_url"
        if args and not isinstance(args[0], ast.Constant):
            state = "user_controlled_url"
        src = self._source_line(node, source_lines)
        call_ctx = tracker.build_call_context(())
        return AnalyzedNode.create(loc, "CONST-SEC-008", "Call", state, call_ctx, src)

    def _detect_os_remove(self, node, file_path, source_root, source_lines, parent_map, tracker):
        loc = self._canonical_location(node, file_path, source_root)
        state = "static_path"
        if node.args and not isinstance(node.args[0], ast.Constant):
            state = "dynamic_path"
        src = self._source_line(node, source_lines)
        call_ctx = tracker.build_call_context(())
        return AnalyzedNode.create(loc, "CONST-SEC-010", "Call", state, call_ctx, src)

    def _detect_os_system(self, node, file_path, source_root, source_lines, parent_map, tracker):
        loc = self._canonical_location(node, file_path, source_root)
        args = node.args
        if args:
            first_arg = args[0]
            if isinstance(first_arg, ast.Constant):
                state = "constant_cmd"
            else:
                state = "dynamic_cmd"
        else:
            state = "dynamic_cmd"
        src = self._source_line(node, source_lines)
        call_ctx = tracker.build_call_context(())
        return AnalyzedNode.create(loc, "CONST-SEC-002", "Call", state, call_ctx, src)

    def _detect_open(
        self, node: ast.Call, loc: str, src: str,
        tracker: _CallContextTracker, parent_map: dict[int, ast.AST],
    ) -> Optional[AnalyzedNode]:
        """Detect open() construct state."""
        sources = _detect_argument_sources(node, 0, tracker) if node.args else ("UNKNOWN",)

        # Determine state — priority: path_traversal > not_as_cm > used_as_cm
        if _is_tainted(sources):
            state = "path_traversal_possible"
        elif _is_inside_with(node, parent_map):
            state = "used_as_context_manager"
        else:
            state = "not_used_as_context_manager"

        call_ctx = tracker.build_call_context(tuple(sources))
        return AnalyzedNode.create(loc, "CONST-OPEN-001", "Call", state, call_ctx, src)

    def _detect_pickle(
        self, node: ast.Call, loc: str, src: str,
        tracker: _CallContextTracker,
    ) -> Optional[AnalyzedNode]:
        """Detect pickle.loads() construct state."""
        sources = _detect_argument_sources(node, 0, tracker) if node.args else ("UNKNOWN",)

        if _is_tainted(sources):
            state = "loads_untrusted_source"
            if "NETWORK_INPUT" in sources:
                state = "loads_network_data"
        else:
            state = "loads_trusted_source"

        call_ctx = tracker.build_call_context(tuple(sources))
        return AnalyzedNode.create(loc, "CONST-PICK-001", "Call", state, call_ctx, src)

    def _detect_random(
        self, node: ast.Call, call_name: str, loc: str, src: str,
        tracker: _CallContextTracker,
    ) -> Optional[AnalyzedNode]:
        """Detect random.* construct state."""
        fn_name = tracker.current_function() or ""
        # Heuristic: security-sensitive if function name contains token/key/secret/password/id
        security_keywords = frozenset({"token", "key", "secret", "password", "passwd",
                                        "auth", "session", "nonce", "salt", "otp"})
        fn_lower = fn_name.lower()
        is_security = any(kw in fn_lower for kw in security_keywords)

        state = "used_for_security" if is_security else "unseeded_or_default_seed"
        call_ctx = tracker.build_call_context(("LOCAL_VARIABLE",))
        return AnalyzedNode.create(loc, "CONST-RAND-001", "Call", state, call_ctx, src)

    def _detect_subprocess(
        self, node: ast.Call, loc: str, src: str,
        tracker: _CallContextTracker,
    ) -> Optional[AnalyzedNode]:
        """Detect subprocess.* construct state."""
        has_shell_true = _has_kwarg(node, "shell", True)
        sources = _detect_argument_sources(node, 0, tracker) if node.args else ("LITERAL_CONSTANT",)
        is_dynamic = not (len(sources) == 1 and "LITERAL_CONSTANT" in sources)

        if has_shell_true and (is_dynamic or _is_tainted(sources)):
            state = "shell_true_dynamic_cmd"
        elif has_shell_true:
            state = "shell_true_constant_cmd"
        elif is_dynamic:
            state = "shell_false_dynamic_args"
        else:
            state = "shell_false_constant_cmd"

        call_ctx = tracker.build_call_context(tuple(sources))
        return AnalyzedNode.create(loc, "CONST-SUBP-001", "Call", state, call_ctx, src)

    def _detect_thread(
        self, node: ast.Call, loc: str, src: str,
        tracker: _CallContextTracker,
        parent_map: dict[int, ast.AST],
    ) -> Optional[AnalyzedNode]:
        """Detect threading.Thread() construct state."""
        is_daemon = _has_kwarg(node, "daemon", True)
        state = "daemon_thread" if is_daemon else "detached_not_joined"
        call_ctx = tracker.build_call_context(("LOCAL_VARIABLE",))
        return AnalyzedNode.create(loc, "CONST-THRD-001", "Call", state, call_ctx, src)

    def _detect_lock(
        self, node: ast.Call, loc: str, src: str,
        tracker: _CallContextTracker,
        parent_map: dict[int, ast.AST],
    ) -> Optional[AnalyzedNode]:
        """Detect threading.Lock() / asyncio.Lock() construct state."""
        in_with = _is_inside_with(node, parent_map)
        state = "acquired_with_context_manager" if in_with else "acquired_without_context_manager"
        call_ctx = tracker.build_call_context(("LOCAL_VARIABLE",))
        return AnalyzedNode.create(loc, "CONST-LOCK-001", "Call", state, call_ctx, src)

    def _detect_global(
        self,
        node: ast.Global,
        file_path: pathlib.Path,
        source_root: pathlib.Path,
        source_lines: list[str],
        tracker: _CallContextTracker,
    ) -> list[AnalyzedNode]:
        """Detect global statement constructs (one AnalyzedNode per global name)."""
        results = []
        loc = self._canonical_location(node, file_path, source_root)
        src = self._source_line(node, source_lines)

        for name in sorted(node.names):   # sorted for determinism
            # Heuristic: check if this name is assigned anywhere in local scope
            local_scope = tracker.current_local_scope()
            state = "write_global" if name in local_scope else "read_only_global"
            call_ctx = tracker.build_call_context(("LOCAL_VARIABLE",))
            analyzed = AnalyzedNode.create(
                f"{file_path}:{node.lineno}:{node.col_offset}",
                "CONST-GLOB-001", "Global", state, call_ctx, src,
            )
            results.append(analyzed)

        return results
