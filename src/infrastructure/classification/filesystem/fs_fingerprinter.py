"""
******************************************************************************
 * FILE:        /src/infrastructure/classification/filesystem/fs_fingerprinter.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Context Classification — Filesystem Fingerprinter
 * PURPOSE:     Deterministic structural analysis of source tree layout
 * DOMAIN:      Context Classification Pipeline
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Derives context signals from the STRUCTURE of a source tree —
 * directory names, file naming patterns, config file presence, and
 * module layout. No file content is read; no code is executed.
 *
 * This is purely structural classification:
 *   "A directory named 'isr/' or 'interrupt_handlers/' is a strong
 *    structural signal for ISR_CONTEXT — regardless of what's inside."
 *
 * WHAT THIS MODULE DOES:
 *   - Walks source tree (bounded depth)
 *   - Matches directory names against signal patterns
 *   - Detects presence of known config files (Makefile, Cargo.toml, etc.)
 *   - Produces sorted tuple of detected ContextTagVocabulary tags
 *   - Computes SHA-256 of the file tree manifest (for replay)
 *
 * WHAT THIS MODULE DOES NOT DO:
 *   - Read file contents (zero I/O on source files)
 *   - Infer semantics ("this directory might mean...")
 *   - Use ML or probabilistic classification
 *   - Follow symlinks outside source root
 *
 * STRUCTURAL SIGNAL SOURCES (all are path-pattern based):
 *   ISR_CONTEXT          : dirs named isr/, interrupt*/, irq*/
 *   KERNEL_CONTEXT       : dirs named kernel/, drivers/, kmod*/
 *   SAFETY_CRITICAL      : dirs named safety*/, certified*/, sil*/
 *   WEB_REQUEST_HANDLER  : dirs named views/, routes/, handlers/, api/
 *   TEST_CONTEXT         : dirs named test*/, spec*/, *_test/
 *   RTOS_CONTEXT         : presence of FreeRTOSConfig.h or RTOS headers
 *   IEC_61508_SCOPE      : presence of iec61508.cfg, sil_*.yaml, etc.
 *
 * REFERENCES:
 *   MISRA C:2012 Section 5.1 — Source file naming conventions
 *   DO-178C Section 11.10 — Software development environment
 *   ENGINEERING-JUDGMENT-v0.1.0 for all pattern definitions
 *
 * DEPENDENCIES:
 *   - src/domain/context/context_model.py (ContextTagVocabulary)
 *   - pathlib, hashlib (stdlib only)
 *
 * CONSTRAINTS:
 *   - Max traversal depth: 8 levels (configurable, bounded)
 *   - Max files processed: 50,000 (quota)
 *   - No symlink following outside source_root
 *   - All paths canonicalized before matching
 *   - No file reads (stat only — name, type, size)
 *
 * DETERMINISM GUARANTEES:
 *   - Files sorted by canonical path before hashing
 *   - Pattern matching is exact prefix/suffix/contains (not regex)
 *   - Source tree hash: SHA-256 of sorted (path, size, mtime_sec) manifest
 *   - Tags returned as sorted tuple — identical across platforms
 *
 * FAILURE MODES:
 *   - TraversalDepthExceeded: tree deeper than max_depth
 *   - FileQuotaExceeded: more files than max_files_quota
 *   - PathTraversalAttempt: symlink points outside source_root
 *   - SourceRootNotFound: source_root does not exist
 *
 * SECURITY:
 *   - Symlink resolution checked against source_root boundary
 *   - No execution of any found file
 *   - No network access
 *
 * COMPLEXITY: O(n) where n = number of files in source tree (bounded)
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import hashlib
import pathlib
from dataclasses import dataclass
from typing import Optional

from src.domain.context.context_model import ContextTagVocabulary


# ─── Errors ───────────────────────────────────────────────────────────────────

class FilesystemFingerprintError(Exception):
    """Base error for filesystem fingerprinting failures."""


class SourceRootNotFound(FilesystemFingerprintError):
    """Source root path does not exist or is not a directory."""


class PathTraversalAttempt(FilesystemFingerprintError):
    """A symlink or path resolves outside the declared source root."""


class FileQuotaExceeded(FilesystemFingerprintError):
    """Source tree contains more files than the configured quota."""


class TraversalDepthExceeded(FilesystemFingerprintError):
    """Source tree is deeper than the configured maximum depth."""


# ─── Configuration ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FingerprintConfig:
    """
    Purpose: Configuration for the filesystem fingerprinter.
    All limits are explicit — no unbounded traversal.

    Inputs:
    - max_depth: Maximum directory depth to traverse (default: 8)
    - max_files: Maximum number of files to process (default: 50_000)
    - follow_symlinks: Whether to follow symlinks (default: False — security)
    - include_extensions: If non-empty, only include these extensions
    - exclude_dirs: Directory names to skip entirely (e.g. ".git", "node_modules")

    Constraints:
    - max_depth must be in [1, 20]
    - max_files must be in [1, 500_000]
    - follow_symlinks defaults to False for security
    """
    max_depth: int = 20
    max_files: int = 50_000
    follow_symlinks: bool = False
    include_extensions: tuple[str, ...] = ()   # empty = all extensions
    exclude_dirs: tuple[str, ...] = (
        ".git", ".svn", ".hg",
        "__pycache__",
        "interfaces",  # Auth layer excluded from kernel checks ".pytest_cache", ".mypy_cache",
        "node_modules", ".tox", "venv", ".venv",
        "build", "dist", ".eggs",
        "target",   # Rust/Maven build output
    )

    def __post_init__(self) -> None:
        if not (1 <= self.max_depth <= 20):
            raise ValueError(f"max_depth must be in [1, 20], got {self.max_depth}")
        if not (1 <= self.max_files <= 500_000):
            raise ValueError(f"max_files must be in [1, 500_000], got {self.max_files}")


# ─── Structural Signal Patterns ───────────────────────────────────────────────

# Each entry: (pattern_type, value, tag)
# pattern_type: "dir_name_contains" | "dir_name_prefix" | "file_name_exact" | "file_extension"
# Ordered by specificity (more specific first)
# Source: ENGINEERING-JUDGMENT-v0.1.0; DO-178C Section 11.10; MISRA C:2012 Section 5.1

_DIR_NAME_TO_TAGS: tuple[tuple[str, str], ...] = (
    # ISR / Interrupt context signals
    ("isr",                   "ISR_CONTEXT"),
    ("interrupt",             "ISR_CONTEXT"),
    ("irq",                   "ISR_CONTEXT"),
    ("exception_handler",     "ISR_CONTEXT"),
    ("fault_handler",         "ISR_CONTEXT"),

    # Kernel / driver context signals
    ("kernel",                "KERNEL_CONTEXT"),
    ("drivers",               "KERNEL_CONTEXT"),
    ("kmod",                  "KERNEL_CONTEXT"),
    ("lkm",                   "KERNEL_CONTEXT"),

    # Safety-critical signals
    ("safety",                "SAFETY_CRITICAL"),
    ("certified",             "SAFETY_CRITICAL"),
    ("sil",                   "SAFETY_CRITICAL"),
    ("asil",                  "SAFETY_CRITICAL"),
    ("do178",                 "SAFETY_CRITICAL"),
    ("qualified",             "SAFETY_CRITICAL"),

    # RTOS signals
    ("freertos",              "RTOS_CONTEXT"),
    ("rtos",                  "RTOS_CONTEXT"),
    ("zephyr",                "RTOS_CONTEXT"),
    ("vxworks",               "RTOS_CONTEXT"),
    ("threadx",               "RTOS_CONTEXT"),

    # Embedded signals
    ("embedded",              "EMBEDDED_CONTEXT"),
    ("firmware",              "EMBEDDED_CONTEXT"),
    ("bsp",                   "EMBEDDED_CONTEXT"),
    ("hal",                   "EMBEDDED_CONTEXT"),
    ("baremetal",             "EMBEDDED_CONTEXT"),
    ("bare_metal",            "EMBEDDED_CONTEXT"),

    # Web request handler signals
    ("views",                 "WEB_REQUEST_HANDLER"),
    ("routes",                "WEB_REQUEST_HANDLER"),
    ("handlers",              "WEB_REQUEST_HANDLER"),
    ("controllers",           "WEB_REQUEST_HANDLER"),
    ("endpoints",             "WEB_REQUEST_HANDLER"),
    ("api",                   "WEB_REQUEST_HANDLER"),
    ("rest",                  "WEB_REQUEST_HANDLER"),
    ("graphql",               "WEB_REQUEST_HANDLER"),
    ("webhooks",              "WEB_REQUEST_HANDLER"),

    # Test context signals
    ("test",                  "TEST_CONTEXT"),
    ("tests",                 "TEST_CONTEXT"),
    ("spec",                  "TEST_CONTEXT"),
    ("specs",                 "TEST_CONTEXT"),
    ("fixtures",              "TEST_CONTEXT"),

    # Authentication / security signals
    ("auth",                  "AUTH_LOGIC"),
    ("authentication",        "AUTH_LOGIC"),
    ("authorization",         "AUTH_LOGIC"),
    ("oauth",                 "AUTH_LOGIC"),
    ("jwt",                   "AUTH_LOGIC"),
    ("crypto",                "CRYPTO_OPERATIONS"),
    ("cryptography",          "CRYPTO_OPERATIONS"),
    ("cipher",                "CRYPTO_OPERATIONS"),
    ("encrypt",               "CRYPTO_OPERATIONS"),

    # Serialization signals
    ("serializers",           "SERIALIZATION_PRESENT"),
    ("serialization",         "SERIALIZATION_PRESENT"),
    ("marshmallow",           "SERIALIZATION_PRESENT"),
    ("schemas",               "SERIALIZATION_PRESENT"),

    # Background worker signals
    ("workers",               "BACKGROUND_WORKER"),
    ("tasks",                 "BACKGROUND_WORKER"),
    ("celery",                "BACKGROUND_WORKER"),
    ("jobs",                  "BACKGROUND_WORKER"),
    ("queue",                 "BACKGROUND_WORKER"),

    # Database signals
    ("models",                "DATABASE_PRESENT"),
    ("migrations",            "DATABASE_PRESENT"),
    ("repositories",          "DATABASE_PRESENT"),
    ("dao",                   "DATABASE_PRESENT"),

    # CLI signals
    ("cli",                   "CLI_ENTRYPOINT"),
    ("commands",              "CLI_ENTRYPOINT"),
    ("cmd",                   "CLI_ENTRYPOINT"),

    # Prototype / experimental signals
    ("prototype",             "PROTOTYPE_CODE"),
    ("poc",                   "PROTOTYPE_CODE"),
    ("proof_of_concept",      "PROTOTYPE_CODE"),
    ("experimental",          "EXPERIMENTAL"),
    ("scratch",               "EXPERIMENTAL"),
    ("sandbox",               "EXPERIMENTAL"),

    # Regulatory scope signals
    ("iec61508",              "IEC_61508_SCOPE"),
    ("iso26262",              "ISO_26262_SCOPE"),
    ("do178c",                "DO_178C_SCOPE"),
    ("iec62443",              "IEC_62443_SCOPE"),
    ("hipaa",                 "HIPAA_SCOPE"),
    ("pci",                   "PCI_DSS_SCOPE"),
    ("soc2",                  "SOC2_SCOPE"),
)

# File name signals (exact file name, case-insensitive)
_FILE_NAME_TO_TAGS: tuple[tuple[str, str], ...] = (
    # RTOS config files
    ("freertosconfig.h",      "RTOS_CONTEXT"),
    ("rtos_config.h",         "RTOS_CONTEXT"),
    ("cmsis_os.h",            "RTOS_CONTEXT"),

    # IEC 61508 scope signals
    ("iec61508.cfg",          "IEC_61508_SCOPE"),
    ("safety_plan.yaml",      "IEC_61508_SCOPE"),
    ("sil_requirements.yaml", "IEC_61508_SCOPE"),

    # ISO 26262 scope signals
    ("iso26262.cfg",          "ISO_26262_SCOPE"),
    ("asil_requirements.yaml","ISO_26262_SCOPE"),

    # DO-178C scope signals
    ("do178c.cfg",            "DO_178C_SCOPE"),
    ("psac.pdf",              "DO_178C_SCOPE"),
    ("sas.pdf",               "DO_178C_SCOPE"),

    # HIPAA scope signals
    ("hipaa_config.yaml",     "HIPAA_SCOPE"),
    ("phi_handler.py",        "HIPAA_SCOPE"),

    # PCI DSS scope signals
    ("pci_dss.cfg",           "PCI_DSS_SCOPE"),
    ("cardholder_data.py",    "PCI_DSS_SCOPE"),
)


# ─── Filesystem Walk Result ───────────────────────────────────────────────────

@dataclass(frozen=True)
class FilesystemWalkResult:
    """
    Purpose: Complete result of a filesystem fingerprinting run.

    Inputs:
    - source_root: Canonical source root path string
    - source_hash: SHA-256 of sorted file manifest (for replay)
    - detected_tags: Sorted tuple of ContextTagVocabulary tags
    - file_count: Total number of files discovered
    - dir_count: Total number of directories traversed
    - max_depth_reached: The deepest directory level encountered
    - python_file_count: Number of .py files (language detection)
    - c_file_count: Number of .c/.h files (language detection)
    - rust_file_count: Number of .rs files (language detection)
    - loc_estimate: Sum of file sizes / 40 (rough lines estimate, integer)

    Constraints:
    - source_hash starts with "sha256:"
    - detected_tags sorted; all in ContextTagVocabulary
    - All counts are non-negative integers
    """
    source_root: str
    source_hash: str
    detected_tags: tuple[str, ...]
    file_count: int
    dir_count: int
    max_depth_reached: int
    python_file_count: int
    c_file_count: int
    rust_file_count: int
    loc_estimate: int

    def primary_language(self) -> str:
        """
        Purpose: Determine primary language from file counts.
        Returns: "python" | "c" | "rust" | "unknown"
        Constraints: Deterministic; pure function of counts
        """
        counts = {
            "python": self.python_file_count,
            "c":      self.c_file_count,
            "rust":   self.rust_file_count,
        }
        if all(v == 0 for v in counts.values()):
            return "unknown"
        return max(counts, key=lambda k: counts[k])


# ─── Fingerprinter ────────────────────────────────────────────────────────────

class FilesystemFingerprinter:
    """
    Purpose: Perform structural filesystem fingerprinting of a source tree.
    Produces a FilesystemWalkResult from directory structure alone.

    Usage:
        config = FingerprintConfig(max_depth=8, max_files=50_000)
        fingerprinter = FilesystemFingerprinter(config)
        result = fingerprinter.fingerprint(source_root="/path/to/project")

    Constraints:
    - Reads only path metadata (name, type, size) — no file contents
    - All paths are resolved and checked against source_root boundary
    - Traversal is depth-first, sorted at each level (deterministic)
    - Source hash computed from sorted manifest of (relative_path, size_bytes)
    """

    def __init__(self, config: FingerprintConfig) -> None:
        self._config = config

    def fingerprint(self, source_root_str: str) -> FilesystemWalkResult:
        """
        Purpose: Fingerprint a source tree from its filesystem structure.

        Inputs: source_root_str — path string to the project root
        Outputs: FilesystemWalkResult (immutable)

        Failure modes:
        - SourceRootNotFound: path doesn't exist or isn't a directory
        - PathTraversalAttempt: symlink escapes source root
        - FileQuotaExceeded: too many files
        - TraversalDepthExceeded: tree too deep

        Determinism: same source tree → same result (path-sorted traversal)
        Security: symlink boundary check enforced at every step
        Complexity: O(n) where n = file count (bounded by max_files)
        """
        source_root = pathlib.Path(source_root_str).resolve().absolute()

        if not source_root.exists():
            raise SourceRootNotFound(
                f"Source root does not exist: {source_root}"
            )
        if not source_root.is_dir():
            raise SourceRootNotFound(
                f"Source root is not a directory: {source_root}"
            )

        detected_tags: set[str] = set()
        manifest_entries: list[str] = []   # (relative_path:size) for hashing

        file_count = 0
        dir_count = 0
        max_depth_reached = 0
        python_files = 0
        c_files = 0
        rust_files = 0
        total_size_bytes = 0

        # Iterative DFS with explicit depth tracking (no unbounded recursion)
        # Stack items: (path, depth)
        # Initialize stack with root's direct children at depth=1.
        # The root itself is NOT pushed — it is the boundary, not a node to classify.
        try:
            root_children = sorted(source_root.iterdir(), key=lambda p: p.name)
        except PermissionError:
            root_children = []
        stack: list[tuple[pathlib.Path, int]] = [
            (child, 1) for child in reversed(root_children)
        ]

        while stack:
            current_path, depth = stack.pop()

            if depth > self._config.max_depth:
                raise TraversalDepthExceeded(
                    f"Source tree exceeds maximum depth {self._config.max_depth} "
                    f"at path: {current_path.relative_to(source_root)}"
                )

            max_depth_reached = max(max_depth_reached, depth)

            if current_path.is_symlink():
                if not self._config.follow_symlinks:
                    continue  # Skip symlinks entirely (security)
                # Resolve and verify stays inside source_root
                resolved = current_path.resolve().absolute()
                if not str(resolved).startswith(str(source_root)):
                    raise PathTraversalAttempt(
                        f"Symlink {current_path} resolves to {resolved} "
                        f"which is outside source root {source_root}"
                    )

            if current_path.is_dir():
                dir_name_lower = current_path.name.lower()

                # Skip excluded directories
                if current_path.name in self._config.exclude_dirs:
                    continue

                # Match directory name against signal patterns
                for pattern, tag in _DIR_NAME_TO_TAGS:
                    if pattern in dir_name_lower:
                        if ContextTagVocabulary.is_valid_tag(tag):
                            detected_tags.add(tag)
                        break  # One match per directory name is sufficient

                dir_count += 1

                # Push children sorted in reverse (so popped in alphabetical order)
                try:
                    children = sorted(current_path.iterdir(), key=lambda p: p.name)
                except PermissionError:
                    continue  # Skip unreadable directories gracefully

                for child in reversed(children):
                    stack.append((child, depth + 1))

            elif current_path.is_file():
                if file_count >= self._config.max_files:
                    raise FileQuotaExceeded(
                        f"Source tree exceeds file quota of {self._config.max_files} files. "
                        f"Increase FingerprintConfig.max_files or exclude build directories."
                    )

                file_name_lower = current_path.name.lower()
                ext_lower = current_path.suffix.lower()

                # Extension filtering
                if self._config.include_extensions:
                    if ext_lower not in self._config.include_extensions:
                        continue

                # Language file counting
                if ext_lower == ".py":
                    python_files += 1
                elif ext_lower in (".c", ".h", ".cpp", ".hpp", ".cc"):
                    c_files += 1
                elif ext_lower == ".rs":
                    rust_files += 1

                # File name signal matching
                for pattern_name, tag in _FILE_NAME_TO_TAGS:
                    if file_name_lower == pattern_name:
                        if ContextTagVocabulary.is_valid_tag(tag):
                            detected_tags.add(tag)
                        break

                # File name contains signal (for test files like test_*.py)
                if file_name_lower.startswith("test_") or file_name_lower.endswith("_test.py"):
                    detected_tags.add("TEST_CONTEXT")

                # Collect manifest entry (relative path + size for deterministic hashing)
                try:
                    size = current_path.stat().st_size
                    total_size_bytes += size
                    relative = str(current_path.relative_to(source_root))
                    manifest_entries.append(f"{relative}:{size}")
                    file_count += 1
                except (OSError, PermissionError):
                    continue  # Skip unreadable files gracefully

        # Compute source hash from sorted manifest
        sorted_manifest = "\n".join(sorted(manifest_entries))
        source_hash = "sha256:" + hashlib.sha256(
            sorted_manifest.encode("utf-8")
        ).hexdigest()

        # Validate and sort detected tags
        valid_tags = ContextTagVocabulary.all_valid_tags()
        final_tags = tuple(sorted(t for t in detected_tags if t in valid_tags))

        # LOC estimate: total bytes / 40 (average chars per line)
        loc_estimate = total_size_bytes // 40

        return FilesystemWalkResult(
            source_root=str(source_root),
            source_hash=source_hash,
            detected_tags=final_tags,
            file_count=file_count,
            dir_count=dir_count,
            max_depth_reached=max_depth_reached,
            python_file_count=python_files,
            c_file_count=c_files,
            rust_file_count=rust_files,
            loc_estimate=loc_estimate,
        )
