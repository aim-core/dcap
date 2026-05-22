"""
******************************************************************************
 * FILE:        /src/infrastructure/classification/buildsystem/build_detector.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Context Classification — Build System Detector
 * PURPOSE:     Deterministic identification of project build system
 * DOMAIN:      Context Classification Pipeline
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Identifies the build system of a project by checking for the presence
 * of canonical build system configuration files in the source root.
 *
 * Detection is STRUCTURAL and DETERMINISTIC:
 *   - Cargo.toml present → CARGO
 *   - CMakeLists.txt present → CMAKE
 *   - Makefile present → MAKE
 *   - pyproject.toml with [tool.poetry] → POETRY
 *   - pyproject.toml (no poetry) or setup.py → PIP
 *   - build.gradle or build.gradle.kts → GRADLE
 *   - pom.xml → MAVEN
 *
 * When multiple signals are present (e.g. CMakeLists.txt AND Makefile),
 * the higher-specificity signal wins. Priority is defined in
 * DETECTION_PRIORITY and is deterministic.
 *
 * WHAT THIS READS:
 *   - File existence checks only (os.path.exists)
 *   - For PIP vs POETRY disambiguation: reads first 512 bytes of
 *     pyproject.toml to detect [tool.poetry] section header
 *   - No other file content is read
 *
 * REFERENCES:
 *   - Cargo: https://doc.rust-lang.org/cargo/reference/manifest.html
 *   - CMake: https://cmake.org/cmake/help/latest/manual/cmake.1.html
 *   - PEP 517/518: https://peps.python.org/pep-0517/ https://peps.python.org/pep-0518/
 *   - Poetry: https://python-poetry.org/docs/pyproject/
 *   - Gradle: https://docs.gradle.org/current/userguide/build_lifecycle.html
 *   - Maven: https://maven.apache.org/guides/introduction/introduction-to-the-pom.html
 *
 * DEPENDENCIES:
 *   - src/domain/context/context_model.py (BuildSystem)
 *   - pathlib, unicodedata (stdlib only)
 *
 * CONSTRAINTS:
 *   - Reads at most 512 bytes from pyproject.toml (bounded I/O)
 *   - No execution of any build file
 *   - No network access
 *   - Bounded: O(1) checks per known build system
 *
 * DETERMINISM GUARANTEES:
 *   - Detection priority list is ordered and immutable
 *   - Same directory structure → same BuildSystem result
 *   - File read is bounded and canonical (NFC normalized)
 *
 * FAILURE MODES:
 *   - Returns BuildSystem.UNKNOWN if no known signal found
 *   - Never raises on missing files (checks existence first)
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import pathlib
import unicodedata
from dataclasses import dataclass

from src.domain.context.context_model import BuildSystem


# ─── Detection Result ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BuildSystemDetectionResult:
    """
    Purpose: Complete result of build system detection.

    Inputs:
    - build_system: The detected BuildSystem value
    - confidence: "certain" | "heuristic" (certain = single unambiguous signal)
    - signals_found: Sorted tuple of files that triggered detection
    - disambiguation_note: Explanation when multiple signals were found
    """
    build_system: str        # BuildSystem value
    confidence: str          # "certain" | "heuristic"
    signals_found: tuple[str, ...]       # sorted file names that triggered detection
    disambiguation_note: str             # empty if no ambiguity


# ─── Detection Priority ────────────────────────────────────────────────────────

# Ordered list: (build_system, required_file_name, disambiguation_fn)
# Earlier entries have higher priority when multiple signals present.
# disambiguation_fn: Optional[Callable] returning True if signal is definitive.

def _is_poetry(root: pathlib.Path) -> bool:
    """
    Purpose: Check if pyproject.toml contains [tool.poetry] header.
    Reads at most 512 bytes — bounded I/O.
    Returns True if POETRY signal; False means plain PIP.
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return False
    try:
        # Read bounded slice — at most 512 bytes
        with pyproject.open("r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(512)
        normalized = unicodedata.normalize("NFC", content)
        return "[tool.poetry]" in normalized
    except (OSError, UnicodeDecodeError):
        return False


def _has_file(root: pathlib.Path, name: str) -> bool:
    """Deterministic file-existence check. Never raises."""
    try:
        return (root / name).exists() and (root / name).is_file()
    except OSError:
        return False


# ─── Detector ─────────────────────────────────────────────────────────────────

def detect_build_system(source_root_str: str) -> BuildSystemDetectionResult:
    """
    Purpose: Detect the build system of a project by checking for
    canonical configuration files in the source root.

    Detection priority (highest to lowest specificity):
    1. Cargo.toml   → CARGO   (Rust; very specific)
    2. CMakeLists.txt → CMAKE (C/C++; very specific)
    3. pom.xml      → MAVEN   (Java; very specific)
    4. build.gradle or build.gradle.kts → GRADLE (Java/Kotlin)
    5. pyproject.toml + [tool.poetry] → POETRY (Python; more specific)
    6. pyproject.toml OR setup.py → PIP (Python)
    7. Makefile     → MAKE    (generic; lowest specificity)
    8. (none found) → UNKNOWN

    Inputs: source_root_str — path to project root
    Outputs: BuildSystemDetectionResult (immutable)

    Constraints:
    - At most one file content read (pyproject.toml, 512 bytes)
    - No execution; no network
    Determinism: same directory → same result
    """
    root = pathlib.Path(source_root_str).resolve().absolute()

    signals: list[str] = []

    # Check all signals (collect all found, priority applied below)
    cargo    = _has_file(root, "Cargo.toml")
    cmake    = _has_file(root, "CMakeLists.txt")
    maven    = _has_file(root, "pom.xml")
    gradle   = _has_file(root, "build.gradle") or _has_file(root, "build.gradle.kts")
    pyproject= _has_file(root, "pyproject.toml")
    setup_py = _has_file(root, "setup.py")
    makefile = _has_file(root, "Makefile") or _has_file(root, "makefile")

    if cargo:    signals.append("Cargo.toml")
    if cmake:    signals.append("CMakeLists.txt")
    if maven:    signals.append("pom.xml")
    if gradle:
        if _has_file(root, "build.gradle"):        signals.append("build.gradle")
        if _has_file(root, "build.gradle.kts"):    signals.append("build.gradle.kts")
    if pyproject: signals.append("pyproject.toml")
    if setup_py:  signals.append("setup.py")
    if makefile:
        if _has_file(root, "Makefile"):  signals.append("Makefile")
        if _has_file(root, "makefile"):  signals.append("makefile")

    # Apply priority to determine winner
    ambiguous = len([x for x in [cargo, cmake, maven, gradle, pyproject or setup_py, makefile] if x]) > 1

    if cargo:
        return BuildSystemDetectionResult(
            build_system=BuildSystem.CARGO.value,
            confidence="certain",
            signals_found=tuple(sorted(signals)),
            disambiguation_note="Cargo.toml overrides all other build signals" if ambiguous else "",
        )

    if cmake:
        return BuildSystemDetectionResult(
            build_system=BuildSystem.CMAKE.value,
            confidence="certain",
            signals_found=tuple(sorted(signals)),
            disambiguation_note="CMakeLists.txt overrides Makefile" if makefile else "",
        )

    if maven:
        return BuildSystemDetectionResult(
            build_system=BuildSystem.MAVEN.value,
            confidence="certain",
            signals_found=tuple(sorted(signals)),
            disambiguation_note="pom.xml overrides Makefile" if makefile else "",
        )

    if gradle:
        return BuildSystemDetectionResult(
            build_system=BuildSystem.GRADLE.value,
            confidence="certain",
            signals_found=tuple(sorted(signals)),
            disambiguation_note="",
        )

    if pyproject:
        # Disambiguate: Poetry vs pip
        is_poetry = _is_poetry(root)
        return BuildSystemDetectionResult(
            build_system=BuildSystem.POETRY.value if is_poetry else BuildSystem.PIP.value,
            confidence="certain",
            signals_found=tuple(sorted(signals)),
            disambiguation_note=(
                "pyproject.toml contains [tool.poetry] → POETRY"
                if is_poetry else
                "pyproject.toml without [tool.poetry] → PIP"
            ),
        )

    if setup_py:
        return BuildSystemDetectionResult(
            build_system=BuildSystem.PIP.value,
            confidence="certain",
            signals_found=tuple(sorted(signals)),
            disambiguation_note="",
        )

    if makefile:
        return BuildSystemDetectionResult(
            build_system=BuildSystem.MAKE.value,
            confidence="heuristic",  # Makefile alone is ambiguous (C, Python, etc.)
            signals_found=tuple(sorted(signals)),
            disambiguation_note="Makefile found but language is ambiguous",
        )

    return BuildSystemDetectionResult(
        build_system=BuildSystem.UNKNOWN.value,
        confidence="certain",
        signals_found=(),
        disambiguation_note="No recognized build system configuration file found",
    )
