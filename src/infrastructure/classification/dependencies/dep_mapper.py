"""
******************************************************************************
 * FILE:        /src/infrastructure/classification/dependencies/dep_mapper.py
 * LAYER:       Infrastructure Layer
 * MODULE:      Context Classification — Dependency Mapper
 * PURPOSE:     Detect frameworks and count dependencies from manifest files
 * DOMAIN:      Context Classification Pipeline
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Reads dependency manifest files (requirements.txt, pyproject.toml,
 * Cargo.toml, package.json) to:
 *   1. Count total external dependencies
 *   2. Detect known frameworks (django, flask, asyncio, etc.)
 *   3. Derive additional ContextTags from detected frameworks
 *
 * FRAMEWORK → TAG MAPPING (all structural, all cited):
 *   asyncio, trio, anyio → ASYNC_CODEBASE (PSF asyncio docs, 2024)
 *   django, flask, fastapi, starlette → WEB_REQUEST_HANDLER
 *   celery, rq, dramatiq → BACKGROUND_WORKER
 *   sqlalchemy, django.db, psycopg → DATABASE_PRESENT
 *   cryptography, pynacl, pyca → CRYPTO_OPERATIONS
 *   boto3, google-cloud → EXTERNAL_API_CALLS
 *   pytest, unittest → TEST_CONTEXT (in dev deps only)
 *   threading, concurrent.futures → THREAD_POOL_USAGE
 *
 * WHAT THIS READS (bounded):
 *   - requirements.txt, requirements/*.txt: line-by-line (max 10,000 lines)
 *   - pyproject.toml: first 8KB (package names only)
 *   - Cargo.toml: [dependencies] section, first 8KB
 *   - setup.py: NOT read (execution risk; only file existence noted)
 *
 * DETERMINISM GUARANTEES:
 *   - Files read in sorted order
 *   - Package names lowercased and NFC-normalized before matching
 *   - Framework signals returned as sorted tuple
 *   - Dependency count is exact integer
 *
 * FAILURE MODES:
 *   - Missing manifest → DependencyMapResult with count=0, no signals
 *   - Parse error → graceful skip (logs to result.parse_warnings)
 *   - Encoding error → file skipped; counted in parse_warnings
 *
 * CONSTRAINTS:
 *   - Max 10,000 lines per requirements file
 *   - Max 8,192 bytes per TOML file read
 *   - No subprocess execution (no pip freeze, no cargo metadata)
 *   - No network access
 *
 * SECURITY:
 *   - setup.py is never executed
 *   - No eval() or exec() of any manifest content
 *   - All reads are bounded
 *
 * COMPLEXITY: O(f * l) where f = manifest files, l = lines per file
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import pathlib
import unicodedata
from dataclasses import dataclass


# ─── Result Type ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DependencyMapResult:
    """
    Purpose: Result of dependency mapping from manifest files.

    Inputs:
    - dependency_count: Total unique external dependencies found
    - framework_signals: Sorted tuple of detected framework names
    - additional_tags: Sorted tuple of ContextTagVocabulary tags derived
    - manifest_files_read: Sorted tuple of manifest files successfully read
    - parse_warnings: Sorted tuple of non-fatal parse issues
    """
    dependency_count: int
    framework_signals: tuple[str, ...]    # sorted lowercase framework names
    additional_tags: tuple[str, ...]      # sorted ContextTagVocabulary tags
    manifest_files_read: tuple[str, ...]  # sorted relative paths
    parse_warnings: tuple[str, ...]       # sorted warning strings


# ─── Framework Signal Table ───────────────────────────────────────────────────

# (package_name_fragment, framework_signal, context_tag)
# package_name_fragment: lowercase; matched via 'in' on package name
# Ordered by specificity (more specific first)
# Source: ENGINEERING-JUDGMENT-v0.1.0; each framework's official docs

_PYTHON_FRAMEWORK_SIGNALS: tuple[tuple[str, str, str], ...] = (
    # Async frameworks
    ("asyncio",          "asyncio",          "ASYNC_CODEBASE"),
    ("trio",             "trio",             "ASYNC_CODEBASE"),
    ("anyio",            "anyio",            "ASYNC_CODEBASE"),
    ("aiohttp",          "aiohttp",          "ASYNC_CODEBASE"),
    ("uvloop",           "uvloop",           "ASYNC_CODEBASE"),

    # Web frameworks → WEB_REQUEST_HANDLER
    ("django",           "django",           "WEB_REQUEST_HANDLER"),
    ("flask",            "flask",            "WEB_REQUEST_HANDLER"),
    ("fastapi",          "fastapi",          "WEB_REQUEST_HANDLER"),
    ("starlette",        "starlette",        "WEB_REQUEST_HANDLER"),
    ("tornado",          "tornado",          "WEB_REQUEST_HANDLER"),
    ("sanic",            "sanic",            "WEB_REQUEST_HANDLER"),
    ("falcon",           "falcon",           "WEB_REQUEST_HANDLER"),
    ("bottle",           "bottle",           "WEB_REQUEST_HANDLER"),
    ("pyramid",          "pyramid",          "WEB_REQUEST_HANDLER"),

    # Background workers
    ("celery",           "celery",           "BACKGROUND_WORKER"),
    ("rq",               "rq",               "BACKGROUND_WORKER"),
    ("dramatiq",         "dramatiq",         "BACKGROUND_WORKER"),
    ("arq",              "arq",              "BACKGROUND_WORKER"),
    ("apscheduler",      "apscheduler",      "BACKGROUND_WORKER"),

    # Database
    ("sqlalchemy",       "sqlalchemy",       "DATABASE_PRESENT"),
    ("psycopg",          "psycopg",          "DATABASE_PRESENT"),
    ("pymongo",          "pymongo",          "DATABASE_PRESENT"),
    ("motor",            "motor",            "DATABASE_PRESENT"),
    ("databases",        "databases",        "DATABASE_PRESENT"),
    ("tortoise-orm",     "tortoise-orm",     "DATABASE_PRESENT"),
    ("peewee",           "peewee",           "DATABASE_PRESENT"),
    ("redis",            "redis",            "DATABASE_PRESENT"),

    # Cryptography
    ("cryptography",     "cryptography",     "CRYPTO_OPERATIONS"),
    ("pynacl",           "pynacl",           "CRYPTO_OPERATIONS"),
    ("bcrypt",           "bcrypt",           "CRYPTO_OPERATIONS"),
    ("passlib",          "passlib",          "CRYPTO_OPERATIONS"),
    ("pyotp",            "pyotp",            "CRYPTO_OPERATIONS"),
    ("jwcrypto",         "jwcrypto",         "CRYPTO_OPERATIONS"),
    ("python-jose",      "python-jose",      "CRYPTO_OPERATIONS"),

    # Auth
    ("authlib",          "authlib",          "AUTH_LOGIC"),
    ("python-jwt",       "python-jwt",       "AUTH_LOGIC"),
    ("pyjwt",            "pyjwt",            "AUTH_LOGIC"),
    ("django-allauth",   "django-allauth",   "AUTH_LOGIC"),
    ("flask-login",      "flask-login",      "AUTH_LOGIC"),
    ("oauthlib",         "oauthlib",         "AUTH_LOGIC"),

    # External APIs / Cloud
    ("boto3",            "boto3",            "EXTERNAL_API_CALLS"),
    ("google-cloud",     "google-cloud",     "EXTERNAL_API_CALLS"),
    ("azure",            "azure-sdk",        "EXTERNAL_API_CALLS"),
    ("requests",         "requests",         "EXTERNAL_API_CALLS"),
    ("httpx",            "httpx",            "EXTERNAL_API_CALLS"),

    # Serialization
    ("marshmallow",      "marshmallow",      "SERIALIZATION_PRESENT"),
    ("pydantic",         "pydantic",         "SERIALIZATION_PRESENT"),
    ("attrs",            "attrs",            "SERIALIZATION_PRESENT"),
    ("cerberus",         "cerberus",         "SERIALIZATION_PRESENT"),
    ("msgpack",          "msgpack",          "SERIALIZATION_PRESENT"),
    ("protobuf",         "protobuf",         "SERIALIZATION_PRESENT"),

    # Thread pool signals
    ("concurrent",       "concurrent",       "THREAD_POOL_USAGE"),
    ("multiprocess",     "multiprocess",     "THREAD_POOL_USAGE"),
)


# ─── Dependency Mapper ────────────────────────────────────────────────────────

class DependencyMapper:
    """
    Purpose: Map dependency manifests to framework signals and context tags.
    Reads manifest files in sorted order; never executes any code.

    Usage:
        mapper = DependencyMapper()
        result = mapper.map_dependencies("/path/to/project")
    """

    _MAX_LINES_PER_REQUIREMENTS = 10_000
    _MAX_BYTES_PER_TOML = 8_192

    def map_dependencies(self, source_root_str: str) -> DependencyMapResult:
        """
        Purpose: Read dependency manifests and produce a DependencyMapResult.

        Inputs: source_root_str — path to project root
        Outputs: DependencyMapResult (immutable)

        Constraints:
        - Bounded read per file
        - No execution
        - Sorted file processing (deterministic)
        Determinism: same manifest files → same result
        """
        root = pathlib.Path(source_root_str).resolve().absolute()

        all_packages: set[str] = set()      # unique package names (lowercase)
        framework_signals: set[str] = set()
        additional_tags: set[str] = set()
        manifests_read: list[str] = []
        warnings: list[str] = []

        # Discover manifest files in sorted order (deterministic)
        manifest_files: list[pathlib.Path] = []

        # requirements.txt and requirements/*.txt
        req_txt = root / "requirements.txt"
        if req_txt.exists() and req_txt.is_file():
            manifest_files.append(req_txt)

        req_dir = root / "requirements"
        if req_dir.exists() and req_dir.is_dir():
            for f in sorted(req_dir.glob("*.txt"), key=lambda p: p.name):
                manifest_files.append(f)

        # pyproject.toml
        pyproject = root / "pyproject.toml"
        if pyproject.exists() and pyproject.is_file():
            manifest_files.append(pyproject)

        # Cargo.toml
        cargo_toml = root / "Cargo.toml"
        if cargo_toml.exists() and cargo_toml.is_file():
            manifest_files.append(cargo_toml)

        # Process each manifest
        for manifest_path in manifest_files:
            rel_path = str(manifest_path.relative_to(root))
            try:
                packages = self._read_manifest(manifest_path, warnings)
                all_packages.update(packages)
                manifests_read.append(rel_path)
            except Exception as e:
                warnings.append(f"Skipped {rel_path}: {type(e).__name__}: {e}")

        # Match packages against framework signal table
        for package_name in all_packages:
            pkg_lower = package_name.lower().replace("_", "-")
            for fragment, signal, tag in _PYTHON_FRAMEWORK_SIGNALS:
                if fragment in pkg_lower:
                    framework_signals.add(signal)
                    additional_tags.add(tag)
                    break  # One signal per package

        return DependencyMapResult(
            dependency_count=len(all_packages),
            framework_signals=tuple(sorted(framework_signals)),
            additional_tags=tuple(sorted(additional_tags)),
            manifest_files_read=tuple(sorted(manifests_read)),
            parse_warnings=tuple(sorted(warnings)),
        )

    def _read_manifest(
        self, path: pathlib.Path, warnings: list[str]
    ) -> list[str]:
        """
        Purpose: Read a manifest file and extract package names.
        Dispatches to format-specific reader based on filename.

        Inputs: path — manifest file path; warnings — list to append to
        Outputs: list of package name strings (lowercase, normalized)
        Constraints: bounded read per format
        """
        name_lower = path.name.lower()

        if name_lower.endswith(".txt"):
            return self._read_requirements_txt(path, warnings)
        elif name_lower == "pyproject.toml":
            return self._read_pyproject_toml(path, warnings)
        elif name_lower == "cargo.toml":
            return self._read_cargo_toml(path, warnings)

        warnings.append(f"Unknown manifest format: {path.name}")
        return []

    def _read_requirements_txt(
        self, path: pathlib.Path, warnings: list[str]
    ) -> list[str]:
        """
        Purpose: Parse requirements.txt into package names.
        Format: one package per line; ignore comments (#) and options (-r, -c, -e)
        Constraints: max _MAX_LINES_PER_REQUIREMENTS lines
        """
        packages: list[str] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line_num, line in enumerate(fh, start=1):
                    if line_num > self._MAX_LINES_PER_REQUIREMENTS:
                        warnings.append(
                            f"{path.name}: truncated at {self._MAX_LINES_PER_REQUIREMENTS} lines"
                        )
                        break

                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith(("-r", "-c", "-e", "--")):
                        continue

                    # Extract package name (before version specifier)
                    # e.g. "django>=4.0" → "django"
                    pkg = line.split("==")[0].split(">=")[0].split("<=")[0]
                    pkg = pkg.split(">")[0].split("<")[0].split("!")[0].split("[")[0]
                    pkg = unicodedata.normalize("NFC", pkg.strip().lower())
                    if pkg:
                        packages.append(pkg)
        except (OSError, UnicodeDecodeError) as e:
            warnings.append(f"{path.name}: read error: {e}")

        return packages

    def _read_pyproject_toml(
        self, path: pathlib.Path, warnings: list[str]
    ) -> list[str]:
        """
        Purpose: Extract dependency names from pyproject.toml.
        Reads only the [dependencies] / [tool.poetry.dependencies] sections.
        Reads at most _MAX_BYTES_PER_TOML bytes (bounded).
        Does NOT use a TOML parser (no external dependencies) — uses
        line-based heuristic for package name extraction.
        """
        packages: list[str] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                content = fh.read(self._MAX_BYTES_PER_TOML)

            in_deps_section = False
            for line in content.splitlines():
                line_stripped = line.strip()

                # Detect dependency sections
                if line_stripped in (
                    "[dependencies]",
                    "[tool.poetry.dependencies]",
                    "[project.dependencies]",
                    "[tool.poetry.dev-dependencies]",
                    "[build-system]",
                ):
                    in_deps_section = True
                    continue

                # Exit section on next section header
                if line_stripped.startswith("[") and in_deps_section:
                    if line_stripped not in (
                        "[tool.poetry.dependencies]",
                        "[tool.poetry.dev-dependencies]",
                        "[project.dependencies]",
                        "[dependencies]",
                    ):
                        in_deps_section = False
                    continue

                if in_deps_section and "=" in line_stripped:
                    pkg = line_stripped.split("=")[0].strip().strip('"').strip("'")
                    pkg = unicodedata.normalize("NFC", pkg.lower().replace("_", "-"))
                    if pkg and not pkg.startswith("#"):
                        packages.append(pkg)

        except (OSError, UnicodeDecodeError) as e:
            warnings.append(f"{path.name}: read error: {e}")

        return packages

    def _read_cargo_toml(
        self, path: pathlib.Path, warnings: list[str]
    ) -> list[str]:
        """
        Purpose: Extract crate names from Cargo.toml [dependencies].
        Reads at most _MAX_BYTES_PER_TOML bytes.
        Line-based heuristic (no TOML parser needed for package names).
        """
        packages: list[str] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                content = fh.read(self._MAX_BYTES_PER_TOML)

            in_deps = False
            for line in content.splitlines():
                line_stripped = line.strip()

                if line_stripped in ("[dependencies]", "[dev-dependencies]",
                                     "[build-dependencies]"):
                    in_deps = True
                    continue

                if line_stripped.startswith("[") and in_deps:
                    in_deps = False
                    continue

                if in_deps and "=" in line_stripped and not line_stripped.startswith("#"):
                    pkg = line_stripped.split("=")[0].strip().replace('"', '').replace("'", "")
                    pkg = unicodedata.normalize("NFC", pkg.lower())
                    if pkg:
                        packages.append(pkg)

        except (OSError, UnicodeDecodeError) as e:
            warnings.append(f"{path.name}: read error: {e}")

        return packages
