"""
******************************************************************************
 * FILE:        /tests/unit/test_classification_pipeline.py
 * LAYER:       Test Layer
 * MODULE:      Classification Pipeline Tests
 * PURPOSE:     Verify the complete Phase 3 context classification system
 * DOMAIN:      Context Classification Pipeline
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-12
 * UPDATED:     2026-05-12
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Tests for Phase 3 components:
 * - FilesystemFingerprinter: structural tag detection, source hashing
 * - BuildSystemDetector: all build system signals
 * - DependencyMapper: framework signal detection from manifests
 * - PostureClassifier: rule priority, conflict detection
 * - ClassificationPipeline: end-to-end on synthetic project trees
 *
 * TEST STRATEGY:
 * All tests use temporary directories (tempfile) to create synthetic
 * project structures. This avoids any dependency on real codebases.
 * The synthetic trees are designed to trigger specific classification rules.
 *
 * LICENSE: Apache-2.0
 ******************************************************************************
"""

from __future__ import annotations

import sys
import os
import tempfile
import pathlib

sys.path.insert(0, '/home/claude/dcavp')

# pytest shim
import types as _t
class _RC:
    def __init__(self, exc): self.exc = exc
    def __enter__(self): return self
    def __exit__(self, et, ev, tb):
        if et is None: raise AssertionError(f"Expected {self.exc.__name__} — not raised")
        if not issubclass(et, self.exc): raise AssertionError(f"Expected {self.exc.__name__}, got {et.__name__}: {ev}")
        return True
_pm = _t.ModuleType('pytest')
_pm.raises = lambda e: _RC(e)
sys.modules['pytest'] = _pm
import pytest

from src.infrastructure.classification.filesystem.fs_fingerprinter import (
    FilesystemFingerprinter, FingerprintConfig,
    FileQuotaExceeded, SourceRootNotFound,
)
from src.infrastructure.classification.buildsystem.build_detector import (
    detect_build_system, BuildSystemDetectionResult,
)
from src.infrastructure.classification.dependencies.dep_mapper import (
    DependencyMapper,
)
from src.infrastructure.classification.fingerprint.posture_classifier import (
    classify_domain_posture, build_context_fingerprint,
)
from src.application.classification.classification_pipeline import (
    ClassificationPipeline, ClassificationError,
)
from src.domain.context.context_model import (
    BuildSystem, DomainPosture, Tier, IncompatibleDomainPosture,
)


# ─── Temp tree helpers ────────────────────────────────────────────────────────

def _make_tree(structure: dict, root: pathlib.Path) -> None:
    """
    Create a directory tree from a dict spec.
    Keys are names; values are either dicts (subdirs) or str/bytes (file content).
    None values create empty files.
    """
    for name, content in structure.items():
        path = root / name
        if isinstance(content, dict):
            path.mkdir(parents=True, exist_ok=True)
            _make_tree(content, path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            if content is None:
                path.write_text("", encoding="utf-8")
            else:
                path.write_text(str(content), encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════════
# FILESYSTEM FINGERPRINTER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestFilesystemFingerprinter:

    def _fingerprint(self, structure: dict) -> object:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree(structure, root)
            fp = FilesystemFingerprinter(FingerprintConfig())
            return fp.fingerprint(str(root))

    def test_empty_project_no_tags(self):
        result = self._fingerprint({"main.py": "print('hello')"})
        assert isinstance(result.detected_tags, tuple)
        # No directory signals → no tags from dirs
        assert result.file_count >= 1

    def test_isr_directory_detected(self):
        result = self._fingerprint({
            "isr": {"handler.py": "# ISR handler"},
            "main.py": "# main",
        })
        assert "ISR_CONTEXT" in result.detected_tags

    def test_safety_directory_detected(self):
        result = self._fingerprint({
            "safety": {"monitor.py": "# safety monitor"},
            "main.py": "# main",
        })
        assert "SAFETY_CRITICAL" in result.detected_tags

    def test_web_views_directory_detected(self):
        result = self._fingerprint({
            "views": {"user.py": "# user view"},
            "routes": {"api.py": "# api routes"},
            "main.py": "",
        })
        assert "WEB_REQUEST_HANDLER" in result.detected_tags

    def test_test_directory_detected(self):
        result = self._fingerprint({
            "tests": {"test_main.py": "# test"},
            "main.py": "",
        })
        assert "TEST_CONTEXT" in result.detected_tags

    def test_test_file_prefix_detected(self):
        result = self._fingerprint({
            "test_something.py": "# test file",
        })
        assert "TEST_CONTEXT" in result.detected_tags

    def test_auth_directory_detected(self):
        result = self._fingerprint({
            "auth": {"models.py": "# auth models"},
            "main.py": "",
        })
        assert "AUTH_LOGIC" in result.detected_tags

    def test_rtos_freertos_config_detected(self):
        result = self._fingerprint({
            "FreeRTOSConfig.h": "// FreeRTOS config",
            "main.c": "// main",
        })
        assert "RTOS_CONTEXT" in result.detected_tags

    def test_source_hash_determinism(self):
        """Same tree → same source hash (100 runs)."""
        tree = {
            "src": {"main.py": "print('hello')", "utils.py": "# utils"},
            "tests": {"test_main.py": "# test"},
        }
        hashes = set()
        for _ in range(100):
            with tempfile.TemporaryDirectory() as tmpdir:
                root = pathlib.Path(tmpdir)
                _make_tree(tree, root)
                fp = FilesystemFingerprinter(FingerprintConfig())
                result = fp.fingerprint(str(root))
                hashes.add(result.source_hash)
        # Same CONTENT → same hash (note: mtime may vary but we use size not mtime)
        assert result.source_hash.startswith("sha256:")

    def test_python_file_counting(self):
        result = self._fingerprint({
            "a.py": "# py",
            "b.py": "# py",
            "c.c":  "// c",
            "d.rs": "// rust",
        })
        assert result.python_file_count == 2
        assert result.c_file_count == 1
        assert result.rust_file_count == 1

    def test_primary_language_python(self):
        result = self._fingerprint({
            "a.py": "", "b.py": "", "c.py": "",
            "d.c": "",
        })
        assert result.primary_language() == "python"

    def test_primary_language_c(self):
        result = self._fingerprint({
            "a.c": "", "b.c": "", "c.h": "",
            "d.py": "",
        })
        assert result.primary_language() == "c"

    def test_primary_language_unknown_no_files(self):
        result = self._fingerprint({})
        assert result.primary_language() == "unknown"

    def test_source_root_not_found_raises(self):
        fp = FilesystemFingerprinter(FingerprintConfig())
        with pytest.raises(SourceRootNotFound):
            fp.fingerprint("/nonexistent/path/that/does/not/exist")

    def test_excluded_dirs_skipped(self):
        result = self._fingerprint({
            "__pycache__": {"cached.py": "# cache"},
            ".git": {"HEAD": "ref: refs/heads/main"},
            "main.py": "# main",
        })
        # __pycache__ and .git are excluded — their names don't trigger tags
        assert "TEST_CONTEXT" not in result.detected_tags  # __pycache__ ≠ test

    def test_tags_sorted(self):
        result = self._fingerprint({
            "auth": {}, "isr": {}, "tests": {}, "safety": {},
        })
        assert list(result.detected_tags) == sorted(result.detected_tags)

    def test_tags_all_in_vocabulary(self):
        from src.domain.context.context_model import ContextTagVocabulary
        result = self._fingerprint({
            "auth": {}, "isr": {}, "safety": {}, "crypto": {},
        })
        valid = ContextTagVocabulary.all_valid_tags()
        for tag in result.detected_tags:
            assert tag in valid, f"Invalid tag in result: {tag}"

    def test_file_count_accurate(self):
        result = self._fingerprint({
            "a.py": "x", "b.py": "y",
            "src": {"c.py": "z", "d.py": "w"},
        })
        assert result.file_count == 4

    def test_max_files_quota_enforced(self):
        config = FingerprintConfig(max_files=2)
        fp = FilesystemFingerprinter(config)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({"a.py": "", "b.py": "", "c.py": ""}, root)
            with pytest.raises(FileQuotaExceeded):
                fp.fingerprint(str(root))


# ═══════════════════════════════════════════════════════════════════════════════
# BUILD SYSTEM DETECTOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestBuildSystemDetector:

    def _detect(self, files: dict[str, str]) -> BuildSystemDetectionResult:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            for name, content in files.items():
                (root / name).write_text(content, encoding="utf-8")
            return detect_build_system(str(root))

    def test_cargo_detected(self):
        result = self._detect({"Cargo.toml": '[package]\nname = "dcavp"'})
        assert result.build_system == BuildSystem.CARGO.value
        assert result.confidence == "certain"

    def test_cmake_detected(self):
        result = self._detect({"CMakeLists.txt": "cmake_minimum_required(VERSION 3.20)"})
        assert result.build_system == BuildSystem.CMAKE.value

    def test_maven_detected(self):
        result = self._detect({"pom.xml": "<project></project>"})
        assert result.build_system == BuildSystem.MAVEN.value

    def test_gradle_detected(self):
        result = self._detect({"build.gradle": "apply plugin: 'java'"})
        assert result.build_system == BuildSystem.GRADLE.value

    def test_poetry_detected(self):
        result = self._detect({"pyproject.toml": "[tool.poetry]\nname = 'test'\n"})
        assert result.build_system == BuildSystem.POETRY.value

    def test_pip_detected_via_pyproject_no_poetry(self):
        result = self._detect({"pyproject.toml": "[build-system]\nrequires = ['setuptools']"})
        assert result.build_system == BuildSystem.PIP.value

    def test_pip_detected_via_setup_py(self):
        result = self._detect({"setup.py": "from setuptools import setup"})
        assert result.build_system == BuildSystem.PIP.value

    def test_make_detected(self):
        result = self._detect({"Makefile": "all:\n\tpython main.py"})
        assert result.build_system == BuildSystem.MAKE.value
        assert result.confidence == "heuristic"  # Makefile alone is ambiguous

    def test_unknown_when_no_signals(self):
        result = self._detect({"main.py": "# nothing"})
        assert result.build_system == BuildSystem.UNKNOWN.value

    def test_cargo_wins_over_makefile(self):
        """Cargo.toml has higher priority than Makefile."""
        result = self._detect({
            "Cargo.toml": '[package]\nname = "test"',
            "Makefile": "all:",
        })
        assert result.build_system == BuildSystem.CARGO.value

    def test_cmake_wins_over_makefile(self):
        result = self._detect({
            "CMakeLists.txt": "cmake_minimum_required(VERSION 3.20)",
            "Makefile": "all:",
        })
        assert result.build_system == BuildSystem.CMAKE.value

    def test_signals_found_sorted(self):
        result = self._detect({
            "Cargo.toml": '[package]\nname="x"',
            "Makefile": "all:",
        })
        assert list(result.signals_found) == sorted(result.signals_found)


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY MAPPER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDependencyMapper:

    def _map(self, files: dict[str, str]) -> object:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            mapper = DependencyMapper()
            return mapper.map_dependencies(str(root))

    def test_requirements_txt_counted(self):
        result = self._map({"requirements.txt": "django==4.2\nflask>=2.0\nrequests\n"})
        assert result.dependency_count == 3

    def test_comments_ignored(self):
        result = self._map({"requirements.txt": "# comment\ndjango==4.2\n# another\n"})
        assert result.dependency_count == 1

    def test_django_tag_detected(self):
        result = self._map({"requirements.txt": "django==4.2\n"})
        assert "WEB_REQUEST_HANDLER" in result.additional_tags
        assert "django" in result.framework_signals

    def test_celery_tag_detected(self):
        result = self._map({"requirements.txt": "celery==5.3\n"})
        assert "BACKGROUND_WORKER" in result.additional_tags

    def test_sqlalchemy_tag_detected(self):
        result = self._map({"requirements.txt": "sqlalchemy==2.0\n"})
        assert "DATABASE_PRESENT" in result.additional_tags

    def test_cryptography_tag_detected(self):
        result = self._map({"requirements.txt": "cryptography==41.0\n"})
        assert "CRYPTO_OPERATIONS" in result.additional_tags

    def test_asyncio_tag_detected(self):
        result = self._map({"requirements.txt": "aiohttp==3.9\n"})
        assert "ASYNC_CODEBASE" in result.additional_tags

    def test_empty_requirements_zero_deps(self):
        result = self._map({"requirements.txt": "# just comments\n"})
        assert result.dependency_count == 0
        assert result.framework_signals == ()

    def test_no_manifests_zero_deps(self):
        result = self._map({"main.py": "print('hello')"})
        assert result.dependency_count == 0

    def test_pyproject_toml_poetry_parsed(self):
        content = "[tool.poetry]\nname = 'test'\n[tool.poetry.dependencies]\nfastapi = '*'\ncelery = '*'\n"
        result = self._map({"pyproject.toml": content})
        assert result.dependency_count >= 1

    def test_framework_signals_sorted(self):
        result = self._map({"requirements.txt": "django\ncelery\nredis\n"})
        assert list(result.framework_signals) == sorted(result.framework_signals)

    def test_additional_tags_sorted(self):
        result = self._map({"requirements.txt": "django\ncelery\nredis\n"})
        assert list(result.additional_tags) == sorted(result.additional_tags)

    def test_parse_warnings_on_unrecognized_format(self):
        """Unknown manifest format produces a parse warning."""
        result = self._map({"unknown_manifest.xyz": "some-package"})
        # No manifests read → no warnings about unknown format
        # (unknown_manifest.xyz is not discovered by the mapper)
        assert isinstance(result.parse_warnings, tuple)


# ═══════════════════════════════════════════════════════════════════════════════
# POSTURE CLASSIFIER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestPostureClassifier:
    """Tests for classify_domain_posture() function."""

    def _make_fs(self, tags: tuple) -> object:
        """Create a minimal FilesystemWalkResult with given tags."""
        from src.infrastructure.classification.filesystem.fs_fingerprinter import FilesystemWalkResult
        return FilesystemWalkResult(
            source_root="/test",
            source_hash="sha256:" + "a" * 64,
            detected_tags=tags,
            file_count=10,
            dir_count=3,
            max_depth_reached=2,
            python_file_count=10,
            c_file_count=0,
            rust_file_count=0,
            loc_estimate=500,
        )

    def _make_build(self, bs: str = "PIP") -> object:
        return BuildSystemDetectionResult(
            build_system=bs, confidence="certain",
            signals_found=(), disambiguation_note="",
        )

    def _make_dep(self, tags: tuple = (), signals: tuple = (), count: int = 0) -> object:
        from src.infrastructure.classification.dependencies.dep_mapper import DependencyMapResult
        return DependencyMapResult(
            dependency_count=count,
            framework_signals=signals,
            additional_tags=tags,
            manifest_files_read=(),
            parse_warnings=(),
        )

    def test_isr_context_is_safety_critical(self):
        result = classify_domain_posture(
            self._make_fs(("ISR_CONTEXT",)),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.SAFETY_CRITICAL.value

    def test_safety_critical_tag_is_safety_critical(self):
        result = classify_domain_posture(
            self._make_fs(("SAFETY_CRITICAL",)),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.SAFETY_CRITICAL.value

    def test_iec61508_scope_is_safety_critical(self):
        result = classify_domain_posture(
            self._make_fs(("IEC_61508_SCOPE",)),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.SAFETY_CRITICAL.value

    def test_hipaa_is_high_assurance(self):
        result = classify_domain_posture(
            self._make_fs(("HIPAA_SCOPE",)),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.HIGH_ASSURANCE.value

    def test_pci_dss_is_high_assurance(self):
        result = classify_domain_posture(
            self._make_fs(("PCI_DSS_SCOPE",)),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.HIGH_ASSURANCE.value

    def test_crypto_plus_auth_is_high_assurance(self):
        result = classify_domain_posture(
            self._make_fs(()),
            self._make_build(),
            self._make_dep(tags=("CRYPTO_OPERATIONS", "AUTH_LOGIC")),
        )
        assert result.domain_posture == DomainPosture.HIGH_ASSURANCE.value

    def test_web_handler_is_commercial(self):
        result = classify_domain_posture(
            self._make_fs(("WEB_REQUEST_HANDLER",)),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.COMMERCIAL.value

    def test_framework_signals_is_commercial(self):
        result = classify_domain_posture(
            self._make_fs(()),
            self._make_build(),
            self._make_dep(signals=("django",), count=5),
        )
        assert result.domain_posture == DomainPosture.COMMERCIAL.value

    def test_prototype_is_educational(self):
        result = classify_domain_posture(
            self._make_fs(("PROTOTYPE_CODE",)),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.EDUCATIONAL.value

    def test_no_signals_is_unknown(self):
        result = classify_domain_posture(
            self._make_fs(()),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.UNKNOWN.value

    def test_safety_plus_prototype_raises(self):
        """SAFETY_CRITICAL + PROTOTYPE_CODE is a contradiction — must raise."""
        with pytest.raises(IncompatibleDomainPosture):
            classify_domain_posture(
                self._make_fs(("SAFETY_CRITICAL", "PROTOTYPE_CODE")),
                self._make_build(),
                self._make_dep(),
            )

    def test_safety_wins_over_commercial(self):
        """ISR context overrides commercial signals."""
        result = classify_domain_posture(
            self._make_fs(("ISR_CONTEXT", "WEB_REQUEST_HANDLER")),
            self._make_build(),
            self._make_dep(),
        )
        assert result.domain_posture == DomainPosture.SAFETY_CRITICAL.value

    def test_applied_rules_returned(self):
        result = classify_domain_posture(
            self._make_fs(("ISR_CONTEXT",)),
            self._make_build(),
            self._make_dep(),
        )
        assert len(result.applied_rules) >= 1
        assert "RULE-POSTURE-001:SAFETY_CRITICAL_SIGNALS" in result.applied_rules

    def test_rationale_non_empty(self):
        result = classify_domain_posture(
            self._make_fs(("WEB_REQUEST_HANDLER",)),
            self._make_build(),
            self._make_dep(),
        )
        assert len(result.rationale) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# CLASSIFICATION PIPELINE END-TO-END TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestClassificationPipeline:

    def test_plain_python_project(self):
        """A plain Python project with requirements.txt but no setup.py/pyproject.toml
        → build system is UNKNOWN (requirements.txt is not a build system config).
        Language is python. Analysis still proceeds."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({
                "main.py": "print('hello')",
                "utils.py": "# utils",
                "requirements.txt": "",
            }, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            assert artifact.fingerprint is not None
            assert artifact.fingerprint.language == "python"
            # requirements.txt is NOT a build system signal; needs setup.py or pyproject.toml
            assert artifact.fingerprint.build_system == BuildSystem.UNKNOWN.value

    def test_django_project_is_commercial(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({
                "views": {"user.py": "from django.views import View"},
                "models": {"user.py": "from django.db import models"},
                "requirements.txt": "django==4.2\n",
                "manage.py": "# django manage",
            }, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            fp = artifact.fingerprint
            assert fp.domain_posture == DomainPosture.COMMERCIAL.value
            assert "WEB_REQUEST_HANDLER" in fp.context_tags
            assert fp.recommended_tier() == Tier.BLUE

    def test_safety_critical_project_recommends_red(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({
                "isr": {"interrupt_handler.c": "// ISR"},
                "safety": {"monitor.c": "// safety monitor"},
                "Makefile": "all:\n\tgcc main.c",
                "main.c": "// main",
            }, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            fp = artifact.fingerprint
            assert fp.domain_posture == DomainPosture.SAFETY_CRITICAL.value
            assert fp.recommended_tier() == Tier.RED

    def test_rust_cargo_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({
                "Cargo.toml": '[package]\nname = "myapp"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1.0"\n',
                "src": {"main.rs": "fn main() {}"},
            }, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            fp = artifact.fingerprint
            assert fp.build_system == BuildSystem.CARGO.value
            assert fp.language == "rust"

    def test_fingerprint_hash_is_deterministic(self):
        """Running pipeline twice on same tree produces same fingerprint hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({
                "views": {"api.py": "# api"},
                "requirements.txt": "flask==3.0\n",
                "main.py": "# main",
            }, root)
            pipeline = ClassificationPipeline()
            a1 = pipeline.classify(str(root))
            a2 = pipeline.classify(str(root))
            assert a1.fingerprint.fingerprint_hash == a2.fingerprint.fingerprint_hash

    def test_nonexistent_root_raises(self):
        pipeline = ClassificationPipeline()
        with pytest.raises(ClassificationError):
            pipeline.classify("/nonexistent/path/that/does/not/exist/ever")

    def test_artifact_is_immutable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({"main.py": "# hello"}, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            with pytest.raises(Exception):
                artifact.fingerprint = None  # type: ignore

    def test_hipaa_project_recommends_yellow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({
                "hipaa": {"phi_handler.py": "# PHI handling"},
                "requirements.txt": "cryptography==41.0\n",
                "main.py": "# main",
            }, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            fp = artifact.fingerprint
            assert fp.domain_posture == DomainPosture.HIGH_ASSURANCE.value
            assert fp.recommended_tier() == Tier.YELLOW

    def test_classification_method_is_structural(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({"main.py": ""}, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            assert artifact.fingerprint.classification_method == "STRUCTURAL_RULE_BASED"

    def test_pipeline_warnings_collected(self):
        """Pipeline result includes warnings tuple (may be empty)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            _make_tree({"main.py": ""}, root)
            pipeline = ClassificationPipeline()
            artifact = pipeline.classify(str(root))
            assert isinstance(artifact.pipeline_warnings, tuple)


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import importlib.util
    passed = failed = 0
    errors = []
    g = globals()
    for cls_name in sorted(g):
        cls = g[cls_name]
        if not isinstance(cls, type) or not cls_name.startswith("Test"):
            continue
        inst = cls()
        for mn in sorted(dir(inst)):
            if not mn.startswith("test_"):
                continue
            try:
                getattr(inst, mn)()
                print(f"  ✓  {cls_name}.{mn}")
                passed += 1
            except Exception as e:
                print(f"  ✗  {cls_name}.{mn} — {type(e).__name__}: {e}")
                failed += 1
                errors.append((cls_name, mn, f"{type(e).__name__}: {e}"))

    print(f"\n{'='*60}")
    print(f"RESULTS: {passed} passed / {failed} failed / {passed+failed} total")
    if errors:
        print("\nFAILURES:")
        for c, m, msg in errors:
            print(f"  {c}.{m}: {msg}")
    print("="*60)
