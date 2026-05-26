"""
******************************************************************************
 * FILE:        /src/application/supply_chain/package_verifier.py
 * LAYER:       Application Layer
 * MODULE:      Package Hallucination Verifier
 * PURPOSE:     Detect AI-hallucinated package imports via PyPI verification
 * DOMAIN:      Supply Chain
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-24
 * UPDATED:     2026-05-24
 * VERSION:     v0.4.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
import ast
import pathlib
"""
PyPI package verification for AI hallucination detection.
"""

import json
import urllib.request
import urllib.error
import pathlib
import sys

# Standard library modules — never hallucinated
STDLIB_MODULES = frozenset({
    "os", "sys", "json", "re", "math", "random", "datetime", "pathlib",
    "ast", "hashlib", "base64", "csv", "io", "time", "collections",
    "itertools", "functools", "typing", "dataclasses", "enum", "abc",
    "logging", "argparse", "subprocess", "threading", "asyncio",
    "http", "urllib", "socket", "ssl", "email", "xml", "html",
    "unittest", "doctest", "pdb", "traceback", "warnings",
    "pickle", "marshal", "shelve", "sqlite3", "struct", "codecs",
    "decimal", "fractions", "statistics", "copy", "pprint", "textwrap",
    "string", "types", "inspect", "importlib", "pkgutil", "venv",
    "webbrowser", "uuid", "secrets", "platform", "locale", "gettext",
    "ctypes", "gc", "atexit", "signal", "mmap", "sysconfig",
    "tempfile", "shutil", "glob", "fnmatch", "linecache", "pickle",
})

# Verified popular packages (cached to avoid API calls)
VERIFIED_PACKAGES = {
    "flask", "django", "fastapi", "requests",
    "yaml",  # PyYAML "numpy", "pandas",
    "pytest", "black", "pylint", "mypy", "ruff", "bandit",
    "sqlalchemy", "alembic", "psycopg2", "redis", "celery",
    "pydantic", "click", "rich", "typer", "uvicorn", "gunicorn",
    "boto3", "google-cloud", "azure", "docker", "kubernetes",
    "torch", "tensorflow", "transformers", "scikit-learn", "pillow",
    "opencv-python", "matplotlib", "plotly", "jupyter", "ipython",
    "pyyaml",
    "yaml",  # Import name differs from package name
    "yaml",  # PyYAML import name "toml", "httpx", "aiohttp", "websockets",
    "cryptography", "bcrypt", "passlib", "pyjwt", "oauthlib",
    "python-dotenv", "faker", "factory-boy", "freezegun",
    "pendulum", "arrow", "marshmallow", "cerberus", "jsonschema",
    "beautifulsoup4", "lxml", "scrapy", "selenium",
    "openpyxl", "xlsxwriter", "pdfplumber", "reportlab",
    "stripe", "twilio", "sendgrid", "slack-sdk", "discord-py",
    "gitpython", "pygithub", "boto3", "paramiko", "fabric",
}

def is_stdlib(module_name: str) -> bool:
    """Check if module is in Python standard library."""
    return module_name.split(".")[0] in STDLIB_MODULES

def is_local_import(module_name: str) -> bool:
    """Check if import is local (starts with .)"""
    return module_name.startswith(".")

def is_verified(module_name: str) -> bool:
    """Check if package is in verified cache."""
    base = module_name.split(".")[0].replace("_", "-").lower()
    return base in VERIFIED_PACKAGES

_PYPI_CACHE = {}

def check_pypi(package_name: str) -> bool:
    base = package_name.split(".")[0]
    if base in _PYPI_CACHE:
        return _PYPI_CACHE[base]
    """Check if package exists on PyPI. Returns True if exists."""
    base = package_name.split(".")[0]
    
    if is_stdlib(base) or is_local_import(base) or is_verified(base):
        return True
    
    try:
        _PYPI_CACHE[base] = True  # Assume exists, will correct if 404
        url = f"https://pypi.org/pypi/{base}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "DCAVP/0.3.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.getcode() == 200:
                VERIFIED_PACKAGES.add(base)
                _PYPI_CACHE[base] = True
                return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
    except Exception:
        pass
    
    return None  # Unknown — network error

def detect_hallucinated_imports(source_file: str) -> list[dict]:
    """
    Scan a Python file for hallucinated imports.
    Returns list of findings.
    """
    findings = []
    
    try:
        tree = ast.parse(pathlib.Path(source_file).read_text(encoding="utf-8"))
    except Exception:
        return findings
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if is_local_import(name):
                    continue
                if is_stdlib(name):
                    continue
                if is_verified(name):
                    continue
                
                exists = check_pypi(name)
                if exists is False:
                    findings.append({
                        "package": name,
                        "line": node.lineno,
                        "col": node.col_offset,
                        "type": "ai_hallucinated_package",
                        "severity": "critical",
                        "message": f"Package '{name}' does not exist on PyPI. This may be an AI hallucination. Attackers could create this package.",
                    })
        
        elif isinstance(node, ast.ImportFrom):
            if node.module and not is_local_import(node.module or ""):
                name = (node.module or "").split(".")[0]
                if is_stdlib(name) or is_verified(name):
                    continue
                
                exists = check_pypi(name)
                if exists is False:
                    findings.append({
                        "package": node.module,
                        "line": node.lineno,
                        "col": node.col_offset,
                        "type": "ai_hallucinated_package",
                        "severity": "critical",
                        "message": f"Package '{node.module}' does not exist on PyPI.",
                    })
    
    return findings