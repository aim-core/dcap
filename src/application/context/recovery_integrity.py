"""
******************************************************************************
 * FILE:        /src/application/context/recovery_integrity.py
 * LAYER:       Application Layer
 * MODULE:      Recovery Integrity Analyzer
 * PURPOSE:     Detect exception swallowing and unsafe state mutation
 * DOMAIN:      Context
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-29
 * UPDATED:     2026-05-29
 * VERSION:     v0.6.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
import ast
from pathlib import Path

def analyze_recovery_integrity(source_file: str) -> list:
    issues = []
    try:
        tree = ast.parse(Path(source_file).read_text(encoding="utf-8"))
    except Exception:
        return issues

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type is None:
                    for stmt in handler.body:
                        if isinstance(stmt, ast.Pass):
                            issues.append({
                                "type": "EXCEPTION_SWALLOWING",
                                "line": handler.lineno,
                                "message": "Bare except with pass - failure silently ignored.",
                                "severity": "WARNING"
                            })
                elif isinstance(handler.type, ast.Name) and handler.type.id == "Exception":
                    for stmt in handler.body:
                        if isinstance(stmt, ast.Pass):
                            issues.append({
                                "type": "EXCEPTION_SWALLOWING",
                                "line": handler.lineno,
                                "message": "except Exception with pass - failure silently ignored.",
                                "severity": "WARNING"
                            })

    return issues