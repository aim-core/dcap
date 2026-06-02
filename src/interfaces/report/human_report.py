"""
******************************************************************************
 * FILE:        /src/interfaces/report/human_report.py
 * LAYER:       Interfaces Layer
 * MODULE:      Human-First Report Translator
 * PURPOSE:     Convert internal findings to plain English (10-second reads)
 * DOMAIN:      Interfaces
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-19
 * UPDATED:     2026-05-19
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Gold extraction layer. Takes DCAVP internal findings (CEF Artifacts,
 * construct IDs, detected states) and translates them into plain English
 * that a human understands in 10 seconds without reading documentation.
 *
 * No CEF artifacts exposed. No construct IDs. No architecture jargon.
 * Input: TierAnalysisResult → Output: HumanReport with plain-English findings.
 *
 * DEPENDENCIES: src/application/tier/tier_engine.py (TierAnalysisResult)
 * CONSTRAINTS:  Read-only access to tier_result; no mutation
 * DETERMINISM:  Same findings → same translation (pure function)
 * LICENSE:      Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


# Plain-English translations for every construct + state combination
_TRANSLATIONS: dict[str, dict[str, dict]] = {
    "CONST-EVAL-001": {
        "dynamic_arg": {
            "headline": "Your code executes user input as code",
            "plain":    "An attacker can type anything — delete files, steal data, crash your server.",
            "fix":      "Replace eval() with json.loads() or ast.literal_eval()",
            "emoji":    "💀",
            "severity": "critical",
        },
        "constant_arg": {
            "headline": "eval() used with a fixed string",
            "plain":    "Not immediately dangerous, but eval() is a bad habit that gets exploited.",
            "fix":      "Write the logic directly in Python instead of evaluating a string.",
            "emoji":    "⚠️",
            "severity": "warning",
        },
        "external_source_arg": {
            "headline": "External data flows directly into code execution",
            "plain":    "Network/user data reaches eval() — this is a critical attack surface.",
            "fix":      "Remove eval(). Parse data with json.loads() or a schema validator.",
            "emoji":    "💀",
            "severity": "critical",
        },
    },
    "CONST-EXEC-001": {
        "dynamic_arg": {
            "headline": "Your code runs arbitrary strings as Python programs",
            "plain":    "exec() is more powerful than eval() — it can redefine any function in your app.",
            "fix":      "Remove exec() completely. No legitimate production use case exists.",
            "emoji":    "💀",
            "severity": "critical",
        },
        "constant_arg": {
            "headline": "exec() used with a fixed string",
            "plain":    "The string is safe today, but exec() invites future security mistakes.",
            "fix":      "Replace with direct Python code.",
            "emoji":    "⚠️",
            "severity": "warning",
        },
    },
    "CONST-PICK-001": {
        "loads_untrusted_source": {
            "headline": "Dangerous data deserialization from untrusted source",
            "plain":    "pickle can execute any Python code hidden inside its data. One crafted file = full takeover.",
            "fix":      "Use json.loads() instead. Never unpickle data you didn't create yourself.",
            "emoji":    "💀",
            "severity": "critical",
        },
        "loads_network_data": {
            "headline": "Network data deserialized with pickle — critical RCE risk",
            "plain":    "Anyone who can send data to your app can run code on your server.",
            "fix":      "Replace pickle with json, protobuf, or msgpack.",
            "emoji":    "💀",
            "severity": "critical",
        },
        "loads_trusted_source": {
            "headline": "pickle used — verify source is always internal",
            "plain":    "pickle is safe only with data you created. One external file slipping through = disaster.",
            "fix":      "Consider json or protobuf for long-term safety.",
            "emoji":    "⚠️",
            "severity": "warning",
        },
    },
    "CONST-SUBP-001": {
        "shell_true_dynamic_cmd": {
            "headline": "Shell commands built from external input",
            "plain":    "A semicolon or pipe in user input runs arbitrary system commands on your server.",
            "fix":      "Remove shell=True. Pass arguments as a list: subprocess.run(['cmd', arg])",
            "emoji":    "💀",
            "severity": "critical",
        },
        "shell_true_constant_cmd": {
            "headline": "subprocess runs with shell=True",
            "plain":    "shell=True is unnecessary for fixed commands and creates future injection risk.",
            "fix":      "Remove shell=True. Use: subprocess.run(['ls', '-la'])",
            "emoji":    "⚠️",
            "severity": "warning",
        },
        "shell_false_dynamic_args": {
            "headline": "External data passed to subprocess",
            "plain":    "Dynamic args to subprocess can be exploited even without shell=True.",
            "fix":      "Validate and sanitize all inputs. Use an allowlist of allowed values.",
            "emoji":    "⚠️",
            "severity": "warning",
        },
    },
    "CONST-RAND-001": {
        "used_for_security": {
            "headline": "Weak random numbers used for security tokens",
            "plain":    "Python's random is predictable. An attacker can guess your tokens after seeing a few.",
            "fix":      "Replace random.hex() with secrets.token_hex(32)",
            "emoji":    "🔓",
            "severity": "critical",
        },
        "unseeded_or_default_seed": {
            "headline": "Unpredictable random without explicit seed",
            "plain":    "Output changes every run — not suitable for reproducible behavior.",
            "fix":      "Set random.seed(42) for reproducibility, or use secrets for security.",
            "emoji":    "⚠️",
            "severity": "warning",
        },
    },
    "CONST-OPEN-001": {
        "path_traversal_possible": {
            "headline": "File paths come from user input — directory traversal risk",
            "plain":    "A user sending '../../../etc/passwd' could read any file on your server.",
            "fix":      "Validate: path = pathlib.Path(user_input).resolve()\nif not path.is_relative_to(ALLOWED_DIR): raise PermissionError",
            "emoji":    "🔓",
            "severity": "critical",
        },
        "not_used_as_context_manager": {
            "headline": "File opened without 'with' — may not close properly",
            "plain":    "If an error occurs, the file stays open. Under load this causes resource exhaustion.",
            "fix":      "Use: with open('file.txt') as f: ...",
            "emoji":    "⚠️",
            "severity": "warning",
        },
        "used_as_context_manager": {
            "headline": "File opened safely as context manager",
            "plain":    "Good practice — file will close automatically.",
            "fix":      "No action needed.",
            "emoji":    "✅",
            "severity": "info",
        },
    },
    "CONST-GLOB-001": {
        "write_global": {
            "headline": "Shared global variable modified in function",
            "plain":    "In web apps and threaded code, this causes data corruption between requests.",
            "fix":      "Pass data as function arguments, or use thread-local storage.",
            "emoji":    "⚠️",
            "severity": "warning",
        },
        "read_only_global": {
            "headline": "Global variable accessed (read-only)",
            "plain":    "Reading globals is safer, but consider dependency injection for testability.",
            "fix":      "Move to a config object or function parameter if possible.",
            "emoji":    "💡",
            "severity": "info",
        },
    },
    "CONST-THRD-001": {
        "daemon_thread": {
            "headline": "Background thread killed without cleanup on exit",
            "plain":    "Daemon threads are killed immediately when the app exits — mid-operation, no cleanup.",
            "fix":      "Use daemon=False and call .join() to wait for completion.",
            "emoji":    "⚠️",
            "severity": "warning",
        },
        "detached_not_joined": {
            "headline": "Thread started but never waited for",
            "plain":    "If the thread fails or leaks, your app won't know. Causes silent data loss at scale.",
            "fix":      "Call thread.join() or use concurrent.futures.ThreadPoolExecutor()",
            "emoji":    "⚠️",
            "severity": "warning",
        },
    },
    "CONST-LOCK-001": {
        "acquired_without_context_manager": {
            "headline": "Lock acquired manually — deadlock risk if exception occurs",
            "plain":    "If an error happens before lock.release(), your entire app freezes permanently.",
            "fix":      "Use: with lock: ... instead of lock.acquire()/release()",
            "emoji":    "⚠️",
            "severity": "warning",
        },
        "acquired_with_context_manager": {
            "headline": "Lock used correctly as context manager",
            "plain":    "Good — lock will release automatically even if an error occurs.",
            "fix":      "No action needed.",
            "emoji":    "✅",
            "severity": "info",
        },
    },
    "CONST-ASYNC-001": {
        "unawaited": {
            "headline": "Async function called but result never awaited",
            "plain":    "The operation runs but you never get the result. Silent data loss in production.",
            "fix":      "Add 'await': result = await your_function()",
            "emoji":    "⚠️",
            "severity": "warning",
        },
    },
}

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


@dataclass
class HumanFinding:
    """A finding a human can understand in 5 seconds."""
    emoji:      str
    headline:   str
    plain:      str
    fix:        str
    severity:   str
    location:   str       # "file.py line 42"
    construct:  str       # "eval()"
    confidence: str


@dataclass
class HumanReport:
    """The complete human-readable report."""
    score:          int              # 0-100
    grade:          str              # A / B / C / D / F
    verdict:        str              # one sentence
    status:         str              # SAFE / REVIEW / DANGER
    status_color:   str              # green / yellow / red
    findings:       list[HumanFinding]
    critical_count: int
    warning_count:  int
    files_analyzed: int
    top_fix:        str              # The single most important action
    shareable_line: str              # One line to paste in Slack/Discord


def translate_findings(tier_result, files_analyzed: int = 1) -> HumanReport:
    """
    Convert internal DCAVP findings into human-readable report.
    This is the gold extraction layer.
    """
    if tier_result.artifact is None:
        return _error_report()

    findings = []
    for f in tier_result.artifact.findings:
        translation = (
            _TRANSLATIONS
            .get(f.construct_id, {})
            .get(f.detected_state)
        )
        if translation is None:
            # Fallback for unknown states
            translation = {
                "headline": f"{f.construct_name} — potential issue detected",
                "plain":    f"State '{f.detected_state}' detected. Review manually.",
                "fix":      "Review this usage and ensure inputs are validated.",
                "emoji":    "⚠️" if f.severity == "warning" else "🔴",
                "severity": f.severity,
            }

        # Format location for humans: "src/app.py line 42"
        loc_parts = f.canonical_location.split(":")
        if len(loc_parts) >= 2:
            filepath = loc_parts[0].split("/")[-1]   # just filename
            line_num = loc_parts[1]
            location = f"{filepath} line {line_num}"
        else:
            location = f.canonical_location.split("/")[-1]

        findings.append(HumanFinding(
            emoji=translation["emoji"],
            headline=translation["headline"],
            plain=translation["plain"],
            fix=translation["fix"],
            severity=translation["severity"],
            location=location,
            construct=f"{f.construct_name}()",
            confidence=f.confidence,
        ))

    # Sort: critical first, then warning, then info
    findings.sort(key=lambda x: _SEVERITY_ORDER.get(x.severity, 9))

    critical_count = sum(1 for f in findings if f.severity == "critical")
    warning_count  = sum(1 for f in findings if f.severity == "warning")

    # Score calculation (simple, understandable)
    score = 100
    score -= critical_count * 20
    score -= warning_count  * 5
    score = max(0, min(100, score))

    # Grade
    if score >= 90:   grade, status, color = "A", "SAFE",   "green"
    elif score >= 75: grade, status, color = "B", "SAFE",   "green"
    elif score >= 60: grade, status, color = "C", "REVIEW", "yellow"
    elif score >= 40: grade, status, color = "D", "REVIEW", "yellow"
    else:             grade, status, color = "F", "DANGER", "red"

    # Override: any critical = minimum REVIEW
    if critical_count > 0:
        status, color = "DANGER", "red"
        if grade in ("A", "B"):
            grade = "D"

    # Verdict — one sentence
    if critical_count == 0 and warning_count == 0:
        verdict = "This code looks clean — no security issues found."
    elif critical_count > 0:
        issues = f"{critical_count} critical issue{'s' if critical_count > 1 else ''}"
        if warning_count > 0:
            issues += f" and {warning_count} warning{'s' if warning_count > 1 else ''}"
        verdict = f"Do not ship — {issues} found that attackers can exploit."
    else:
        verdict = f"{warning_count} warning{'s' if warning_count > 1 else ''} found — review before production."

    # Top fix — most important action
    top_fix = findings[0].fix if findings else "No action needed."

    # Shareable line
    badge = {"SAFE": "✅ SAFE", "REVIEW": "⚠️ REVIEW", "DANGER": "🔴 DANGER"}[status]
    shareable = f"DCAVP scan: {badge} | Score {score}/100 | {critical_count} critical, {warning_count} warnings"

    return HumanReport(
        score=score,
        grade=grade,
        verdict=verdict,
        status=status,
        status_color=color,
        findings=findings,
        critical_count=critical_count,
        warning_count=warning_count,
        files_analyzed=files_analyzed,
        top_fix=top_fix,
        shareable_line=shareable,
    )


def _error_report() -> HumanReport:
    return HumanReport(
        score=0, grade="F", verdict="Analysis failed to complete.",
        status="ERROR", status_color="red", findings=[],
        critical_count=0, warning_count=0, files_analyzed=0,
        top_fix="Check that your code is valid Python.",
        shareable_line="DCAVP scan: ❌ ERROR — analysis failed",
    )
