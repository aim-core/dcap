"""
******************************************************************************
 * FILE:        /src/application/explainability/explainability_engine.py
 * LAYER:       Application Layer
 * MODULE:      Multi-Audience Explainability Engine
 * PURPOSE:     Translate findings into gateway-appropriate explanations
 * DOMAIN:      Trust Infrastructure
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-14
 * UPDATED:     2026-05-14
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * DELTA EXTENSION — wraps Finding objects; does not modify them.
 *
 * Same finding → 4 different explanations by gateway level (Directive §28):
 *
 *   GREEN  — Simple language for hobbyists and beginners
 *   YELLOW — Engineering explanation for developers
 *   BLUE   — Architectural + operational impact for enterprises
 *   RED    — Safety, compliance, liability impact for critical systems
 *
 * Explanation templates are DATA, not logic. The engine selects and
 * populates templates deterministically based on (construct_id, severity, tier).
 *
 * CONSTRAINTS:
 *   - Pure function: no I/O, no database, no external calls
 *   - Templates keyed by (construct_id, gateway) — deterministic lookup
 *   - Finding is never modified (read-only access)
 *   - All text is NFC-normalized before storage
 *
 * DETERMINISM: same (finding, gateway) → identical ExplainedFinding
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Optional


# ─── Gateway Levels ───────────────────────────────────────────────────────────

class Gateway:
    GREEN  = "GREEN"
    YELLOW = "YELLOW"
    BLUE   = "BLUE"
    RED    = "RED"


# ─── Explanation Templates ────────────────────────────────────────────────────
# Format: {construct_id: {gateway: {severity_bucket: (short, detail, fix)}}}
# severity_bucket: "critical_or_error" | "warning" | "info"

_TEMPLATES: dict[str, dict[str, dict[str, tuple[str, str, str]]]] = {

    "CONST-EVAL-001": {
        Gateway.GREEN: {
            "critical_or_error": (
                "⚠️ Danger: your code can run unknown commands",
                "You're using something called eval(). It's like letting a stranger "
                "type commands directly into your computer. This is very dangerous.",
                "Replace eval() with json.loads() for data, or write the logic directly.",
            ),
            "warning": (
                "💡 Tip: avoid using eval()",
                "eval() with a fixed string still creates a bad habit. Better alternatives exist.",
                "Write the expression directly or use ast.literal_eval() for safe evaluation.",
            ),
        },
        Gateway.YELLOW: {
            "critical_or_error": (
                "🔧 eval() — Code Injection Surface",
                "eval() accepts arbitrary Python expressions. With user-controlled input, "
                "an attacker achieves Remote Code Execution (RCE). "
                "OWASP A03:2021 — Injection. CWE-94.",
                "Replace with json.loads() for data parsing, ast.literal_eval() for literals, "
                "or refactor logic to eliminate dynamic evaluation.",
            ),
        },
        Gateway.BLUE: {
            "critical_or_error": (
                "🏗️ Architectural Risk: Code Injection in Request Path",
                "eval() in a request handler creates a system-wide RCE surface. "
                "An attacker bypassing input validation gains full process execution context, "
                "enabling lateral movement to databases and internal services. "
                "Architectural impact: all instances exposed simultaneously.",
                "Architectural fix: replace eval() with a safe parser at the boundary layer. "
                "Add input validation middleware. Conduct full audit of all request handlers.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ Safety Violation: Dynamic Code Execution Prohibited",
                "eval() is classified as CATASTROPHIC in safety-critical systems. "
                "IEC 61508-3 Clause 7.4.4 prohibits dynamic code generation. "
                "ISO 26262-6 Table 1 classifies this as ASIL D violation. "
                "DO-178C Section 6.3.4 requires all executable code to be statically verifiable. "
                "This construct CANNOT be certified.",
                "Complete removal required. File a waiver request with dual-control approval "
                "if any dynamic dispatch is architecturally necessary. "
                "Analysis blocked until remediation is confirmed.",
            ),
        },
    },

    "CONST-PICK-001": {
        Gateway.GREEN: {
            "critical_or_error": (
                "⚠️ Dangerous: opening untrusted data packages",
                "pickle is like opening a mystery box that can run anything inside it. "
                "If someone sends you a bad pickle, your computer does whatever it says.",
                "Use json instead of pickle. json.loads() is safe for data exchange.",
            ),
        },
        Gateway.YELLOW: {
            "critical_or_error": (
                "🔧 Unsafe Deserialization — RCE Vector",
                "pickle.loads() executes Python bytecode during deserialization (by design). "
                "A crafted payload calls os.system() or subprocess.Popen() without any check. "
                "CWE-502: Deserialization of Untrusted Data. OWASP A08:2021.",
                "Use json.loads(), msgpack, or protobuf. Never deserialize pickle from "
                "network or user-controlled sources.",
            ),
        },
        Gateway.BLUE: {
            "critical_or_error": (
                "🏗️ Critical: Deserialization Attack Surface in Data Pipeline",
                "pickle.loads() in a data pipeline allows supply-chain attacks: "
                "any upstream data provider can compromise all downstream consumers. "
                "Attack vector: network (CVSS:3.1/AV:N). No authentication bypasses this.",
                "Replace with protobuf or JSON schema validation at all pipeline boundaries. "
                "Implement strict input validation with schema enforcement at ingestion.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ Certification Blocker: Unsafe Deserialization",
                "pickle.loads() cannot be present in any safety-certified software. "
                "IEC 62443-3-3 SR 3.4 prohibits unauthorized code execution channels. "
                "This constitutes a Severity 1 (catastrophic) finding under IEC 61508.",
                "Immediate removal required. Dual-control sign-off needed for any exception.",
            ),
        },
    },

    "CONST-SUBP-001": {
        Gateway.GREEN: {
            "critical_or_error": (
                "⚠️ Risk: running external commands with user data",
                "subprocess with shell=True lets users type system commands. "
                "This can delete files, steal data, or break your server.",
                "Remove shell=True. Use subprocess.run(['cmd', arg1, arg2]) instead.",
            ),
        },
        Gateway.YELLOW: {
            "critical_or_error": (
                "🔧 OS Command Injection — CWE-78",
                "subprocess with shell=True interprets shell metacharacters. "
                "Input containing ';', '|', '&&', or backticks enables injection. "
                "OWASP A03:2021. Bandit B602: HIGH/HIGH.",
                "Use subprocess.run(cmd_list, shell=False). Validate all inputs before passing.",
            ),
        },
        Gateway.BLUE: {
            "critical_or_error": (
                "🏗️ OS Command Injection — System-Wide Exposure",
                "shell=True in a web context allows OS command injection through any "
                "API endpoint receiving this input. Full system compromise enables "
                "lateral movement to all services in the same network segment.",
                "Architectural remediation: remove shell=True platform-wide. "
                "Implement a subprocess abstraction layer with allowlisted commands only.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ Prohibited: External Process Execution with Dynamic Input",
                "DO-178C §6.3.3 and IEC 61508-3 §7.4.4 prohibit unverifiable external "
                "process calls in certified software. This is a Severity 1 finding.",
                "Complete elimination required. Static command allowlist with dual-control review.",
            ),
        },
    },

    "CONST-RAND-001": {
        Gateway.GREEN: {
            "critical_or_error": (
                "⚠️ Weak randomness for security",
                "random is like rolling a predictable dice — it's not truly random. "
                "For passwords, tokens, or secret keys, use the secrets module instead.",
                "Replace random.hex() with secrets.token_hex() for security purposes.",
            ),
            "warning": (
                "💡 Use explicit seed for reproducibility",
                "Random without a seed produces different results each run. "
                "Set a seed for reproducible simulations.",
                "Add random.seed(42) at the start of your simulation.",
            ),
        },
        Gateway.YELLOW: {
            "critical_or_error": (
                "🔧 Cryptographically Weak PRNG — CWE-338",
                "random uses Mersenne Twister (MT19937). Its state is recoverable "
                "after observing 624 outputs. Tokens generated with random are forgeable. "
                "FIPS 140-3 prohibits MT19937 for cryptographic use.",
                "Use secrets.token_hex(32) for tokens. Use os.urandom() for key material.",
            ),
        },
        Gateway.BLUE: {
            "critical_or_error": (
                "🏗️ Authentication Token Weakness — Forgeable Sessions",
                "MT19937 token predictability allows session hijacking at scale. "
                "An attacker observing N tokens can reconstruct state and predict all "
                "future tokens, compromising all active sessions simultaneously.",
                "Platform-wide: replace all auth token generation with secrets module. "
                "Rotate all existing tokens immediately after deployment.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ FIPS 140-3 Non-Compliance: Non-Approved DRBG",
                "MT19937 is not an approved Deterministic Random Bit Generator under "
                "FIPS 140-3. Any system requiring FIPS compliance cannot use random module "
                "for security purposes. NIST SP 800-90A requires CTR_DRBG or HASH_DRBG.",
                "Use os.urandom() or secrets module (backed by OS CSPRNG). "
                "Document CSPRNG selection in the security plan.",
            ),
        },
    },

    "CONST-EXEC-001": {
        Gateway.GREEN: {
            "critical_or_error": (
                "⚠️ Very dangerous: running code as text",
                "exec() lets text become executable code. Attackers can use this "
                "to take over your program completely.",
                "Remove exec() entirely. Write the logic directly in Python.",
            ),
        },
        Gateway.YELLOW: {
            "critical_or_error": (
                "🔧 Arbitrary Code Execution — CWE-94",
                "exec() is more powerful than eval(): it executes statements, "
                "defines functions, imports modules. Any controlled input enables RCE. "
                "Bandit B102: HIGH/HIGH.",
                "Eliminate exec() completely. No production justification exists.",
            ),
        },
        Gateway.BLUE: {
            "critical_or_error": (
                "🏗️ Catastrophic: Full Runtime Code Injection",
                "exec() in production represents complete loss of code integrity. "
                "An attacker with exec() access can redefine any function, "
                "import malicious modules, and persist across restarts.",
                "Immediate removal. Architectural review of all dynamic dispatch patterns.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ exec() is Unconditionally Prohibited",
                "No safety standard permits exec() in certified software. "
                "IEC 61508, ISO 26262, DO-178C, IEC 62443 all prohibit runtime "
                "code generation. Analysis halted. Dual-control exemption required.",
                "Complete removal. File remediation report before re-analysis.",
            ),
        },
    },

    "CONST-GLOB-001": {
        Gateway.GREEN: {
            "warning": (
                "💡 Shared data can cause surprises",
                "global variables are shared across all function calls. "
                "This can cause unexpected behavior, especially in web apps.",
                "Pass data as function arguments instead of using global.",
            ),
            "critical_or_error": (
                "⚠️ Shared data modified unsafely",
                "Modifying a global variable from multiple places causes unpredictable bugs.",
                "Use a class or pass the value as a parameter.",
            ),
        },
        Gateway.YELLOW: {
            "critical_or_error": (
                "🔧 Global Mutable State — Race Condition Risk (CWE-362)",
                "Writing to global variables in threaded/async code creates race conditions. "
                "Python GIL protects reference counts but NOT application-level data. "
                "MISRA C:2012 Rule 8.7.",
                "Replace globals with dependency injection or thread-local storage.",
            ),
        },
        Gateway.BLUE: {
            "critical_or_error": (
                "🏗️ Global State — Testing and Scaling Risk",
                "Global mutable state breaks horizontal scaling (state not shared across "
                "instances) and makes unit testing impossible without full state reset. "
                "In concurrent request handlers, global writes cause data races.",
                "Refactor to request-scoped context or dependency injection. "
                "Consider Redis or distributed cache for cross-instance state.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ Shared Mutable State — Prohibited in Safety-Critical Paths",
                "IEC 61508-3 Section 7.4.5 prohibits unprotected shared state in "
                "concurrent safety-critical systems. MISRA C:2012 Rule 8.7 prohibits "
                "external linkage for single-TU objects.",
                "Eliminate or protect with mutex + timeout. Formal concurrency analysis required.",
            ),
        },
    },

    "CONST-ASYNC-001": {
        Gateway.GREEN: {
            "warning": (
                "💡 Your async function is not being waited for",
                "You created an async function but forgot to await it. "
                "The function ran but its result was silently thrown away.",
                "Add 'await' before the function call: result = await your_function()",
            ),
        },
        Gateway.YELLOW: {
            "warning": (
                "🔧 Unawaited Coroutine — Silent Task Loss",
                "Creating a coroutine without awaiting it produces a RuntimeWarning "
                "and silently discards the operation. This causes invisible bugs in "
                "async pipelines. asyncio documentation §Coroutines-and-Tasks.",
                "Add await, or use asyncio.create_task() if parallel execution is intended.",
            ),
        },
        Gateway.BLUE: {
            "warning": (
                "🏗️ Async Contract Violation — Operation Silently Dropped",
                "Unawaited coroutines in production systems cause silent operation failure: "
                "database writes not committed, notifications not sent, audit logs missing. "
                "These failures are invisible without explicit coroutine tracking.",
                "Implement coroutine lifecycle tracking. Use structured concurrency (anyio/trio). "
                "Add asyncio debug mode to catch unawaited coroutines in staging.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ Async Operation Loss — Safety Path Integrity Violation",
                "In safety-critical systems, silent operation loss is classified as "
                "a Severity 2 (Critical) failure under IEC 61508. "
                "Any unawaited coroutine in a safety path requires formal verification.",
                "Prove all async operations complete or are explicitly cancelled. "
                "Formal verification of async flow required before certification.",
            ),
        },
    },

    "CONST-OPEN-001": {
        Gateway.GREEN: {
            "critical_or_error": (
                "⚠️ File path from user can access other files",
                "If a user controls the file path, they might read files they shouldn't. "
                "Like asking for 'invoice.pdf' but getting '../../passwords.txt'.",
                "Validate and restrict the path before opening. Use pathlib.Path().resolve().",
            ),
            "warning": (
                "💡 File not properly closed",
                "If an error happens, your file might not get closed properly. "
                "Use 'with open(...) as f:' to ensure it always closes.",
                "Change to: with open('filename') as f: ...",
            ),
        },
        Gateway.YELLOW: {
            "critical_or_error": (
                "🔧 Path Traversal — CWE-22",
                "User-controlled file path enables '../' traversal to read arbitrary files. "
                "An attacker reads /etc/passwd, ~/.ssh/id_rsa, or application secrets.",
                "Use pathlib.Path(user_input).resolve() and verify it's within the allowed root. "
                "Never construct file paths from user input without strict validation.",
            ),
        },
        Gateway.BLUE: {
            "critical_or_error": (
                "🏗️ Path Traversal — Credential and Config Exfiltration Risk",
                "Path traversal in an API handler enables automated scanning for "
                "credentials, TLS keys, and configuration files across all server instances. "
                "CVSS 3.1 score: 7.5 (HIGH) for unauthenticated path traversal.",
                "Implement a file serving abstraction with strict allowlisted paths. "
                "Audit all file I/O in request handlers for user-controlled components.",
            ),
        },
        Gateway.RED: {
            "critical_or_error": (
                "🛡️ File System Access Control Violation",
                "Uncontrolled file access violates IEC 62443-3-3 SR 2.8 (Auditable Events) "
                "and SR 3.4 (Software and Information Integrity). "
                "Path traversal in safety systems can access calibration files or safety configs.",
                "All file access must use a formally verified path resolver with allowlist. "
                "Document file access policy in the security plan.",
            ),
        },
    },

    "CONST-THRD-001": {
        Gateway.GREEN: {
            "warning": (
                "💡 Background thread may stop unexpectedly",
                "Daemon threads are killed when your program exits, possibly mid-operation. "
                "This can leave incomplete tasks or corrupted data.",
                "Consider using threading.Thread(daemon=False) and call .join() when done.",
            ),
        },
        Gateway.YELLOW: {
            "warning": (
                "🔧 Daemon Thread Lifecycle Risk — Silent Kill",
                "Daemon threads receive no cleanup signal on process exit. "
                "In-progress I/O operations, database transactions, or file writes "
                "are truncated without flushing. CWE-400.",
                "Use daemon=False with explicit .join(). Or use concurrent.futures.ThreadPoolExecutor "
                "with context manager for guaranteed cleanup.",
            ),
        },
        Gateway.BLUE: {
            "warning": (
                "🏗️ Thread Lifecycle — Resource Leak Risk at Scale",
                "Daemon threads in high-traffic services cause resource leaks under "
                "graceful shutdown: pending requests dropped, connections not returned to pool. "
                "Under Kubernetes: threads leak across pod restarts.",
                "Implement graceful shutdown with threading.Event and explicit join timeouts. "
                "Use asyncio for I/O-bound concurrency to avoid threading issues entirely.",
            ),
        },
        Gateway.RED: {
            "warning": (
                "🛡️ Uncontrolled Thread Lifecycle — Certification Risk",
                "IEC 61508-3 Section 7.4.5 requires all concurrent tasks to have "
                "defined termination conditions. Daemon threads violate this requirement. "
                "Safety-critical systems must use controlled task management with formal proof.",
                "Replace with controlled task lifecycle using RTOS primitives or verified "
                "thread management framework. Document task lifecycle in safety plan.",
            ),
        },
    },

    "CONST-LOCK-001": {
        Gateway.GREEN: {
            "warning": (
                "💡 Lock not used safely",
                "Locks protect shared data but must be released. "
                "If an error occurs before release, your program might freeze forever.",
                "Use 'with lock:' instead of lock.acquire()/release().",
            ),
        },
        Gateway.YELLOW: {
            "warning": (
                "🔧 Improper Locking — Deadlock Risk (CWE-667)",
                "Lock.acquire() without a context manager can leave locks held if "
                "an exception occurs. Multiple locks acquired in inconsistent order "
                "cause deadlocks (Dijkstra 1965 — resource ordering theorem).",
                "Always use 'with lock:'. Establish consistent lock ordering. "
                "Consider using threading.RLock for reentrant scenarios.",
            ),
        },
        Gateway.BLUE: {
            "warning": (
                "🏗️ Locking Pattern — System Availability Risk",
                "Improper locking in high-concurrency services causes latency spikes "
                "or complete service freeze under load. Deadlocks require process restart, "
                "causing unplanned downtime in 24/7 services.",
                "Adopt consistent lock hierarchy document. Use timeout on all acquires. "
                "Consider lock-free data structures (queue.Queue) for producer-consumer patterns.",
            ),
        },
        Gateway.RED: {
            "warning": (
                "🛡️ Locking Correctness — Formal Verification Required",
                "IEC 61508-3 Section 7.4.5 requires formal proof of deadlock freedom "
                "in safety-critical concurrent systems. Ad-hoc locking is insufficient.",
                "Apply formal concurrency analysis (e.g., model checking with TLA+). "
                "Document lock hierarchy and formal proof in the safety case.",
            ),
        },
    },
}

# Default template for constructs not in the template dict
_DEFAULT_TEMPLATE: dict[str, dict[str, tuple[str, str, str]]] = {
    Gateway.GREEN: {
        "critical_or_error": (
            "⚠️ A code risk was detected",
            "The analyzer found a potential problem in your code.",
            "Review the finding details and the suggested standards for guidance.",
        ),
        "warning": (
            "💡 A code quality issue was found",
            "The analyzer found something that could be improved.",
            "Consider the suggestion to make your code safer.",
        ),
    },
    Gateway.YELLOW: {
        "critical_or_error": (
            "🔧 Security finding detected",
            "A security-relevant pattern was found. Review the standards for remediation.",
            "Apply the referenced standards (CWE, OWASP) for remediation guidance.",
        ),
    },
    Gateway.BLUE: {
        "critical_or_error": (
            "🏗️ Enterprise risk finding",
            "This finding has architectural and operational implications.",
            "Review the operational impact and apply architectural remediation.",
        ),
    },
    Gateway.RED: {
        "critical_or_error": (
            "🛡️ Safety compliance finding",
            "This finding may violate safety certification requirements.",
            "Consult the referenced standards and apply formal remediation.",
        ),
    },
}


# ─── Explained Finding ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ExplainedFinding:
    """
    Purpose: A Finding with gateway-appropriate explanation.
    The original Finding is preserved unchanged.

    Inputs:
    - finding_id: From the original Finding
    - gateway: Gateway level used for explanation
    - short_title: One-line summary (emoji + brief description)
    - detail: Detailed explanation appropriate for the gateway audience
    - remediation: Concrete fix recommendation
    - audience_level: "beginner" | "developer" | "enterprise" | "safety"
    """
    finding_id: str
    gateway: str
    construct_id: str
    severity: str
    canonical_location: str
    short_title: str
    detail: str
    remediation: str
    audience_level: str


# ─── Engine ───────────────────────────────────────────────────────────────────

def explain_finding(finding, gateway: str) -> ExplainedFinding:
    """
    Purpose: Produce a gateway-appropriate explanation for one Finding.
    Inputs: finding — a Finding (immutable, read-only); gateway — Gateway constant
    Outputs: ExplainedFinding (immutable)
    Constraints: Pure function; no I/O; deterministic
    Determinism: same (finding, gateway) → identical ExplainedFinding
    """
    from src.domain.constructs.construct_model import Severity

    # Determine severity bucket
    sev = finding.severity
    if sev in (Severity.CRITICAL.value, Severity.ERROR.value):
        bucket = "critical_or_error"
    else:
        bucket = "warning"

    # Look up template
    construct_templates = _TEMPLATES.get(finding.construct_id, _DEFAULT_TEMPLATE)
    gateway_templates   = construct_templates.get(gateway, _DEFAULT_TEMPLATE.get(gateway, {}))
    template = gateway_templates.get(bucket) or gateway_templates.get("critical_or_error") or (
        "Finding detected", "A relevant finding was detected.", "Review finding details."
    )

    short, detail, remediation = template

    audience_map = {
        Gateway.GREEN:  "beginner",
        Gateway.YELLOW: "developer",
        Gateway.BLUE:   "enterprise",
        Gateway.RED:    "safety",
    }

    def _n(s: str) -> str:
        return unicodedata.normalize("NFC", s)

    return ExplainedFinding(
        finding_id=finding.finding_id,
        gateway=gateway,
        construct_id=finding.construct_id,
        severity=finding.severity,
        canonical_location=finding.canonical_location,
        short_title=_n(short),
        detail=_n(detail),
        remediation=_n(remediation),
        audience_level=audience_map.get(gateway, "developer"),
    )


def explain_all(artifact, gateway: str) -> tuple[ExplainedFinding, ...]:
    """
    Purpose: Explain all findings in a CEFArtifact for a given gateway.
    Returns sorted tuple (by canonical_location, then finding_id).
    Determinism: same (artifact, gateway) → identical tuple
    """
    explained = [explain_finding(f, gateway) for f in artifact.findings]
    return tuple(sorted(explained, key=lambda e: (e.canonical_location, e.finding_id)))
