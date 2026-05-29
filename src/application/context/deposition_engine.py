"""
******************************************************************************
 * FILE:        /src/application/context/deposition_engine.py
 * LAYER:       Application Layer
 * MODULE:      Deterministic Deposition Engine
 * PURPOSE:     Generate witness deposition transcripts for findings
 * DOMAIN:      Context
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-29
 * UPDATED:     2026-05-29
 * VERSION:     v0.6.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

def generate_deposition(finding: dict, tier: str, correlation_count: int = 0, exec_surface: str = "") -> list[dict]:
    """Generate deposition Q&A based on finding context and tier."""
    
    qa = []
    state = finding.get("state", "")
    construct = finding.get("construct", "")
    severity = finding.get("severity", "WARNING").upper()
    is_tainted = any(s in state for s in ("external_source", "user_controlled", "dynamic_arg", "dynamic_cmd"))
    
    # Layer 1: Evidence (all tiers)
    qa.append({
        "question": "What is the evidence?",
        "answer": f"Deterministic AST pattern match. Construct: {construct}. State: {state}.",
        "icon": "🔍"
    })
    
    # Layer 2: Confidence (YELLOW+)
    if tier in ("YELLOW", "RED"):
        qa.append({
            "question": "What is the confidence level?",
            "answer": f"CERTAIN. This is not a heuristic guess. The finding is based on exact pattern matching.",
            "icon": "✅"
        })
    
    # Layer 3: Attack Surface (YELLOW+)
    if tier in ("YELLOW", "RED"):
        attack = "HIGH" if is_tainted else "MEDIUM" if severity in ("CRITICAL", "ERROR") else "LOW"
        qa.append({
            "question": "What is the attack surface?",
            "answer": f"{attack}. {'User-controlled input reaches this execution sink.' if is_tainted else 'Pattern detected without confirmed tainted input.'}",
            "icon": "⚔️"
        })
    
    # Layer 4: Root Cause (RED only)
    if tier == "RED":
        root_cause = "User input flows into this execution sink without validation." if is_tainted else "Static analysis confirms this pattern exists in active code path."
        qa.append({
            "question": "What is the root cause?",
            "answer": root_cause,
            "icon": "🧠"
        })
    
    # Layer 5: Correlation (RED only)
    if tier == "RED" and correlation_count > 0:
        qa.append({
            "question": "Is this part of a larger chain?",
            "answer": f"Yes. This finding is linked to {correlation_count} other execution constructs forming an attack chain.",
            "icon": "🔗"
        })
    
    # Layer 6: Remediation (all tiers)
    fixes = {
        "eval": "Replace with ast.literal_eval() or JSON schema validation.",
        "exec": "Remove and use explicit function calls.",
        "subprocess": "Use subprocess.run() with shell=False and validated arguments.",
        "pickle.loads": "Never deserialize untrusted data. Use JSON.",
        "os.system": "Use subprocess.run() with shell=False.",
        "sql_injection": "Use parameterized queries.",
        "open": "Validate paths with pathlib.resolve() and restrict to trusted directories.",
        "yaml.load": "Use yaml.safe_load().",
        "requests.get": "Restrict URLs to trusted domains.",
        "os.remove": "Validate paths before deletion.",
        "random": "Use secrets module for security tokens.",
        "debug=True": "Remove before production deployment.",
        "global": "Use dependency injection instead of global state.",
    }
    fix = fixes.get(construct, "Manual review required.")
    qa.append({
        "question": "How should this be fixed?",
        "answer": fix,
        "icon": "🛠️"
    })
    
    # Layer 7: Replay Proof (RED only)
    if tier == "RED":
        qa.append({
            "question": "Is this report reproducible?",
            "answer": "Yes. This finding is deterministically reproducible. Same code + Same catalog + Same seed = Same result.",
            "icon": "📜"
        })
    
    # Layer 8: Governance (RED only)
    if tier == "RED":
        qa.append({
            "question": "What is the governance impact?",
            "answer": f"Violates RED tier Zero-Trust Forensic Policy. Deployment is RESTRICTED until remediated.",
            "icon": "🏛️"
        })
    
    return qa