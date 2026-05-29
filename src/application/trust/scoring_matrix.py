
"""
******************************************************************************
 * FILE:        /src/application/trust/scoring_matrix.py
 * LAYER:       Application Layer
 * MODULE:      Security Scoring Matrix
 * PURPOSE:     Dynamic security scoring based on severity and tier
 * DOMAIN:      Trust
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-24
 * UPDATED:     2026-05-24
 * VERSION:     v0.3.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
from src.domain.constructs.construct_model import Severity

PENALTY_MATRIX = {
    Severity.INFO.value:     {"GREEN": 0,  "BLUE": 0,   "YELLOW": 0,   "RED": -1},
    Severity.WARNING.value:  {"GREEN": -1, "BLUE": -1,  "YELLOW": -2,  "RED": -3},
    Severity.ERROR.value:    {"GREEN": -2, "BLUE": -3,  "YELLOW": -5,  "RED": -8},
    Severity.CRITICAL.value: {"GREEN": -3, "BLUE": -5,  "YELLOW": -8,  "RED": -10},
}

BASE_SCORE = 100
SEVERITY_WEIGHTS = {"critical": 10, "error": 5, "warning": 2, "info": 0}
TIER_MULTIPLIERS = {"GREEN": 1, "BLUE": 1, "YELLOW": 1, "RED": 1}  # All tiers use same penalty now - severity is intrinsic

def compute_security_score(findings, tier: str) -> int:
    total_penalty = 0
    multiplier = TIER_MULTIPLIERS.get(tier.upper(), 0.5)
    for f in findings:
        severity = f.get("severity", "warning").lower()
        weight = SEVERITY_WEIGHTS.get(severity, 3)
        total_penalty += weight * multiplier
        
    return int(max(0, min(100, BASE_SCORE - total_penalty)))

def get_security_grade(score: int) -> str:
    if score >= 90: return "A"
    elif score >= 70: return "B"
    elif score >= 50: return "C"
    elif score >= 30: return "D"
    else: return "F"

def get_security_label(score: int) -> str:
    if score >= 90: return "Excellent"
    elif score >= 70: return "Good"
    elif score >= 50: return "Fair"
    elif score >= 30: return "Poor"
    else: return "Critical Risk"
