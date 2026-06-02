"""
******************************************************************************
 * FILE:        /src/application/context/drift_collector.py
 * LAYER:       Application Layer
 * MODULE:      Construct Drift Collector
 * PURPOSE:     Collect unknown patterns for human review (NOT auto-learning)
 * DOMAIN:      Context
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-31
 * UPDATED:     2026-05-31
 * VERSION:     v0.8.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
import json
from pathlib import Path
from datetime import datetime

DRIFT_REGISTRY = Path.home() / ".dcap" / "construct_drift_registry.json"

def record_unknown_construct(node_info: dict) -> None:
    """Record an unknown construct for human review.
    
    This does NOT change engine behavior.
    This only logs what the engine could not classify.
    """
    DRIFT_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "construct_id": node_info.get("construct_id", "UNKNOWN"),
        "ast_node_type": node_info.get("ast_node_type", "UNKNOWN"),
        "detected_state": node_info.get("state", "UNKNOWN"),
        "source_line": node_info.get("source_line", "")[:120],
        "file_path": node_info.get("file_path", "UNKNOWN"),
        "line_number": node_info.get("line_number", 0),
        "reviewed": False,
        "action": "PENDING"
    }
    
    registry = []
    if DRIFT_REGISTRY.exists():
        try:
            registry = json.loads(DRIFT_REGISTRY.read_text())
        except:
            pass
    
    # Avoid duplicates
    if not any(e.get("source_line") == entry["source_line"] for e in registry):
        registry.append(entry)
        DRIFT_REGISTRY.write_text(json.dumps(registry, indent=2, ensure_ascii=False))

def get_unreviewed_drifts() -> list:
    """Get all unreviewed drift entries."""
    if not DRIFT_REGISTRY.exists():
        return []
    try:
        registry = json.loads(DRIFT_REGISTRY.read_text())
        return [e for e in registry if not e.get("reviewed", False)]
    except:
        return []

def export_drifts_for_review() -> str:
    """Export unreviewed drifts as a human-readable report."""
    drifts = get_unreviewed_drifts()
    if not drifts:
        return "No unknown patterns recorded."

    report = f"CONSTRUCT DRIFT REPORT — {datetime.utcnow().strftime('%Y-%m-%d')}\n"
    report += f"{'='*60}\n"
    report += f"Total unknown patterns: {len(drifts)}\n\n"

    # Group by construct_id
    by_type = {}
    for d in drifts:
        cid = d.get("construct_id", "UNKNOWN")
        by_type.setdefault(cid, []).append(d)

    for cid, entries in by_type.items():
        report += f"\n[{cid}] — {len(entries)} occurrence(s)\n"
        for e in entries[:3]:
            report += f"  File: {e.get('file_path')}:{e.get('line_number')}\n"
            report += f"  State: {e.get('detected_state')}\n"
            report += f"  Source: {e.get('source_line','')}\n"

    return report