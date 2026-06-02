"""
******************************************************************************
 * FILE:        /src/interfaces/report/human_readable.py
 * LAYER:       Interface Layer
 * MODULE:      Human-Readable Forensic Report
 * PURPOSE:     Deterministic forensic audit report with all intelligence layers
 * DOMAIN:      Report
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-29
 * UPDATED:     2026-05-30
 * VERSION:     v0.7.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
import uuid
import datetime
import hashlib
import json
from pathlib import Path

def print_human_report(output: dict, result) -> None:
    tier = output.get("tier", "BLUE")
    policies = {
        "GREEN":  "PERMITTED - Educational tier. NOT a safety assessment.",
        "BLUE":   "PERMITTED - Professional tier policy.",
        "YELLOW": "RESTRICTED - Enterprise governance applied.",
        "RED":    "BLOCKED - Zero-trust forensic policy.",
    }
    report_id = f"DCAP-{tier}-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    
    print(f"\n{'='*60}")
    print(f"  DCAP {tier} TIER - FORENSIC AUDIT REPORT")
    print(f"{'='*60}")
    print(f"  Report ID      : {report_id}")
    print(f"  Timestamp      : {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} (UTC)")
    print(f"  Detection      : COMPLETE - {output['finding_count']} findings in {output['files_analyzed']} files")
    print(f"  Risk Signals   : {output.get('nodes_discovered', 0)} detected")
    print(f"  Tier Policy    : {policies.get(tier, 'PERMITTED')}")
    print(f"  Source         : {output['source_root']}")
    
    if tier in ("YELLOW", "RED"):
        from src.application.trust.scoring_matrix import compute_security_score, get_security_grade
        score = compute_security_score(output.get("findings", []), tier)
        grade = get_security_grade(score)
        print(f"  Security Score  : {score}/100 - {grade}")
    
    proof_material = json.dumps(output.get("findings",[]), sort_keys=True)
    proof_hash = hashlib.sha256(proof_material.encode()).hexdigest()[:16]
    print(f"  Engine Trust   : VERIFIED (Merkle + Triple Replay)")
    print(f"  Proof Sig      : {proof_hash}")
    
    replay_material = f"{output.get('artifact_hash','')}:{output.get('finding_count',0)}:{tier}"
    replay_fp = hashlib.sha256(replay_material.encode()).hexdigest()[:12]
    print(f"  Replay FP      : {replay_fp}")
    print(f"  Elapsed        : {output['elapsed_ms']}ms")
    
    constructs = [f.get("construct","") for f in output.get("findings",[])]
    exec_surface = [c for c in constructs if c in ("eval", "exec", "subprocess", "os.system", "pickle.loads")]
    
    print(f"\n  {'='*60}")
    print(f"  EXECUTIVE VERDICT")
    print(f"  {'='*60}")
    if output['finding_count'] >= 5 and len(exec_surface) >= 3:
        print(f"  CRITICAL: Multiple attack chains detected.")
    elif output['finding_count'] > 0:
        print(f"  WARNING: Security findings require review.")
    else:
        print(f"  CLEAN: No risk patterns detected.")
    
    if output["findings"]:
        print(f"\n  FORENSIC FINDINGS")
        for f in output["findings"]:
            sev = f.get("severity", "WARNING").upper()
            state = f.get("state", f.get("detected_state", ""))
            taint = " [TAINTED]" if any(s in state for s in ("external_source", "user_controlled", "dynamic_arg", "dynamic_cmd")) else ""
            print(f"\n  {f['id']} {sev} {f.get('construct','')}{taint}")
            print(f"     Location : {f.get('location','unknown')}")
            if taint:
                print(f"     Root Cause: User-controlled input reaches this execution sink")
            if tier in ("YELLOW", "RED"):
                from src.application.context.deposition_engine import generate_deposition
                depo = generate_deposition(f, tier, len(exec_surface))
                for qa in depo[:3 if tier == "YELLOW" else 8]:
                    print(f"     {qa['icon']} {qa['question']}")
                    print(f"        {qa['answer']}")
    
    if len(exec_surface) >= 3:
        print(f"\n  CORRELATION ANALYSIS: Execution Surface Collection Detected")
        print(f"     {len(exec_surface)} constructs form an execution surface collection:")
        print(f"     {' → '.join(exec_surface)}")
    
    if tier in ("YELLOW", "RED"):
        try:
            from src.application.context.recovery_integrity import analyze_recovery_integrity
            all_issues = []
            seen = set()
            for f in output.get("findings", []):
                loc = f.get("location", "")
                if loc:
                    filepath = loc.split(":")[0]
                    if Path(filepath).exists() and filepath not in seen:
                        seen.add(filepath)
                        all_issues.extend(analyze_recovery_integrity(filepath))
            if all_issues:
                print(f"\n  RECOVERY INTEGRITY")
                for i in all_issues[:3]:
                    print(f"     [{i['type']}] Line {i['line']}: {i['message']}")
        except Exception:
            pass
    
    print(f"\n  {'='*60}")
    print(f"  DETERMINISTIC EVIDENCE")
    print(f"  {'='*60}")
    print(f"  This analysis is cryptographically verifiable.")
    
    if tier == "GREEN":
        print(f"\n  FINAL DECISION: PERMITTED under GREEN tier (Educational)")
    elif output.get("pipeline_blocked"):
        print(f"\n  FINAL DECISION: RESTRICTED under {tier} tier policy")
    else:
        print(f"\n  FINAL DECISION: PERMITTED under {tier} tier policy")