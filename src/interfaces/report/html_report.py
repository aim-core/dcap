"""
******************************************************************************
 * FILE:        /src/interfaces/report/html_report.py
 * LAYER:       Interface Layer
 * MODULE:      HTML Forensic Report Generator
 * PURPOSE:     Generate enterprise-grade HTML audit reports with deposition
 * DOMAIN:      Report
 * AUTHOR:      DCAP Engineering
 * CREATED:     2026-05-30
 * UPDATED:     2026-05-30
 * VERSION:     v0.7.0
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
import datetime
import hashlib
import json
import uuid
from pathlib import Path

def generate_html_report(output: dict, result, filepath: str) -> None:
    tier = output.get("tier", "BLUE")
    findings = output.get("findings", [])
    
    # Tier colors
    tier_colors = {"GREEN": "#22c55e", "BLUE": "#3b82f6", "YELLOW": "#eab308", "RED": "#ef4444"}
    tier_names = {"GREEN": "Educational", "BLUE": "Professional", "YELLOW": "Enterprise", "RED": "Zero-Trust Forensic"}
    color = tier_colors.get(tier, "#6b7280")
    is_blocked = output.get("pipeline_blocked", False)
    status_color = "#ef4444" if is_blocked else "#22c55e"
    status_text = "RESTRICTED" if is_blocked else "PERMITTED"
    
    # Build findings HTML with deposition
    findings_html = ""
    for f in findings:
        sev = f.get("severity", "WARNING").upper()
        sev_color = {"CRITICAL": "#ef4444", "ERROR": "#f59e0b", "WARNING": "#eab308"}.get(sev, "#94a3b8")
        state = f.get("state", "")
        taint = " [TAINTED]" if any(s in state for s in ("external_source", "user_controlled", "dynamic_arg", "dynamic_cmd")) else ""
        
        # Deposition Q&A
        depo_html = ""
        if tier in ("YELLOW", "RED"):
            try:
                from src.application.context.deposition_engine import generate_deposition
                depo = generate_deposition(f, tier, len(findings))
                max_qa = 3 if tier == "YELLOW" else 8
                depo_html = '<div class="deposition" style="display:none;margin-top:10px;padding:10px;background:#1e293b;border-radius:8px;">'
                for qa in depo[:max_qa]:
                    depo_html += f'<div style="margin-bottom:8px;"><strong>{qa["icon"]} {qa["question"]}</strong><br><span style="color:#94a3b8;">{qa["answer"]}</span></div>'
                depo_html += '</div>'
            except:
                pass
        
        findings_html += f'''
        <div class="finding" style="border-left:4px solid {sev_color};padding:15px;margin:10px 0;background:#1e293b;border-radius:0 8px 8px 0;">
            <div style="display:flex;justify-content:space-between;">
                <strong style="color:{sev_color};">{f["id"]} {sev} {f.get("construct","")}{taint}</strong>
                <span style="color:#94a3b8;font-size:0.85em;">{f.get("location","")}</span>
            </div>
            {f'<div class="depo-toggle" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==\'none\'?\'block\':\'none\'" style="cursor:pointer;color:{color};margin-top:8px;font-size:0.9em;">📜 Toggle Deposition</div>' if depo_html else ''}
            {depo_html}
        </div>'''
    
    # Score display
    score_html = ""
    if tier in ("YELLOW", "RED"):
        try:
            from src.application.trust.scoring_matrix import compute_security_score, get_security_grade
            score = compute_security_score(findings, tier)
            grade = get_security_grade(score)
            score_color = "#22c55e" if score >= 70 else "#eab308" if score >= 40 else "#ef4444"
            score_html = f'''
            <div class="metric" style="text-align:center;">
                <div style="font-size:3em;color:{score_color};font-weight:bold;">{score}/100</div>
                <div style="color:#94a3b8;">{grade}</div>
            </div>'''
        except:
            pass
    
    # Correlation chain
    constructs = [f.get("construct","") for f in findings]
    exec_surface = [c for c in constructs if c in ("eval", "exec", "subprocess", "os.system", "pickle.loads")]
    corr_html = ""
    if len(exec_surface) >= 3:
        corr_html = f'''
        <div class="card">
            <h2>🔗 Execution Chain</h2>
            <p style="color:#94a3b8;">{len(exec_surface)} constructs form an attack chain:</p>
            <p style="color:#e2e8f0;font-family:monospace;">{" → ".join(exec_surface)}</p>
        </div>'''
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>DCAP {tier} TIER — Forensic Audit Report</title>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
        .container{{max-width:960px;margin:0 auto;padding:2rem 1.5rem}}
        .header{{text-align:center;padding:2rem 0;border-bottom:2px solid {color};margin-bottom:2rem}}
        .header h1{{color:#f8fafc;font-size:2rem}}
        .header .subtitle{{color:#94a3b8}}
        .status-badge{{display:inline-block;padding:0.5rem 1.5rem;border-radius:2rem;font-weight:bold;background:{status_color};color:white;margin:1rem 0}}
        .card{{background:#1e293b;border-radius:12px;padding:1.5rem;margin:1rem 0;border:1px solid #334155}}
        .card h2{{color:#f1f5f9;font-size:1.1rem;margin-bottom:1rem}}
        .metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem}}
        .metric{{text-align:center;padding:1rem;background:#0f172a;border-radius:8px}}
        .metric .value{{font-size:2rem;font-weight:bold;color:#f8fafc}}
        .metric .label{{font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.1em}}
        .footer{{text-align:center;color:#64748b;font-size:0.8rem;margin-top:2rem;padding-top:1rem;border-top:1px solid #334155}}
        .depo-toggle:hover{{text-decoration:underline}}
        @media(max-width:768px){{.metrics{{grid-template-columns:repeat(2,1fr)}}}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DCAP {tier} TIER</h1>
            <p class="subtitle">Deterministic Forensic Audit Report</p>
            <div class="status-badge">{status_text}</div>
            <p style="color:#64748b;">Tier: {tier_names.get(tier, "Standard")} | Policy: {output.get("tier_policy","")}</p>
        </div>
        
        <div class="card">
            <h2>📊 Executive Summary</h2>
            <div class="metrics">
                <div class="metric"><div class="value">{output["finding_count"]}</div><div class="label">Findings</div></div>
                <div class="metric"><div class="value">{output["files_analyzed"]}</div><div class="label">Files</div></div>
                <div class="metric"><div class="value">{output["elapsed_ms"]}ms</div><div class="label">Elapsed</div></div>
                {score_html}
            </div>
            <p style="margin-top:1rem;color:#94a3b8;"><strong>Source:</strong> {output["source_root"]}</p>
        </div>
        
        <div class="card">
            <h2>🔍 Forensic Findings ({len(findings)})</h2>
            {findings_html if findings_html else '<p style="color:#22c55e;">No risk patterns detected.</p>'}
        </div>
        
        {corr_html}
        
        <div class="card">
            <h2>📜 Deterministic Evidence</h2>
            <p style="color:#94a3b8;">Proof Signature: <code>{hashlib.sha256(json.dumps(findings,sort_keys=True).encode()).hexdigest()[:16]}</code></p>
            <p style="color:#94a3b8;">This analysis is cryptographically verifiable and deterministically reproducible.</p>
        </div>
        
        <div class="footer">
            <p>DCAP v0.7.0 — Deterministic Code Analysis Platform</p>
            <p>Same code + Same catalog + Same seed = Same result. Always.</p>
        </div>
    </div>
</body>
</html>'''
    
    Path(filepath).write_text(html, encoding='utf-8')
    import sys
    print(f"\n[DCAP] HTML report written to: {filepath}", file=sys.stderr)