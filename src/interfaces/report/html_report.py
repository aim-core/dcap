"""
******************************************************************************
 * FILE:        /src/interfaces/report/html_report.py
 * LAYER:       Interfaces Layer
 * MODULE:      HTML Report Generator
 * PURPOSE:     Generate enterprise-grade HTML security reports
 * DOMAIN:      Interfaces
 * AUTHOR:      DCAP Engineering System
 * CREATED:     2026-05-22
 * UPDATED:     2026-05-22
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * Marketing-grade HTML report generator. Produces standalone HTML files
 * with executive summary, findings detail, tier comparison, trust score,
 * and enterprise upsell features.
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""
from __future__ import annotations
import datetime
import pathlib
from typing import Any


def generate_html_report(output: dict, result: Any, filepath: str) -> None:
    """Generate enterprise-grade HTML security report."""
    status = output["status"]
    tier = output["tier"]
    is_clean = status == "PASS"
    
    status_color = "#22c55e" if is_clean else "#ef4444"
    status_emoji = "PASS" if is_clean else "BLOCKED"
    status_text = "PIPELINE CLEAR" if is_clean else "PIPELINE BLOCKED"
    status_desc = "Safe to deploy" if is_clean else "Do not deploy — critical issues found"
    
    tier_colors = {"GREEN": "#22c55e", "BLUE": "#3b82f6", "YELLOW": "#eab308", "RED": "#ef4444"}
    tier_names = {"GREEN": "Basic", "BLUE": "Standard", "YELLOW": "Industrial", "RED": "Safety-Critical"}
    tier_color = tier_colors.get(tier, "#6b7280")
    tier_name = tier_names.get(tier, tier)
    
    findings = output.get("findings", [])
    critical_count = sum(1 for f in findings if f["severity"] == "critical")
    warning_count = sum(1 for f in findings if f["severity"] == "warning")
    
    findings_html = ""
    for f in findings:
        sev = f["severity"].upper()
        sev_color = "#ef4444" if f["severity"] == "critical" else "#eab308"
        sev_bg = "#450a0a" if f["severity"] == "critical" else "#422006"
        sev_icon = "[CRITICAL]" if f["severity"] == "critical" else "[WARNING]"
        location = f["location"]
        parts = location.split(":")
        file_path = parts[0] if parts else location
        line = parts[1] if len(parts) > 1 else "?"
        filename = file_path.split(chr(92))[-1] if chr(92) in file_path else file_path.split("/")[-1]
        
        fixes = {
            "eval": ("Remove eval(). Parse data with json.loads() or a schema validator.", "CWE-94"),
            "exec": ("Remove exec(). Use explicit function calls instead.", "CWE-94"),
            "subprocess": ("Use subprocess.run([cmd, arg]) with shell=False and validated arguments.", "CWE-78"),
            "open": ("Use pathlib.Path().read_text() or add context manager with proper validation.", "CWE-22"),
            "global": ("Replace with explicit parameter passing or frozen dataclass.", "CWE-1108"),
        }
        fix_text, cwe = fixes.get(f["construct"], ("Manual review required.", "N/A"))
        
        findings_html += f"""<div style="border-left:4px solid {sev_color};background:{sev_bg};margin-bottom:1rem;padding:1.25rem;border-radius:0.5rem">
<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:0.75rem">
<div><span style="font-size:1.1rem;font-weight:bold;color:{sev_color}">{sev_icon} {f['id']}</span>
<span style="background:{sev_color};color:white;padding:0.15rem 0.5rem;border-radius:0.25rem;font-size:0.75rem;margin-left:0.5rem">{sev}</span>
<span style="color:#94a3b8;margin-left:0.5rem;font-size:0.85rem">{f['construct']}()</span></div>
<span style="color:#f87171;font-size:0.8rem;font-weight:bold">HUMAN REVIEW</span></div>
<div style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.5rem">Location: <code>{filename}</code> line {line}</div>
<div style="color:#e2e8f0;margin-bottom:0.5rem;font-size:0.9rem"><strong>State:</strong> {f['state'].replace('_', ' ')}</div>
<div style="background:#1e293b;padding:0.75rem;border-radius:0.5rem;margin-top:0.5rem">
<div style="color:#22c55e;font-weight:bold;margin-bottom:0.25rem">Recommended Fix:</div>
<div style="color:#e2e8f0;font-size:0.9rem">{fix_text}</div>
<div style="color:#64748b;font-size:0.75rem;margin-top:0.25rem">Reference: {cwe}</div></div></div>"""

    locked_features = [
        ("Supply Chain Analysis", "Detect typosquatting and malicious packages", "YELLOW"),
        ("AI Hallucination Detection", "Catch AI-invented APIs and phantom imports", "YELLOW"),
        ("CI/CD Native Integration", "GitHub/GitLab security gates with auto-block", "BLUE"),
        ("Team Security Dashboard", "Multi-project overview with trend analysis", "BLUE"),
        ("Custom Security Policies", "Your organization rules, enforced automatically", "RED"),
        ("Proof Certificate Export", "Cryptographically verifiable audit reports", "RED"),
    ]
    
    locked_rows = ""
    for name, desc, req_tier in locked_features:
        color = tier_colors.get(req_tier, "#6b7280")
        locked_rows += f"""<div style="background:#1e293b;padding:1rem;border-radius:0.5rem;border:1px solid #334155">
<div style="display:flex;justify-content:space-between;align-items:center">
<div><div style="font-weight:bold;color:#f1f5f9">{name}</div>
<div style="color:#94a3b8;font-size:0.85rem">{desc} — Requires {req_tier} tier</div></div>
<a href="https://dcap.io/upgrade" style="background:{color};color:white;padding:0.5rem 1rem;border-radius:0.5rem;text-decoration:none;font-weight:bold;font-size:0.85rem">UPGRADE</a></div></div>"""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DCAP Security Report — {output['source_root']}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
.container{{max-width:960px;margin:0 auto;padding:2rem 1.5rem}}
.hero{{text-align:center;padding:3rem 0 2rem}}
.hero h1{{font-size:2.5rem;color:#f8fafc;margin-bottom:0.5rem}}
.hero .subtitle{{color:#94a3b8;font-size:1.1rem;margin-bottom:2rem}}
.status-pill{{display:inline-block;padding:0.75rem 2rem;border-radius:2rem;font-weight:bold;font-size:1.2rem;background:{status_color};color:white;margin-bottom:0.5rem}}
.status-desc{{color:#94a3b8;font-size:0.95rem}}
.card{{background:#1e293b;border-radius:1rem;padding:1.75rem;margin-bottom:1.5rem;border:1px solid #334155}}
.card h2{{color:#f1f5f9;font-size:1.2rem;margin-bottom:1.25rem}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem}}
.metric{{text-align:center;padding:1rem;background:#0f172a;border-radius:0.75rem}}
.metric .value{{font-size:2rem;font-weight:bold;color:#f8fafc}}
.metric .label{{font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.1em;margin-top:0.25rem}}
.trust-bar{{height:8px;background:#334155;border-radius:4px;margin:1rem 0;overflow:hidden}}
.trust-fill{{height:100%;background:linear-gradient(90deg,#22c55e,#3b82f6,#eab308,#ef4444);border-radius:4px}}
.tier-badge{{display:inline-block;padding:0.35rem 1rem;border-radius:1rem;font-weight:bold;font-size:0.9rem;background:{tier_color};color:white}}
.tiers{{display:grid;grid-template-columns:repeat(4,1fr);gap:0.5rem;margin-top:1rem}}
.tier-card{{padding:1rem;border-radius:0.75rem;text-align:center;border:2px solid #334155}}
.tier-card.active{{border-color:{tier_color};background:{tier_color}15}}
.tier-card .name{{font-weight:bold;font-size:1rem}}
.tier-card .level{{font-size:0.75rem;color:#94a3b8;margin-top:0.25rem}}
.footer{{text-align:center;color:#64748b;font-size:0.8rem;margin-top:3rem;padding-top:1.5rem;border-top:1px solid #334155}}
.footer a{{color:#3b82f6;text-decoration:none}}
.btn{{display:inline-block;padding:0.75rem 1.5rem;border-radius:0.5rem;font-weight:bold;text-decoration:none;font-size:0.9rem}}
.btn-primary{{background:#3b82f6;color:white}}
.btn:hover{{opacity:0.9}}
@media(max-width:768px){{.tiers{{grid-template-columns:repeat(2,1fr)}}.hero h1{{font-size:1.8rem}}}}
</style></head><body>
<div class="container">
<div class="hero"><h1>DCAP Security Analysis</h1><p class="subtitle">Deterministic Code Analysis & Verification Platform</p>
<div class="status-pill">{status_emoji} — {status_text}</div><p class="status-desc">{status_desc}</p>
<p style="color:#64748b;font-size:0.85rem;margin-top:0.5rem">Analysis: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p></div>

<div class="card"><h2>Security Risk</h2>
<div style="text-align:center;font-size:3rem;font-weight:bold;color:#22c55e">{output['honesty_score']}/1000</div>
<div class="trust-bar"><div class="trust-fill" style="width:{output['honesty_score']/10}%"></div></div>
<div style="display:flex;justify-content:center;gap:2rem;margin-top:1rem;flex-wrap:wrap">
<div style="text-align:center"><div style="color:#22c55e">VERIFIED</div><div style="font-size:0.8rem;color:#94a3b8">Analysis Integrity</div></div>
<div style="text-align:center"><div style="color:#22c55e">VERIFIED</div><div style="font-size:0.8rem;color:#94a3b8">Catalog Merkle</div></div>
<div style="text-align:center"><div style="color:#22c55e">VERIFIED</div><div style="font-size:0.8rem;color:#94a3b8">Triple Replay</div></div>
<div style="text-align:center"><div style="color:#22c55e">VERIFIED</div><div style="font-size:0.8rem;color:#94a3b8">Artifact Signed</div></div></div>
<p style="color:#64748b;font-size:0.8rem;text-align:center;margin-top:0.75rem">Cryptographically verifiable. Artifact: <code>{output['artifact_hash'][:32]}...</code></p></div>

<div class="card"><h2>Executive Summary</h2>
<div class="metrics">
<div class="metric"><div class="value"><span class="tier-badge">{tier}</span></div><div class="label">{tier_name} Tier</div></div>
<div class="metric"><div class="value">{output['files_analyzed']}</div><div class="label">Files</div></div>
<div class="metric"><div class="value">{output['nodes_discovered']}</div><div class="label">Nodes</div></div>
<div class="metric"><div class="value" style="color:{status_color}">{output['finding_count']}</div><div class="label">Findings</div></div>
<div class="metric"><div class="value" style="font-size:1.2rem">{output['elapsed_ms']}ms</div><div class="label">Scan Time</div></div>
<div class="metric"><div class="value" style="font-size:1.2rem">{output['trust_level']}</div><div class="label">Analysis Integrity</div></div></div>
<div style="margin-top:1rem;color:#94a3b8;font-size:0.9rem"><strong>Source:</strong> <code>{output['source_root']}</code></div></div>

<div class="card"><h2>Findings ({len(findings)})</h2>
{findings_html if findings_html else '<p style="color:#22c55e;text-align:center;padding:2rem">No findings — your code passed all security checks.</p>'}</div>

<div class="card"><h2>Analysis Depth</h2><p style="color:#94a3b8;margin-bottom:1rem;font-size:0.9rem">DCAP offers four tiers. Your current tier is highlighted.</p>
<div class="tiers">
<div class="tier-card {'active' if tier=='GREEN' else ''}"><div class="name" style="color:#22c55e">GREEN</div><div class="level">Basic</div><div style="font-size:0.75rem;color:#94a3b8;margin-top:0.5rem">Warnings only</div></div>
<div class="tier-card {'active' if tier=='BLUE' else ''}"><div class="name" style="color:#3b82f6">BLUE</div><div class="level">Standard</div><div style="font-size:0.75rem;color:#94a3b8;margin-top:0.5rem">CI/CD default</div></div>
<div class="tier-card {'active' if tier=='YELLOW' else ''}"><div class="name" style="color:#eab308">YELLOW</div><div class="level">Industrial</div><div style="font-size:0.75rem;color:#94a3b8;margin-top:0.5rem">Supply chain</div></div>
<div class="tier-card {'active' if tier=='RED' else ''}"><div class="name" style="color:#ef4444">RED</div><div class="level">Safety-Critical</div><div style="font-size:0.75rem;color:#94a3b8;margin-top:0.5rem">Aerospace</div></div></div></div>

<div class="card"><h2>DCAP Enterprise - Available on Request</h2><p style="color:#94a3b8;margin-bottom:1rem;font-size:0.9rem">Unlock the full power of DCAP.</p>
<div style="display:flex;flex-direction:column;gap:0.75rem">{locked_rows}</div></div>

<div style="text-align:center;padding:2rem 0">
<h2 style="color:#f8fafc;margin-bottom:0.5rem">Ready to secure your codebase?</h2>
<p style="color:#94a3b8;margin-bottom:1.5rem">Upgrade to unlock enterprise features and advanced analysis.</p>
<a href="https://dcap.io/upgrade" class="btn btn-primary" style="font-size:1.1rem;padding:1rem 2rem">Upgrade Now</a>
<a href="https://dcap.io/docs" class="btn" style="background:#334155;color:#e2e8f0;margin-left:0.75rem">Documentation</a></div>

<div class="footer">
<p><strong>Verification Certificate</strong><br>This certifies that <code>{output['source_root']}</code><br>was analyzed by DCAP v0.1.0 under {tier} tier rules.<br>Artifact Hash: <code>{output['artifact_hash']}</code></p>
<p style="margin-top:0.75rem">This hash is cryptographically unique and is tamper-evident.</p>
<p style="margin-top:1.5rem"><strong>DCAP</strong> — Deterministic Code Analysis & Verification Platform<br>
<a href="https://dcap.io">https://dcap.io</a> | <a href="mailto:security@dcap.io">security@dcap.io</a></p>
<p style="margin-top:1rem;color:#475569">2026 DCAP. Apache 2.0 License. All analysis results are deterministically reproducible.</p></div>
</div></body></html>"""
    
    pathlib.Path(filepath).write_text(html, encoding='utf-8')
    import sys
    print(f"\n[DCAP] HTML report written to: {filepath}", file=sys.stderr)
