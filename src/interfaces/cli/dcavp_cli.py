"""
******************************************************************************
 * FILE:        /src/interfaces/cli/dcavp_cli.py
 * LAYER:       Interfaces Layer
 * MODULE:      CLI Interface
 * PURPOSE:     Command-line entry point for DCAVP analysis
 * DOMAIN:      Interfaces
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-13
 * UPDATED:     2026-05-13
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The DCAVP CLI provides four commands:
 *
 *   analyze    — Run analysis on a source tree
 *   verify     — Run self-verification gateway
 *   replay     — Replay a previous analysis and verify
 *   catalog    — Show catalog information
 *
 * DESIGN PRINCIPLES:
 *   - CLI is a thin wrapper over application layer — no business logic
 *   - Exit codes are deterministic: 0=pass, 1=fail, 2=error
 *   - Output is structured JSON or human-readable (--format flag)
 *   - All output goes to stdout; errors to stderr
 *
 * EXIT CODES:
 *   0  — Analysis complete, no pipeline-blocking findings
 *   1  — Analysis complete, pipeline BLOCKED (findings above threshold)
 *   2  — Analysis error (parse failure, catalog error, etc.)
 *   3  — Self-verification failure
 *
 * LICENSE: Apache-2.0 / Enterprise Extension
 ******************************************************************************
"""

from __future__ import annotations

import argparse
import json
import sys
import pathlib
from datetime import datetime, timezone


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cmd_analyze(args: argparse.Namespace) -> int:
    """
    Purpose: Run analysis on a source tree.
    Returns exit code: 0=pass, 1=blocked, 2=error
    """
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent.parent))

        from src.infrastructure.catalog.engine.catalog_loader import load_python_catalog
        from src.application.tier.tier_engine import TierEngine
        from src.application.classification.classification_pipeline import ClassificationPipeline
        from src.application.replay.replay_bundle import build_replay_bundle
        from src.domain.constructs.construct_model import Tier

        tier_map = {
            "GREEN": Tier.GREEN, "BLUE": Tier.BLUE,
            "YELLOW": Tier.YELLOW, "RED": Tier.RED,
        }
        tier = tier_map.get(args.tier.upper(), Tier.BLUE)

        # Load catalog
        if not args.quiet:
            print(f"[DCAVP] Loading catalog...", file=sys.stderr)
        catalog = load_python_catalog()

        # Classify project
        if not args.quiet:
            print(f"[DCAVP] Classifying project...", file=sys.stderr)
        pipeline = ClassificationPipeline()
        classification = pipeline.classify(args.source_root)
        fp = classification.fingerprint

        if not args.quiet:
            print(f"[DCAVP] Project: {fp.domain_posture} | "
                  f"Tier: {tier.value} | "
                  f"Language: {fp.language}", file=sys.stderr)

        # Run analysis
        if not args.quiet:
            print(f"[DCAVP] Analyzing...", file=sys.stderr)
        engine = TierEngine(catalog)
        result = engine.analyze(
            source_root=args.source_root,
            context=fp,
            tier=tier,
            execution_seed=args.seed,
        )

        if result.artifact is None:
            print("ERROR: Analysis failed to produce artifact", file=sys.stderr)
            return 2

        # Build replay bundle
        bundle = build_replay_bundle(result)

        # Output
        output = {
            "status": "BLOCKED" if result.pipeline_blocked else "PASS",
            "tier": tier.value,
            "source_root": args.source_root,
            "files_analyzed": result.files_analyzed,
            "nodes_discovered": result.nodes_discovered,
            "finding_count": result.artifact.finding_count,
            "pipeline_blocked": result.pipeline_blocked,
            "requires_dual_control": result.requires_dual_control,
            "artifact_hash": result.artifact.artifact_hash,
            "elapsed_ms": result.elapsed_ms,
            "trust_level": result.artifact.boundary_honesty.trust_level,
            "honesty_score": result.artifact.boundary_honesty.score_numerator,
            "findings": [
                {
                    "id":       f.finding_id,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "construct": f.construct_name,
                    "location": f.canonical_location,
                    "state":    f.detected_state,
                    "human_review": f.human_review_required,
                }
                for f in result.artifact.findings
            ],
            "warnings": list(result.analysis_warnings[:10]),
        }

        if args.format == "json":
            print(json.dumps(output, indent=2))
        elif args.format == "html":
            html_path = args.output_bundle or 'dcavp-report.html'
            from src.interfaces.report.html_report import generate_html_report
            generate_html_report(output, result, html_path)
        else:
            _print_human(output, result)

        # Write replay bundle if requested
        if args.output_bundle:
            bundle_path = pathlib.Path(args.output_bundle)
            bundle_path.write_text(bundle.to_canonical_json(), encoding="utf-8")
            if not args.quiet:
                print(f"[DCAVP] Replay bundle → {bundle_path}", file=sys.stderr)

        return 1 if result.pipeline_blocked else 0

    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def _print_human(output: dict, result) -> None:
    """Human-readable analysis output."""
    status_sym = "✓" if output["status"] == "PASS" else "✗"
    print(f"\n{'='*60}")
    print(f"  DCAVP Analysis Report")
    print(f"{'='*60}")
    print(f"  Status         : {status_sym} {output['status']}")
    print(f"  Tier           : {output['tier']}")
    print(f"  Source         : {output['source_root']}")
    print(f"  Files          : {output['files_analyzed']}")
    print(f"  Nodes          : {output['nodes_discovered']}")
    print(f"  Findings       : {output['finding_count']}")
    print(f"  Analysis Conf.: {output['trust_level']} ({output['honesty_score']}/1000)")
    print(f"  Elapsed        : {output['elapsed_ms']}ms")
    print(f"  Artifact hash  : {output['artifact_hash'][:48]}...")

    if output["findings"]:
        print(f"\n  Findings:")
        icons = {"critical": "🔴", "error": "🟠", "warning": "🟡", "info": "🔵"}
        for f in output["findings"]:
            icon = icons.get(f["severity"], "?")
            hr   = " [HUMAN REVIEW]" if f["human_review"] else ""
            loc  = f["location"].split("/")[-1]
            print(f"  {icon} {f['id']}  {f['severity'].upper():8s}  "
                  f"{f['construct']:12s}  {loc}{hr}")

    if output.get("warnings"):
        print(f"\n  Warnings ({len(output['warnings'])}):")
        for w in output["warnings"]:
            print(f"    ⚠ {w[:80]}")

    if output['pipeline_blocked']:
            has_nodes = output.get("nodes_discovered", 0) > 0
            has_findings = output.get("finding_count", 0) > 0
            if not has_nodes:
                print(f"\n  ✗ PIPELINE BLOCKED: ANALYSIS VACUUM - zero nodes produced")
            elif has_findings:
                print(f"\n  ✗ PIPELINE BLOCKED: CRITICAL findings exceed tier threshold")
            else:
                print(f"\n  ✗ PIPELINE BLOCKED: governance or integrity check failed")
    else:
            print(f"\n  ✓ Pipeline clear")


def _print_html(output: dict, result, filepath: str) -> None:
    """Generate standalone HTML report."""
    status_color = "#22c55e" if output["status"] == "PASS" else "#ef4444"
    status_text = output["status"]
    tier = output["tier"]
    tier_colors = {"GREEN": "#22c55e", "BLUE": "#3b82f6", "YELLOW": "#eab308", "RED": "#ef4444"}
    tier_color = tier_colors.get(tier, "#6b7280")
    
    findings_html = ""
    for f in output.get("findings", []):
        sev_color = "#ef4444" if f["severity"] == "critical" else "#eab308"
        findings_html += f"""
        <tr>
            <td style="color:{sev_color};font-weight:bold">{f['severity'].upper()}</td>
            <td>{f['construct']}</td>
            <td><code>{f['location']}</code></td>
            <td>{f['state']}</td>
            <td>{'⚠️ Yes' if f['human_review'] else 'No'}</td>
        </tr>"""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DCAVP Security Report — {output['source_root']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #f8fafc; font-size: 1.8rem; margin-bottom: 0.5rem; }}
        .subtitle {{ color: #94a3b8; margin-bottom: 2rem; }}
        .status-badge {{ display: inline-block; padding: 0.5rem 1.5rem; border-radius: 2rem; font-weight: bold; font-size: 1.2rem; background: {status_color}; color: white; margin-bottom: 1.5rem; }}
        .card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
        .card h2 {{ color: #f1f5f9; font-size: 1.1rem; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; }}
        .metric {{ text-align: center; }}
        .metric .value {{ font-size: 2rem; font-weight: bold; color: #f8fafc; }}
        .metric .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
        .tier-badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 1rem; font-weight: bold; font-size: 0.9rem; background: {tier_color}; color: white; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.75rem 0.5rem; border-bottom: 1px solid #334155; }}
        td {{ padding: 0.75rem 0.5rem; border-bottom: 1px solid #1e293b; font-size: 0.9rem; }}
        tr:hover {{ background: #334155; }}
        code {{ background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.85rem; }}
        .footer {{ text-align: center; color: #64748b; font-size: 0.8rem; margin-top: 2rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DCAVP Security Analysis Report</h1>
        <p class="subtitle">Deterministic security analysis for AI-generated Python code</p>
        <div class="status-badge">{status_text}</div>
        
        <div class="card">
            <h2>Summary</h2>
            <div class="grid">
                <div class="metric"><div class="value"><span class="tier-badge">{tier}</span></div><div class="label">Tier</div></div>
                <div class="metric"><div class="value">{output['files_analyzed']}</div><div class="label">Files</div></div>
                <div class="metric"><div class="value">{output['nodes_discovered']}</div><div class="label">Nodes</div></div>
                <div class="metric"><div class="value">{output['finding_count']}</div><div class="label">Findings</div></div>
                <div class="metric"><div class="value">{output['honesty_score']}/1000</div><div class="label">Analysis Confidence</div></div>
                <div class="metric"><div class="value">{output['elapsed_ms']}ms</div><div class="label">Elapsed</div></div>
            </div>
        </div>
        
        <div class="card">
            <h2>Source</h2>
            <p><code>{output['source_root']}</code></p>
            <p style="color:#94a3b8;font-size:0.85rem;margin-top:0.5rem;">Artifact: {output['artifact_hash'][:48]}...</p>
        </div>
        
        <div class="card">
            <h2>Findings ({len(output.get('findings', []))})</h2>
            {f'''<table>
                <tr><th>Severity</th><th>Construct</th><th>Location</th><th>State</th><th>Human Review</th></tr>
                {findings_html}
            </table>''' if findings_html else '<p style="color:#22c55e;">✓ No findings — pipeline clear</p>'}
        </div>
        
        <div class="footer">
            DCAVP v0.1.0 | Confidence: {output['trust_level']} | {'Pipeline BLOCKED' if output['pipeline_blocked'] else 'Pipeline CLEAR'}
        </div>
    </div>
</body>
</html>"""
    
    pathlib.Path(filepath).write_text(html, encoding='utf-8')
    print(f"\n[DCAVP] HTML report written to: {filepath}", file=sys.stderr)


def _print_html(output: dict, result, filepath: str) -> None:
    """Generate standalone HTML report."""
    status_color = "#22c55e" if output["status"] == "PASS" else "#ef4444"
    status_text = output["status"]
    tier = output["tier"]
    tier_colors = {"GREEN": "#22c55e", "BLUE": "#3b82f6", "YELLOW": "#eab308", "RED": "#ef4444"}
    tier_color = tier_colors.get(tier, "#6b7280")
    
    findings_html = ""
    for f in output.get("findings", []):
        sev_color = "#ef4444" if f["severity"] == "critical" else "#eab308"
        findings_html += f"""
        <tr>
            <td style="color:{sev_color};font-weight:bold">{f['severity'].upper()}</td>
            <td>{f['construct']}</td>
            <td><code>{f['location']}</code></td>
            <td>{f['state']}</td>
            <td>{'⚠️ Yes' if f['human_review'] else 'No'}</td>
        </tr>"""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DCAVP Security Report — {output['source_root']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #f8fafc; font-size: 1.8rem; margin-bottom: 0.5rem; }}
        .subtitle {{ color: #94a3b8; margin-bottom: 2rem; }}
        .status-badge {{ display: inline-block; padding: 0.5rem 1.5rem; border-radius: 2rem; font-weight: bold; font-size: 1.2rem; background: {status_color}; color: white; margin-bottom: 1.5rem; }}
        .card {{ background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
        .card h2 {{ color: #f1f5f9; font-size: 1.1rem; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; }}
        .metric {{ text-align: center; }}
        .metric .value {{ font-size: 2rem; font-weight: bold; color: #f8fafc; }}
        .metric .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
        .tier-badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 1rem; font-weight: bold; font-size: 0.9rem; background: {tier_color}; color: white; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.75rem 0.5rem; border-bottom: 1px solid #334155; }}
        td {{ padding: 0.75rem 0.5rem; border-bottom: 1px solid #1e293b; font-size: 0.9rem; }}
        tr:hover {{ background: #334155; }}
        code {{ background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.85rem; }}
        .footer {{ text-align: center; color: #64748b; font-size: 0.8rem; margin-top: 2rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DCAVP Security Analysis Report</h1>
        <p class="subtitle">Deterministic security analysis for AI-generated Python code</p>
        <div class="status-badge">{status_text}</div>
        
        <div class="card">
            <h2>Summary</h2>
            <div class="grid">
                <div class="metric"><div class="value"><span class="tier-badge">{tier}</span></div><div class="label">Tier</div></div>
                <div class="metric"><div class="value">{output['files_analyzed']}</div><div class="label">Files</div></div>
                <div class="metric"><div class="value">{output['nodes_discovered']}</div><div class="label">Nodes</div></div>
                <div class="metric"><div class="value">{output['finding_count']}</div><div class="label">Findings</div></div>
                <div class="metric"><div class="value">{output['honesty_score']}/1000</div><div class="label">Analysis Confidence</div></div>
                <div class="metric"><div class="value">{output['elapsed_ms']}ms</div><div class="label">Elapsed</div></div>
            </div>
        </div>
        
        <div class="card">
            <h2>Source</h2>
            <p><code>{output['source_root']}</code></p>
            <p style="color:#94a3b8;font-size:0.85rem;margin-top:0.5rem;">Artifact: {output['artifact_hash'][:48]}...</p>
        </div>
        
        <div class="card">
            <h2>Findings ({len(output.get('findings', []))})</h2>
            {f'''<table>
                <tr><th>Severity</th><th>Construct</th><th>Location</th><th>State</th><th>Human Review</th></tr>
                {findings_html}
            </table>''' if findings_html else '<p style="color:#22c55e;">✓ No findings — pipeline clear</p>'}
        </div>
        
        <div class="footer">
            DCAVP v0.1.0 | Confidence: {output['trust_level']} | {'Pipeline BLOCKED' if output['pipeline_blocked'] else 'Pipeline CLEAR'}
        </div>
    </div>
</body>
</html>"""
    
    pathlib.Path(filepath).write_text(html, encoding='utf-8')
    print(f"\n[DCAVP] HTML report written to: {filepath}", file=sys.stderr)
    print(f"{'='*60}\n")


def cmd_verify(args: argparse.Namespace) -> int:
    """Run self-verification gateway."""
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent.parent))
        from src.verification.self_test.self_verification import SelfVerificationGateway

        source_root = args.source_root or str(pathlib.Path(__file__).parent.parent.parent.parent)
        if not args.quiet:
            print(f"[DCAVP] Running self-verification on: {source_root}", file=sys.stderr)

        gateway = SelfVerificationGateway(source_root)
        report  = gateway.verify()

        print(f"\n{'='*60}")
        print(f"  DCAVP Self-Verification Report")
        print(f"{'='*60}")
        print(f"  Timestamp  : {report.timestamp_utc}")
        print(f"  Kernel     : {report.kernel_version}")
        print(f"  Catalog    : {report.catalog_version}")
        print(f"  Checks     : {report.checks_passed}/{len(report.checks)} passed")
        print()
        for c in report.checks:
            sym = "✓" if c.passed else "✗"
            print(f"  [{sym}] {c.check_id}: {c.check_name}")
            if not c.passed:
                print(f"       → {c.diagnostic}")
        print()
        print(f"  {report.summary}")
        print(f"{'='*60}\n")

        return 0 if report.milestone_eligible else 3

    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def cmd_catalog(args: argparse.Namespace) -> int:
    """Show catalog information."""
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent.parent))
        from src.infrastructure.catalog.engine.catalog_loader import (
            load_python_catalog, get_catalog_summary,
        )

        catalog  = load_python_catalog()
        summary  = get_catalog_summary(catalog)
        is_valid, diag = catalog.verify_integrity()

        print(f"\n{'='*60}")
        print(f"  DCAVP Knowledge Catalog")
        print(f"{'='*60}")
        print(f"  Version    : {summary['catalog_version']}")
        print(f"  Constructs : {summary['construct_count']}")
        print(f"  Languages  : {summary['languages']}")
        print(f"  Merkle     : {summary['merkle_root'][:40]}...")
        print(f"  Signature  : {summary['signature']}")
        print(f"  Integrity  : {'✓ VERIFIED' if is_valid else '✗ FAILED'}")
        print()
        print("  Constructs:")
        for lang in sorted(catalog.list_languages()):
            for cid in catalog.list_by_language(lang):
                c = catalog.require_construct(cid)
                print(f"    {cid}  [{lang}]  "
                      f"dangers={len(c.danger_conditions)}  "
                      f"citations={len(c.knowledge_citations)}")
        print(f"{'='*60}\n")
        return 0

    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


def main() -> int:
    """DCAVP CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="dcavp",
        description="DCAVP — Deterministic Context-Aware Verification Platform",
    )
    parser.add_argument("--version", action="version", version="dcavp-kernel/0.1.0")

    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze a source tree")
    p_analyze.add_argument("source_root", help="Path to source root")
    p_analyze.add_argument("--tier", default="BLUE",
                            choices=["GREEN", "BLUE", "YELLOW", "RED"],
                            help="Analysis tier (default: BLUE)")
    p_analyze.add_argument("--seed", default="0xdeadbeef0000",
                            help="Execution seed for replay (must start with 0x)")
    p_analyze.add_argument("--format", default="human",
                            choices=["human", "json", "html"],
                            help="Output format (default: human)")
    p_analyze.add_argument("--output-bundle", metavar="PATH",
                            help="Write replay bundle to this path")
    p_analyze.add_argument("--quiet", action="store_true",
                            help="Suppress progress output")

    # verify (self-verification)
    p_verify = sub.add_parser("verify", help="Run self-verification gateway")
    p_verify.add_argument("--source-root", default=None,
                           help="Path to DCAVP source (default: auto-detect)")
    p_verify.add_argument("--quiet", action="store_true")

    # catalog
    p_catalog = sub.add_parser("catalog", help="Show catalog information")

    args = parser.parse_args()

    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "catalog":
        return cmd_catalog(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
