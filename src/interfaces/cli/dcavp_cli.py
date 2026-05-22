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
    print(f"  Trust          : {output['trust_level']} ({output['honesty_score']}/1000)")
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

    if output["pipeline_blocked"]:
        print(f"\n  ✗ PIPELINE BLOCKED: findings exceed tier threshold")
    else:
        print(f"\n  ✓ Pipeline clear")
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
                            choices=["human", "json"],
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
