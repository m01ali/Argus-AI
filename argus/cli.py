#!/usr/bin/env python3
"""
Argus-AI command-line interface.

Usage:
    python -m argus.cli --target 192.168.56.101 --authorize
    python -m argus.cli --target 192.168.56.101 --authorize --dry-run

The --authorize flag confirms you hold written authorisation to test the
target. Without it, Argus-AI refuses to run. Patch application is interactive:
for each confirmed finding you are shown the proposed remediation and asked
y/n before anything is applied.
"""

from __future__ import annotations

import argparse
import logging
import sys

from .config import ArgusConfig
from .orchestrator import Argus
from .models import Finding
from .report import write_reports


def _interactive_authorizer(f: Finding) -> bool:
    print("\n" + "=" * 70)
    print(f"CONFIRMED FINDING {f.finding_id}: {f.title}  [{f.severity.value}]")
    print("-" * 70)
    print(f.description or "(no description)")
    print("\nProposed remediation:\n")
    print(f.remediation or "(none generated)")
    print("=" * 70)
    try:
        ans = input("Authorise applying this patch? [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans == "y"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Argus-AI privacy-first assessment agent")
    parser.add_argument("--target", required=True, help="In-scope target host/IP")
    parser.add_argument("--authorize", action="store_true",
                        help="Confirm you have written authorisation to test the target")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate commands but do not execute them")
    parser.add_argument("--executor-model", default=None)
    parser.add_argument("--advisor-model", default=None)
    parser.add_argument("--ollama-host", default=None)
    parser.add_argument("--max-iterations", type=int, default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    cfg = ArgusConfig.from_env()
    cfg.scope.authorized_targets = [args.target]
    cfg.scope.authorization_confirmed = args.authorize
    cfg.sandbox.enabled = not args.dry_run
    if args.executor_model:
        cfg.models.executor_model = args.executor_model
    if args.advisor_model:
        cfg.models.advisor_model = args.advisor_model
    if args.ollama_host:
        cfg.models.ollama_host = args.ollama_host
    if args.max_iterations:
        cfg.max_loop_iterations = args.max_iterations

    if not args.authorize:
        print("Refusing to run without --authorize. You must confirm written "
              "authorisation to test the target.", file=sys.stderr)
        return 2

    argus = Argus(cfg, authorizer=_interactive_authorizer)
    try:
        results = argus.run(args.target)
    except PermissionError as exc:
        print(f"Authorisation error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - surface any backend failure clearly
        print(f"Run failed: {exc}", file=sys.stderr)
        return 1

    md, js = write_reports(results, args.target, cfg.report.output_dir)
    print(f"\nReports written:\n  {md}\n  {js}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
