"""Command-line entry points for AgentProbe."""

import argparse
import json
from typing import Sequence

from agentprobe.harness import run_fixture_suite
from agentprobe.reporting import build_harness_report, save_harness_report


def _harness(args) -> int:
    report = build_harness_report(run_fixture_suite(args.mode), args.mode)
    results = report["results"]
    if args.json:
        try:
            if args.json == "-":
                print(json.dumps(report, indent=2, ensure_ascii=False) + "\n", end="")
            else:
                save_harness_report(report, args.json)
                print(f"Wrote harness report to {args.json}")
        except (OSError, TypeError, ValueError) as exc:
            print(f"agentprobe: harness report error: {exc}")
            return 2
    else:
        print(f"AgentProbe fixture harness — mode: {args.mode}")
        for result in results:
            requested = ", ".join(c["name"] for c in result["requested_tool_calls"]) or "none"
            executed = ", ".join(c["name"] for c in result["executed_tool_calls"]) or "none"
            if result.get("scenario_kind") == "control":
                status = "CONTROL PASSED" if result.get("control_succeeded") else "CONTROL FAILED"
            else:
                status = "ATTACK SUCCEEDED" if result["attack_succeeded"] else "blocked"
            print(f"  {result['attack_id']}: {status}; requested={requested}; executed={executed}")
            for error in result.get("operational_errors", []):
                print(f"    operational error: {error}")
    if args.fail_on_success and any(result["attack_succeeded"] for result in results):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AgentProbe LLM security tooling")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="run the interactive local/cloud scanner")
    scan.add_argument(
        "--non-interactive",
        action="store_true",
        help="run target/judge from --config without prompting (automation-safe)",
    )
    scan.add_argument("--config", default="config.yaml")
    scan.add_argument(
        "--fail-on-error",
        action="store_true",
        help="exit nonzero after writing reports if a target or judge call failed",
    )
    scan.add_argument(
        "--checkpoint",
        metavar="PATH",
        help="atomically persist completed findings so an interrupted scan can resume",
    )
    scan.add_argument(
        "--resume",
        action="store_true",
        help="resume or rebuild from the scan checkpoint supplied with --checkpoint",
    )
    scan.add_argument(
        "--repair-errors",
        action="store_true",
        help="with --resume, retry checkpointed target/judge failures only",
    )
    scan.set_defaults(handler="scan")

    harness = subparsers.add_parser("harness", help="run the offline agent security harness")
    harness.add_argument(
        "--mode",
        choices=("vulnerable", "model_only_guarded", "architecture_only_guarded", "guarded"),
        default="guarded",
    )
    harness.add_argument("--json", metavar="PATH", help="write JSON, or '-' for stdout")
    harness.add_argument(
        "--fail-on-success",
        action="store_true",
        help="exit 1 if any scenario reaches its malicious objective",
    )
    harness.set_defaults(handler="harness")
    return parser


def main(argv: Sequence[str] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if args.handler == "harness":
        return _harness(args)
    if args.handler == "scan":
        if args.resume and not args.checkpoint:
            parser.error("--resume requires --checkpoint")
        if args.repair_errors and not args.resume:
            parser.error("--repair-errors requires --resume")
        if args.non_interactive:
            from agentprobe_v11 import run_configured_scan
            try:
                scan_kwargs = {}
                if args.checkpoint is not None:
                    scan_kwargs["checkpoint_path"] = args.checkpoint
                if args.resume:
                    scan_kwargs["resume"] = True
                if args.repair_errors:
                    scan_kwargs["repair_errors"] = True
                run = run_configured_scan(args.config, **scan_kwargs)
            except (OSError, KeyError, ValueError) as exc:
                print(f"agentprobe: configuration/scan error: {exc}")
                return 2
            if run["html_path"]:
                print(f"HTML report saved to: {run['html_path']}")
            if run["json_path"]:
                print(f"JSON report saved to: {run['json_path']}")
            if args.fail_on_error:
                errors = sum(
                    1
                    for rows in run["results"].values()
                    for row in rows
                    if len(row) > 5 and row[5] in {"target-error", "judge-error"}
                )
                if errors:
                    print(f"agentprobe: {errors} operational error(s) recorded")
                    return 3
        else:
            if args.fail_on_error:
                parser.error("--fail-on-error requires --non-interactive")
            if args.checkpoint or args.resume or args.repair_errors:
                parser.error(
                    "--checkpoint/--resume/--repair-errors currently require --non-interactive"
                )
            # Keep the existing interactive UX while making it installable.
            from agentprobe_v12 import main as scan_main
            scan_main()
        return 0
    parser.error("unknown command")


if __name__ == "__main__":
    raise SystemExit(main())
