#!/usr/bin/env python3
# ============================================================
# AGENTPROBE v1.2 — DISCLOSURE CLI
# ============================================================
# Command-line front end for the responsible-disclosure workflow.
#
#   check     run the authorization gate for a target + mode
#   classify  decide if a candidate finding is PAYABLE / etc.
#   report    render a vendor disclosure report from a finding JSON
#   track     add / list / update findings in the disclosure ledger
#
# Examples:
#   python3 disclosure_cli.py check --target openai-safety-bounty --mode automated
#   python3 disclosure_cli.py check --target openai-safety-bounty --mode manual
#   python3 disclosure_cli.py classify --target openai-safety-bounty \
#       --category indirect_injection --crossed-boundary --reproducibility 0.7
#   python3 disclosure_cli.py report --target openai-safety-bounty --finding finding.json
#   python3 disclosure_cli.py track list
# ============================================================
import argparse
import json
import os
import sys

from disclosure.authorization import (
    require_authorization,
    load_authorization,
    find_authorization,
    classify_finding,
    AuthorizationError,
    MODE_AUTOMATED,
    MODE_MANUAL,
)
from disclosure.report import generate_disclosure_report
from disclosure import tracker


def cmd_check(args):
    try:
        auth = require_authorization(args.target, mode=args.mode)
    except AuthorizationError as e:
        print(f"BLOCKED — scan not permitted.\n\n{e}")
        return 1
    print(f"AUTHORIZED — {args.mode} testing of '{auth.target_id}' is permitted.")
    print(f"  Program:  {auth.program_name}")
    print(f"  Submit:   {auth.platform}")
    print(f"  Repro bar: {auth.min_reproducibility:.0%}   Safe harbor: {auth.safe_harbor}")
    print(f"  Confirmed by: {auth.authorized_by or '(unnamed)'} on {auth.authorized_date or '(no date)'}")
    return 0


def cmd_classify(args):
    path = find_authorization(args.target)
    if path is None:
        print(f"No authorization record for '{args.target}'.")
        return 1
    auth = load_authorization(path)
    result = classify_finding(
        category=args.category,
        crossed_trust_boundary=args.crossed_boundary,
        reproducibility=args.reproducibility,
        auth=auth,
    )
    print(f"Classification: {result}")
    print(f"  category={args.category}  crossed_boundary={args.crossed_boundary}  "
          f"reproducibility={args.reproducibility:.0%}  bar={auth.min_reproducibility:.0%}")
    return 0


def cmd_report(args):
    path = find_authorization(args.target)
    if path is None:
        print(f"No authorization record for '{args.target}'.")
        return 1
    auth = load_authorization(path)
    with open(args.finding, "r") as f:
        finding = json.load(f)
    md = generate_disclosure_report(finding, auth, reporter_handle=args.reporter)
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as f:
            f.write(md)
        print(f"Disclosure report written to: {args.out}")
    else:
        print(md)
    return 0


def cmd_track(args):
    if args.track_cmd == "list":
        findings = tracker.list_findings(target_id=args.target, status=args.status)
        if not findings:
            print("No findings tracked yet.")
            return 0
        for f in findings:
            repro = f.get("reproducibility")
            repro_s = f"{repro:.0%}" if isinstance(repro, (int, float)) else "—"
            print(f"  {f['id']:<28} {f['status']:<14} {f['classification']:<13} "
                  f"{f['severity']:<8} repro={repro_s}  {f['title']}")
        return 0
    if args.track_cmd == "add":
        fid = tracker.add_finding(
            target_id=args.target, title=args.title, category=args.category,
            classification=args.classification, severity=args.severity,
            discovered_date=args.date, reproducibility=args.reproducibility,
            note=args.note,
        )
        print(f"Added finding: {fid}")
        return 0
    if args.track_cmd == "update":
        record = tracker.update_status(
            args.id, args.status, args.date, note=args.note, bounty=args.bounty
        )
        print(f"{record['id']} -> {record['status']}")
        return 0
    return 1


def build_parser():
    p = argparse.ArgumentParser(description="AgentProbe v1.2 disclosure workflow")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="run the authorization gate")
    c.add_argument("--target", required=True)
    c.add_argument("--mode", choices=[MODE_AUTOMATED, MODE_MANUAL], default=MODE_AUTOMATED)
    c.set_defaults(func=cmd_check)

    c = sub.add_parser("classify", help="classify a candidate finding")
    c.add_argument("--target", required=True)
    c.add_argument("--category", required=True)
    c.add_argument("--crossed-boundary", dest="crossed_boundary", action="store_true")
    c.add_argument("--reproducibility", type=float, default=0.0)
    c.set_defaults(func=cmd_classify)

    c = sub.add_parser("report", help="render a disclosure report from a finding JSON")
    c.add_argument("--target", required=True)
    c.add_argument("--finding", required=True, help="path to finding JSON")
    c.add_argument("--reporter", default="nar1")
    c.add_argument("--out", help="write markdown here instead of stdout")
    c.set_defaults(func=cmd_report)

    c = sub.add_parser("track", help="disclosure ledger")
    tsub = c.add_subparsers(dest="track_cmd", required=True)
    tl = tsub.add_parser("list")
    tl.add_argument("--target")
    tl.add_argument("--status")
    ta = tsub.add_parser("add")
    ta.add_argument("--target", required=True)
    ta.add_argument("--title", required=True)
    ta.add_argument("--category", required=True)
    ta.add_argument("--classification", required=True)
    ta.add_argument("--severity", required=True)
    ta.add_argument("--date", required=True)
    ta.add_argument("--reproducibility", type=float)
    ta.add_argument("--note", default="")
    tu = tsub.add_parser("update")
    tu.add_argument("--id", required=True)
    tu.add_argument("--status", required=True)
    tu.add_argument("--date", required=True)
    tu.add_argument("--note", default="")
    tu.add_argument("--bounty", type=float)
    c.set_defaults(func=cmd_track)

    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))
