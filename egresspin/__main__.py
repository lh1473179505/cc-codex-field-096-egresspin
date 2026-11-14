from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .engine import admit_request, inspect_plan
from .load import load_json, load_pin_store, load_policy, load_resolver


def _write_json(path: str, obj) -> None:
    Path(path).write_text(
        json.dumps(obj, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _save_pin_store(path: str, store: dict) -> None:
    target = Path(path)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(
        json.dumps(store, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, target)


def cmd_inspect(args: argparse.Namespace) -> int:
    plan = load_json(args.plan)
    report = inspect_plan(plan)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


def cmd_admit(args: argparse.Namespace) -> int:
    try:
        plan = load_json(args.plan)
        resolver = load_resolver(args.resolver)
        policy = load_policy(args.policy)
        store = load_pin_store(args.pin_store)
        report = admit_request(plan, resolver, policy, store)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"load failure: {e}", file=sys.stderr)
        return 2
    except NotImplementedError as e:
        print(str(e), file=sys.stderr)
        return 2

    _write_json(args.report, report)
    _save_pin_store(args.pin_store, store)
    decision = report.get("decision")
    if decision == "allow":
        return 0
    if decision == "deny":
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="egresspin")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_i = sub.add_parser("inspect")
    p_i.add_argument("--plan", required=True)
    p_i.add_argument("--report")
    p_i.set_defaults(func=cmd_inspect)

    p_a = sub.add_parser("admit")
    p_a.add_argument("--plan", required=True)
    p_a.add_argument("--resolver", required=True)
    p_a.add_argument("--policy", required=True)
    p_a.add_argument("--pin-store", required=True)
    p_a.add_argument("--report", required=True)
    p_a.set_defaults(func=cmd_admit)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
