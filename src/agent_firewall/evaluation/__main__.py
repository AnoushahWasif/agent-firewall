"""Run the evaluation: every case in a split, with the firewall off and on.

    python -m agent_firewall.evaluation --split dev
    python -m agent_firewall.evaluation --split test --out reports/eval-test.json  # once

Writes JSON with every outcome and prints a table: attacks that leaked per family, normal tasks
completed, with 95% Wilson intervals (the sets are small, so a bare percentage overstates).
"""

import argparse
import asyncio
import json
import math
import statistics
import sys
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from agent_firewall.evaluation.cases import load_cases
from agent_firewall.evaluation.run import Outcome, run_case


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = hits / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centre - half), min(1.0, centre + half))


def summarise(outcomes: list[Outcome]) -> dict:
    groups: dict[tuple[str, bool], list[Outcome]] = defaultdict(list)
    for o in outcomes:
        groups[(o.family if o.kind == "attack" else "normal tasks", o.enforced)].append(o)
    rows = []
    for (family, enforced), items in sorted(groups.items()):
        good = (
            [o.completed for o in items] if family == "normal tasks" else [o.leaked for o in items]
        )
        hits = sum(good)
        low, high = wilson(hits, len(items))
        rows.append(
            {
                "family": family,
                "firewall": "on" if enforced else "off",
                "measure": "completed" if family == "normal tasks" else "leaked",
                "count": hits,
                "of": len(items),
                "ci95": [round(low, 3), round(high, 3)],
            }
        )
    on = [o.seconds for o in outcomes if o.enforced]
    off = [o.seconds for o in outcomes if not o.enforced]
    latency = {
        name: {
            "median_s": round(statistics.median(v), 4),
            "p95_s": round(sorted(v)[max(0, math.ceil(0.95 * len(v)) - 1)], 4),
        }
        for name, v in (("on", on), ("off", off))
        if v
    }
    return {"rows": rows, "latency_per_run": latency}


async def evaluate(cases_dir: Path, split: str) -> list[Outcome]:
    outcomes = []
    for case in load_cases(cases_dir):
        if split != "all" and case.split != split:
            continue
        for enforce in (False, True):
            outcomes.append(await run_case(case, enforce))
    return outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent_firewall.evaluation")
    parser.add_argument("--cases", type=Path, default=Path("attacks"))
    # No "all": the held-out half is only ever run on its own, on purpose, once.
    parser.add_argument("--split", choices=["dev", "test"], default="dev")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.split == "test" and args.out and args.out.exists():
        print(f"{args.out} exists: the held-out half is scored once.", file=sys.stderr)
        return 2
    outcomes = asyncio.run(evaluate(args.cases, args.split))
    summary = summarise(outcomes)
    for row in summary["rows"]:
        low, high = row["ci95"]
        print(
            f"{row['family']:<22} firewall {row['firewall']:<3} {row['measure']:<9} "
            f"{row['count']:>3}/{row['of']:<3} ({low:.0%}-{high:.0%})"
        )
    for name, lat in summary["latency_per_run"].items():
        print(f"run time, firewall {name}: median {lat['median_s']}s, p95 {lat['p95_s']}s")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "split": args.split,
            "summary": summary,
            "outcomes": [asdict(o) for o in outcomes],
        }
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
