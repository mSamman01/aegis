"""Build the evaluation cases, to look at them:  python tools/make_eval_cases.py [--out FOLDER]

``python -m aegis evaluate`` rebuilds the cases itself before scoring them;
this script only builds them. What a case is, and how the benign twins are
made, is described in aegis/evalcases.py. Cases from real data hold real
alerts and are written to data/eval/cases, which git ignores (D8).
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.evalcases import DEFAULT_CASES, CaseError, build_all  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Aegis's evaluation cases.")
    parser.add_argument("--out", type=Path, default=DEFAULT_CASES, help="where to write them (default: data/eval/cases)")
    args = parser.parse_args()
    try:
        built = build_all(args.out)
    except (OSError, CaseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for spec in built:
        labels = spec["labels"]
        print(f"{spec['name']:<24} {spec['kind']:<9} {spec['alerts']:>5} alerts  {spec['verdicts']:>4} verdicts  "
              f"{len(labels['attack_events'])} attack anchor(s)  {spec['about'][:60]}")
    print(f"Wrote {len(built)} cases to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
