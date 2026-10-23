"""
Rebuild everything with one command:

    python run.py            (add --no-pdf if Google Chrome is not installed)

  1. generate the synthetic poker room          -> data/*.csv
  2. load it into SQLite and run rules/*.sql     -> output/poker_room.sqlite
  3. group rule hits into ranked cases          -> output/case_list.md, output/case_list.csv
  4. check the results against the answer key    -> output/detection_check.md
  5. write the monthly fraud-trends report       -> output/monthly_fraud_trends.md / .html / .pdf

Python 3.10+ standard library only - nothing to install.
"""

import argparse
import os
import time
from pathlib import Path

from pipeline import cases as case_builder
from pipeline import check, detect, generate_data, report

ROOT = Path(__file__).resolve().parent
DATA, OUTPUT, RULES = ROOT / "data", ROOT / "output", ROOT / "rules"
DEFAULT_CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def step(n, text):
    print(f"[{n}/5] {text}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Regenerate the data, run the fraud rules, write cases and report.")
    parser.add_argument("--no-pdf", action="store_true", help="skip the PDF (no Chrome needed)")
    parser.add_argument("--chrome", default=os.environ.get("CHROME_PATH", DEFAULT_CHROME),
                        help="path to Chrome/Edge for the PDF (default: CHROME_PATH or the standard Windows path)")
    args = parser.parse_args()
    started = time.time()
    OUTPUT.mkdir(exist_ok=True)

    step(1, "Generating synthetic poker room ...")
    counts = generate_data.generate(DATA)
    print(f"      {counts['players']:,} players, {counts['hands']:,} hands, {counts['logins']:,} logins, "
          f"{counts['transactions']:,} deposits/withdrawals")

    step(2, "Loading into SQLite and running detection rules ...")
    con = detect.load(OUTPUT / "poker_room.sqlite", DATA)
    detect.run_rules(con, RULES)
    for table, n in detect.signal_counts(con).items():
        print(f"      {table:<28} {n:>4}")

    step(3, "Building ranked case list ...")
    cases = case_builder.build_cases(con)
    case_builder.write_case_list(con, cases, OUTPUT)
    by_priority = {p: sum(c.priority == p for c in cases) for p in ("P1", "P2", "P3")}
    print(f"      {len(cases)} cases: " + ", ".join(f"{n} {p}" for p, n in by_priority.items()))

    step(4, "Checking results against the planted answer key ...")
    summary, unplanned = check.check(con, cases, DATA, OUTPUT)
    print(f"      fraud scenarios caught {summary['fraud_caught']}/{summary['fraud_total']}, "
          f"look-alikes left alone {summary['benign_ok']}/{summary['benign_total']}, "
          f"unplanned cases {summary['unplanned']}")

    step(5, "Writing monthly fraud-trends report ...")
    chrome = None
    if not args.no_pdf:
        if Path(args.chrome).exists():
            chrome = args.chrome
        else:
            print(f"      Chrome not found at {args.chrome} - skipping the PDF (use --chrome PATH or --no-pdf)")
    pages = report.write_report(con, cases, summary, OUTPUT, chrome)
    if pages is not None:
        print(f"      PDF written ({pages} page{'s' if pages != 1 else ''})")
        if pages != 1:
            print("      WARNING: the report is meant to fit on one page")
    con.close()

    print(f"\nDone in {time.time() - started:.1f}s. Open output/case_list.md and output/monthly_fraud_trends.pdf")


if __name__ == "__main__":
    main()
