"""
Step 4 of the pipeline: compare what the rules found with what was planted.

The rules never see data/answer_key.csv. Because the same project designed both
the data and the rules, a good score shows the pipeline works end to end - it
does not show the thresholds are tuned for real traffic.
"""

import csv

from pipeline.cases import LABELS, md_table


def check(con, cases, data_dir, out_dir):
    with open(data_dir / "answer_key.csv", newline="", encoding="utf-8") as f:
        key = list(csv.DictReader(f))
    case_of = {p: c for c in cases for p in c.players}
    excluded = {r[0] for r in con.execute("SELECT shared_value FROM excluded_shared_values")}

    def flagged(kind, players):
        return [c for c in cases for s in c.signals if s.kind == kind and set(s.players) & set(players)]

    results, planted = [], set()
    for row in key:
        players = row["player_ids"].split(";")
        planted.update(players)
        expected = row["expected"]
        hit_cases = sorted({case_of[p].case_id + f" ({case_of[p].priority})" for p in players if p in case_of})
        if row["kind"] == "fraud":
            kinds = expected.split(";")
            in_case = [case_of[p] for p in players if p in case_of]
            one_case = len(in_case) == len(players) and len({c.case_id for c in in_case}) == 1
            if not in_case:
                verdict = "Missed"
            elif one_case and all(k in in_case[0].kinds for k in kinds):
                verdict = "Caught"
            else:
                verdict = "Partly caught"
            expect_text = " + ".join(LABELS[k] for k in kinds)
        elif expected.startswith("no:"):
            kind = expected[3:]
            verdict = "Correctly not flagged" if not flagged(kind, players) else "False positive"
            expect_text = f"No '{LABELS[kind]}' flag"
        elif expected == "watchlist_only":
            verdict = "Correctly not flagged (watchlist only)" if not hit_cases else "False positive"
            expect_text = "No case; weak IP link on the watchlist"
        elif expected in ("excluded_ip", "excluded_wallet"):
            linked = con.execute("SELECT COUNT(*) FROM link_evidence WHERE shared_value = ?", (row["value"],)).fetchone()[0]
            verdict = "Correctly ignored" if row["value"] in excluded and not linked else "Not ignored"
            expect_text = "Shared value ignored by the linking rule"
        else:  # expected_fp:<kind>
            kind = expected.split(":")[1]
            verdict = ("Flagged - expected false positive for an analyst to clear" if flagged(kind, players)
                       else "Not flagged")
            expect_text = f"{LABELS[kind]} flag that a human must clear"
        results.append({"row": row, "verdict": verdict, "expected": expect_text, "cases": hit_cases, "players": players})

    unplanned = [c for c in cases if not set(c.players) & planted]
    fraud = [r for r in results if r["row"]["kind"] == "fraud"]
    benign = [r for r in results if r["row"]["kind"] == "benign" and not r["row"]["expected"].startswith("expected_fp")]
    fp = [r for r in results if r["row"]["expected"].startswith("expected_fp")]
    summary = {
        "fraud_caught": sum(r["verdict"] == "Caught" for r in fraud),
        "fraud_partly": sum(r["verdict"] == "Partly caught" for r in fraud),
        "fraud_total": len(fraud),
        "benign_ok": sum(r["verdict"].startswith("Correctly") for r in benign),
        "benign_total": len(benign),
        "expected_fp_flagged": sum(r["verdict"].startswith("Flagged") for r in fp),
        "unplanned": len(unplanned),
    }

    out = ["# Detection check - rules vs. the planted answer key", "",
           "_The generator writes down every scenario it plants in `data/answer_key.csv`. The rules never read that "
           "file. This page compares the two. Because the same project designed both the data and the rules, a good "
           "score proves the pipeline works end to end, not that the thresholds would hold on real traffic._", "",
           f"- **Fraud scenarios caught:** {summary['fraud_caught']} of {summary['fraud_total']} "
           f"(all accounts in one case, with the expected signals)"
           + (f"; {summary['fraud_partly']} partly caught" if summary["fraud_partly"] else ""),
           f"- **Innocent look-alikes correctly left alone:** {summary['benign_ok']} of {summary['benign_total']}",
           f"- **Planted false positive flagged (on purpose):** {summary['expected_fp_flagged']} of {len(fp)}",
           f"- **Cases not linked to any planted scenario:** {summary['unplanned']}", "",
           "## Fraud scenarios", "",
           md_table(["ID", "What was planted", "Expected", "Result", "Case"],
                    [[r["row"]["scenario_id"], f"**{r['row']['title']}** - {r['row']['notes']}", r["expected"],
                      r["verdict"], ", ".join(r["cases"]) or "-"] for r in fraud]), "",
           "## Innocent look-alikes", "",
           md_table(["ID", "What was planted", "Expected", "Result", "Case"],
                    [[r["row"]["scenario_id"], f"**{r['row']['title']}** - {r['row']['notes']}", r["expected"],
                      r["verdict"], ", ".join(r["cases"]) or "-"]
                     for r in sorted(benign + fp, key=lambda r: r["row"]["scenario_id"])]), ""]
    out += ["## Cases nobody planted", ""]
    if unplanned:
        out += ["These came out of the random 'normal' population. They are treated like any other lead: an analyst "
                "works through the verification steps in the case list.", ""]
        out += md_table(["Case", "Priority", "Signals", "Summary"],
                        [[c.case_id, c.priority, " + ".join(LABELS[k] for k in c.kinds),
                          " ".join(c.headlines[k] for k in c.kinds)] for c in unplanned]).split("\n")
    else:
        out += ["_None._"]
    (out_dir / "detection_check.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    return summary, unplanned
