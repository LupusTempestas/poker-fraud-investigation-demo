"""
Step 5 of the pipeline: the one-page "Monthly fraud trends" report.

Built from the ranked cases: what was opened this month, how that compares with
earlier months, which rings were active, and what to change. Written twice from
the same content - Markdown (readable on GitHub) and HTML, which headless Chrome
prints to a one-page PDF. Charts are plain SVG drawn here, so nothing needs
installing.
"""

import html
import re
import subprocess
import tempfile
from datetime import date

from pipeline.cases import LABELS, usdt

REPORT_MONTH = "2026-09"
MONTHS = ["2026-07", "2026-08", "2026-09"]
MONTH_NAMES = {"2026-07": "July", "2026-08": "August", "2026-09": "September"}

# Colours: the validated default categorical palette (slots 1-4) and neutral chart ink
SURFACE, INK, INK_2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BAD, GOOD = "#d03b3b", "#006300"
FAMILY_ORDER = ["Game integrity", "Account security", "Bonus abuse & multi-accounting", "AML"]
FAMILY_SHORT = {"Game integrity": "Game integrity", "Account security": "Account security",
                "Bonus abuse & multi-accounting": "Bonus & multi-accounting", "AML": "AML"}
FAMILY_COLOR = dict(zip(FAMILY_ORDER, ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]))
FONT = "'Segoe UI', system-ui, -apple-system, sans-serif"


# =============================================================================
# Numbers
# =============================================================================

def device_reused_from_home(con, sig):
    r = sig.row
    return con.execute("""SELECT COUNT(*) FROM logins WHERE player_id = ? AND device_id = ? AND ts > ?
                          AND ip_country = ?""",
                       (r["player_id"], r["device_id"], r["withdrawal_ts"], r["home_country"])).fetchone()[0] > 0


def monthly_numbers(cases):
    by_month = {m: [c for c in cases if c.month == m] for m in MONTHS}
    counts = {m: {f: sum(c.family == f for c in by_month[m]) for f in FAMILY_ORDER} for m in MONTHS}
    exposure = {f: sum(c.total_exposure for c in by_month[REPORT_MONTH] if c.family == f) for f in FAMILY_ORDER}
    return by_month, counts, exposure


def kpis(by_month):
    cur, prev = by_month[REPORT_MONTH], by_month[MONTHS[-2]]
    accounts = lambda cs: len({p for c in cs for p in c.players})
    money = lambda cs: sum(c.total_exposure for c in cs)
    p1 = lambda cs: sum(c.priority == "P1" for c in cs)
    return [("New cases", len(cur), len(prev), str), ("Accounts involved", accounts(cur), accounts(prev), str),
            ("Money at risk", money(cur), money(prev), lambda v: f"{v:,.0f} USDT"),
            ("P1 cases (review today)", p1(cur), p1(prev), str)]


def insights(con, cases, by_month):
    cur, prev = by_month[REPORT_MONTH], by_month[MONTHS[-2]]
    month, prev_name = MONTH_NAMES[REPORT_MONTH], MONTH_NAMES[MONTHS[-2]]
    month_start = REPORT_MONTH + "-01"
    out = []

    ato_cur = [s for c in cur for s in c.of("account_takeover")]
    ato_prev = [s for c in prev for s in c.of("account_takeover")]
    if ato_cur:
        text = f"**Account takeover: {len(ato_cur)} flags (vs {len(ato_prev)} in {prev_name}).** "
        campaign_flags = 0
        for c in cur:
            sigs = c.of("account_takeover")
            if len(sigs) > 1:
                campaign_flags += len(sigs)
                text += (f"{len(sigs)} were one campaign: the same device, IP and payout wallet on consecutive nights, "
                         f"{usdt(c.exposure['account_takeover'])} withdrawn, all from hosting (server/VPN) IPs. ")
        maybe_phone = [s for s in ato_cur if device_reused_from_home(con, s)]
        if maybe_phone:
            other = " other" if campaign_flags else ""
            text += (f"{len(maybe_phone)}{other} flag looks like a traveller's new phone (the 'new' device was later "
                     f"used from home): probably a false positive, to confirm with the player."
                     if len(maybe_phone) == 1 else
                     f"{len(maybe_phone)}{other} flags look like travellers' new phones: probably false positives.")
        out.append(text)

    farms = [c for c in cur if c.of("bonus_abuse")]
    earlier = [c for m in MONTHS[:-1] for c in by_month[m] if c.of("bonus_abuse")]
    if farms:
        big = max(farms, key=lambda c: len(c.of("bonus_abuse")[0].players))
        members = big.of("bonus_abuse")[0].row["members"]
        disposable = sum(m["email_domain"].endswith(".example") for m in members)
        spread = int(con.execute("SELECT julianday(?) - julianday(?)",
                                 (members[-1]["signup_ts"], members[0]["signup_ts"])).fetchone()[0]) + 1
        text = f"**Bonus abuse: a farm of {len(members)} linked accounts"
        if earlier:
            prior = max(earlier, key=lambda c: len(c.of("bonus_abuse")[0].players))
            text += f" (largest before: {len(prior.of('bonus_abuse')[0].players)} in {MONTH_NAMES[prior.month]})"
        emails = "all" if disposable == len(members) else f"{disposable} of {len(members)}"
        text += (f".** Opened within {spread} days, {emails} with disposable emails; each took the welcome bonus "
                 f"and they cashed out {usdt(sum(m['withdrawn_usdt'] for m in members))}. Small money, "
                 f"but the pattern is scaling.")
        out.append(text)

    passes = [s for c in cur for s in c.of("aml_pass_through")]
    structs = [s for c in cur for s in c.of("aml_structuring")]
    if passes or structs:
        text = "**AML: "
        if passes:
            shared = len({s.row["payout_wallets"] for s in passes}) < len(passes)
            swapped = sum(s.row["deposit_asset"] != s.row["payout_assets"] for s in passes)
            text += (f"{len(passes)} new account{'s' if len(passes) > 1 else ''} moved "
                     f"{usdt(sum(s.row['deposit_usdt'] for s in passes))} through with almost no play.** ")
            details = ["they shared a payout wallet"] if shared else []
            if swapped:
                details.append(("all" if swapped == len(passes) else f"{swapped} of {len(passes)}")
                               + " switched from BTC/ETH to USDT on the way")
            if details:
                sentence = ", and ".join(details)
                text += sentence[0].upper() + sentence[1:] + ". "
        else:
            text += "structuring.** "
        for s in structs:
            text += (f"{'Separately, ' if passes else ''}{s.row['player_id']} made {s.row['deposits']} deposits just under "
                     f"the {s.row['threshold_usdt']:,} USDT review threshold in a week (structuring). ")
        out.append(text + "All of these go to the MLRO; the players are not told why.")

    integrity_new = [c for c in cur if c.family == "Game integrity"]
    integrity_old = [c for c in cases if c.family == "Game integrity" and c.month < REPORT_MONTH and c.last_ts >= month_start]
    if integrity_new or integrity_old:
        bits = []
        if integrity_new:
            kinds = sorted({LABELS[c.kinds[0]].split(" /")[0].lower() for c in integrity_new})
            bits.append(f"{len(integrity_new)} new {' and '.join(kinds)} case{'s' if len(integrity_new) > 1 else ''} "
                        f"({usdt(sum(c.total_exposure for c in integrity_new))})")
        if integrity_old:
            bits.append("still active from earlier months: " + ", ".join(
                f"the {MONTH_NAMES[c.month]} {LABELS[c.kinds[0]].split(' /')[0].lower()} group ({len(c.players)} "
                f"accounts, until {c.last_ts[8:10].lstrip('0')} {month[:3]})" for c in integrity_old))
        out.append("**Game integrity:** " + "; ".join(bits) + ".")
    return out


def rings(cases):
    active = [c for c in cases if c.last_ts >= REPORT_MONTH + "-01" and len(c.players) >= 3]
    return sorted(active, key=lambda c: -c.score)


def recommendations(con, by_month):
    cur = by_month[REPORT_MONTH]
    kinds = {k for c in cur for k in c.kinds}
    out = []
    if "account_takeover" in kinds:
        out.append("**Step-up check on new-wallet withdrawals.** Ask for 2FA or email confirmation when a withdrawal "
                   "goes to a never-used wallet within 24 h of a login from a new device and country. It would have "
                   "challenged every takeover withdrawal this month; the cost is one extra step for travellers.")
    if "bonus_abuse" in kinds:
        out.append("**Make the welcome bonus slower to cash out:** hold it for 7 days or 100 hands, and refuse it to "
                   "devices and wallets already linked to a claimed bonus.")
    if kinds & {"aml_pass_through", "aml_structuring"}:
        out.append("**Send this month's AML cases to the MLRO** and screen the shared payout wallet with blockchain "
                   "analytics; hold large deposits that are withdrawn almost unplayed for manual review.")
    private = con.execute("""SELECT SUM(h.seats = 2), COUNT(*) FROM sig_chip_dumping s
                             JOIN hand_players a ON a.player_id = s.from_player
                             JOIN hand_players b ON b.hand_id = a.hand_id AND b.player_id = s.to_player
                             JOIN hands h ON h.hand_id = a.hand_id""").fetchone()
    if private[1] and private[0] / private[1] >= 0.9:
        out.append(f"**Alert in real time when linked accounts open a two-seat table together:** "
                   f"{100 * private[0] / private[1]:.0f}% of the hands between flagged chip-dumping pairs this quarter "
                   f"were played at one.")
    return out


# =============================================================================
# Charts (plain SVG)
# =============================================================================

def esc(text):
    return html.escape(str(text), quote=True)


def column_path(x, y, w, h, r):
    """A bar with rounded top corners and a square base."""
    r = min(r, h, w / 2)
    return (f"M{x:.1f},{y + h:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} H{x + w - r:.1f} "
            f"Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} V{y + h:.1f} Z")


def row_path(x, y, w, h, r):
    """A horizontal bar with a rounded right end and a square base on the left."""
    r = min(r, w, h / 2)
    return (f"M{x:.1f},{y:.1f} H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} V{y + h - r:.1f} "
            f"Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f} H{x:.1f} Z")


def svg_open(w, h, title):
    return [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" aria-label="{esc(title)}" font-family="{FONT}">',
            f"<title>{esc(title)}</title>", f'<rect width="{w}" height="{h}" fill="{SURFACE}"/>']


def chart_cases_by_month(counts):
    w, h = 340, 182
    left, right, top, base = 30, 330, 52, 158
    title = "New cases per month by type"
    out = svg_open(w, h, title)
    for i, fam in enumerate(FAMILY_ORDER):           # legend: two rows of two
        x, y = (0, 0) if i % 2 == 0 else (165, 0)
        y = 8 + 18 * (i // 2)
        out.append(f'<rect x="{x}" y="{y}" width="10" height="10" rx="2" fill="{FAMILY_COLOR[fam]}"/>')
        out.append(f'<text x="{x + 15}" y="{y + 9}" font-size="11" fill="{INK_2}">{esc(FAMILY_SHORT[fam])}</text>')
    totals = [sum(counts[m].values()) for m in MONTHS]
    top_value = max(2, -(-max(totals) // 2) * 2)
    scale = (base - top) / top_value
    for tick in range(0, top_value + 1, 2):
        y = base - tick * scale
        out.append(f'<line x1="{left}" x2="{right}" y1="{y:.1f}" y2="{y:.1f}" stroke="{AXIS if tick == 0 else GRID}" stroke-width="1"/>')
        out.append(f'<text x="{left - 8}" y="{y + 3.5:.1f}" font-size="10" fill="{MUTED}" text-anchor="end">{tick}</text>')
    band = (right - left) / len(MONTHS)
    for i, m in enumerate(MONTHS):
        cx = left + band * (i + 0.5)
        x, done = cx - 12, 0
        stack = [f for f in FAMILY_ORDER if counts[m][f]]
        for j, fam in enumerate(stack):
            n = counts[m][fam]
            y_top = base - (done + n) * scale
            y_bottom = base - done * scale - (2 if j > 0 else 0)       # 2px surface gap between segments
            shape = (column_path(x, y_top, 24, y_bottom - y_top, 4) if j == len(stack) - 1
                     else f"M{x:.1f},{y_top:.1f} H{x + 24:.1f} V{y_bottom:.1f} H{x:.1f} Z")
            out.append(f'<path d="{shape}" fill="{FAMILY_COLOR[fam]}"><title>{esc(MONTH_NAMES[m])} · '
                       f'{esc(fam)}: {n} case{"s" if n > 1 else ""}</title></path>')
            done += n
        out.append(f'<text x="{cx:.1f}" y="{base - totals[i] * scale - 6:.1f}" font-size="11" font-weight="600" '
                   f'fill="{INK}" text-anchor="middle">{totals[i]}</text>')
        out.append(f'<text x="{cx:.1f}" y="{base + 18}" font-size="11" fill="{INK_2}" text-anchor="middle">'
                   f'{esc(MONTH_NAMES[m])}</text>')
    out.append("</svg>")
    return "\n".join(out)


def chart_exposure(exposure):
    w, h = 340, 182
    bar_x, bar_max = 152, 110
    title = f"Money at risk in {MONTH_NAMES[REPORT_MONTH]}'s new cases, by type (USDT)"
    out = svg_open(w, h, title)
    ordered = sorted(FAMILY_ORDER, key=lambda f: -exposure[f])
    biggest = max(exposure.values()) or 1
    row_h, bar_h, y0 = 37, 18, 24
    for i, fam in enumerate(ordered):
        y = y0 + i * row_h
        value = exposure[fam]
        out.append(f'<text x="0" y="{y + 13}" font-size="11" fill="{INK_2}">{esc(FAMILY_SHORT[fam])}</text>')
        length = bar_max * value / biggest
        if length >= 1:
            out.append(f'<path d="{row_path(bar_x, y, length, bar_h, 4)}" fill="{FAMILY_COLOR[fam]}">'
                       f'<title>{esc(fam)}: {value:,.0f} USDT</title></path>')
        out.append(f'<text x="{bar_x + length + 6:.1f}" y="{y + 13}" font-size="11" font-weight="600" fill="{INK}">'
                   f'{value:,.0f}</text>')
    out.append(f'<line x1="{bar_x}" x2="{bar_x}" y1="{y0 - 6}" y2="{y0 + 3 * row_h + bar_h + 6}" stroke="{AXIS}" stroke-width="1"/>')
    out.append("</svg>")
    return "\n".join(out)


# =============================================================================
# Rendering
# =============================================================================

def inline_md(text):
    """The tiny bit of Markdown used in report text (**bold**, `code`) as HTML."""
    text = esc(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", text)


def build(con, cases, check_summary):
    by_month, counts, exposure = monthly_numbers(cases)
    excluded = con.execute("SELECT value_type, accounts FROM excluded_shared_values").fetchall()
    phones = sum(device_reused_from_home(con, s) for c in cases for s in c.of("account_takeover"))
    return {
        "kpis": kpis(by_month),
        "counts": counts,
        "exposure": exposure,
        "insights": insights(con, cases, by_month),
        "rings": rings(cases),
        "recommendations": recommendations(con, by_month),
        "health": (f"7 rules, {len(cases)} cases this quarter; {len(excluded)} shared identifiers ignored as too "
                   f"common to identify anyone (carrier gateway, VPN exit, exchange wallet). Against the planted answer "
                   f"key: {check_summary['fraud_caught']}/{check_summary['fraud_total']} fraud scenarios caught, "
                   f"{check_summary['benign_ok']}/{check_summary['benign_total']} innocent look-alikes left alone. "
                   f"Known false-positive pattern: {phones} takeover flag{'s' if phones != 1 else ''} where the 'new' "
                   f"device was later used from home (a traveller's new phone) - which is why every flag goes to a "
                   f"human."),
    }


def delta_text(cur, prev, fmt):
    diff = cur - prev
    if diff == 0:
        return f"same as {MONTH_NAMES[MONTHS[-2]]}", INK_2
    arrow = "▲" if diff > 0 else "▼"
    return f"{arrow} {fmt(abs(diff))} vs {MONTH_NAMES[MONTHS[-2]]}", BAD if diff > 0 else GOOD


def render_markdown(r, chart_paths):
    month = MONTH_NAMES[REPORT_MONTH]
    out = [f"# Monthly fraud trends - {month} 2026", "",
           "_Demo crypto poker room · synthetic data · new cases opened in "
           f"{month}, compared with July and August. Generated by `python run.py`._", ""]
    out += ["| " + " | ".join(k[0] for k in r["kpis"]) + " |", "|" + "---|" * len(r["kpis"]),
            "| " + " | ".join(f"**{k[3](k[1])}** ({delta_text(k[1], k[2], k[3])[0]})" for k in r["kpis"]) + " |", ""]
    out += ["### New cases per month by type", "", f"![New cases per month by type]({chart_paths[0]})", "",
            f"### Money at risk in {month}'s new cases (USDT)", "", f"![Money at risk by type]({chart_paths[1]})", ""]
    out += [f"## What changed in {month}", ""] + [f"- {t}" for t in r["insights"]] + [""]
    out += [f"## Rings and campaigns active in {month}", "",
            "| Case | Type | Accounts | Active | Money at risk | Priority |", "|---|---|---|---|---|---|"]
    out += [f"| {c.case_id} | {' + '.join(LABELS[k] for k in c.kinds)} | {len(c.players)} | "
            f"{c.first_ts[5:10]} → {c.last_ts[5:10]} | {usdt(c.total_exposure)} | {c.priority} |" for c in r["rings"]]
    out += ["", "## Recommended actions", ""] + [f"- {t}" for t in r["recommendations"]] + [""]
    out += ["## Rule health", "", r["health"], "",
            "_All figures come from synthetic data (2,000 fictional players, July-September 2026). Case details: "
            "[case_list.md](case_list.md); rule logic: [rules/](../rules/)._", ""]
    return "\n".join(out)


def render_html(r, charts):
    month = MONTH_NAMES[REPORT_MONTH]
    tiles = []
    for label, cur, prev, fmt in r["kpis"]:
        text, color = delta_text(cur, prev, fmt)
        tiles.append(f'<div class="tile"><div class="label">{esc(label)}</div><div class="value">{esc(fmt(cur))}</div>'
                     f'<div class="delta" style="color:{color}">{esc(text)}</div></div>')
    ring_rows = "".join(
        f"<tr><td>{c.case_id}</td><td>{esc(' + '.join(LABELS[k] for k in c.kinds))}</td><td class='num'>{len(c.players)}</td>"
        f"<td>{c.first_ts[5:10]} → {c.last_ts[5:10]}</td><td class='num'>{esc(usdt(c.total_exposure))}</td>"
        f"<td>{c.priority}</td></tr>" for c in r["rings"])
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Monthly Fraud Trends</title>
<style>
  :root {{ --surface: {SURFACE}; --ink: {INK}; --ink-2: {INK_2}; --muted: {MUTED}; --grid: {GRID}; --axis: {AXIS};
          --tile: #f3f2ee; }}
  @page {{ size: A4; margin: 9mm 12mm; }}
  * {{ box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  html, body {{ background: #ffffff; }}
  body {{ margin: 0 auto; max-width: 186mm; padding: 0; font-family: {FONT}; font-size: 9pt; line-height: 1.36;
          color: var(--ink); }}
  @media screen {{ body {{ padding: 16px; }} }}
  h1 {{ font-size: 17pt; margin: 0 0 1mm; font-weight: 650; letter-spacing: -0.01em; }}
  .sub {{ color: var(--ink-2); margin: 0 0 4mm; font-size: 8.6pt; }}
  h2 {{ font-size: 10.5pt; margin: 3.5mm 0 1.2mm; font-weight: 650; }}
  h3 {{ font-size: 9pt; margin: 0 0 1mm; font-weight: 600; color: var(--ink-2); }}
  .tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 3mm; }}
  .tile {{ background: var(--tile); border-radius: 6px; padding: 2.5mm 3mm; }}
  .tile .label {{ color: var(--ink-2); font-size: 8.4pt; }}
  .tile .value {{ font-size: 16pt; font-weight: 600; line-height: 1.2; margin-top: 0.5mm; }}
  .tile .delta {{ font-size: 8.2pt; font-weight: 600; }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 6mm; margin-top: 3.5mm; }}
  .charts svg {{ width: 100%; height: auto; display: block; }}
  ul {{ margin: 0; padding-left: 4.5mm; }}
  li {{ margin: 0 0 1mm; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 8.6pt; }}
  th {{ text-align: left; color: var(--ink-2); font-weight: 600; border-bottom: 1px solid var(--axis); padding: 1mm 1.5mm; }}
  td {{ border-bottom: 1px solid var(--grid); padding: 1mm 1.5mm; }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .health {{ color: var(--ink-2); font-size: 8.4pt; }}
  .foot {{ color: var(--muted); font-size: 7.8pt; margin-top: 3mm; border-top: 1px solid var(--grid); padding-top: 1.5mm; }}
  code {{ font-family: Consolas, monospace; font-size: 0.95em; }}
</style>
</head>
<body>
<h1>Monthly fraud trends · {month} 2026</h1>
<p class="sub">Demo crypto poker room · synthetic data · cases opened in {month} vs. July and August ·
generated {date.today():%d %b %Y}</p>
<div class="tiles">{''.join(tiles)}</div>
<div class="charts">
  <div><h3>New cases per month by type</h3>{charts[0]}</div>
  <div><h3>Money at risk in {month}'s new cases, by type (USDT)</h3>{charts[1]}</div>
</div>
<h2>What changed in {month}</h2>
<ul>{''.join(f'<li>{inline_md(t)}</li>' for t in r['insights'])}</ul>
<h2>Rings and campaigns active in {month}</h2>
<table><thead><tr><th>Case</th><th>Type</th><th class="num">Accounts</th><th>Active</th><th class="num">Money at risk</th><th>Priority</th></tr></thead>
<tbody>{ring_rows}</tbody></table>
<h2>Recommended actions</h2>
<ul>{''.join(f'<li>{inline_md(t)}</li>' for t in r['recommendations'])}</ul>
<h2>Rule health</h2>
<p class="health">{inline_md(r['health'])}</p>
<p class="foot">Synthetic data only (2,000 fictional players, Jul-Sep 2026) · case details: <code>output/case_list.md</code>
· rule logic: <code>rules/*.sql</code> · rebuild: <code>python run.py</code></p>
</body>
</html>
"""


def write_pdf(html_path, pdf_path, chrome):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                        f"--user-data-dir={profile}", "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}",
                        html_path.resolve().as_uri()],
                       check=True, capture_output=True, timeout=120)
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf_path.read_bytes()))


def write_report(con, cases, check_summary, out_dir, chrome=None):
    r = build(con, cases, check_summary)
    charts = [chart_cases_by_month(r["counts"]), chart_exposure(r["exposure"])]
    chart_dir = out_dir / "charts"
    chart_dir.mkdir(exist_ok=True)
    names = ["cases_by_month.svg", "money_at_risk_by_type.svg"]
    for name, svg in zip(names, charts):
        (chart_dir / name).write_text(svg, encoding="utf-8")
    (out_dir / "monthly_fraud_trends.md").write_text(render_markdown(r, [f"charts/{n}" for n in names]), encoding="utf-8")
    html_path = out_dir / "monthly_fraud_trends.html"
    html_path.write_text(render_html(r, charts), encoding="utf-8")
    pages = None
    if chrome:
        pages = write_pdf(html_path, out_dir / "monthly_fraud_trends.pdf", chrome)
    return pages
