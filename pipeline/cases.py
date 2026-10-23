"""
Step 3 of the pipeline: turn rule hits into ranked investigation cases.

A "signal" is one rule firing once (one chip-dumping pair, one takeover...).
Signals that touch the same or linked accounts become one case. Each case is
scored, ranked and written up the way an investigator documents a case for an
appeal: what happened, the evidence, what it does NOT prove, how to verify it,
and the proposed action. Nothing here acts on an account - a human decides.
"""

import csv
import sqlite3
import statistics
from dataclasses import dataclass, field

from pipeline.detect import Clusters, attacker_values

WEIGHTS = {"account_takeover": 40, "chip_dumping": 35, "collusion": 35, "aml_pass_through": 30,
           "aml_structuring": 30, "bonus_abuse": 25, "multi_accounting": 20, "account_sharing": 15}
LABELS = {"account_takeover": "Account takeover", "chip_dumping": "Chip dumping",
          "collusion": "Collusion / soft-play", "aml_pass_through": "AML: pass-through",
          "aml_structuring": "AML: structuring", "bonus_abuse": "Bonus abuse",
          "multi_accounting": "Multi-accounting", "account_sharing": "Account sharing"}
FAMILIES = {"chip_dumping": "Game integrity", "collusion": "Game integrity",
            "account_takeover": "Account security", "account_sharing": "Account security",
            "bonus_abuse": "Bonus abuse & multi-accounting", "multi_accounting": "Bonus abuse & multi-accounting",
            "aml_pass_through": "AML", "aml_structuring": "AML"}
RULE_FILES = {"multi_accounting": "01_shared_identifiers.sql", "account_takeover": "02_account_takeover.sql",
              "bonus_abuse": "03_bonus_abuse.sql", "chip_dumping": "04_chip_dumping.sql",
              "collusion": "05_collusion_soft_play.sql", "account_sharing": "06_account_sharing.sql",
              "aml_pass_through": "07_aml_red_flags.sql", "aml_structuring": "07_aml_red_flags.sql"}

# What each signal does not prove, how to check it, and what to propose if it holds up.
PLAYBOOK = {
    "account_takeover": {
        "alternatives": ["The owner travelled, bought a new phone and withdrew to a new personal wallet.",
                         "The owner shared their login with a family member abroad (still a breach, but not theft).",
                         "The 'new' wallet may have been used before the start of this 3-month data extract."],
        "verify": ["Contact the owner through the verified email or phone on file - never through the flagged session - "
                   "and ask them to confirm the login and the withdrawal.",
                   "Check whether the password, email or 2FA settings were changed during the flagged session.",
                   "Check the full account history (beyond this extract) for earlier use of the destination wallet.",
                   "Screen the destination wallet with a blockchain-analytics tool for links to scams or mixers."],
        "actions": ["Lock the account and hold any pending withdrawals; force a password reset and 2FA.",
                    "If confirmed: share the attacker wallet with the exchange/analytics provider, block the device "
                    "fingerprint, and handle the customer's loss under the goodwill policy."],
    },
    "chip_dumping": {
        "alternatives": ["A weaker player losing repeatedly to a stronger one - but that usually happens at showdown, "
                         "not by folding after large bets.",
                         "A small sample: a handful of big pots can look one-sided by chance."],
        "verify": ["Replay the hand histories: do the folds make poker sense (folding strong hands, folding to a "
                   "small bet after calling large ones)?",
                   "Check how the losing accounts were funded and whether they were opened just before the games.",
                   "Check who chose the table: did the pair open a private or heads-up table and wait for each other?"],
        "actions": ["Hold withdrawals on the receiving account while the review is open.",
                    "If confirmed: void the transferred funds under the chip-dumping clause, close the feeder accounts, "
                    "and review the receiving account's other activity."],
    },
    "collusion": {
        "alternatives": ["Friends who agree not to play each other - still against the rules, but no "
                         "card-sharing may be involved.",
                         "Two regulars who prefer the same tables (they would still contest pots normally)."],
        "verify": ["Review hands where both were in the pot and hands where one folded early to the other: "
                   "check-downs, folds of strong hands, squeezing a third player.",
                   "Check whether they join the same tables within seconds of each other, and the chat logs.",
                   "Compare each account's win rate with and without the partner at the table."],
        "actions": ["Suspend the accounts pending review.",
                    "If confirmed: close the accounts, confiscate the winnings and refund the affected players "
                    "where they can be identified."],
    },
    "bonus_abuse": {
        "alternatives": ["Friends or family who signed up together after the same promotion - but they would not "
                         "normally share devices and payout wallets."],
        "verify": ["Compare KYC details, device fingerprints and payment sources across the accounts.",
                   "Check the referral or affiliate code used at sign-up: one affiliate driving a farm is common.",
                   "Read the bonus terms to confirm which clause applies (one bonus per person / household / device)."],
        "actions": ["Void the bonuses and any winnings made with them, as the bonus terms allow.",
                    "Close the duplicate accounts and add the devices and wallets to the bonus-exclusion list."],
    },
    "multi_accounting": {
        "alternatives": ["Family members or housemates sharing a computer or a wallet.",
                         "A second-hand device, or a wallet service that reuses deposit addresses."],
        "verify": ["Request ID verification (KYC) for every linked account: are these different real people?",
                   "Check whether the linked accounts ever sat at the same table or moved money to each other."],
        "actions": ["If it is one person: keep the oldest account, close the duplicates, and review any winnings "
                    "made while the accounts overlapped."],
    },
    "account_sharing": {
        "alternatives": ["VPN use - but a VPN changes the country, not the device.",
                         "A relative using the account with the owner's permission (still a breach of terms)."],
        "verify": ["Compare play style between the two device profiles: stakes, hands per hour, VPIP, time of day.",
                   "Ask the owner for a selfie/liveness check from the device they normally use."],
        "actions": ["Warn the owner and require re-verification; lock the account if the second user cannot be explained.",
                    "Check whether the second user is a banned or self-excluded player."],
    },
    "aml_pass_through": {
        "alternatives": ["A deposit made by mistake and withdrawn (usually smaller amounts, same wallet back).",
                         "A player who changed their mind about playing."],
        "verify": ["Screen the deposit and payout wallets with blockchain analytics (sanctions, mixers, darknet markets).",
                   "Request source-of-funds information and enhanced due diligence (EDD) before releasing further "
                   "withdrawals."],
        "actions": ["Escalate to the MLRO, who decides whether to file a suspicious activity report.",
                    "Do not tell the player why the account is under review - tipping off is an offence."],
    },
    "aml_structuring": {
        "alternatives": ["An exchange's daily withdrawal limit that happens to sit just under 2,000.",
                         "A personal budgeting habit."],
        "verify": ["Check the funding exchange and its limits; request source-of-funds information.",
                   "Look for the same pattern on withdrawals and on accounts linked to this one."],
        "actions": ["Escalate to the MLRO and apply enhanced due diligence.",
                    "Do not tell the player why the account is under review - tipping off is an offence."],
    },
}


@dataclass
class Signal:
    kind: str
    players: list
    first_ts: str
    last_ts: str
    row: dict


@dataclass
class Case:
    players: list
    signals: list
    case_id: str = ""
    rank: int = 0
    score: int = 0
    priority: str = ""
    exposure: dict = field(default_factory=dict)
    headlines: dict = field(default_factory=dict)
    sections: dict = field(default_factory=dict)
    extra_alternatives: list = field(default_factory=list)

    @property
    def kinds(self):
        return sorted({s.kind for s in self.signals}, key=lambda k: -WEIGHTS[k])

    @property
    def first_ts(self):
        core = [s.first_ts for s in self.signals if s.kind != "multi_accounting"] or [s.first_ts for s in self.signals]
        return min(core)

    @property
    def last_ts(self):
        return max(s.last_ts for s in self.signals)

    @property
    def month(self):
        return self.first_ts[:7]

    @property
    def family(self):
        return FAMILIES[self.kinds[0]]

    @property
    def total_exposure(self):
        return sum(self.exposure.values())

    @property
    def urgent(self):
        return "account_takeover" in self.kinds

    def of(self, kind):
        return [s for s in self.signals if s.kind == kind]


# =============================================================================
# Helpers
# =============================================================================

def rows(con, sql, params=()):
    return [dict(r) for r in con.execute(sql, params).fetchall()]


def one(con, sql, params=()):
    return con.execute(sql, params).fetchone()[0]


def usdt(x):
    return f"{x:,.0f} USDT" if abs(x) >= 100 else f"{x:,.2f} USDT"


def short(wallet):
    return f"{wallet[:6]}…{wallet[-4:]}" if wallet and len(wallet) > 12 else (wallet or "-")


def when(ts):
    return ts[:16] if ts else "-"


def pct(x):
    return f"{100 * x:.0f}%"


def duration(minutes):
    return f"{minutes} minutes" if minutes < 120 else f"{minutes / 60:.0f} hours"


LINK_NAMES = {"device": "device", "ip": "IP", "wallet": "wallet"}


def link_text(types):
    return ", ".join(LINK_NAMES[t] for t in types.split(",")) if types else None


def md_table(headers, body):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in body]
    return "\n".join(out)


def placeholders(items):
    return ",".join("?" * len(items))


# =============================================================================
# Signals and cases
# =============================================================================

def collect_signals(con):
    sigs = []
    for r in rows(con, "SELECT * FROM sig_account_takeover"):
        sigs.append(Signal("account_takeover", [r["player_id"]], r["login_ts"], r["withdrawal_ts"], r))
    for r in rows(con, "SELECT * FROM sig_chip_dumping"):
        sigs.append(Signal("chip_dumping", [r["from_player"], r["to_player"]], r["first_pot_ts"], r["last_pot_ts"], r))
    for r in rows(con, "SELECT * FROM sig_collusion"):
        sigs.append(Signal("collusion", [r["player_a"], r["player_b"]], r["first_hand_ts"], r["last_hand_ts"], r))
    for cluster in rows(con, "SELECT DISTINCT cluster_id FROM sig_bonus_abuse"):
        members = rows(con, "SELECT * FROM sig_bonus_abuse WHERE cluster_id = ? ORDER BY signup_ts", (cluster["cluster_id"],))
        last = max(one(con, "SELECT MIN(ts) FROM transactions WHERE player_id = ? AND type = 'withdrawal'", (m["player_id"],))
                   for m in members)
        sigs.append(Signal("bonus_abuse", [m["player_id"] for m in members], members[0]["signup_ts"], last,
                           {"members": members}))
    for r in rows(con, "SELECT * FROM sig_account_sharing"):
        sigs.append(Signal("account_sharing", [r["player_id"]], r["first_switch_ts"], r["last_switch_ts"], r))
    for r in rows(con, "SELECT * FROM sig_aml_pass_through"):
        sigs.append(Signal("aml_pass_through", [r["player_id"]], r["deposit_ts"], r["withdrawal_ts"], r))
    for r in rows(con, "SELECT * FROM sig_aml_structuring"):
        sigs.append(Signal("aml_structuring", [r["player_id"]], r["first_ts"], r["last_ts"], r))
    for c in rows(con, "SELECT * FROM multi_accounting_clusters WHERE has_strong_link = 1"):
        members = c["accounts"].split(";")
        signups = [one(con, "SELECT signup_ts FROM players WHERE player_id = ?", (m,)) for m in members]
        sigs.append(Signal("multi_accounting", members, max(signups), max(signups), c))
    return sigs


def group_cases(con, signals):
    """Signals sharing an account, a cluster or an attacker's device/wallet become one case."""
    groups = Clusters()
    for s in signals:
        for p in s.players:
            groups.union(s.players[0], p)
    flagged = {p for s in signals for p in s.players}
    for cluster_id, in con.execute("SELECT DISTINCT cluster_id FROM player_clusters"):
        members = [r[0] for r in con.execute("SELECT player_id FROM player_clusters WHERE cluster_id = ?", (cluster_id,))]
        if flagged & set(members):
            for m in members:
                groups.union(members[0], m)
    attacker = attacker_values(con)
    for a, b, value in con.execute("SELECT player_a, player_b, shared_value FROM link_evidence"):
        if value in attacker:
            groups.union(a, b)
    cases = []
    for members in groups.groups():
        member_set = set(members)
        sigs = [s for s in signals if member_set & set(s.players)]
        if sigs:
            cases.append(Case(players=members, signals=sigs))
    return cases


def ring_stats(con, members):
    """How the collusion members did in hands where two or more of them sat together."""
    marks = placeholders(members)
    shared_hands = f"""SELECT hand_id FROM hand_players WHERE player_id IN ({marks})
                       GROUP BY hand_id HAVING COUNT(*) >= 2"""
    n = one(con, f"SELECT COUNT(*) FROM ({shared_hands})", members)
    net = one(con, f"""SELECT COALESCE(SUM(net), 0) FROM hand_players
                       WHERE player_id IN ({marks}) AND hand_id IN ({shared_hands})""", members + members)
    return n, net


def score_cases(con, cases):
    for c in cases:
        exp = {}
        for kind in c.kinds:
            sigs = c.of(kind)
            if kind == "account_takeover":
                exp[kind] = sum(s.row["amount_usdt"] for s in sigs)
            elif kind == "chip_dumping":
                exp[kind] = sum(s.row["amount_usdt"] for s in sigs)
            elif kind == "collusion":
                members = sorted({p for s in sigs for p in s.players})
                exp[kind] = max(0.0, ring_stats(con, members)[1])
            elif kind == "bonus_abuse":
                exp[kind] = sum(m["withdrawn_usdt"] for s in sigs for m in s.row["members"])
            elif kind == "aml_pass_through":
                exp[kind] = sum(s.row["deposit_usdt"] for s in sigs)
            elif kind == "aml_structuring":
                exp[kind] = sum(s.row["total_usdt"] for s in sigs)
            else:
                exp[kind] = 0.0
        c.exposure = exp
        c.score = round(sum(WEIGHTS[k] for k in c.kinds)
                        + min(30, c.total_exposure / 100)
                        + min(10, 2 * (len(c.players) - 1)))
        c.priority = "P1" if c.score >= 70 else "P2" if c.score >= 45 else "P3"

    # case IDs follow the order cases started (FR-YYMM-nn); rank follows the score
    for month in sorted({c.month for c in cases}):
        in_month = sorted((c for c in cases if c.month == month), key=lambda c: c.first_ts)
        for i, c in enumerate(in_month, 1):
            c.case_id = f"FR-{month[2:4]}{month[5:7]}-{i:02d}"
    cases.sort(key=lambda c: (-c.score, -c.total_exposure, c.case_id))
    for i, c in enumerate(cases, 1):
        c.rank = i
    return cases


def build_cases(con):
    con.row_factory = sqlite3.Row
    cases = score_cases(con, group_cases(con, collect_signals(con)))
    for c in cases:
        describe(con, c)          # fills c.headlines, used by the queue table and the report
    return cases


# =============================================================================
# Write-ups: one function per signal type -> (headline, evidence bullets, optional table)
# =============================================================================

def room_heads_up_baseline(con):
    r = con.execute("""
        WITH hu AS (SELECT hand_id FROM hand_players WHERE vpip = 1 AND invested > 0
                    GROUP BY hand_id HAVING COUNT(*) = 2)
        SELECT AVG(1 - hp.showdown), AVG(hp.invested / h.big_blind)
        FROM hu JOIN hand_players hp ON hp.hand_id = hu.hand_id AND hp.net < 0
        JOIN hands h ON h.hand_id = hu.hand_id""").fetchone()
    return r[0], r[1]


def write_account_takeover(con, case, sigs):
    bullets = []
    for s in sigs:
        r = s.row
        after = con.execute("""SELECT COUNT(*), SUM(ip_country = ?) FROM logins
                               WHERE player_id = ? AND device_id = ? AND ts > ?""",
                            (r["home_country"], r["player_id"], r["device_id"], r["withdrawal_ts"])).fetchone()
        owner_back = one(con, """SELECT MIN(ts) FROM logins WHERE player_id = ? AND ts > ?
                                 AND device_id <> ? AND ip_country = ?""",
                         (r["player_id"], r["withdrawal_ts"], r["device_id"], r["home_country"]))
        bullets.append(f"**{r['player_id']}** - account {r['account_age_days']} days old, registered in "
                       f"{r['home_country']}, KYC level '{r['kyc_level']}'.")
        bullets.append(f"{when(r['login_ts'])}: first ever login from device `{r['device_id']}` and first ever login "
                       f"from {r['ip_country']} ({r['ip_type']} IP {r['ip']}).")
        bullets.append(f"{duration(r['minutes_to_withdrawal'])} later: withdrawal of {usdt(r['amount_usdt'])} to wallet "
                       f"`{short(r['wallet_address'])}`, which this account had never used.")
        if after[0]:
            bullets.append(f"The new device was used again {after[0]} time(s) after the withdrawal, "
                           f"{after[1] or 0} of them from {r['home_country']} - that fits a new phone better than a thief.")
        else:
            bullets.append("The new device was never seen again after the withdrawal.")
        if owner_back:
            bullets.append(f"The account's usual device logged in again from {r['home_country']} on {when(owner_back)}.")
    devices = {s.row["device_id"] for s in sigs}
    wallets = {s.row["wallet_address"] for s in sigs}
    if len(sigs) > 1 and (len(devices) == 1 or len(wallets) == 1):
        days = int(one(con, "SELECT julianday(?) - julianday(?)", (sigs[-1].row["login_ts"], sigs[0].row["login_ts"]))) + 1
        bullets.insert(0, f"**One attacker, {len(sigs)} victims:** the same device (`{sorted(devices)[0]}`) and payout "
                          f"wallet (`{short(sorted(wallets)[0])}`) were used against {len(sigs)} unrelated accounts "
                          f"within {days} days. The victims are linked only through the attacker, so this is not "
                          f"multi-accounting.")
        case.extra_alternatives.append("Several unrelated owners travelling with the same device on consecutive "
                                       "nights is not a realistic explanation here; the open question is how the "
                                       "attacker got the passwords (phishing, or reuse from a leaked site).")
        headline = (f"{len(sigs)} accounts taken over by one device/wallet in {days} days; "
                    f"{usdt(sum(s.row['amount_usdt'] for s in sigs))} withdrawn to the attacker's wallet.")
    else:
        r = sigs[0].row
        headline = (f"{r['player_id']}: first login from a new device in {r['ip_country']}, then "
                    f"{usdt(r['amount_usdt'])} withdrawn to a never-used wallet {duration(r['minutes_to_withdrawal'])} later.")
    return headline, bullets, None


def write_chip_dumping(con, case, sigs):
    base_fold, base_bb = room_heads_up_baseline(con)
    total = sum(s.row["amount_usdt"] for s in sigs)
    back = sum(s.row["money_back_usdt"] for s in sigs)
    pots = sum(s.row["pots"] for s in sigs)
    receivers = sorted({s.row["to_player"] for s in sigs})
    feeders = sorted({s.row["from_player"] for s in sigs})
    fold = sum(s.row["fold_share"] * s.row["pots"] for s in sigs) / pots
    avg_bb = sum(s.row["avg_big_blinds"] * s.row["pots"] for s in sigs) / pots
    private = sum(one(con, """SELECT COUNT(*) FROM hands h
                              JOIN hand_players a ON a.hand_id = h.hand_id AND a.player_id = ?
                              JOIN hand_players b ON b.hand_id = h.hand_id AND b.player_id = ?
                              WHERE h.seats = 2""", (s.row["from_player"], s.row["to_player"])) for s in sigs)
    bullets = [
        f"{len(feeders)} account(s) lost {usdt(total)} to {', '.join(receivers)} in {pots} pots only they played; "
        f"{usdt(back)} ({pct(back / total)}) went the other way.",
        f"The losing side folded without showdown in {pct(fold)} of those pots after putting in {avg_bb:.0f} big blinds "
        f"on average. Room average for a losing player in a two-player pot: folds {pct(base_fold)}, "
        f"after {base_bb:.1f} big blinds.",
        f"The pairs played {private} hands at tables where nobody else was seated.",
    ]
    for s in sigs:
        r = s.row
        if r["receiver_next_withdrawal_ts"]:
            hours = (one(con, "SELECT julianday(?) - julianday(?)", (r["receiver_next_withdrawal_ts"], r["last_pot_ts"]))) * 24
            bullets.append(f"{r['to_player']} withdrew {usdt(r['receiver_next_withdrawal_usdt'])} {hours:.0f} hours after "
                           f"the last pot from {r['from_player']}.")
    table = (["From → to", "Pots", "Lost", "Came back", "Folded", "Avg big blinds", "Direct link", "Period"],
             [[f"{s.row['from_player']} → {s.row['to_player']}", s.row["pots"], usdt(s.row["amount_usdt"]),
               usdt(s.row["money_back_usdt"]), pct(s.row["fold_share"]), s.row["avg_big_blinds"],
               link_text(s.row["link_types"]) or ("via cluster" if len(case.players) > 2 else "none"),
               f"{s.row['first_pot_ts'][:10]} → {s.row['last_pot_ts'][:10]}"] for s in sigs])
    headline = (f"{len(feeders)} account(s) lost {usdt(total)} to {', '.join(receivers)} in {pots} heads-up pots, "
                f"folding without showdown {pct(fold)} of the time.")
    return headline, bullets, table


def write_collusion(con, case, sigs):
    members = sorted({p for s in sigs for p in s.players})
    n_shared, ring_net = ring_stats(con, members)
    bullets = [f"{', '.join(members)} sat together (2+ of them at one table) in {n_shared:,} hands and won "
               f"{usdt(ring_net)} from the other players in those hands."]
    for s in sigs:
        r = s.row
        bullets.append(f"{r['player_a']} and {r['player_b']}: {r['hands_together']:,} hands at the same table "
                       f"({pct(r['share_of_hands'])} of the less active one's hands). Both played the same pot only "
                       f"{r['both_played']} times; their normal habits predict about {r['both_played_expected']:.0f} "
                       f"({r['contest_ratio']:.2f}x the expected rate).")
    table = (["Pair", "Hands together", "Share of hands", "Both played", "Expected", "Ratio", "Pair result", "Direct link"],
             [[f"{s.row['player_a']} + {s.row['player_b']}", f"{s.row['hands_together']:,}", pct(s.row["share_of_hands"]),
               s.row["both_played"], f"{s.row['both_played_expected']:.0f}", f"{s.row['contest_ratio']:.2f}",
               usdt(s.row["pair_net_usdt"]), link_text(s.row["link_types"]) or "via cluster"] for s in sigs])
    headline = (f"{len(members)} accounts shared tables for {n_shared:,} hands, almost never played a pot against each "
                f"other, and won {usdt(ring_net)} from the rest of the table.")
    return headline, bullets, table


def write_bonus_abuse(con, case, sigs):
    members = [m for s in sigs for m in s.row["members"]]
    ids = [m["player_id"] for m in members]
    spread = one(con, "SELECT julianday(?) - julianday(?)", (members[-1]["signup_ts"], members[0]["signup_ts"]))
    disposable = sum(m["email_domain"].endswith(".example") for m in members)
    declared = sorted({m["country"] for m in members})
    login_places = rows(con, f"""SELECT ip_country, ip_type, COUNT(DISTINCT ip) AS ips FROM logins
                                WHERE player_id IN ({placeholders(ids)}) GROUP BY ip_country, ip_type""", ids)
    payout = sorted({w for m in members for w in m["payout_wallets"].split(",")})
    bullets = [
        f"{len(members)} accounts registered within {spread:.0f} days ({members[0]['signup_ts'][:10]} → "
        f"{members[-1]['signup_ts'][:10]}).",
        f"{disposable} of {len(members)} used a disposable email domain. Declared countries: {', '.join(declared)}; "
        f"all logins came from " + "; ".join(f"{p['ips']} {p['ip_type']} IP(s) in {p['ip_country']}" for p in login_places) + ".",
        f"Each claimed the {usdt(members[0]['bonus_usdt'])} welcome bonus, played a median of "
        f"{statistics.median(m['hands_played'] for m in members):.0f} hands and cashed out after a median of "
        f"{statistics.median(m['days_to_withdraw'] for m in members):.1f} days.",
        f"Total withdrawn: {usdt(sum(m['withdrawn_usdt'] for m in members))}, to {len(payout)} wallet(s): "
        + ", ".join(f"`{short(w)}`" for w in payout) + ".",
    ]
    table = (["Account", "Signed up", "Email domain", "Declared country", "Bonus", "Hands", "Days to cash-out",
              "Withdrawn", "Payout wallet"],
             [[m["player_id"], when(m["signup_ts"]), m["email_domain"], m["country"], usdt(m["bonus_usdt"]),
               m["hands_played"], m["days_to_withdraw"], usdt(m["withdrawn_usdt"]),
               ", ".join(short(w) for w in m["payout_wallets"].split(","))] for m in members])
    headline = (f"{len(members)} linked accounts opened within {spread:.0f} days each took the welcome bonus, played "
                f"~{statistics.median(m['hands_played'] for m in members):.0f} hands and cashed out to "
                f"{len(payout)} shared wallet(s).")
    return headline, bullets, table


def write_account_sharing(con, case, sigs):
    bullets = []
    for s in sigs:
        r = s.row
        bullets.append(f"{r['player_id']} (registered in {r['home_country']}) switched between two device-and-country "
                       f"profiles {r['switches']} times on {r['days_with_switches']} days, on average "
                       f"{r['avg_gap_hours']} hours apart ({r['first_switch_ts'][:10]} → {r['last_switch_ts'][:10]}).")
        bullets.append(f"Countries: {r['countries'].replace(',', ', ')}. Devices: " + ", ".join(f"`{d}`" for d in r["devices"].split(",")) + ".")
    r = sigs[0].row
    others = [c for c in r["countries"].split(",") if c != r["home_country"]]
    headline = (f"{r['player_id']} alternated between {r['home_country']} and {', '.join(others)} on two devices "
                f"{r['switches']} times, hours apart.")
    return headline, bullets, None


def write_aml_pass_through(con, case, sigs):
    bullets = []
    for s in sigs:
        r = s.row
        swap = f" (deposited {r['deposit_asset']}, withdrew {r['payout_assets']})" if r["deposit_asset"] != r["payout_assets"] else ""
        age = "opened less than a day before" if r["account_age_days"] == 0 else f"account {r['account_age_days']} days old"
        bullets.append(f"**{r['player_id']}** ({age}, KYC '{r['kyc_level']}'): "
                       f"deposited {usdt(r['deposit_usdt'])} in {r['deposit_asset']} from `{short(r['deposit_wallet'])}` on "
                       f"{when(r['deposit_ts'])}; {r['hours_to_withdrawal']} hours later withdrew {usdt(r['withdrawn_usdt'])} "
                       f"({pct(r['withdrawn_usdt'] / r['deposit_usdt'])}) to `{short(r['payout_wallets'])}`{swap}.")
        bullets.append(f"In between it played {r['hands_played']} hands and wagered {usdt(r['wagered_usdt'])} "
                       f"({pct(r['wagered_usdt'] / r['deposit_usdt'])} of the deposit).")
    payouts = [s.row["payout_wallets"] for s in sigs]
    if len(sigs) > 1 and len(set(payouts)) == 1:
        bullets.insert(0, f"**{len(sigs)} accounts paid out to the same wallet** `{short(payouts[0])}`.")
    total = sum(s.row["deposit_usdt"] for s in sigs)
    hours = max(s.row["hours_to_withdrawal"] for s in sigs)
    headline = (f"{usdt(total)} deposited and withdrawn within {hours:.0f} hours by {len(sigs)} account(s) with almost no play"
                + (", switching crypto asset on the way." if any(s.row["deposit_asset"] != s.row["payout_assets"] for s in sigs) else "."))
    return headline, bullets, None


def write_aml_structuring(con, case, sigs):
    bullets = []
    for s in sigs:
        r = s.row
        days = one(con, "SELECT julianday(?) - julianday(?)", (r["last_ts"], r["first_ts"]))
        bullets.append(f"**{r['player_id']}** (KYC '{r['kyc_level']}'): {r['deposits']} deposits between 1,800 and 1,999 USDT "
                       f"in {days:.0f} days ({r['first_ts'][:10]} → {r['last_ts'][:10]}), from {r['wallets']} wallet(s). "
                       f"Amounts: {r['amounts']}.")
        bullets.append(f"Total {usdt(r['total_usdt'])}. Deposited in one go, it would have crossed the "
                       f"{r['threshold_usdt']:,} USDT review threshold; each split deposit stayed just under it.")
    r = sigs[0].row
    headline = f"{r['player_id']}: {r['deposits']} deposits just under the {r['threshold_usdt']:,} USDT threshold within a week ({usdt(r['total_usdt'])})."
    return headline, bullets, None


def write_multi_accounting(con, case, sigs):
    members = sorted({p for s in sigs for p in s.players})
    attacker = attacker_values(con)
    links = [r for r in rows(con, f"""SELECT * FROM link_evidence WHERE player_a IN ({placeholders(members)})
                                      AND player_b IN ({placeholders(members)}) ORDER BY strength, link_type""",
                             members + members) if r["shared_value"] not in attacker]
    by_value = {}
    for r in links:
        by_value.setdefault((r["link_type"], r["shared_value"]), set()).update((r["player_a"], r["player_b"]))
    by_type = {}
    for link_type, value in by_value:
        by_type[link_type] = by_type.get(link_type, 0) + 1
    bullets = [f"{len(members)} accounts are connected by " +
               ", ".join(f"{n} shared {LINK_NAMES[k]}{'s' if n > 1 else ''}" for k, n in sorted(by_type.items())) + "."]
    excluded = rows(con, f"""SELECT DISTINCT e.value_type, e.shared_value, e.accounts FROM excluded_shared_values e
                             JOIN logins l ON l.ip = e.shared_value WHERE l.player_id IN ({placeholders(members)})
                             GROUP BY e.shared_value HAVING COUNT(DISTINCT l.player_id) >= 2""", members)
    for e in excluded:
        bullets.append(f"They also share IP {e['shared_value']}, which was left out of the linking because "
                       f"{e['accounts']} accounts use it (too common to identify anyone on its own).")
    ordered = sorted(by_value.items(), key=lambda kv: (kv[0][0] == "ip", kv[0][0], -len(kv[1])))
    table = (["Shared", "Value", "Strength", "Accounts using it"],
             [[LINK_NAMES[t], f"`{short(v) if t == 'wallet' else v}`", "weak" if t == "ip" else "strong",
               ", ".join(sorted(ps))] for (t, v), ps in ordered])
    headline = f"{len(members)} accounts linked by shared " + ", ".join(LINK_NAMES[t] for t in sorted(by_type)) + "."
    return headline, bullets, table


WRITERS = {"account_takeover": write_account_takeover, "chip_dumping": write_chip_dumping,
           "collusion": write_collusion, "bonus_abuse": write_bonus_abuse,
           "account_sharing": write_account_sharing, "aml_pass_through": write_aml_pass_through,
           "aml_structuring": write_aml_structuring, "multi_accounting": write_multi_accounting}


def describe(con, case):
    for kind in case.kinds:
        headline, bullets, table = WRITERS[kind](con, case, case.of(kind))
        case.headlines[kind] = headline
        case.sections[kind] = (bullets, table)


def account_rows(con, case):
    out = []
    for p in case.players:
        info = dict(con.execute("SELECT * FROM players WHERE player_id = ?", (p,)).fetchone())
        hands = one(con, "SELECT COUNT(*) FROM hand_players WHERE player_id = ?", (p,))
        dep = one(con, "SELECT COALESCE(SUM(amount_usdt), 0) FROM transactions WHERE player_id = ? AND type = 'deposit'", (p,))
        wd = one(con, "SELECT COALESCE(SUM(amount_usdt), 0) FROM transactions WHERE player_id = ? AND type = 'withdrawal'", (p,))
        flags = [LABELS[s.kind] for s in case.signals if p in s.players and s.kind != "multi_accounting"]
        out.append([p, info["signup_ts"][:10], info["country"], info["email_domain"], info["kyc_level"], f"{hands:,}",
                    usdt(dep), usdt(wd), ", ".join(dict.fromkeys(flags)) or "linked only"])
    return out


def timeline(con, case, limit=14):
    marks = placeholders(case.players)
    events = [(r["ts"], r["player_id"], f"{r['type'].capitalize()} {usdt(r['amount_usdt'])}"
                                          f"{'' if r['asset'] == 'USDT' else ' (paid in ' + r['asset'] + ')'} "
                                          f"{'from' if r['type'] == 'deposit' else 'to'} `{short(r['wallet_address'])}`",
               r["amount_usdt"])
              for r in rows(con, f"SELECT * FROM transactions WHERE player_id IN ({marks})", case.players)]
    events += [(r["ts"], r["player_id"], f"Welcome bonus {usdt(r['amount_usdt'])}", 0)
               for r in rows(con, f"SELECT * FROM bonuses WHERE player_id IN ({marks})", case.players)]
    events += [(r["signup_ts"], r["player_id"], "Account opened", 0)
               for r in rows(con, f"SELECT * FROM players WHERE player_id IN ({marks}) AND signup_ts >= '2026-07-01'",
                             case.players)]
    for s in case.of("account_takeover"):
        events.append((s.row["login_ts"], s.row["player_id"],
                       f"**Flagged login**: new device + new country ({s.row['ip_country']})", float("inf")))
    for s in case.of("account_sharing"):
        events.append((s.row["first_switch_ts"], s.row["player_id"], "**First device/country switch**", float("inf")))
    for s in case.of("chip_dumping") + case.of("collusion"):
        a, b = s.players
        events.append((s.first_ts, a, f"**First flagged hand** with {b}", float("inf")))
    events.sort()
    omitted = 0
    if len(events) > limit:
        keep = set(sorted(range(len(events)), key=lambda i: -events[i][3])[:limit])
        omitted = len(events) - limit
        events = [e for i, e in enumerate(events) if i in keep]
    return [[when(ts), pid, text] for ts, pid, text, _ in events], omitted


# =============================================================================
# Output
# =============================================================================

def case_title(c):
    title = " + ".join(LABELS[k] for k in c.kinds)
    return f"{c.rank}. {c.case_id} · {c.priority} · score {c.score} · {title}"


def summary_line(c):
    n = len(c.players)
    return f"{n} account{'s' if n > 1 else ''}. " + " ".join(c.headlines[k] for k in c.kinds)


def write_case(con, c):
    out = [f"### {case_title(c)}", ""]
    status = "Open - pending analyst review. No action has been taken on these accounts."
    if c.urgent:
        status = "**URGENT** - possible theft from a customer; review first. " + status
    out += [f"- **Status:** {status}",
            f"- **Accounts:** {', '.join(c.players)}",
            f"- **Activity:** {when(c.first_ts)} → {when(c.last_ts)}",
            f"- **Money at risk:** {usdt(c.total_exposure) if c.total_exposure else 'none quantified (rule-breach risk only)'}"
            + (" (" + ", ".join(f"{LABELS[k]} {usdt(v)}" for k, v in c.exposure.items() if v) + ")" if c.total_exposure else ""),
            f"- **Rules fired:** " + ", ".join(f"{LABELS[k]} (`rules/{RULE_FILES[k]}`)" for k in c.kinds), ""]
    out += ["**Summary.** " + summary_line(c), ""]
    for kind in c.kinds:
        bullets, table = c.sections[kind]
        out += [f"#### Evidence - {LABELS[kind]}", ""] + [f"- {b}" for b in bullets] + [""]
        if table:
            out += [md_table(*table), ""]
    out += ["#### Accounts", "", md_table(["Account", "Signed up", "Declared country", "Email domain", "KYC", "Hands",
                                           "Deposited", "Withdrawn", "Signals"], account_rows(con, c)), ""]
    events, omitted = timeline(con, c)
    out += ["#### Timeline", "", md_table(["When", "Account", "Event"], events), ""]
    if omitted:
        out += [f"_{omitted} smaller events left out; full history in the database._", ""]
    out += ["#### What this does not prove", ""]
    out += [f"- {a}" for a in c.extra_alternatives + [a for k in c.kinds for a in PLAYBOOK[k]["alternatives"]]] + [""]
    out += ["#### Verify before acting", ""]
    out += [f"{i}. {v}" for i, v in enumerate((v for k in c.kinds for v in PLAYBOOK[k]["verify"]), 1)] + [""]
    out += ["#### Proposed action (if verified)", ""]
    out += [f"- {a}" for k in c.kinds for a in PLAYBOOK[k]["actions"]] + [""]
    strongest = c.headlines[c.kinds[0]]
    weakest = PLAYBOOK[c.kinds[0]]["alternatives"][0]
    out += ["#### Appeal note", "",
            f"If the account holder appeals, the decision rests on behavioural and transactional records (hands, logins, "
            f"wallet transfers), not on one data point. Strongest evidence: {strongest} The most likely counter-argument "
            f"is: \"{weakest}\" - the verification steps above are designed to test exactly that. Every figure in this "
            f"case can be reproduced by running `python run.py` and the rule files listed above.", "", "---", ""]
    return out


def write_watchlist(con, cases):
    in_cases = {p for c in cases for p in c.players}
    weak = [r for r in rows(con, "SELECT * FROM multi_accounting_clusters WHERE has_strong_link = 0")
            if not set(r["accounts"].split(";")) & in_cases]
    excluded = rows(con, "SELECT * FROM excluded_shared_values ORDER BY accounts DESC")
    out = ["## Watchlist - weak links, no case opened", "",
           "Accounts linked only by an IP address, with no other signal. Common for households and shared flats; "
           "kept here so the link is visible if anything else happens on these accounts.", ""]
    out += [md_table(["Cluster", "Accounts", "Linked by"],
                     [[r["cluster_id"], r["accounts"].replace(";", ", "), "same IP address only"] for r in weak])
            if weak else "_None._", ""]
    out += ["## Identifiers left out of the linking", "",
            "Values used by so many accounts that sharing them says nothing about who someone is.", "",
            md_table(["Type", "Value", "Accounts", "Why it was left out"],
                     [[e["value_type"], f"`{short(e['shared_value']) if e['value_type'] == 'wallet' else e['shared_value']}`",
                       e["accounts"], e["reason"]] for e in excluded]), ""]
    return out


def write_case_list(con, cases, out_dir):
    out = ["# Fraud case queue - demo crypto poker room", "",
           "_Synthetic data (July-September 2026). Generated by `python run.py`. Every case below is a lead for a human "
           "analyst, not a decision: no account has been actioned._", "",
           "**How to read this.** Priority P1 (score 70+) = review today, P2 (45-69) = this week, P3 (under 45) = when "
           "capacity allows. URGENT = account takeover, where customer money may still be recoverable. Score = rule "
           "weights + 1 point per 100 USDT at risk (max 30) + 2 points per extra account (max 10); see the README.", "",
           "## Queue", ""]
    out += [md_table(["Rank", "Case", "Priority", "Score", "Type", "Accounts", "At risk", "Started"],
                     [[c.rank, c.case_id, c.priority + (" URGENT" if c.urgent else ""), c.score,
                       " + ".join(LABELS[k] for k in c.kinds), len(c.players),
                       usdt(c.total_exposure) if c.total_exposure else "-", c.first_ts[:10]]
                      for c in cases]), ""]
    out += ["## Cases", ""]
    for c in cases:
        out += write_case(con, c)
    out += write_watchlist(con, cases)
    (out_dir / "case_list.md").write_text("\n".join(out), encoding="utf-8")

    with open(out_dir / "case_list.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rank", "case_id", "priority", "score", "urgent", "case_types", "accounts", "n_accounts",
                    "money_at_risk_usdt", "first_activity", "last_activity", "summary"])
        for c in cases:
            w.writerow([c.rank, c.case_id, c.priority, c.score, int(c.urgent), "; ".join(LABELS[k] for k in c.kinds),
                        " ".join(c.players), len(c.players), round(c.total_exposure, 2), c.first_ts, c.last_ts,
                        summary_line(c)])
