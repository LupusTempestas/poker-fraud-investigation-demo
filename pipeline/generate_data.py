"""
Step 1 of the pipeline: build a synthetic crypto poker room.

Nothing here is real. Players, emails, IP addresses and wallets are invented:
emails are stored only as a hash plus the domain, every IP sits in the private
10.x.x.x range (so it cannot point to anyone), and wallet addresses are random.

The room has 2,000 players and three months of activity (July-September 2026).
On top of normal play we deliberately plant:
  * fraud scenarios the rules should catch: chip-dumping rings, collusion teams,
    bonus-abuse farms, account takeovers, account sharing, money-laundering patterns
  * innocent look-alikes the rules should NOT flag: a household sharing wifi, a
    mobile-carrier IP shared by dozens of strangers, an exchange wallet, travellers...

Everything planted is written to data/answer_key.csv. The detection rules never
read that file; it is only used afterwards to check how well they did.
"""

import csv
import hashlib
import math
import random
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

SEED = 2026
N_PLAYERS = 2000
WINDOW_START = datetime(2026, 7, 1)
WINDOW_END = datetime(2026, 10, 1)      # exclusive: activity covers 1 July - 30 September 2026
WELCOME_BONUS = 25.0                    # USDT, credited on a first deposit
BIG_BLIND = {"micro": 0.10, "low": 0.50, "mid": 2.00, "high": 5.00}   # USDT
TABLES_PER_DAY = {"micro": 4, "low": 3, "mid": 2}
CGNAT_IP = "10.250.0.1"                 # one mobile-carrier gateway shared by many strangers

# (value, weight) lists used for random picks
COUNTRIES = [("DE", 14), ("GB", 10), ("CA", 9), ("BR", 9), ("IN", 8), ("PH", 7), ("MX", 6),
             ("TR", 6), ("AR", 5), ("JP", 5), ("TH", 5), ("AU", 4), ("PL", 4), ("ES", 4)]
EMAIL_DOMAINS = [("gmail.com", 40), ("outlook.com", 12), ("hotmail.com", 8), ("yahoo.com", 8),
                 ("proton.me", 10), ("icloud.com", 8), ("gmx.de", 5), ("mail.com", 4)]
DISPOSABLE_DOMAINS = ["quickinbox.example", "tmpmail.example"]


def at(month, day, hour=0, minute=0):
    return datetime(2026, month, day, hour, minute)


def pick(rng, options):
    values, weights = zip(*options)
    return rng.choices(values, weights)[0]


class Room:
    """Holds every generated record until it is written to CSV."""

    def __init__(self, seed=SEED):
        self.rng = random.Random(seed)
        self.players, self.logins, self.transactions, self.bonuses = [], [], [], []
        self.hands, self.hand_players, self.answer_key = [], [], []
        self.pools = {}
        self._ip_counters = defaultdict(int)
        self._tables = 0
        self.exchange_wallet = self.new_wallet()
        self.known_wallets = [{"wallet_address": self.exchange_wallet,
                               "label": "Exchange hot wallet (synthetic label)",
                               "label_type": "exchange"}]

    # --- identifiers -------------------------------------------------------
    def new_device(self):
        return "dev-" + "".join(self.rng.choice("0123456789abcdef") for _ in range(10))

    def new_wallet(self):
        return "0x" + "".join(self.rng.choice("0123456789abcdef") for _ in range(40))

    def new_ip(self, kind):
        # private 10.x range only; the second number tells the kind of network apart
        n = self._ip_counters[kind]
        self._ip_counters[kind] += 1
        base = {"residential": 1, "mobile": 200, "hosting": 240}[kind]
        return f"10.{base + n // 64516}.{(n // 254) % 254}.{n % 254 + 1}"

    def new_player(self, signup_ts, country=None, email_domain=None, kyc=None, stake=None,
                   in_pool=True, role="normal"):
        rng = self.rng
        p = {
            "key": len(self.players), "id": None, "role": role,
            "signup_ts": signup_ts,
            "country": country or pick(rng, COUNTRIES),
            "email_domain": email_domain or pick(rng, EMAIL_DOMAINS),
            "email_hash": hashlib.sha256(f"{len(self.players)}-{rng.random()}".encode()).hexdigest()[:16],
            "kyc_level": kyc or pick(rng, [("none", 30), ("basic", 50), ("verified", 20)]),
            "devices": [self.new_device()],
            "home_ip": self.new_ip("residential"),
            "mobile_ip": None,
            "wallet": self.new_wallet(),
            "vpip": rng.uniform(0.15, 0.45),        # how often the player chooses to play a hand
            "skill": min(1.5, max(0.6, rng.gauss(1.0, 0.15))),
            "stake": stake or pick(rng, [("micro", 50), ("low", 35), ("mid", 15)]),
            "activity": rng.lognormvariate(0, 0.8),
            "in_pool": in_pool,                     # sits at ordinary tables and has ordinary account activity
            "custom_withdrawals": False,
            "withdraw_to_exchange": False,
            "no_random_travel": False,
        }
        self.players.append(p)
        return p

    def finalise_ids(self):
        # player IDs follow signup order, like a real sign-up counter
        for i, p in enumerate(sorted(self.players, key=lambda p: p["signup_ts"]), 1):
            p["id"] = f"P{i:05d}"
            p["active_from"] = max(p["signup_ts"], WINDOW_START)

    def build_pools(self):
        for stake in TABLES_PER_DAY:
            self.pools[stake] = [p for p in self.players if p["in_pool"] and p["stake"] == stake]

    def pick_fillers(self, stake, ts, k, exclude=()):
        taken = {p["key"] for p in exclude}
        eligible = [p for p in self.pools[stake] if p["active_from"] <= ts and p["key"] not in taken]
        return self.rng.sample(eligible, min(k, len(eligible)))

    # --- records -----------------------------------------------------------
    def login(self, p, ts, device, ip, country, ip_type="residential"):
        self.logins.append({"player": p, "ts": ts, "device_id": device, "ip": ip,
                            "ip_country": country, "ip_type": ip_type})

    def tx(self, p, ts, kind, amount, wallet, asset="USDT"):
        self.transactions.append({"player": p, "ts": ts, "type": kind, "amount_usdt": round(amount, 2),
                                  "asset": asset, "wallet_address": wallet})

    def bonus(self, p, ts, kind, amount):
        self.bonuses.append({"player": p, "ts": ts, "bonus_type": kind, "amount_usdt": amount})

    def note(self, scenario, kind, title, expected, players, notes, value=""):
        self.answer_key.append({"scenario_id": scenario, "kind": kind, "title": title, "expected": expected,
                                "players": players, "value": value, "notes": notes})

    # --- poker -------------------------------------------------------------
    def _new_hand(self, table_id, ts, bb, seats):
        hand = {"hid": len(self.hands), "table_id": table_id, "ts": ts, "big_blind": bb, "seats": seats}
        self.hands.append(hand)
        return hand

    def _row(self, hand, p, seat, vpip, invested, net, showdown):
        self.hand_players.append({"hand": hand, "player": p, "seat": seat, "vpip": vpip,
                                  "invested": round(invested, 2), "net": round(net, 2), "showdown": showdown})

    def play_hand(self, table_id, ts, bb, seated, team_keys=frozenset(), edge=1.0, showdown_rate=0.45):
        """One simplified hand: who plays, how much goes in, who wins. Blinds are ignored."""
        rng = self.rng
        hand = self._new_hand(table_id, ts, bb, len(seated))
        teammates = [p for p in seated if p["key"] in team_keys]
        # colluders: when two or more of them sit together, only one plays the pot
        team_player = rng.choice(teammates) if len(teammates) >= 2 else None
        plays = []
        for p in seated:
            chance = p["vpip"]
            if team_player is not None and p["key"] in team_keys:
                chance = min(0.6, chance * 1.3) if p is team_player else 0.02
            plays.append(rng.random() < chance)
        contestants = [p for p, played in zip(seated, plays) if played]
        if len(contestants) < 2:
            for seat, (p, played) in enumerate(zip(seated, plays), 1):
                self._row(hand, p, seat, int(played), 0.0, 0.0, 0)
            return
        level = bb * min(100.0, rng.lognormvariate(math.log(5), 0.9))   # what it costs to see the end
        weights = [p["skill"] * (edge if p["key"] in team_keys else 1.0) for p in contestants]
        winner = rng.choices(contestants, weights)[0]
        showed = {p["key"]: rng.random() < showdown_rate for p in contestants if p is not winner}
        invested = {p["key"]: level if (p is winner or showed[p["key"]]) else level * rng.uniform(0.2, 1.0)
                    for p in contestants}
        pot = sum(invested.values())
        rake = min(0.05 * pot, 3 * bb)
        for seat, (p, played) in enumerate(zip(seated, plays), 1):
            if not played:
                self._row(hand, p, seat, 0, 0.0, 0.0, 0)
            elif p is winner:
                self._row(hand, p, seat, 1, level, pot - rake - level, int(any(showed.values())))
            else:
                self._row(hand, p, seat, 1, invested[p["key"]], -invested[p["key"]], int(showed[p["key"]]))

    def play_dump_hand(self, table_id, ts, bb, feeder, receiver, bb_range):
        """Chip dumping: the feeder puts in a lot, then folds and lets the receiver take it."""
        rng = self.rng
        hand = self._new_hand(table_id, ts, bb, 2)
        if rng.random() < 0.08:
            # now and then the feeder wins a small pot, so it does not look completely one-sided
            winner, loser, amount, showed = feeder, receiver, bb * rng.uniform(2, 4), 1
        else:
            winner, loser, amount, showed = receiver, feeder, bb * rng.uniform(*bb_range), int(rng.random() < 0.07)
        rake = min(0.05 * 2 * amount, 3 * bb)
        for seat, p in enumerate([feeder, receiver], 1):
            net = amount - rake if p is winner else -amount
            self._row(hand, p, seat, 1, amount, net, showed)

    def run_table(self, start, stake, seated, n_hands, team=(), keep=(), edge=1.0, showdown_rate=0.45,
                  dump=None, dump_bb=(12, 40)):
        """Play a session of hands at one table. Unprotected seats change every 15 hands."""
        self._tables += 1
        table_id = f"T{self._tables:05d}"
        bb = BIG_BLIND[stake]
        team_keys = frozenset(p["key"] for p in team)
        protected = team_keys | {p["key"] for p in keep} | {p["key"] for p in (dump or ())}
        seated, ts = list(seated), start
        for i in range(n_hands):
            if dump:
                self.play_dump_hand(table_id, ts, bb, dump[0], dump[1], dump_bb)
            else:
                self.play_hand(table_id, ts, bb, seated, team_keys, edge, showdown_rate)
            ts += timedelta(seconds=self.rng.randint(50, 130))
            if not dump and len(seated) > 2 and i % 15 == 14 and stake in self.pools:
                replaceable = [j for j, p in enumerate(seated) if p["key"] not in protected]
                newcomer = self.pick_fillers(stake, ts, 1, exclude=seated)
                if replaceable and newcomer:
                    seated[self.rng.choice(replaceable)] = newcomer[0]
        return ts

    def net_in_hands(self, p, since_index):
        return sum(r["net"] for r in self.hand_players[since_index:] if r["player"] is p)


# =============================================================================
# Population
# =============================================================================

def random_signup(rng):
    if rng.random() < 0.85:
        start, end = datetime(2025, 1, 1), WINDOW_START
    else:
        start, end = WINDOW_START, WINDOW_END - timedelta(days=3)
    return (start + (end - start) * rng.random()).replace(microsecond=0)


def create_scenario_accounts(room):
    """Accounts that exist only because a fraud scenario needs them."""
    r = room
    s = {}
    s["R1"] = {  # chip-dumping ring: four feeders lose on purpose to one receiver
        "receiver": r.new_player(at(7, 26, 21, 4), "GB", kyc="basic", stake="mid", role="fraud"),
        "feeders": [r.new_player(at(8, 1 + 2 * i, 19, 30 + i), "GB", kyc="none", in_pool=False, role="fraud")
                    for i in range(4)],
    }
    s["R2"] = {  # chip-dumping pair: brand-new account feeds an older one
        "receiver": r.new_player(datetime(2026, 6, 2, 18, 40), "MX", kyc="basic", stake="mid", role="fraud"),
        "feeder": r.new_player(at(9, 10, 22, 15), "MX", kyc="none", in_pool=False, role="fraud"),
    }
    s["R3"] = [r.new_player(d, "AR", kyc="basic", stake="mid", role="fraud")      # collusion team of three
               for d in (datetime(2026, 5, 12, 20), datetime(2026, 5, 19, 21, 30), datetime(2026, 6, 3, 19, 10))]
    s["R4"] = [r.new_player(d, "TR", kyc="none", stake="low", role="fraud")       # collusion pair
               for d in (at(7, 28, 20, 5), at(7, 30, 22, 40))]
    s["R5"] = [r.new_player(at(9, 3 + i // 2, 10 + 3 * (i % 2), 7 * i % 60), email_domain=DISPOSABLE_DOMAINS[i % 2],
                            kyc="none", in_pool=False, role="fraud") for i in range(12)]   # bonus farm
    s["R6"] = [r.new_player(at(7, 14 + i, 16, 12 * i), "PL", email_domain=DISPOSABLE_DOMAINS[1], kyc="none",
                            in_pool=False, role="fraud") for i in range(5)]               # smaller bonus farm
    s["S1"] = r.new_player(datetime(2026, 6, 11, 12), "CA", kyc="basic", stake="low", role="fraud")
    s["S2"] = r.new_player(datetime(2026, 4, 2, 9, 30), "GB", kyc="basic", stake="low", role="fraud")
    s["A1"] = r.new_player(at(8, 4, 9, 50), kyc="none", in_pool=False, role="fraud")
    s["A2"] = r.new_player(at(9, 13, 23, 20), kyc="none", in_pool=False, role="fraud")
    s["A3"] = r.new_player(at(9, 24, 21, 5), kyc="none", in_pool=False, role="fraud")
    s["ST1"] = r.new_player(datetime(2026, 6, 20, 14), kyc="basic", stake="micro", role="fraud")
    s["ST2"] = r.new_player(at(8, 28, 11, 45), kyc="basic", stake="micro", role="fraud")
    for p in (s["S1"], s["S2"]):
        p["no_random_travel"] = True
    for p in (s["R1"]["receiver"], s["R2"]["receiver"], s["ST1"], s["ST2"]):
        p["custom_withdrawals"] = True
        p["activity"] = 0.5
    for p in s["R3"] + s["R4"]:
        p["activity"] = 0.4
    return s


def pick_roles(room):
    """Ordinary players who get a special part: takeover victims and innocent look-alikes."""
    rng = room.rng

    def take(n, cond=lambda p: True):
        candidates = [p for p in room.players if p["role"] == "normal" and cond(p)]
        chosen = rng.sample(candidates, n)
        for p in chosen:
            p["role"] = "role"
            p["no_random_travel"] = True
        return chosen

    established = lambda p: p["signup_ts"] < datetime(2026, 2, 1)
    roles = {
        "victims": take(4, established),
        "traveller_ok": take(1, established)[0],
        "traveller_fp": take(1, established)[0],
        "household": take(2),
        "cgnat": take(30),
        "exchange": take(40),
        "regs": take(2, established),
        "high_roller": take(1, established)[0],
        "fish": take(1, established)[0],
        "shark": take(1, established)[0],
    }
    for p, country in zip(roles["victims"], ("DE", "CA", "GB", "BR")):
        p["country"], p["kyc_level"] = country, "verified"
    roles["traveller_ok"]["country"] = "GB"
    roles["traveller_fp"]["country"] = "CA"
    a, b = roles["household"]
    a["country"] = b["country"] = "DE"
    a["stake"], b["stake"] = "micro", "mid"
    b["home_ip"] = a["home_ip"]
    for p in roles["cgnat"]:
        p["country"], p["mobile_ip"] = "PH", CGNAT_IP
    for p in roles["exchange"]:
        p["withdraw_to_exchange"] = True
    for p in roles["regs"]:
        p["stake"], p["activity"], p["skill"] = "mid", 3.0, 1.1
    hr = roles["high_roller"]
    hr["stake"], hr["activity"], hr["vpip"], hr["kyc_level"] = "mid", 2.5, 0.35, "verified"
    roles["fish"].update(stake="mid", skill=0.6, vpip=0.55)
    roles["shark"].update(stake="mid", skill=1.5, vpip=0.30)
    return roles


def prepare_identities(room, s, roles):
    """Shared devices, IPs and wallets - set before any activity is generated."""
    r = room
    # R1: feeders share two devices and two home IPs; the receiver later uses a feeder device once
    s["R1"]["shared_devices"] = [r.new_device(), r.new_device()]
    shared_ips = [r.new_ip("residential"), r.new_ip("residential")]
    for i, f in enumerate(s["R1"]["feeders"]):
        f["devices"], f["home_ip"] = [s["R1"]["shared_devices"][i // 2]], shared_ips[i // 2]
    # R2: same flat (IP), different devices -> only a weak link
    s["R2"]["feeder"]["home_ip"] = s["R2"]["receiver"]["home_ip"]
    # R3: the team plays from one flat; two of them also share a laptop
    c1, c2, c3 = s["R3"]
    c2["home_ip"] = c3["home_ip"] = c1["home_ip"]
    c2["devices"].append(c1["devices"][0])
    # R4: both accounts are funded from the same wallet
    s["R4"][1]["wallet"] = s["R4"][0]["wallet"]
    # R5: twelve accounts, two devices, one VPN exit
    farm_devices, vpn_ip = [r.new_device(), r.new_device()], r.new_ip("hosting")
    for i, p in enumerate(s["R5"]):
        p["devices"], p["home_ip"] = [farm_devices[i % 2]], vpn_ip
    # R6: five accounts on one laptop at home
    laptop, home = r.new_device(), r.new_ip("residential")
    for p in s["R6"]:
        p["devices"], p["home_ip"] = [laptop], home


# =============================================================================
# Ordinary behaviour
# =============================================================================

def simulate_regular_accounts(room):
    """Logins, deposits and welcome bonuses for everyone who plays at ordinary tables."""
    rng = room.rng
    for p in room.players:
        if not p["in_pool"]:
            continue
        start = p["active_from"]
        span = (WINDOW_END - start).total_seconds()
        if rng.random() < 0.35:
            p["devices"].append(room.new_device())
        if p["mobile_ip"] is None and rng.random() < 0.3:
            p["mobile_ip"] = room.new_ip("mobile")
        new_signup = p["signup_ts"] >= WINDOW_START
        if new_signup:
            room.login(p, p["signup_ts"], p["devices"][0], p["home_ip"], p["country"])
        for _ in range(3 + int(p["activity"] * 10)):
            ts = start + timedelta(seconds=rng.uniform(0, span))
            ip, ip_type, country = p["home_ip"], "residential", p["country"]
            if p["mobile_ip"] and rng.random() < 0.35:
                ip, ip_type = p["mobile_ip"], "mobile"
            if not p["no_random_travel"] and rng.random() < 0.02:     # on a trip, with their usual device
                ip, ip_type, country = room.new_ip("mobile"), "mobile", pick(rng, COUNTRIES)
            room.login(p, ts, rng.choice(p["devices"]), ip, country, ip_type)
        if new_signup or rng.random() < 0.65:
            first = (p["signup_ts"] + timedelta(minutes=rng.uniform(5, 120)) if new_signup
                     else start + timedelta(seconds=rng.uniform(0, span * 0.6)))
            extra = min(5, int(rng.expovariate(1.0) * (1 + p["activity"])))
            later = sorted(first + (WINDOW_END - first) * rng.random() for _ in range(extra))
            for ts in [first] + later:
                amount = min(1500.0, max(10.0, rng.lognormvariate(math.log(60), 1.0)))
                room.tx(p, ts, "deposit", amount, p["wallet"], pick(rng, [("USDT", 70), ("BTC", 18), ("ETH", 12)]))
            if new_signup and rng.random() < 0.55:
                room.bonus(p, first, "welcome", WELCOME_BONUS)


def simulate_normal_tables(room):
    """Every day: a few tables per stake level, seats filled with active players."""
    rng = room.rng
    day = WINDOW_START
    while day < WINDOW_END:
        for stake, n_tables in TABLES_PER_DAY.items():
            eligible = [p for p in room.pools[stake] if p["active_from"] <= day]
            cum, total = [], 0.0
            for p in eligible:
                total += p["activity"]
                cum.append(total)
            for _ in range(n_tables):
                k, seats = rng.choice([5, 6, 6, 6]), []
                while len(seats) < k:
                    p = rng.choices(eligible, cum_weights=cum)[0]
                    if all(p is not s for s in seats):
                        seats.append(p)
                start = day + timedelta(minutes=rng.randint(0, 23 * 60))
                room.run_table(start, stake, seats, rng.randint(25, 60))
        day += timedelta(days=1)


def simulate_regular_withdrawals(room):
    """Ordinary players cash out part of their balance a few days after their last deposit."""
    rng = room.rng
    net, deposits, bonuses = defaultdict(float), defaultdict(list), defaultdict(float)
    for r in room.hand_players:
        net[r["player"]["key"]] += r["net"]
    for t in room.transactions:
        if t["type"] == "deposit":
            deposits[t["player"]["key"]].append(t)
    for b in room.bonuses:
        bonuses[b["player"]["key"]] += b["amount_usdt"]
    for p in room.players:
        if not p["in_pool"] or p["custom_withdrawals"]:
            continue
        deps = deposits[p["key"]]
        balance = sum(t["amount_usdt"] for t in deps) + bonuses[p["key"]] + net[p["key"]]
        if not deps:
            balance += rng.uniform(50, 500)      # money left over from before July
        if balance < 30 or rng.random() > 0.7:
            continue
        earliest = max([t["ts"] for t in deps], default=WINDOW_START) + timedelta(days=3.5)
        latest = WINDOW_END - timedelta(hours=1)
        if earliest >= latest:
            continue
        wallet = room.exchange_wallet if p["withdraw_to_exchange"] else p["wallet"]
        room.tx(p, earliest + (latest - earliest) * rng.random(), "withdrawal",
                balance * rng.uniform(0.5, 0.9), wallet)


# =============================================================================
# Planted scenarios
# =============================================================================

def plant_chip_dump_ring(r, ring):
    rcv, feeders = ring["receiver"], ring["feeders"]
    funding_wallet, payout_wallet = r.new_wallet(), r.new_wallet()
    r.tx(rcv, rcv["signup_ts"] + timedelta(minutes=20), "deposit", 150.0, rcv["wallet"])
    for f in feeders:
        r.login(f, f["signup_ts"], f["devices"][0], f["home_ip"], f["country"])
        r.tx(f, f["signup_ts"] + timedelta(minutes=r.rng.randint(10, 50)), "deposit",
             r.rng.uniform(1700, 2300), funding_wallet)
    r.login(rcv, at(8, 12, 23, 41), ring["shared_devices"][0], rcv["home_ip"], rcv["country"])
    for f, first_day in zip(feeders, (at(8, 10), at(8, 17), at(8, 24), at(9, 1))):
        mark, start = len(r.hand_players), None
        for d in range(3):        # three late-night heads-up sessions per feeder
            start = first_day + timedelta(days=d, hours=r.rng.uniform(1, 4))
            r.login(f, start - timedelta(minutes=6), f["devices"][0], f["home_ip"], f["country"])
            r.login(rcv, start - timedelta(minutes=3), rcv["devices"][0], rcv["home_ip"], rcv["country"])
            r.run_table(start, "high", [f, rcv], r.rng.randint(4, 6), dump=(f, rcv))
        r.tx(rcv, start + timedelta(hours=r.rng.uniform(6, 20)), "withdrawal",
             r.net_in_hands(rcv, mark) * 0.9, payout_wallet)
    r.note("R1", "fraud", "Chip-dumping ring (5 accounts)", "chip_dumping;multi_accounting", feeders + [rcv],
           "4 new accounts funded from one wallet, sharing 2 devices, lose on purpose to 1 receiver "
           "in late-night heads-up games; the receiver cashes out to a fresh wallet")


def plant_chip_dump_pair(r, pair):
    f, rcv = pair["feeder"], pair["receiver"]
    r.login(f, f["signup_ts"], f["devices"][0], f["home_ip"], f["country"])
    r.tx(f, f["signup_ts"] + timedelta(minutes=15), "deposit", 1300.0, f["wallet"], "BTC")
    mark = len(r.hand_players)
    for day in (at(9, 12), at(9, 15), at(9, 19)):
        start = day + timedelta(hours=r.rng.uniform(0, 3))
        r.login(f, start - timedelta(minutes=5), f["devices"][0], f["home_ip"], f["country"])
        r.login(rcv, start - timedelta(minutes=2), rcv["devices"][0], rcv["home_ip"], rcv["country"])
        r.run_table(start, "mid", [f, rcv], 4, dump=(f, rcv), dump_bb=(25, 60))
    r.tx(rcv, at(9, 20, 14, 5), "withdrawal", r.net_in_hands(rcv, mark) * 0.85, rcv["wallet"])
    r.note("R2", "fraud", "Chip-dumping pair", "chip_dumping", [f, rcv],
           "a 2-day-old account dumps its deposit to an older account on the same home IP (different devices)")


def plant_collusion(r, team, stake, first_day, last_day, gaps, scenario, title, notes):
    """The team joins tables together; when two of them are in a hand, one gets out of the way."""
    for p in team:
        r.tx(p, max(p["active_from"], first_day) - timedelta(hours=2), "deposit", r.rng.uniform(800, 1500), p["wallet"])
    day = first_day
    while day < last_day:
        members = team if len(team) == 2 or r.rng.random() < 0.7 else r.rng.sample(team, 2)
        start = day + timedelta(hours=r.rng.uniform(17, 22))
        fillers = r.pick_fillers(stake, start, 6 - len(members), exclude=team)
        r.run_table(start, stake, members + fillers, r.rng.randint(40, 70), team=team, edge=1.6)
        day += timedelta(days=r.rng.choice(gaps))
    r.note(scenario, "fraud", title, "collusion;multi_accounting", team, notes)


def plant_bonus_farm(r, farm, scenario, title, payout_wallets, deposit_wallets, notes):
    deposits = {}
    for i, p in enumerate(farm):
        ip_type = "hosting" if p["home_ip"].startswith("10.240.") else "residential"
        p["ip_country"] = "DE" if ip_type == "hosting" else p["country"]
        r.login(p, p["signup_ts"], p["devices"][0], p["home_ip"], p["ip_country"], ip_type)
        ts = p["signup_ts"] + timedelta(minutes=r.rng.randint(4, 25))
        deposits[p["key"]] = r.rng.uniform(20, 24)
        wallet = deposit_wallets[i % len(deposit_wallets)] if deposit_wallets else p["wallet"]
        r.tx(p, ts, "deposit", deposits[p["key"]], wallet)
        r.bonus(p, ts, "welcome", WELCOME_BONUS)
    for a, b in zip(farm[0::2], farm[1::2] + farm[:1]):     # a few micro hands, two farm accounts at a time
        start = max(a["signup_ts"], b["signup_ts"]) + timedelta(hours=r.rng.uniform(8, 30))
        fillers = r.pick_fillers("micro", start, 4, exclude=[a, b])
        r.run_table(start, "micro", [a, b] + fillers, r.rng.randint(12, 30), keep=[a, b])
    for i, p in enumerate(farm):
        played = sum(row["net"] for row in r.hand_players if row["player"] is p)
        ts = p["signup_ts"] + timedelta(days=r.rng.uniform(2.5, 5))
        r.login(p, ts - timedelta(minutes=8), p["devices"][0], p["home_ip"], p["ip_country"],
                "hosting" if p["home_ip"].startswith("10.240.") else "residential")
        r.tx(p, ts, "withdrawal", deposits[p["key"]] + WELCOME_BONUS + played - r.rng.uniform(0, 3),
             payout_wallets[i % len(payout_wallets)])
    r.note(scenario, "fraud", title, "bonus_abuse;multi_accounting", farm, notes)


def plant_account_takeover(r, victim, attack_ts, device, ip, ip_country, wallet, amount):
    seed_ts = datetime(2026, 7, 2, 19) + timedelta(hours=r.rng.uniform(0, 48))
    r.login(victim, seed_ts - timedelta(minutes=5), victim["devices"][0], victim["home_ip"], victim["country"])
    r.tx(victim, seed_ts, "deposit", amount * r.rng.uniform(1.1, 1.3), victim["wallet"])
    r.login(victim, attack_ts, device, ip, ip_country, "hosting")
    r.tx(victim, attack_ts + timedelta(minutes=r.rng.randint(12, 40)), "withdrawal", amount, wallet)
    # the real owner comes back later on their usual device
    r.login(victim, attack_ts + timedelta(hours=r.rng.uniform(10, 30)), victim["devices"][0],
            victim["home_ip"], victim["country"])


def plant_account_sharing(r, p, first_day, days, other_country):
    abroad_device, abroad_ip = r.new_device(), r.new_ip("residential")
    for d in range(days):
        day = first_day + timedelta(days=d)
        for k in range(r.rng.randint(2, 3)):
            t = day + timedelta(hours=8 + 5 * k + r.rng.uniform(0, 1.5))
            r.login(p, t, p["devices"][0], p["home_ip"], p["country"])
            r.login(p, t + timedelta(minutes=r.rng.randint(40, 150)), abroad_device, abroad_ip, other_country)


def plant_pass_through(r, p, deposit_ts, deposit, asset, hands, hours, payout_wallet, stake="micro"):
    r.login(p, p["signup_ts"], p["devices"][0], p["home_ip"], p["country"])
    r.login(p, deposit_ts - timedelta(minutes=4), p["devices"][0], p["home_ip"], p["country"])
    r.tx(p, deposit_ts, "deposit", deposit, p["wallet"], asset)
    if hands:
        start = deposit_ts + timedelta(minutes=40)
        r.run_table(start, stake, [p] + r.pick_fillers(stake, start, 4), hands, keep=[p])
    out_ts = deposit_ts + timedelta(hours=hours)
    r.login(p, out_ts - timedelta(minutes=6), p["devices"][0], p["home_ip"], p["country"])
    r.tx(p, out_ts, "withdrawal", deposit * r.rng.uniform(0.98, 0.995), payout_wallet)


def plant_structuring(r, p, days, amounts, withdraw_ts=None, withdraw=0.0):
    wallets = [p["wallet"], r.new_wallet()]
    for i, (day, amount) in enumerate(zip(days, amounts)):
        ts = day + timedelta(hours=r.rng.uniform(9, 22))
        r.login(p, ts - timedelta(minutes=3), p["devices"][0], p["home_ip"], p["country"])
        r.tx(p, ts, "deposit", amount, wallets[i % 2])
    if withdraw_ts:
        r.tx(p, withdraw_ts, "withdrawal", withdraw, r.new_wallet())


def plant_scenarios(room, s, roles):
    r, rng = room, room.rng
    plant_chip_dump_ring(r, s["R1"])
    plant_chip_dump_pair(r, s["R2"])
    plant_collusion(r, s["R3"], "mid", at(7, 5), at(9, 29), [2, 2, 3, 3, 4], "R3", "Collusion team (3 accounts)",
                    "three accounts on one home IP (two also share a laptop) sit together and avoid playing each other")
    plant_collusion(r, s["R4"], "low", at(8, 15), at(9, 30), [2, 3, 4], "R4", "Collusion pair",
                    "two accounts funded from the same wallet sit together and soft-play each other")
    plant_bonus_farm(r, s["R5"], "R5", "Bonus-abuse farm (12 accounts)", [r.new_wallet(), r.new_wallet()],
                     [r.new_wallet(), r.new_wallet(), r.new_wallet()],
                     "12 accounts opened in 6 days with disposable emails on 2 devices behind one VPN exit; "
                     "each takes the welcome bonus, plays a few hands and cashes out to 2 shared wallets")
    plant_bonus_farm(r, s["R6"], "R6", "Bonus-abuse farm (5 accounts)", [r.new_wallet()], [],
                     "5 accounts opened on consecutive days on one laptop, cashing out to one wallet")

    # account takeovers: one in August, then a three-account campaign in September
    v = roles["victims"]
    plant_account_takeover(r, v[0], at(8, 19, 2, 14), r.new_device(), r.new_ip("hosting"), "SG", r.new_wallet(), 1840.0)
    r.note("ATO1", "fraud", "Account takeover", "account_takeover", [v[0]],
           "established account: login from a new device in a new country, then a withdrawal to a new wallet within 40 min")
    att_device, att_ip, att_wallet = r.new_device(), r.new_ip("hosting"), r.new_wallet()
    for victim, ts, amount in zip(v[1:], (at(9, 21, 3, 5), at(9, 22, 1, 40), at(9, 23, 4, 10)), (2310.0, 1160.0, 3040.0)):
        plant_account_takeover(r, victim, ts, att_device, att_ip, "NL", att_wallet, amount)
    r.note("ATO2", "fraud", "Account-takeover campaign (3 victims)", "account_takeover", v[1:],
           "one attacker device, IP and payout wallet used against three unrelated accounts on three nights")

    plant_account_sharing(r, s["S1"], at(7, 10), 10, "AR")
    r.note("S1", "fraud", "Account sharing", "account_sharing", [s["S1"]],
           "account used alternately from Canada and Argentina on two devices, hours apart, for 10 days")
    plant_account_sharing(r, s["S2"], at(9, 5), 9, "TH")
    r.note("S2", "fraud", "Account sharing", "account_sharing", [s["S2"]],
           "account used alternately from the UK and Thailand on two devices, hours apart, for 9 days")

    plant_pass_through(r, s["A1"], at(8, 6, 10, 12), 4800.0, "BTC", 8, 20.3, r.new_wallet())
    r.note("A1", "fraud", "Deposit-and-withdraw (pass-through)", "aml_pass_through", [s["A1"]],
           "2-day-old account deposits 4,800 in BTC, plays 8 micro hands, withdraws ~99% in USDT 20 h later")
    shared_payout = r.new_wallet()
    plant_pass_through(r, s["A2"], at(9, 14, 9, 5), 3200.0, "ETH", 3, 9.0, shared_payout, stake="low")
    plant_pass_through(r, s["A3"], at(9, 25, 13, 40), 2600.0, "BTC", 0, 30.2, shared_payout)
    r.note("A2", "fraud", "Pass-through pair sharing a payout wallet", "aml_pass_through;multi_accounting",
           [s["A2"], s["A3"]], "two new accounts deposit in ETH/BTC, barely play, and withdraw USDT to the same wallet")

    plant_structuring(r, s["ST1"], [at(7, 8), at(7, 9), at(7, 10), at(7, 12), at(7, 13)],
                      [1950.0, 1980.0, 1900.0, 1990.0, 1960.0], at(7, 28, 20, 30), 6000.0)
    r.note("ST1", "fraud", "Structuring under the 2,000 threshold", "aml_structuring", [s["ST1"]],
           "five deposits of 1,900-1,990 in six days from two wallets")
    plant_structuring(r, s["ST2"], [at(9, 2), at(9, 4), at(9, 6), at(9, 8)], [1850.0, 1995.0, 1920.0, 1970.0])
    r.note("ST2", "fraud", "Structuring under the 2,000 threshold", "aml_structuring", [s["ST2"]],
           "four deposits of 1,850-1,995 in a week")

    # ---- innocent look-alikes -------------------------------------------------
    a, b = roles["household"]
    r.note("B1", "benign", "Household sharing wifi", "watchlist_only", [a, b],
           "two people in one home: same IP, own devices and wallets, never at the same table")

    t = roles["traveller_ok"]
    r.login(t, at(7, 10, 18, 55), t["devices"][0], t["home_ip"], t["country"])
    r.tx(t, at(7, 10, 19), "deposit", 500.0, t["wallet"])
    tablet, holiday_ip = r.new_device(), r.new_ip("mobile")
    for d in range(8, 19):
        r.login(t, at(8, d, rng.randint(9, 22), rng.randint(0, 59)), tablet, holiday_ip, "ES", "mobile")
    r.tx(t, at(8, 12, 21, 30), "withdrawal", 300.0, t["wallet"])
    r.note("B4", "benign", "Traveller withdrawing to own wallet", "no:account_takeover", [t],
           "on holiday in Spain with a new tablet; withdraws to the wallet they always use")

    t = roles["traveller_fp"]
    r.login(t, at(7, 20, 17, 55), t["devices"][0], t["home_ip"], t["country"])
    r.tx(t, at(7, 20, 18), "deposit", 900.0, t["wallet"])
    phone, trip_ip = r.new_device(), r.new_ip("mobile")
    r.login(t, at(9, 9, 15, 20), phone, trip_ip, "MX", "mobile")
    r.tx(t, at(9, 9, 18, 5), "withdrawal", 640.0, r.new_wallet())
    for d in range(10, 14):
        r.login(t, at(9, d, rng.randint(10, 22), rng.randint(0, 59)), phone, trip_ip, "MX", "mobile")
    for d in range(15, 30, 2):
        r.login(t, at(9, d, rng.randint(17, 23), rng.randint(0, 59)), phone, t["home_ip"], t["country"])
    r.note("B8", "benign", "Traveller with new phone and new wallet", "expected_fp:account_takeover", [t],
           "buys a phone in Mexico and withdraws to a new wallet - looks exactly like a takeover until a human checks")

    g1, g2 = roles["regs"]
    day = at(7, 3)
    while day < at(9, 28):
        start = day + timedelta(hours=rng.uniform(12, 22))
        r.run_table(start, "mid", [g1, g2] + r.pick_fillers("mid", start, 4, exclude=[g1, g2]),
                    rng.randint(40, 70), keep=[g1, g2])
        day += timedelta(days=rng.choice([2, 3, 4]))
    r.note("B5", "benign", "Two regulars who share tables", "no:collusion", [g1, g2],
           "high-volume players at the same stake who often sit together but contest pots normally")

    hr = roles["high_roller"]
    for ts, amount in ((at(7, 6, 20), 2500.0), (at(8, 3, 19), 6000.0), (at(9, 7, 21), 4000.0)):
        r.login(hr, ts - timedelta(minutes=5), hr["devices"][0], hr["home_ip"], hr["country"])
        r.tx(hr, ts, "deposit", amount, hr["wallet"])
    for d in range(6):
        start = at(8, 3, 20) + timedelta(hours=8 * d)
        r.run_table(start, "mid", [hr] + r.pick_fillers("mid", start, 5, exclude=[hr]), 60, keep=[hr])
    r.tx(hr, at(8, 5, 22), "withdrawal", 5500.0, hr["wallet"])
    r.note("B6", "benign", "High roller: big deposit, big play, fast cash-out", "no:aml_pass_through", [hr],
           "deposits 6,000 and withdraws 5,500 two days later - but plays ~360 hands in between")

    fish, shark = roles["fish"], roles["shark"]
    for day in (at(7, 18), at(7, 25), at(8, 2), at(8, 9), at(8, 21), at(9, 4), at(9, 11), at(9, 25)):
        r.run_table(day + timedelta(hours=rng.uniform(18, 22)), "mid", [fish, shark], 25, showdown_rate=0.7)
    r.note("B7", "benign", "Weak player repeatedly losing to a strong one", "no:chip_dumping", [fish, shark],
           "heads-up games where the weaker player loses most pots - but at showdown, not by folding big bets")


def note_identifier_lookalikes(room, roles):
    """B2 and B3 are only known once activity exists: who actually used the shared IP / exchange wallet."""
    phones = {x["player"]["key"]: x["player"] for x in room.logins if x["ip"] == CGNAT_IP and x["ts"] < WINDOW_END}
    room.note("B2", "benign", "Mobile-carrier gateway IP", "excluded_ip", list(phones.values()),
              f"{len(phones)} unrelated players whose phones share one carrier-grade NAT address", CGNAT_IP)
    users = {t["player"]["key"]: t["player"] for t in room.transactions
             if t["wallet_address"] == room.exchange_wallet and t["ts"] < WINDOW_END}
    room.note("B3", "benign", "Exchange hot wallet used by many players", "excluded_wallet", list(users.values()),
              f"{len(users)} unrelated players withdraw to the same labelled exchange address", room.exchange_wallet)


# =============================================================================
# Output
# =============================================================================

def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_csvs(room, data_dir):
    data_dir.mkdir(parents=True, exist_ok=True)
    keep = lambda rows: sorted((x for x in rows if x["ts"] < WINDOW_END), key=lambda x: x["ts"])

    players = sorted(room.players, key=lambda p: p["id"])
    write_csv(data_dir / "players.csv",
              [{"player_id": p["id"], "signup_ts": fmt(p["signup_ts"]), "country": p["country"],
                "email_domain": p["email_domain"], "email_hash": p["email_hash"], "kyc_level": p["kyc_level"],
                "signup_ip": p["home_ip"]} for p in players],
              ["player_id", "signup_ts", "country", "email_domain", "email_hash", "kyc_level", "signup_ip"])

    write_csv(data_dir / "logins.csv",
              [{"login_id": f"L{i:07d}", "player_id": x["player"]["id"], "ts": fmt(x["ts"]), "device_id": x["device_id"],
                "ip": x["ip"], "ip_country": x["ip_country"], "ip_type": x["ip_type"]}
               for i, x in enumerate(keep(room.logins), 1)],
              ["login_id", "player_id", "ts", "device_id", "ip", "ip_country", "ip_type"])

    write_csv(data_dir / "transactions.csv",
              [{"tx_id": f"T{i:06d}", "player_id": x["player"]["id"], "ts": fmt(x["ts"]), "type": x["type"],
                "amount_usdt": f"{x['amount_usdt']:.2f}", "asset": x["asset"], "wallet_address": x["wallet_address"]}
               for i, x in enumerate(keep(room.transactions), 1)],
              ["tx_id", "player_id", "ts", "type", "amount_usdt", "asset", "wallet_address"])

    write_csv(data_dir / "bonuses.csv",
              [{"bonus_id": f"B{i:05d}", "player_id": x["player"]["id"], "ts": fmt(x["ts"]),
                "bonus_type": x["bonus_type"], "amount_usdt": f"{x['amount_usdt']:.2f}"}
               for i, x in enumerate(keep(room.bonuses), 1)],
              ["bonus_id", "player_id", "ts", "bonus_type", "amount_usdt"])

    hands = keep(room.hands)
    hand_ids = {h["hid"]: f"H{i:07d}" for i, h in enumerate(hands, 1)}
    write_csv(data_dir / "hands.csv",
              [{"hand_id": hand_ids[h["hid"]], "table_id": h["table_id"], "ts": fmt(h["ts"]),
                "big_blind": f"{h['big_blind']:.2f}", "seats": h["seats"]} for h in hands],
              ["hand_id", "table_id", "ts", "big_blind", "seats"])
    rows = [x for x in room.hand_players if x["hand"]["hid"] in hand_ids]
    rows.sort(key=lambda x: (hand_ids[x["hand"]["hid"]], x["seat"]))
    write_csv(data_dir / "hand_players.csv",
              [{"hand_id": hand_ids[x["hand"]["hid"]], "player_id": x["player"]["id"], "seat": x["seat"],
                "vpip": x["vpip"], "invested": f"{x['invested']:.2f}", "net": f"{x['net']:.2f}",
                "showdown": x["showdown"]} for x in rows],
              ["hand_id", "player_id", "seat", "vpip", "invested", "net", "showdown"])

    write_csv(data_dir / "known_wallets.csv", room.known_wallets, ["wallet_address", "label", "label_type"])
    write_csv(data_dir / "answer_key.csv",
              [{**{k: v for k, v in a.items() if k != "players"},
                "player_ids": ";".join(sorted(p["id"] for p in a["players"]))} for a in room.answer_key],
              ["scenario_id", "kind", "title", "expected", "player_ids", "value", "notes"])
    return {"players": len(players), "logins": sum(1 for x in room.logins if x["ts"] < WINDOW_END),
            "transactions": sum(1 for x in room.transactions if x["ts"] < WINDOW_END),
            "hands": len(hands), "hand_player_rows": len(rows)}


def generate(data_dir):
    room = Room(SEED)
    scenarios = create_scenario_accounts(room)
    while len(room.players) < N_PLAYERS:
        room.new_player(random_signup(room.rng))
    room.finalise_ids()
    roles = pick_roles(room)
    prepare_identities(room, scenarios, roles)
    room.build_pools()
    simulate_regular_accounts(room)
    plant_scenarios(room, scenarios, roles)
    simulate_normal_tables(room)
    simulate_regular_withdrawals(room)
    note_identifier_lookalikes(room, roles)
    return write_csvs(room, Path(data_dir))


if __name__ == "__main__":
    print(generate(Path(__file__).resolve().parent.parent / "data"))
