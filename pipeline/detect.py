"""
Step 2 of the pipeline: load the CSVs into SQLite and run the detection rules.

The rules themselves live in rules/*.sql, one file per rule, each with a plain-
language explanation at the top. This file only does the glue work SQL is bad at:
loading data, running the files in order, and turning pairwise links into
clusters of accounts ("connect the dots").
"""

import csv
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE players       (player_id TEXT PRIMARY KEY, signup_ts TEXT, country TEXT, email_domain TEXT,
                            email_hash TEXT, kyc_level TEXT, signup_ip TEXT);
CREATE TABLE logins        (login_id TEXT PRIMARY KEY, player_id TEXT, ts TEXT, device_id TEXT, ip TEXT,
                            ip_country TEXT, ip_type TEXT);
CREATE TABLE transactions  (tx_id TEXT PRIMARY KEY, player_id TEXT, ts TEXT, type TEXT, amount_usdt REAL,
                            asset TEXT, wallet_address TEXT);
CREATE TABLE bonuses       (bonus_id TEXT PRIMARY KEY, player_id TEXT, ts TEXT, bonus_type TEXT, amount_usdt REAL);
CREATE TABLE hands         (hand_id TEXT PRIMARY KEY, table_id TEXT, ts TEXT, big_blind REAL, seats INTEGER);
CREATE TABLE hand_players  (hand_id TEXT, player_id TEXT, seat INTEGER, vpip INTEGER, invested REAL, net REAL,
                            showdown INTEGER);
CREATE TABLE known_wallets (wallet_address TEXT PRIMARY KEY, label TEXT, label_type TEXT);

CREATE INDEX idx_logins_player  ON logins(player_id, ts);
CREATE INDEX idx_tx_player      ON transactions(player_id, ts);
CREATE INDEX idx_tx_wallet      ON transactions(wallet_address);
CREATE INDEX idx_hp_hand        ON hand_players(hand_id);
CREATE INDEX idx_hp_player      ON hand_players(player_id);
CREATE INDEX idx_hands_ts       ON hands(ts);
"""

TABLES = ["players", "logins", "transactions", "bonuses", "hands", "hand_players", "known_wallets"]

# Files run in this order. Account takeover runs before clustering so the attacker's
# device/wallet is not mistaken for the account owner's; bonus abuse needs the clusters.
RULES_BEFORE_CLUSTERS = ["01_shared_identifiers.sql", "02_account_takeover.sql"]
RULES_AFTER_CLUSTERS = ["03_bonus_abuse.sql", "04_chip_dumping.sql", "05_collusion_soft_play.sql",
                        "06_account_sharing.sql", "07_aml_red_flags.sql"]


def load(db_path, data_dir):
    db_path.unlink(missing_ok=True)
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    for table in TABLES:
        with open(data_dir / f"{table}.csv", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            columns = next(reader)
            marks = ",".join("?" * len(columns))
            con.executemany(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({marks})", reader)
    con.commit()
    return con


class Clusters:
    """Union-find: every link merges two groups; what is left are clusters of linked accounts."""

    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)

    def groups(self):
        out = {}
        for x in self.parent:
            out.setdefault(self.find(x), []).append(x)
        return sorted(sorted(members) for members in out.values())


def attacker_values(con):
    """Device, IP and wallet used in a flagged account takeover belong to the attacker."""
    rows = con.execute("SELECT device_id, ip, wallet_address FROM sig_account_takeover").fetchall()
    return {value for row in rows for value in row}


def build_clusters(con):
    attacker = attacker_values(con)
    links = con.execute("SELECT player_a, player_b, link_type, shared_value FROM link_evidence").fetchall()
    clusters = Clusters()
    strong = set()
    for a, b, link_type, value in links:
        if value in attacker:
            continue
        clusters.union(a, b)
        if link_type in ("device", "wallet"):
            strong.update((a, b))

    con.execute("DROP TABLE IF EXISTS player_clusters")
    con.execute("DROP TABLE IF EXISTS multi_accounting_clusters")
    con.execute("CREATE TABLE player_clusters (player_id TEXT PRIMARY KEY, cluster_id TEXT, cluster_size INTEGER)")
    con.execute("""CREATE TABLE multi_accounting_clusters
                   (cluster_id TEXT PRIMARY KEY, accounts TEXT, cluster_size INTEGER, has_strong_link INTEGER)""")
    for i, members in enumerate(clusters.groups(), 1):
        cluster_id = f"CL{i:03d}"
        con.executemany("INSERT INTO player_clusters VALUES (?, ?, ?)", [(m, cluster_id, len(members)) for m in members])
        con.execute("INSERT INTO multi_accounting_clusters VALUES (?, ?, ?, ?)",
                    (cluster_id, ";".join(members), len(members), int(any(m in strong for m in members))))
    con.commit()


def run_rules(con, rules_dir):
    for name in RULES_BEFORE_CLUSTERS:
        con.executescript((rules_dir / name).read_text(encoding="utf-8"))
    build_clusters(con)
    for name in RULES_AFTER_CLUSTERS:
        con.executescript((rules_dir / name).read_text(encoding="utf-8"))
    con.commit()


def signal_counts(con):
    tables = ["link_evidence", "multi_accounting_clusters", "sig_account_takeover", "sig_bonus_abuse",
              "sig_chip_dumping", "sig_collusion", "sig_account_sharing", "sig_aml_pass_through",
              "sig_aml_structuring"]
    return {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
