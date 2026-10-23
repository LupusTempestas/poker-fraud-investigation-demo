# Poker Fraud Investigation Demo

A small, self-contained project that shows how fraud in an online **crypto poker room** can be found,
investigated and reported: a synthetic player base with deliberately planted fraud rings, seven
detection rules written in plain SQL, a ranked queue of case files written the way an investigator
documents a case for an appeal, and a one-page monthly fraud-trends report.

Built by **Alex Lafarque** (Trust & Safety, 6+ years) with **Claude Code**, an AI coding assistant.
Alex set what the project had to demonstrate and reviewed the results; Claude Code wrote the Python
and SQL. See [How this was built](#how-this-was-built).

> **All data is synthetic.** No real player, email, IP address or wallet is involved.

---

## In 30 seconds

| | |
|---|---|
| **What it does** | Generates 3 months of activity for 2,000 fictional poker players, runs 7 fraud rules, groups the hits into investigation cases, ranks them, and writes a monthly report. |
| **What it catches** | Multi-accounting, chip dumping, collusion / soft-play, bonus abuse, account takeover, account sharing, and two AML red flags (pass-through money, structuring). |
| **How well** | Found all **14** planted fraud scenarios and left all **7** innocent look-alikes alone. It also flagged **2** travellers with new phones as possible account takeovers - one planted on purpose, one that arose by chance - which is exactly why every flag goes to a human. |
| **Start here** | [`output/monthly_fraud_trends.pdf`](output/monthly_fraud_trends.pdf) (one page) · [`output/case_list.md`](output/case_list.md) (case files) · [`rules/`](rules/) (each rule explained at the top of its file) |

---

## How to run it

```bash
python run.py
```

That one command rebuilds everything in about 5 seconds: new data, all rules, case files, the check
against the answer key, and the report. It needs only **Python 3.10 or newer** - no packages to
install. The PDF is printed with Google Chrome; without Chrome, run `python run.py --no-pdf` (or point
to Chrome/Edge with `--chrome PATH`). Results are identical on every run (the random data uses a
fixed seed).

| Output | What it is |
|---|---|
| `output/case_list.md` | The case queue: ranked table, then a full case file for each case |
| `output/case_list.csv` | The same queue as a spreadsheet |
| `output/monthly_fraud_trends.pdf` | One-page report for September 2026 (also `.md` and `.html`) |
| `output/detection_check.md` | Rules vs. the planted answer key: what was caught, what was missed |
| `output/poker_room.sqlite` | All data and rule results, for anyone who wants to run their own queries |
| `data/*.csv` | The synthetic raw data, plus `answer_key.csv` (what was planted) |

---

## The data

A fictional crypto poker room, **1 July - 30 September 2026**, 2,000 players, ~40,000 hands.

| Table | One row per | Useful columns |
|---|---|---|
| `players` | account | signup date, declared country, email domain, KYC level |
| `logins` | login | device ID, IP address, IP country, IP type (home / mobile / hosting) |
| `transactions` | deposit or withdrawal | amount (in USDT), crypto asset used, wallet address |
| `bonuses` | bonus credited | type, amount |
| `hands` | poker hand | table, time, big blind size, seats |
| `hand_players` | player in a hand | played the hand or not (VPIP), money put in, result, reached showdown |

**Privacy by design**, the way an analyst would see a minimised extract: emails are stored only as a
hash plus the domain, every IP address is in the private `10.x.x.x` range (it cannot point to anyone),
and wallet addresses are random.

**Simplifications.** Hands have no cards and blinds are ignored: each hand records who chose to play,
how much they put in, who won, and whether it went to showdown. That is enough to see the patterns
the rules look for.

### What was planted

On top of ordinary play, the generator plants scenarios the rules **should** catch and innocent
look-alikes they **should not** flag. Everything is listed in `data/answer_key.csv`. The rules never
read that file; it is only used afterwards to check them.

| ID | Fraud scenario |
|---|---|
| R1 | **Chip-dumping ring** - 4 new accounts funded from one wallet lose on purpose to a 5th account in late-night two-player games; the 5th cashes out to a fresh wallet |
| R2 | **Chip-dumping pair** - a 2-day-old account dumps its deposit to an older account on the same home IP |
| R3 | **Collusion team** - 3 accounts on one home IP sit at the same tables and avoid playing each other |
| R4 | **Collusion pair** - 2 accounts funded from the same wallet do the same |
| R5 | **Bonus farm, 12 accounts** - disposable emails, 2 devices, 1 VPN exit; each takes the welcome bonus and cashes out |
| R6 | **Bonus farm, 5 accounts** - one laptop, one payout wallet |
| ATO1 | **Account takeover** - new device + new country, then the balance goes to a new wallet within the hour |
| ATO2 | **Takeover campaign** - one attacker device and wallet used against 3 unrelated accounts on 3 nights |
| S1, S2 | **Account sharing** - one account used alternately from two countries, hours apart, for over a week |
| A1 | **Pass-through** - 4,800 deposited in BTC, 8 tiny hands, ~99% withdrawn in USDT 20 hours later |
| A2 | **Pass-through pair** - 2 new accounts, same pattern, same payout wallet |
| ST1, ST2 | **Structuring** - 4-5 deposits just under 2,000 USDT within a week |

| ID | Innocent look-alike (should not be flagged) |
|---|---|
| B1 | Two people in one home sharing wifi (same IP, own devices and wallets) |
| B2 | ~30 strangers whose phones share one mobile-carrier IP address |
| B3 | 20 players who withdraw to the same exchange wallet |
| B4 | A traveller who logs in from abroad on a new tablet and withdraws to their usual wallet |
| B5 | Two high-volume regulars who often sit at the same tables |
| B6 | A high roller who deposits 6,000 and withdraws 5,500 two days later - after playing ~360 hands |
| B7 | A weak player who keeps losing to a strong one in two-player games |
| B8 | A traveller who buys a phone abroad and withdraws to a new wallet. **Planted false positive**: it looks exactly like a takeover until a human checks |

---

## The rules

Each rule is one SQL file in [`rules/`](rules/) with a plain-English explanation at the top and its
thresholds listed in a `settings` block, so they are easy to find and change.

| # | Rule | In one line | File |
|---|---|---|---|
| 1 | Multi-accounting | Accounts that share a device, IP address or wallet, grouped into clusters | [`01_shared_identifiers.sql`](rules/01_shared_identifiers.sql) |
| 2 | Account takeover | New device + new country, then a withdrawal to a new wallet within 24 h | [`02_account_takeover.sql`](rules/02_account_takeover.sql) |
| 3 | Bonus abuse | 3+ linked new accounts that take the welcome bonus, barely play and cash out | [`03_bonus_abuse.sql`](rules/03_bonus_abuse.sql) |
| 4 | Chip dumping | Money flowing one way between two players, lost by folding after big bets | [`04_chip_dumping.sql`](rules/04_chip_dumping.sql) |
| 5 | Collusion / soft-play | Players who sit together often but rarely play a pot against each other | [`05_collusion_soft_play.sql`](rules/05_collusion_soft_play.sql) |
| 6 | Account sharing | One account switching device and country back and forth within hours | [`06_account_sharing.sql`](rules/06_account_sharing.sql) |
| 7 | AML red flags | Deposits withdrawn almost unplayed; deposits split to stay under a threshold | [`07_aml_red_flags.sql`](rules/07_aml_red_flags.sql) |

### 1. Multi-accounting

- **What it detects:** two or more accounts that used the same device, the same IP address, or the
  same crypto wallet. Links are joined into clusters ("connect the dots": if A shares a device with B
  and B shares a wallet with C, all three are one cluster).
- **Why it matters in poker:** one person with several accounts can sit at one table with several
  hands of cards, pass chips between accounts, or claim the welcome bonus again and again. Most other
  rules become far stronger when the accounts involved are linked.
- **How it works:** list every account-device, account-IP and account-wallet pair, then find values
  that two different accounts have in common. Device and wallet links are **strong**; an IP link alone
  is **weak**.
- **False-positive risks:** households and flatmates share wifi; mobile carriers put hundreds of
  phones behind one IP address; many players withdraw to the same exchange wallet. The rule therefore
  ignores IPs used by more than 10 accounts and wallets labelled as exchange wallets, and lists what it
  ignored. Clusters linked only by IP go on a watchlist, not into a case.
- **How an analyst verifies:** request ID verification (KYC) for every linked account - are these
  different real people? Did the linked accounts ever sit at the same table or move money to each other?

### 2. Account takeover (ATO)

- **What it detects:** on an account at least 30 days old, a login from a device **and** a country
  the account has never used, followed within 24 hours by a withdrawal to a wallet it has never used.
- **Why it matters in poker:** crypto withdrawals cannot be reversed. A criminal with a phished or
  reused password logs in and empties the balance. The victim is a real customer, so this is the most
  time-critical case type (marked **URGENT** in the queue). In production this check would run at the
  moment of withdrawal, not in a monthly batch.
- **How it works:** number each account's logins (first time on this device? first time from this
  country?) and its wallets (first time used?), then look for the three firsts in that order, fast.
  Each signal alone is common; the combination is not.
- **False-positive risks:** a traveller who buys a phone abroad and withdraws to a new wallet looks
  identical (scenario B8). The case file shows the tell: whether the "new" device keeps being used from
  the home country afterwards, and whether the usual device comes back.
- **How an analyst verifies:** contact the owner through the verified email or phone on file - never
  through the flagged session; check whether password or 2FA settings changed; screen the destination
  wallet with a blockchain-analytics tool.

### 3. Bonus abuse

- **What it detects:** a cluster of linked accounts (from rule 1) where 3 or more were opened within
  14 days of each other, each claimed the welcome bonus, played fewer than 100 hands and withdrew
  within 7 days of signing up.
- **Why it matters in poker:** a welcome bonus is marketing money meant to buy a long-term player. A
  "bonus farm" collects it many times and leaves. The money per account is small; the pattern scales.
- **How it works:** find "hit and run" accounts (bonus, little play, quick cash-out), then keep only
  clusters with several of them.
- **False-positive risks:** friends who sign up together after the same promotion - but they would
  not usually share devices and payout wallets. A single quick cash-out is never enough on its own.
- **How an analyst verifies:** compare KYC details, device fingerprints and payment sources; check the
  referral or affiliate code used at sign-up; confirm which bonus-terms clause applies.

### 4. Chip dumping

- **What it detects:** a pair of players where, in pots only the two of them played, one side lost
  500+ USDT over 5+ pots, got back no more than 15% of it, and lost mostly by **folding after putting
  in big amounts** (60%+ of the time, 15+ big blinds on average).
- **Why it matters in poker:** losing on purpose moves money between accounts - to launder it, to
  collect funds from multi-accounts or stolen accounts into one cash-out account, or to dodge
  withdrawal limits.
- **How it works:** for every two-player pot, record who paid whom and whether the loser folded; add
  it up in each direction and compare. The case file adds the room's normal behaviour for contrast
  (an ordinary losing player in this room folds about half the time after ~6 big blinds), whether the
  pair is linked, and how soon the receiver withdrew.
- **False-positive risks:** a weak player who keeps losing to a strong regular (scenario B7). That is
  why the rule needs folds after big bets, not just one-way money: weak players lose at showdown,
  dumpers give the pot away.
- **How an analyst verifies:** replay the hand histories (do the folds make poker sense?); check how
  the losing accounts were funded and when they were opened; check whether the pair opened a private
  table and waited for each other.

### 5. Collusion / soft-play

- **What it detects:** two players who shared a table for 100+ hands (at least 25% of the less active
  player's hands) and who played the same pot far less often than their normal habits predict - 35%
  of the expected rate or less.
- **Why it matters in poker:** colluders share information and avoid taking money from each other,
  so together they beat the honest players at the table. When collusion is confirmed, poker sites
  refund the victims.
- **How it works:** each player has a normal rate of choosing to play a hand (VPIP). If A plays 30% of
  hands and B plays 25%, two strangers sitting together should both play about 7.5% of hands. The rule
  compares that expectation with what actually happened. Honest pairs land near 1.0x; the planted
  colluders land around 0.2-0.3x.
- **False-positive risks:** two regulars who like the same tables sit together a lot (scenario B5) -
  but they still play pots against each other normally. Sitting together alone is never evidence.
- **How an analyst verifies:** review the hands where one folded early to the other; check whether
  they join tables within seconds of each other; compare each player's results with and without the
  partner present.

### 6. Account sharing

- **What it detects:** an account that switches between different devices in different countries
  within 3 hours, at least 4 times.
- **Why it matters in poker:** a shared account can mean someone stronger playing for the owner
  ("ghosting"), a bot operator, or an account rented to someone who could not pass verification -
  possibly a banned or self-excluded player.
- **How it works:** put each account's logins in time order and compare each with the one before:
  different device, different country, less than 3 hours apart = one switch.
- **False-positive risks:** VPN users appear to jump between countries, but a VPN does not change the
  device, so a device change is required too.
- **How an analyst verifies:** compare play style between the two device profiles (stakes, hours,
  how often they play a hand); ask the owner for a liveness check from their usual device.

### 7. AML red flags

Two classic anti-money-laundering patterns. A flag is **not proof of laundering**: it is a reason to
escalate to the MLRO (Money Laundering Reporting Officer), who decides whether to file a suspicious
activity report. The player is not told why the account is under review - "tipping off" is an offence.

- **Pass-through:** a deposit of 1,000+ USDT where at least 80% is withdrawn within 72 hours while
  less than 10% is wagered. The poker room is being used as a pipe between wallets, often switching
  asset on the way (in BTC, out USDT) to break the trail on the blockchain.
- **Structuring ("smurfing"):** 3+ deposits within 7 days, each between 1,800 and 1,999.99 USDT -
  just under a 2,000 review threshold. The 2,000 figure is illustrative; it mirrors the EU rule that
  gambling operators carry out customer due diligence on transactions of EUR 2,000 or more, counting
  linked transactions together - precisely so that splitting does not work.
- **False-positive risks:** a deposit made by mistake and withdrawn (usually small); an exchange's
  daily withdrawal limit that happens to sit just under 2,000; and a high roller who deposits big and
  cashes out fast - but only after real play (scenario B6), which the wagering test protects.
- **How an analyst verifies:** screen both wallets with blockchain analytics (sanctions, mixers,
  darknet markets); request source of funds and enhanced due diligence before releasing more
  withdrawals.

---

## How cases are built and ranked

1. **Signals become cases.** Each rule hit is a signal. Signals that touch the same account, the same
   cluster of linked accounts, or the same attacker device/wallet are grouped into one case.
2. **Each case gets a score:**
   - rule weights, counted once per rule type: account takeover 40 · chip dumping 35 · collusion 35 ·
     AML pass-through 30 · AML structuring 30 · bonus abuse 25 · multi-accounting 20 · account sharing 15
   - \+ 1 point per 100 USDT at risk (max 30)
   - \+ 2 points per extra account involved (max 10)

   The weights reflect harm: a takeover hurts a real customer and cannot be reversed; chip dumping and
   collusion hurt other players and can launder money; AML flags carry regulatory duties; bonus abuse
   is a marketing loss; multi-accounting alone breaks the rules but mostly matters because it enables
   the rest.
3. **Priority:** P1 (70+) review today · P2 (45-69) this week · P3 (under 45) when capacity allows.
   Account takeovers are also tagged **URGENT**.
4. **Each case file** has: status, accounts, money at risk, rules fired; a one-paragraph summary; the
   evidence with exact figures; an accounts table; a timeline; **what this does not prove**; numbered
   **verification steps**; the **proposed action if verified**; and an **appeal note** stating what the
   decision rests on and the most likely counter-argument. No action is ever taken automatically.

The case list ends with a **watchlist** (accounts linked only by a shared IP, with no other signal)
and a list of the **identifiers left out** of linking because too many accounts use them.

---

## Results on this dataset

From [`output/detection_check.md`](output/detection_check.md):

- **14 of 14** planted fraud scenarios caught, each with all its accounts in one case and the expected
  signals.
- **7 of 7** innocent look-alikes left alone: the household went to the watchlist only, the
  mobile-carrier IP and exchange wallet were ignored, and the traveller, regulars, high roller and weak
  player raised no flag.
- **16 cases** in the queue (4 P1, 9 P2, 3 P3), including **2 false positives**, both "new phone on a
  trip" takeover flags:
  - **B8** was planted to show the limit of the takeover rule.
  - **FR-2607-01** was not planted. An ordinary player logged in from abroad on a device not seen
    before in this 3-month extract, and the same day made their first withdrawal of the quarter to
    their own wallet - which looked "new" only because the data starts on 1 July. Both case files
    show the tell: the "new" device kept being used from home afterwards.

**The honest caveat.** The same project designed both the data and the rules, so a perfect score
shows the pipeline works end to end - not that these thresholds would hold on real traffic. On real
data the work is different: tune thresholds against cases analysts have confirmed, measure what share
of flags turn out to be real (precision), watch for missed abuse reported by players, and keep the
queue small enough that analysts can actually work it.

---

## The monthly report

[`output/monthly_fraud_trends.pdf`](output/monthly_fraud_trends.pdf) is a one-page summary for
September 2026, mirroring a typical requirement to "present regular reports and insights on fraud
trends and abuse rings": headline numbers against August, new cases per month by type, money at risk
by type, what changed, the rings and campaigns still active, recommended control changes, and how the
rules themselves performed. Every sentence is generated from the data, so it updates when the data
or the rules change.

---

## Limitations, and what would come next with real data

- **Simplified poker.** No cards, no blinds, no betting rounds. With real hand histories, chip dumping
  and soft-play checks would look at the actual decisions (folding a strong hand, checking down
  against a friend).
- **Bots and real-time assistance** are not covered: they need timing data (how fast and how
  regularly someone acts) rather than money flows.
- **Thresholds are hand-set.** Real thresholds come from confirmed cases and from how many alerts the
  team can work.
- **Linking is simple.** Real device fingerprints are probabilistic; wallets can be clustered with
  blockchain-analytics tools that also flag sanctioned or mixer-linked addresses.
- **Batch, not real time.** Takeover and pass-through checks belong at the moment of withdrawal.
- **SQLite.** The SQL uses standard features (window functions, common table expressions) and would
  move to PostgreSQL, BigQuery or Snowflake with small changes.

---

## Project layout

```
run.py                      one command: rebuild everything
pipeline/
  generate_data.py          step 1 - synthetic poker room + planted scenarios
  detect.py                 step 2 - load into SQLite, run the rules, build clusters
  cases.py                  step 3 - group signals into cases, score, write case files
  check.py                  step 4 - compare with the answer key
  report.py                 step 5 - monthly report (Markdown, HTML, PDF) and charts
rules/                      the seven detection rules, one SQL file each
data/                       generated CSVs + answer_key.csv
output/                     case list, report, detection check, SQLite database
```

---

## Glossary

| Term | Meaning |
|---|---|
| **AML** | Anti-money laundering |
| **Big blind** | The forced bet that sets the stakes of a table; amounts are often measured "in big blinds" |
| **Chip dumping** | Losing chips on purpose to move money to another player |
| **Collusion / soft-play** | Players working together; soft-play means avoiding taking money from a partner |
| **CGNAT** | Carrier-grade NAT: a mobile carrier putting many phones behind one public IP address |
| **EDD / KYC** | Enhanced due diligence / know your customer: identity and source-of-funds checks |
| **Heads-up** | A pot or table with only two players |
| **Hosting IP** | An IP address belonging to a server or VPN provider rather than a home or phone |
| **Hot wallet** | An exchange's shared wallet used for many customers' deposits and withdrawals |
| **MLRO** | Money Laundering Reporting Officer: decides whether to report suspicious activity |
| **Multi-accounting** | One person running more than one account |
| **Rake** | The fee the poker room takes from each pot |
| **Showdown** | The end of a hand, when remaining players reveal their cards |
| **Structuring / smurfing** | Splitting money into amounts just under a reporting or review threshold |
| **Tipping off** | Telling a customer they are under AML investigation (an offence in most regimes) |
| **USDT** | Tether, a crypto "stablecoin" pegged to the US dollar; all amounts here are in USDT |
| **VPIP** | "Voluntarily put money in pot": how often a player chooses to play a hand |

---

## How this was built

Alex Lafarque works in Trust & Safety (Rec Room, 2020-2026; now freelance content review and
labelling) and builds software as a product owner, directing AI coding assistants rather than writing
code by hand. For this project, Alex defined what it had to show - the
abuse types that matter in online poker, privacy-safe synthetic data, rules a non-engineer can read,
case files fit for an appeal, and a monthly trends report - and **Claude Code** (Anthropic's AI coding
assistant) wrote the Python and SQL. The aim was to learn the iGaming-specific side of fraud
investigation and to show the reasoning behind each rule, not to present hand-written code.
