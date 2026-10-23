# Detection check - rules vs. the planted answer key

_The generator writes down every scenario it plants in `data/answer_key.csv`. The rules never read that file. This page compares the two. Because the same project designed both the data and the rules, a good score proves the pipeline works end to end, not that the thresholds would hold on real traffic._

- **Fraud scenarios caught:** 14 of 14 (all accounts in one case, with the expected signals)
- **Innocent look-alikes correctly left alone:** 7 of 7
- **Planted false positive flagged (on purpose):** 1 of 1
- **Cases not linked to any planted scenario:** 1

## Fraud scenarios

| ID | What was planted | Expected | Result | Case |
|---|---|---|---|---|
| R1 | **Chip-dumping ring (5 accounts)** - 4 new accounts funded from one wallet, sharing 2 devices, lose on purpose to 1 receiver in late-night heads-up games; the receiver cashes out to a fresh wallet | Chip dumping + Multi-accounting | Caught | FR-2608-02 (P1) |
| R2 | **Chip-dumping pair** - a 2-day-old account dumps its deposit to an older account on the same home IP (different devices) | Chip dumping | Caught | FR-2609-05 (P2) |
| R3 | **Collusion team (3 accounts)** - three accounts on one home IP (two also share a laptop) sit together and avoid playing each other | Collusion / soft-play + Multi-accounting | Caught | FR-2607-02 (P1) |
| R4 | **Collusion pair** - two accounts funded from the same wallet sit together and soft-play each other | Collusion / soft-play + Multi-accounting | Caught | FR-2608-03 (P2) |
| R5 | **Bonus-abuse farm (12 accounts)** - 12 accounts opened in 6 days with disposable emails on 2 devices behind one VPN exit; each takes the welcome bonus, plays a few hands and cashes out to 2 shared wallets | Bonus abuse + Multi-accounting | Caught | FR-2609-02 (P2) |
| R6 | **Bonus-abuse farm (5 accounts)** - 5 accounts opened on consecutive days on one laptop, cashing out to one wallet | Bonus abuse + Multi-accounting | Caught | FR-2607-05 (P2) |
| ATO1 | **Account takeover** - established account: login from a new device in a new country, then a withdrawal to a new wallet within 40 min | Account takeover | Caught | FR-2608-04 (P2) |
| ATO2 | **Account-takeover campaign (3 victims)** - one attacker device, IP and payout wallet used against three unrelated accounts on three nights | Account takeover | Caught | FR-2609-07 (P1) |
| S1 | **Account sharing** - account used alternately from Canada and Argentina on two devices, hours apart, for 10 days | Account sharing | Caught | FR-2607-04 (P3) |
| S2 | **Account sharing** - account used alternately from the UK and Thailand on two devices, hours apart, for 9 days | Account sharing | Caught | FR-2609-03 (P3) |
| A1 | **Deposit-and-withdraw (pass-through)** - 2-day-old account deposits 4,800 in BTC, plays 8 micro hands, withdraws ~99% in USDT 20 h later | AML: pass-through | Caught | FR-2608-01 (P2) |
| A2 | **Pass-through pair sharing a payout wallet** - two new accounts deposit in ETH/BTC, barely play, and withdraw USDT to the same wallet | AML: pass-through + Multi-accounting | Caught | FR-2609-06 (P1) |
| ST1 | **Structuring under the 2,000 threshold** - five deposits of 1,900-1,990 in six days from two wallets | AML: structuring | Caught | FR-2607-03 (P2) |
| ST2 | **Structuring under the 2,000 threshold** - four deposits of 1,850-1,995 in a week | AML: structuring | Caught | FR-2609-01 (P2) |

## Innocent look-alikes

| ID | What was planted | Expected | Result | Case |
|---|---|---|---|---|
| B1 | **Household sharing wifi** - two people in one home: same IP, own devices and wallets, never at the same table | No case; weak IP link on the watchlist | Correctly not flagged (watchlist only) | - |
| B2 | **Mobile-carrier gateway IP** - 29 unrelated players whose phones share one carrier-grade NAT address | Shared value ignored by the linking rule | Correctly ignored | - |
| B3 | **Exchange hot wallet used by many players** - 20 unrelated players withdraw to the same labelled exchange address | Shared value ignored by the linking rule | Correctly ignored | - |
| B4 | **Traveller withdrawing to own wallet** - on holiday in Spain with a new tablet; withdraws to the wallet they always use | No 'Account takeover' flag | Correctly not flagged | - |
| B5 | **Two regulars who share tables** - high-volume players at the same stake who often sit together but contest pots normally | No 'Collusion / soft-play' flag | Correctly not flagged | - |
| B6 | **High roller: big deposit, big play, fast cash-out** - deposits 6,000 and withdraws 5,500 two days later - but plays ~360 hands in between | No 'AML: pass-through' flag | Correctly not flagged | - |
| B7 | **Weak player repeatedly losing to a strong one** - heads-up games where the weaker player loses most pots - but at showdown, not by folding big bets | No 'Chip dumping' flag | Correctly not flagged | - |
| B8 | **Traveller with new phone and new wallet** - buys a phone in Mexico and withdraws to a new wallet - looks exactly like a takeover until a human checks | Account takeover flag that a human must clear | Flagged - expected false positive for an analyst to clear | FR-2609-04 (P2) |

## Cases nobody planted

These came out of the random 'normal' population. They are treated like any other lead: an analyst works through the verification steps in the case list.

| Case | Priority | Signals | Summary |
|---|---|---|---|
| FR-2607-01 | P3 | Account takeover | P00841: first login from a new device in MX, then 333 USDT withdrawn to a never-used wallet 16 hours later. |
