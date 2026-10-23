/* =========================================================================
   RULE 7 - AML RED FLAGS: pass-through deposits and structuring
   -------------------------------------------------------------------------
   Two classic anti-money-laundering patterns. A flag here is not proof of
   laundering: it is a reason to escalate to the MLRO (Money Laundering
   Reporting Officer), who decides whether to file a suspicious activity
   report. Never tell the player why the account is under review
   ("tipping off" is an offence in most AML regimes).

   7a. PASS-THROUGH ("deposit, barely play, withdraw")
     What it looks for: a deposit of 1,000+ USDT where, within 72 hours,
     the account withdrew at least 80% of it while wagering less than 10%.
     Why it matters: the poker room is being used as a pipe to move money
     between wallets - often switching asset on the way (deposit BTC,
     withdraw USDT), which breaks the trail on the blockchain.

   7b. STRUCTURING ("smurfing")
     What it looks for: 3+ deposits within 7 days, each between 90% and
     100% of a 2,000 USDT review threshold (1,800 - 1,999.99).
     Why it matters: splitting money into amounts just under a threshold
     avoids the checks that a single large deposit would trigger. The 2,000
     figure is illustrative; it mirrors the EU rule that gambling operators
     run customer due diligence at EUR 2,000, counting linked transactions
     together - exactly so that splitting does not work.

   False-positive risks: a player who deposits by mistake and withdraws
   (usually small amounts); an exchange's daily withdrawal limit that
   happens to sit just under 2,000 (check before escalating).
   ========================================================================= */

DROP TABLE IF EXISTS sig_aml_pass_through;
DROP TABLE IF EXISTS sig_aml_structuring;

CREATE TABLE sig_aml_pass_through AS
WITH settings AS (
    SELECT 1000 AS min_deposit_usdt,
           72   AS window_hours,
           0.10 AS max_wagered_share,
           0.80 AS min_withdrawn_share
),
big_deposits AS (
    SELECT t.*,
           datetime(t.ts, '+' || (SELECT window_hours FROM settings) || ' hours') AS window_end
    FROM transactions t
    WHERE t.type = 'deposit'
      AND t.amount_usdt >= (SELECT min_deposit_usdt FROM settings)
),
activity AS (
    SELECT d.player_id, d.tx_id, d.ts AS deposit_ts, d.amount_usdt AS deposit_usdt,
           d.asset AS deposit_asset, d.wallet_address AS deposit_wallet,
           (SELECT COUNT(*) FROM hand_players hp JOIN hands h ON h.hand_id = hp.hand_id
             WHERE hp.player_id = d.player_id AND h.ts BETWEEN d.ts AND d.window_end)                AS hands_played,
           (SELECT COALESCE(SUM(hp.invested), 0) FROM hand_players hp JOIN hands h ON h.hand_id = hp.hand_id
             WHERE hp.player_id = d.player_id AND h.ts BETWEEN d.ts AND d.window_end)                AS wagered_usdt,
           (SELECT COALESCE(SUM(w.amount_usdt), 0) FROM transactions w
             WHERE w.player_id = d.player_id AND w.type = 'withdrawal'
               AND w.ts BETWEEN d.ts AND d.window_end)                                            AS withdrawn_usdt,
           (SELECT MIN(w.ts) FROM transactions w
             WHERE w.player_id = d.player_id AND w.type = 'withdrawal'
               AND w.ts BETWEEN d.ts AND d.window_end)                                            AS withdrawal_ts,
           (SELECT GROUP_CONCAT(DISTINCT w.wallet_address) FROM transactions w
             WHERE w.player_id = d.player_id AND w.type = 'withdrawal'
               AND w.ts BETWEEN d.ts AND d.window_end)                                            AS payout_wallets,
           (SELECT GROUP_CONCAT(DISTINCT w.asset) FROM transactions w
             WHERE w.player_id = d.player_id AND w.type = 'withdrawal'
               AND w.ts BETWEEN d.ts AND d.window_end)                                            AS payout_assets
    FROM big_deposits d
)
SELECT a.player_id, a.tx_id, a.deposit_ts, ROUND(a.deposit_usdt, 2) AS deposit_usdt, a.deposit_asset,
       a.deposit_wallet, a.hands_played, ROUND(a.wagered_usdt, 2) AS wagered_usdt,
       ROUND(a.withdrawn_usdt, 2) AS withdrawn_usdt, a.withdrawal_ts, a.payout_wallets, a.payout_assets,
       ROUND((julianday(a.withdrawal_ts) - julianday(a.deposit_ts)) * 24, 1) AS hours_to_withdrawal,
       CAST(julianday(a.deposit_ts) - julianday(p.signup_ts) AS INTEGER)  AS account_age_days,
       p.kyc_level
FROM activity a
JOIN players p ON p.player_id = a.player_id
WHERE a.withdrawn_usdt >= a.deposit_usdt * (SELECT min_withdrawn_share FROM settings)
  AND a.wagered_usdt   <= a.deposit_usdt * (SELECT max_wagered_share FROM settings)
ORDER BY a.deposit_ts;

CREATE TABLE sig_aml_structuring AS
WITH settings AS (
    SELECT 2000 AS review_threshold_usdt,
           0.90 AS near_threshold_share,
           7    AS window_days,
           3    AS min_deposits
),
near_threshold AS (
    SELECT t.*
    FROM transactions t
    WHERE t.type = 'deposit'
      AND t.amount_usdt >= (SELECT review_threshold_usdt * near_threshold_share FROM settings)
      AND t.amount_usdt <  (SELECT review_threshold_usdt FROM settings)
),
bursts AS (
    -- for each near-threshold deposit, gather the same player's near-threshold deposits in the next 7 days
    SELECT a.player_id,
           a.ts                              AS first_ts,
           MAX(b.ts)                         AS last_ts,
           COUNT(*)                          AS deposits,
           ROUND(SUM(b.amount_usdt), 2)      AS total_usdt,
           GROUP_CONCAT(CAST(ROUND(b.amount_usdt) AS INTEGER), ' / ') AS amounts,
           COUNT(DISTINCT b.wallet_address)  AS wallets
    FROM near_threshold a
    JOIN near_threshold b
      ON b.player_id = a.player_id
     AND b.ts BETWEEN a.ts AND datetime(a.ts, '+' || (SELECT window_days FROM settings) || ' days')
    GROUP BY a.player_id, a.tx_id
),
best AS (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY deposits DESC, total_usdt DESC) AS pick
    FROM bursts
    WHERE deposits >= (SELECT min_deposits FROM settings)
)
SELECT b.player_id, b.first_ts, b.last_ts, b.deposits, b.total_usdt, b.amounts, b.wallets,
       (SELECT review_threshold_usdt FROM settings) AS threshold_usdt,
       p.kyc_level
FROM best b
JOIN players p ON p.player_id = b.player_id
WHERE b.pick = 1
ORDER BY b.first_ts;
