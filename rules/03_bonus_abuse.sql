/* =========================================================================
   RULE 3 - BONUS ABUSE: linked new accounts that take the bonus and run
   -------------------------------------------------------------------------
   What it looks for
     A cluster of linked accounts (from rule 1) where at least 3 members
     were opened within 14 days of each other, each claimed the welcome
     bonus, played fewer than 100 hands, and withdrew within 7 days of
     signing up.

   Why it matters in poker
     A welcome bonus is marketing money meant to buy a new long-term
     player. A "bonus farm" opens many accounts to collect it many times
     and leaves. On its own one quick cash-out is normal; a group of linked
     accounts doing exactly the same thing is not.

   How it works
     1. For each account: hands played, first withdrawal, welcome bonus.
     2. Keep "hit and run" accounts: bonus claimed, < 100 hands, cashed out
        within 7 days of signup.
     3. Group them by cluster (player_clusters, built by the Python step from
        rule 1's links) and keep clusters with 3+ such accounts opened within
        14 days of each other.
   ========================================================================= */

DROP TABLE IF EXISTS sig_bonus_abuse;

CREATE TABLE sig_bonus_abuse AS
WITH settings AS (
    SELECT 7   AS max_days_to_withdraw,
           100 AS max_hands_played,
           3   AS min_accounts_in_ring,
           14  AS max_signup_spread_days
),
play AS (
    SELECT player_id, COUNT(*) AS hands_played
    FROM hand_players
    GROUP BY player_id
),
withdrawals AS (
    SELECT player_id,
           MIN(ts)                           AS first_withdrawal_ts,
           ROUND(SUM(amount_usdt), 2)        AS withdrawn_usdt,
           GROUP_CONCAT(DISTINCT wallet_address) AS payout_wallets
    FROM transactions
    WHERE type = 'withdrawal'
    GROUP BY player_id
),
hit_and_run AS (
    SELECT p.player_id, c.cluster_id, p.signup_ts, p.email_domain, p.country,
           b.amount_usdt                     AS bonus_usdt,
           COALESCE(pl.hands_played, 0)      AS hands_played,
           ROUND(julianday(w.first_withdrawal_ts) - julianday(p.signup_ts), 1) AS days_to_withdraw,
           w.withdrawn_usdt,
           w.payout_wallets
    FROM players p
    JOIN bonuses b         ON b.player_id = p.player_id AND b.bonus_type = 'welcome'
    JOIN withdrawals w     ON w.player_id = p.player_id
    JOIN player_clusters c ON c.player_id = p.player_id
    LEFT JOIN play pl      ON pl.player_id = p.player_id
    WHERE julianday(w.first_withdrawal_ts) - julianday(p.signup_ts) <= (SELECT max_days_to_withdraw FROM settings)
      AND COALESCE(pl.hands_played, 0) < (SELECT max_hands_played FROM settings)
),
rings AS (
    SELECT cluster_id
    FROM hit_and_run
    GROUP BY cluster_id
    HAVING COUNT(*) >= (SELECT min_accounts_in_ring FROM settings)
       AND julianday(MAX(signup_ts)) - julianday(MIN(signup_ts)) <= (SELECT max_signup_spread_days FROM settings)
)
SELECT *
FROM hit_and_run
WHERE cluster_id IN (SELECT cluster_id FROM rings)
ORDER BY cluster_id, signup_ts;
