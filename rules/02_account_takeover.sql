/* =========================================================================
   RULE 2 - ACCOUNT TAKEOVER (ATO)
   -------------------------------------------------------------------------
   What it looks for
     On an established account: a login from a device AND a country this
     account has never used before, followed within 24 hours by a withdrawal
     to a wallet this account has never used before.

   Why it matters in poker
     Crypto withdrawals cannot be reversed. A criminal with stolen
     credentials (phishing, a leaked password reused from another site)
     logs in and empties the balance to their own wallet. The victim is a
     real customer, so speed matters more here than anywhere else.

   How it works
     1. Number each account's logins: first login ever, first time on this
        device, first time from this country.
     2. Keep logins that are a first on device AND country, on accounts at
        least 30 days old (new accounts have no "normal" to compare with) and
        not the account's very first login in the data.
     3. Keep withdrawals that are the first time the account used that wallet.
     4. Pair them up: suspicious login, then new-wallet withdrawal within 24 h.

   Each signal alone is common (people travel, buy phones, open exchange
   accounts). The combination, in that order and that fast, is not.

   Runs before clustering: the attacker's device, IP and wallet are not the
   account owner's, so the Python step does not treat them as multi-accounting.
   ========================================================================= */

DROP TABLE IF EXISTS sig_account_takeover;

CREATE TABLE sig_account_takeover AS
WITH settings AS (
    SELECT 30 AS min_account_age_days,
           24 AS max_hours_to_withdrawal
),
login_history AS (
    SELECT l.*,
           ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY ts)             AS login_number,
           ROW_NUMBER() OVER (PARTITION BY player_id, device_id ORDER BY ts)  AS device_use_number,
           ROW_NUMBER() OVER (PARTITION BY player_id, ip_country ORDER BY ts) AS country_use_number
    FROM logins l
),
suspicious_logins AS (
    SELECT h.player_id, h.ts AS login_ts, h.device_id, h.ip, h.ip_country, h.ip_type,
           p.country AS home_country, p.kyc_level,
           CAST(julianday(h.ts) - julianday(p.signup_ts) AS INTEGER) AS account_age_days
    FROM login_history h
    JOIN players p ON p.player_id = h.player_id
    WHERE h.login_number > 1
      AND h.device_use_number = 1
      AND h.country_use_number = 1
      AND julianday(h.ts) - julianday(p.signup_ts) >= (SELECT min_account_age_days FROM settings)
),
withdrawals_to_new_wallet AS (
    SELECT t.player_id, t.ts, t.amount_usdt, t.wallet_address
    FROM transactions t
    WHERE t.type = 'withdrawal'
      AND NOT EXISTS (SELECT 1 FROM transactions earlier
                      WHERE earlier.player_id = t.player_id
                        AND earlier.wallet_address = t.wallet_address
                        AND earlier.ts < t.ts)
)
SELECT s.*,
       w.ts             AS withdrawal_ts,
       w.amount_usdt,
       w.wallet_address,
       CAST(ROUND((julianday(w.ts) - julianday(s.login_ts)) * 24 * 60) AS INTEGER) AS minutes_to_withdrawal
FROM suspicious_logins s
JOIN withdrawals_to_new_wallet w
  ON w.player_id = s.player_id
 AND w.ts BETWEEN s.login_ts
              AND datetime(s.login_ts, '+' || (SELECT max_hours_to_withdrawal FROM settings) || ' hours')
ORDER BY s.login_ts;
