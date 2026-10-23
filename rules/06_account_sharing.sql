/* =========================================================================
   RULE 6 - ACCOUNT SHARING: one account, two people in two countries
   -------------------------------------------------------------------------
   What it looks for
     An account that switches back and forth between different devices in
     different countries within 3 hours of each other - at least 4 times.
     Nobody flies between countries that often, so two people are using it.

   Why it matters in poker
     A shared account can mean "ghosting" (a stronger player or coach
     playing for the owner), a bot operator, or an account sold or rented
     to someone who could not pass verification. It breaks the one-person-
     one-account rule and can hide a banned player.

   How it works
     1. Line up each account's logins in time order.
     2. Compare every login with the one before it (LAG): different device,
        different country, less than 3 hours apart = one "switch".
     3. Keep accounts with 4+ switches.

   False-positive risk: VPN users can appear to jump between countries -
   but a VPN does not change the device, which is why a device change is
   required too. Families sharing one account with permission still break
   most sites' terms, but the intent is different.
   ========================================================================= */

DROP TABLE IF EXISTS sig_account_sharing;

CREATE TABLE sig_account_sharing AS
WITH settings AS (
    SELECT 3 AS max_gap_hours,
           4 AS min_switches
),
ordered AS (
    SELECT player_id, ts, device_id, ip_country,
           LAG(ts)         OVER w AS prev_ts,
           LAG(device_id)  OVER w AS prev_device,
           LAG(ip_country) OVER w AS prev_country
    FROM logins
    WINDOW w AS (PARTITION BY player_id ORDER BY ts)
),
switches AS (
    SELECT *
    FROM ordered
    WHERE ip_country <> prev_country
      AND device_id  <> prev_device
      AND (julianday(ts) - julianday(prev_ts)) * 24 <= (SELECT max_gap_hours FROM settings)
)
SELECT s.player_id,
       COUNT(*)                                        AS switches,
       COUNT(DISTINCT date(s.ts))                      AS days_with_switches,
       ROUND(AVG((julianday(s.ts) - julianday(s.prev_ts)) * 24), 1) AS avg_gap_hours,
       p.country                                       AS home_country,
       (SELECT GROUP_CONCAT(DISTINCT x.ip_country) FROM switches x WHERE x.player_id = s.player_id) AS countries,
       (SELECT GROUP_CONCAT(DISTINCT x.device_id)  FROM switches x WHERE x.player_id = s.player_id) AS devices,
       MIN(s.ts)                                       AS first_switch_ts,
       MAX(s.ts)                                       AS last_switch_ts
FROM switches s
JOIN players p ON p.player_id = s.player_id
GROUP BY s.player_id
HAVING COUNT(*) >= (SELECT min_switches FROM settings)
ORDER BY switches DESC;
