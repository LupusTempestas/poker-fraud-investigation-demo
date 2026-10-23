/* =========================================================================
   RULE 1 - MULTI-ACCOUNTING: accounts that share a device, IP or wallet
   -------------------------------------------------------------------------
   What it looks for
     Two accounts that logged in from the same device, connected from the
     same IP address, or moved money through the same crypto wallet.

   Why it matters in poker
     One person running several accounts can sit at a table with several
     hands of cards (collusion), feed chips from one account to another
     (chip dumping) or claim a welcome bonus many times (bonus abuse).
     Most other rules get stronger when the accounts involved are linked.

   How it works
     1. List every (account, device), (account, IP) and (account, wallet).
     2. Match the list against itself: two different accounts with the
        same value make one "link".
     3. Ignore values shared by so many accounts that they say nothing about
        identity: IPs used by more than 10 accounts (mobile-carrier gateways,
        public wifi, VPN exits) and wallets labelled as exchange hot wallets.
        These are kept in excluded_shared_values so an analyst can see them.
     The Python step afterwards joins links into clusters ("connect the dots").

   Strength of evidence
     device or wallet = strong; IP alone = weak (households, shared flats).
   ========================================================================= */

DROP TABLE IF EXISTS excluded_shared_values;
DROP TABLE IF EXISTS link_evidence;

CREATE TABLE excluded_shared_values AS
WITH settings AS (SELECT 10 AS busy_ip_limit)
SELECT 'ip'                       AS value_type,
       ip                         AS shared_value,
       COUNT(DISTINCT player_id)  AS accounts,
       'IP shared by more than ' || (SELECT busy_ip_limit FROM settings)
           || ' accounts (mobile-carrier gateway, public wifi or VPN exit)' AS reason
FROM logins
GROUP BY ip
HAVING COUNT(DISTINCT player_id) > (SELECT busy_ip_limit FROM settings)
UNION ALL
SELECT 'wallet', k.wallet_address, COUNT(DISTINCT t.player_id), 'Labelled exchange wallet: ' || k.label
FROM known_wallets k
JOIN transactions t ON t.wallet_address = k.wallet_address
WHERE k.label_type = 'exchange'
GROUP BY k.wallet_address;

CREATE TABLE link_evidence AS
WITH identifiers AS (
    SELECT player_id, 'device' AS link_type, device_id AS shared_value FROM logins
    UNION
    SELECT player_id, 'ip', ip FROM logins
    UNION
    SELECT player_id, 'wallet', wallet_address FROM transactions
),
usable AS (
    SELECT * FROM identifiers
    WHERE shared_value NOT IN (SELECT shared_value FROM excluded_shared_values)
)
SELECT a.player_id AS player_a,
       b.player_id AS player_b,
       a.link_type,
       a.shared_value,
       CASE WHEN a.link_type = 'ip' THEN 'weak' ELSE 'strong' END AS strength
FROM usable a
JOIN usable b
  ON b.link_type    = a.link_type
 AND b.shared_value = a.shared_value
 AND a.player_id    < b.player_id
ORDER BY player_a, player_b;
