/* =========================================================================
   RULE 5 - COLLUSION / SOFT-PLAY: players who sit together but avoid each other
   -------------------------------------------------------------------------
   What it looks for
     A pair of players who shared a table for 100+ hands, where that is at
     least 25% of the less active player's hands, and who played the same
     pot far less often than their normal habits predict (35% of the
     expected rate or less).

   Why it matters in poker
     Colluders share information about their cards and avoid taking money
     from each other ("soft-play"), so together they beat the rest of the
     table. The victims are the other, honest players - which is why sites
     refund them when collusion is confirmed.

   How it works
     1. For each player: hands played and how often they choose to play a
        hand (VPIP - "voluntarily put money in pot").
     2. For each pair: hands at the same table, and hands where both played.
     3. Expected "both played" = hands together x VPIP(A) x VPIP(B).
        Honest strangers land near 1.0x. Soft-players land far below.
     4. Add the pair's combined result in shared hands (won from others)
        and whether they are linked (rule 1).

   False-positive risk: two regulars who prefer the same tables sit together
   a lot - but they play pots against each other normally, so their ratio
   stays near 1.0. Sitting together alone is not evidence.
   ========================================================================= */

DROP TABLE IF EXISTS sig_collusion;

CREATE TABLE sig_collusion AS
WITH settings AS (
    SELECT 100  AS min_hands_together,
           0.25 AS min_share_of_hands,
           0.35 AS max_contest_ratio
),
player_stats AS (
    SELECT player_id, COUNT(*) AS hands, AVG(vpip) AS vpip_rate
    FROM hand_players
    GROUP BY player_id
),
pairs AS (
    SELECT a.player_id          AS player_a,
           b.player_id          AS player_b,
           COUNT(*)             AS hands_together,
           SUM(a.vpip * b.vpip) AS both_played,
           SUM(a.net + b.net)   AS pair_net,
           MIN(h.ts)            AS first_hand_ts,
           MAX(h.ts)            AS last_hand_ts
    FROM hand_players a
    JOIN hand_players b ON b.hand_id = a.hand_id AND a.player_id < b.player_id
    JOIN hands h        ON h.hand_id = a.hand_id
    GROUP BY a.player_id, b.player_id
    HAVING COUNT(*) >= (SELECT min_hands_together FROM settings)
),
scored AS (
    SELECT p.*,
           1.0 * p.hands_together / MIN(sa.hands, sb.hands)  AS share_of_hands,
           p.hands_together * sa.vpip_rate * sb.vpip_rate     AS both_played_expected
    FROM pairs p
    JOIN player_stats sa ON sa.player_id = p.player_a
    JOIN player_stats sb ON sb.player_id = p.player_b
)
SELECT player_a,
       player_b,
       hands_together,
       ROUND(share_of_hands, 2)                       AS share_of_hands,
       both_played,
       ROUND(both_played_expected, 1)                 AS both_played_expected,
       ROUND(both_played / both_played_expected, 2)   AS contest_ratio,
       ROUND(pair_net, 2)                             AS pair_net_usdt,
       first_hand_ts,
       last_hand_ts,
       (SELECT GROUP_CONCAT(DISTINCT le.link_type) FROM link_evidence le
         WHERE le.player_a = scored.player_a AND le.player_b = scored.player_b) AS link_types
FROM scored
WHERE share_of_hands >= (SELECT min_share_of_hands FROM settings)
  AND both_played / both_played_expected <= (SELECT max_contest_ratio FROM settings)
ORDER BY contest_ratio;
