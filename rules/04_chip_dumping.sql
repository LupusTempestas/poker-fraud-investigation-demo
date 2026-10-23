/* =========================================================================
   RULE 4 - CHIP DUMPING: money flowing one way between two players
   -------------------------------------------------------------------------
   What it looks for
     A pair of players where, in pots only the two of them played, one
     side lost 500+ USDT over 5+ pots, got back no more than 15% of that,
     and lost mostly by FOLDING after putting in big amounts (15+ big blinds
     on average) rather than by losing at showdown.

   Why it matters in poker
     Chip dumping moves money between accounts by losing on purpose. It is
     used to launder money, to pass funds from multi-accounts or stolen
     accounts to one cash-out account, or to get around withdrawal limits.
     The losing account usually bets or calls big, then folds - a weak
     player loses at showdown; a dumper gives the pot away.

   How it works
     1. Find heads-up pots: hands where exactly two players put money in.
     2. In each, record who paid whom and whether the loser folded.
     3. Add it up per direction (A->B and B->A) and compare the two.
     4. Note whether the pair is linked (rule 1) and when the receiver
        next withdrew - dump-then-cash-out is a strong pattern.

   False-positive risk: a weak player who keeps losing to a strong regular.
   That is why the fold share and big-blind size are required, not just
   one-way money.
   ========================================================================= */

DROP TABLE IF EXISTS sig_chip_dumping;

CREATE TABLE sig_chip_dumping AS
WITH settings AS (
    SELECT 500  AS min_amount_usdt,
           5    AS min_pots,
           0.15 AS max_money_back_share,
           0.60 AS min_fold_share,
           15   AS min_avg_big_blinds
),
heads_up_pots AS (
    SELECT hand_id
    FROM hand_players
    WHERE vpip = 1 AND invested > 0
    GROUP BY hand_id
    HAVING COUNT(*) = 2
),
flows AS (
    SELECT h.hand_id, h.ts,
           loser.player_id                AS from_player,
           winner.player_id               AS to_player,
           -loser.net                     AS amount,
           loser.showdown                 AS loser_showdown,
           loser.invested / h.big_blind   AS loser_big_blinds
    FROM heads_up_pots hu
    JOIN hands h             ON h.hand_id = hu.hand_id
    JOIN hand_players loser  ON loser.hand_id  = hu.hand_id AND loser.net < 0
    JOIN hand_players winner ON winner.hand_id = hu.hand_id AND winner.net > 0
),
pair_totals AS (
    SELECT from_player, to_player,
           COUNT(*)                 AS pots,
           SUM(amount)              AS amount,
           AVG(1 - loser_showdown)  AS fold_share,
           AVG(loser_big_blinds)    AS avg_big_blinds,
           MIN(ts)                  AS first_pot_ts,
           MAX(ts)                  AS last_pot_ts
    FROM flows
    GROUP BY from_player, to_player
)
SELECT f.from_player,
       f.to_player,
       f.pots,
       ROUND(f.amount, 2)                 AS amount_usdt,
       ROUND(COALESCE(r.amount, 0), 2)    AS money_back_usdt,
       COALESCE(r.pots, 0)                AS pots_back,
       ROUND(f.fold_share, 2)             AS fold_share,
       ROUND(f.avg_big_blinds, 1)         AS avg_big_blinds,
       f.first_pot_ts,
       f.last_pot_ts,
       (SELECT GROUP_CONCAT(DISTINCT le.link_type) FROM link_evidence le
         WHERE le.player_a = MIN(f.from_player, f.to_player)
           AND le.player_b = MAX(f.from_player, f.to_player))          AS link_types,
       (SELECT t.ts FROM transactions t
         WHERE t.player_id = f.to_player AND t.type = 'withdrawal' AND t.ts >= f.last_pot_ts
         ORDER BY t.ts LIMIT 1)                                        AS receiver_next_withdrawal_ts,
       (SELECT t.amount_usdt FROM transactions t
         WHERE t.player_id = f.to_player AND t.type = 'withdrawal' AND t.ts >= f.last_pot_ts
         ORDER BY t.ts LIMIT 1)                                        AS receiver_next_withdrawal_usdt
FROM pair_totals f
LEFT JOIN pair_totals r ON r.from_player = f.to_player AND r.to_player = f.from_player
WHERE f.amount         >= (SELECT min_amount_usdt FROM settings)
  AND f.pots           >= (SELECT min_pots FROM settings)
  AND COALESCE(r.amount, 0) <= f.amount * (SELECT max_money_back_share FROM settings)
  AND f.fold_share     >= (SELECT min_fold_share FROM settings)
  AND f.avg_big_blinds >= (SELECT min_avg_big_blinds FROM settings)
ORDER BY f.amount DESC;
