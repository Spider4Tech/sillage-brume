# `SBOX6` — linear, differential and boomerang analysis

Recorded on 2026-11-08. Companion to [`README.md`](README.md). All S-box and
trail numbers below are produced by [`analyse_sbox6.py`](analyse_sbox6.py);
the reduced-round boomerang numbers come from `tests/c/brume_attaques`
(run through [`tester_brume_attaques.sh`](tester_brume_attaques.sh) for
`SBOX6`, and from the unmodified binary for the current BRUME S-box).

This is a prototype analysis, not a change to `sillage/` or to the existing
tests. The reduced-round results are distinguishers on a few rounds, not
attacks on the 32-round permutation.

## 1. Summary

`SBOX6 = RECTANGLE(x) XOR 6` reaches the requested target, **BCT max = 6**
(the minimum for a 4-bit permutation with DU 4). A trail-level analysis
shows that this is **not a uniform security improvement**:

| Indicator (14 rounds unless stated) | BRUME | `SBOX6` | Effect |
|---|---:|---:|---|
| BCT max | 10 | **6** | better |
| DBCT max (two consecutive S-boxes) | 52 | **32** | better |
| MEDP2 (2-round hull bound) | 2^-14.99 | **2^-15.97** | better by ~1 bit |
| Best differential trail | 2^-2830 | **2^-2600** | **weaker by 230 bits** |
| Best linear trail | 2^-1417 | 2^-1421 | essentially unchanged |
| Boomerang-switch trail (single trail) | 2^-2776 | **2^-2486** | **weaker by 290 bits** |
| 3-round boomerang, 2^22 quartets, 16 comb. | z = 27.6 | z = 10.5 | weaker but still present |

The reason is structural, not a matter of one coefficient. BRUME's BCT has
a few high rows (max 8 and 10) but also rows whose best entry is only 2;
`SBOX6` is **flat at 6 for every input difference**. A trail search can
exploit a flat profile, and a lower maximum does not compensate. The same
effect appears in the DDT: BRUME has three input differences with maximum
DDT 2, while `SBOX6` has a DDT-4 output for every input difference.

The best `SBOX6` differential trail uses 1300 active S-boxes, **all at
DDT 4**. The best BRUME trail uses 1306 active S-boxes, of which 218 are
forced through DDT 2. This is the direct cause of the 230-bit gap.

## 2. Conventions and method

- `DDT[a][b] = #{x : S(x) ^ S(x^a) = b}`.
- `LAT[a][b] = sum_x (-1)^(a.S(x) ^ b.x)`. The maximum is 8 and the
  non-linearity is `NL = (16 - 8)/2 = 4`.
- `BCT[a][b] = #{x : S^-1(S(x)^b) ^ S^-1(S(x^a)^b) = a}`.
- `LBCT`, `UBCT`, `EBCT`, `FBCT`, `DBCT`: definitions of Garg, Hasan,
  Riera and Stanica (DCC 2025); `BCT` follows Cid et al. (EUROCRYPT 2018).
- `DLCT` uses the repository convention,
  `DLCT[a][b] = sum_x (-1)^(b.(S(x)^S(x^a)))`; its non-trivial maximum is
  8 for a 4-bit permutation (Parseval).
- Trail costs are in **half-bits**: a differential trail of cost `c` has
  probability `2^(-c/2)`, and a linear trail has correlation `2^(-c/2)`.
- The trail engine is the one of `tests/banc_trails.py`: greedy choice of
  the output difference (resp. mask) at each active S-box, independently
  per position. Weight-1 sources are exhaustive, weight-3 sources are
  sampled (50,000), and weight-2 sources are exhaustive only up to 8
  rounds. The weight-2 sweep does not improve the best costs up to that
  horizon, so the 14-round table uses weight 1 and weight 3.
- These are **valid characteristics** (each one is a concrete trail), but
  they are not a proof that no better trail exists. The repository uses
  the same convention and calls them "best trails in the greedy space".

## 3. Exact S-box tables

### 3.1 Global histograms are identical

| Table | BRUME | `SBOX6` |
|---|---|---|
| DDT (225 non-trivial entries) | `0:135, 2:90, 4:15` | `0:135, 2:90, 4:15` |
| LAT (255 non-trivial entries) | `0:105, 4:120, 8:30` | `0:105, 4:120, 8:30` |
| BCT (225 non-trivial entries) | `0:105, 2:78, 4:28, 6:11, 8:2, 10:1` | `0:120, 2:60, 4:15, 6:30` |

The usual differential and linear histograms are unchanged. Only the BCT
distribution changes, and it changes in both directions: fewer 0 and 2,
more 6, no 8 or 10. The mean BCT is 1.60 for both.

### 3.2 The row structure is what differs

DDT rows, grouped by their profile over the 16 output differences:

| DDT row profile | BRUME | `SBOX6` |
|---|---:|---:|
| `{0:8, 2:8}` — no output at DDT 4 | 3 rows (`a = 1, 2, 9`) | 0 |
| `{0:9, 2:6, 4:1}` — exactly one output at DDT 4 | 9 rows | 15 rows |
| `{0:10, 2:4, 4:2}` — two outputs at DDT 4 | 3 rows (`a = 8, 12, 14`) | 0 |

`SBOX6` is **uniform**: every non-zero input difference has exactly one
output difference at DDT 4. BRUME is not: three input differences never
reach DDT 4, and three reach it twice.

The BCT rows show the same phenomenon at the boomerang level:

| Maximum BCT on row `a` (`b != 0`) | 2 | 4 | 6 | 8 | 10 |
|---|---:|---:|---:|---:|---:|
| BRUME, number of rows | 3 | 3 | 6 | 2 | 1 |
| `SBOX6`, number of rows | 0 | 0 | 15 | 0 | 0 |

For BRUME, the best switch probability depends strongly on the input
difference: 2/16 for `a = 1, 2, 9`, up to 10/16 for `a = 8`. For `SBOX6`,
every input difference offers a 6/16 switch. The worst case is lower, but
the **best case is higher** for every row that was previously at 2 or 4.

The ratio between the BCT and the DDT on the same transition makes this
quantitative:

| Statistic over transitions with DDT > 0 | BRUME | `SBOX6` |
|---|---:|---:|
| mean `log2(BCT/DDT)` | 0.207 | **0.453** |
| max `log2(BCT/DDT)` | **2.322** | 1.585 |

The single worst switch is worse for BRUME, but the **average switch is
more than twice as expensive in bits for `SBOX6`**. In a trail with many
active S-boxes, the average dominates the product.

### 3.3 Refined boomerang tables

| Table, non-trivial maximum | BRUME | `SBOX6` |
|---|---:|---:|
| LBCT (`a,b,c != 0`) | 4 | 4 |
| UBCT (`a,b,c != 0`) | 4 | 4 |
| EBCT (all four indices non-zero) | 4 | 4 |
| FBCT (`a != b`, `ab != 0`) | 4 | 4 |
| DBCT (`a,d != 0`) | 52 | **32** |
| DLCT (repo convention, `a,b != 0`) | 8 | 8 |

The LBCT, UBCT, EBCT and FBCT spectra are essentially identical; the only
visible difference is a slight UBCT improvement (45 entries at 4 for BRUME
against 42 for `SBOX6`, with three more entries at 2). The **DBCT is the
one refined table that clearly improves**, which is consistent with the
lower BCT maximum: two consecutive S-boxes are better for `SBOX6`.

DBCT distribution over `a,d != 0`:

| DBCT | 0 | 4 | 8 | 12 | 16 | 20 | 24 | 28 | 32 | 48 | 52 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BRUME | 0 | 9 | 14 | 46 | 54 | 49 | 38 | 9 | 4 | 1 | 1 |
| `SBOX6` | 1 | 5 | 25 | 32 | 69 | 46 | 29 | 15 | 3 | 0 | 0 |

The mean DBCT is almost the same (17.49 against 17.07), but the tail is
shorter: BRUME has two entries above 40, `SBOX6` has none.

## 4. Differential trails

Best greedy differential trail, probability exponent in bits
(`cost/2`; lower is better for the attacker, i.e. worse for the designer):

| Rounds | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BRUME | 2 | 16 | 87 | 272 | 518 | 774 | 1040 | 1287 | 1545 | 1795 | 2059 | 2297 | 2571 | **2830** |
| `SBOX6` | 2 | 16 | 84 | 250 | 472 | 708 | 944 | 1182 | 1422 | 1656 | 1894 | 2134 | 2368 | **2600** |

Up to 2 rounds the two S-boxes are tied. From 3 rounds on, `SBOX6` is
strictly weaker. At 14 rounds the gap is 230 bits.

Best 14-round trail detail:

| | BRUME | `SBOX6` |
|---|---:|---:|
| Active S-boxes | 1306 | 1300 |
| S-boxes at DDT 4 | 1088 | **1300** |
| S-boxes at DDT 2 | **218** | 0 |
| Trail probability | 2^-2830 | **2^-2600** |

This is the row-profile effect measured directly: `SBOX6` can avoid every
DDT-2 transition, while BRUME cannot.

The 2-round **hull** bound (Park et al.) goes the other way:

| 2-round bound | BRUME | `SBOX6` |
|---|---:|---:|
| MEDP2 | 2^-14.99 | **2^-15.97** |
| MELP2 | 2^-15.00 | 2^-15.00 |

`MEDP2` is `max_u sum_v DP(u,v)^8`; it is a clustering bound, not a single
trail. `SBOX6` is slightly better because its DDT rows never contain two
entries at 4. This is the trade-off: fewer clusters at 2 rounds, but a
uniformly available DDT-4 transition for long greedy trails.

## 5. Linear trails

Best greedy linear trail, correlation exponent in bits:

| Rounds | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BRUME | 7 | 41 | 123 | 236 | 352 | 471 | 588 | 707 | 827 | 941 | 1058 | 1180 | 1300 | **1417** |
| `SBOX6` | 7 | 40 | 124 | 238 | 354 | 470 | 586 | 705 | 829 | 945 | 1063 | 1180 | 1302 | **1421** |

The two curves cross repeatedly and the 14-round values differ by 4 bits
(0.3 %). The best 14-round trails have 1417 (BRUME) and 1421 (`SBOX6`)
active S-boxes, all at `|LAT| = 4`. The linear resistance is essentially
unchanged; `SBOX6` is marginally worse at the final horizon.

The LAT row profiles are identical for both S-boxes (every row has two
entries at 8, eight at 4 and six at 0), which is why the linear trail
landscape is so close.

## 6. Boomerang trails

A single-trail boomerang model is used to evaluate the BCT at the trail
level. For a `2r`-round boomerang, write `E = E1 o E0` with
`E0 = E1 = r` full rounds. The upper trail uses the DDT on the `r` rounds
of `E0`. The switch is the first S-box layer of `E1`: its input difference
`delta` comes from the upper trail, and its output difference `beta` is
chosen by the BCT. The lower trail then uses the DDT on the remaining
`r - 1` rounds. The cost is
`cost(DDT upper) + cost(BCT switch) + cost(DDT lower)`; the model is
greedy and uses one trail, so it is a heuristic, not a full quartet count.

| Rounds | 2 | 4 | 6 | 8 | 10 | 12 | 14 |
|---|---:|---:|---:|---:|---:|---:|---:|
| BRUME | 9 | 247 | 726 | 1205 | 1719 | 2253 | **2776** |
| `SBOX6` | 9 | 211 | 625 | 1065 | 1531 | 2006 | **2486** |

The 2-round values are identical, then `SBOX6` becomes steadily weaker;
at 14 rounds the gap is 290 bits. The cause is the BCT row maximum being 6
everywhere: the greedy switch always finds a 6/16 transition, whereas
BRUME sometimes has to accept a 2/16 transition.

A second, more aggressive stress test evaluates **every** S-box layer with
the BCT (not a real boomerang, only a measure of how easy it is to stay on
high BCT entries):

| Model, 14 rounds | BRUME | `SBOX6` |
|---|---:|---:|
| BCT at every S-box layer | 2^-2028 | **2^-1302** |
| BCT only at the switch (table above) | 2^-2776 | **2^-2486** |

Both models point in the same direction: the flat BCT profile is easier to
follow than BRUME's spiky profile, despite the lower maximum.

## 7. Reduced-round boomerang experiment

The C test `tests/c/brume_attaques.c` runs `R` rounds forward and the
inverse of the same `R` rounds, with a middle difference
`delta = M * (one nibble)`, and counts, nibble by nibble, how often the
quartet returns. `z` is the maximum over the tested nibbles and
combinations; the threshold is Bonferroni-corrected for the number of
tests. The 3-round signal is the relevant one; there is no significant
signal at 4 rounds or beyond in these runs.

| Test | BRUME, z | `SBOX6`, z | Threshold |
|---|---:|---:|---:|
| 2^18 quartets, 16 combinations | **7.4** | 3.7 | 5.30 |
| 2^20 quartets, 16 combinations | **13.4** | 4.6 | 5.30 |
| 2^20 quartets, 32 combinations | **13.4** | 12.1 | 5.42 |
| 2^20 quartets, 64 combinations | **19.9** | 14.5 | 5.55 |
| 2^22 quartets, 16 combinations | **27.6** | 10.5 | 5.30 |

The `2^20`, 16-combination `SBOX6` value (z = 4.6) is **below** the
threshold, but it is not evidence that the signal is absent. When the same
16 combinations are run with 2^22 quartets, `SBOX6` gives z = 10.5, well
above the threshold; the 2^20 value is a small-sample fluctuation. The
honest reading is: **`SBOX6` has a real 3-round boomerang distinguisher,
weaker than BRUME's but not removed** (z = 10.5 against 27.6 at the same
sample size; z = 14.5 against 19.9 at 2^20/64).

At 3 rounds, the number of exact full-state returns is also lower for
`SBOX6` (0 against 9 at 2^22/16; 1 against 6 at 2^20/64), but the
nibble-level z is the more sensitive statistic.

## 8. Interpretation

1. **BCT max is a worst-case per-S-box indicator, not a trail indicator.**
   `SBOX6` improves the worst entry from 10 to 6 but makes the row maxima
   flat: every input difference has a 6/16 switch. BRUME has rows at 2, 4,
   6, 8 and 10. A trail search can choose the row; a flat 6 is not better
   than a mix of 2 and 10 when the trail has many active S-boxes.

2. **The DDT has the same issue.** `SBOX6` has a DDT-4 output for every
   input difference. BRUME has three input differences with maximum 2.
   The best 14-round `SBOX6` trail is therefore 230 bits more probable
   than the best BRUME trail found by the same engine.

3. **The positive results are real but narrower.** DBCT drops from 52 to
   32 (two consecutive S-boxes), and MEDP2 improves by about one bit.
   The LBCT, UBCT, EBCT and FBCT spectra are unchanged. So `SBOX6` is a
   trade-off, not a uniform improvement.

4. **The full 32-round bounds are unchanged.** The wide-trail argument
   uses DU = 4, max `|LAT| = 8` and branch number 8; all three are the same
   for `SBOX6`. The proved 32-round bounds (2^-256 differential, 2^-128
   linear) remain valid. What changes is the reduced-round trail
   distribution and the boomerang behaviour, not the generic bound.

5. **If a BCT-6 S-box is wanted, optimize the row profile too.** The
   search should score at least:
   - BCT max (target 6), and the BCT row-max distribution;
   - the mean `log2(BCT/DDT)`, not only the maximum;
   - the DDT row profile (keep some input differences at max 2, or at
     least avoid a DDT-4 output on every row);
   - the 14-round greedy differential trail cost;
   - the 14-round boomerang-switch trail cost;
   - the reduced-round `brume_attaques` z at 2^20 and 2^22 quartets.

   `SBOX6` is useful as a counterexample: reaching BCT 6 is necessary but
   not sufficient.

## 9. Reproduce

```bash
# Exact tables, row profiles, greedy differential/linear trails,
# boomerang-switch model, BCT-greedy stress test.
python3 prototypes/brume_sbox6/analyse_sbox6.py

# Optional: include the exhaustive weight-2 sweep up to 8 rounds
# (slower, does not change the reported best costs).
python3 prototypes/brume_sbox6/analyse_sbox6.py --w2 8

# Reduced-round boomerang test with SBOX6 in a temporary copy.
prototypes/brume_sbox6/tester_brume_attaques.sh 20 64
prototypes/brume_sbox6/tester_brume_attaques.sh 22 16

# The same test with the current BRUME S-box (from the repository root,
# in a temporary directory if you do not want to overwrite resultats/).
mkdir -p /tmp/brume_ref/resultats && cd /tmp/brume_ref
/home/hachille/dev/orion/tests/c/build/brume_attaques 20 64
```

`analyse_sbox6.py` writes `analyse_sbox6.json` next to the script. The
script imports `tests/banc_trails.py` and `sillage/brume512.py` read-only;
it does not modify the repository.

## 10. References

- C. Cid, T. Huang, T. Peyrin, Y. Sasaki, L. Song, *Boomerang Connectivity
  Table: A New Cryptanalysis Tool*, EUROCRYPT 2018.
- C. Boura, A. Canteaut, *On the Boomerang Uniformity of Cryptographic
  Sboxes*, IACR ToSC 2018(3).
- K. Garg, S. U. Hasan, C. Riera, P. Stanica, *The revised boomerang
  connectivity tables and their connection to the Difference Distribution
  Table*, Designs, Codes and Cryptography 93 (2025).
- S. Tian, C. Boura, L. Perrin, *Boomerang Uniformity of Popular S-box
  Constructions*, WCC 2019.
- Repository files: `tests/banc_trails.py`, `tests/banc_wide_trail.py`,
  `tests/test_hull.py`, `docs/PROOFS.md`.
