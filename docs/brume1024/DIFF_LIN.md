# Study: differential-linear distinguishers (BRUME-1024q)

> **v0.6 (17 November 2026).** This document now lives in `docs/brume1024/`. BRUME-1024q is the permutation of the suite: its code is `sillage/c/brume1024.c` and its checks are in the battery (`tests/c/brume1024.c`, `tests/c/brume1024_api.c`, `tests/test_b1024_*.py`). File names cited below without a path are documents of this folder (`*.md`) or tools of `prototypes/brume_q/b1024/` (programs, scripts, `dp1024/`, `gpu/`, `cm26_verif/`, …); `brume1024.c` meant the prototype, whose code is now the library.

Written on 17 November 2026, before the measurements (ROADMAP § 3, "Differential-linear at scale"). The criteria below
are fixed **before** the results. Nothing in the permutation changes; this is analysis only.

## Question

How many rounds does a differential-linear (DL) distinguisher reach, in the usual model and on the real permutation?

## The model and its bound (computed while writing this plan)

A DL distinguisher splits r rounds as E1 ∘ S ∘ E0: a differential of probability p over r0 rounds, one middle S-box layer
crossed through the DLCT, and a linear approximation of correlation q over r1 = r − 1 − r0 rounds. Its correlation is
about ε = p · c · q², with |c| ≤ 1 (Langford–Hellman, Bar-On et al. 2019). It needs about ε^{−2} pairs.

With the certified minimum numbers of active S-boxes A(t) over t rounds (B = 8 for two rounds, C3 ≥ 21, C4 ≥ 28, and
their sums; the same bounds hold for differential and linear trails), a characteristic has p ≤ 2^{−2A(r0)} and a trail
|q| ≤ 2^{−A(r1)} (S-box: probability 2^{−2}, correlation 2^{−1}). Taking A(0 … 10) = 0, 1, 8, 21, 28, 29, 42, 49, 56, 63, 70:

| r | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|
| best log₂ ε of the model | −4 | −18 | −32 | −58 | −60 | −74 | −100 | −114 |
| pairs needed | 2^8 | 2^36 | 2^64 | 2^116 | 2^120 | 2^148 | 2^200 | 2^228 |

So in this model **the DL reach is 7 rounds within 2^128 pairs and 8 rounds within 2^192**. This is a bound on the
characteristic-based estimate only. It ignores clustering in both parts, a middle of more than one round (the
"sandwich" of Bar-On et al.), and the dependency between E0 and E1. That is why the real permutation is measured.

## What is measured (`dl_verif.c`)

- Pairs (x, x ⊕ Δ) with Δ on one input nibble v and a **fixed** value δ (a DL correlation is for a fixed difference),
  x uniform; after r rounds, for each of the 256 output nibbles, the 16-bin histogram of the output difference. From it,
  the correlation of each of the 15 non-zero masks μ on that nibble: ε = E[(−1)^{μ·Δy}]. That is 3 840 cells per (v, δ).
- The grid. r = 4 (witness: the 32 nibbles outside the radius-4 ball have zero difference, so ε = 1 for every mask; the
  detector must flag exactly them), r = 5 and r = 6. 16 input nibbles spread over the state × the 15 values of δ, 2^28
  pairs each at r = 5 and 6 (noise 2^{−14} per cell). At r = 4, 2^24 pairs.
- Significance: Bonferroni over all cells of a run (α = 10^{−3}). Every significant cell is re-measured with a new seed
  and 4 times more pairs before it counts.
- Checks before the grid: the kernel (perm1) is compared with the reference round function; a planted bias (one output
  bit forced to the input bit) is detected; at r = 4 the 32 zero nibbles are found and nothing else.

## Alarm criterion

A confirmed significant cell at **r ≥ 5** (the model's best is 2^{−32} at r = 5, about 2^{18} below the detection
limit of 2^{−14}): any such cell would mean the model is wrong by a large factor. Otherwise, the result is recorded as:
the model reach (7 rounds at 2^128 pairs, 8 at 2^192), with the measured upper bound of |ε| at r = 5 and 6.

## Limits, stated in advance

- Only one-nibble differences and one-nibble masks are measured: the shapes that the diffusion favours, not all shapes.
- The measurement can only see |ε| ≥ about 2^{−12}. Below that, the model is the only argument.
- The model bound is heuristic (characteristic-based, Markov); it is not a proof of DL resistance.

## Results (17 November 2026)

> **18 November 2026.** The reading of the gap below and its reach table are superseded by § "Edge of diffusion" at the
> end: the gap is explained, the Markov assumption holds there, and 5 rounds are distinguished at 2^{−7.06} with a dense mask.

HyperCompute job 377b5a00 (33 units: 32 for r = 5 and 6, one for the checks), one thread per unit, 35 to 60 minutes
per unit on the three machines; every unit ended with code 0. Outputs: `resultats/hypercompute/diff-lin/`.

**r = 5 and r = 6: nothing.** 32 runs (r = 5 and 6 × 16 input nibbles), each 15 values of δ × 3 840 cells = 921 600
cells at 2^28 pairs (noise 2^{−14.0}), 29.5 million cells in all. Bonferroni threshold per run |z| = 6.10. No cell
crosses it: the largest |z| is 4.68 at r = 5 and 4.71 at r = 6, what the maximum of about a million roughly independent
normal variables gives. No nibble keeps a zero difference at r = 5 (full diffusion). So, for one-nibble input
differences and one-nibble output masks, **|ε| < 2^{−11.4} at r = 5 and 6** (6.1 × the noise). No cell needed the
re-measurement step. **The alarm criterion is not met.**

**Checks.** At r = 4 (2^24 pairs, 4 input nibbles × 15 δ), the 32 nibbles outside the radius-4 ball are found in every
configuration (1 920 = 60 × 32 nibbles, ε = 1 for all 15 masks). The planted bias at r = 5 is found (30 cells,
ε = 0.501). **One check did not come out as written:** at r = 4 the detector also flags 3 997 other cells, not "nothing
else". They are real: the cells kept in the output have |ε| between 2^{−9} and 2^{−7} (z up to 38), on output nibbles at
the edge of the radius-4 ball, which the input difference reaches through few paths. The same was seen on the first
check run (233 such cells at 2^24 pairs with fewer inputs), noted then in the ROADMAP row but not in this plan.

**What this says about the model.** At r = 4 the model of § "The model and its bound" gives at best 2^{−18}; the
measurement gives 2^{−7}, a factor of about 2^{11}. The model counts the active S-boxes of the whole state, while a
one-nibble mask at the edge of the diffusion only sees the few S-boxes on the paths that reach it; this is the
clustering the plan lists as ignored. So the model is **not** a bound, as § "Limits" already said, and here it is
off by 2^{11} at r = 4. At r = 5 and 6 every nibble is reached through many paths and nothing is measurable, so the
gap there is unknown. Two readings of the reach:

| Reading | r = 7 | r = 8 | r = 9 | Reach within 2^128 pairs | within 2^192 |
|---|---|---|---|---|---|
| model as planned | 2^{−60} | 2^{−74} | 2^{−100} | 7 | 8 |
| model × 2^{11} (the r = 4 gap carried to every r) | 2^{−49} | 2^{−63} | 2^{−89} | 8 | 9 |

The second reading is a pessimistic guess, not a measurement. Both leave 23 rounds or more of margin at 32 rounds.
Recorded result: **DL reach 7 to 8 rounds within 2^128 pairs, 8 to 9 within 2^192; measured |ε| < 2^{−11.4} at
r = 5 and 6.**

## Edge of diffusion: why the model and the measurement differ (18 November 2026)

**Question.** At r = 4 the model of § "The model and its bound" gives at best 2^{−18}, and the measurement 2^{−6.6}. Either
the Markov assumption fails at the edge of the diffusion, and then every probability of the suite derived from it is in
doubt, or the model misuses the active S-box counts. Tools: `dl_bord.c` (measurement, two modes) and `bord_diffusion.py`
(computations); numbers in `resultats/dl_bord.json`.

### 1. The Markov assumption holds there (measured)

`dl_bord.c` runs the measurement of `dl_verif.c` twice: on the permutation (fixed constants), and with round constants
drawn uniformly and independently for every pair and every round. In the second mode the sequence of differences is
exactly a Markov chain, so its correlations are the Markov prediction. Two inputs, (v, δ) = (0, 1) and (184, 14), the
second being the best one found in § 2, at 2^28 pairs each (noise 2^{−14}), on the 3 360 cells inside the radius-4 ball:

| Input | Cells | Mean z² of the difference between the two modes | Largest \|ε\|, fixed / Markov |
|---|---|---|---|
| (0, 1), edge (distance 4) | 1 455 | 1.006 (largest \|z\| 3.7) | 2^{−6.77} / 2^{−6.75} |
| (0, 1), inside (distance ≤ 3) | 1 905 | 1.009 (3.6) | 2^{−8.09} / 2^{−8.11} |
| (184, 14), edge | 1 455 | 0.998 (3.4) | 2^{−6.60} / 2^{−6.58} |
| (184, 14), inside | 1 905 | 1.040 (3.9) | 2^{−8.19} / 2^{−8.22} |

The difference is noise (a mean z² of 1 is what noise alone gives). The permutation behaves as its Markov model at the
edge, and its fixed constants play no measurable role.

### 2. What is wrong: the formula ε ≈ p · c · q² with p ≤ 2^{−2A(r0)} and q ≤ 2^{−A(r1)}

That formula prices a DL distinguisher as one differential characteristic, one DLCT layer and one linear trail, and
bounds each part by the certified active S-box counts. Under Markov the exact quantity is different. Write
W(μ) = E[(−1)^{μ·Δx}] for the Walsh transform of the difference distribution of one nibble. An S-box acts on it through
its squared correlation matrix, W′(λ) = Σ_μ W(μ) · c²(μ, λ), and a nibble whose difference is zero has W = 1 for every
mask. The formula is wrong in two places:

- **The differential part costs nothing.** A DL distinguisher needs no fixed middle difference: it sums over all of them,
  and their probabilities add up to 1. Bounding that part by one characteristic, 2^{−2A(r0)}, charges a cost that the
  distinguisher never pays.
- **In the linear part, only the S-boxes inside the ball of the input difference cost something.** A mask that meets a
  nibble with zero difference crosses it for free. The counts A(t) bound trails in which every active S-box is paid.
  At the edge, most of the S-boxes on the trail lie outside the ball: the ball holds 1, 7, 37, 127, 224 and 256 nibbles
  after 0 to 5 rounds. For an output nibble at distance 4, only the 2 to 6 nibbles of the last layer that lie inside the
  radius-3 ball, and the thin cone behind them, have a cost.

The counts A(t) themselves are not in question. They bound characteristics, and every characteristic still has at least
28 active S-boxes over 4 rounds. The correlation measured at the edge is the sum over a very large number of
characteristics that agree on the observed nibble: the aggregation that § "Limits, stated in advance" lists as ignored.

**Check of this reading.** Propagating W nibble by nibble, with the 7 inputs of a nibble taken as independent (a "mean
field"; `bord_diffusion.py`), gives a best correlation of 2^{−6.56} at r = 4 over all 3 840 inputs. At the input it
designates, (184, 14), the measured value is 2^{−6.60}, and over the edge cells the mean field correlates with the
measurement at 0.93 (0.88 at (0, 1)). Beyond 4 rounds the mean field is no longer usable. It falls to 2^{−34.6} at 5
rounds and 2^{−648} at 6, because it drops the correlations between nibbles, and those correlations then carry the
dominant terms.

### 3. Consequence: a distinguisher on 5 rounds at 2^{−7.06}

The reading predicts a distinguisher that the measurement of the plan could not see, since that measurement looked only
at one-nibble masks. Take the best edge cell at 4 rounds, (v, δ) = (184, 14) with output nibble w = 197. Choose the
output mask γ after 5 rounds so that γ · L(s) = β · s_w: then γ sees only S-box w of round 5. L is invertible; the
mask is found by Gaussian elimination and checked, and it is dense (241 nibbles out of 256). The correlation is then a
computation on one S-box from the 4-round measurement, ε5 = Σ_μ W4[w](μ) · c²(μ, β):

| Input | Predicted | Permutation, 2^28 / 2^30 pairs | Random constants, 2^28 / 2^30 |
|---|---|---|---|
| (184, 14), w = 197, β = 3 | 7.47·10^{−3} = 2^{−7.06} | 7.469 / 7.463·10^{−3} | 7.481 / 7.544·10^{−3} |
| (0, 1), w = 13, β = 6 | 6.42·10^{−3} = 2^{−7.28} | 6.480 / 6.401·10^{−3} | 6.255 / 6.463·10^{−3} |

The noise is 6.1·10^{−5} at 2^28 pairs and 3.1·10^{−5} at 2^30, and the measurements use seeds independent of the
4-round data the prediction comes from. So **5 rounds are distinguished with about 2^14 pairs**. The model said 2^{−32}
(2^64 pairs), and § "Results" recorded "nothing at r = 5"; that "nothing" holds only for one-nibble masks.

### 4. Corrected model and reach

The corrected model has two parts:
- **a prefix** of p ≤ 4 rounds, from a one-nibble difference to one output nibble, at the cost of the mean field: 2^{−1},
  2^{−1.68}, 2^{−2.48} and 2^{−6.56} for p = 1 to 4, the last one measured;
- **one linear characteristic** over the remaining r − p rounds, whose first S-box is the S-box of the prefix, squared,
  and priced by the certified counts.

So log₂ ε(r) ≈ max_p [e_p + 1.49 − 2A(r − p)]. The 1.49 bits are the gain of the junction measured at 5 rounds: one
S-box costs 0.51 bits there instead of 2, because several Walsh components add up. At r = 5 the formula gives the
measured value by construction. The junction gain is measured only for p = 4 and is applied to p = 3 as well.

| r | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|
| log₂ ε, corrected model | −7.1 (measured) | −21.1 | −47.1 | −59.0 | −63.1 | −89.1 | −103.1 | −117.1 |
| pairs | 2^14 | 2^42 | 2^94 | 2^118 | 2^126 | 2^178 | 2^206 | 2^234 |
| log₂ ε, model of the plan | −32 | −58 | −60 | −74 | −100 | −114 | | |

**Reach: 9 rounds within 2^128 pairs and 10 within 2^192**, instead of 7–8 and 8–9; **a margin of 22 rounds** at 32
rounds instead of 23. The model remains a heuristic of the same kind as the plan's:
- the suffix is one characteristic, with no aggregation of linear trails;
- the prefix is the best one-nibble shape;
- r = 9 rests on A(5) = 29 (C4 plus one S-box), a weak composed bound.

Unlike the plan's model, it now agrees with the measurement at 4 and 5 rounds.

### 5. What this says about the Markov model of the suite

Nothing against it:
- the real permutation follows the Markov chain at 4 and 5 rounds, to the noise;
- the certified bounds on characteristics (224 active S-boxes; 2^{−448} and 2^{−224} over 32 rounds) are unchanged,
  because they bound one characteristic, which is all they claim.

What has never followed from them (README, "Limits") is a bound on quantities that sum over characteristics:
differentials, hulls, and DL or truncated distinguishers. The edge of the diffusion is where this matters most. In the
first four rounds the ball of the difference is not full, and the S-boxes outside it cost nothing. Any estimate that
charges A(t) over those rounds is too optimistic, by about the S-boxes that lie outside the ball. The other rows of
`NIVEAU3.md` § 4 do not price an aggregated quantity with A(t):
- the rebound path and collision item 1 are characteristic estimates;
- the truncated-differential row already counts the free diffusion to 4 rounds;
- the boomerang is measured.
