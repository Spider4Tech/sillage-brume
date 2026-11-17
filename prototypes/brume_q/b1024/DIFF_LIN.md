# Study: differential-linear distinguishers (BRUME-1024q)

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

## Results

(To be filled in after the measurements.)
