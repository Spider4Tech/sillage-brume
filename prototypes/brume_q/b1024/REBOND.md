# Study: rebound-type collision attacks on the reduced-round sponge (BRUME-1024q)

Written on 17 November 2026, before the search (ROADMAP § 3, "Rebound attacks"). The criteria below are fixed **before**
the results. Nothing in the permutation changes; this is analysis only.

## Question

For how many rounds R can an attacker find collisions of the BRUME-1024q sponge (and so of the hash and the tree) faster
than the generic bound, by a differential path that starts and ends in the rate, with the first rounds paid by the
freedom of the message?

## Attack model

- **Target.** A collision of the sponge on P_R (the first R rounds). Two messages whose block j differs, with the same
  chaining state before it. If P_R maps the difference to a difference **in the rate only** (capacity difference zero),
  block j + 1 cancels it, and the two states are equal from then on: a collision of every output (hash, XOF, tree
  leaf). The generic cost is 2^{c/2} = **2^192** (birthday on the capacity).
- **Differential path, at the nibble level.** The model of `tronquees1024.py` (ETUDE_GROUPE_STRUCTURE.md § B1): the
  S-box keeps activity; an output nibble of the linear layer with two or more active inputs may cancel, at a cost of
  4 bits; its cost is recomputed exactly as 4 × the GF(16) rank of each round's cancellation system. Two constraints
  are added: **no active capacity nibble at the input** (the attacker only controls the rate), and **no active capacity
  nibble at the output**.
- **The inbound phase: message modification.** The attacker chooses the values of the rate. The S-box transitions and
  cancellations of the first rounds depend on values he can set: in round 0, the values of the active nibbles
  themselves; in round 1, values that are affine in round-0 S-box outputs, among which the free rate nibbles. The
  model counts the cancellations of the first m rounds as **free**, for m = 0, 1 (see the amendment below).
- **Why not a classical rebound with the inbound in the middle.** A middle inbound fixes the full 1 024-bit state there.
  Going back to the input, the capacity of that state must equal the chaining value: a 384-bit condition, that is
  2^{−384}, above the generic bound. The freedom an attacker can use is the 640 bits of the rate, at the start of the
  permutation. This is why the inbound is placed in the first rounds.
- **Cost of the attack.** 2^{C_m(R)} pairs, where C_m(R) is the exact cost (rank) of the cancellations after the first
  m rounds. An attack beats the generic bound if C_m(R) < 192. **R_coll(m)** is the largest such R.

## Baseline, computed while writing this plan (free diffusion, no cancellation before the last layer)

A single active rate nibble diffuses freely (no cancellation) for R − 1 rounds; at the last linear layer, every capacity
nibble it reaches must cancel, at 4 bits each, which is possible only if it has two active inputs or more. Over the 160
possible starts, the best ones give: **R = 2: 3 capacity nibbles to cancel (start 57), 12 bits; R = 3: 23 (start
133), 92 bits; R = 4: 68 (start 29), 272 bits**, each with at least two active inputs. A difference stays entirely in
the rate for one round only (32 starts). So **R_coll ≥ 3 is expected**, at about 2^92 against 2^192. The search below
looks for better paths (cancellations earlier, to keep the activity away from the capacity), for R = 4 and beyond.

## What is computed

1. **CP-SAT, minimisation** of C_m(R) for R = 2 … 6 and m = 0, 1, 4 threads, 2 hours each (reported: the best path
   found, its exact cost by rank, and the solver's lower bound; OPTIMAL means proved in the model). The symmetry used in
   the B1 study (any nibble may be the active input) is **not** valid here, since the rate and the capacity break it.
2. **Checks of the tool** before the grid: the baseline above is reproduced (paths at R = 2 and 3 with costs ≤ 12 and ≤ 92); a path
   is refused if a capacity nibble is active at the input or output; the rank cost of every path found is recomputed
   independently of the solver.
3. **Measurement on the real permutation** (`rebond_verif.c`), on the paths found for R ≤ 3. The Markov model says
   that each forced cancellation costs 2^{−4}. Pairs following the input pattern are drawn, and the frequency with
   which a chosen group of output capacity nibbles has zero difference is compared with 2^{−4·(size of the group)},
   for groups of 1 to 5 nibbles (2^{−4} … 2^{−20}), with enough pairs for a ±10 % relative error. A witness with a
   group outside the active set must give frequency 1.
4. **Realisability over GF(16)** of every path reported (`realisable_tour`): each round's cancellation system must
   leave a non-zero kernel in which no active input and no active output is forced to zero. A path that fails is cut
   and the search resumed (lazy cuts).

**Amendment (17 November, after the first probes, before the grid).** A probe with free rounds and no realisability
check returned impossible paths (97 active nibbles cancelling down to 1 after round 0, which would need y = M⁻¹·e_j,
dense and touching the capacity). Hence: (a) the realisability check above; (b) for a free round, a restriction to at
most |active inputs| − 1 cancellations, sufficient for a non-zero kernel but not necessary, so the m = 1 result is an
upper bound on the attacker's cost, not an optimum; (c) **m = 2 is dropped**: making round 1 free needs control of the
round-1 values through the rate, which this nibble model cannot represent honestly. In round 0 the attacker sets the
S-box output differences directly (for any value x and wanted δ_out, δ_in = x ⊕ S⁻¹(S(x) ⊕ δ_out)), so m = 1 is exact
in that respect.

## Alarm criterion

**A collision path beating the generic bound at R ≥ 6** (C_m(R) < 192 for m = 0 or 1), or a measured cancellation
probability more than twice the 2^{−4} per nibble of the model. Otherwise, the result is R_coll, recorded with the
margin 32 − R_coll.

## Limits, stated in advance

- The nibble model ignores the DDT (transitions with probability 2^{−2} or 2^{−3} per S-box, here treated as free) and
  the dependencies between rounds; the measurement in point 3 covers what is measurable.
- Only collision paths through the rate are searched. Near-collisions, multi-block paths (several blocks, each moving
  the difference), and attacks on the keyed modes are not covered.
- Only round 0 is paid by the message. Controlling later rounds through the values (classical message modification,
  several blocks, larger structures) could buy more rounds; it is not modelled.

## Results

(To be filled in after the search.)
