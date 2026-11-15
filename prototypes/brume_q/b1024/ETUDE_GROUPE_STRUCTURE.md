# Study: clustering of trails, truncated differentials and hidden structure (BRUME-1024q)

Written on 15 November 2026, at the author's request, after the security summary (`README.md` § 5–6). Two open points:

1. **Clustering.** The differential and linear bounds are on characteristics, one trail at a time: at least 218
   active S-boxes over 32 rounds (C3 ≥ 21; 224 since C4 ≥ 28 was certified the same day). A differential (or a linear hull) is the sum of all the trails with the same
   ends. Until now this sum was computed exactly only at 2 rounds (`agregation2.c`: no aggregation at the maximum,
   factor ≤ 1.5).
2. **Structure the tools did not look for.** Truncated differentials beyond 2 rounds were not studied. The
   non-linear invariants searched were sums of functions of single nibbles only (`structure1024.py`).

The criteria below are fixed **before** the results. Nothing in the permutation changes; this is analysis only.

## A. Clustering at 3 and 4 rounds (`agregation34.c`)

**Question.** At the best ends known, how much larger is the exact differential probability (or hull correlation) than
its best trail? Does that factor grow with the number of rounds?

**Method.** Shape of the best trails found by `trails1024.py`: one active nibble at one end ([1, 7, 32] differential,
[31, 7, 1] linear). From that end, the tool sums **all** the trails to a fixed far end:
- R = 2, 3: every path (b, u₁) from the single nibble, about 1.7·10⁶ in differential and 10⁸ in linear; at 3 rounds the
  sum for a fixed end uses the kernel of the linear system "x₂ = L·y₁ is zero outside the support of the end", which
  leaves only a few paths;
- R = 4: the same kernel method at the last transition (the 36 middle nibbles are never enumerated);
- linear hulls carry their signs (round constants), rounds r0 … r0 + R − 1, several r0.

Then the best ends are found by branch and bound (exact top T per input) and improved by local search on the end.
Model: the usual Markov assumption (S-box inputs independent and uniform), under which `agregation2.c` was confirmed on
the real permutation at 2 rounds.

**Checks** (`agregation34 controle`, 10/10): 2-round best trails 2^−16 and 2^−8 as `agregation2`; 2-round sum equals
its formula; the linear layer equals the dense product (M and Mᵀ in binary); kernel sum equals the direct sum at 3
rounds (differential and linear); branch and bound equals exhaustive enumeration (top 5); a 2-round witness where the
factor exceeds 1 is detected.

**Alarm criterion.** At R ≤ 4, an exact differential or hull that beats its best trail by more than **2^4**, or a factor
that grows from 2 to 3 to 4 rounds by more than 2^2 per round. Otherwise: clustering negligible at the sizes that can be
computed exactly, and the characteristic bound stands as the working estimate (it remains a bound on trails, not a
proof on differentials).

**First results** (15 November, before the campaign): at the ends of the best known trails, the exact sum is **one
single trail** (factor 1) at 3 rounds (differential 2^−89, linear 2^−40) and at 4 rounds (differential 2^−321 in 531 s,
kernel ≤ 16 bits; linear 2^−142 in 427 s, kernel ≤ 4 bits; no path left untreated). Over two input nibbles at 3 rounds, the best
linear hull found has 2 trails, factor 1.008.

## B1. Truncated differentials beyond 2 rounds (`tronquees1024.py`, `tronquees_verif.c`)

**Question.** Is there a truncated differential (zeros on part of the output) better than random beyond the 4 rounds
that diffusion gives for free?

**Model** (CP-SAT, nibble level). The S-box keeps activity. A nibble after the linear layer is forced inactive with no
active input, and forced active with exactly one (non-zero coefficients). With two or more active inputs it may
**cancel**, at a cost of 4 bits. Proved redundancies: one active nibble per round, and B = 8 over two layers. Advantage =
4·(zero output nibbles) − cost, against 2^−4 per nibble for a random permutation. The cost is then recomputed exactly as
4 × the GF(16) rank of each round's cancellation system. Both directions: forward (M) and backward (M⁻¹, dense).

**Empirical scan** (real permutation, `perm1` at r rounds). Pairs (x, x ⊕ δ) with δ on one nibble, or on two adjacent
nibbles. For each of the 256 output nibbles, the frequency of a zero difference against 1/16, with a Bonferroni threshold
at α = 10⁻³. This catches effects the model cannot see: the DDT and the dependencies between rounds.

**Checks.** The model finds the safe balls 7, 37, 127, 224, 256 and the free 4-round distinguisher (32 zero nibbles,
advantage 128 bits), and its rank is checked on known cases. Scan witness at r = 4: 128 outputs always zero over 4 inputs,
z = 1 983. At r = 5 with 2^18 pairs, nothing over the threshold.

**Alarm criterion.** A truncated differential with positive advantage, cost ≤ 255 bits, at **6 rounds or more** in either
direction. Or a significant cell in the empirical scan at r ≥ 5.

## B2. Local quadratic invariants (`invariants_quad1024.c`)

**Question.** Is there a non-linear invariant of degree 2 whose monomials live in one nibble or on one edge of M's graph?
That is the natural family for a local linear layer: quadratic invariants of Todo–Leander–Sasaki and
Beierle–Canteaut–Leander, as in the attacks on Midori, Scream and iSCREAM. It extends the nibble-sum family excluded at
level 1.

**Method.** 14 848 unknowns: 1 024 linear, 1 536 within nibbles, 768 edges × 16. Each random state gives one equation
g(R_t(x)) ⊕ g(x) = ε_t that is linear in the coefficients. The kernel dimension is exact up to probability 2^−64. It is
computed for each of the 32 rounds, and for all of them at once.

**Checks.** Identity witness: kernel 14 848. Constants only: 14 784, which contains at least the 1 024 linear
functions. S-box only (M = I, RC = 0): 704. Real round 0: **0**.

**Alarm criterion.** Any non-zero kernel for a real round, or for all rounds at once.

## Results (15 November, 22 h 40; campaign still running)

Files: `resultats/hypercompute/etude-groupe-structure-{c,cpsat}/unit-*/out/`. Nothing below has triggered an alarm
criterion so far. Each line says what is exact, what is a search, and what is not finished.

### A. Clustering

| Rounds | Direction | Ends | Best trail | Exact sum | Largest factor | Status |
|---|---|---|---|---|---|---|
| 2 | diff | sweep: 256 nibbles × 15 values, top 256 ends | 2^−16 | 2^−16 | 1 | exact at each end |
| 2 | lin | same | 2^−8 | best hull found 2^−7.96 | 1.03 | exact at each end; the **search** for ends is heuristic: `agregation2.c`'s exhaustive maximum over the same shape is 2^−7.83 |
| 3 | diff | same | **2^−87** | 2^−87 (1 trail) | 1.25 (at 2^−88.68, trail 2^−89) | exact at each end |
| 3 | lin | same, rounds from r0 = 0, 12, 24 | 2^−40 | best hull 2^−39.91 (r0 = 12) | 1.25 (r0 = 0, at 2^−40.68, trail 2^−41) | exact at each end |
| 3 | diff, lin | ends of the `trails1024.py` characteristics, plus local search | 2^−89, 2^−40 | same (1 trail) | 1 | exact |
| 4 | diff | end of the best characteristic found (2^−321) | 2^−321 | 2^−321 (1 trail) | 1 | exact, kernel ≤ 16 bits, 327 s |
| 4 | lin | end of the best trail found (2^−142) | 2^−142 | 2^−142 (1 trail) | 1 | exact, kernel ≤ 4 bits, 169 s |
| 4 | diff, lin | ends of the "restricted" characteristics (2^−331, 2^−148) | | | | **not finished**: stopped at the 4-hour limit (larger kernels); a computing limit, not a result |

- **Correction.** The best 3-round differential characteristic is **87 bits**, not 89. `trails1024.py` (CP-SAT, 30 min)
  had stopped at 89 with a lower bound of 42. The 87-bit trail starts at nibble 144 with difference 1. It was re-checked
  by an independent exhaustive enumeration in numpy (`verif_chemin3.py`, reference module only): 87 bits from (144, 1),
  and 89 from (115, 12), the start of CP-SAT's characteristic. That characteristic was therefore optimal for its own start
  only. 87 is the best known value, for the shape with one active nibble at round 0; no bound is proved for the other
  shapes beyond the certified active-S-box counts. The certified bounds (B, C3 ≥ 21, C4 ≥ 28) are not affected.
- **Reading.** The largest factor seen is 1.25, against the alarm threshold 2^4. It does not grow from 2 to 3 to 4
  rounds (1.03 → 1.25 → 1). At the computable sizes, clustering is negligible.

### B1. Truncated differentials

- **CP-SAT, maximisation** (`cherche`, 2 h each). Backward at 2 and 3 rounds: best advantage **0, proved optimal**
  (M⁻¹ is dense: 2 active nibbles become 255 in one round). Forward at 5, 6 and 7 rounds: the only patterns found are free
  diffusion (advantage 0), and the solver's upper bound stayed near 890 bits. **Not a proof.** Checks 5/5.
- **CP-SAT, decision** (`decide`, added on 15 November): "is there a pattern with advantage ≥ 4 bits and cost ≤ 255?",
  with nibble 0 imposed as active at the input. This is without loss of generality, because the support of M is invariant
  under σ (i ↦ i + 1 in each half) and τ (i ↦ −i, halves swapped), a group that is transitive on the 256 nibbles; the tool
  checks this before using it. INFEASIBLE would prove absence in the model. Checks 7/7: at 2 rounds with budget 0,
  advantage 876 is feasible and 880 is INFEASIBLE, as the safe balls require; a support without the symmetry is refused.
  The checks were rerun on the worker (proxmox): 7/7. Campaign running at 5, 6 and 7 rounds (3 h 53 each).
- **Empirical scan** (real permutation). At 5 rounds from one nibble, 2^30 pairs for each of 64 inputs, 16 384 cells: the
  largest deviation is z = 4.39 (input 116, output 103, frequency 0.06253 against 0.0625), the Bonferroni threshold is
  5.42. No significant cell and no output that is always zero: **conforming**. A maximum near 4.3 is what 16 384 normal
  cells give by chance. At 5 rounds from two neighbouring nibbles (2^30 pairs × 64 inputs): largest |z| = 4.51 (a
  deficit, frequency 0.06247), conforming. At 7 rounds from one nibble (2^28 pairs × 64 inputs): largest z = 4.00,
  conforming. 6 rounds (one and two nibbles): running.

### B2. Local quadratic invariants

**No invariant of the family, for any round.** For each of the 32 rounds, the system has full rank 14 849 (14 848
coefficients plus ε), so the kernel is 0; for the 32 rounds at once, the kernel is also 0 (`inv_tous_32.json`, 3 min on
the local machine). The witnesses of the tool (identity 14 848, constants ≥ 1 024, S-box alone 704) show that it finds
invariants when they exist. Limit, as stated in advance: degree 3, and functions spanning more than one edge, are not
covered.

## Campaign

- Runs on HyperCompute, after C4 ≥ 28 (`--after` its phases 3 and 3b).
- Sources are frozen in `~/orion_calc/etude/src`: revision `f01fca2` plus the uncommitted lot of 15 November. The trail
  ends are in `entrees/`.
- C units (19): AVX2 machines only.
- CP-SAT units (6): any machine.
- Results go to `resultats/hypercompute/etude-*`. A summary will go into this file, `ROADMAP.md` and the Dossier.

## Limits, stated in advance

- **A** covers the shape with one active nibble at one end, and exact ends only up to 4 rounds. Wider shapes, and
  aggregation over 32 rounds, stay out of reach of exact computation. The extrapolation will be stated as such.
- **B1** uses the classical truncated model (cancellation probability 2^−4). The scan covers what can be measured
  (probabilities ≥ 2^−26 or so).
- **B2** excludes one family more. Absence in this family is not absence of every invariant: degree 3, or functions
  spanning more than one edge, are not covered.
