# Certified bound on active S-boxes over 3 rounds of BRUME-512 (C3)

Written on 12 November 2026. **Status: certificate checked by machine; the encoding and the checker are not reviewed by a
human.** Nothing in `sillage/` changes.

**Result.** Every differential characteristic and every linear trail over 3 consecutive rounds of BRUME-512 has at least
**21 active S-boxes** (C3 ≥ 21; first certified at 18, then at 21). Until now this was only a CP-SAT dual bound, with no certificate (`BestObjectiveBound`,
10 November). The value was not proved exactly before. The best feasible pattern of the relaxation has 30 active S-boxes,
[4, 21, 5], so 21 ≤ C3(relaxation) ≤ 30, and the true C3 of the permutation is at least the relaxation value.

## 1. What is proved, in three separate parts

The result is the conjunction of three statements, each checked on its own (as asked in review: correspondence with the
permutation, then a checkable infeasibility certificate):

| Part | Statement | How it is checked |
|---|---|---|
| (i) Model | Every real characteristic satisfies the relaxation below | Argument § 2, plus `c3_cnf verif` (§ 3) |
| (ii) Encoding | The CNF is satisfied by every pattern of the relaxation with ≤ 17 active S-boxes | Construction § 2.2, plus `c3_cnf verif` and `c3_cnf modele` |
| (iii) Infeasibility | The CNF is unsatisfiable | 361 cubes + 1 completeness proof, each an LRAT proof checked by `lrat_verif` (§ 4) |

### 2. The relaxation (model)

**The round.** A round of BRUME-512 is s ← M·S(s ⊕ RC_r) (`sillage/brume512.py`, `_permute_batch`). There is no other
linear layer. Round constants do not change differences or masks. So between two S-box layers there is exactly one
application of M (differences) or of the binary adjoint Mᵀ (masks: b_r = Mᵀ a_{r+1}).

**Variables.** x[t][v] = 1 if S-box v of round t is active, for t = 0, 1, 2 and v = 0…127, giving 384 variables.

**Constraints.** Each one is valid for every real characteristic:
- **(T) Truncation.** Let A = M (differential) or A = Mᵀ (linear, rounds numbered backwards). For an output v of A, let
  s = #{k ∈ supp(A[v]) : x[t][k] = 1}. Then s = 0 ⇒ x[t+1][v] = 0, and s = 1 ⇒ x[t+1][v] = 1 (one non-zero term times a non-zero
  coefficient). s ≥ 2 leaves the output free (cancellation in GF(16) is possible). For masks, the binary adjoint L_cᵀ of a
  non-zero multiplication is invertible, so the same activity rule holds.
- **(V) No empty layer.** S is bijective and A is invertible, so a non-zero characteristic has a non-zero difference in every
  round.
- **(F) Exact branch facts**, recomputed by exhaustive enumeration in `c3_cnf verif` for inputs of weight w ≤ 3:

  | w | wt x + wt(Mx) | wt x + wt(M⁻¹x) | wt x + wt(Mᵀx) | wt x + wt((Mᵀ)⁻¹x) |
  |---|---|---|---|---|
  | 1 | 8 | 112 | 8 | 111 |
  | 2 | 13 | 106 | 13 | 108 |
  | 3 | 17 | 104 | 17 | 103 |

  Since every pair with w_in + w_out ≤ 7 has min(w_in, w_out) ≤ 3, these values prove that the differential and linear branch
  numbers are both **exactly 8**: at least 8 by the table, and at most 8 because a single input reaches the 7 terms of its column.
  The facts are used as W_t = w ⇒ W_{t+1} ≥ min_A[w] − w, and W_{t+1} = w ⇒ W_t ≥ min_{A⁻¹}[w] − w.
- **(S) Symmetry.** The 128 left multiplications v ↦ h·v of D₁₂₈ are automorphisms of supp(M) and of supp(Mᵀ). This is checked
  for all 128 of them on both supports. They act transitively (h·0 = h). The constraints (F) only involve the layer weights. So
  any pattern can be mapped onto one where S-box 0 of round 0 is active, and we impose x[0][0] = 1.

**Correction to the CP-SAT model of the tie-break** (`prototypes/brume_sbox6/departage/certificat_tronque.py`). That model says
it is valid for linear trails but uses the facts of M⁻¹ (112, 99*, 99*) instead of those of (Mᵀ)⁻¹ (111, 108, 103). The
values marked * are capped in `resultats/branch_exact.json`. The w = 1 fact is therefore one too strong for masks. This does
not affect any bound below 103, so the 18 of 10 November is not affected. Here the linear model uses its own facts.

**Differential and linear give the same CNF.** At K = 18 or 21, every inverse fact (≥ 103) is capped at K, and the forward
facts of M and Mᵀ are equal (8, 13, 17). The supports are equal too, because supp(M) is symmetric. So the two CNFs are identical
apart from the comment line, which was checked with `cmp`. One proof covers both.

### 2.2 Encoding

- (T) as clauses: x[t+1][v] ⇒ ∨_{k ∈ supp} x[t][k], and for each k, x[t][k] ∧ ∧_{k′ ≠ k} ¬x[t][k′] ⇒ x[t+1][v].
- One clause per layer for (V).
- A totalizer per layer, capped at K, with clauses in both directions: o_k ⇔ "at least k ones", and o_K ⇔ "at least K".
- (F) as 3-literal clauses on these counters.
- The global counter is the merge of the layer counters, and its output o_K is forbidden.
- (S) is a unit clause.

Soundness of the encoding (part ii): set every auxiliary variable to its exact meaning, an exact count of ones in its interval.
Then every clause is satisfied by any pattern that satisfies the relaxation with at most K − 1 active S-boxes.

## 3. Checks of the model and of the encoding (`c3_cnf verif`)

All checks below pass, run on two machines with two compilations:

| Check | Result |
|---|---|
| Generated tables against `sl_brume_permute` (64 states) | identical |
| 7 terms per row, supp(M) = supp(Mᵀ) | yes |
| The 128 left multiplications are automorphisms of both supports, and transitive | yes |
| Exhaustive branch facts (table above) | B_diff = B_lin = 8, exact |
| **Real trails**: 20 000 random differential characteristics (output differences drawn among DDT > 0, then the real M over GF(16)) and 20 000 linear trails (input masks drawn among LAT ≠ 0, then the real binary adjoint), for 2, 3 and 4 rounds, mapped by the symmetry, evaluated against **every clause** of the CNF with exact auxiliaries | 0 violated clauses out of 120 000 trails |
| Satisfiable side (`c3_cnf modele`): at K = 31, CaDiCaL returns the pattern [4, 21, 5] = 30, checked directly against the relaxation (without the CNF), and against the CNF with exact auxiliaries | valid, 0 false clauses |

The last check rules out an encoding that would be unsatisfiable for a trivial reason: it accepts a pattern at 30 and
refuses everything at 17.

## 4. The proof

- **Solver.** CaDiCaL 1.7.3 (Ubuntu package, sha256 `7b73df0a6d9c…`), option `--lrat=true --binary=false`.
- **Splitting (`cubes.sh`).** A complete decision tree on the counters of layers 0 and 1. Leaf (a, b) means W₀ = a and W₁ = b,
  for a, b ∈ {0, …, K}, where K stands for "≥ K". That gives (K + 1)² leaves: 361 at K = 18 and 484 at K = 21.
- **Completeness of the splitting**, proved as well: the CNF ∧_leaves ¬cube is unsatisfiable, with a checked LRAT proof.
- **Checker (`lrat_verif.c`, about 240 lines).** It is written for this purpose and independent of the solver:
  - each lemma must follow by unit propagation on the clauses it cites, and on those only;
  - indices must increase, and a cited clause must exist and not be deleted;
  - RAT steps are refused;
  - the empty clause must be derived.

  Mutation tests: the intact proof is accepted, and 4 corrupted proofs are rejected (a hint removed, a literal changed, the
  empty clause removed, a clause removed from the CNF).

| Bound | Leaves | Proved and checked | Completeness | Total solver time | Hardest leaf | Proof volume |
|---|---|---|---|---|---|---|
| **C3 ≥ 18** | 361 | **361 / 361** | checked | 154 s (11 processes) | (6, 7): 40 s | 1.2 GB (3.7·10⁶ RUP lemmas) |
| **C3 ≥ 21** | 484 | **484 / 484**: 482 directly; (4, 9) and (6, 9) through 2 × 22 sub-cubes on W₂, plus their 4 completeness chains, all checked | checked | 5 212 s | (6, 10): 1 922 s | ≈ 10⁸ RUP lemmas in total |
| C3 ≥ 24 | 625 | running on a second machine (16 threads), not counted | checked | | | |

The proofs are deleted once checked (they total several GB). They are reproducible: same CNF, same solver, `cubes.sh`.

**Second checker (done on 12 November, evening).** Once its download was authorised, `lrat-check` from the drat-trim
repository (M. Heule, commit 2e3b2dc of 25 November 2024, compiled with `-std=gnu99 -DLONGTYPE`) was added to the scripts as
a **mandatory** second checker. It accepts the intact proofs and rejects a mutated one.
- **C3 ≥ 21 for BRUME-512** was then re-proved from scratch on the second machine: 484 / 484 leaves and the completeness
  proof, every proof accepted by both checkers. So the bound no longer rests on our checker alone.
- Not done: a check with the formally verified `cake_lpr` (CakeML).

**BRUME-1024** (`-DB1024`, `../b1024/README.md`), also with both checkers:
- C3 ≥ 18: 361 / 361;
- C3 ≥ 21: 484 / 484, of which 4 leaves through sub-cubes and one sub-cube through 128 fine cubes (`cubes_fins.sh`).

## 5. Reproduce

```bash
cc -O3 -march=native -fopenmp -I sillage/c -I tests/c prototypes/brume_q/sat/c3_cnf.c sillage/c/commun.c \
   sillage/c/brume512.c sillage/c/brume512_avx2.c -lm -o tests/c/build/c3_cnf
tests/c/build/c3_cnf verif 20000                       # (i), (ii)
prototypes/brume_q/sat/cubes.sh diff 3 21 11           # (iii): needs cadical in the PATH; work directory ~/orion_sat
prototypes/brume_q/sat/sous_cubes.sh diff 3 21 7 "4 9" "6 9"   # optional: split the hardest leaves by W2
# BRUME-1024: build c3_cnf with -DB1024 -I prototypes/brume_q/b1024, then C3BIN=tests/c/build/c3_cnf1024 PREFIXE=b1024 …
# cubes_fins.sh base.cnf dir "parent cube" "v1 … vk" jobs [part nparts]   # 2^k fine cubes, split across machines
```

## 6. What it gives, and what it does not

- **Consequence.** Over R consecutive rounds, at least 21·⌊R/3⌋ + (0, 1, 8)[R mod 3] active S-boxes. Each one has
  DP ≤ 2⁻² and |correlation| ≤ 2⁻¹. That is ≥ 218 at 32 rounds (against 128 with B alone), and ≥ 190 over 28 rounds.
- **Limit.** Like B, this bounds **characteristics** and trails, in the Markov model. It does not bound differentials or hulls
  (aggregation), which are only measured beyond 2 rounds (Proposition 12).
- **Limit.** It is a bound on the truncated relaxation. The true C3 of the permutation can be larger, never smaller.
