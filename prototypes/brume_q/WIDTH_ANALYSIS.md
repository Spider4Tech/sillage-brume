# BRUME-512q: is a 768- or 1024-bit permutation worth it?

> **Record of a decision, closed.** The answer was 1 024 bits: BRUME-1024q (`b1024/`). Since 13 November 2026 work focuses on
> BRUME-1024q only, and **BRUME-512q is abandoned**; its prototype was removed from the repository (`README.md`). The
> references below to `brume_q.c`, to the README of BRUME-512q and to `resultats/brume_q.*` are to that archived version.

Written on 12 November 2026, **revised the same day after an external review**. Status: analysis plus measurements; no new
permutation is proposed. Each figure is marked as one of three kinds:
- **proved**: a theorem, or a certificate checked by machine;
- **computed**: an exact computation, reproducible with the program cited;
- **measured**, or **modelled**.

What the revision changed:

| Point | Before | Now |
|---|---|---|
| "The quantum level depends on c, not on the width" | stated without qualification | **too strong.** True for the best known attacks. False for the proved bounds, which depend on min(r, c) (Alagic–Carolan–Majenz–Tokat 2025). § 1.1 |
| Lower bound of 18 active S-boxes over 3 rounds | CP-SAT dual bound, no certificate | **certified** (SAT, LRAT, encoding checked against the permutation), then **raised to 21** with a certificate: `sat/README.md`. § 4 |
| Validity of the CP-SAT model for linear trails | claimed | the w = 1 fact of the inverse was one too strong for masks (112 against 111). No effect on the bound. Corrected in the SAT model |
| Diffusion and λ* for 768 and 1024 | one program, checked on D₁₂₈ only | reproduced by a second program and other methods (§ 2.1). Generators and definitions are published |
| Degree | "22 rounds at 1024" | formula and hypotheses given. It is a guaranteed reach of the zero-sum distinguisher, not a security level (§ 2.2) |
| Speed of 1024 | model ×2.0–2.5 | **measured** kernel (§ 3) |
| 32 rounds | Markov model only | table per attack family (§ 4.2) |
| Boomerang | "P < 2^−34" | a statistical observation, at 95 % confidence (README § 4) |
| B = 8 | ambiguous | **exact**: the differential and linear branch numbers are both 8 (proved by exhaustive enumeration, `sat/README.md` § 2) |

## 1. The question, stated precisely

For a generic quantum collision cost of 2^128 on the capacity (BHT), c = 384. The width b = r + c then only changes the rate:

| Width | Nibbles | Rate at c = 384 | Rate / width | Rate per call vs 512 | min(r, c) |
|---|---|---|---|---|---|
| 512 | 128 | 128 bits | 25 % | ×1 | 128 |
| 768 | 192 | 384 bits | 50 % | ×3 | 384 |
| 1024 | 256 | 640 bits | 62.5 % | ×5 | 384 |

With c = 384, BRUME-512 spends 75 % of its state on the capacity. That is the structural problem.

### 1.1 Quantum security of the three widths, in one model

The adversary has quantum access to P and P⁻¹ (unkeyed modes: hashing, XOF, tree), with a 512-bit digest. Three distinct
questions are kept apart:
- (a) the best **known** generic attacks;
- (b) the **proved** bounds;
- (c) what (b) means for our parameters.

**(a) Best known generic attacks** (cost in quantum queries; identical for the three widths at c = 384):

| Attack | Cost | Depends on |
|---|---|---|
| Inner collision on the capacity, free quantum memory (BHT 1998) | 2^(c/3) = 2^128 | c |
| Inner collision, quantum memory counted (CNS 2017) | 2^(2c/5) = 2^153.6 | c |
| Collision on the 512-bit digest (BHT) | 2^170.7 | output length |
| Preimage of the 512-bit digest: inner meet-in-the-middle, i.e. an inner collision search | ≥ 2^128 | c |

No known generic attack gets cheaper when r is small, as long as the digest is long. Here it is 512 bits: several squeeze
blocks for BRUME-512q (r = 128), but **a single block truncated to 512 of 640 bits for BRUME-1024q** (r = 640). An attack does
depend on r if the output is one block of r bits: BHT on the output costs 2^(r/3), which is 2^42.7 at r = 128. That is why
the digest of BRUME-512q has 64 bytes.

**(b) Proved bounds.** Quantum indifferentiability of the sponge with a random **invertible** permutation was proved by
Alagic, Carolan, Majenz and Tokat (arXiv 2504.16887, 2025). The statements below are quoted from the paper. Theorem 7.22
itself, which Theorem 1.2 summarises, was not read in full.
- Theorem 1.2 (informal summary of Theorem 7.22), indifferentiability, q quantum queries, inputs of at most r·ℓ bits:
  **O(ℓ³·(q⁹·2^(−min(r,c)))^(1/4))**. The abstract calls it "a loose O(poly(q) 2^(−min(r,c)/4))".
- Theorem 1.1 (informal summary of Theorems 6.11 and 6.12), collision and preimage resistance: **O(q⁵·n·2^(−min(r,c)))**, with
  n = r + c. This covers **one squeeze round** (an r-bit output) and any number of absorbed blocks.
- The authors describe these quantum bounds as not tight. The classical bound q²/2^c is tight and does not depend on r.

**(c) What these bounds give** (order of magnitude: the log₂ of q at which the bound reaches a constant, ignoring constants and
taking ℓ = 1):

| Width | min(r, c) | Indifferentiability: min(r,c)/9 | Collision and preimage (r-bit output): (min(r,c) − log₂ n)/5 |
|---|---|---|---|
| 512 (r = 128) | 128 | 2^14.2 | 2^23.8 |
| 768 (r = 384) | 384 | 2^42.7 | 2^74.9 |
| 1024 (r = 640) | 384 | 2^42.7 | 2^74.8 |

Consequences:
1. **No width reaches 128 proved quantum bits**, nor does SHA-3 with these bounds. The 128-bit quantum level of BRUME-512q rests
   on (a), the cost of the best known attacks, not on a proof. This was already stated in the README (§ 2.1). It is the
   situation of the whole field.
2. **The review is right on one point:** widening raises the proved bounds. The indifferentiability exponent triples, from
   2^14 to 2^43, because min(r, c) goes from 128 to 384. My sentence "widening buys speed, never security" was false for the
   proved bounds.
3. **768 and 1024 are equal in proved terms**: both have min(r, c) = c = 384. Going beyond r = c gains nothing in proof, only
   speed.
4. **Whether the dependence on r is an artefact of the proof technique is open.** Classically the tight bound depends on c alone,
   and no known attack depends on r when the output is long. This leans towards an artefact, but it is not established.
5. **Our digests are not covered by Theorem 1.1 as stated**, which covers one squeeze round with an r-bit output:
   - BRUME-512q has several squeeze blocks;
   - BRUME-1024q has one block, truncated to 512 of its 640 bits.

   The truncated case needs its own argument. Generic BHT on the 512-bit output costs 2^170.7, so the binding term remains
   the capacity (2^128).

## 2. Diffusion and structure: what the width costs

**Exact definitions.**
- **Group and law.** D_{2m} = Z/m ⋊ Z/2, with the law of `sillage/brume512.py`: (a, f)·(b, g) = (a + (−1)^f·b, f ⊕ g).
- **Vertices.** Vertex v = a + m·f is nibble v of the state.
- **Generators.** Six reflections s_k = (k, 1), k ∈ K. The neighbourhood of x is {x·s_k : k ∈ K}, a 6-regular bipartite graph.
- **M.** Its support is A + I: the vertex plus its 6 neighbours, so 7 terms per row.
- **Diffusion in r rounds.** The size of the support of (A + I)^r applied to a single nibble, i.e. the ball of radius r.
  "Full diffusion" means the ball is the whole state.
- **λ\*.** The largest |eigenvalue| of A other than ±6.
- **Generator sets.**
  - 512: K = {21, 0, 7, 45, 8, 62}. These are the actual generators: the graph built from them is **identical** to the support
    of the real M, checked against the generated tables.
  - 768: K = {0, 76, 13, 10, 15, 34}.
  - 1024: K = {0, 83, 56, 51, 17, 42}. **First selection, superseded**: BRUME-1024q uses K = {0, 105, 71, 76, 72, 31},
    found by the full parameter search with the overlap and GF(2) constraints (§ 6 bis, `b1024/README.md`).
- **Selection.** Best of 400 000 random draws: the fewest rounds to full diffusion, then the largest ball just before, then
  the smallest λ\*. Taking 0 ∈ K loses no generality, because the bipartite graph of K + t is isomorphic to that of K.
- **For 768 and 1024, only the support is defined.** The GF(16) coefficients of M have not been chosen, so there is no M yet to
  publish, and its B is not certified. That is criterion 1 of § 6.

### 2.1 Results, by two independent programs

The first program is the analysis program. It runs a BFS from vertex 0 and computes λ\* with the representations of D_m:
λ\* = max over j of |Σ_k ω^{jk}|. The second, `largeur/verif_largeur.c`, uses other methods:
- the comparison with the real M;
- balls computed from **each** vertex, giving their min and max;
- λ\* by Jacobi diagonalisation of the dense adjacency matrix;
- the random fraction recomputed with another generator.

| Width | Balls r = 1…5 (min = max over all vertices) | λ\* representations / Jacobi (Ramanujan 2√5 = 4.472) | Eigenvalues ±6 | Random sets full in 5 rounds (2 draws) |
|---|---|---|---|---|
| 512 | 7, 37, 94, 127, 128 | 3.5076 / 3.5076 | 2 | — |
| 768 | 7, 37, 116, 181, 192 | 3.683 / 3.6825 | 2 | 38.6 % / 38.4 % |
| 1024, first selection (superseded) | 7, 37, 125, 222, 256 | 3.927 / 3.9267 | 2 | 7.6 % / 7.6 % |
| **1024, BRUME-1024q** (K = {0, 105, 71, 76, 72, 31}) | **7, 37, 127, 224, 256** | **3.796** | 2 | — |

The two programs agree. The equal min and max of the balls confirm vertex-transitivity.

**What these figures are, and are not.** Full diffusion in 5 rounds is a property of the graph, not a resistance proof. It
says how far a single difference can spread in the best case. It does not say how many rounds a differential or linear
attack needs, since the trails can stay sparse. The bound that matters for those attacks is the minimal activity (§ 4). The
inactive nibbles do matter for **truncated and impossible differentials**: at 4 rounds, 34 out of 256 are still untouched,
against 1 out of 128 today. So these attacks should gain about one round per direction at 1024. This is an estimate: at 512
the measured reach is 5 rounds (`tests/c/structure_miss.c`), and nothing is measured at 1024.

### 2.2 Degree: formula and hypotheses

- **Bound** (Boura, Canteaut, De Cannière 2011; Boura–Canteaut 2013). For a layer of 4-bit S-boxes followed by a linear map:

  deg(P_{r+1}) ≤ min( deg(S)·deg(P_r), n − ⌈(n − deg(P_r))/γ⌉ ),

  with γ = max_{1 ≤ i ≤ 3} (4 − i)/(4 − δ_i), where δ_i is the largest degree of a product of i coordinates of the inverse
  S-box. The linear layer does not change the degree. The same recurrence is used by `tests/test_integral_degre.py` and
  `tests/dp_sat.py`.
- **Computed** from the S-box AD412650BFEC7893 (`verif_largeur`):
  - deg S = deg S⁻¹ = 3;
  - δ₁ = δ₂ = δ₃ = 3, in both directions, so γ = 3, the generic value for 4 bits.
- **Results.** deg(P_r) ≤ n − 2 holds up to r = 10 at n = 512 and 768, and up to r = 11 at n = 1024, in each direction.
- **What it is.** An **upper** bound on the degree, hence a **guaranteed** zero-sum distinguisher: the sum over any affine
  subspace of dimension n − 1 vanishes. It spans 20 rounds inside-out at 512 and 768, and 22 at 1024. It is a lower bound on
  the reach of this distinguisher, not a security level.
  - At 512, the exact reach of the division property is known, and it is also 20 (PROOFS, Theorem 12 sexies).
  - At 1024 it is not computed: the reach is **at least** 22.
- **What is not computed** at 768 and 1024, for lack of a defined M:
  - the degree actually reached (measured at 512: 3, 9, 27 in rounds 1–3, `test_c_degre`);
  - the degree of the components and of the inverse;
  - the degree of the functions used by the hash and AEAD modes.

Altogether, at 1024 the structural reach is longer by about one round per direction for the degree (computed) and for the
truncated differentials (estimated).

## 3. Speed: measured

`largeur/noyau1024.c` is a one-state AVX2 kernel in the style of the suite:
- one nibble per byte, so 512 bits take 4 ymm registers and 1024 bits take 8;
- GF(16) multiplication by logarithms;
- rotations of one half of the state by alignr;
- packing and unpacking at each permutation.

The 512-bit version is checked to be identical to `sl_brume_permute`. The 1024-bit version is checked against a scalar reference
of the same round, with random non-zero coefficients: they are irrelevant to the speed, and this is not a design. Ryzen 5 5600G
at rest, 40 rounds, median of 7 runs:

| One state, 40 rounds | 512 bits (D₁₂₈) | 1024 bits (D₂₅₆) | Ratio |
|---|---|---|---|
| Permutation, kernel of the measurement | 466–471 ns | 1002–1012 ns | **×2.15** (3 series) |
| `sl_brume_permute` (suite), scaled to 40 rounds | 467–472 ns | — | the 512 kernel is the suite's speed |
| Sequential sponge, c = 384 (permutation only: rate / time) | 34.0–34.3 MB/s (rate 16 B) | 79.0–79.8 MB/s (rate 80 B) | **×2.33** |
| Message 64 B → 64 B digest | 9 permutations, ≈ 4.2 µs | 2 permutations, ≈ 2.0 µs | ×2.1 |

The model announced ×2.0–2.5 and 65–81 MB/s. The measurement lands at the top of that range: the register pressure (8 ymm of
state, 8 of temporaries) costs less than feared. The full sponge of `brume_q.c` gives 32–33 MB/s at 512, consistent with the
permutation-only figure.

**Not measured:**
- the 32-state (vertical) kernel at 1024. Its cost per nibble and per edge does not depend on the width, so the tree mode
  should gain about ×2.6. This is still a model;
- AVX-512, NEON and GPU;
- machines other than the 5600G.

On AVX-512 (Zen 4, Ice Lake and later), 1024 bits fit in 4 zmm registers, and the penalty should disappear. That is not
measured, for lack of such a machine.

## 4. The lever that comes before the width: the multi-round bound

### 4.1 Certified bound

**Proved** (`sat/README.md`): every characteristic, differential or linear, over 3 rounds has at least 18 active S-boxes
(C3 ≥ 18). Since the relaxation has a pattern at 30 ([4, 21, 5]), the true C3 of the relaxation is between 18 and 30.

The proof has three separate parts:
- **the model**: every real characteristic satisfies the relaxation;
- **the encoding**, checked against 120 000 real trails and on the satisfiable side;
- **infeasibility**: 361 cubes plus completeness, each with an LRAT proof checked by an independent checker.

**Also certified: C3 ≥ 21.** The run has 484 cubes. 482 are proved directly; the two hardest ones ((4, 9) and (6, 9)) are
split again by the weight of round 2, with 2 × 22 sub-cubes and their completeness, all checked. Solver time: 5 212 s; the
hardest leaf took 1 922 s, with 2·10⁷ lemmas. C3 ≥ 24 is running on a second machine (625 cubes, slow), and is not counted
here. So 21 ≤ C3 ≤ 30.

At 4 rounds, the CP-SAT dual bound is only 22 (5.5 per round), against a feasible pattern at 49. So blocks of 3 rounds remain the
best decomposition.

| Bound used | Rounds for 2^128 quantum | Proved quantum cost at 32 rounds | At 32 rounds, after 4 free rounds | At 40 rounds, after 4 free rounds |
|---|---|---|---|---|
| B = 8 (exact) | 32, zero margin | 2^128 | 2^112 | 2^144 |
| C3 ≥ 18 (certified) | 23 | 2^188 | 2^163 | 2^216 |
| **C3 ≥ 21 (certified)** | 20 | 2^218 | **2^190** | 2^252 |

Over R rounds, the bound is C3·⌊R/3⌋ + (0, 1, 8)[R mod 3] active S-boxes, with DP ≤ 2^−2 and |c| ≤ 2^−1 per S-box. The quantum
attacker gets the square root (Kaplan–Leurent–Leverrier–Naya-Plasencia 2016).

### 4.2 BRUME-512q at 32 rounds: every attack family

The review asked for a check that, at 32 rounds, no family other than characteristics becomes limiting:

| Family | Status | Reach or cost at 32 rounds | Quantum effect |
|---|---|---|---|
| Generic (capacity c = 384) | proved for the known attacks (§ 1.1 a) | **2^128: the limiting term** | already quantum |
| Differential characteristics | **proved** (C3 ≥ 21, Markov model) | DP ≤ 2^−436; ≤ 2^−380 after 4 free rounds | ≥ 2^190 |
| Linear trails | **proved** (same certificate) | \|c\| ≤ 2^−218; ≤ 2^−190 after 4 free rounds | ≥ 2^190 |
| Differentials and hulls (aggregation) | proved only weakly: MEDP_R ≤ MEDP_2 (Proposition 12, Markov model); clustering measured at 2 rounds (`test_hull`) | no bound that grows with R | square root of the classical cost |
| Boomerang | measured | 3 rounds 2^−8.8; 4 rounds < 2^−34.4 (95 %) | square root |
| Truncated and impossible differentials, zero correlation | computed (miss-in-the-middle, weight ≤ 2) | 5 rounds | no known quantum gain on the reach |
| Division property, zero-sum | proved: exact reach (Theorem 12 sexies) | 20 rounds inside-out, a 12-round margin | none known: a sum over 2^d inputs needs Ω(2^d) quantum queries, because parity has no quadratic speed-up |
| Algebraic degree | computed (§ 2.2) | 10 rounds per direction | none known |
| Rebound and inside-out (best measured) | measured | 8 rounds (5 + 3) | Grover on the free part |
| Guess-and-determine on the AEAD | measured | 2 rounds (≈ 2^97 classical) | square root of the guessing part |

**Reading.**
- At 32 rounds, every family with a proof or a measurement stays well above the generic term (2^128), which is the limiting
  one. It is the same at 40 rounds.
- The structural families (degree, division property) are counted in rounds, not in cost. Their margin at 32 rounds is 12
  rounds, the same as BRUME-512 in the suite.
- Two things are still not covered at 32 rounds, as at 40:
  - aggregation (differentials, hulls): no bound that grows with the number of rounds;
  - quantum attacks that would exploit something these bounds do not cover.

## 5. Cost and risk of a new width

| Item | 768 | 1024 |
|---|---|---|
| Choice of M (GF(16) coefficients, Weisfeiler–Lehman asymmetry, density of M⁻¹) | 1–2 days | 1–2 days |
| Exact certification of B (weight ≤ 3 on both sides, as for 512) and of C3 (same SAT bench, `sat/`) | hours | hours |
| AVX2 kernels (1 state: written for the measurement; 32 states), NEON, GPU; conformance against a dense reference | 2–3 days | 2–3 days (AVX-512 natural) |
| Porting the cryptanalysis bench (≈ 40 tests written for N = 128) | 1–2 weeks | 1–2 weeks |
| Exact division property (CP-SAT, model twice larger) | uncertain | uncertain |
| Mode proofs | unchanged (generic in b and c) | unchanged |
| Data layout | 96 packed bytes, 6 ymm, 3 zmm: awkward | 128 bytes, 8 ymm / 4 zmm, 32 GPU words: natural |

**Strategic risk.** Two permutations in one suite split the cryptanalytic attention, the scarcest resource for a new design.
The way out is a **family** BRUME-f[b] with a single design rule:
- a dihedral Cayley graph with 6 reflections;
- the same S-box;
- weights set by a public rule.

## 6. Verdict (revised)

1. **BRUME-512q at 32 rounds becomes defensible** now that C3 ≥ 21 is certified (and C3 ≥ 18 with a wide margin):
   - 2^190 after 4 free rounds, against 2^144 for the 40 rounds justified by B;
   - every other family below the generic term (§ 4.2);
   - +25 % of speed;
   - P₃₂ is BRUME-512 itself, so its cryptanalysis is the suite's.

   **The user decides.** I would only fix it once the checker has been doubled by `drat-trim` or `cake_lpr`, which were not
   available here.
2. **Tree mode by default** above 8 KiB, done in the prototype (`brume_q.c`: own KATs; the sequential sponge stays the XOF):
   ×1.7 per core.
3. **c = 384 or c = 320**: a decision on the cost model. 320 gives 128 bits only if quantum memory is counted (CNS: 2^128),
   against 2^106.7 with BHT. Neither choice changes the proved bounds of § 1.1, which are limited by r = 128.
4. **768 against 1024.** In proved terms (§ 1.1) they are equal: min(r, c) = 384 for both, three times the exponent of 512.
   1024 adds speed: ×2.33 on the sequential sponge and ×2.1 on short messages, measured. 768 has the same engineering cost and an awkward layout.
   1024 therefore remains preferred. But the reason to widen is now twofold: speed **and** proved bounds.
5. **BRUME-1024, as a research prototype**, with go/no-go criteria fixed in advance:
   - M certified with B = 8, full diffusion in 5 rounds, λ\* ≤ 4, asymmetric;
   - one-state AVX2 kernel at most 2.3 × BRUME-512: **measured at ×2.15, criterion met** (§ 3);
   - measured structural reach at most BRUME-512 + 2 rounds (division property, truncated, boomerang);
   - certified C3 at least equal to that of BRUME-512, using the same SAT bench.

## 6 bis. Decision and outcome (12 November 2026, evening)

**The author's decision:**
- c = 384, 32 rounds;
- a 1024-bit permutation, to recover the speed lost to the capacity.

**What was built:** BRUME-1024q, in `b1024/` (README there).
- The parameters were generated by the BRUME-512 rule, with the criteria of § 6 applied during the search.
- **The search found a better graph than the one of § 2**: K = {0, 105, 71, 76, 72, 31}, with balls 7, 37, 127, 224, 256,
  λ\* = 3.796 and overlap 2. § 2 analysed K = {0, 83, 56, 51, 17, 42}, which was ranked without the overlap and GF(2)
  constraints.
- **Criteria:**
  1. met;
  2. met (×1.99);
  3. partly met (impossible differentials 5 rounds as at 512; degree +2 inside-out, at the limit; boomerang and division
     property not measured);
  4. met (C3 ≥ 21 certified with two checkers).
- **Speed** at 32 rounds and c = 384, measured: sponge 105 MB/s (×2.9 BRUME-512q), tree 138 MB/s per core and 752 MB/s on
  12 threads, AEAD 104 MB/s. That is the speed of the classical suite, at the quantum level.

## 7. References

- G. Brassard, P. Høyer, A. Tapp, *Quantum cryptanalysis of hash and claw-free functions*, LATIN 1998 (BHT).
- A. Chailloux, M. Naya-Plasencia, A. Schrottenloher, *An efficient quantum collision search algorithm and implications on
  symmetric cryptography*, ASIACRYPT 2017, ePrint 2017/847 (CNS).
- M. Kaplan, G. Leurent, A. Leverrier, M. Naya-Plasencia, *Quantum differential and linear cryptanalysis*, FSE 2016.
- C. Boura, A. Canteaut, C. De Cannière, *Higher-order differential properties of Keccak and Luffa*, FSE 2011; C. Boura,
  A. Canteaut, *On the influence of the algebraic degree of F⁻¹ on the algebraic degree of G ∘ F*, IEEE-IT 2013.
- J. Czajkowski, C. Majenz, C. Schaffner, S. Zur, *Quantum lazy sampling and game-playing proofs for quantum
  indifferentiability*, ePrint 2019/428 (random internal function).
- J. Czajkowski, *Quantum indifferentiability of SHA-3*, ePrint 2021/192 (invertible permutation): **marked as withdrawn**.
- G. Alagic, J. Carolan, C. Majenz, S. Tokat, *The Sponge is Quantum Indifferentiable*, arXiv 2504.16887 (2025): the first
  proof for the invertible permutation, with bounds in min(r, c) (§ 1.1).
