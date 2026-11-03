# SILLAGE audit report — v0.2 → v0.3

*English translation of [`RAPPORT_AUDIT.md`](RAPPORT_AUDIT.md), which remains the reference version. Test names (`test_…`), check names and result files are identifiers in the code and are kept as they are.*

Scope: KEM, BRUME-512 (permutation, AEAD, TE, hashing), SIG.
Method: the `tests/` suite (39 tests, 290 checks — **290/290 passed** on 2026-10-30 —
replayable: `python3 -m tests.run_all`),
raw results in `resultats/`. This report consolidates the initial audit of
v0.2, the decisions taken on the open points and the verdict of the
full test suite against v0.3.

## 1. Flaws of v0.2 and fixes

| # | Component | Flaw | Severity | v0.3 fix | Regression test |
|---|---|---|---|---|---|
| 1 | SIG | Challenge 2 revealed `r` and `r⊕e` in the clear: one signature leaked the secret key | Critical | Conformant Stern protocol (3 commitments, response `π(u), π(e)` to challenge 2) | `test_sig`: `temoin_absent` |
| 2 | AEAD | Last ciphertext block and length block XORed into the same rate: `(c ⊕ Δ(L,L'), L')` kept the tag (forgery with probability 1) | Critical | Last block always partial + 10*, separate domains, permutation before the length | `test_aead` (all lengths ≤ 3 blocks, L ± 1, L + 8) |
| 3 | KEM | `decaps` without re-encapsulation: every decodable ciphertext accepted (IND-CPA at best) | Major | FO with implicit rejection, randomness derived from `(μ, H(pk))` | `test_kem`: `fo_rejette_chiffres_non_honnetes` |
| 4 | KEM | `tensor` mode: sparse `h = h1·h2`, pk of density 0.25 (z ≈ −180) | Major | Mode removed | `test_kem`: `mode_tensor_refuse` |
| 5 | SIG | Challenges `{0,1,2,3}→{0,1,2,2}`: ε = 3/4; byte permutation (leak of the pattern of `e`) | Major | Uniform ternary challenges, bit permutation, t = ⌈λ/log₂ 1.5⌉ | `test_sig`, `test_isd_parametres` |
| 6 | Parameters | “Prange / 2.4” (KEM) and “/ 1.35” (SIG) without basis; KEM ≈ 300 real bits for 128 announced | Major | Concrete ISD estimators (Prange, Stern-Dumer, BJMM); KEM resized: n = 68 059 / 244 043, pk 8.5 / 30.5 KB, ct 17 / 61 KB (instead of 16.4 / 65.6 and 32.8 / 131 KB); n chosen so that δ ≤ 2^−λ is **proved** (see §5) | `test_isd_parametres` |
| 7 | Bench | Linear propagation with the GF(16) transpose instead of the binary adjoint of the LAT | Medium | `GMUL_T` (exact binary adjoint) | `test_diff_lin_empirique`, `test_branch_exact` |
| 8 | Bench | “Strengthened” guarantee B ≥ 13 (2⁻⁴¹⁶): false, B = 8 is reached | Medium | Removed | `test_banc_cryptanalyse` |
| 9 | AEAD | Key processed by SHAKE256, never by BRUME | Design | Keyed duplex entirely on the permutation | `test_fonctionnel` (KAT) |
| 10 | AEAD | 256-bit capacity incompatible with λ = 256 | Design | BRUME-512-256 profile: rate 128, capacity 384 | `test_aead` |
| 11 | TE | Truncated parities accepted, metadata not checked | Minor | Strict checks | `test_te` |
| 12 | Misc. | `demo.py` / `bench.py` imported a non-existent `sillage` package | Minor | Tree rebuilt (`sillage/` = package) | `test_fonctionnel`: `demo_execution` |

## 2. Decisions on the open points

- **Security estimation**: in the sparse regime (KEM, w ≪ n), all
  ISD variants have Prange's dominant exponent (BJMM ≈ 0.9 × Prange
  measured); dividing by 2.4 made no sense. The KEM parameters are
  recomputed as tightly as possible (security ≥ λ + 8 after the QC gain, decoding
  failure ≤ 2^−(λ+64), smallest Artin n): **sizes divided by
  ≈ 2.5–3**. For the signature, BJMM gives 160.5 bits: it is the FS forgery
  (128.1 bits) that sets the security.
- **Capacity**: hashing keeps c = 256 (collisions at 2¹²⁸, the standard
  target of a 256-bit digest). The keyed AEAD follows the bound of the
  keyed duplex `M·N/2^c`: c = 256 for λ = 128 and c = 384 for λ = 256.
- **Noise cascade**: kept (an idea of the project) but documented as
  **neutral**. π being public, `π(e2)` has the distribution of `e2`. Making it active
  would require a shared secret, which is impossible on the encapsulation side.
- **TE**: remains a channel error-correcting code. Its “tamper evidence” only holds
  against accidental alterations; adversarial integrity rests
  on the tag (tested: recomputed parities are stopped by the tag).
- **Side channels**: out of scope (Python). Measured for information:
  valid/invalid timing gap ≈ 3 % (decrypt) and ≈ 4 % (decaps).

## 3. Results of the test suite against v0.3

### BRUME-512, permutation

| Property | Result |
|---|---|
| Branch number (diff. and lin.) | **B = 8 exactly** (enumeration of weights ≤ 3 of M, M⁻¹, Mᵀ, (Mᵀ)⁻¹) |
| Bounds at 32 rounds | differential characteristic ≤ 2⁻²⁵⁶, linear trail ≤ 2⁻¹²⁸ (**proved**) |
| Best trails found, 14 rounds | diff. 2⁻²⁸³⁰, lin. 2⁻¹⁴¹⁷ (greedy); beam: 2⁻²⁷⁵³ / 2⁻¹³⁸⁰ |
| Iterative cycles | none on v1 (the unweighted v0 control shows 5 287) |
| Model validation (1 round) | diff. 0.1263 measured / 0.125 predicted; correlation 0.0070 / 0.0078 (σ = 0.001); exact adjoint |
| Nibble cubes | zero sum up to 3 rounds; random at 4 |
| Bit cubes (2⁸–2¹⁶) | 4 rounds (partial); random at 5 |
| Integral 2²⁰ (graph neighbourhood) | 4 rounds (101/128 zero nibbles); 5–6 rounds: random |
| Degree bounds (Boura–Canteaut) | full degree (511) at round 11; inside-out zero-sum ≤ 20 rounds → **margin of 12 rounds** |
| Bit-based division property | balance proved up to 10 rounds in each direction; monomial trails verified to **all** bits from 15 rounds (forward) and 12 rounds (backward), **for the cube with bit 0 inactive** → for this cube, no DP distinguisher beyond 14 + 11 = 25 rounds inside-out (tightened in § 9: 10 + 10 = 20, for every cube) |
| Aggregation (hull) | MEDP₂ ≤ 2⁻¹⁴·⁹⁹, MELP₂ ≤ 2⁻¹⁵ (**proved**, Park et al.); measured aggregation factor 1.1 on an 8-S-box trail |
| Diffusion | full support in 5 rounds (all vertices), full avalanche in 4 |
| SAC 512×512 at 32 rounds | mean 0.5001, z_max = 4.81 (≈ 5.1 expected at random) |
| Statistics (AEAD keystream, hashing, counter) | 33 p-values, min 0.026: no rejection |
| Symmetries | no invariant translation of D₁₂₈; WL: 128 colours (asymmetry); distinct, non-periodic RCs |
| Invariants | no subspace stable under S and M; order of M > 256; S-box: trivial self-equivalence only, no linear structure |

The longest distinguisher found covers **4 rounds out of 32**. The reach
of a division-property distinguisher is bracketed between 20 rounds
(proved for every cube) and 25 rounds (verified for the cube with bit 0
inactive), out of 32. *Update (§ 9): exact reach of 20 rounds, for every
cube.*

### Modes

| Test | Result |
|---|---|
| AEAD | all alterations rejected (bit by bit, extension, truncation, tag, nonce, AAD, key, length/final-block collision) on both profiles |
| TE | correction at every position and for every mask; 400 double errors in the same block: 386 TAMPER, 14 TAG, **0 accepted** |
| Hashing | injective padding (exhaustive), distinct extensions, 65 792 distinct digests, collisions on 20 bits as expected (5 observed / 8 expected), avalanche 127.8/256 |

### KEM and SIG

| Test | Result |
|---|---|
| KEM correctness | 150/150 (128), 25/25 (256) |
| Decoding margin | max 108 flips for a threshold of 265 (128); 170 / 476 (256) |
| Proved δ (Chernoff, per key) | generated key 2⁻¹⁶⁷ (128) / 2⁻³⁷⁷ (256); worst of 30 raw keys 2⁻¹³⁸ / 2⁻²⁵⁶; keygen rejects any key above 2^−λ |
| FO | decodable dishonest ciphertexts → implicit rejection; deterministic rejection; malformed inputs without exceptions |
| SIG | verification, rejections, witness absent, cheater with a dense preimage (weight 862) rejected, uniform challenges (χ²) |
| Fuzzing | no undeclared exception (decrypt, decrypt_te, verify, decaps) |

## 4. Second pass: open points resolved

| Point | Finding | Fix | Test |
|---|---|---|---|
| KEM δ-correctness | the Gaussian argument announced 2⁻¹⁹²; the rigorous bound (Hoeffding, sampling without replacement) only gave 2⁻⁶⁰ to 2⁻⁷⁵ | Chernoff bound certified **key by key** (`borne_echec_log2`), keygen rejects keys > 2^−λ, n resized to 68 059 / 244 043 | `test_kem`, `test_isd_parametres` |
| Formal proofs | missing | `docs/PREUVES.md`: IND-CPA, IND-CCA (FO ⊥̸), Stern (completeness, 3-soundness, HVZK), EUF-CMA, wide trail, Park, duplex | — |
| Linear hull | not measured | proved MEDP₂ / MELP₂ bounds, measurement of aggregation | `test_hull` |
| Division property | not done (SAT too slow: > 40 min without an answer at 11 rounds) | monomial trails built (minimum-cost flow + beam) then **re-checked** step by step, extended bit by bit by induction | `test_division_property` |
| “Strengthened” wide-trail bounds | invalid (B ≥ 13 not established) | removed | `test_banc_cryptanalyse` |
| Trivial check | `best_char` compared with `DDT.max()` (= 16, row 0) | `DDT[1:].max()` | `test_diff_lin_empirique` |
| Performance | permutation as a loop over rounds | fused kernel (S∘·c table per edge and per round), **+30 %**, KAT unchanged | `bench_perf`, `bench_tailles` |

Benchmark by size (`resultats/BENCH_TAILLES.md`): 0 B → 1 MiB, 4
kinds of content, all round trips checked; ≈ 100 KiB/s in
AEAD-128 and ≈ 50 KiB/s in AEAD-256; fixed hybrid KEM cost ≈ 1.7 / 2.2 ms.

## 5. Third pass: intensive tests in C

C/OpenMP kernel (`tests/c/noyau.c`, loaded by `tests/noyau_c.py`): tables
taken from `sillage/brume512.py`, bit-by-bit conformance checked before
each test, ≈ 700 000 permutations/s at 32 rounds (×127 compared with
Python). Sample sizes are multiplied by 100 to 8 000.

| Test | Measurement | Result |
|---|---|---|
| `test_c_integral` | cubes 2¹⁶–2²⁴ (random nibbles, graph neighbourhood, isolated bits), forward and backward | 4 rounds (forward), 2 (backward); 5 rounds random even at 2²⁴; consistent with DP ≤ 14 / 11 |
| `test_c_diff_lin` | 2-round differential on 2²⁷ pairs; 2-round hull on 2²⁸ | factors 0.99 ± 0.04 and 1.004 ± 0.016: **no aggregation effect** at 2 rounds |
| | truncated and linear, aligned on the S-boxes (outer linear layer removed) | 5 rounds (forward), 2 (backward) truncated; 1 round linear on one nibble |
| `test_c_sac` | SAC 512 × 512, 2¹⁶ samples per bit, round by round | indistinguishable from 5 rounds (forward), 2 (backward); conformant at 32 rounds |
| `test_c_statistiques` | 34 NIST-style tests on 1 GiB (counter), 512 MiB (sponges), reduced rounds | conformant at 32 rounds (p_min 0.054 / 0.024, KS 0.23 / 0.89); fails up to 4 rounds, conformant from 5 |
| `test_c_kem_bruit` | 3.4·10⁷ (128) and 8.4·10⁶ (256) simulated decoding noises, cross-checked with the real KEM | δ bound ≥ measurement at every observable threshold, margin ≈ 18 bits; max 129 / 265 and 202 / 476 flips |

Pushed campaign (intensity ×4 to ×8, `resultats/<test>_x<k>.json`):

- cubes of 2²⁸: the backward direction goes to 3 rounds, forward stays at 4;
- 2-round differential (2²⁹ pairs): factor 1.013 ± 0.022;
- 2-round hull (2³⁰ samples): factor 1.011 ± 0.008;
- SAC (2¹⁸ samples per bit): unchanged;
- statistical battery on 4 GiB in counter mode and 2 GiB of sponges: conformant;
- KEM noise (1.3·10⁸ draws): bound margin of 19 bits, maximum of
  132 flips for a threshold of 265.

The longest empirical distinguisher covers **5 rounds (forward) + 3
(backward) = 8 rounds inside-out out of 32**. The δ bound is valid and conservative:
it overestimates the measured frequency by about 2¹⁸ at the observable thresholds.
A tighter bound might allow reducing n, but the
parameters only rely on the proved bound.

## 6. Fourth pass: C implementation, complementary analyses

**C implementation** (`sillage/c/`): a complete port of the suite (BRUME-512,
AEAD, TE, hashing, KEM with the δ bound in keygen, SIG, SHAKE256),
**byte-for-byte conformant** to the Python code and interoperable in both
directions (`test_c_impl`, 26 checks). Single-core benchmark
(`resultats/BENCH_C.md`):

| Measurement | Result |
|---|---|
| Permutation | 4.5 µs; AEAD-128 at 6.8 MiB/s (×69 to ×78 compared with Python), AEAD-256 at 3.4 MiB/s |
| KEM-128 | keygen 1.1 ms, encaps 0.28 ms, decaps 0.41 ms (×4 to ×6) |
| SIG-128 | signing 53 ms, verification 37 ms (×14 to ×16), about 129 KB |

**Complementary analyses:**

| Test | Result |
|---|---|
| `test_c_cube_init` (nonce cubes on the reduced initialisation) | zero sums up to 4 rounds; **no linear superpoly** (20 + 20 BLR trials per bit) → no state recovery; real path of 64 rounds |
| `test_c_degre` (random subspaces) | maximal degree 3, 9, 27 reached at rounds 1–3, in both directions; Boura–Canteaut bound respected |
| Division property (wider beam, 24 new verified trails) | forward ≤ 14, backward ≤ 11 (before: 15 and 12) → **inside-out ≤ 25**; backward, 10 ≤ reach ≤ 11 |

**Method defects fixed during the pass** (in the tests, not in
SILLAGE):
- a single-bit linear probe was blind by construction;
- a degree test on isolated bits was invalid in the forward direction;
- a linearity test with 10 trials produced 1.5 false positives per round.

## 7. Fifth pass: performance without changing the algorithm

Goal: high throughput, with the same outputs and the same KATs, and
without any loss of security.

| Item | Result | Security |
|---|---|---|
| AVX2 permutation of one state (Cayley structure of D₁₂₈: reflections → swap of halves and byte rotation; S-box and GF(16) log/exp by `vpshufb`) | 0.41 µs (×11); AEAD-128 on a single message: 79 MiB/s | **constant-time** (dudect, threshold \|t\| < 4.5); it replaces state-indexed tables |
| Batches of 32 states, multi-message AEAD and hashing (OpenMP, automatic choice between batches and one message per core) | 0.19 µs per state; AEAD-128: 624 MB/s (1 KiB messages), 713 MB/s (16 KiB) on 12 threads | constant-time |
| KEM decapsulation (Python and C) | systematic re-encapsulation, selection by mask, branch-free decoding | removes a **decoding-failure oracle** (≈ 0.28 ms gap), the vector of reaction attacks |
| Sparse sampling (C) | fixed number of words (P(insufficient) < 2⁻¹²⁸), branch-free acceptance; same positions | removes the leak through the number of rejections (“Don't Reject This”, CHES 2022), **detected by dudect** in the re-encapsulation (t = −53) |
| KEM products (C) | dense representation, Karatsuba + PCLMULQDQ, bits written by masked sweep; decapsulation 0.95 / 5.1 ms | **constant-time C KEM**: dudect below the threshold \|t\| < 4.5 for the FO oracle and for the secret key (keys with the same σ_h); plans redone in the twelfth pass (§ 14) |
| `test_c_impl` (34 checks), `test_c_temps` (4 checks) | outputs identical to Python for every path (single, AVX2, batches) | — |

Leads measured but **not adopted**, because they change the algorithm
(parallel duplex, fewer rounds in the data phase), and low-priority residual
leaks (SIG): `docs/PISTES.md`, with the
security conditions of each.

## 8. Sixth pass: proof of the mode, exact division property, memory safety

| Item | Result |
|---|---|
| **Proof of the AEAD mode** (`docs/PREUVES.md` § 4.3, Theorem 14) | Lemma 1: replacing the rate with the plaintext amounts to absorbing the ciphertext by XOR; the mode is a standard keyed duplex, without an overwrite flag. Lemma 2: injective, prefix-free encoding. Lemma 3: key absorption in N/2ᵏ + 2N/2ᵇ + N/2ᶜ. Lemma 4: capacity collisions. AE bound: σ²/2^{c+1} + 2σN/2ᶜ + N/2ᶜ + N/2ᵏ + q_d/2^τ, i.e. 128 and 256 bits for σ ≤ 2⁶⁴ |
| `test_mode_aead` (9 checks) | the abstract duplex of the proof, written without brume512.py, reproduces ciphertexts and tags exactly (two profiles); injective, prefix-free encoding on 441 boundary paths per profile; no plaintext released on rejection |
| **Exact division property** (`tests/dp_cpsat.py`, `tests/dp_sat.py`) | exact model (same rules as the checker, inactive bit free), correct weight windows (including Boura–Canteaut on F⁻¹), infeasible for R ≤ 10; at R = 12, one trail re-checked in 18 min; at 11 rounds, targeted UNSAT queries do not conclude in 25 min → **exact value not reached** (lead 6) |
| **Scope correction** | the upper bounds of the division property (14 / 11 / 25) only hold for the cube with bit 0 inactive; the documentation presented them as general. Only the lower bound (10 per direction) holds for every cube |
| `test_c_fuzz` (3 checks) | memory safety of the C code: UBSan in trap mode and a guard-page allocator (heap overflow → fault, write into the padding → canary, use after free → fault), validated on deliberate errors; 2 000 iterations over every API: **no memory error or undefined behaviour** |
| `test_dp_modele` | consistency (infeasible for R ≤ 10), completeness (the verified trails are accepted) |
| Performance, without changing the outputs | fused `log∘S` (−7 %), precomputed IV, key context, unrolled Keccak, Karatsuba in VPCLMULQDQ; a 1 MiB message: 83 MiB/s; KEM: 0.60 ms decapsulation; SIG: 31 ms; multi-message: 628 to 705 MB/s |

## 9. Seventh pass: exact reach of the division property (lead 6)

| Item | Result |
|---|---|
| **Splicing** (`test_dp_tous_cubes`, PREUVES Lemma 12 ter, Corollary 12 quater) | the first linear layer moves inactive bits freely; a matching (Hopcroft–Karp) in the bipartite graph of L carries each trail of cube 0 to the 511 other cubes. 27 trails × 512 cubes = 13 824 splicings, **all re-checked**, no failure. The bounds 14 / 11 / 25 hold for **all** cubes |
| **Decomposition** (`tests/dp_queue.py`, Lemma 12 quinquies) | prefix of a verified trail + exact suffix by CP-SAT towards a given bit, on a model reduced to the reachable and co-reachable bits (about 1 s per query, against more than 25 min without a conclusion for the full model) |
| **Exact reach** (`test_dp_exact`, Theorem 12 sexies) | 18 forward trails of 11 rounds obtained from prefixes of 12- and 13-round trails, then a verified trail to **each of the 512 bits at 11 rounds, in each direction** (1 024 trails, 12 min). Reach of the division property: **exactly 10 rounds per direction, 20 inside-out, for every cube** (instead of 10 ≤ · ≤ 14 / 11 / 25 for a single cube) |
| Per-nibble cuts (`test_dp_modele`) | wt(u) ≤ 3·[v ≠ 0] + [v = F] and cw(v) ≤ 3·[u ≠ F] + [u = 0], checked on the 3 194 transitions of all exact tables; they did not suffice for the full model to conclude (UNSAT at 11 rounds stopped: the targeted bit does in fact have a trail) |
| Limit of the statement | a trail shows that the method no longer proves balance, not that the sum is non-zero (trails in even number); the actual integral distinguisher remains measured empirically (4 rounds forward, 3 backward) |

## 10. Eighth pass: constant-time signature (lead 3), tree hashing (lead 5)

| Item | Result |
|---|---|
| **Leak in the C signature** (before) | π materialised then read at indices π(i), Fisher–Yates swaps at secret indices, rows of H skipped depending on the bits of u and e: a cache spy could recover π in a challenge-2 round, hence e = π⁻¹(π(e)). dudect measurement on the old path: t ≈ −220 to −460 |
| **Fix** (`sillage/c/sig.c`) | π is no longer built: the Fisher–Yates swaps (same draws) are applied by masked sweep to the bit planes of u and e, then H·u and H·e are masked (H·u grouped over the t rounds). Identical signatures (`tests/c/sig_ct.c`: 600 trials, exact conformance; Python interoperability unchanged) |
| Measured constant time | signer round with given swaps: t ≈ 0.4 to 1.8; full signature, fixed key against random keys: t ≈ −0.6 to −1.5 (threshold 4.5) |
| Drawing the swaps | variable duration depending on rejections, which only concern the rejected values of the stream (independent of π); fresh λ-bit seed σ_π, not enumerable |
| 4-way Keccak-f (AVX2, gcc vectors) | SHAKE stream of the draws 4 blocks at a time, identical outputs: SIG-128 signs in 29 ms (31 before, not constant-time), verifies in 12 ms (20); SIG-256: 166 / 50 ms (130 / 86) |
| **Tree hashing** (`brume512_hash_arbre`, `sl_hash_arbre`) | 8 KiB leaves in batches of 32 on all cores, root CV ‖ k ‖ B, LEAF / ROOT / SINGLE domains in the capacity. Proof: PREUVES § 4.4 (Theorem 16, BDPV 2014 conditions). 16 MiB: 160 MB/s on one core, 785 to 850 MB/s on 12 threads (86 sequentially) |
| `test_hachage_arbre` (14 checks) | model of the mode ≡ Python ≡ C on 13 boundary lengths; decodability, completeness, separability checked; structural alterations; multi-thread determinism; frozen KATs |
| `test_c_fuzz` | extended to tree hashing (60 lengths up to 5 leaves, batched path compared with a leaf-by-leaf recomputation, under guard pages): no fault |

## 11. Ninth pass: external audit

Report received on the first version of the artifact, reproduced with the
point-by-point answer (not published).

| Point | Verdict | Fix |
|---|---|---|
| KEM H1 / H2 distinguishable through parity (s(1), u(1) public) | **confirmed**, a proof defect | H1-P / H2-P assumptions with parity (as in HQC), IND-CPA proof redone; scheme and KATs unchanged; checks of the invariant in `test_kem` |
| AEAD bound and “128 bits” | misleading wording, correct bound | cost/advantage notion defined; Corollary 14 bis term by term (128 / 256 bits for σ ≤ 2⁶⁴); case N = 2¹²⁸ discussed |
| AEAD ideal game | ambiguous wording | standard restriction (no decryption of an output of Enc) made explicit |
| SIG: q_H factor | a real factor, t justified in the cost/advantage sense | budget term by term; programming term tightened to q_S(q_S + q_H)/2³⁸⁴ |
| KEM quantum level | wording | profiles named after the classical level; no quantum level claimed |
| Overall security of BRUME, DP, constant time, multi-user | wording | made precise (README, PREUVES § 4.3 remarks 4 and 5) |
| C signature not constant-time | already fixed (eighth pass) | — |
| Reproducibility | addition | `tests/empreintes.py` → `resultats/EMPREINTES.md` |

## 12. Tenth pass: assumptions and open problems (in C)

From now on, all new work is in C. Python remains the frozen
reference (KATs). The native C tests write their own
`resultats/<name>.json` (`tests/c/resultat.h`, `tests/c/Makefile`), and the
`run_all` launcher runs them through a “c:<name>” hook.

| Item | Result |
|---|---|
| **H1-P / H2-P / H3: real ISD** (`tests/c/isd_reel.c`) | Prange on reduced instances with the same structure. The measured cost follows the estimator's formula, with ratios from 0.93 to 1.02 on three quasi-cyclic sizes (n an Artin prime) and two random codes. Quasi-cyclic gain (n shifted syndromes) measured at ×163 for n = 149: it equals the estimator's log₂ n credit. Rank of the differences of s equal to n − 1 on 6 Artin primes: **parity is the only linear invariant** |
| **Impossible differentials / zero correlations** (`tests/c/structure_miss.c`) | miss-in-the-middle at the nibble level, patterns of weight ≤ 2: **5 rounds** at most in both cases (a margin of 27 rounds). The propagation rules are validated on 1.4·10⁶ predictions confronted with real differences (0 violations). Support density: M 5.5 %, M⁻¹ 94 % |
| **Multi-user AEAD** (PREUVES Theorem 14-mu) | proof written in full: Lemma 3 terms multiplied by μ, plus μ²/2^{k+1}; 128 / 256 bits for μ ≤ 2⁶⁴ and σ ≤ 2⁶⁴ in total |
| **Lemma 15 written in full** | simulator and bad event. **Correction**: the term is 7q²/2^{c+1}, not q²/2^{c+1}, since with domains in the capacity, two capacities that differ by a value of D ⊕ D make a call ambiguous. The level is not affected |
| **Quantum adversary** (PREUVES § 5 bis) | **SIG: only ≈ 64 / 128 bits**, since Grover applies to Fiat–Shamir in √((3/2)^t); KEM ≈ 91 / 158; hash collisions ≈ 2⁸⁵ (BHT); AEAD: key at 2²⁵⁶. The profiles are classical; quantum SIG profiles are noted (lead 7) |

## 13. Eleventh pass: external audit, second pass

Report and detailed answer not published.

| Point | Verdict | Fix |
|---|---|---|
| Diffusion support “128 in 3 rounds” | **confirmed**: an error in the artifact (the test suite measured 5 rounds) | `diffusion_support` (C): exact supports 7, 37, 94, 127, 128 (combinatorial = actual dependency through the permutation), dihedral-group bounds recomputed, M⁻¹ complete in 2 rounds; density 15/16 of the linear powers over GF(16); bipartite graph, λ* = 3.5076 recomputed excluding ±6. PREUVES Proposition 10 bis |
| D ⊕ D in Lemma 15 | **partly**: 7 is correct for D = {0, 8, 9, 10} (F_0 included), but D was not defined in the artifact | definition and the {8, 9, 10} case (factor 4) made explicit; tree hashing moved back to “under validation” |
| Model of the 2⁻²⁵⁶ / 2⁻¹²⁸ bounds | **confirmed** | Corollary 11: certified activity, probabilities under the Markov model (an assumption); summary qualified |
| H1-P / H2-P | **confirmed**: remains an assumption | `kem_distributions` (C): parity of u is the only linear invariant of H2-P (5 reduced instances); no bias or u / v / s correlation at full sizes (11 checks) |
| AEAD review | **confirmed** | “proved, not reviewed” in every summary |
| Review of the constant-time SIG code | **confirmed** | `sig_flux` (C): instrumented sig.c (`-fsanitize-coverage=trace-pc`), 40.3·10⁶ identical basic blocks for 6 keys (one of them structured), key generation and masked functions likewise, control detected; test probe `-DSL_SONDES` (public digest forced), absent from the production code; machine code of `appliquer_echanges_ct` inspected (jumps on public counters) |

## 14. Twelfth pass: night campaign of 2026-10-30, fixes

The 8-hour run (477 min) reported 2 dudect failures on the KEM, and re-reading it
showed several tests without detection power. The cryptographic code did
not change; only the benches and campaigns were fixed. The results
of this run stay in `resultats/NUIT.md` until the next launch, which will
archive them.

**dudect failures (t = −5.68 / −6.75).** The plan in `temps.c` opposed a fixed
ciphertext to varied ciphertexts and thus confused a public value with a secret. Separate
plans, 600 000 measurements per mode:

| Mode | Gap | t |
|---|---|---|
| Value of the ciphertext alone (fixed against 256 honest) | +197 cycles | −5.23 |
| Accepted / rejected (256 honest against 256 random) | +18 cycles | −0.47 |
| Secret alone (fixed key against 64 keys, same ciphertext) | −28 cycles | 0.69 |

The effect therefore comes from repeating a public ciphertext. **Its mechanism has not
been identified.** It exposes no secret in these plans, which remains a
measurement and not a proof.

New plans (pools of ciphertexts shared by the classes, copy into a
common measurement buffer, pinned core):

| Plan | Measurements | t |
|---|---|---|
| `kem_oracle`: decoding, honest against random | 1 200 000 | 0.15 |
| `kem_oracle_fo`: FO comparison, one bit of v flipped | 1 200 000 | −1.59 |
| `kem_decaps`: fixed key against 64 keys with the same σ_h | 1 200 000 | −0.56 |
| `kem_encaps`: fixed μ against random | 1 200 000 | −2.81 |
| `kem_aa`: bench bias (A/A) | 600 000 | 0.58 |
| `kem_temoin`: control, +300 cycles injected | 300 000 | **−6.84, detected** |

Sensitivity: about ±40 cycles out of 2.5 M, to be compared with a median that varies
from 2.507 to 2.620 M cycles from one process to another.

**Campaign defects, fixed:**

| Defect | Fix |
|---|---|
| Check “no distinguisher beyond 7/5” impossible to fail (tests limited to 6/5) | a reach specific to each family and a coverage check: `chaque_famille_testee_au_dela_de_sa_portee_connue`, `aucun_distingueur_au_dela_de_la_portee_connue` |
| Night truncated differentials (Δ = 0, without M⁻¹ at the output) blind to the known bias | aligned χ² with 15 dof; controls at 5 rounds forward and 2 backward, detected (χ² = 15·N: predictable, M⁴ leaves one nibble outside the support) |
| “New distinguisher” at 3 rounds backward, already known | classified as a control (3³ = 27 < 28) |
| Isolated cubes with little sensitivity; 227 zero bits (z = −2.56) at 4 rounds backward | series of 32 cubes (total z, most unbalanced bit, Bonferroni 512) and a re-check at 2³² |
| Cubes of 2³⁶ never launched | scheduling revised, fallback to 2³⁴ for the backward cube |
| Tautological check of the KEM bound | independent naive recomputation on 1 key in 64 |
| KEM campaign: only 57 227 real decapsulations, implicit rejection not tested | 1/64 cross-check, implicit rejection, worst key, keygen rejection rate |
| Poor fuzzing of the KEM and SIG | dedicated processes, extreme inputs (all-0 / all-1 ciphertexts and keys, null u or v, empty or maximum-length signatures, empty message) |
| Random ISD drift (1.07 / 1.17 / 1.22, against 0.92 before) left without a verdict | 300 instances at n = 280, cumulative deviation (Stouffer), check `pas_de_derive_systematique_de_la_formule`; QC gain measured on 4 sizes |

**Error introduced and then fixed during this pass.** The new joint linear
test counted 225 dof instead of 255 (uniform over 256 cells, known margins),
hence p-values that were too small (0.007 at 2 rounds, 0.7 once fixed). The
χ², stable from 2²⁴ to 2³⁰, gave it away: a real bias would have grown with the sample.
The check `statistiques_chi2_calibrees_sous_h0` now verifies the mean at
12 rounds (254.88 for 255; 14.94 for 15).

**Checked:** a 15-minute campaign on a copy of the repository, no failed check
(fuzz 271 000 iterations, 0 failures; KEM 12/12; ISD 3/3), then a
330-second cryptanalysis campaign after the dof fix (5/5). `test_c_temps`: 10/10;
`test_c_fuzz`: 3/3.

**Not checked:** the full 8-hour campaign with these plans has not been
rerun, so the 2³⁶ cubes and the large samples remain to be measured.
The ISD drift check only covered small sizes. ASan and
coverage-guided fuzzing remain unavailable here (UBSan and guard pages
only).

## 15. Overall assessment

**BRUME-512.** Nothing that has been run makes a dent in it.
- The proved bounds (B = 8 exactly, characteristics ≤ 2⁻²⁵⁶ and trails
  ≤ 2⁻¹²⁸ at 32 rounds) hold.
- The measured aggregation is nil at 2 rounds (factors 1.01 ± 0.01).
- All empirical distinguishers stop at 5 rounds forward and 3
  backward, i.e. 8 rounds out of 32, with samples up to 2³⁰ and
  4 GiB streams.
- The reach of the division property is known exactly: 10 rounds per
  direction, 20 inside-out, for every cube (seventh pass).
- The degree grows maximally, and neither symmetry nor invariant is found.

The margin is comfortable: 12 rounds beyond the exact reach of the
division property (20 inside-out), 24 beyond the measured distinguishers.
The theoretical uncertainty that set the floor (forward DP reach of 10 to
14 rounds) is lifted. The cost is
high: about 140 cycles per byte for the reference permutation.

**Sillage-KEM.**
- Correct, IND-CCA in the ROM under decisional QCSD with parity (H1-P / H2-P,
  a formulation corrected after the external audit), with a δ proved key by key and
  validated empirically (a conservative bound by about 18 to 20 bits).
- The security margin is modest: 137 bits estimated for 128 targeted, which
  makes it sensitive to any progress in ISD algorithms on sparse
  quasi-cyclic codes. This level is classical: the Prange–Grover quantum
  estimate is 91 bits.
- The noise cascade adds nothing to security.
- The repetition code gives ciphertexts of 17 KB.

**Sillage-SIG.** Conformant Stern, secure under SD, but very costly: about
131 KB per signature and 29 ms in C, now constant-time. This is the price of a reference baseline.

**What these tests do not show.** They cover the known attack
families: differential, linear, integral/DP, cubes, algebraic,
statistical, generic. Finding nothing is a necessary condition,
not a proof. An original design (weighted Cayley diffusion
over D₁₂₈) may have structural weaknesses that no standard
tool targets.

**What would increase confidence the most:**
1. third-party cryptanalysis;
2. a review of Lemma 15 and Theorem 16 (tree hashing);
3. a third-party review of the proof of the AEAD mode (§ 4.3 of PREUVES.md,
   written) and of Theorem 12 sexies.

## 16. Accepted limitations

- The proved bounds concern individual characteristics and trails,
  and aggregation over 2 rounds. Beyond that, there is a
  measurement (factor 1.1) and a margin of more than 2 500 bits, without a proof.
- Division property: the exact reach (10 rounds per direction) is that of
  the method based on the existence of trails. The actual integral
  distinguisher, which depends on the parity of the number of trails, is only measured
  empirically.
- AEAD mode: proof written (Theorem 14) and tied to the code by
  `test_mode_aead`, but not yet reviewed by a third party.
- Side channels: BRUME-512, the KEM and the signature in C are
  constant-time (checked with dudect); the Python implementation is
  not. The signature's Fisher–Yates sampling keeps a variable duration,
  independent of π. The effect of repeating a public ciphertext on
  decapsulation (≈ 200 cycles out of 2.5 M, § 14) is not explained.
- Quantum levels below the nominal levels (PREUVES § 5 bis),
  in particular for the signature (≈ λ/2); QROM reductions cited, not
  instantiated.

---

## Errata of 2026-10-30 (review of Sillage-SIG, ISD, Theorem 16)

These points correct values quoted above, which are left as they are as a record.
Details: `docs/PREUVES.md` § 3, § 4.4, § 5 and § 5 bis; history in the `README`.

- **SIG-256 was worth ≈ 128 bits, not 256**: σ_π of 128 bits and 256-bit hashes. Fixed,
  and the format changed. SIG-128 keeps its sizes.
- **ISD for the signature:** 159.7 / 314.9 bits, instead of 160.5 / 327.2.
- **Quantum signature:** the Grover attack on σ_π adds to Fiat–Shamir. “≈ 128 bits” for
  SIG-256 only holds after the fix. Lead 7 corrected.
- **Side channels:** two secret-dependent accesses, found by Valgrind and that dudect
  had not seen. One of them also affects the KEM (`sl_creux`).
- **Lemma 15 and Theorem 16:** proof completed, see the status in § 4.4. **The review done
  is an AI's; the “third-party review” item remains open.**

## Errata of 2026-11-01 (dudect bench)

The “OK” results of `aead` and `kem_decaps` in `resultats/NUIT.md` of 2026-10-31 only held thanks to a
second measurement. The run `resultats/special/20261101_131954` (4 values × 3 processes) finds
reproducible gaps (|t| up to 26 on `aead`, 7 on `kem_decaps`). **Origin not elucidated at
this date.** Bench fixes:

- **Second measurement:** it no longer clears an exceedance (`scripts/rundenuit.sh`, `tests/test_c_temps.py`).
  It dropped its fixed values and its memory layout, so it did not retest the same thing.
- **`kem_decaps`:** the random class only used 8 keys out of 64 (`idx[i] &= NK - 1`).
  Fixed; earlier measurements concern 8 keys.
- **`aead`:** the classes were prepared differently (two system calls per input for
  one, `memcpy` for the other). New plans `aead_sym`, `aead_aa_fixe`, `aead_aa_alea`,
  `kem_decaps_aa`, measured by `./scripts/runspecial`, with and without ASLR.
- **Verdict of `./scripts/runspecial`:** it is judged on all seeds (permutation of F), no longer on a
  single repeated seed.

## Errata of 2026-11-02 (AEAD: key-dependent timing, fixed)

**`kem_decaps`: a bench artefact.** The original plan copied the fixed key from a single memory area, against 64 for the
random class. In the same binary, without ASLR, it exceeds 5 times out of 9 (t_p50: 9 out of 9), and the symmetric plan 0 times out of 9.
`kem_decaps` now measures the symmetric plan; the old one remains as a control (`kem_decaps_asym`).

**`aead`: a real dependency on the key, tied to the position of the state `w` of `duplex()` and `sl_aead_cle()` within a cache
line.** Measurements by `./scripts/runspecial`, 62.5 M or 12.5 M calls per point, threshold |t| = 4.5:
- **Sign and key.** The sign follows the key (aead_cle exceeds up to |t| = 29, aead_clair never). The gap is tiny: 0.2 cycle
  at most out of about 13 100.
- **Causality.** Forcing the stack layout makes the gap appear (6 out of 6) or disappear (0 out of 6) at will.
- **Position grid** (`--bloc grille` and `grille1`). The position of the key context has no effect. With a forced position of `w`,
  only 1 exceedance out of 96 measurements (t = 4.63, `w` at 32 bytes), while the controls of the same run exceed (t = −6.08 and
  +8.87, opposite signs depending on the seed). `w` at 32 bytes into a line keeps a weak bias, of constant sign whatever the key
  (24 measurements out of 24 positive, t from 0.8 to 4.6); at 0 bytes, |t| ≤ 1.98.
- **Fix.** Every 64-byte state `w` on the stack is aligned on 64 bytes (`sillage/c/brume512.c`, `brume512_avx2.c`). Outputs
  unchanged: `test_c_impl` 38/38.
- **Confirmation** on the fixed base binary (`--bloc confirme`, run 20261102_152718): 0 exceedances out of 24 measurements, in both
  stack layouts (aead_cle 4 seeds, aead_sym 2 seeds, 2 passes), |t| ≤ 2.16, mixed signs; +300-cycle control detected.

**Mechanism not identified** (Zen 3 processor): the alignment removes the gap, it does not explain it. Another microarchitecture or
another compiler may behave differently; dudect has to be redone on any new machine.

## Errata of 2026-11-02 (H1-P / H2-P, C code review)

**Theorem 1: a wrong proof step, fixed.** Game 1 bounded the loss due to key rejection by
a factor `1/(1 − ε_rej)` on the advantage of H1-P. This factor holds for a search problem, not
for a distinguishing advantage: acceptance depends on (x, y), which (h, s) determines, and the correct
bound keeps an additive term ε_rej (5 and 8 %). H1-P is now stated on the actual distribution of accepted
keys. The search version, for its part, does transfer, with a loss of at most 0.13 bit: ISD
costs are unchanged. The scheme, the KATs and the levels are unchanged (`docs/PREUVES.md` § 1 and § 2.1).

**Lemma 0 (new, proved): exact linear spectrum of H1-P and H2-P.** Every linear bias is
a product of Krawtchouk polynomials. Corollary: the parity of s (resp. of u) is the only linear
invariant, at every size. Until now, this was only measured on reduced instances. A
linear distinguisher amounts to finding a low-weight codeword. The estimate, heuristic, gives
139 bits for 128 and 267 for 256, at the level of ISD. Exhaustive verification in integers by
`tests/c/h1p_fourier.c` (6 checks). The artifact's measurements are reproduced:
`isd_reel` 5/5 (Prange 2^8.20, 2^10.16, 2^12.36; QC gain ×163), `kem_distributions` 11/11.
**H1-P and H2-P remain assumptions**: non-linear distinguishers are outside the proof.

**Theorem 16: reviewed again** (Lemma 15, the three BDPV conditions, composition); no defect
found, and `test_indiff_arbre` passes (15/15). This is again an AI review: the “under
validation” status stays until a human review.

**C code review (external, not published), follow-up finding by finding:**

| Finding | Status | Fix |
|---|---|---|
| C-01 scalar fallback not constant-time | **fixed** | `#error` without AVX2 or NEON; the table fallback requires `-DSL_REPLI_NON_CT` (only `test_c_simd` uses it, for comparison) |
| C-02 lengths missing from the APIs | **fixed at the boundary** | `sillage_c.py` checks pk, sk, ct, mu, x, y before any C call; the C API keeps its fixed-size contract, documented |
| C-03 profiles and levels | fixed (commit 55bb6aa) | — |
| C-04 unchecked allocations | **fixed** | `sl_malloc` / `sl_calloc`: a hard stop rather than a dereferenced null pointer; `sl_calloc` refuses the overflow of n × size (batches) |
| C-05 secrets not erased | fixed (55bb6aa) | — |
| C-06 `_Thread_local` caches | open | requires a context API; no effect as long as the OpenMP pool is stable |
| C-07 TE: capacity, partial mutation | **fixed** | all blocks validated before any correction (ct intact on −2); capacity of `corrections[]` documented |
| C-08 length overflows | **fixed** | roundings `len / B + (len % B != 0)` (TE, tree, parallel AEAD); `l1 + l2` bounded by the address space |
| C-09 internal preconditions | fixed (55bb6aa) | — |
| C-10 `ferror | fclose` | fixed (55bb6aa) | — |
| C-11 little-endian | fixed (55bb6aa) | `_Static_assert` in `sillage.h` |
| C-12 `-march=native` | open | build policy; C-01 makes any build without SIMD explicit |
| C-13 tests in CI | **extended** | the CI runs `revue_c` and checks the generated tables |
| C-14 domain of `sl_kem_borne` | **fixed** | returns 0 (no guarantee) if the weight of x or y differs from w |
| C-15 non-canonical public key | **fixed** | `sl_kem_encaps_det` refuses the padding bits of s (−3) |
| C-16 generated tables | **fixed** | CI job: `make tables` then `git diff --exit-code` (reproduced byte for byte locally) |
| C-17 `getrandom` / EINTR | fixed (55bb6aa) | — |
| C-18 public / internal header | open | a reorganisation with no effect on safety |
| C-19 guard allocator | fixed (55bb6aa) | — |

Checks: `tests/c/revue_c.c` (6/6); `test_api_c`, `test_c_impl`, `test_te`, `test_c_fuzz`, `test_c_simd`,
`test_kem`, `test_fonctionnel`, `test_robustesse`, `test_hachage_arbre`, `test_aead_parallele` passed.

## Errata of 2026-11-03 (cryptanalysis: invariants, key rejection, reduced-round BRUME)

**KEM key rejection rates: the values quoted were wrong.** PROOFS § 1 and § 2.3 (and the previous errata) gave
“5 % and 8 %” for Sillage-128 and Sillage-256. Measured on 32 768 and 8 192 keys drawn as by `KeyGen` (`tests/c/kem_rejet.c`):
**7.1 % ± 0.14 and 5.9 % ± 0.26**, in the opposite order. No consequence for the statements: the loss on ISD costs for accepted keys is
log₂(1/(1 − ε_rej)) ≤ 0.11 bit (0.13 stated). Values corrected in PREUVES, PROOFS and the cryptanalysis plan.

**Rejection and the public key (attack C4 of the plan): no trace.** Five non-linear statistics of s (weight, transitions at steps 1 and 2,
triples of ones, `wt(s ∧ z⁷s)`) do not separate accepted from rejected keys: |z| ≤ 1.79 against a threshold of 4.5 (detectable shift: 0.10 and
0.21 standard deviations of one key). A detection test, not a proof of H1-P on accepted keys.

**Non-linear invariants of BRUME (attack A6 of the plan): excluded by computation.** Criterion of Beierle, Canteaut, Leander and Rotella:
dim W_M(D) = 512 with the 31 inner constants, three consecutive constants suffice; no invariant common to all rounds,
whatever the S-box (`tests/c/invariants.c`, PROOFS § 4.2 bis). Outside the criterion remain invariants that vary from round to round and
closed-loop invariants.

**BRUME at 2 rounds: capacity recovered in ≈ 2^97 (attack B3 of the plan).** Guess-and-determine on the bipartite structure
(rate = half A, capacity = half B, generators all reflections): each rate nibble depends on 6 unknowns after 2 rounds,
width 24, model validated on the real BRUME (oracle of 21 unknowns, 24 states out of 24 recovered, deviation ≤ 1.2 bits). SAT topped out at
128 unknown bits. At 3 rounds, 63 unknowns out of 64 per equation: the method stops. Preimage at 2 rounds: 2²⁰⁴, above the generic bound.

**Minimal number of active S-boxes, exact model.** Bit-level linear layer, actual DDT and actual LAT (SAT, `tests/c/sat_trails.c`):
exactly 8 over 2 rounds, reached; 3 rounds undecided at 600 s for K = 13 to 20. No improvement of Proposition 10 within this budget.

Checks: `invariants` 5/5, `kem_rejet` 6/6, `brume_gd2` 4/4.
