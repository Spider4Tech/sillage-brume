# BRUME-1024q — roadmap

Written on 12 November 2026, **rewritten on 13 November 2026**. Work concerns **this prototype only** (`b1024/`):
BRUME-512q is abandoned, and the suite (`sillage/`) is not modified.

**Rules of the author:**
- no security is traded for a negligible gain;
- **better to over-verify than to under-verify**.

Status legend:
- **to do**: not started;
- **in progress**;
- **done**: done and checked;
- **author**: the decision is the author's.

**v0.6 (decision of the author, 13 November 2026): BRUME-1024q replaces BRUME-512 in the suite** (`docs/MIGRATION_V06.md`).

**Order.**
1. The AEAD, now corrected (SpongeWrap orientation): verify it widely, then write its proof.
2. Verify the implementation by every independent means available.
3. The cryptanalysis of the permutation.
4. A dossier for an external review.
5. Performance, which is now secondary: the main gains are obtained (§ 5).

## 1. AEAD — verify widely, then prove

| Item | Status | Detail |
|---|---|---|
| **SpongeWrap orientation** | **done** (13 November) | Encryption XORs the plaintext into the rate, which then holds the ciphertext. Decryption overwrites it with the ciphertext. Same speed. The 4 AEAD KATs with text changed; the 14 others are identical. `aead_lot32` and `aead_lot256` were adapted. Checked against a **literal transcription of DMV17's Algorithm 1** (`aead_kd`), encryption and decryption, partly with the dense permutation. 17/17 checks; mutations caught (old orientation in `aead()` or in the batch only, full-rate flag in the reference) |
| **Local 8-hour campaign, resumable** | **done** (13 November), no interruption: see `resultats/campagne_locale_20261113.md` | `campagne_locale.sh`: the local machine can switch itself off. All state is on disk (`~/orion_local8h`), and relaunching the same command resumes it: finished units are skipped, the mutation score resumes mutant by mutant, and the deadline is kept. No automatic relaunch. Units: compiler diversity, sanitizers, Valgrind, lengths beyond 2^32, threads, mutation score, then prolongation of the AEAD modes with seeds other than songbird's |
| **8-hour campaign on songbird** | **done** (13 November): **conforming** | Results in `resultats/campagne_aead_songbird_20261113.md`, and with the local campaign: 739 million equivalence cases against the literal DMV17 reference (511 000 with the dense permutation), 2.7 billion forgeries with none accepted, 3 billion avalanche cases (max \|z\| = 3.2, no violation of the SpongeWrap structure), 1.6 billion messages for bias (8.2 × 10^12 keystream bits, max \|z\| = 4.4 over 5 376 positions). Witnesses detected. The automatic verdict "ÉCHEC" was a false alarm: leaks of the suite's result harness, now filtered (`lsan_harnais.supp`). Design notes below |
| (design notes of the songbird campaign) | — | `campagne_aead.c` and `campagne_aead_songbird.sh`. Phase 1: checks, ctgrind, dudect (including the verified decryption, accept and reject paths). Phase 2, until the deadline, on 15 processes: **equiv** (`aead()` ≡ literal DMV17 reference, random sizes concentrated on the boundaries), **forge** (20 kinds of forgery, all must be rejected and wiped), **multi** (256- and 32-batches ≡ one message), **aval** (avalanche on tag and ciphertext, and the structural property of SpongeWrap), **biais** (keystream and tags with counter nonces or keys: bias per bit position, χ² of bytes and of byte pairs). Every detector is first run against a planted defect (forge: 1 169 forgeries accepted by a faulty decryption; aval: z = 24.6; biais: z = 11.9) |
| **Write the AE step** (ideal XIF → privacy, authenticity) | **done** (13 November, evening) | `AEAD_SECURITY.md` § 4 bis: a full reduction of the AE game (nonce-respecting, no RUP, multi-user) to DMV17 Theorem 1, with a hop KD → IXIF, then IXIF → ideal (identical until a valid decryption), and the forgery by case on the final path (new path: 2^−256; an encryption's final path: the decoder gives the same (A, C), so the tag differs). **Result: Adv ≤ 2σ_D·N/2^384 + 2(N+1)/2^384 + q_iv·N/2^512 + q_d/2^256 + negligible terms.** Encryption data do not erode it; the decryption calls do (L + Ω ≤ 2σ_D). **The regime L = Ω = 0 asserted on p. 610 is NOT obtained**: it would need an analysis of the AE game itself. The facts the proof uses are checked by two new checks (24 in all, planted defects caught): decryption path = encryption path, decoding of the final path, roles of the calls |
| **Check DMV17 Theorem 1 for our parameters** | **done for our parameters, and re-checked** (13 November, night) | `AEAD_SECURITY.md` § 4 quater: every step of the proof (Lemma 2, §§ 6.1–6.4) checked against the text, and the places where the flag enters (§ 4 ter). **Two steps are false as written, each shown by a simulation on a reduced model** (`dmv17_verif/`): (F2) the bound on the s-collision event of Lemma 2 is exceeded by 20σ when a flagged query copies the most loaded outer value (witness with a random value: −19σ); repaired by C(M−L, 2)/2^r. (F3) The bound ν/2^c on Pr(μ_fw > T_fw), claimed for the real world O, is exceeded 28-fold by a state-recovery adversary within the theorem's resources (L = Ω = 0, N + M ≤ 0.1·2^c); repaired by Pr_O ≤ Pr_P + Δ with threshold T_fw + 1. The re-check also found the same gap in P (states repeat after an s-collision in RD), now covered by 2·(Lemma 2′). **(F1), a suspicion on term (26), was withdrawn**: the unconditional per-pair probability is 2^−b, so the paper's bound holds. (F4) For M − L ≤ 2^127, a birthday bound replaces §§ 6.5–6.6. Theorem 1 itself is not shown false. **Theorem 1′** is one bit weaker; the AE bound is (2σ_D + 5)·N/2^384 (with L ≤ q_d, Mennink 2023) + 2·q_iv·N/2^512 + q_d/2^256 + negligible terms. Second pass: F2 computed exactly (ratio to the written bound 1.03–1.18, witness always below), tighter repair Lemma 2″ checked exactly; F3 reimplemented independently, predicted analytically (agreement), ratio 11 / 28 / 36 at c = 10 / 12 / 14. Lemma 2's statement and Theorem 1 are not shown false. **Mennink, ToSC 2023(2), read (14 November):** his "certain issue" concerns the same sentence as F2 but the other way (too pessimistic for Ascon-PRF); the independent bound of Dobraunig–Mennink 2019 has the ν·(L+Ω)/2^c term that F2 finds missing, so F2 agrees with it; F3 is not mentioned; his Theorem 7 is our AE step (independent confirmation, tighter L ≤ q_d now used); the generic attack of Gilbert et al. (EUROCRYPT 2023, 2^{3c/4} with many decryptions) refutes our heuristic on σ_D·N, now withdrawn. **DMV17 full version (ePrint 2017/498) read (14 November): same text for F2 and F3, no correction. DM19 read: its independent proof handles F2 correctly (ν·(L+Ω) term); it has the same unconditional writing as F3 in (18c) (our simulation exceeds it 20-fold), but there the repair is free, so DM19's theorem stands. GBKR23 read: its generic attack (2^{3c/4}, key recovery) meets both its conditions in our mode, but needs ciphertexts of 3·2^{c/2} blocks, beyond our 64-bit length encoding; proposed (author): state |A|, |M| < 2^64 bytes in SPEC.md and reject longer inputs.** Novelty of F2 and F3 established only with respect to these four texts. Then a human review; telling the authors is an author decision |
| **A second implementation, portable** | **done on x86-64 and ARM64** (qemu, gcc 15 aarch64: 18/18) | `spec_ref.c`: portable C written from `SPEC.md` alone, sharing no function with `brume1024.c`. It checks the fingerprint of the tables and re-derives the round constants. **It reproduces the 18 test vectors**, including the 100- and 300-leaf trees, which the dense reference could not afford. The same author wrote the spec and both implementations: the independence is in the code, not the author. Previous detail | Scalar C without AVX2, written from `AEAD_SECURITY.md` § 1 and `DOMAINS.md` alone: the KATs must match. Also built for ARM64 (qemu and gcc-aarch64 on songbird) |
| **Q1** | to do | Look for a usable quantum result on the keyed duplex; until then the level stays heuristic and labelled as such |
| Nonce reuse | **done** (13 November, evening) | Exact leakage written (`AEAD_SECURITY.md` § 4 (e)): the keystream of block t is the same for two messages **if and only if** their paths before t are the same, so c ⊕ c' = m ⊕ m' up to and including the first block whose padded entry differs, and nothing after; a prefix message gives a prefix ciphertext. Check `nonce_reutilise_fuite_exacte_…`: measured on `aead()`, predicted by the recorded paths, both directions, AAD 0/79/80 × texts 0 … 200 bytes × 4 kinds of second message (1 269 blocks predicted equal); planted defects caught |
| **Maximum lengths in `SPEC.md`** | **written in SPEC.md** (14 November, author's decision); **implementation to do**: `aead()` / `aead_ouvrir()` must reject \|A\| or \|M\| ≥ 2^64 bytes, plus a check | Write \|A\|, \|M\| < 2^64 bytes (already implied by le64) and reject longer inputs. The generic attack of Gilbert et al. (EUROCRYPT 2023), whose two conditions our mode meets, needs ciphertexts of 3·2^{c/2} blocks: the limit keeps its published form out of reach (`AEAD_SECURITY.md` § 4 bis) |
| Pass the remark on the suite's Theorem 14 (remark 2) on to the human review of `docs/PROOFS.md` | to do | The suite keeps the plaintext-overwrite orientation, and its σN/2^c bound is consistent; DMV17's improvement does not apply to its encryption blocks |
| **Length limits** (`SPEC.md` § 3.5) | **done** (14 November) | `aead()`, `aead_ouvrir()` and `aead_multi()` return −1 and touch nothing when \|A\| or \|X\| exceeds 2^63 − 1 bytes, or when n·\|X\| does. This bound is stricter than the SPEC's 2^64 − 1: the block loops' index computations (`i + RB`, `b·RB + k`) overflow beyond 2^64 − 81, and the last block would then reread the start of the buffer. Check `longueurs_hors_limite_rejetees_sans_lecture_ni_ecriture` (27 checks): real buffers of a few bytes with guard bytes, the limit itself admitted, lengths 2^63, 2^64 − 1 … rejected. Six planted defects are caught (guard removed in `aead()` or `aead_multi()`, n·len or 64·n unchecked, off-by-one, wiping on rejection). KATs unchanged |
| Merging the length block (4 → 3 permutations) | **feasibility assessed** (14 November, `AEAD_SECURITY.md` § 6 bis); **author decision** | The argument transposes as it is: the encoding is already injective without the length, and the final role becomes `DOM_TEXTE`, which no keystream path ends with. The bound keeps its form, with one call fewer per query. Recommended: plain removal (option A). Estimated gain: −25 % below 80 bytes. Cost: 5 AEAD KATs, about ten places in the code, and re-verification |

## 2. Implementation — over-verify

| Item | Status | Detail |
|---|---|---|
| Sanitizers | **done** (no memory error; harness leaks filtered by `lsan_harnais.supp`) | ASan and UBSan: every campaign mode clean on songbird (13 November); the battery under sanitizers in both 8-hour campaigns (gcc 15 on songbird, gcc 13 locally) |
| Valgrind memcheck on the whole battery | **done** | No invalid access, no uninitialised value. Only known leaks: the result harness of the suite and libgomp's per-thread storage, now filtered by `valgrind.supp` (0 errors with it, 22/22) |
| **Mutation score** | **second pass done** (13 November): **86.5 %**, then **≈ 87.0 %** after two new checks; every survivor classified (`resultats/mutation2_1024q.md`) | **First pass:** 80.3 % (1 545 of 1 922 compilable mutants caught, 377 survivors, read one by one). Most survivors are equivalent mutations, the rest one-cell overflows. Seven real gaps were found and filled on 13 November (22 checks now): scheduler thresholds of the tree, several bitsliced batches and the remainder handled message by message in `aead_multi`, DMV17 reference beyond 255 and 65 535 bytes, the allocation check reusing an old output buffer and counting an injection without a real failure, the cache of P(IV) when the rounds change (**latent defect found and fixed**: `BS_IV` was only prepared for the start-up rounds, and the P(IV) cache could be filled by several threads; `arbre` now refreshes both outside any parallel region), the return value of the tree, the default rounds. **Second pass** (`mutation_songbird.sh`): all mutants against the 22 checks, then the survivors under ASan and UBSan. **Pass 1 done: 81.9 %** (1 580 of 1 929 compilable mutants caught, 349 survivors). **ASan/UBSan on the first 70 survivors: 19 more caught** (one-cell overflows of tables and loops), 51 survive (mostly sizes of arrays and of function parameters that do not change the code, and rotation constants `(128 − K) % 128` → `% 129` or `% 127`: equivalent mutations, read in `ROTM`: for K ∈ {105, 71, 76, 72, 31}, 128 − K < 127 so both moduli give the same value, and for K₀ = 0 a rotation by 128 selects the register (c + 4) % 4 = c with a shift of 0, the same as 0); combined 82.8 % so far. All 349 survivors were run under ASan (songbird [0, 140), local machine [140, 349), same archive): 88 more caught, so 86.5 %. The 261 final survivors were read: 237 are equivalent, and 13 are in tables used only by `bench_lot.c`. **11 were real test gaps, now filled** (26 checks): (G1, 7 mutants) one-element overflows hidden by oversized test buffers, in the fallback of `feuilles()`, the tail of the tree, the 256-batch AEAD (fallback and main path), and the key read by the DMV17 reference. They are now caught by exact-size buffers with guard bytes (`tampons_exacts_…`). (G3, 4 mutants) the P(IV) cache disabled, which would recompute P(IV) inside parallel regions; now caught by a counter (`cache_piv_aucun_recalcul_…`). The 8 representative mutants were re-applied to the new source and are all caught. A third full pass on the 26-check source was not run. Earlier detail | `mutants.c`: 2 010 mutants of the library part of `brume1024.c` (operators, integer constants ±1, intrinsics, deletion of an assignment). Local campaign, unit F, 7 processes. **The rehearsal already found a gap:** the one-message-per-task path of `aead_multi` (fewer than 32 messages per thread) was never exercised by the checks; a 5-message case was added and the mutant is now caught. Every survivor will be studied: missing test, or equivalent mutation |
| Compiler and flag diversity | **done** (gcc 16 at -O0, -O2, -O3, `x86-64-v3`; gcc 13; gcc 15 on songbird: 17/17, KATs identical; clang not tested: no `omp.h` in the container) | Local campaign, unit A: gcc 16 at -O0, -O2, -O3 and `x86-64-v3`; gcc 13 and clang in the `tgh` container. Each build runs the 17 checks and regenerates the KATs, which must be identical. gcc 15 on songbird |
| Determinism across thread counts | **done** (147 000 cases identical from 1 to 12 threads) | Local campaign, unit D (`campagne_aead fils`): tree and multi-message AEAD with 1, then 2, 3, 5, 8 and 12 threads, for 40 minutes |
| Large lengths | **done** (conforming) | Local campaign, unit E (`campagne_aead grand`): AEAD of 2^32 + 1 234 bytes ≡ the literal DMV17 reference, round trip, a tampered byte rejected and wiped; tree of 2^32 + 3·8 192 + 7 bytes: bitsliced batches ≡ sponges ≡ one thread |
| dudect on both machines with the new operations | in progress | Songbird in the campaign; the 5600G at rest afterwards |
| Allocation failures | **done** | Fallbacks without allocation (same outputs) or an error reported (tree root), with an injection point; check `echecs_d_allocation_injectes_…` |
| Verified decryption, boundaries, tampering | **done** | `aead_ouvrir`, 383 alterations, crossed AAD × text boundaries at 0, 1, 79, 80, 81, 159, 160 and 161 bytes |

## 3. Cryptanalysis of the permutation (before any adoption)

| Item | Status | Detail |
|---|---|---|
| Differential and linear: characteristics | **done** | B = 8 exact; C3 ≥ 21 certified (two LRAT checkers). At least 218 active S-boxes at 32 rounds, 190 after 4 free rounds. These are bounds on characteristics, not on differentials |
| **Aggregation (differentials, hulls)** | **done** (13 November, laptop, `resultats/agregation2_1024q.json`) | `agregation2.c`: **exact** 2-round differentials (one active nibble, then 7) and linear hulls (7 active, then 1), all characteristics aggregated, by an exact branch-and-bound over the endpoints, with the round constants (they matter for the signs of the hulls). **Max DP₂ = 2^−16 = the best characteristic** (no aggregation at the maximum; ratio ≤ 1.5, on 350 of 3 840 entries); **max hull correlation 2^−7.83 against 2^−8** for the best trail (2 trails per hull, ratio ≤ 1.125). Park et al.'s proved bound: MEDP₂ ≤ 2^−15. **Confirmed on the real permutation at 2^31 samples** for 16 entries (8 differentials, 8 hulls; the maximal ones and random ones): max \|z\| = 1.65. Other 2-round shapes (k, 8 − k) are not enumerated: Park's bound covers them |
| **Cube and zero-sum experiments** | **done** (13 November, laptop, `resultats/cubes_1024q.md`, plus a confirmation run) | `cubes_degre.c`: sum of the output over a cube of d input bits after r rounds (bitsliced; checked equal to sums computed state by state with `perm1` in 12 cases). Grid d = 8 … 32, r = 3 … 8, three shapes (ball in the graph, whole nibbles, scattered bits), 4 cubes each, and d = 36 for the ball. **Reach: 5 rounds.** At 4 rounds, every shape sums to zero on all 1 024 bits from d = 20 to 28. At 5 rounds, scattered-bit cubes keep a strong bias: 983 of 1 024 bits on average at d = 32 (16 cubes, another seed; 2 of 8 cubes of the grid at 1 024), while balls and nibbles are near 512 (balls of 36 bits: 588–596). **At 6 rounds, nothing**: 192 cubes of dimension 24 (3 shapes × 64, another seed) average 510–514 with a standard deviation of 13–17, as for random sums (512 ± 16); the grid's maximum of 562 was not reproduced. 32 rounds leave 26 rounds beyond the observed reach (integral attacks may add rounds at both ends: the exact division property below) |
| **Boomerang** | **3 rounds done** (14 November); 4 rounds running (second machine's GPU, 2^36 quartets per combination) | `gpu/boomerang1024.cu` and `gpu/brume1024.cuh`: port of the suite's GPU bench to 256 nibbles (tables read as `constexpr`, M by its 7 edges per vertex, dense M⁻¹ as a 1 024 × 1 024 binary matrix applied to both states of a pair). **Conformity:** P_R and P_R⁻¹ against 112 vectors of `brume1024.c`'s dense reference (`gpu/vecteurs_b1024.c`), and the first 4 096 quartets of each combination recomputed on the CPU: 0 differences, on two GPUs (sm_89 and sm_75). **3 rounds:** a scan of 900 combinations (i, j′ ∈ {0, 128}, a, d′ ∈ [1, 15]) at 2^22 quartets, then the best confirmed at 2^30: **2^−19.41** for (i, a, j′, d′) = (0, 14, 0, 13), 4σ Wilson interval [2^−19.56 ; 2^−19.26], against 2^−8.77 at 512. Every return is truncated (only nibble i differs). The scan's maximum overstates: (128, 3, 128, 6) gave 2^−20.4 in the scan and 2^−23.66 at 2^30. `resultats/boomerang1024_r3_*.txt` |
| **Exact division property** | to do | Cube and zero-sum experiments first (the reached degree), then the exact reach (CP-SAT model of 512, decomposition of Theorem 12 sexies, twice as large) |
| Impossible differentials, zero correlations | **done** | 5 rounds, as at 512 |
| Degree | **done** (bound) | Boura–Canteaut, γ = 3: 11 rounds per direction (22 inside-out) |
| **Statistical battery on the permutation** | **done** (14 November, laptop, `resultats/stats1024.json`): **conforming** | `stats1024.c`: the suite's battery (`tests/test_c_statistiques.py`, `test_c_sac.py`) ported to C. **Streams** (34 NIST-type tests, Bonferroni and KS on the p-values): counter mode on P₃₂, 1 GiB, indistinguishable (p_min 0.020, Bonferroni 0.69, KS 0.44); XOF, 256 MiB, indistinguishable; reduced rounds, 256 MiB each: **distinguished up to 4 rounds, not at 5, 6, 8**, as BRUME-512 (statistical reach 4). **Strict avalanche**, full 1 024 × 1 024 matrix: forward indistinguishable from **5 rounds** (2^16 samples per input; 4 rounds: max \|z\| = 256), inverse from **2 rounds** (2^14), as BRUME-512 (5 and 2); 32 rounds indistinguishable both ways. Witnesses: splitmix64 passes; a stream with one bit in 512 forced fails, and one with a lag-32 correlation fails. The fast inverse (binary matrix) is checked against `ref_tour_inv` |
| Quantum analysis of the constructions | to do | From `README.md` § 5: hash and tree (BHT 2^128 on the capacity, 2^170.7 on a 64-byte CV), AEAD in Q1 (§ 1), and the proved bounds in min(r, c) = 384. Keep proved, generic and heuristic apart |

## 4. Dossier for an external review

| Item | Status | Detail |
|---|---|---|
| `SPEC.md`, a self-contained specification | **done** (draft v0.6-1, 13 November) | Normative: S-box, GF(2⁴), graph and coefficients (with a SHAKE256 fingerprint of the tables), round constants (re-derived independently with Python's hashlib: identical), round, frame, sponge, XOF, tree, AEAD in the SpongeWrap orientation, test vectors. Informative: separation, security claims with their status. Previous detail | Generation of the parameters, the round, the modes, the AEAD, the bit layouts, written so that an independent implementation can be done from it alone (§ 1, second implementation) |
| Test vectors as text | **done** (`kat_b1024.txt`) | The 18 KATs, with their inputs, in a hex file independent of the C header |
| A canonical measurement table | to do | One table, dated, with machine and campaign, to which `README.md`, `LEADS.md` and the Dossier refer, instead of repeating figures |
| Clean the outdated statements | **done** (13 November) | 22 → 17 gates; "bitslicing not measured"; 17 → 18 KATs in `DOMAINS.md`; position of the nonce (16 bytes in the rate, 8 in the capacity); explanation of the bitsliced-batch threshold; algebraic proof of the translated S-box circuit (`README.md`) |

## 5. Performance (secondary)

**Outcome.**
- The bitsliced kernel (×1.9–2.15 on the tree on one core) and the bitsliced multi-message AEAD are in place.
- The tree beats the classical suite on both machines.
- The one-state kernel is at about 84 % of its floor.
- The bitsliced kernel is limited by instruction throughput.

| Item | Status | Detail |
|---|---|---|
| S-box in 16 gates | in progress | SAT search on songbird (2 hours per instance) if it still runs; 17 gates installed |
| Less bitsliced code | open | Reuse the fused body for the last round (−101 KB) |
| Smaller batches (128 states, `__m128i`) | open | Same throughput expected on Zen+, half on Zen 3 |
| Merging the length block | **author**, after § 1 | See § 1 |

## Done before 13 November (summary)

- **Stabilisation:**
  - 18 frozen KATs, regeneration refused if the kernel and the reference disagree;
  - domain-separation table and checks;
  - dudect and ctgrind on both machines;
  - reproducible benchmarks.
- **Bitsliced kernel and tree:** see § 5.
- **Analyses of the 32-state kernel:** variants timed (compact loop, fusion, 64 states), and the op-cache hypothesis
  rejected on Zen+ and Zen 3.

## Appendix A. Suggestions of the first review removed, and why

| Suggestion | Why it is removed |
|---|---|
| "Create a separate full-state keyed duplex prototype" | Already done, inside the prototype, with checks against the dense reference. A separate copy would duplicate the code without testing anything more |
| "Reduce memory loads" (as the main lever of the tree) | Measured since: the limit was the throughput of `pshufb`. Bitslicing removed it (§ 4) |
| "Study an 8- or 16-state version" | For throughput, fewer states per batch keeps the same instruction count per output nibble and processes fewer states per instruction: it can only lose. Medium sizes are handled by the scheduling rule |
| "Test messages from 0 to 256 bytes" | Done (`BENCH_1024Q.md`) |
| "Generic differential and linear attacks" | Kept only for what is not covered: characteristics are certified, aggregation is not |

## Appendix B. Second review (GPT, 12 November): what was checked and kept (priority numbers of that time)

The review read versions of the documents from before priority 1 and before the bitsliced kernel. Each point was checked
against the current files.

| Point | Verdict | What was done |
|---|---|---|
| A. `WIDTH_ANALYSIS.md` still shows the first 1024 set (K = {0, 83, 56, 51, 17, 42}, λ\* = 3.927, balls … 125, 222) as if it were the permutation | **Pertinent** (verified: § 2 and § 2.1 present it without saying it was superseded; only § 6 bis does) | Marked as the first selection, superseded, with the final set beside it |
| B. The README's comparison table measures the old AEAD (5 permutations, 3.89 µs at 64 B) | **Pertinent** (verified: the table and its reading still say 5 permutations) | Remeasured on both machines with the current AEAD (4 permutations) and the bitsliced tree |
| C. KATs not frozen | **Outdated** | Done in priority 1 (18 KATs) |
| D. "Several squeeze blocks" for the digest is inherited from BRUME-512q (abandoned since 13 November) | **Pertinent** (verified: `WIDTH_ANALYSIS.md` § 1.1 (a) and consequence 5). At r = 640 the 512-bit digest is one squeeze block, truncated to 512 of 640 bits | Corrected. Theorem 1.1 covers an r-bit output; a truncated output needs its own argument (generic BHT on 512 bits: 2^170.7) |
| E. Separate the generic quantum attacks (BHT 2^128 on c = 384) from the loose proved bounds (2^42.7, 2^74.8) and from what is not demonstrated | **Pertinent** (`WIDTH_ANALYSIS.md` already separates them; the README's AEAD argument did not) | Kept as a rule for priority 3; the AEAD argument was withdrawn (priority 2) |
| F. The FKD security is not established by the DMV17 reference alone | **Pertinent.** The README called rate-only absorption "a special case" with no demonstration, and did not mention overwrite | Priority 2, with the specification above |
| G. AEAD boundary tests at 80 and 160 bytes, crossed AAD/text | **Partly pertinent** (79/80/81 are tested on the text, not 159–161 nor the AAD at the boundaries) | Priority 1 |
| H. AEAD tampering protocol, and no plaintext released before the tag is checked | **Pertinent** (verified: no verified-decryption function; the caller compares) | Priority 1 |
| I. Constant time not verified | **Outdated** | dudect and ctgrind done (priority 1) |
| J. Do not spend days optimising the tree while the AEAD is not formalised | **Agreed for what remains.** The bitsliced kernel was done before this review, at the author's request | Remaining performance items moved to priority 4 |
| K. Do not go to 2 048 bits, do not raise the rounds now | **Agreed** | No change of parameters planned |

## Appendix C. Third review (GPT, 13 November): what was checked and kept

| Point | Verdict | What was done |
|---|---|---|
| Stale statements: 22 gates in the file table and the S-box section, "bitslicing not measured", 17 KATs in `DOMAINS.md`, circuit versions mixed in this roadmap | **Pertinent** (verified) | Corrected (§ 4) |
| Explain how the bitsliced batches handle fewer than 256 leaves | **Pertinent** | No padding: only full batches of 256, the rest goes to 32-batches or sponges (`README.md`, scheduling) |
| The nonce straddles the rate (16 bytes) and the capacity (8 bytes) | **Pertinent** (verified: bytes 64..87, rate up to 79) | Stated in `DOMAINS.md` and `AEAD_SECURITY.md`; without effect on DMV17 (iv = the last b − k bits) |
| Decryption returns the plaintext and leaves the comparison to the caller | **Outdated**: `aead_ouvrir` existed since the morning of 13 November | Its rule is now in the README: the only decryption to expose |
| Write `AEAD_SECURITY.md` and read DMV17 in full | **Done** before this review, then **revised**: the SpongeWrap orientation was adopted | § 1 |
| Algebraic proof of the S(x ⊕ 3) ⊕ S(3) circuit with the adjusted constants | **Pertinent** | Written (`README.md`, bitsliced section) |
| Tests of allocation failures | **Pertinent** | Fallbacks and an injection point (§ 2) |
| Cryptanalysis order: hulls, then boomerang, then division property | **Agreed** | § 3 |
| Do not touch width, S-box or rounds | **Agreed** | No change |
| Canonical measurements in `LEADS.md` and elsewhere | **Pertinent** | § 4 (canonical table) |
