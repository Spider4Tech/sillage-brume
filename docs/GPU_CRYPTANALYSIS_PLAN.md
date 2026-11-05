# GPU cryptanalysis plan — SILLAGE v0.4

Written on 2026-11-02. Hardware: RTX 4070 Ti (12 GiB, driver 615), Ryzen 5 5600G. Status: **plan**; campaign no. 1 (differential-linear, `tests/gpu/campagne_dl.cu`) started on 2026-11-02 and was interrupted by a GPU hardware instability.

## 0. Goal and ground rules

We attack the suite as an outside cryptanalyst would. Nobody breaks a 32-round permutation on 512 bits in a week, nor
an ISD at 2^138. The realistic goal is therefore threefold:

1. **Reduce the measured margin.** Find the best real attacks on reduced-round and reduced-parameter versions,
   and push them as far as possible. This is how NIST candidates or Keccak are judged (the “crunchy contest”).
2. **Validate the cost models at a scale 2^15 to 2^20 times larger than today.** Quasi-cyclic ISD is only measured
   up to n = 149 (`tests/c/isd_reel.c`). The BRUME distinguishers stop at 2^36 inputs.
3. **Look for the structural flaw that no small-scale test can see.**

Rules:
- **All code is in C and CUDA C**, in `tests/gpu/`, and nothing in Python (project rules of 2026-10-29 and 2026-10-31).
- **Every GPU kernel matches the C code byte for byte** (KATs, `sl_brume_permute_ref` round by round) before any campaign.
- **The GPU never runs during a dudect measurement** (`scripts/runspecial`, timing part of `scripts/rundenuit.sh`).
- **Long campaigns can be resumed.** A checkpoint is written every 10 min, the JSON is rewritten after each
  experiment and the power is capped (`nvidia-smi -pl`, to be set from the host). An interruption must no longer cost anything.
- **Campaigns longer than 2 hours are prepared, then started by the maintainer**, like `scripts/rundenuit.sh`.
- **Any fix that would change the outputs (KATs) is submitted to the maintainer first**, and nothing in `sillage/` is changed without agreement.

## 1. Weaknesses inherent in the design: where to strike

| # | Component | Design property | Why it is a target |
|---|---|---|---|
| F1 | BRUME | B = 8 nibbles over 2 rounds, i.e. **at least 4 active S-boxes per round out of 128** | The proved bound is very low (3 % of the S-boxes). The whole margin rests on the gap between this bound and the actual best trails (44 active measured at 3 rounds, against 12 proved). This gap is not certified. |
| F2 | BRUME | 4-bit S-box, **degree 3**, max BCT 10/16 | The degree grows slowly: the division property holds 10 rounds per direction. The boomerang only costs 2^−0.7 per S-box in the middle. |
| F3 | BRUME | **Unkeyed permutation**, fixed constants (SHAKE) | The Markov model is only an assumption. Attacks that exploit the actual values (differential-linear, clustering, non-linear invariants) are not covered by the bounds. |
| F4 | BRUME | Linear layer sparse forward (7 terms), **dense backward** | Asymmetry: attack on the forward side (5 rounds measured against 3 backward). Inside-out, put the fewest rounds on the backward side. |
| F5 | BRUME | One permutation for everything: hashing, AEAD, the KEM's G/H oracles, the signature's hashes | A distinguisher on P affects all three primitives at once. Hashing, being unkeyed, is the most favourable playing field for the attacker. |
| F6 | AEAD | **Overwrite** duplex, c = 256 in BRUME-512 | The nonce is separated from the first keystream by 2 full permutations, so the initialisation is out of reach. In the data phase, rate input and output are known on either side of a single permutation, which is the state-recovery setting (1 round already broken). |
| F7 | KEM | Quasi-cyclic, very sparse (w = 75, n = 50 021), cascaded noise e1 ⊕ π(e2), truncated v | The QC credit and the estimator are only validated up to n = 149. BJMM is never measured at a size where it beats Dumer. |
| F8 | KEM | δ proved by a Chernoff bound at fixed θ, keys rejected (7.1 % and 5.9 %, measured) depending on the secret | If the bound or its implementation (rounding to 2^12, threshold c > 15) were wrong, failure attacks (GJS, failure boosting) would again become threat no. 1, as for HQC. |
| F9 | SIG | MPCitH over binary SD of rate 0.7, five-pass Fiat–Shamir | The Kales–Zaverucha bound is only tested on a toy model (N = 4, τ = 3). The binary instance has never been analysed by a third party (PROOFS § 6). |

## 2. Phase 0 — Infrastructure (1 session, prerequisite for everything else)

**Status on 2026-11-02: items 1 and 2 done.** CUDA 12.9 (`nvcc`, runtime) is installed in `tgh`, without the driver library.
`tests/gpu/brume.cuh` processes one state per thread, without register spilling, and `tests/gpu/brume_gpu.cu` checks it
(`make -C tests/gpu && tests/gpu/build/brume_gpu`):
- **Conformance, 4 checks out of 4:** forward identical to `br_tours_avx2` for R = 1 to 32 on 2^20 states; intermediate rounds and backward
  identical to the dense reference `tests/c/brume_ref.h`; a 32-round round trip equal to the identity on 2^20 states.
- **Measured throughput:** 2^27.26 full permutations per second, **2^29.94 at 5 rounds**, 2^27.04 at 5 rounds backward. Backward is slower,
  M⁻¹ being dense. This is about 60 times one AVX2 core (0.39 µs per permutation). Bitslicing (about ×4 expected) is kept in
  reserve, to be done if a campaign is limited by it.

1. **CUDA in the `tgh` distrobox.** `nvcc` is missing there. Install `cuda-toolkit` (NVIDIA repository, Ubuntu 24.04, target `sm_89`).
2. **`tests/gpu/brume.cuh`: BRUME-512 on GPU, bitsliced**, 1 to 32 rounds, in both directions.
   - **Cost of a round:** the S-box in gates and M as XORs of 4×4 matrices over GF(2), i.e. about 350 operations per state and per round.
   - **Expected throughput:** of the order of 2^30 full permutations per second and 2^33 at 5 rounds, **to be measured**. Registers
     are the constraint: work in slices of 16 or 32 states per thread. A fallback with tables in shared memory exists.
   - **Check:** conformance to `sl_brume_permute_ref`, round by round, on 2^20 random states and on the KATs.
3. **`tests/gpu/gf2.cuh`: batched Gaussian elimination over GF(2)** (one matrix per block, M4RI style), for ISD.
4. **(Done.) `scripts/rungpu`, a launcher modelled on `scripts/runspecial`**: `--statut`, `--arreter`, resume, one `BILAN.md` per campaign and
   `resultats/gpu/<campaign>.json`. It refuses to start if `scripts/runspecial` or dudect is running.
5. **Controls in every campaign:** an instance within the known reach, which must be detected, and a random instance, which must
   not be.

## 3. Phase 1 — BRUME, distinguishers (high priority: F1 to F5)

**Campaign no. 1, started on 2026-11-02 at 16:17** (`./scripts/rungpu`, `tests/gpu/campagne_dl.cu`, about 6 h 30): A2 and A3 on the same
histogram of aligned differences, 128 nibbles × 16 values, giving the χ² per nibble and the 1 920 differential-linear correlations.
- **Controls:** H0 at 32 rounds; a sensitivity control (a 2^−15 bias forced on one cell, detected at 2^32 pairs: z = 6.26); the
  deterministic structures at 5 rounds forward and 2 backward, which only check the alignment.
- **Targets:** 6 rounds forward at 2^40 pairs (nibbles 0 and 77), 3 rounds backward at 2^39, 6 rounds at 2^42, 7 rounds at 2^40.
- **Sensitivity:** at 2^40 pairs, the campaign sees biases of about 2^−19 per cell.
- **Extended plan** (`--long`, `./scripts/rungpu2080`, 2026-11-03): 7 rounds at 2^42, backward 3 rounds on nibble 77, backward 4 rounds at 2^40,
  6 rounds at 2^44 (≈ 2^−21 per cell); full extended plan ≈ 26 h on the 4070 Ti, two to three times more on an RTX 2080. Binary for sm_75 and sm_89.

**A finding that reorders A1.** A plain cube gains no round from the GPU. With the first round free (whole nibbles), a zero
sum requires a degree below the cube dimension. But the degree is 27 after 3 rounds, which 2^28 inputs already cover, and 81 after 4.
Cubes of dimension above 81 would therefore be needed, while the GPU tops out around 46. A1 only remains of interest in forms not
covered by the degree: conditional cubes, or series of cubes looking for a partial bias.

At the measured throughput (2^29.9 at 5 rounds), 2^44 evaluations take about 5 h and 2^48 about 3.5 days: A1 therefore aims at 2^40 to 2^44 per cube, unless bitslicing is implemented.

| Attack | Current state | What the GPU aims for | Budget |
|---|---|---|---|
| **A1. Real cubes and zero-sums**: cubes of dimension 40 to 48, nibbles chosen from the graph neighbourhood (F4), forward direction; inside-out zero-sum by partition | 4 rounds forward, 3 backward, up to 2^36 | 5 to 6 rounds forward, 4 backward, 9 to 10 inside-out; measuring the real gap with the DP (10 + 10) | 2^44 to 2^48 per cube, 1 to 9 h |
| **A2. Differential-linear** (DLCT of the S-box, correlation measured on the real P): **never tried on BRUME** | — | 5 to 7 rounds. It is often the best reduced-round attack on sponges (Ascon, Keccak), and it exploits F3 | 2^40 to 2^46 pairs per configuration |
| **A3. Aligned truncated differentials** and clustering | 5 rounds (z = 3.2 without alignment at 2^34) | 6 rounds, at 2^44 pairs | ≈ 2 h per point |
| **A4. Boomerang and rectangle** with δ = M·nibble | 3 rounds (z = 14.8 at 2^20 quartets) | 4 rounds, at 2^36 to 2^40 quartets | ≈ 1 h |
| **A5. GPU-assisted trail search**: exhaustive enumeration of low-weight activity patterns, parallel Matsui branch-and-bound | CP-SAT proves 12, 16 and 24 S-boxes over 3, 4 and 6 rounds (the 4r of the bound); best trail found: 44 at 3 rounds | The **true minimum** activity over 3 and 4 rounds, to replace the 4r bound and certify the margin of F1 | a few hours |
| **A6. Non-linear invariants and invariant subspaces with the real constants** (Todo–Leander–Sasaki): search for functions g of degree ≤ 2 such that g ∘ round = g + constant | **Done on 2026-11-03, on CPU** (`tests/c/invariants.c`): Beierle–Canteaut–Leander–Rotella criterion, dim W_M(D) = 512, no invariant common to all rounds, of any degree | Remains: invariants that change from round to round, closed-loop invariants (Beyne) | 0.2 s |

**What would count as a result:** a distinguisher on 7 rounds or more forward, or on more than 12 rounds inside-out. It would reduce the stated
margin (24 rounds beyond the measured distinguishers) and would be publishable as a cryptanalysis result.

## 4. Phase 2 — BRUME in actual use (F5, F6)

| Attack | Model | Goal |
|---|---|---|
| **B1. Collision on the reduced-round hash**: differential trail found in A3 and A5, message modification on the first rounds, birthday paradox with distinguished points on GPU for the end | unkeyed | **A real collision on R rounds**, the classic flagship result. Aim for R = 4 to 5 |
| **B2. Preimage through linear structures** (Guo–Liu–Song): choose an input subspace that linearises 1 to 2 rounds, then GPU enumeration | unkeyed | 2 to 3 rounds, instead of the single round broken today |
| **B3. State recovery on the reduced-round duplex**: guess-and-determine, with GPU enumeration of 2^40 to 2^48 guesses on the capacity, then linearisation | AEAD, rate known on both sides | **2 rounds done on 2026-11-03, on CPU** (`tests/c/brume_gd2.c`): 256 bits recovered in ≈ 2^97, model validated; 3 rounds out of reach of the method (63 unknowns out of 64 per equation) |
| **B4. Nonce-reuse attacks** (outside the model, but a professional measures it): cubes on one plaintext block, fixed capacity | AEAD, repeated nonce | Establish the level of resistance to misuse; to be documented as outside the claims |

The AEAD initialisation (nonce → 2 full permutations → keystream) is out of reach by construction: this is documented as a
strength of the design and no time is spent on it.

## 5. Phase 3 — KEM (F7, F8)

| Attack | What is done | Why |
|---|---|---|
| **C1. Quasi-cyclic ISD on GPU**, Prange, Stern, Dumer then BJMM, on instances with the **same geometry** as Sillage-128 (2 blocks, n an Artin prime, density 2w²/n = 0.225) for n from about 500 to 4 000, i.e. 2^35 to 2^50 operations | Real cost / model curve over 15 more bits than today, extrapolated to n = 50 021; QC gain (DOOM, shifts) measured at each size | Validates or corrects the 138.2 bits. A gap of more than 3 bits below the model at the largest size would require revisiting n or w |
| **C2. Failure attack on a reduced KEM**: toy parameters at δ ≈ 2^−20 and the same RM(1,7) × D code; mass decapsulations on GPU (sparse multiplications); (a) real failure rate against the Chernoff bound; (b) a complete GJS and failure-boosting attack up to key recovery | Number of failures needed to recover x, y | If the bound is violated, even by a factor of 2, it is a critical flaw. Otherwise, the margin against the threat that cost HQC the most is quantified |
| **C3. Statistical distinguishers for H2-P at full size**: u / v / s correlations, truncated v, distribution of e1 ⊕ π(e2), on 2^30 ciphertexts instead of a few million | Detection tests, like `kem_distributions.c`, at a scale ×1 000 | Directly targets the noise-cascade “twist” (design note § 2.1) |
| **C4. Leakage through key rejection**: are rejected keys recognisable from pk? Correlation between rejection and h or s | **Done on 2026-11-03, on CPU** (`tests/c/kem_rejet.c`): 32 768 and 8 192 keys, five non-linear statistics of s, \|z\| ≤ 1.79; measured rejection 7.1 % and 5.9 % | Detection only, not a proof; 2^24 keys would remain possible on GPU |

## 6. Phase 4 — SIG (F9)

| Attack | What is done | Why |
|---|---|---|
| **D1. Kales–Zaverucha forgery at an intermediate scale**: N = 2^8, τ = 4, K = GF(2^16) to GF(2^20), t = 1 to 2; grinding h1 then h2 on GPU, with the real C verifier | Forgery cost measured at 2^35 to 2^42, against Theorem 8 | This is the attack that sets τ. **First step done on 2026-11-03** (`./runtestg-gpu.sh`): N = 2^8, τ = 4, K = GF(2^12), t = 1, h1 and h2 grinding on GPU, real C verifier; 22,525 / 1,000,000 against an exact prediction of 0.0223 and a bound of 0.0486. The GF(2^18) variant is ready (`./runtestg-gpu.sh --k18`, 6 \| 18, x^18 + x^7 + 1): false positives 64 times rarer (T has 63 roots, all in F_poly), ≈ 2.8·10^6 h1 attempts per retained h1, ≈ 2^34 Keccak permutations per forgery; first run 8 / 300 against a prediction of 0.0289 and a bound of 0.0592. Still to do: a large run |
| **D2. ISD on binary SD of rate 0.7 near GV**, n from 256 to 640, BJMM included | Measure BJMM where it overtakes Dumer | PROOFS § 5: “the advantage of BJMM at large sizes rests on the model, not on a measurement”. The GPU can measure it |
| **D3. Algebraic false witnesses**: look for (Q, P) with S·Q = P·F for an S of weight > w, over GF(2^8) to GF(2^11) | Exhaustive, then random search | A direct check of Lemma A at the size of the real F_poly (checked today over GF(8)) |

## 7. Order and schedule

| Step | Content | GPU time | Who runs it |
|---|---|---|---|
| 0 | CUDA, `brume.cuh`, `gf2.cuh`, `scripts/rungpu`, conformance, calibration | — | preparation |
| 1 | A5, A6 (short), then A2 and A1 | ≈ 1 night | maintainer |
| 2 | A3, A4, then B1 with the trails of step 1 | ≈ 1 night | maintainer |
| 3 | C1 (Prange and Stern, then BJMM) and D2: these two campaigns share `gf2.cuh` | 1 to 2 nights | maintainer |
| 4 | C2, D1, C3, C4 | ≈ 1 night | maintainer |
| 5 | B2, B3, B4 | depending on the results of steps 1 and 2 | maintainer |

After each step: results in `resultats/gpu/`, a section in `docs/AUDIT_REPORT.md`, an update of the SILLAGE dossier, and
a proposed fix if a weakness is found.

**Long experiments of the night campaign (2026-11-05).** `tests/gpu/frontiere_gpu.cu`, launched by `./scripts/rungpu_special`
(docs/CAMPAIGN_24H.md, § 9): the cubes of 2^34 to 2^42 inputs and the real Prange ISD at QC n = 197–227 and random n = 360–480 that the
8-hour CPU campaign could not fit, about 3 h on the RTX 4070 Ti. Short validation run: cube sums identical to the dense reference;
ISD at the sizes already measured on the CPU within tolerance (ratios 0.92 to 1.08), every solution checked; random n = 360 in 27 s,
against about 2 100 s estimated on the CPU. Not yet run in full.

## 8. What will not run on the GPU

- **dudect and any timing measurement:** the processor is what is measured, and a GPU load would add noise.
- **Valgrind, guided fuzzing and KATs:** they are CPU-bound or instantaneous.
- **CP-SAT and SAT (division property, `dp_queue`):** no useful GPU solver. A5 replaces the enumerative part.
