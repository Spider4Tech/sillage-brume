# Leads for later — performance and hardening

*The code cites the leads by number (“piste n” in its French comments).*

This document lists what was **measured but not adopted**, and under which
security conditions each lead could be. Rule: no lead
that changes the algorithm (and hence the KATs) is merged without the analysis
that justifies it.

## Already in place (does not change the algorithm)

| Item | Measured effect | Security |
|---|---|---|
| AVX2 permutation of one state (`br_permuter_avx2`): S-box and GF(16) log/exp by `vpshufb`, diffusion by byte rotations (Cayley structure of D₁₂₈) | 0.41 µs instead of 4.4 µs (×11); a single message: 79 MiB/s | **constant-time** (dudect: \|t\| < 1); identical outputs |
| Permutation: fused `log∘S` table | 0.39 µs (−7 %) | constant-time; identical outputs |
| State after P(IV) precomputed; key context (`sl_aead_cle`): state after key absorption | 64-byte message: 3.4 → 2.7 µs; multi-message with a common key: +23 % (64 B) | identical outputs; context erased (`sl_effacer`) |
| Unrolled Keccak-f[1600] (generated) | SIG ×1.7, KEM ×1.4 | matches `hashlib` |
| Karatsuba base case in column-wise `VPCLMULQDQ` (threshold 40 words) | decapsulation ×1.5 (v0.3: 0.48 / 2.89 ms instead of 0.75 / 4.31) | constant-time (dudect) |
| Batches of 32 states (`br_permuter_lot`, SSE transposition) + multi-message AEAD/hashing on all cores | 0.19 µs per state; AEAD-128: 105–128 MB/s per core, **624–713 MB/s** on 12 threads (messages ≥ 1 KiB) | constant-time; identical outputs |
| KEM decapsulation: systematic re-encapsulation, secret selected by a mask, branch-free decoding | removes a gap of ≈ 0.28 ms between “decoding failure” and “success” | removes the reaction-attack oracle |
| Sparse sampling with a FIXED number of words (Chernoff bound, P(insufficient) < 2⁻¹²⁸), branch-free acceptance | same result as rejection sampling | removes the leak through the number of rejections (“Don't Reject This”, CHES 2022) |
| C KEM in dense representation: bits written by masked sweep, Karatsuba product + `PCLMULQDQ` | decapsulation ×2 (measured in v0.3: 0.96 ms and 5.3 ms); 0.31 and 1.84 ms in v0.4 | **C KEM constant-time** with respect to the secret key and the decrypted μ (dudect) |
| 4-way Keccak-f[1600] (gcc vectors, AVX2) for the SHAKE integer stream (4 blocks at a time) | faster KEM sampling and SIG GGM trees (v0.3: SIG-128 verified in 12 ms instead of 20) | identical outputs (C/Python conformance) |
| **Constant-time C signature** (lead 3, v0.3 under Stern, redone for MPC-in-the-Head in v0.4): XOR, masks and carry-less products, masked H·x | SIG-128 / 256 sign in 38.5 / 139 ms on one core | dudect: round t = −0.62, signature t = 0.12; control t = −2 039; Valgrind, `sig_flux` |
| **Tree hashing** (lead 5, `brume512_hash_arbre`, `sl_hash_arbre`): 8 KiB leaves in batches of 32, root over the CVs | 16 MiB: 160 MB/s on one core (86 sequentially), **785 to 850 MB/s** on 12 threads | new function, new KATs; proof PROOFS § 4.4 (Theorem 16); sequential hash unchanged |
| Bit writing and masked sweeps in AVX2, branch-free rejection, δ bound by a table read with `vpshufb`, public API served by the C code (`sillage/rapide.py`) | KEM-128 keygen / encaps: 5.98 / 0.20 ms; KEM-256: 28.3 / 1.17 ms (v0.4: bound over 254 hyperplanes) | dudect and Valgrind; C/Python conformance |
| Signing and verification with OpenMP (static scheduling), H cached per thread | SIG-128 sign / verify: 38.5 / 38.4 ms on one core, 5.9 / 5.9 ms on 12 threads; SIG-256: 139 / 138 ms, 21.1 / 20.7 ms | dudect on 1 core and on all; identical outputs |
| **v0.4 sizes** (changes the formats): KEM with a spread RM(1,7) code, MPC-in-the-Head SIG, 24-byte nonce | ct 9 837 / 35 587 B (17 004 / 61 002); signature 8 522 / 34 867 B (133 917 / 536 326) | v0.3 levels kept, δ proved; PROOFS § 2.3 and § 3; KEM keygen ×16 and SIG verification ×8 on one core |

## Lead 1 — Parallel duplex: DONE

Profiles `BRUME-512p` and `BRUME-512-256p` (`Brume512P`, `sl_aead_p_encrypt`), next to the sequential profiles, which are unchanged.
The message is split into 4 KiB leaves rather than block by block over 32 lanes. Splitting into leaves scales
to all cores, like tree hashing, which 32 fixed lanes did not allow; the price is that a batch is only full
from 128 KiB on. Proof: PROOFS § 4.5 (Theorem 14-p), 128 and 256 bits kept for σ ≤ 2⁶⁴, i.e. about 3 % less data.
Tests: `tests/test_aead_parallele.py`, including the cross-leaf alterations this lead required, and a reduced model.
Leaves of 2, 4 and 8 KiB measured: 4 KiB gives the best trade-off (16 MiB: 150 MB/s on one core, 777 MB/s on 12 threads).
The sequential mode remains preferable below 16 KiB.

## Lead 2 — Fewer rounds for the data phase

**Goal.** Keep 32 rounds for initialisation and finalisation, and
use R_d < 32 between two data blocks.

**Measured gain.** ×2 for R_d = 16 (≈ 340 MB/s per core with lead 1).

**What would allow it (current state of the results):**
- R_d = 16: characteristics ≤ 2⁻¹²⁸ and trail correlation ≤ 2⁻⁶⁴ (the
  square exceeds the limit of 2⁶⁴ data blocks);
- division property: exact reach of 10 rounds per direction, for all
  cubes (Theorem 12 sexies), i.e. 6 rounds of margin at R_d = 16;
- empirical distinguishers ≤ 5 rounds forward.

The inside-out reach (exactly 20 rounds) assumes control of the state in the middle
of the permutation, which the keyed duplex does not allow.

**Conditions before adoption.**
- A dedicated analysis of the data phase: an attacker who knows the rate
  (the plaintext, in overwrite mode) and observes the keystream; cubes and state
  recovery over R_d rounds; differentials over consecutive blocks.
- Redo the exact search (lead 6) on the data phase at R_d
  rounds, with an attacker who controls the rate: `tests/test_dp_exact.py`
  adapts by changing the starting cube.
- Do not go below 16 rounds as things stand.

## Lead 3 — Residual leaks: DONE for the C signature

The C signature is constant-time on the signer's side, with identical outputs
(`sillage/c/sig.c`, checks in `tests/test_c_temps.py`):
- π is never built. The Fisher–Yates swaps (drawn from a SHAKE
  stream) are applied directly to the bit planes of u and
  e, by a masked sweep: y[k] = x[π(k)] is invariant under the
  swaps;
- H·u and H·e are masked. The product over the t rounds is grouped, which reads
  H once instead of t times;
- the number of rejections in sampling remained variable, on rejected values only.

The above describes the Stern signature of v0.3. The MPC-in-the-Head signature of v0.4 no longer draws
a permutation: its secrets only go through XORs, masks and carry-less products
(`tests/test_c_sig_valgrind.py`, `tests/c/sig_flux.c`, `tests/test_c_temps.py`).

What remains, with no leak of a secret:
- **the KEM's π** (Fisher–Yates by rejection on σ_h): σ_h is public;
- **Python**: not constant-time by nature (big integers); it is a
  reference implementation.

## Lead 4 — SIMD ports: NEON DONE, AVX-512 remains

- **ARM NEON: done.** Permutation of one state and batches of 16 (`vqtbl1q_u8`, `vextq_u8`), diffusion macros generated by
  `gen_tables.py`, keygen δ bound, carry-less product with PMULL. Identical outputs under qemu (`tests/test_c_simd.py`). **Constant time
  and throughput not measured**: a real ARM machine is needed. Keccak stays in gcc vectors there, so without any particular gain.
- **AVX-512 (VBMI):** 64 states per register, byte permutations (`vpermb`) → about ×2 per core for batches, and a
  simpler horizontal diffusion. Not testable on the current machine.
- **Batch transposition:** already in SSE (`tr16`), nothing to gain.
- **Done on x86:** output of `sl_shake4` by AVX2 transposition, SIG 10 % faster; the `nuit_cryptanalyse` campaign on the AVX2
  kernel, forward direction 11 times faster than the tables (2.26 ns against 25.7 ns per round, all cores). Backward, M⁻¹ is dense and stays with tables.
- **Not adopted:** KEM and SIG cores, already in AVX2; 32-bit `mini_brume`, limited by its number of instances and not by time.

## Lead 5 — Hashing a single large message in parallel: DONE

`brume512_hash_arbre` (Python) and `sl_hash_arbre` (C). 8 KiB leaves
hashed in batches of 32 on all cores, root over the chaining
values, domains separated in the capacity (LEAF, ROOT, SINGLE;
domain 0 = sequential hash, unchanged). Proof: PROOFS § 4.4
(decodable, complete, final-node separable → indifferentiable, 128 bits).
Test: `tests/test_hachage_arbre.py` (14 checks). Throughput on 16 MiB:
160 MB/s on one core, 785 to 850 MB/s on 12 threads.

Possible extensions: a multi-level tree (useless before 2⁶⁴
leaves), a configurable leaf size (B already appearing in the root,
the encoding allows it without ambiguity).

## Lead 6 — Exact division property, valid for all cubes: DONE

**Result** (`docs/PROOFS.md`, Theorem 12 sexies). The reach of the
division property is **exactly 10 rounds per direction, and 20 rounds
inside-out, for every cube**. It was bracketed by 10 ≤ reach ≤ 14
(forward) / ≤ 11 (backward), and these upper bounds were only established
for one cube.

**What worked.**
1. *Splicing* (`tests/test_dp_tous_cubes.py`). The first linear
   layer moves inactive bits freely: a matching in the
   bipartite graph of L carries each trail of cube 0 to the 511
   other cubes. Result: 13 824 spliced trails, all re-checked.
2. *Decomposition* (`tests/dp_queue.py`, `tests/test_dp_exact.py`). Keep
   the prefix of a verified trail and let CP-SAT complete the last
   rounds towards a given bit, in a model reduced to the reachable
   and co-reachable bits. A query takes about one second, against
   several hours for the full model. With prefixes of trails of
   12 and 13 rounds, 18 forward trails of 11 rounds are obtained, then a trail
   to each of the 512 bits at 11 rounds in each direction. Duration: 12 minutes.

**What did not work** (not to be retried as is):
- the full exact model in CP-SAT or SAT (CaDiCaL), even with
  per-nibble linear cuts: 1.4 million variables, nothing in 25 to
  30 minutes at 11 rounds;
- beam search alone: no forward trail at 11 rounds.

**What remains open.** The reach of the actual integral distinguisher. Trails
in even number cancel: one would need to count trails modulo 2
(full monomial prediction), which is out of reach at 512 bits.
Empirically, cubes stop at 4 rounds forward and 3 backward.

## Lead 7 — Sillage-SIG at a quantum level (parameters)

**Finding** (PROOFS § 5 bis). Grover on forgery costs √(2^{128}): SIG-128 only offers
about 64 bits against a quantum adversary, and SIG-256 about 132.

**Option.** New profiles, which require **more than doubling τ**
(check: PROOFS § 5 bis, `sig_niveau_quantique`): for 128 quantum
bits, N^τ ≥ 2^{256}, 32-byte seeds and w = 204 (n = 4 080, Prange–Grover), or
w = 278 (n = 5 560) if quantum walks with free QRAM are counted; 48-byte hashes
if BHT with QRAM is counted. The QROM proof (loss in q²) would need instantiating. These are new
parameters. The current profiles remain, named after their classical level.

## Lead 8 — KEM in the HQC regime (4.4 KB)

**Finding.** The proof of δ (PROOFS § 2.3) bounds the noise on S by `T1 + T2 + Te`, ignoring XOR
cancellations. It therefore requires `2w²/n < 1/2`. With a spread RM(1,7) code, the proved minimum is 9.8 KB.
Under the assumption of independent positions, the same code would suffice around n ≈ 28 000, i.e. ≈ 6.5 KB (estimate, without
an outer code), and HQC goes down to 4.4 KB with an outer Reed–Solomon code.

**Tried.** A martingale on `W = Σ_S (−1)^{N_i}` gives an exact contraction `E[W'] = γW` and a Bennett bound
computable key by key. It ignores correlations, however: `|A| ≤ c` is worst case, which saturates at `n²/(8w²)` and only beats the
simple sum for small S (−50 against −41 bits at n = 40 000, D = 8; −84 against −108 at n = 45 000, D = 16).

**Conditions before adoption.** A proved bound (not a simulation) on `Pr[W ≤ 0]` that accounts for cancellations, and, for
an outer code, a joint bound over several blocks (the per-key computation does not cover unions of supports).
Adopting HQC as is would reintroduce the assumption removed in v0.3.

## Lead 9 — Reducing sizes

**Signature, breakdown.** `aux` 63 and 66 %, seeds 26 %, α and β 6 and 3 %, commitments 4 %. These fields are uniform (Proposition 7): compression
only gains the padding bits, 16 B at most on SIG-128.

**Signature, parameters** (`tests/c/compression_sig.c`, the two dominant terms of Theorem 8; recovers the costs and sizes of the dossier). Estimated time proportional to N·τ:

| N | SIG-128 | Time | SIG-256 | Time |
|---|---|---|---|---|
| 2¹³ | 7 896 B (−7 %) | ×1.8 | 32 260 B (−7 %) | ×1.7 |
| 2¹⁵ | 7 422 B (−13 %) | ×6.5 | 30 238 B (−13 %) | ×6.3 |
| 2¹⁶ | 7 032 B (−17 %) | ×11.6 | 27 808 B (−20 %) | ×11 |

The gain is small for that time, and each variant breaks the format: not adopted.

**Signature, change of protocol: VOLE-in-the-Head over regular SD — ADOPTED in v0.5 (11 November 2026)** as the signature of the suite (`sillage/c/vole.c`, SPEC § 4 bis); the v0.4 signature is kept as a reference. In the style of SDitH v2.0. It is the only lever of this magnitude. Prototype `prototypes/vole/vole_proto.c`, version 2 of 11 November 2026; security in **PROOFS § 3 bis** (Theorems 17 and 17-Q, Lemmas 17.1 and 17.2). Medians over 50 runs, one key, Ryzen 5 5600G (`build/vole_proto --bench 50`); current SIG from the dossier:

| | Signature | Public key | Sign, 1 core | Sign, 12 threads | Verify, 1 core | Verify, 12 threads |
|---|---|---|---|---|---|---|
| Current SIG-128 | 8 522 B | 109 B | 38.5 ms | 5.9 ms | 38.4 ms | 5.9 ms |
| **VOLE-128** | **4 235 B (−50 %)** | 106 B | 16.6 ms | 2.9 ms | 13.6 ms | 2.4 ms |
| **VOLE-128f** | 5 193 B (−39 %) | 106 B | 7.0 ms | **1.45 ms** | 4.9 ms | **1.0 ms** |
| Current SIG-256 | 34 867 B | 186 B | 139 ms | 21.1 ms | 138 ms | 20.7 ms |
| **VOLE-256** | **16 122 B (−54 %)** | 211 B | 94 ms | 19.8 ms | 83 ms | 17.5 ms |
| **VOLE-256f** | 20 467 B (−41 %) | 211 B | 27 ms | **5.4 ms** | 20 ms | **4.2 ms** |

H is cached per key (2.6 and 10 ms otherwise). The "f" profiles take N = 2^8 (τ = 16 and 32, T_open from SDitH2-fast, wpow = 3): 5 to 10 times fewer leaves. The 12-thread figures vary by 30 to 70 % from one run to another (another run gave 5.1, 29, 1.8 and 7.0 ms for signing); 6 threads give about the same, since the machine has 6 cores.

*What was done on 11 November 2026.*
1. **Exact blocks** (Lemma 17.1). The first prototype had blocks of 245 and 253 positions for Π μ = 256. The verifier accepted empty blocks, and x = 0 on y = 0. `ctx_init` now refuses `bloc ≠ Π μ`. SDitH v2.0's own Table 3 has the same gap (n/w = 185, 252 and 191 for Π μ = 192, 256 and 192), while its text requires equality; this was not checked against its code.
2. **Regular SD reduced exactly to SD** (Lemma 17.2). The codimension is `⌈log₂ C(n, w)⌉` and no row is removed, so any regular solution is an SD solution. There is no uniqueness heuristic, unlike Theorem 5.1 of SDitH v2.0; the loss is `log₂(C(n, w)/b^w) + 1.79` bits. The cost is a few bytes of public key (93 → 106 and 186 → 211); the signature does not change, since the witness does not depend on the codimension. Measured on small instances: the success rate is above the bound of the lemma and matches the refined prediction (z = +0.31 and +1.34). (H3-R) is therefore no longer a separate assumption in the ROM.
3. **Executed attacks on the three challenges** (Δ, γ, VOLE check): the measurements match the exact predictions.
4. **Theorem 17** (ROM): λ bits in the cost/advantage notion, at 0.877 to 0.881 of the budget. This requires seeds of λ + 8 bits, a 32-byte salt and the minimal wpow; one bit less fails.
5. **Theorem 17-Q** (QROM, sketch based on Theorems 54 and 56 of Baum et al., ePrint 2026/164): proved level 2^61.8 and 2^125.8 quantum queries, within 2.2 bits of Grover. Theorem 8 only proves 2^32.2 and 2^68.2. It needs the decisional assumption (D-H3-R), as FAEST does with lossy keys.
6. **Hardened code**:
   - errors are propagated, with no partial signature;
   - each allocation and each random draw is injected as a failure in turn, also under ASan and LeakSanitizer;
   - ctgrind finds nothing on the full VOLE-128 and VOLE-256 profiles, and its control is detected;
   - dudect gives |t| ≤ 0.95, and its control is detected;
   - KATs (5 profiles) are identical on x86-64 and ARM64, with 1 and 12 threads.
7. **Speed without changing the outputs** (KATs unchanged by these changes):
   - the grinding looks for the smallest valid `ctr` in parallel, in batches of 4 SHAKE (sl_shake4);
   - the opening count no longer walks the tree, using `|M| − 2τ + 1` (checked against `marquer`);
   - the VOLE folding is split into parallel chunks;
   - the tables of γᵀH are built in parallel, and the VOLE universal hash is parallel;
   - the witness preparation is parallel per block.

   On 12 threads, the grinding drops from 4.1 to 0.2 ms (128) and from 30 to 1.4 ms (256). Signing goes from 7.0 to 2.9–5.1 ms and from 45 to 20–29 ms. Byte tables beat nibble tables (tried and dropped).

*Further speed would change the format* (not done; it is a decision):
- **PRG-based leaf commitments** (ePrint 2026/164, § 3):
  - The "Full" variant takes an AES-CTR PRG and a universal hash of 3λ bits. It is statistically binding in the ROM without idealising AES (their Lemma 26), but the hidden commitments grow to 3λ bits, i.e. +176 B (128) and +672 B (256).
  - Measured there: leaf commitments 7× faster than SHAKE at λ = 128 and 2.4× at λ = 256; the vector commitment takes 27 % and 83 % of the SHAKE time.
  - Here, the leaves are 30 to 40 % of the signing time.
  - Cost: AES would enter SILLAGE as an assumption (PRG security), and the binding proof would have to be redone.
- Hashing the commitments in a tree.

*Parameters.* The VOLE parameters are the smallest of the exact-block grid for which Lemma 17.2 keeps the margins of the current signature (160 and 316 bits): `(19 456, 18 736, 76)` and `(38 912, 37 480, 152)`, μ = (4, 4, 4, 4). The grid is not a global optimum, and monotonicity in w is only sampled. τ, κ and T_open come from SDitH. With our ISD estimator, the SDitH2 instances are only guaranteed 108.7 / 155.6 / 198.1 bits by their own reduction, against 143 / 207 / 272 targeted. The specification stores the leaves at `e·N + i`, so paths never merge and T_open is never reached. The prototype interleaves them (`i·τ + e`), which recovers the stated probability.

**Conditions before adoption** (still open):
- **Human review** of Theorem 17, Theorem 17-Q, Propositions 17.3 and 17.4, and Lemmas 17.1 and 17.2. An AI-written proof is not a guarantee.
- **(D-H3-R)** for the QROM, and (H3) at rate ≈ 0.96, a regime that the current SIG (rate 0.7) does not use: both rest on the ISD estimators.
- ~~SUF-CMA and binding~~ done on 11 November 2026 (Propositions 17.3 and 17.4, PROOFS § 3 bis.6). The only malleability is another `ctr` giving the same challenge, at a cost of 2^(τκ+wpow) = 2^131; it is executed on the reduced model at its predicted cost. Binding: CEO and DEO at 2^λ.
- **Implementation**:
  - the file is a single piece of about 1 900 lines;
  - dudect was measured on Zen 3 with gcc 16 only;
  - the machine code of other compilers was not inspected.
- **Format decision**: short or fast profile, new KATs, the full battery.

*Code review (`docs/VOLE_CODE_REVIEW.md`).* All points are addressed except V-14 (single file). Checks in `vole_proto` (78, including SUF and binding): field, trees, KATs, the four profiles, exact blocks, Theorem 17 and minimal wpow, the QROM level, the three attacks, failure injection and the opening count. Checks in `vole_params` (3): SDitH2 sizes, the measured exact reduction, monotonicity.

**Direct attacks on regular SD** (`tests/c/rsd_attaques.c`, log₂ of operations, free memory, parameters of version 2):

| Family | VOLE-128 (target 160) | VOLE-256 (target 316) | SDitH2-L1 (target 143) |
|---|---|---|---|
| Regular ISD: Prange / Dumer / depth-2 BJMM | 374.3 / 299.7 / 278.5 | 727.9 / 596.5 / 551.9 | 269.1 / 209.8 / 196.4 |
| ISD without structure / with the w regularity equations | 267.3 / **264.0** | 531.7 / **525.0** | 188.4 / **185.5** |
| **Best, margin over the target** | **264.0, +104** | **525.0, +209** | **185.5, +43** |

*Independent cross-check* (CryptographicEstimators `RegSDEstimator`, free memory): 275.4 for VOLE-128, 612.2 for VOLE-256 (CCJ excluded, overflow), 196.1 for SDitH2-L1, all above our figures. The generalised birthday attack has no lists large enough, since the solution is unique. H comes from SHAKE and has no quasi-cyclic structure.

*Limitations.* The attack models were written from the papers' abstracts; the full papers of Esser–Santini and Kim et al. were not read, and depth 3 is not modelled. Real validation covers regular Prange and linearisation on small instances.

**KEM** (`tests/c/compression_kem.c`, the real δ bound on real keys, variable D, w and θ, no attack cost below v0.3). With the current selection criterion (at most 5 % of keys
beyond 2^−(λ+8)), the gain ranges from 0 to 0.6 % depending on the run, since keys are drawn at random. Accepting up to 10 % rejections at the 2^−λ threshold: about 9 710 B (−1.3 %, D = 12, θ = 0.8) and 34 800 B (−2 %, D = 22 to 24), but n and hence pk increase
(about 6 670 and 23 500 B). Lowering D forces n up: the current parameters are already in the right place. Not adopted; only lead 8 can change the order of magnitude.

## Lead 10 — BRUME-512 kernels: performance assessment and next steps (2026-11-03)

Measured on a Ryzen 5 5600G (Zen 3), one core, gcc 13.3 `-O3 -march=native`, with hardware counters (`perf_event_open`,
actual core cycles). All of BRUME rests on two kernels: the sequential modes (AEAD, hashing, TE: 87 MB/s) cost nothing
beyond the single-state permutation; the batch modes (multi-message, tree, parallel duplex: 125 to 160 MB/s per core) are
limited by the batch kernel.

| Kernel | Measurement | Limit |
|---|---|---|
| `br_tours_avx2` (one state, 32 rounds) | 1 623 cycles, 50.7 per round, 6 269 instructions, IPC 3.86 | FP ports: ≈ 176 vector operations per round against a floor of 168, i.e. 42 cycles at 4 per cycle |
| `br_permuter_lot` (32 states) | 849 cycles per state, 26.5 per state and per round, IPC 3.53 | loads: ≈ 1 250 per round (897 `vpshufb` with a memory operand, `TG` tables reloaded), 2 per cycle |

Measured throughput of this core: `vpaddb`, `vpminub`, `vpxor` 4 per cycle; `vpshufb`, `vpalignr` 2; `vperm2i128` 1;
256-bit load 2. No GFNI or AVX-512 on Zen 3.

**One state: nothing to gain with AVX2.** Each edge and register needs a rotation, `add`, `sub`, `min`, `vpshufb` and
`xor`. The reduction modulo 15 (`sub` and `min`, a third of the operations) cannot be removed: a sum of two logarithms
covers [0, 28], which no 16-entry table read by `vpshufb` can reduce in one instruction. Tried without gain:
- clang 18: +2 % (one state), +26 % (batches);
- accumulation grouped by destination register: 10 % fewer instructions, same duration (IPC 3.4);
- the constant 15 hidden from the compiler, which was folding it into a second constant read from memory;
- explicit sharing of the `vperm2i128`; `-fno-schedule-insns`;
- two interleaved states: only −3 % (1 569 cycles), which confirms that the kernel is throughput-bound, not
  latency-bound.

**One state with GFNI (Zen 4, Intel Ice Lake and later): about ×2, to be measured.** GF(16) (polynomial 0x13) is a
subfield of GF(2⁸) (polynomial 0x11B of `gf2p8mulb`). The embedding φ is GF(2)-linear and preserves products:
- the S-box can output φ(S(x ⊕ rc)) directly through `vpshufb`;
- each edge becomes a rotation, a `gf2p8mulb` by φ(c) and an `xor` (3 operations instead of 6);
- φ⁻¹ takes one `gf2p8affineqb` per register and per round.

Estimate: ≈ 88 operations per round instead of 168. With AVX-512 VBMI, half a state fits in one register and each
rotation becomes a `vpermb`: ≈ 46 operations. Not measurable on this machine; conformance could be checked under an
emulator (Intel SDE). See also lead 4.

**Batches: a bitsliced prototype on 256 states, conformant, −26 %.** One register holds one bit of the state for 256
states (plane p = 4·nibble + bit, 16 KiB per batch state). Multiplication by a GF(16) constant becomes a 4 × 4 binary
matrix, i.e. a few XORs, with no table. In total, 7 146 XORs per round.
- **S-box in 25 operations** (Shannon decomposition on x₃, `vpandn`), checked on its 16 inputs. The circuit returns
  S(x) ⊕ 8. The complement of bit 3 is absorbed into the constants of the next round, since M·(y ⊕ e) = M·y ⊕ M·e, and
  compensated at the output of the last round.
- **Round generated in assembly**, with explicit register allocation. Each source plane is loaded only once: as a memory
  operand if it is used once, in a register otherwise. Result: 4 096 loads, ≈ 10 900 vector operations and
  14 500 instructions per round.
- **Measurement:** outputs identical to `sl_brume_permute` on 256 random states; **630 cycles per state instead of 849**.
  The transposition to and from planes is not counted (estimated at 5 to 10 % more).

Prototype steps, in cycles per state:

| Step | Cycles per state |
|---|---|
| Naive ANF, unrolled C code | 924 |
| Barrier per nibble (gcc was reordering the blocks: 680 spills, 18 KB of stack) | 680 |
| 25-operation S-box | 651 |
| Generated assembly | 630 |

Tried without gain:
- two or three accumulators per plane: +4 to +6 %, so latency is not the limit;
- smaller source footprint: −2 %, so the L1D is not the limit;
- each block replayed on two groups of 256 states: +7 %, the data (64 KiB) overflows the L1D.

**Current limit: the front end.** An unrolled round is ≈ 95 KB of code, more than the L1i (32 KiB) and the op cache. The
same number of instructions replayed from a small block runs in 3 145 cycles per round instead of 6 300 (IPC 4.6
instead of 2.9).

Possible next steps:
- **fewer XORs** (Paar's algorithm, local to each nibble: 4 rows over 28 planes), estimated gain 15 to 20 %;
- **shorter encodings** (one pointer per generator, 8-bit displacements): only ≈ −11 % of code.

**Conditions for adoption:**
- **useful only from about 180 states per core.** A 1 MiB tree has only 128 leaves and would be slower with it. The
  old kernel would remain for small batches;
- **no output changes**: the format does not fix the batch width of the tree or of the parallel duplex;
- **constant-time by construction** (Boolean operations only), but dudect has to be run again;
- **95 KB of generated code** to maintain: the C generator would be the only source.

Prototype: `prototypes/brume_bitslice/` (generator `gen_asm.c`, S-box `sbox_bs.h`, bench `banc.c`, which reruns the checks and measurements).

## Lead 11 — BRUME-1024q: 128 bits of quantum security (prototype, 2026-11-12, refocused 2026-11-13)

**Status: prototype, not adopted, not reviewed** (`prototypes/brume_q/b1024/`, README and ROADMAP there).

- **History.**
  - A first prototype, BRUME-512q (the suite's permutation with c = 384 and 40 rounds), was measured on 12 November.
  - It was slow: 33–37 MB/s on the sponge, because the rate is only 128 bits.
  - Its proved quantum bounds were low: they depend on min(r, c) = 128.
  - The width analysis (`prototypes/brume_q/WIDTH_ANALYSIS.md`) led to a 1024-bit permutation.
  - **BRUME-512q was abandoned on 13 November 2026** at the author's request. Its prototype is archived outside the
    repository.
- **Design.** A 1024-bit BRUME permutation generated by the BRUME-512 rule:
  - D₂₅₆, K = {0, 105, 71, 76, 72, 31}, the same S-box;
  - 32 rounds, c = 384, rate 640 bits.

  Modes:
  - sponge and XOF;
  - default hash = tree;
  - full-state keyed AEAD, in the **SpongeWrap orientation** since 13 November (the rate holds the ciphertext). Its security
    model (`AEAD_SECURITY.md`) maps it onto DMV17, but the AE step is not written yet.
- **Certified.** B = 8 exact. C3 ≥ 21, with two LRAT checkers (ours and `lrat-check` of drat-trim). BRUME-512's C3 ≥ 21 was
  re-proved with both checkers as well.
- **Checked.**
  - 12/12 checks against the dense reference;
  - 18 frozen KATs;
  - domain-separation table and checks;
  - dudect and ctgrind clean on both machines.
- **Measured.** Impossible differentials and zero correlations reach 5 rounds, as at 512.
- **Speed** (13 November, Ryzen 5 5600G; the reference figures are those of `resultats/BENCH_1024Q.md` and
  `BENCH_1024Q_zenplus.md`, dated, the others are rounded copies):
  - sponge 106 MB/s;
  - tree 281 MB/s on one core and 1 048 MB/s on 12 threads (bitsliced 256-leaf batches);
  - AEAD 105 MB/s;
  - multi-message AEAD up to ×1.63 faster than the suite's AEAD-128 on all cores.
- **Missing.**
  - the AE step of the AEAD proof (`AEAD_SECURITY.md` § 4 (b));
  - boomerang;
  - aggregation (hulls);
  - exact division property;
  - review.

## Tried and rejected

- **BLAKE3 instead of SHAKE256 in the KEM and the signature:** measured on a copy (BLAKE3 1.5.5, AVX2). In an isolated call it is 3 times faster on 64 B, but the signature hashes in batches of four (SHAKE: 97 ns per hash, BLAKE3: 83 ns), and it slows down: signing 42.3 against 34.4 ms at 128 bits (8 internal lanes not tested, the public API does not expose them). KEM: a gain of about 8 to 10 % at 128 bits, decapsulation 0.28 against 0.32 ms. Its ×7 gain only applies to large messages, which the KEM and the signature do not hash. Security: a 128-bit level at most, hence incompatible with the 2λ-bit hashes of the 256 profile; 7 rounds and less scrutiny than SHAKE; breaks every KAT. Not adopted.
- **Batches of 64 states (two registers per nibble):** 268 ns per state
  against 196 for batches of 32. Register pressure cancels the
  gain on table loads.

## Not recommended

- **Reducing the capacity below 256 bits to enlarge the rate:** a gain of
  25 % at most, and loss of the generic M·N/2^c bound.
- **Lightening the diffusion or making its coefficients uniform:** this destroys
  the asymmetry of the weighted graph (128 Weisfeiler–Lehman colours), which
  is at the heart of the concept, as well as B = 8.
- **Changing the S-box for speed:** in vector code, any 4-bit S-box
  costs a single instruction. Bitsliced (lead 10), this one costs 25 operations over 4 planes,
  about 20 % of a round: a shorter circuit is to be searched for with the S-box fixed, without touching the KATs. **Found on 13
  November 2026 for BRUME-1024q** (same S-box): 17 gates by SAT (`prototypes/brume_q/b1024/circuit_sbox.c`), for S(x ⊕ 3) ⊕ S(3),
  the two constants folding into the round constants; reusable for a bitsliced BRUME-512.
