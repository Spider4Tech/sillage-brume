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

**Signature, change of protocol: VOLE-in-the-Head over regular SD**, in the style of SDitH v2.0. It is the only lever of this magnitude. Measured prototype (`prototypes/vole/vole_proto.c`, Ryzen 5 5600G):

| | Current SIG-128 | VOLE-128 | Current SIG-256 | VOLE-256 |
|---|---|---|---|---|
| Signature | 8 522 B | **4 112 B (−52 %)** | 34 867 B | **15 906 B (−54 %)** |
| Public key | 109 B | 93 B | 186 B | 185 B |
| Sign, one core | 34.4 ms | 16.4 ms | 121 ms | 117.8 ms |
| Verify, one core | 34.3 ms | 13.2 ms | 121 ms | 93.5 ms |
| Sign, 12 threads | 5.5 ms | 6.4 ms | 18.4 ms | 43.9 ms |
| Verify, 12 threads | 6.5 ms | 4.6 ms | 17.8 ms | 23.8 ms |

Averages over 5 keys × 8 messages; medians, p90, keygen and a 1 MiB message in `resultats/vole_proto.json`. Exploratory measurements, not a statistical characterisation. Public key: a λ-bit seed ‖ y. H is cached per key; otherwise, add 2.1 and 10.1 ms on one core. Signing time varies because of grinding, on public values.

*Parameters.* The reduction (SDitH, Theorem 5.1) maps RSD `(n, k_rsd, w)` to SD `(n, k_sd, w)`, with a loss of `log2(C(n, w)/(n/w)^w)`. With our ISD estimator (free memory), the reduction only guarantees the SDitH2 instances
108.7 / 155.6 / 198.1 bits, against 143 / 207 / 272 targeted (`prototypes/vole/vole_params.c`). These are guarantees by reduction, not attack costs (see below). For the reduction to hold in our model, longer codes are needed: `(18620, 18004, 76)` and `(38456, 37232, 152)`, which keep the margins of the current signature (160 and 316 bits), blocks of 245 and 253, d = 4, μ = (4, 4, 4, 4). τ, κ, T_open and the grinding come from SDitH (τκ = 121 and 252).

*Checked.* Exact sizes against the SDitH formula, alterations rejected, false witness rejected, and an attack run on a reduced model: without a witness, α cancels the residue at d points of E, Δ is searched among them, and the verifier accepts, at a measured cost of 1 235 trials against N^τ/d = 1 024.
The specification stores the leaves at `e·N + i`: with this layout, paths never merge and T_open is never reached. The prototype interleaves (`i·τ + e`), which recovers the stated probability (0.19 for 0.2).

**Conditions before adoption** (none is met):
- **An EUF-CMA theorem** to be written for this protocol, with its own terms; nothing from § 3 of PROOFS carries over. Human review is indispensable.
- **Forgery cost.** The γ term is q/2^λ, and cannot be tuned by grinding. With the current grinding, the cost is 2^127; one more bit gives 2^127.4. Getting past 2^128 requires a larger field or two draws of γ, to be costed.
- **Regular SD.** § 3 of PROOFS currently excludes restricted errors, and the reduction contains a heuristic step (unique solution). Direct attacks: see the table below. They do not threaten these parameters in our models, but these models still need to be checked against the full papers.
- **Rules of the current signature**: seeds of λ + 8 bits, 32-byte salt. The prototype follows SDitH (λ bits). Aligning with them gives about 4 235 and 16 122 B.
- **Constant time**: `keygen` and the witness now walk through every block under a mask. ctgrind detects nothing on the reduced model only (μ = 2, so without pair constraints); its branching control is detected. Neither the full profile, nor dudect, nor the machine code of other compilers is checked.
- **Production implementation**: errors propagated instead of `abort` (memory, randomness), injection of those failures, dudect, an independent reference. **QROM**: not analysed.
- **Parameters**: this is the best point of a grid (d = 4, n ≤ 40 000), not a global optimum; monotonicity is only sampled. Refining around the minimum only gains 0.3 % (4 101 B, w = 75): parameters unchanged.

*Code review (`docs/VOLE_CODE_REVIEW.md`).* Addressed: V-01 (93-byte public key now exact: λ-bit seed and canonical encoding), V-02 and V-06 (a single grammar, little-endian integers, H4 equal to four scalar calls), V-03 (`siglen`), V-05 (secret paths above), V-07 (cached H bound to its seed), V-08 (erasures), V-09 (exit code: 1 if a check fails, 2 if the results are not written), V-10 (see below), V-11, V-12, V-14. Partial: V-04 and V-13, allocations checked with a hard stop, without error propagation or failure injection. The file remains in one piece.
Checks added: `fmul` against a bit-by-bit reference, exhaustive reduced trees, signer and verifier constraints equal on valid and invalid witnesses, every field boundary, invalid lengths, identical KATs on x86-64 and ARM64 (qemu), fuzzing under ASan and UBSan (`--fuzz`).

**Direct attacks on regular SD** (`tests/c/rsd_attaques.c`, log₂ of operations, free memory):

| Family | VOLE-128 (target 160) | VOLE-256 (target 316) | SDitH2-L1 (target 143) |
|---|---|---|---|
| Regular ISD: Prange / Dumer / depth-2 BJMM | 384.6 / 300.0 / 282.4 | 756.0 / 601.3 / 564.4 | 269.1 / 209.8 / 196.4 |
| ISD without structure / with the w regularity equations | 269.2 / **266.1** | 539.5 / **532.8** | 188.4 / **185.5** |
| Combinatorial: meet in the middle | 301.6 | 606.7 | 210.9 |
| Hybrid algebraic (ω = 2) | 373.2 | 746.5 | 258.8 |
| **Best, margin over the target** | **266.1, +106** | **532.8, +217** | **185.5, +43** |

The generalised birthday attack has no lists large enough: the instance has a unique solution. Structure: H comes from SHAKE, without quasi-cyclic structure; the form `[H' | I]` has no measured effect (3 138 iterations of real regular Prange against 2 846 on a dense H, model 2 557); distinct and dense columns.

*Reading.* The reduction limits these parameters, not the direct attacks: the margins exceed the published gains (≈ 30 bits for the regular ISD of Esser–Santini and for the hybrid algebraic attack of Kim et al., on other parameters). SDitH2 therefore also holds against known attacks; it is its guarantee by reduction that does not hold in our cost model, which is more favourable to the attacker.

*Limitations.* These models were written from the papers' abstracts: the full papers were not read, and neither the non-uniform distribution of guesses (Kim et al.) nor depth 3 is included. Real validation: regular Prange, and linearisation on 8 small instances, all of degree 2, whereas VOLE-256 predicts degree 3. The cost of regular BJMM and Dumer is not checked against a real attack.

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
  about 20 % of a round: a shorter circuit is to be searched for with the S-box fixed, without touching the KATs.
