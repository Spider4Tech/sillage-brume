# SILLAGE — an experimental cryptographic suite based on noisy decoding

**Research prototype — version 0.4.0 — Python 3.10+, numpy; a conforming C
implementation (`sillage/c/`, gcc); the test suite also uses `networkx`
(division property trails), gcc with OpenMP (intensive tests) and, when
available, `matplotlib`.**

> ⚠️ **WARNING**: this code is a research object. The parameters are
> preliminary, the design has not undergone third-party cryptanalysis, and
> none of it should be deployed in production. It is, however, designed to be
> **read, attacked, measured and iterated on** — that is its purpose.

The proofs, design notes and audit reports in `docs/`, and the identifiers in
the code, are in French.

---

## 1. Design identity

SILLAGE is a complete suite (KEM + symmetric encryption + signatures) unified
by a single paradigm:

> **Every secret lives on the far side of a noisy channel.** The adversary has
> to decode a random channel (syndrome decoding — NP-hard, 45 years of
> cryptanalysis; the best known quantum attacks are ISD sped up by Grover);
> the key holder decodes a structured channel (easy for them).

Guiding engineering principle: **"safely degrading novelty"**. Every
non-standard component is designed so that, if it were broken, it would
collapse to the best-studied hard problem — never to an unknown weakness. No
new structure carries the security.

### Why these foundations (and not others)

| Family | 2022-2025 verdict |
|---|---|
| Isogenies (SIKE) | dead — broken in about 1 h on a single-core PC (Castryck–Decru, 2022) |
| Multivariate (Rainbow, GeMSS) | dead (Beullens, 2022) |
| Non-commutative (braids, AAG) | dead |
| Chaos / cellular automata | disastrous cryptanalytic track record — rejected |
| Euclidean lattices (Kyber/Dilithium) | solid, but they are the current standard (out of scope by the project brief) |
| **Decoding random codes (sparse LPN, syndrome)** | **45+ years, NP-hard, quantum-resistant, under-exploited** |

---


## 2. Repository layout

```
sillage-brume/
├── README.md            this document
├── docs/
│   ├── guide.md         original design note (the SILLAGE paradigm)
│   ├── RAPPORT_AUDIT.md audit v0.2 → v0.3: flaws, fixes, proofs
│   ├── PREUVES.md       security proofs (KEM, SIG, BRUME, modes)
│   └── PISTES.md        measured but not adopted leads (performance, hardening)
├── sillage/             the package (v0.4.0)
│   ├── sillage_common.py   rings, sparse vectors, permutations, ISD estimators
│   ├── sillage_kem.py      Sillage-KEM (QC sparse LPN + FO)
│   ├── brume512.py         BRUME-512: permutation, duplex AEAD, EC mode, hash
│   ├── brume512_tables.py  frozen tables (S-box, graph, coefficients)
│   ├── select_params.py    reproducible curation of the tables
│   ├── sillage_sig.py      Sillage-SIG (hypercube MPC-in-the-Head)
│   ├── demo.py             end-to-end scenario
│   ├── rapide.py           public API served by the C code (Python fallback with a warning)
│   ├── sillage_c.py        Python access (ctypes) to the C implementation
│   └── c/                  C implementation: brume512.c, brume512_avx2.c
│                           (AVX2 and NEON kernels, batches, parallel AEAD), kem.c, sig.c, isd.c
│                           (estimators), commun.c (SHAKE256), bench.c,
│                           Makefile; headers generated
│                           by gen_tables.py: brume512_tables.h, brume512_simd.h
├── tests/               test and cryptanalysis suite (run_all.py)
│   ├── noyau_c.py          ctypes bridge to the C kernel (build, conformance)
│   └── c/noyau.c           C/OpenMP kernel of the intensive tests (build/: cache)
└── resultats/           outputs: SYNTHESE.md, EMPREINTES.md, BENCH_C.md, BENCH_TAILLES.md, and the
                         division property certificates; everything else is regenerated locally
```

## 3. Usage

```bash
python3 -m sillage.demo                 # end-to-end scenario
python3 -m tests.run_all                # full suite → resultats/SYNTHESE.md
python3 -m tests.run_all aead kem       # subset
python3 -m tests.bench_perf [--quick]   # performance → resultats/bench_perf.txt
python3 -m tests.bench_tailles          # throughput by size → resultats/BENCH_TAILLES.md
python3 -m tests.noyau_c                # C kernel conformance and throughput
python3 -m tests.bench_c                # C implementation benchmark → resultats/BENCH_C.md
python3 -m tests.empreintes             # SHA-256 fingerprints (sources, KAT, results) → resultats/EMPREINTES.md
make -C sillage/c                       # C library (build/libsillage.so) + build/bench
SILLAGE_INTENSITE=8 python3 -m tests.run_all c_integral c_sac   # C tests pushed ×8
python3 -m sillage.select_params 1 && python3 -m sillage.select_params 2   # tables
```

```python
from sillage import SillageKEM, Brume512, Brume512P, brume512_hash, brume512_hash_arbre, SillageSIG

kem = SillageKEM("Sillage-128")
pk, sk = kem.keygen()
ct, ss = kem.encaps(pk)
assert kem.decaps(sk, ct) == ss

br = Brume512("BRUME-512", key=ss * 2)                # 64-byte key
c, tag = br.encrypt(nonce24, message, aad=b"ctx")
p = br.decrypt(nonce24, c, tag, aad=b"ctx")           # raises Brume512TagError
ct, pars, tag, meta = br.encrypt_te(nonce24, message)
pt, corriges = br.decrypt_te(nonce24, ct, pars, tag, meta)

brp = Brume512P("BRUME-512p", key=ss * 2)             # large messages: all cores, different ciphertexts
c, tag = brp.encrypt(nonce24, gros_fichier)

h = brume512_hash(b"empreinte", 32)
h2 = brume512_hash_arbre(gros_fichier, 32)            # parallel (C: sl_hash_arbre)

sig = SillageSIG("Sillage-SIG-128")
pk_s, sk_s = sig.keygen()
s = sig.sign(sk_s, pk_s, message)
assert sig.verify(pk_s, message, s)
```

These classes are served by the C code (`sillage/rapide.py`) and fall back to
Python, with a warning, if the library does not compile (`SILLAGE_C_OBLIGATOIRE=1`
turns the fallback into an error). The reference classes remain in
`sillage_kem`, `sillage_sig` and `brume512`; they serve as a cross-check for
`test_c_impl` and `test_api_c`. The library is compiled with `-march=native`: it
is only valid on the CPU that built it, and its cache fingerprint includes the
CPU flags. Do not call `fork()` without `exec` after a signature or a
verification (OpenMP): a child calling these functions again may hang.

---

## 4. Architecture (v0.4.0)

### 4.1 Sillage-KEM (`sillage_kem.py`)

- **Ring** `R = F2[z]/(z^n − 1)`, `n` an **Artin prime** (2 is a generator,
  checked by the tests).
- **Keys**: `sk = (x, y)` sparse (weight w), `pk = (σ_h, s = x·h ⊕ y)`.
- **Deterministic encryption**: `(r1, r2, e1, e2)` derived from `(μ, H(pk))`;
  `u = r1·h ⊕ r2`, `v = cw(μ) ⊕ r1·s ⊕ e1 ⊕ π(e2)`; decryption cancels exactly
  the `r1·x·h` terms: `v ⊕ u·x = cw(μ) ⊕ r1·y ⊕ r2·x ⊕ e` (all sparse).
- **FO transform with implicit rejection**: `decaps` decodes μ,
  **re-encapsulates** and compares; any mismatch → a pseudo-random secret bound
  to `σ_rej`.
- **Code**: RM(1,7) repeated D times through a public spreading: a block of 128·D bits carries one
  byte of μ, with maximum-likelihood decoding (Walsh transform). In v0.4 it replaces the
  repetition code (`d = 531` and `953`), with an equivalent proof: the ciphertext is divided by 1.7.
- **PROVEN δ-correctness**: a rigorous Chernoff bound on the flips
  (`borne_echec_log2`, with no bit-independence assumption); `keygen`
  rejects any key whose bound exceeds `2^−λ` (5 and 8 % of draws).
- **Noise cascade** `e1 ⊕ π(e2)`: kept as an object of study, but **neutral**
  for security — since π is public, `π(e2)` follows the distribution of `e2`.
  Security rests entirely on `(r1, r2)` and `(x, y)`.

| Profile | n | w | D | pk | ct | classical security | quantum (Prange-Grover) | proven δ (median key) |
|---|---|---|---|---|---|---|---|---|
| Sillage-128 | 50,021 | 75 | 14 | 6,285 B | **9,837 B** | **138.2 b** | 91.7 b | ≈ 2⁻¹⁴⁶ (threshold 2⁻¹²⁸) |
| Sillage-256 | 170,003 | 140 | 28 | 21,283 B | **35,587 B** | **265.1 b** | 158.4 b | ≈ 2⁻²⁸⁹ (threshold 2⁻²⁵⁶) |

v0.3, with the repetition code: ct of 17,004 and 61,002 B, pk of 8,540 and 30,538 B, 137.3 and 264.9 b, 91.1 and 158.0 b.
HQC-128 reaches 4.4 KB, but its failure rate relies on an independence assumption that the v0.3
proof removed; SILLAGE does not follow it on that point (`docs/PREUVES.md` § 2.3, `docs/PISTES.md` lead 8).

Security = min(key recovery, message recovery): concrete ISD (Prange, Stern,
Dumer, depth-2 BJMM, optimized parameters) on the QC code `[2n, n]` of weight
`2w`, minus `log2 n` (rotations) or `log2(n)/2` (DOOM), and a 3-block `(u, v)`
attack with unequal densities (no measured gain). `n` is the smallest Artin prime
(within ~5 %, checked by `tests/test_isd_parametres.py`) such that security ≥ that
of v0.3 **and** proven δ ≤ 2^−(λ+8) for a typical key. Proofs of IND-CPA → IND-CCA
(FO with implicit rejection) and δ-correctness: `docs/PREUVES.md`.

**Naming and quantum level.** Profiles are named after their **classical**
level (concrete ISD). The Prange–Grover quantum estimate (91.7 and 158.4 bits,
with no depth constraint) is **below** 128 and 256: the profiles do not claim
128 and 256 bits against a quantum adversary. Placing them in the NIST categories
would require a quantum gate cost model, which has not been done.

**Assumptions with parity.** The ring splits as F2 × F_{2^{n−1}}: the parity of
s and u is a public function of h and of w mod 2. The decisional assumptions are
therefore stated "with parity" (H1-P, H2-P, as in HQC). The initial statement,
without parity, was distinguishable with advantage 1/2 (found by an external
audit). The scheme and its outputs are unchanged.

### 4.2 BRUME-512 (`brume512.py`)

1. **State**: 512 bits = 128 nibbles of GF(16) = GF(2)[x]/(x⁴+x+1).
2. **Optimal 4-bit S-box**: U = 4, NL = 4, no fixed point or linear structure,
   degree 3 on all components, trivial self-equivalences.
3. **Diffusion** `v' = M·v`, support `A ⊕ I` of a **non-abelian (D₁₂₈)** 6-regular
   Cayley graph, generated by 6 reflections, hence **bipartite** (trivial
   eigenvalues ±6); Ramanujan on the other 126 (λ\* = 3.5076 < 2√5); GF(16)\*
   coefficients weighted edge by edge; **branch number B = 8 exactly certified**
   (differential and linear). Diffusion support: 7, 37, 94, 127 then 128 nibbles,
   i.e. **full diffusion in 5 rounds** (2 for the inverse), certified by
   `diffusion_support`.
4. **32 rounds**, SHAKE256 constants (anti-slide).
5. **Hash**: sponge with rate 256 / capacity 256. **Tree hash**
   `brume512_hash_arbre` (a separate function with its own KATs): 8 KiB leaves
   hashed in parallel, root over the chaining values, domains separated in the
   capacity; indifferentiable (PREUVES § 4.4), 128 bits.
   **Status: proof completed, reviewed by an AI and tested on a reduced model;
   independent human review still to be done** (`docs/PREUVES.md` § 4.4).
6. **Keyed duplex AEAD, entirely on the permutation**, **24-byte** nonce (as in XChaCha20: collision in `q²/2¹⁹³` when drawn at random, enough for BRUME-512 up to 2⁶⁴ messages;
   **BRUME-512-256 requires unique nonces for its 256 bits**, PREUVES Corollary 14 ter): IV(profile) → absorb key ‖ nonce → AAD (10*, domain) → encryption (last block
   always partial, 10* padding) → "text" domain → length block
   ("final" domain) → tag extracted in rate blocks. **Parallel duplex** `Brume512P`
   (profiles `BRUME-512p`, `BRUME-512-256p`, different ciphertexts): 4 KiB leaves, each followed by its keyed duplex derived from a
   trunk (key, nonce, AAD), final states absorbed by the trunk. Same levels for σ ≤ 2⁶⁴
   (PREUVES § 4.5, Theorem 14-p). **Status: proof written and tested on a reduced model; independent human review still to be done.**
   Worthwhile from about 16 KiB; below that, the sequential profile is faster.

| Profile | rate | capacity | tag | λ (keyed duplex, M ≤ 2^(c−λ) blocks) |
|---|---|---|---|---|
| BRUME-512 | 256 b | 256 b | 128 b | 128 |
| BRUME-512-256 | 128 b | 384 b | 256 b | 256 (512-b key → 2²⁵⁶ after Grover) |

7. **EC mode (`te`)**: SEC-DED parities per bit-plane (+10.9 %): corrects 1 byte
   per 64-byte block, detects multiple **accidental** alterations. The parities are
   not authenticated: against an adversary, only the tag guarantees integrity
   (checked by the tests).

### 4.3 Sillage-SIG (`sillage_sig.py`)

- **MPC-in-the-Head** in the style of SDitH, on **binary** syndrome decoding `H·x = y`, `wt(x) ≤ w`, `H = [H' | I]`:
  the same assumption (H3) as in v0.3, where the Stern protocol gave 134 and 536 KB. `sk = x_A ‖ Q ‖ P`, with
  `S·Q = P·F` over `GF(2^e)`, `n = 2^e`; checked at t points of `GF(2^{ep})` with a Beaver triple.
- **Hypercube**: N = 2¹² leaves, one hidden seed (soundness 1/N), D + 1 simulations per repetition.
- **5-pass Fiat–Shamir**: `salt ‖ h1 ‖ h2 ‖ (path ‖ commitment ‖ aux ‖ α ‖ β)` per repetition, fixed length.
  Master seed covered by `(sk, salt, m)`: faulty randomness does not repeat seeds.

| Profile | (n, k, w) | τ | pk | sk | signature | ISD | forgery |
|---|---|---|---|---|---|---|---|
| SIG-128 | (2048, 1434, 103) | 11 | 109 B | 464 B | **8,522 B** | 160.3 b | 128.3 b |
| SIG-256 | (4096, 2867, 206) | 23 | 186 B | 977 B | **34,867 B** | 316.2 b | 264 b |

v0.3: 133,917 and 536,326 B on average, ISD 159.7 and 314.9 b. The level also depends on the `λ + 8`-bit seeds
and the 2λ-bit hashes, and the parameters follow the Kales–Zaverucha attack (false positive, then hidden party):
see `docs/PREUVES.md` § 3. **The protocol is new in v0.4 and has not been reviewed by any third party.**

---

## 5. Cryptanalysis — test suite (`tests/`)

`python3 -m tests.run_all` runs everything in parallel; each test writes
`resultats/<test>.json` (boolean checks + measurements). Summary:
`resultats/SYNTHESE.md`.

| Test | Content |
|---|---|
| `test_fonctionnel` | self-tests, KATs (hash, AEAD), table fingerprints, round trips, demo |
| `test_aead` | all alterations (bit by bit, extension, truncation, tag, nonce, AAD, key) on all lengths up to 3 blocks, length/final-block collision regression |
| `test_te` | correction at each position, 2 errors/block, metadata, truncated/recomputed parities |
| `test_hachage` | exhaustive padding injectivity, extensions, uniqueness, XOF, 20-bit birthdays, near-collisions |
| `test_branch_exact` | exact certificate B = 8 (M, M⁻¹, Mᵀ, (Mᵀ)⁻¹, weight ≤ 3), conjugation by the trace |
| `test_banc_cryptanalyse` | S-box/graph statics, greedy differential/linear trails (exhaustive weight ≤ 2), Monte Carlo probes, wide-trail bounds |
| `test_diff_lin_empirique` | experimental validation of DDT/LAT/adjoint on 1 round, clustering effect on 2 rounds |
| `test_cycles` | iterative characteristics (v1 vs unweighted v0 control) |
| `test_beam_trails` | beam search for trails beyond greedy |
| `test_integral_degre` | nibble and bit cubes, 2²⁰ integral, degree bounds (Boura–Canteaut), inside-out zero-sum |
| `test_symetries_invariants` | group translations, Weisfeiler-Lehman, constants, invariant subspaces, self-equivalences, order of M |
| `test_diffusion_stats` | support, avalanche per round, 512×512 SAC at 32 rounds, inverse, statistical battery (AEAD stream, hash, counter) |
| `test_kem` | correctness, measured decoding margin, FO, implicit rejection, malformed inputs, pk density |
| `test_sig` | correctness, rejections, no witness leak, dense-preimage cheater, challenge uniformity |
| `test_isd_parametres` | estimator consistency, security and minimality of parameters |
| `test_hull` | PROVEN 2-round MEDP/MELP bounds (Park et al.), clustering factor measured on an 8-S-box trail |
| `test_division_property` | bitwise division property (monomial prediction): lower bound proven by degree, upper bound through trails built then re-checked, forward and inverse |
| `test_robustesse` | fuzzing of all decoders, timing measurements |
| `test_c_integral` | **C**: cubes of 2¹⁶ to 2²⁴ inputs (2²⁸ at intensity 8), random nibbles / graph neighborhood / single bits, forward and inverse |
| `test_c_diff_lin` | **C**: 2-round differential (2²⁷ pairs) and 2-round hull (2²⁸ samples); S-box-aligned truncated / linear sweep, round by round, forward and inverse |
| `test_c_sac` | **C**: full 512 × 512 SAC matrix round by round (2¹⁶ samples per bit), forward and inverse, and at 32 rounds |
| `test_c_statistiques` | **C**: extended NIST-style battery (34 tests) on 1 GiB in counter mode, 512 MB of sponges, and on reduced rounds (statistical reach) |
| `test_c_sig_valgrind` | **C**: SIG under Valgrind, memory errors and leaks on valid and malformed inputs, no branch or access depending on the key, seeds or shares (ctgrind method, with control) |
| `test_indiff_arbre` | Lemma 15 and Theorem 16: BDPV decoder on small instances, composed simulator on a reduced sponge, bad event under the bound, distinguisher through inverse queries |
| `test_c_kem_bruit` | **C**: empirical validation of the δ bound on 3.4·10⁷ simulated decoding noises, cross-checked with the real KEM |
| `test_c_cube_init` | **C**: cube attack on the reduced AEAD initialization (nonce bits, unknown key state): zero sums and linear superpolys (state recovery) |
| `test_c_degre` | **C**: actual growth of the algebraic degree (random subspaces of dimension 3^r and 3^r + 1), forward and inverse |
| `test_c_impl` | byte-for-byte conformance of the C implementation (`sillage/c/`) with Python: permutation, hash, AEAD, EC mode, KEM, SIG, key interoperability |
| `test_mode_aead` | proof model of the mode (duplex absorbing the ciphertext) ≡ implementation; injective prefix-free encoding; no release of unverified plaintext |
| `test_aead_parallele` | parallel duplex: proof model ≡ reference ≡ C; injective prefix-free paths; alterations across leaves (swap, truncation, grafting); no reused keystream; independence from the thread count; forgeries on a reduced duplex |
| `test_c_simd` | **C**: same outputs with AVX2, without SIMD and with NEON (qemu, when the cross toolchain is present) |
| `test_c_fuzz` | **C**: memory safety (UBSan in trap mode + validated guard-page allocator), 2,000 iterations over all APIs, malformed inputs |
| `test_dp_modele` | exact division property framework (CP-SAT): infeasible for R ≤ 10, accepts verified trails, per-nibble cuts valid on all tables |
| `test_dp_tous_cubes` | division property bounds extended to the 512 cubes by stitching (13,824 stitched and re-checked trails) |
| `test_hachage_arbre` | tree hash: mode model ≡ Python ≡ C, proof conditions (decodable, complete, separable final node), domain separation, structural alterations, multi-thread determinism, KATs |
| `test_dp_validation` | division property against real cube sums (2¹⁶ inputs, reduced rounds, both directions): no bit proven balanced has a non-zero sum |
| `structure_miss` (**C**) | impossible differentials and zero correlations (miss-in-the-middle, nibbles, patterns of weight ≤ 2), propagation validated on real differences |
| `isd_comparaison` (**C**) | real Prange, Stern, Dumer and BJMM on the same reduced instances, compared with the models (iterations and cost), solutions re-checked |
| `isd_reel` (**C**) | real ISD attacks (Prange) on reduced instances: cost matching the formulas (quasi-cyclic KEM, random code of the SIG), measured quasi-cyclic gain, parity as the only linear invariant of s |
| `diffusion_support` (**C**) | exact supports of M^r and (M⁻¹)^r (combinatorial, GF(16), real dependency through the permutation), dihedral group bound, spectrum of the bipartite graph |
| `kem_distributions` (**C**) | H1-P / H2-P: parity of u as the only linear invariant (reduced instances); biases and correlations of u / v / s at real sizes |
| `sig_flux` (**C**) | SIG constant time at control-flow level: identical basic-block traces for different keys (instrumented sig.c, MPC rounds and full signature), positive control |
| `brume_attaques` (**C**) | S-box (DDT, LAT, BCT, DLCT), real boomerang on reduced rounds, impossible differentials and zero correlations through value sets, with the real coefficients |
| `mini_brume` (**C**) | exact model at 24 and 32 bits: real integral reach against the degree bound, duality, exact distribution against the Markov model and best trail, exact boomerang, random control |
| `test_brume_algebre` | graph structure, rotational pairs, minimal polynomial and invariants of M, S-box, activity (CP-SAT), 1-round attack, state recovery through SAT, monomial trails on mini-BRUME (cancellations) |
| `test_sig_modele` | SIG on a reduced model: irreducible fields, exhaustive Lemma A, Lemma 6 counted over K², Proposition 6 with the real verifier, Kales–Zaverucha attack executed under the Theorem 8 bound, unique encoding (each bit, each hidden leaf, C included) |
| `test_aead_modele` | Theorem 14 on a reduced duplex: each term confronted with an executed attack, including multi-target chosen plaintext (σN/2^c); forgeries passed to the real decryption |
| `test_dp_exact` | exact division property reach: a verified trail to each of the 512 bits at 11 rounds, in each direction (prefix + CP-SAT suffix decomposition) |
| `test_c_kem_valgrind` | **C**: KEM under Valgrind, memory errors and leaks, no branch or access depending on a secret (ctgrind method, with control) |
| `test_api_c` | public API served by the C code: interoperability with the reference classes, malformed inputs, δ bound C ≡ reference, ISD estimators C ≡ reference, concurrency |
| `test_c_temps` | **C**: measured constant time (dudect method) — AVX2 permutation, AEAD, KEM decapsulation at both levels (decoding failure oracle, FO oracle, secret key dependency, μ at encapsulation, bench bias), SIG signer (one-sided simulation and full signature, on one core and on all) and conformance of the constant-time paths |
| `bench_c` (outside the checks) | single-core C benchmark: KEM, SIG, 4 content types × 12 sizes (0 B → 16 MiB), compared with Python |
| `bench_tailles` (outside the checks) | encryption of 4 content types × 10 sizes (0 B → 1 MiB): AEAD-128/256, EC mode, hash, hybrid KEM+AEAD |

**Latest run (v0.4.0, 2026-10-31): 502/502 checks passed,
51 tests, 3,604 s.** The suite notably includes the proof model of the AEAD
mode, C memory fuzzing, measured constant time and the exact division property
search (reach for all cubes). Highlights: B = 8 certified; best 14-round trails
2⁻²⁸³⁰ (diff.) / 2⁻¹⁴¹⁷ (lin.); integral/cube distinguishers limited to 4 rounds
out of 32; bitwise division property: exact reach of 10 rounds per direction (20
inside-out) for any cube; no symmetry or round invariant found (M alone has 16
invariant subspaces, which the S-box leaves: PREUVES § 4.2 bis); statistical
battery without rejection; all AEAD alterations rejected; KEM: 0 decoding failures
(max 246 flips / threshold 448 over 2²³ noises), proven δ ≤ 2⁻¹²⁸ and 2⁻²⁵⁶ for each key; SIG: cheater measured at 1/N, witness never exposed.

---

### Intensive tests in C (OpenMP kernel)

Python capped the "black box" tests (≈ 5,000 permutations/s).
`tests/c/noyau.c` recomputes the permutation with the tables of
`sillage/brume512.py`, checks its bit-by-bit conformance (forward 1–32 rounds,
inverse) before any use, and reaches ≈ 900,000 permutations/s at 32 rounds
(×168, S layer then a 128 KiB linear table). What this enabled (intensity 1):

| Measurement | Python (before) | C (now) | Result |
|---|---|---|---|
| Cubes / integrals | 2²⁰ inputs | 2²⁴ (2²⁸ at ×8), 4 contexts, forward + inverse | distinguisher: 4 rounds (forward), 2 (inverse) |
| 2-round differential | ~32 occurrences | 2²⁷ pairs, 508 occurrences | clustering factor **0.99 ± 0.04** (characteristic 2⁻¹⁸) |
| 2-round linear hull | 2²², factor 1.1 ± 0.12 | 2²⁸ samples | hull factor **1.004 ± 0.016** |
| Truncated differentials (S-box-aligned) | — | 2²⁴ pairs per round, 3 inputs | biases up to 5 rounds (forward), 2 (inverse) |
| Single-nibble linear (aligned) | — | 1,920 output masks per round | bias at 1 round only (B = 8) |
| 512 × 512 SAC | 500 samples, 32 rounds | 2¹⁶ per bit, round by round | indistinguishable from 5 rounds (forward), 2 (inverse) |
| Statistical battery | 128 KB, 11 tests | **1 GiB** counter + 512 MB sponge, 34 tests | compliant at 32 rounds; fails ≤ 4 rounds, compliant from 5 |
| KEM δ bound | — | 2²³ and 2²⁰ simulated noises (cross-checked with the real KEM, z = −1.3 and 0.1) | the bound dominates the measurement at every observable threshold: 18.5 and 16.5 bits of margin per word, 26.4 and 28.8 per hyperplane; max 246 / threshold 448, 446 / 896 |

Extended campaign (`SILLAGE_INTENSITE` = 4 to 8, results in
`resultats/<test>_x<k>.json`):
- 2²⁸ cubes: 4 rounds forward (unchanged) and **3 inverse** (+1);
- 2-round differential on 2²⁹ pairs: factor 1.013 ± 0.022;
- 2-round hull on 2³⁰ samples: factor 1.011 ± 0.008;
- SAC on 2¹⁸ samples per bit: unchanged;
- statistical battery on 4 GiB in counter mode and 2 GiB of sponges:
  compliant at 32 rounds, fails up to 4 rounds;
- 1.3·10⁸ KEM noises (v0.3 repetition code): the bound dominated the measurement,
  with 19 bits of margin; maximum of 132 flips for a threshold of 265. Not redone on the RM code.

Longest empirical reach: **5 rounds forward (truncated differential) and 3
inverse (2²⁸ cube), i.e. 8 rounds inside-out out of 32**, to be compared with the
exact division property reach: 20 rounds inside-out (10 per direction), for any cube.

Night campaign (`./rundenuit.sh [hours]`, C and shell, summary in
`resultats/NUIT.md`; after an interruption, `./reprendre_nuit.sh [hours]` resumes at the interrupted campaign, and at the interrupted step for BRUME): full suite (from 6 h), cryptanalysis of BRUME and proof models at large scale (`tests/nuit_brume.py`), memory fuzzing (including extreme KEM and SIG
inputs), dudect on plans that isolate the secret, with A/A test and
controls, real KEM (implicit rejection, recomputation of the bound, worst key), ISD,
cube series up to 2³⁶, truncated differentials and aligned linear approximations.
Each family is tested beyond its known reach, and its statistics are calibrated
under the null hypothesis. The previous run is archived in
`resultats/nuit_archives/`. The full 8-hour run of 2026-10-30 predates these plans
and v0.4: it covers neither the RM KEM nor the MPC-in-the-Head SIG; see `docs/RAPPORT_AUDIT.md` § 14.

Two complementary analyses:
- **cube attack on the reduced AEAD initialization** (nonce bits as variables,
  unknown state derived from the key): zero sums up to 4 rounds, **no linear
  superpoly** at any round, hence no usable equation to recover the state. The
  actual path between the nonce and the keystream counts 64 rounds;
- **algebraic degree**: it grows at the maximum rate (3, 9, 27 at rounds 1 to 3,
  in both directions, on random subspaces), and the Boura–Canteaut bound always
  holds. The reach of the degree distinguisher (10 rounds per direction) is thus
  not skewed by slow growth.

### C implementation (`sillage/c/`) and benchmark

A complete C port of the suite: BRUME-512 (permutation, hash, AEAD in two
profiles, EC mode), Sillage-KEM (FO, δ bound at keygen), Sillage-SIG, SHAKE256.
It is **byte-for-byte conformant** with Python and interoperable with it
(`test_c_impl`: crossed keys, ciphertexts and signatures). `resultats/BENCH_C.md`,
on a single core (Ryzen 5 5600G):

| Operation | C | Python | Factor |
|---|---|---|---|
| BRUME-512 permutation (AVX2, **constant-time**) | 0.39 µs | ≈ 0.3 ms | ×770 |
| AEAD-128, one 1 MiB message | 12.1 ms (**83 MiB/s**) | 10.2 s | ×840 |
| AEAD-128, 64 B message (key / key context) | 3.4 / **2.7 µs** | 3.1 ms | ×915 |
| AEAD-256, one 1 MiB message | 24.3 ms (41 MiB/s) | 20.3 s | ×840 |
| AEAD-128 multi-message (1 KiB / 16 KiB), 12 threads | **623 / 685 MB/s** (shared key: 654 / 690) | — | — |
| Multi-message hash (1 KiB), 12 threads | 810 MB/s | — | — |
| **Tree** hash of a 16 MiB message: 1 core / 12 threads | 161 / **793 MB/s** (sequential: 86) | — | — |
| **Parallel** AEAD of a 16 MiB message: 1 core / 12 threads | 150 / **777 MB/s** (sequential: 86) | — | — |
| KEM-128 keygen / encaps / decaps (constant-time) | 6.27 / 0.21 / 0.32 ms | 154 / 3.5 / 17.8 ms | ×17–56 |
| KEM-256 keygen / encaps / decaps (constant-time) | 26.7 / 1.19 / 1.86 ms | 676 / 16.3 / 58.6 ms | ×14–32 |
| SIG-128 sign (constant-time) / verify | 34.4 / 34.3 ms | 2.06 / 2.06 s | ×60 |
| SIG-256 sign (constant-time) / verify | 121 / 121 ms | 6.60 / 6.59 s | ×54 |
| SIG-128 / SIG-256 sign, 12 threads | **5.5 / 18.4 ms** | — | — |
| SIG-128 / SIG-256 verify, 12 threads | **6.5 / 17.8 ms** | — | — |

Encapsulation caches H(pk) per thread: towards a pk that changes on every call,
it costs 0.26 / 1.42 ms. Decapsulation always recomputes H(pk).

Compared with v0.3 (the cost of size): KEM keygen goes from 0.37 / 1.63 ms to 6.27 / 26.7 ms, because the δ bound
goes through 254 hyperplanes over the whole circle. Signing goes from 14.9 / 76.5 ms to 34.4 / 121 ms and verification from
4.8 / 21 ms to 34.3 / 121 ms, on one core: the hypercube expands N = 2¹² leaves per round on both sides. Encapsulation and
decapsulation are faster than before, the RM code being much shorter than the repetition code.

**AVX2 kernels (same outputs, same KATs).**
- *One state*: the S-boxes and the GF(16) product (through logarithm and
  exponential) go through `vpshufb`, with the tables in registers. The diffusion
  exploits the Cayley structure of D₁₂₈: the six generators are reflections, so
  the neighbor is obtained by swapping halves and rotating bytes. The table
  version took 4.4 µs.
- *Batches of 32 states*: 0.19 µs per state. AEAD and multi-message hashing
  choose on their own between batches and one message per core.
- **Constant time verified** by `test_c_temps` (dudect method): no dependency on
  the secret is detected, either in the permutation or in the AEAD.

The **C KEM is also constant-time**. Secret vectors are handled in dense form,
with a Karatsuba + PCLMULQDQ product. Sparse sampling consumes a fixed number of
words, which removes the "Don't Reject This" type of leak. Decapsulation always
re-encapsulates. The RM word is placed through masks and decoded by a Walsh
transform, with branch-free selection: the permutation `Q` is public and the noisy
bit indexes nothing. The keygen δ bound reads its public table through `vpshufb`; only the worst product
is declared public, since it decides the rejection of the key.

Dudect in v0.4 (`|t|` < 4.5): decoding oracle t = 0.39 (128) and −2.83 (256), FO oracle
t = −1.00, decapsulation t = −1.47 and 0.60, μ at encapsulation t = 0.77, A/A test t = −1.51.
These measurements are shorter than the v0.3 campaign (1.2 M measurements per plan): 3,000 to
20,000 here. The v0.3 cache effect on a repeated ciphertext, a public value, has not been measured again.

The **C SIG is constant-time on the signer side**. Secrets only go through XORs, masks
and carry-less products in GF(2^e) and GF(2^ep), with no table indexed by a secret. The product
H·x is masked, and only the public challenge selects the revealed shares. Checks: Valgrind
(ctgrind) with control, control-flow traces (`sig_flux`) and dudect: MPC round t = −0.62, full
signature t = 0.12 (400 measurements) and −0.40 on all cores, branching control t = −2,039.
Signing and verification distribute the rounds through OpenMP with static scheduling. The throughput
leads for a single stream (reduced rounds in the data phase) are measured and not
adopted: their security conditions are in `docs/PISTES.md`.

### Performance (Python/numpy reference implementation)

Measurements of the reference classes, for comparison: the public API goes
through the C code (§ 3).

`resultats/BENCH_TAILLES.md`: 4 content types (text, random, zeros, JSON) × 10
sizes (0 B → 1 MiB), all round trips verified.

| Size | AEAD-128 | AEAD-256 | Hash | Hybrid KEM+AEAD |
|---|---|---|---|---|
| 0 B | 2.5 ms | 3.7 ms | 0.6 ms | 6.2 ms |
| 1 KiB | 12.4 ms | 23.5 ms | 10.5 ms | 16.0 ms |
| 64 KiB | 0.64 s | 1.27 s | 0.63 s | 0.64 s |
| 1 MiB | 10.2 s | 20.3 s | 10.0 s | 10.2 s |

Asymptotic throughput ≈ 100 KiB/s (AEAD-128, 64 B/perm. rate) and ≈ 50 KiB/s
(AEAD-256, 32 B/perm. rate); EC mode adds ≈ 4 % in time and 10.9 % in size; the
KEM adds a fixed cost of ≈ 3.5 ms (encaps.) / 18 ms (decaps.) and 9,853 B. The
content type affects neither the time nor the ciphertext entropy (≈ 8 bits/byte,
even for an all-zero plaintext).

---

## 6. Security status

**Proven or exhaustively verified:**
- B = 8 (differential and linear) → at 32 rounds, differential characteristic
  ≤ 2⁻²⁵⁶ and linear trail correlation ≤ 2⁻¹²⁸ (for an unkeyed permutation, the
  product of local probabilities assumes independent rounds; these bounds apply to
  a characteristic, not to an aggregated differential);
- S-box properties, Ramanujan (bipartite graph, ±6 excluded), diffusion support
  (full in 5 rounds), asymmetry of the weighted graph;
- injectivity of the paddings (hash, AEAD).

**Resting on hard assumptions:** QC syndrome decoding (KEM), random syndrome
decoding (SIG), random oracle model (FO, Fiat-Shamir, SHAKE256 in the KEM and the
SIG).

**Proven under assumptions (docs/PREUVES.md):** IND-CPA of the underlying
encryption (decisional QCSD with parity, H1-P / H2-P), IND-CCA of the KEM in the ROM (FO with implicit
rejection, δ ≤ 2^−λ proven key by key), completeness / soundness (1/N, false positive p) /
HVZK of the MPC-in-the-Head protocol, EUF-CMA and SUF-CMA of the signature in the ROM. The QROM reductions,
instantiated with caveats, prove ≈ 60 / 104 bits for the KEM and ≈ 32 / 68 bits for the SIG (PREUVES § 5 bis).

**Division property (bitwise): exact reach OF THE METHOD, for any cube — not
that of every integral attack.**
- Balance proven up to 10 rounds per direction (Boura–Canteaut degree).
- At 11 rounds, each of the 512 bits has a re-checked monomial trail, in each
  direction: the method no longer proves anything. Reach: **exactly 10 rounds per
  direction, 20 inside-out** (`docs/PREUVES.md`, Theorem 12 sexies).
- Method: stitching trails over the 512 cubes, and exact completion of the last
  rounds through CP-SAT on a reduced model.
- Still open: the real integral distinguisher (trails counted modulo 2). 20 rounds inside-out is **not**
  a real integral attack covering 20 rounds. On mini-BRUME, no cancellation observed (`docs/PREUVES.md` § 4.2 bis).
- Reproducible certificates: `resultats/pistes_division.json` and
  `resultats/pistes_exactes.json`, re-checked by `verifier`
  (`tests/pistes_monomiales.py`, independent of the construction).

**Impossible differentials and zero correlations** (`structure_miss`, `brume_attaques`,
C tests): 5 rounds at most out of 32, at nibble level and with the real coefficient values.

**128 active S-boxes, 2⁻²⁵⁶ and 2⁻¹²⁸: two statuses.** The 128 active S-boxes are proven. The probabilities rest on the Markov model, an assumption
that the exact model shows to be close, but not exact (`docs/PREUVES.md` § 4.2 bis). Boomerang: 3 rounds measured. 1 round: state recovered by linear solving.
Aggregation beyond 2 rounds remains open.

**Quantum adversary** (`docs/PREUVES.md` § 5 bis): the nominal levels are
classical. KEM ≈ 91 / 158 bits (Prange–Grover), 67 / 129 with quantum walks and
free QRAM; SIG ≈ 64 / 132 bits, since Grover applies to Fiat–Shamir and to the
seeds; NIST category (MAXDEPTH, coarse model): none for SIG-128, 3 for SIG-256;
hash collisions ≈ 2⁸⁵; AEAD: key search in 2²⁵⁶.

**What these guarantees do not say.** The properties of the linear layer
(Ramanujan expansion, Weisfeiler–Lehman asymmetry, B = 8) are structural
properties. Together with the trail and division property bounds, they rule out
specific families of attacks. They do not prove the security of the full
permutation. That remains an assumption (ideal permutation in the mode proofs),
supported by the absence of any distinguisher found and awaiting independent
cryptanalysis.

**Trail aggregation:** proven bounds at 2 rounds (MEDP₂, MELP₂ ≤ 2⁻¹⁵); measured
clustering factor ≈ 1.1; beyond that, a margin argument (> 2,500 bits between
found trails and proven thresholds).

**Side channels:** BRUME-512, the KEM and the SIG (signer side) in C are
constant-time, verified by dudect (measurements, with positive controls) and, for
the SIG, by the control-flow check (`sig_flux`: identical basic-block traces for
different keys). The Python code is not. These are verifications, not a certification.

---

## 7. Roadmap

1. **Signatures**: MPCitH done in v0.4 (×15.7); SUF-CMA, multi-user, reduced model and quantified QROM done. Third-party review of the protocol, of Theorem 8 and of the QROM sketch remains. VOLE-in-the-Head is the main lead on size (`docs/PISTES.md`, lead 9): not adopted, it requires a new proof system and regular SD.
2. **KEM**: RM(1,7) code done in v0.4 (×1.7). A bound proven under XOR cancellations remains
   (`docs/PISTES.md`, lead 8; a parameter search at equal guarantees gains about 1 and 2 %, lead 9); study of a noise cascade with a real effect.
3. **BRUME**: aggregation bounds beyond 2 rounds; real integral reach; search for attacks (boomerang, integrals, algebraic, impossible, graph structure), started, § 4.2 bis; third-party analysis of
   the design. (Exact division property for all cubes: done, 10 rounds per direction.)
4. **C implementation**: done and conformant. BRUME-512 (AVX2, batches), the
   KEM and the SIG are constant-time. NEON done, outputs verified under qemu: constant time and throughput
   to be measured on a real ARM machine. AVX-512 remains (not testable here).
5. **Single-stream throughput**: parallel duplex done (PREUVES § 4.5, review to be done). Reduced rounds in the data
   phase: not adopted, conditions in `docs/PISTES.md`.

---

## 8. Log of flaws found (educational value)

| Version | Flaw | Detection | Fix |
|---|---|---|---|
| v0.1 | KEM: dense term `(r1⊕r2)·x·h` (noise ≈ n/2) | bench | `r1·s` |
| v0.1 | Diffusion through sequential XOR → 0 % avalanche | bench | simultaneous XOR |
| v0.1 | "Kasami" S-box x¹³: du = 12 | bench | x²⁵¹ |
| v0.1 | EC code blind to even masks | bench | per-bit-plane syndromes |
| v0.2 | Unweighted diffusion on an exponent-2 group: cycle 1→7→1 | theorem + bench | D₁₂₈ + GF(16) coefficients |
| v0.2 | AEAD: zero extension | self-test | length block |
| **v0.3** | **SIG: challenge 2 revealing r and r⊕e → key handed over by one signature** | audit | conforming Stern |
| **v0.3** | **AEAD: final block and length block in the same rate → forgery with p = 1** | audit | 10*, domains, permutation |
| v0.3 | KEM without re-encapsulation (no FO) | audit | FO with implicit rejection |
| v0.3 | KEM `tensor` mode: pk of density 0.25 | audit | mode removed |
| **v0.3** | **KEM: decapsulation skipped re-encapsulation after a decoding failure → failure visible in timing (≈ 0.28 ms), oracle for reaction attacks** | inspection + dudect | systematic re-encapsulation, masked selection (Python and C) |
| v0.3 | C permutation through tables indexed by the state (cache leak) | dudect | constant-time AVX2 kernel (same outputs) |
| **v0.3** | **KEM proofs: H1 and H2 stated without the parity constraint (s(1) and u(1) are public), hence distinguishable with advantage 1/2** | external audit | H1-P / H2-P assumptions with parity, IND-CPA proof redone; scheme unchanged |
| v0.3 | AEAD proof: "advantage ≤ 2⁻⁶², 128 bits" instantiation mixing two notions; ambiguous ideal game | external audit | cost/advantage notion defined, Corollary 14 bis term by term, standard restriction of the AE game |
| v0.3 | C SIG: π materialized and read at indices π(i), rows of H skipped depending on the bits of u and e (cache and timing leak) | dudect (t ≈ −220 to −460) | Fisher–Yates applied through a masked sweep, masked H·u (same signatures) |
| **v0.4** | **SIG: 134 KB (Stern): responses containing whole n-bit vectors, ε = 2/3** | external size analysis, figures re-checked | hypercube MPC-in-the-Head, 8.5 KB, same (H3), ISD margins kept |
| **v0.4** | **KEM: repetition code of rate 1/531** | external analysis, figures re-checked; its 5–7 KB target assumed independence | spread RM(1,7), proven δ, 9.8 KB |
| v0.4 | RM code at consecutive or periodic positions: the certified bound loses up to 30 bits and varies between keys (dense windows) | measurement on real keys | public pseudo-random spreading of the positions |
| v0.4 | SIG: `aux` unbound when the last leaf is hidden (≈ 1 signature in 370): malleable signature. EUF-CMA and the secret unaffected | review of the proof against the code, attack executed | `aux = 0` required, Proposition 9 (SUF-CMA) |
| v0.4 | `sig_flux` red on the new SIG: table built during the trace, loop duplicated by gcc, hashes compared after the loop. Test artifacts: the `mat_vec_ct` assembly contains no secret branch | control-flow check, reading the assembly | test fixed; `asm` barriers on the masks kept as a precaution |
| v0.4 | `(double)uint64_t` in the δ bound: the conversion branches on x86, on a value derived from the key | Valgrind (ctgrind) | going through `(double)(int64_t)` |
| v0.3 | C KEM: sparse sampling by rejection with variable duration (seed derived from μ) → "Don't Reject This" type of leak | dudect (t = −53) | fixed number of words, branch-free acceptance (same positions) |
| v0.3 | C KEM: sparse multiplications with secret shifts (cache) | inspection + dudect | dense representation, Karatsuba + PCLMULQDQ |
| v0.3 | Documentation: division property upper bounds presented as general while established for a single cube (bit 0 inactive) | review (exact search) | scope corrected, then bounds established for all cubes and tightened to the exact value (10 per direction) |
| v0.3 | KEM dudect bench: ciphertext repeated per class, confounded with the secret → false failures in the night run (t = −5.68 / −6.75) | night run + diagnosis through separate plans | plans with shared ciphertext pools, shared measurement buffer, A/A and control; mechanism of the repetition effect not identified |
| v0.3 | Night campaign: "no distinguisher beyond 7/5" check impossible to fail (tests limited to 6/5); truncated differentials blind to the known bias; tautological KEM bound | run review | per-family reach, controlled coverage, aligned χ², independent naive recomputation |
| v0.3 | New joint linear test in the campaign: χ² with 225 dof instead of 255 → p-values too small (0.007 at 2 rounds, 0.7 once fixed) | validation campaign (χ² stable from 2²⁴ to 2³⁰) | 255 dof, calibration check under H₀ (254.88 measured) |
| **v0.3** | **SIG-256: 128-bit σ_π (one signature gives e in 2¹²⁸) and 256-bit hashes (collision of H(m) → forgery in 2¹²⁸): real level ≈ 128 bits instead of 256** | review of Theorem 8 | \|σ_π\| = λ, 2λ-bit hashes (SIG-256 format changed), π bound to (salt, i); attack executed on a reduced space |
| v0.3 | Theorem 8: commitments called "hiding by entropy", false for challenges 0 and 1; no term for H(m); needless forking | review | Proposition 7 and Theorem 8 rewritten, extraction from the oracle table (reduction with no loss in q) |
| v0.3 | C: `H(pk)` cached in decapsulation, dudect alert (t ≈ −69 at 128 bits, −44 at 256): a cache effect, on a public value, but it masked any measurement | dudect, during optimization | cache removed from decapsulation (t = −0.31 / 1.36), kept for encapsulation |
| v0.3 | SIG Valgrind control eliminated by gcc, hence a blind check; KEM without a Valgrind check | undetected control | barrier on the result, `test_c_kem_valgrind` |
| v0.3 | C: unchecked system randomness, static caches shared between threads, intermediate secrets not erased, δ bound histogram indexed by a secret | review during optimization | error reported, per-thread caches, erasures, bitsliced counters |
| v0.3 | C: `tmp[k]` in `sl_creux` (index depending on rejections, KEM and SIG), `sk[pos]` at keygen; gcc recreated a branch on k; π(u), g, pos not erased | Valgrind (ctgrind), not seen by dudect | write through a masked sweep, optimization barrier, erasures (same outputs) |
| v0.3 | Lemma 15: inverse queries "removed" for q²/2^{b+1} (false: concrete distinguisher in q²/2^c), inputs already asked not counted, F_0 mishandled | review and simulation | proof rewritten; bound 7q(q+1)/2^{c+1}; BDPV conditions checked against their definitions |
| v0.3 | SIG ISD: BJMM optimum on the grid boundary (p ≤ 24): 160.5 / 327.2 b announced, 159.7 / 314.9 b real; Stern and Dumer conflated | review | locally stopping grid, controlled optimum, real solvers, comparison with CryptographicEstimators |
| v0.3 | Lead 7: "t = 438 is enough for 128 quantum b" false | quantum check | also needs a 32-byte σ_π and w ≥ 204 |
| v0.3 | SIG: ε = 3/4 (challenges {0,1,2,2}), byte permutation | audit | ternary challenges, bits |
| v0.3 | Unfounded "Prange/2.4" estimators (KEM ≈ 300 b for 128 announced) | audit | concrete ISD, resizing (sizes ÷ 2.5) |
| v0.3 | Linear propagation with unconverted masks | audit | binary adjoint `GMUL_T` |
| v0.3 | AEAD key processed by SHAKE, never by BRUME | audit | keyed duplex on the permutation |
| v0.3 | 256-b capacity incompatible with λ = 256 | audit | -256 profile: capacity 384 |
| **v0.3** | **KEM: δ justified by a Gaussian z-score — rigorous bound: 2⁻⁶⁰…2⁻⁷⁵ instead of 2⁻¹⁹²** | FO proof | certified Chernoff bound, key validation, resizing |
| v0.3 | Permutation: 4 numpy operations per round | bench | merged tables (RC+S+GF(16)): +30 % |

Details: `docs/RAPPORT_AUDIT.md`.
