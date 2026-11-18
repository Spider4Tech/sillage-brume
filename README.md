# SILLAGE / BRUME

[![C/C++ CI](https://github.com/Spider4Tech/sillage-brume/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/Spider4Tech/sillage-brume/actions/workflows/c-cpp.yml)
[![CodeQL](https://github.com/Spider4Tech/sillage-brume/actions/workflows/codeql.yml/badge.svg)](https://github.com/Spider4Tech/sillage-brume/actions/workflows/codeql.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

**Experimental cryptographic research project — version 0.6.0**

SILLAGE is a research suite built around code-based constructions and noisy decoding. The repository contains a key-encapsulation mechanism, a syndrome-decoding signature scheme, the BRUME-1024q permutation, authenticated-encryption modes, hash functions, C implementations, and a collection of tests and cryptanalysis tools.

> **Version status.** **v0.6.0** replaces BRUME-512 by **BRUME-1024q** (1 024-bit permutation, sponge capacity
> c = 384, 32 rounds, 128-bit quantum generic target) in the library and in the test battery (`docs/MIGRATION_V06.md`).
> Its specification, proofs and studies are in [`docs/brume1024/`](docs/brume1024/); C3 ≥ 21 and C4 ≥ 28 are certified;
> the AEAD, parallel AEAD and TE proofs are written by us and **not reviewed**; quantum security of the AEAD under
> superposition queries (Q2) is not claimed. The KEM and the signature are unchanged from v0.5. BRUME-512 and its tests
> are archived in `tests/historique_v05/`.

> **Research prototype — not for production use.** The parameters and constructions are experimental. The v0.6.0 designs have not received a complete independent cryptanalysis. The reductions and computational estimates documented here are conditional on the assumptions and models stated in [`docs/PROOFS.md`](docs/PROOFS.md) and [`docs/brume1024/`](docs/brume1024/). Passing the test suite is not evidence that a construction is secure.

The measurements and test totals below refer to dated runs committed with the project; they are not live CI results. The documents in `docs/` are in English ([`docs/README.md`](docs/README.md) lists them); a few external review reports are kept in their original French. Code comments, test names and result files are in French. The C implementation and Python package are under `sillage/`.

**Reviewers and cryptanalysts:** results are welcome, including on reduced rounds or reduced sizes. See [`SECURITY.md`](SECURITY.md) for where to report them and [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to build and test.

---

## Contents

- [Project scope](#project-scope)
- [Components at a glance](#components-at-a-glance)
- [Installation and build](#installation-and-build)
- [Quick start](#quick-start)
- [Sillage-KEM](#sillage-kem)
- [BRUME-1024q](#brume-1024q)
- [Authenticated-encryption modes](#authenticated-encryption-modes)
- [Hash functions](#hash-functions)
- [Sillage-SIG](#sillage-sig)
- [C implementation and SIMD](#c-implementation-and-simd)
- [Tests and cryptanalysis](#tests-and-cryptanalysis)
- [Measured performance](#measured-performance)
- [Security assumptions and limitations](#security-assumptions-and-limitations)
- [Repository layout](#repository-layout)
- [Development roadmap](#development-roadmap)
- [Design history](#design-history)
- [Continuous integration](#continuous-integration)
- [Reporting, contributing and citing](#reporting-contributing-and-citing)
- [Further reading](#further-reading)

---

## Project scope

The project explores a common design direction: use sparse secret vectors and noisy algebraic relations so that the legitimate party can recover a structured message or witness, while an attacker is faced with a decoding problem.

The current implementation contains three main cryptographic components:

1. **Sillage-KEM**, a quasi-cyclic sparse-noise key-encapsulation mechanism with a Fujisaki–Okamoto transform and implicit rejection.
2. **BRUME-1024q**, a 1 024-bit permutation used by a full-state keyed duplex (AEAD), a parallel AEAD, a self-correcting mode (TE), a sponge XOF and a tree hash (the default digest).
3. **Sillage-SIG**, a VOLE-in-the-Head signature over regular syndrome decoding (v0.5), with the MPC-in-the-Head signature of v0.4 kept as a reference.

The repository is intended to make the constructions inspectable and testable. It includes mathematical notes, reductions, parameter estimators, reduced-model experiments, C implementations, conformance tests and cryptanalysis programs. It is not a standards submission and does not claim production readiness.

## Components at a glance

| Component | Construction | Current profiles | Main qualification |
|---|---|---|---|
| Sillage-KEM | Quasi-cyclic sparse-noise decoding, RM(1,7) code, FO transform | `Sillage-256` (`Sillage-128` removed on 18 November 2026) | IND-CCA argument in the ROM, conditional on H1-P/H2-P and the stated correctness bound |
| BRUME-1024q | 1 024-bit, 32-round permutation over 256 GF(16) nibbles; sponge r = 640, c = 384 | — | C3 ≥ 21 and C4 ≥ 28 certified (≥ 224 active S-boxes over 32 rounds); security of the full permutation is not proved |
| Sequential AEAD | Full-state keyed duplex over BRUME-1024q (key 64 B, nonce 24 B, tag 32 B) | `BRUME-1024q` | Ideal-permutation proof (repaired DMV17 Theorem 1) and Q1 proof, ours, not reviewed; unique nonces |
| Parallel AEAD | Leaves of 8 KiB, two fork calls, 64-byte chaining values, root | `BRUME-1024qp` | Separate construction and ciphertext format; separate proof and tests |
| TE mode | 7 parity bytes per 64-byte block, one byte corrected per block, then the AEAD tag | over `BRUME-1024q` | Exact reduction to the AEAD (Proposition TE) |
| Hash | Default digest: sponge up to 8 KiB, one-level tree above (64-byte output); XOF | Variable output length, 64 B by default | Generic sponge bound 2^192 classical; quantum collision/preimage proved at ≈ 2^123.8 queries (ours, not reviewed) |
| Sillage-SIG v0.5 | VOLE-in-the-Head over regular syndrome decoding (C only) | `VOLE-256`, `VOLE-256f` (`VOLE-128`, `VOLE-128f` removed on 18 November 2026) | EUF-CMA/SUF-CMA in the ROM reduced to binary SD (Lemma 17.2); QROM sketch within ≈ 2 bits of Grover; not reviewed |
| Sillage-SIG v0.4 (reference) | MPC-in-the-Head over binary syndrome decoding | `Sillage-SIG-128`, `Sillage-SIG-256` | Kept unchanged as a reference; superseded by v0.5 |

The profile suffixes `128` and `256` are parameter labels. They must not be read as a blanket claim of 128-bit or 256-bit post-quantum security. The KEM and signature sections give the actual estimates and limitations. **v0.6.0 changes every symmetric format.** BRUME-1024q replaces BRUME-512: every AEAD, TE, hash and XOF output, the tag length (32 bytes) and the default digest length (64 bytes) change; there is a single AEAD profile. v0.5 ciphertexts, hashes and KATs are no longer valid. The KEM and signature outputs are unchanged.

---

## Installation and build

### Requirements

The Python reference package requires:

- Python 3.10 or later;
- NumPy.

The documented and benchmarked native build is on Linux with GCC. Other operating systems and compilers require separate validation. Building the C library requires:

- GCC or a compatible C compiler;
- GNU Make;
- OpenMP support in the compiler;
- a platform providing the system interfaces used by the C implementation.

The full test suite also uses additional packages, including NetworkX, OR-Tools, `python-sat` and SciPy, plus Valgrind and the SAT solvers `cryptominisat5` and `cadical` on the PATH. Matplotlib is used by optional plotting code when available. The repository does not currently provide a pinned dependency lockfile, so the exact package versions used for a run should be recorded with its results.

### Install the Python runtime dependency

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt        # NumPy
```

For the full test and cryptanalysis suite:

```bash
python -m pip install -r requirements-tests.txt  # NetworkX, OR-Tools, python-sat, Matplotlib, SciPy
```

Some tests require a working C toolchain and OpenMP even when the Python package is available.

### Build the C library

```bash
make -C sillage/c
```

This builds:

- `sillage/c/build/libsillage.so` — the shared library loaded by the Python API;
- `sillage/c/build/bench` — the C benchmark executable.

The default Makefile flags are `-O3 -march=native -fopenmp -Wall -Wextra`. The resulting binary is tuned for the CPU on which it was built. It should not be copied to a different processor and assumed to be portable. The C loader fingerprints the build configuration, including CPU flags.

The BRUME-1024q tables (`sillage/c/brume1024_*.h`) are generated by `prototypes/brume_q/b1024/gen_b1024.c` and
`gen_bitslice.c`; the battery and the CI check that the generator gives them back unchanged. Without AVX2 (for example on
ARM), the library uses a portable constant-time kernel; there is no table-based fallback.

### Python fallback and the C requirement

The public API in `sillage/rapide.py` uses the C implementation when it is available. If the library cannot be loaded or built, it emits a warning and falls back to the Python reference implementation for the KEM and the v0.4 signature. BRUME-1024q and the VOLE signature exist only in C: without the library their classes raise `RuntimeError`.

The Python implementation is useful for inspection and cross-checking, but it is **not constant-time**. To make an unavailable C backend an error instead of silently using the Python fallback, set:

```bash
SILLAGE_C_OBLIGATOIRE=1 python -m sillage.demo
```

This setting does not make the prototype production-safe; it only prevents fallback to the non-constant-time reference code.

---

## Quick start

The following example uses the public API. It illustrates the interfaces; it is not a deployment recommendation.

```python
import secrets

from sillage import (
    SillageKEM,
    SillageVOLE,
    Brume1024,
    Brume1024P,
    brume1024_hash,
    brume1024_xof,
)

# Key encapsulation
kem = SillageKEM("Sillage-256")
pk, sk = kem.keygen()
ct_kem, shared_secret = kem.encaps(pk)
assert kem.decaps(sk, ct_kem) == shared_secret

# Sequential authenticated encryption
key = secrets.token_bytes(64)
nonce = secrets.token_bytes(24)  # Must be unique per key.
aead = Brume1024("BRUME-1024q", key=key)
plaintext = b"example message"
ciphertext, tag = aead.encrypt(nonce, plaintext, aad=b"context")
assert aead.decrypt(nonce, ciphertext, tag, aad=b"context") == plaintext

# Parallel authenticated encryption: a distinct mode and ciphertext format
parallel_key = secrets.token_bytes(64)
parallel_nonce = secrets.token_bytes(24)
parallel = Brume1024P("BRUME-1024qp", key=parallel_key)
large_message = b"example" * 10000
ct_parallel, tag_parallel = parallel.encrypt(parallel_nonce, large_message)
assert parallel.decrypt(parallel_nonce, ct_parallel, tag_parallel) == large_message

# Self-correcting mode: one damaged byte per 64-byte block is repaired before the tag check
ct_te, parities, tag_te, meta = aead.encrypt_te(nonce, plaintext)
recovered, corrections = aead.decrypt_te(nonce, ct_te, parities, tag_te, meta)

# Hashing: default digest (64 bytes; sponge up to 8 KiB, tree above) and XOF
h = brume1024_hash(b"message")
stream = brume1024_xof(b"seed", 200)

# Digital signatures (v0.5: VOLE-in-the-Head)
sig = SillageVOLE("VOLE-256")
pk_sig, sk_sig = sig.keygen()
signature = sig.sign(sk_sig, plaintext)
assert sig.verify(pk_sig, plaintext, signature)
```

**Nonce handling is the caller's responsibility.** Do not reuse a nonce with the same key: the proofs are nonce-respecting. See [Authenticated-encryption modes](#authenticated-encryption-modes).

The package exports the public classes and profiles from `sillage/__init__.py`. The reference implementations of the KEM and the v0.4 signature remain available from `sillage.sillage_kem` and `sillage.sillage_sig` for comparison with the C-backed API.

---

## Sillage-KEM

### Construction

Sillage-KEM is based on sparse decoding in the ring

$$
R = \mathbb{F}_2[z]/(z^n - 1),
$$

where `n` is selected as an Artin prime for which 2 generates the multiplicative group modulo `n`.

The secret key contains sparse vectors `x` and `y`. A public value is derived from a seed `σ_h`, and the public relation has the form

$$
s = xh \oplus y.
$$

Encapsulation derives its randomness deterministically from the message secret `μ` and the public key. In the notation used by the implementation, it computes

$$
u = r_1h \oplus r_2,
$$

$$
v = cw(\mu) \oplus r_1s \oplus e_1 \oplus \pi(e_2).
$$

The decoder removes the `r₁xh` term through `ux`; the remaining error is bounded and decoded. The public permutation `π` spreads the positions of the RM code. Since `π` is public, the noise cascade is not treated as an additional source of hardness: the security argument rests on the sparse-noise relation and its decoding assumptions.

The PKE is wrapped in a Fujisaki–Okamoto transform with implicit rejection. Decapsulation always re-encapsulates and compares the ciphertext. On a mismatch, it returns a rejection secret bound to `σ_rej`, rather than exposing a decoding-failure result.

### Error-correction code and correctness bound

The v0.4 code uses RM(1,7) repeated `D` times and a public pseudo-random spreading of the positions. A block of `128·D` bits carries one byte of the shared secret. Decoding uses a Walsh transform.

Correctness is analysed with a Chernoff bound that does not assume independent error bits. Key generation evaluates the bound for each candidate key and rejects keys whose certified failure bound exceeds `2⁻λ`. The measured key rejection rate is about 6.1% (Sillage-256) on 8 192 keys (`tests/c/kem_rejet.c`); θ = 0.7 sits at the minimum of these rates (`tests/test_kem_theta.py`). The median bounds are substantially below the acceptance thresholds; see [`docs/PROOFS.md`](docs/PROOFS.md), §2.3.

### Parameters

The values below are from the v0.4.0 parameter set. Since 18 November 2026, **Sillage-256 is the only level**:
Sillage-128 (`n` = 50,021, `w` = 75) was removed because its classical ISD cost (2^138.2) is 4.8 bits under the
2^143 gates of NIST category 1 ([`docs/NIST_CATEGORIES.md`](docs/NIST_CATEGORIES.md)). The level keeps its number in the
C API (1), so its domains and known answers are unchanged; level 0 is refused.

| Parameter | Sillage-256 |
|---|---:|
| `n` | 170,003 |
| Secret/error weight `w` | 140 |
| RM repetition parameter `D` | 28 |
| Public key | 21,283 bytes |
| Encapsulation ciphertext | 35,587 bytes |
| Shared secret | 64 bytes |
| Classical ISD work-factor estimate | 265.1 bits |
| Prange–Grover estimate | 158.4 bits |
| Median certified decapsulation-failure bound | ≈ `2⁻²⁸⁹` |
| Key acceptance threshold | `2⁻²⁵⁶` |

The classical estimates use the concrete ISD estimators documented in the repository. They are computational estimates, not reductions proving that every attack must take that many operations. The quantum figures shown are Prange–Grover estimates without a depth constraint; they are below the profile labels. A separate quantum-walk estimate with free QRAM is lower still. **Sillage-KEM does not claim 128-bit or 256-bit post-quantum security.**

### Security statement

The IND-CPA argument is conditional on the decisional quasi-cyclic syndrome-decoding assumptions H1-P and H2-P, stated with the public parity information. The original formulations without parity were distinguishable and were replaced. The FO transform gives an IND-CCA argument in the random-oracle model under the stated correctness condition and assumptions.

The proof and parameter analysis are in [`docs/PROOFS.md`](docs/PROOFS.md), §§2 and 5. The tests include correctness, malformed-input handling, implicit rejection, distribution checks, ISD estimator comparisons and simulated validation of the `δ` bound. Those tests do not establish the hardness of H1-P or H2-P at the full parameter sizes.

---

## BRUME-1024q

Normative specification: [`docs/brume1024/SPEC.md`](docs/brume1024/SPEC.md); proofs condensed in
[`docs/PROOFS.md`](docs/PROOFS.md) § 4; full arguments and studies in [`docs/brume1024/`](docs/brume1024/).

### Permutation design

BRUME-1024q is a 1 024-bit permutation with 32 rounds. The state is represented as 256 nibbles over

$$
\mathbb{F}_{16} = \mathbb{F}_2[x]/(x^4+x+1).
$$

Each round applies:

1. XOR with a round-constant vector;
2. the 4-bit S-box `AD412650BFEC7893` (that of BRUME-512 v0.5: differential uniformity 4, linearity 8, degree 3) to each of the 256 nibbles;
3. a linear diffusion layer over GF(16): the weighted adjacency matrix plus identity of a 6-regular Cayley graph on the dihedral group `D₂₅₆` (shifts {0, 105, 71, 76, 72, 31}), 7 terms per row.

Diffusion is complete after 5 forward rounds; `M⁻¹` is dense. As a sponge: rate r = 640 bits (80 bytes), capacity c = 384 bits, chosen so that the generic quantum collision cost on the capacity (BHT) is 2^128.

### What the structural results establish

The branch number is exactly 8 over 2 rounds, and two SAT certificates (LRAT proofs checked by two independent checkers) give **C3 ≥ 21** and **C4 ≥ 28** active S-boxes over 3 and 4 rounds. Hence **at least 224 active S-boxes over 32 rounds** and, in the independent-round Markov model:

- differential characteristic probability: at most `2⁻⁴⁴⁸`;
- linear trail correlation: at most `2⁻²²⁴`;

and 196 active S-boxes (`2⁻³⁹²`, `2⁻¹⁹⁶`) with 4 rounds left free (PROOFS, Corollary 11). These are characteristic/trail bounds in the stated model, not bounds on differentials or hulls; aggregation is measured exactly at 2 rounds (max DP `2⁻¹⁶`, hull `2⁻⁷·⁸³`) and at chosen ends of 3 and 4 rounds (factor ≤ 1.25). The permutation is not proved to be an ideal permutation.

### Current cryptanalysis results

All of it is our own analysis (no third-party cryptanalysis yet). Reaches in rounds of 32 ([`docs/brume1024/NIVEAU3.md`](docs/brume1024/NIVEAU3.md) § 4):

| Analysis | Reach | Scope and qualification |
|---|---|---|
| Statistical battery, avalanche | 4 rounds forward, 2 backward | measured |
| Cubes, zero sums | 5 | measured |
| Exact division property | 11 inverse, 11 or 12 forward; 22 or 23 inside-out at ≈ 2^1023 | proved / verified trails; a structural property, not an attack |
| Truncated differentials | free diffusion to 4; nothing found at 5–7 | model + real permutation |
| Impossible differentials, zero correlations | 5 | structural |
| Boomerang | 3 rounds (2^−19.4); below 2^−32 at 4 | measured on GPU |
| Differential-linear | 5 rounds measured (2^−7.1, about 2^14 pairs, dense output mask); model: 9 rounds within 2^128 pairs, 10 within 2^192 | measured at 4 and 5 (the real permutation follows its Markov model there); model corrected for the edge of diffusion and checked at 4 and 5 |
| Sponge collision, rebound type | 3 rounds at ≈ 2^92 | optimal in the nibble model; 4–6 not found below 2^192, not excluded |
| Direct algebraic attacks (CICO by SAT) | advantage over brute force up to 3 rounds | 4 with a linearised first round |

Largest reach of an attack or distinguisher below the claimed level: 9 or 10 rounds (differential-linear, model), a margin of at least 22 rounds.

---

## Authenticated-encryption modes

BRUME-1024q provides two keyed constructions with one profile each, plus a self-correcting layer. They have separate initial states (mode nibble), ciphertexts and proofs.

### Sequential AEAD (full-state keyed duplex)

The key (64 bytes) and the nonce (24 bytes) fill the initial state together with the profile frame; associated data and text are absorbed with 0x01 padding and phase domains; the rate is overwritten by the ciphertext (SpongeWrap orientation); the 32-byte tag is read after the last text block. Three permutations for a short message.

| Profile | Key | Nonce | Rate | Capacity | Tag | Stated level |
|---|---:|---:|---:|---:|---:|---:|
| `BRUME-1024q` | 64 bytes | 24 bytes, unique per key | 640 bits | 384 bits | 32 bytes | classical: forgery 2^256 per attempt, inner state 2^192; Q1: ≈ 127 bits (σ ≤ 2^64) |

The ideal-permutation proof ([`docs/brume1024/AEAD_SECURITY.md`](docs/brume1024/AEAD_SECURITY.md), PROOFS § 4.3) rests on our repaired form of Theorem 1 of Daemen–Mennink–Van Assche (2017); the repair is needed (the published Theorem 1 is exceeded when L + Ω > 0, see `prototypes/brume_q/b1024/dmv17_verif/papier/`). Superposition queries to the mode (Q2) are not claimed. Lengths are limited to 2^63 − 1 bytes.

### Nonce policy

The API receives the nonce from the caller; it does not allocate or track nonces. The proofs are nonce-respecting: a nonce must never be reused with the same key (reuse leaks the XOR of plaintexts up to the first differing block). Uniqueness must survive process restarts and be coordinated across devices sharing a key.

### Parallel AEAD (`Brume1024P`)

For large messages: a trunk absorbs the AAD; each leaf of 8 KiB starts from the trunk, makes two fork calls with its index, and encrypts its chunk as the text phase of the sequential mode; its 64-byte chaining value goes to a root that also absorbs the number of leaves and the length, and gives the tag. Leaves are processed on all cores. Different ciphertexts from the sequential mode. Proof: Theorem P (PROOFS § 4.5, [`V06_MODES.md`](docs/brume1024/V06_MODES.md) § 2).

### Error-correction mode (`TE`)

The `TE` mode adds seven bytes of parity for each 64-byte ciphertext block and corrects one altered byte per block before checking the tag. The parity data is **not authenticated** and does not provide adversarial integrity; the AEAD tag remains the integrity check. It reduces exactly to the AEAD (Proposition TE, PROOFS § 4.6). Overhead ≈ 10.9 % of the ciphertext.

---

## Hash functions

One unkeyed sponge (rate 640 bits, capacity 384 bits) with four domains.

### Default digest (`brume1024_hash`, `sl_hash`)

Messages up to 8 KiB are hashed by the sponge alone; longer messages are split into 8 KiB leaves, each hashed to a 64-byte chaining value (in parallel, in batches of 256 bitsliced states), and a root sponge absorbs the chaining values and the tree metadata. Output length is free, **64 bytes by default** (a 32-byte output would cap quantum collisions at 2^85). Generic classical collision and preimage cost: 2^192. Quantum: collision and preimage proved at about 2^123.8 and 2^124.1 standard queries for a random permutation (PROOFS § 4.4, [`SPONGE_QROM.md`](docs/brume1024/SPONGE_QROM.md); ours, not reviewed), against 2^128 for the best generic attack. Indifferentiability: only ≈ 2^42.7 proved.

### XOF (`brume1024_xof`, `sl_xof`)

The sequential sponge with domain 0 and any output length. A distinct function from the default digest.

---

## Sillage-SIG

### v0.5: VOLE-in-the-Head over regular syndrome decoding

The signature proves knowledge of a **regular** vector x, with one error per block of 256 positions, such that `H x = y` and
`H = [H′ | I]`. Each position is the tensor product of four unit vectors of size 4, which gives degree-4 constraints, checked
with a single GGM tree, an opening limit and grinding (VOLE-in-the-Head, in the style of FAEST and SDitH v2.0). The format is
SPEC § 4 bis, with a normative annex for the constraint system; the code is `sillage/c/vole.c`, C only.

| Profile | `(n, k, w)` | τ, κ | Public key | Secret key | Signature | Sign, 12 threads |
|---|---|---|---:|---:|---:|---:|
| `VOLE-256` | `(38 912, 37 480, 152)` | 21, 12 | 211 B | 363 B | 16 122 B | 20–29 ms |
| `VOLE-256f` | same as VOLE-256 | 32, 8 | 211 B | 363 B | 20 467 B | 5.4 ms |

`VOLE-128` and `VOLE-128f` were removed from the library on 18 November 2026: they reach no NIST category in the gate model
([`docs/NIST_CATEGORIES.md`](docs/NIST_CATEGORIES.md)). The remaining profiles keep their numbers in the C API (1 and 3),
so their known answers are unchanged; 0 and 2 are refused. The research prototype (`prototypes/vole/vole_proto.c`) still
studies the 128-bit parameters, and the proofs below still state them.

What is established, and how (PROOFS § 3 bis):
- **Assumption.** Lemma 17.2 is an exact reduction from binary SD (H3) to regular SD, with no uniqueness heuristic: the
  codimension is `⌈log₂ C(n, w)⌉`. In its direct form (12 November 2026), the (H3) instance is passed on unchanged. In the ROM,
  the scheme therefore rests on (H3) alone, at rate ≈ 0.96. The reduction guarantees 162.4 and 317.8 bits in our ISD model
  (160.6 and 316.0 with the former form, which went through uniform-matrix SD); the best direct attack costs 264.0 and 525.0 bits (CryptographicEstimators:
  275.4 and 612.2).
- **Exact blocks.** Lemma 17.1 shows that a block must have exactly `Π μ = 256` positions. Otherwise empty blocks pass. Our first
  prototype, and apparently the parameter table of SDitH v2.0, had this gap.
- **EUF-CMA in the ROM** (Theorem 17): λ bits in the cost/advantage notion, at 0.88 of the budget. Lemma 17.5 shows that the
  opening limit and grinding do not change the Δ term.
- **SUF-CMA and binding** (Propositions 17.3 and 17.4). The only malleability is another counter giving the same challenge, at a
  cost of 2^131 or more.
- **QROM** (Theorem 17-Q, a sketch based on Theorems 54 and 56 of ePrint 2026/164): 2^61.8 and 2^125.8 quantum queries, within
  2.2 bits of Grover. It needs the decisional variant of regular SD. Its round-by-round soundness is proved in Lemma 17.6;
  the other steps of that paper are still cited.
- **Executed attacks**, against the real verifier:
  - each soundness term on reduced models: the Δ, γ and VOLE-check challenges;
  - Kales–Zaverucha transposed to the three rounds of VOLE, at intermediate scale.

  In each case, the success frequency matches the exact prediction and stays under the bound.
- **Implementation:**
  - memory and randomness errors are propagated, with injected failures;
  - ctgrind on the full profiles, dudect, fuzzing under ASan and UBSan;
  - KATs are identical on x86-64 and ARM64.

**None of these proofs has been reviewed by a third party.**

### v0.4: MPC-in-the-Head (reference)

The v0.4 signature (hypercube MPC-in-the-Head over binary SD, five-pass Fiat–Shamir; `SillageSIG`, `sl_sig_*`, SPEC § 4) is
kept unchanged as a reference.

| Parameter | Sillage-SIG-128 | Sillage-SIG-256 |
|---|---:|---:|
| Binary code `(n, k, w)` | `(2048, 1434, 103)` | `(4096, 2867, 206)` |
| Public key / secret key | 109 / 464 bytes | 186 / 977 bytes |
| Signature | 8,522 bytes | 34,867 bytes |
| Classical ISD / ROM forgery estimates | 160.3 / 128.3 bits | 316.2 / 264 bits |

Its QROM reduction proves only about 32 and 68 bits (Don–Fehr–Majenz). The profile labels do not imply 128-bit or 256-bit quantum
security for either signature.

---

## C implementation and SIMD

The `sillage/c/` directory contains the C implementation of BRUME-1024q and its modes (`brume1024.c`), Sillage-KEM, Sillage-SIG and SHAKE256 support code. The C API (`sillage/c/sillage.h`) is exposed to Python through `ctypes` in `sillage/sillage_c.py` and used by the public wrappers in `sillage/rapide.py`.

### BRUME-1024q kernels

All kernels are constant time with respect to the state (no table indexed by secret data):

- **AVX2, one state:** the state is kept unpacked (one nibble per byte, 8 registers) from block to block; the S-box and the GF(16) products are register shuffles (`vpshufb`), the diffusion uses fixed rotations.
- **AVX2, 32-state batches** (vertical) and **AVX2 bitsliced, 256 states** (one register per bit of a nibble, S-box as a 22-gate circuit): used for tree leaves and multi-message AEAD.
- **Portable kernel** (`brume1024_portable.h`, plain C on 64-bit words, S-box as a 17-gate circuit): used when AVX2 is not available (for example on ARM). There is no table-based fallback and no NEON kernel yet.
- **Dense reference** (explicit M and M⁻¹, `sl_brume_permute_ref`, `sl_brume_permute_inv_ref`): for cross-checking only, not constant time.

The kernel is selected at compile time (`-march=native`). Every kernel is checked against the dense reference and the 23 test vectors, with and without AVX2 (`tests/c/brume1024.c`, `tests/c/brume1024_api.c`).

### Parallel processing

Tree leaves, parallel-AEAD leaves and multi-message batches are distributed across cores with OpenMP. Single-core and multi-core measurements are identified separately in the benchmark report.

### Side-channel testing

dudect-style timing experiments (`tests/c/temps1024.c` for BRUME-1024q: AVX2 and portable kernels, AEAD with key and plaintext secret, verified decryption on the accept and reject paths; `tests/c/temps.c` for the KEM and SIG) and Valgrind/ctgrind checks (`tests/test_c_brume1024_valgrind.py`, `tests/test_c_kem_valgrind.py`, `tests/test_c_sig_valgrind.py`), each with a witness that must be detected, and a static check for Speculative Store Bypass stack-slot gadgets (`tests/test_c_gadget_ssb.py`, which ctgrind cannot see). These are empirical checks, not a proof of constant-time execution; results depend on compiler, flags, CPU, operating system and methodology. The Python reference implementation of the KEM is not constant-time. Timing on ARM is not measured.

---

## Tests and cryptanalysis

Run the complete suite with:

```bash
python3 -m tests.run_all
```

The orchestrator runs the Python tests concurrently and schedules the intensive C/OpenMP tests after them. Each test writes a JSON result under `resultats/` and a log under `resultats/logs/`; the orchestrator writes `resultats/SYNTHESE.md` and `resultats/synthese.json`.

Useful subsets and options:

```bash
python3 -m tests.run_all brume1024 b1024_preuves kem    # select tests
python3 -m tests.run_all -j 4                           # four concurrent Python test workers
SILLAGE_INTENSITE=4 python3 -m tests.run_all b1024_statistiques
python3 -m tests.bench_c                                # C implementation benchmark
python3 -m tests.empreintes                             # source, KAT and result fingerprints
```

The long BRUME-1024q campaigns (cryptanalysis studies, certificates) are run with the tools of `prototypes/brume_q/b1024/` and `prototypes/brume_q/sat/`; their results are written into the studies of `docs/brume1024/`. `./scripts/rundenuit.sh`, `./scripts/runlong` and `scripts/rundenuit.cmd` still run the long KEM, signature, fuzzing and timing campaigns ([`docs/CAMPAIGN_24H.md`](docs/CAMPAIGN_24H.md)); their BRUME-512 phases were retired in v0.6.

### Coverage by area

Individual test modules and C programs contain the precise parameters and assertions.

| Area | Main checks and experiments | Selected modules / programs |
|---|---|---|
| Functional behaviour | KATs, round trips, malformed inputs, API behaviour, table fingerprints, demo | `test_fonctionnel`, `test_kem`, `test_sig`, `test_vole` |
| BRUME-1024q modes | 23 test vectors through the API with and without AVX2; kernels against the dense reference; AEAD against a literal transcription of DMV17; decoder of the final path; tamper rejection; parallel AEAD; TE corrections and refusals; multi-message batches | `brume1024`, `brume1024_api`, `brume1024_api_portable` |
| Specification | Second implementation from the specification alone; table generator reproduces the library tables; portable kernel against an independent dense reference | `test_b1024_seconde_implementation` |
| Proof checks | Encoding lemma of the parallel AEAD; quantum hash bound (counting lemma exhaustive on small models, witness); Carolan–Majenz chain evaluated exactly; Q1 identities and lemmas; numerical instantiations of PROOFS | `test_b1024_preuves`, `test_bornes_preuves` |
| BRUME-1024q permutation | C4 ≥ 28 certificate tree re-read; structure (Frobenius, invariants, invariant subspaces, quasi-symmetries); local quadratic invariants; exact 2-round aggregation; statistical battery and avalanche | `test_b1024_certificats`, `test_b1024_structure`, `test_b1024_statistiques` |
| Cryptanalysis tools | Algebraic (CICO by SAT), rebound and differential-linear tools, each against its witness | `test_b1024_etudes` |
| KEM assumptions and estimators | Error distributions, δ-bound experiments, reduced-instance ISD, estimator consistency, parity and correlation checks | `test_isd_parametres`, `test_c_kem_bruit`, `isd_reel`, `isd_comparaison`, `kem_distributions` |
| Signature protocol | Reduced-model checks, Kales–Zaverucha attacks against the C verifier, challenge distribution, malformed signatures | `test_sig_modele`, `sig_kz`, `sig_flux`, `test_vole_kz` |
| C implementation | Conformance, API interoperability, fuzzing, guard pages, UBSan, Valgrind/ctgrind and dudect timing tests | `test_c_impl`, `test_api_c`, `test_c_fuzz`, `test_c_brume1024_valgrind`, `test_c_kem_valgrind`, `test_c_sig_valgrind`, `test_c_gadget_ssb`, `temps1024`, `test_c_temps` |

The tests of BRUME-512 (v0.5) are archived in `tests/historique_v05/` and no longer run.

### Latest committed test summary

The committed [`resultats/SYNTHESE.md`](resultats/SYNTHESE.md) reports the v0.6 run of 18 November 2026, after the removal of the 128-bit KEM and VOLE profiles: **570 of 570 controls passed, 46 tests**, 42 minutes.

Two findings of the v0.6 runs were fixed before this one ([`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md), changes of 2026-11-17). The dudect test flagged the portable BRUME-1024q kernel (|t| up to 22) when GCC 13.3 inlined it into the timing harness on a Zen 3 machine; the signal followed the code layout (not the frequency, not the alignment of the state; ctgrind clean), and disappears on every layout tried once the kernel is not inlined (`noinline`, outputs unchanged). Its cause was then identified as a Speculative Store Bypass: inlined, the kernel shared one stack slot between the round-constant pointer and a secret intermediate, and a speculative reload of the pointer used the secret as an address (proved by turning the bypass off with SSBD: 12 of 12 runs clean against 12 of 12 flagged). A static check of the library for this pattern, `test_c_gadget_ssb`, now runs in the battery and in the CI. A control of the rebound study tool depended on the solver's wall-clock time; it now uses the solver's deterministic time. This is a snapshot of one run on one machine; passing it does not prove the hardness assumptions or the security of the full permutation.

---

## Measured performance

The committed C benchmark [`resultats/BENCH_C.md`](resultats/BENCH_C.md) was produced on 17 November 2026 on an AMD
Ryzen 5 5600G (6 cores / 12 threads), GCC 13.3, `-O3 -march=native`, OpenMP, Python 3.12 for the reference. Unless
stated otherwise, values are single-core. They are measurements of this implementation on this machine, not portable
guarantees.

| Operation | Measured result |
|---|---:|
| BRUME-1024q permutation, AVX2, one state | 0.771 µs |
| BRUME-1024q permutation, 32-state batch | 725 ns per state |
| AEAD, 64-byte message | 2.35 µs |
| AEAD, 1 MiB | 101 MiB/s |
| Default hash, 16 MiB, one core / 12 threads | 240 / 873 MB/s |
| XOF, 16 MiB | 106 MB/s |
| Parallel AEAD, 16 MiB, one core / 12 threads | 103 / 627 MB/s |
| Multi-message AEAD, 16 KiB messages, 12 threads | 523 MB/s (674 MB/s with a common key) |
| TE, 1 MiB: encryption / correction | 29.8 / 48.7 ms |

KEM and signature timings are unchanged from v0.5 (the code did not change): Sillage-256 key generation 27 ms,
encapsulation 1.18 ms, decapsulation 1.84 ms; Sillage-SIG-128 (v0.4, reference) signing 34.9 ms on one core, 5.5 ms on
12 threads. The full tables, with the C/Python factors, are in [`resultats/BENCH_C.md`](resultats/BENCH_C.md).
Against BRUME-512 (v0.5, same machine): the AEAD at 1 MiB goes from about 83 to 101 MiB/s, the tree hash on 12 threads
from 793 to 873 MB/s, at a larger capacity (384 bits instead of 256). Known gap: multi-message batches with a common key
(`sl_aead_*_multi_ctx`) do not yet use the batch kernels for short messages (177 MB/s against 265 MB/s at 64 bytes).

---

## Security assumptions and limitations

The status of each claim matters. The repository distinguishes exact structural results, bounds proved in a specified model, computational estimates, reduced-model experiments and open assumptions. They should not be conflated.

### BRUME-1024q

- The S-box properties, branch number and diffusion supports are checked exhaustively; C3 ≥ 21 and C4 ≥ 28 are certified by SAT with LRAT proofs checked by two checkers. The 224-active-S-box bound over 32 rounds is structural; the probabilities derived from it use the independent-round Markov model.
- Aggregated differentials and hulls are computed exactly only at 2 rounds and at chosen ends of 3 and 4 rounds; no general aggregation bound is claimed. The active S-box counts bound characteristics only: a differential-linear correlation sums over characteristics, and in the first four rounds the S-boxes outside the ball of the difference cost nothing. The corrected differential-linear model is a heuristic, checked against the measurement at 4 and 5 rounds (`docs/brume1024/DIFF_LIN.md`).
- The mode proofs model BRUME-1024q as an ideal permutation. They do not prove that the concrete 32-round permutation is ideal or pseudorandom.
- The permutation is new; all its cryptanalysis is ours. Third-party cryptanalysis is the main missing item.

### Sillage-KEM

- IND-CPA depends on H1-P and H2-P, the decisional quasi-cyclic syndrome-decoding assumptions with the parity information included.
- IND-CCA is argued through the FO transform in the random-oracle model, under the stated correctness condition and assumptions.
- The per-key Chernoff bound certifies the documented decapsulation-failure probability for accepted keys. It does not prove H1-P or H2-P.
- Classical ISD costs are estimates from the attack families and parameter searches implemented in the repository. The quantum estimates are below the profile labels; no 128-bit or 256-bit post-quantum claim is made.
- The proof document explores QROM reduction estimates of approximately 60 and 104 bits (or 43 and 85 bits under the free-QRAM variant). These are reduction bounds, not measured attack costs. There is an important qualification: the cited reduction is formulated for explicit rejection, whereas Sillage-KEM uses implicit rejection; the document notes that this step has not been verified. The separate quantum attack estimates are approximately 91.7 and 158.4 bits for Prange–Grover, and approximately 67 and 129 bits under the documented quantum-walk model with free QRAM. None of these figures supports a 128-bit or 256-bit post-quantum claim.

### Sillage-SIG

- The EUF-CMA and SUF-CMA arguments depend on H3 and the random-oracle model, along with the stated protocol lemmas.
- The v0.4 MPC-in-the-Head protocol and its proof are new to this version. The reduced-model tests exercise selected properties but do not replace a full cryptographic analysis of the instantiated protocol.
- The QROM analysis is not a complete security proof for the instantiated scheme. The proof document gives an exploratory reduction estimate of approximately 32.2 and 68.2 bits, compared with Grover-based forgery estimates of approximately 64.1 and 132 bits. The reduction requires assumptions about the commitment hash and quantum proof of knowledge that are not established for this implementation. The profile names do not represent established quantum security levels.

### AEAD and hashing

- The sequential AEAD, the parallel AEAD and TE are proved in the ideal-permutation model, nonce-respecting, without release of unverified plaintext (PROOFS § 4.3–4.6). The classical proof rests on our repaired form of DMV17 Theorem 1. Model Q1 (quantum queries to the permutation) is proved by us at about 127 bits for σ ≤ 2^64; superposition queries to the mode (Q2) are not claimed beyond two partial results. **None of these proofs has been reviewed by a third party.**
- NIST categories, from a gate model of the attacks ([`docs/NIST_CATEGORIES.md`](docs/NIST_CATEGORIES.md), ours, not reviewed): the suite is in category 3 (KEM-256 and hash preimages; VOLE-256 reaches 5 only with the revised JNRV 2020 thresholds); the AEAD is in category 5 against the known attacks. The 128-bit KEM and VOLE profiles, which reached no category, were removed on 18 November 2026.
- The hash's 128-bit quantum level for collisions rests on the generic attack cost (BHT on c = 384); our adaptation of Carolan–Majenz proves about 2^123.8 queries (preprint, ours, not reviewed). Indifferentiability is proved only at about 2^42.7.
- The TE parity data is not authenticated. Only the AEAD tag protects against adversarial modification.

### Implementation and side channels

- The Python reference code of the KEM is not constant-time.
- The BRUME-1024q kernels (AVX2 and portable) avoid state-dependent memory accesses and branches; dudect and ctgrind found no secret-dependent behaviour in the tested configurations on x86-64. This is not a formal guarantee for every compiler or CPU; timing on ARM is not measured.
- The dense reference permutation is for correctness comparisons and is not a constant-time backend.
- Compiler flags, optimisation, CPU microarchitecture and surrounding application behaviour can change side-channel properties.

### Use restrictions

Do not use this code to protect real data, production services, credentials, communications or long-term keys. Do not interpret the profile names, passing tests, measured performance or the existence of proofs as a certification or a security endorsement.

---

## Repository layout

```text
sillage-brume/
├── README.md
├── LICENSE                  AGPL-3.0-only
├── SECURITY.md              Where to report attacks and vulnerabilities
├── CONTRIBUTING.md          Build, test and change rules
├── CITATION.cff             How to cite the project
├── requirements.txt         Python runtime dependency (NumPy)
├── requirements-tests.txt   Dependencies of the full test suite
├── docs/
│   ├── README.md            Index of the documents
│   ├── SPEC.md              Normative specification of the suite (BRUME-1024q in § 2, by reference)
│   ├── PROOFS.md            Proofs, assumptions and parameter derivations (BRUME-1024q in § 4)
│   ├── MIGRATION_V06.md     The v0.6 change: decisions D1–D7
│   ├── brume1024/           BRUME-1024q: SPEC, test vectors, AEAD and hash proofs, modes, studies, roadmap
│   ├── AUDIT_REPORT.md      Development audit history and corrected issues
│   ├── LEADS.md             Measured optimisations and research leads
│   ├── DESIGN_NOTE.md       Original design note
│   ├── CAMPAIGN_24H.md      Running the long campaigns on another machine
│   ├── GPU_CRYPTANALYSIS_PLAN.md  GPU cryptanalysis plan
│   └── VOLE_CODE_REVIEW.md  Review of the VOLE-in-the-Head prototype
├── sillage/
│   ├── sillage_common.py    Rings, sparse vectors, SHAKE helpers and estimators
│   ├── sillage_kem.py       Sillage-KEM reference implementation
│   ├── sillage_sig.py       Sillage-SIG v0.4 reference implementation
│   ├── rapide.py            Public API with C backend (Brume1024, Brume1024P, hash, XOF, KEM, SIG, VOLE)
│   ├── sillage_c.py         ctypes bindings to the C library
│   ├── demo.py              End-to-end example
│   └── c/
│       ├── brume1024.c      BRUME-1024q: kernels, sponge, tree, AEAD, parallel AEAD, batches, TE
│       ├── brume1024_*.h    Generated tables, portable, bitsliced and batch kernels
│       ├── kem.c            KEM implementation
│       ├── sig.c, vole.c    Signature implementations (v0.4 reference, v0.5 VOLE)
│       ├── isd.c            ISD estimators
│       ├── commun.c         SHAKE256 and common C routines
│       ├── bench.c          C benchmarks
│       └── Makefile
├── tests/
│   ├── run_all.py           Test orchestrator
│   ├── test_*.py            Functional, proof-model and cryptanalysis tests (test_b1024_*: BRUME-1024q)
│   ├── c/                   C programs of the battery (brume1024*.c, temps1024.c, ct1024.c, KEM and SIG studies)
│   ├── gpu/                 CUDA tools (signature attack)
│   └── historique_v05/      BRUME-512 and its tests, archived at v0.6 (not run)
├── prototypes/              Research tools and prototypes that are not part of the library
│   ├── brume_q/b1024/       BRUME-1024q analysis tools (generators, cryptanalysis, proof checks, campaigns, DMV17 paper)
│   ├── brume_q/sat/         SAT certificates of C3 and C4 (with the C4 ≥ 28 reproduction package)
│   ├── vole/                VOLE-in-the-Head signature prototype
│   ├── brume_bitslice/      Bitsliced kernel study (BRUME-512)
│   └── brume_sbox6/, brume_sbox8/  S-box selection of v0.5; idea note on 8-bit S-boxes
├── resultats/
│   ├── SYNTHESE.md          Latest committed test summary
│   ├── BENCH_C.md           C benchmark report
│   ├── EMPREINTES.md        Source, KAT and result fingerprints
│   └── pistes_*.json        Division-property certificates of BRUME-512 (v0.5, history)
└── scripts/                 Campaign launchers, run from the repository root
    ├── rundenuit.sh         Extended (night) campaign
    ├── reprendre_nuit.sh    Resume an interrupted campaign
    ├── runlong              Long campaign in the background, with monitoring and resume
    ├── preparer_campagne.sh Machine check and Python environment setup
    ├── surveillance_gpu     Watches the GPU during a campaign
    ├── rundenuit.cmd, .ps1  Windows launcher (runs the campaign in WSL 2)
    └── rundenuit_wsl.sh     Linux side of the Windows launcher
```

Generated binaries, per-test JSON files and raw campaign logs are not all committed. They are produced locally when the corresponding commands are run. The `.gitignore` file documents which result files are retained in the repository.

Copyright (C) 2026 Spider4Tech. This project is free software, released under the [GNU Affero General Public License, version 3](LICENSE) (AGPL-3.0-only). It comes with no warranty. The licence does not change the warning above: this is a research prototype, not for production use.

---

## Development roadmap

The current research priorities recorded in the project are:

1. **BRUME-1024q cryptanalysis:** third-party cryptanalysis first; then the open points of [`docs/brume1024/ROADMAP.md`](docs/brume1024/ROADMAP.md) and the level-3 attack models of [`docs/brume1024/NIVEAU3.md`](docs/brume1024/NIVEAU3.md) (multi-block rebound beyond 3 rounds, conditional cubes around the 22–23-round zero sums, the keyed duplex). Human review of the AEAD, parallel AEAD, Q1 and TE proofs.
2. **Sillage-KEM:** seek a tighter correctness bound that accounts for XOR cancellations without adding an unsupported independence assumption (a parameter search at equal guarantees gains only about 1 and 2 %, [`docs/LEADS.md`](docs/LEADS.md), lead 9); continue structured and multi-block decoding attacks; improve the classical and quantum cost models.
3. **Sillage-SIG:** strengthen the protocol analysis, evaluate VOLE-in-the-Head as the main route to smaller signatures (a prototype in `prototypes/vole/vole_proto.c` measures 4,112 and 15,906 bytes; it is not a format of this suite, and the conditions for adopting it are listed in [`docs/LEADS.md`](docs/LEADS.md), lead 9), and determine what additional work is required for a meaningful QROM security statement.
4. **AEAD modes:** continue checking the correspondence between the proof models and the C implementation, including nonce handling, multi-user use and parallel-leaf boundary cases.
5. **C portability:** a NEON kernel for BRUME-1024q and timing measurements on native ARM hardware (the portable kernel is used there today), runtime backend selection, testing across compilers and CPU generations.
6. **Reproducibility:** retain complete run manifests, compiler/CPU metadata, source fingerprints and raw outputs for long cryptanalysis campaigns.

Optimisations that change the construction or its parameters must be accompanied by updated proofs, test vectors and conformance tests. Performance changes alone do not justify changing the algorithm.

---

## Design history

The repository records earlier design failures and the changes made in response. The following examples are included because they materially changed the current constructions:

| Area | Earlier issue | Current treatment |
|---|---|---|
| BRUME diffusion | The unweighted diffusion layer admitted a short iterative characteristic | Replaced with the weighted GF(16) diffusion on the `D₁₂₈` support |
| BRUME AEAD | Ambiguous padding and length handling enabled a trivial forgery in an earlier design | Separate padding, domain values and a final length block; proof model and regression tests updated |
| KEM transform | Earlier decapsulation exposed decoding failure through timing | Systematic re-encapsulation and masked selection for implicit rejection |
| KEM assumptions | The first decisional assumptions omitted public parity information | Replaced by H1-P/H2-P with parity included; IND-CPA argument rewritten |
| KEM correctness | A Gaussian estimate overstated the failure bound | Replaced by a certified Chernoff bound evaluated per key |
| Signature protocol | The Stern-based signature format was too large and had earlier challenge/response issues | Replaced in v0.4.0 by the hypercube MPC-in-the-Head construction; transcript binding and auxiliary-field checks added |
| Signature protocol (v0.5) | The MPC-in-the-Head signature was 8.5 / 34.9 KB, and its QROM reduction proved only half its bits | Replaced by VOLE-in-the-Head over regular SD: −50 % size, an exact reduction to SD, a QROM sketch close to Grover. Found and fixed on the way: empty blocks when `Π μ` exceeds the block, a shared hash prefix between the short and fast profiles, and a flawed attack harness (the fake witness was 2 bits from the real one) |
| Permutation width (v0.6) | BRUME-512 at c = 256 gave only 2^85 against quantum collisions; its 256-bit profile was slow | Replaced by BRUME-1024q (c = 384, 2^128 BHT), with C3 and C4 certified, a full-state keyed duplex AEAD proved on a repaired DMV17 Theorem 1, and faster than BRUME-512 on almost every size |
| BRUME S-box (v0.5) | The S-box came from a seeded search; a tie-break among the optimal 4-bit S-boxes found a better one | Replaced by `AD412650BFEC7893` (decision rule fixed beforehand, `prototypes/brume_sbox6/departage/`): BCT 8 against 10, D3, L3, D2 and 3-round boomerang better, exact division-property reach unchanged |
| C implementation | State-indexed tables and secret-dependent operations produced side-channel concerns | Added AVX2/NEON kernels, masked operations, fixed-work sampling and dedicated timing/control-flow tests |
| Division property | Earlier upper-bound claims were limited to particular cubes | Extended the trail construction and verification to all 512 bit cubes; exact method reach documented as 10 rounds per direction |

The full issue history, including detection methods and fixes, is maintained in [`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md).

---

## Continuous integration

On every push and pull request, the C/C++ workflow:

- builds the C library, the benchmark and the native test programs;
- runs the C review checks (`tests/c/revue_c.c`), the exact-spectrum checks of Lemma 0 (`tests/c/h1p_fourier.c`) and the VOLE prototype's known-answer tests;
- fuzzes the VOLE verifier briefly under AddressSanitizer and UndefinedBehaviorSanitizer;
- checks that the BRUME-1024q tables are those of their generator;
- runs the BRUME-1024q checks on the library with and without AVX2 (23 test vectors, kernels, modes, TE);
- runs quick Python tests: known-answer tests, C ≡ Python conformance for the KEM and the signature, the second implementation of BRUME-1024q written from its specification, the C4 ≥ 28 certificate audit, and the numerical instantiations of the proofs;
- checks the quantum bound of the hash on small models, with a witness that must fail.

A CodeQL workflow analyses the C and Python code. The CI does **not** run the full cryptographic test suite (about one hour on 12 cores), nor the timing, Valgrind or long cryptanalysis campaigns: run `python3 -m tests.run_all` and the scripts in `scripts/` locally for those.

---

## Reporting, contributing and citing

- **Attacks and proof flaws:** open a public issue with the *Cryptanalysis result* template. **Implementation vulnerabilities** (memory safety, side channels): report them privately. Details in [`SECURITY.md`](SECURITY.md).
- **Contributing:** build and test instructions, and the rules a change must follow (frozen outputs, C ≡ Python, constant time, a status for every claim), are in [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **Citing:** metadata are in [`CITATION.cff`](CITATION.cff); GitHub shows it as *Cite this repository*.

---

## Further reading

- [`docs/README.md`](docs/README.md) — index of all documents, with their language and status.
- [`docs/DESIGN_NOTE.md`](docs/DESIGN_NOTE.md) — original design direction and component concepts.
- [`docs/PROOFS.md`](docs/PROOFS.md) — formal statements, assumptions, reductions, parameter bounds and open proof obligations.
- [`docs/LEADS.md`](docs/LEADS.md) — measured performance work, optimisations and research leads not adopted into the construction.
- [`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md) — development audit history, previously identified flaws and their corrections.
- [`resultats/SYNTHESE.md`](resultats/SYNTHESE.md) — committed test-suite snapshot.
- [`resultats/BENCH_C.md`](resultats/BENCH_C.md) — C performance measurements.
- [`docs/brume1024/README.md`](docs/brume1024/README.md) — BRUME-1024q: design, certified bounds, modes, measurements, security summary.
- [`docs/MIGRATION_V06.md`](docs/MIGRATION_V06.md) — the v0.6 change and its decisions.
