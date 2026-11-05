# SILLAGE / BRUME

[![C/C++ CI](https://github.com/Spider4Tech/sillage-brume/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/Spider4Tech/sillage-brume/actions/workflows/c-cpp.yml)
[![CodeQL](https://github.com/Spider4Tech/sillage-brume/actions/workflows/codeql.yml/badge.svg)](https://github.com/Spider4Tech/sillage-brume/actions/workflows/codeql.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

**Experimental cryptographic research project — version 0.4.0**

SILLAGE is a research suite built around code-based constructions and noisy decoding. The repository contains a key-encapsulation mechanism, a binary-syndrome-decoding signature scheme, the BRUME-512 permutation, authenticated-encryption modes, hash functions, C implementations, and a collection of tests and cryptanalysis tools.

> **Research prototype — not for production use.** The parameters and constructions are experimental. The v0.4.0 designs have not received a complete independent cryptanalysis. The reductions and computational estimates documented here are conditional on the assumptions and models stated in [`docs/PROOFS.md`](docs/PROOFS.md). Passing the test suite is not evidence that a construction is secure.

The measurements and test totals below refer to dated runs committed with the project; they are not live CI results. The documents in `docs/` are in English ([`docs/README.md`](docs/README.md) lists them); a few external review reports are kept in their original French. Code comments, test names and result files are in French. The C implementation and Python package are under `sillage/`.

**Reviewers and cryptanalysts:** results are welcome, including on reduced rounds or reduced sizes. See [`SECURITY.md`](SECURITY.md) for where to report them and [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to build and test.

---

## Contents

- [Project scope](#project-scope)
- [Components at a glance](#components-at-a-glance)
- [Installation and build](#installation-and-build)
- [Quick start](#quick-start)
- [Sillage-KEM](#sillage-kem)
- [BRUME-512](#brume-512)
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
2. **BRUME-512**, a 512-bit permutation used by a keyed duplex, a sponge hash, and a tree hash. A separate parallel duplex mode is provided for large messages.
3. **Sillage-SIG**, a Fiat–Shamir signature scheme based on MPC-in-the-Head and binary syndrome decoding.

The repository is intended to make the constructions inspectable and testable. It includes mathematical notes, reductions, parameter estimators, reduced-model experiments, C implementations, conformance tests and cryptanalysis programs. It is not a standards submission and does not claim production readiness.

## Components at a glance

| Component | Construction | Current profiles | Main qualification |
|---|---|---|---|
| Sillage-KEM | Quasi-cyclic sparse-noise decoding, RM(1,7) code, FO transform | `Sillage-128`, `Sillage-256` | IND-CCA argument in the ROM, conditional on H1-P/H2-P and the stated correctness bound |
| BRUME-512 | 512-bit, 32-round permutation over 128 GF(16) nibbles | `BRUME-512` | Structural and trail properties are documented; security of the full permutation is not proved |
| Sequential AEAD | Keyed duplex over BRUME-512 | `BRUME-512`, `BRUME-512-256` | Ideal-permutation analysis; nonce policy differs by profile |
| Parallel AEAD | Tree-like duplex with 4 KiB message leaves | `BRUME-512p`, `BRUME-512-256p` | Separate construction and ciphertext format; separate proof and tests |
| Hash | Sponge and one-level tree hash over BRUME-512 | Variable output length | Generic sponge/tree analysis under the stated model |
| Sillage-SIG | MPC-in-the-Head over binary syndrome decoding | `Sillage-SIG-128`, `Sillage-SIG-256` | EUF-CMA/SUF-CMA argument in the ROM; QROM analysis remains limited |

The profile suffixes `128` and `256` are parameter labels. They must not be read as a blanket claim of 128-bit or 256-bit post-quantum security. The KEM and signature sections give the actual estimates and limitations. The v0.4.0 KEM and signature formats differ from v0.3; keys, ciphertexts and signatures from the earlier format are not assumed to be interoperable.

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

The full test suite also uses additional packages, including NetworkX, OR-Tools and `python-sat`. Matplotlib is used by optional plotting code when available. The repository does not currently provide a pinned dependency lockfile, so the exact package versions used for a run should be recorded with its results.

### Install the Python runtime dependency

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt        # NumPy
```

For the full test and cryptanalysis suite:

```bash
python -m pip install -r requirements-tests.txt  # NetworkX, OR-Tools, python-sat, Matplotlib
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

To regenerate the BRUME C tables from the Python parameter tables:

```bash
make -C sillage/c tables
```

### Python fallback and the C requirement

The public API in `sillage/rapide.py` uses the C implementation when it is available. If the library cannot be loaded or built, it emits a warning and falls back to the Python reference implementation.

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
    SillageSIG,
    Brume512,
    Brume512P,
    brume512_hash,
    brume512_hash_arbre,
)

# Key encapsulation
kem = SillageKEM("Sillage-128")
pk, sk = kem.keygen()
ct_kem, shared_secret = kem.encaps(pk)
assert kem.decaps(sk, ct_kem) == shared_secret

# Sequential authenticated encryption
key = secrets.token_bytes(64)
nonce = secrets.token_bytes(24)  # Random nonces are supported by BRUME-512 under its stated usage bound.
aead = Brume512("BRUME-512", key=key)
plaintext = b"example message"
ciphertext, tag = aead.encrypt(nonce, plaintext, aad=b"context")
assert aead.decrypt(nonce, ciphertext, tag, aad=b"context") == plaintext

# Parallel authenticated encryption: a distinct mode and ciphertext format
parallel_key = secrets.token_bytes(64)
parallel_nonce = secrets.token_bytes(24)
parallel = Brume512P("BRUME-512p", key=parallel_key)
large_message = b"example" * 10000
ct_parallel, tag_parallel = parallel.encrypt(parallel_nonce, large_message)
assert parallel.decrypt(parallel_nonce, ct_parallel, tag_parallel) == large_message

# Hashing
h = brume512_hash(b"message", 32)
h_tree = brume512_hash_arbre(large_message, 32)

# Digital signatures
sig = SillageSIG("Sillage-SIG-128")
pk_sig, sk_sig = sig.keygen()
signature = sig.sign(sk_sig, pk_sig, plaintext)
assert sig.verify(pk_sig, plaintext, signature)
```

**Nonce handling is the caller's responsibility.** Do not reuse a nonce with the same key. The 256-bit AEAD profiles require unique nonces to retain the stated 256-bit cost/advantage level; a random 24-byte nonce does not provide that guarantee. See [Authenticated-encryption modes](#authenticated-encryption-modes).

The package exports the public classes and profiles from `sillage/__init__.py`. The reference implementations remain available from `sillage.sillage_kem`, `sillage.sillage_sig` and `sillage.brume512` for comparison with the C-backed API.

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

Correctness is analysed with a Chernoff bound that does not assume independent error bits. Key generation evaluates the bound for each candidate key and rejects keys whose certified failure bound exceeds `2⁻λ`. The measured key rejection rates are about 7.0% (Sillage-128) and 6.1% (Sillage-256) on 32 768 and 8 192 keys (`tests/c/kem_rejet.c`); θ = 0.7 sits at the minimum of these rates (`tests/test_kem_theta.py`). The median bounds are substantially below the acceptance thresholds; see [`docs/PROOFS.md`](docs/PROOFS.md), §2.3.

### Parameters

The values below are from the v0.4.0 parameter set and its committed documentation.

| Parameter | Sillage-128 | Sillage-256 |
|---|---:|---:|
| `n` | 50,021 | 170,003 |
| Secret/error weight `w` | 75 | 140 |
| RM repetition parameter `D` | 14 | 28 |
| Public key | 6,285 bytes | 21,283 bytes |
| Encapsulation ciphertext | 9,837 bytes | 35,587 bytes |
| Shared secret | 32 bytes | 64 bytes |
| Classical ISD work-factor estimate | 138.2 bits | 265.1 bits |
| Prange–Grover estimate | 91.7 bits | 158.4 bits |
| Median certified decapsulation-failure bound | ≈ `2⁻¹⁴⁶` | ≈ `2⁻²⁸⁹` |
| Key acceptance threshold | `2⁻¹²⁸` | `2⁻²⁵⁶` |

The classical estimates use the concrete ISD estimators documented in the repository. They are computational estimates, not reductions proving that every attack must take that many operations. The quantum figures shown are Prange–Grover estimates without a depth constraint; they are below the profile labels. A separate quantum-walk estimate with free QRAM is lower still. **Sillage-KEM does not claim 128-bit or 256-bit post-quantum security.**

### Security statement

The IND-CPA argument is conditional on the decisional quasi-cyclic syndrome-decoding assumptions H1-P and H2-P, stated with the public parity information. The original formulations without parity were distinguishable and were replaced. The FO transform gives an IND-CCA argument in the random-oracle model under the stated correctness condition and assumptions.

The proof and parameter analysis are in [`docs/PROOFS.md`](docs/PROOFS.md), §§2 and 5. The tests include correctness, malformed-input handling, implicit rejection, distribution checks, ISD estimator comparisons and simulated validation of the `δ` bound. Those tests do not establish the hardness of H1-P or H2-P at the full parameter sizes.

---

## BRUME-512

### Permutation design

BRUME-512 is a 512-bit permutation with 32 rounds. The state is represented as 128 nibbles over

$$
\mathbb{F}_{16} = \mathbb{F}_2[x]/(x^4+x+1).
$$

Each round applies:

1. XOR with a round-constant vector derived from SHAKE256;
2. the same 4-bit bijective S-box to each of the 128 nibbles;
3. a linear diffusion layer over GF(16).

The S-box has differential uniformity 4, nonlinearity 4 and algebraic degree 3 in each component. The documented checks also report no fixed points, no linear structures and trivial self-equivalences for the selected table.

The diffusion support is the adjacency matrix plus the identity of a 6-regular Cayley graph on the dihedral group `D₁₂₈`. The graph is bipartite; its two trivial eigenvalues are `+6` and `−6`. The largest absolute value among the other eigenvalues is reported as `3.5076`, below the 6-regular Ramanujan bound `2√5`. Each edge has a non-zero GF(16) coefficient.

The branch number is **exactly 8**, certified for the linear layer and its relevant adjoints. The support sizes of successive powers are reported as `7, 37, 94, 127, 128` in the forward direction and full support after two inverse steps. Thus the linear layer reaches all 128 nibbles after five forward applications and two inverse applications.

### What the structural results establish

The exact branch-number result gives a wide-trail lower bound of at least 128 active S-boxes over 32 rounds. Under the independent-round Markov model, the documented characteristic bounds are:

- differential characteristic probability: at most `2⁻²⁵⁶`;
- linear trail correlation: at most `2⁻¹²⁸`.

These are **characteristic/trail bounds in the stated model**, not bounds on the sum of all differential characteristics or linear trails for the concrete fixed permutation. The Markov model is an assumption for a permutation without subkeys. In exact reduced models (mini-BRUME, 24 bits), fixed-constant instances deviate from it by no more than the dispersion measured between random constant sets, of which the Markov chain is the exact average (PROOFS § 4.2 bis); this does not extend to 512 bits by itself. A two-round aggregation bound is documented separately. No corresponding general aggregation proof is claimed for arbitrary numbers of rounds.

The permutation is not proved to be an ideal permutation or a secure PRP. Its structural properties rule out or constrain particular attack families; they do not prove the security of the full 32-round construction.

### Current cryptanalysis results

The repository contains searches and experiments covering differential and linear trails, hulls, boomerang transitions, impossible differentials, cube/integral distinguishers, algebraic degree, invariant structures and reduced-state models.

The current documented results include:

| Analysis | Result | Scope and qualification |
|---|---|---|
| Differential / linear trails | Best searched 14-round trails: approximately `2⁻²⁸³⁰` differential and `2⁻¹⁴¹⁷` linear | Results of the specified search, not global bounds on all trails |
| Impossible differentials / zero correlations | Up to 5 rounds | Nibble-level patterns covered by the current search; not a bound for all possible masks or patterns |
| Boomerang | A 3-round signal was measured | No general upper bound follows from this experiment |
| Cube / integral experiments | 4-round forward and 2-round inverse in the baseline full-width C campaign; an extended campaign reached 3 inverse rounds | Experimental reach depends on the tested cube family and sample budget |
| Reduced-state integral models | 24-bit models reached 4 rounds; 32-bit models reached 5 rounds in the reported instances | Reduced models do not establish the same reach at 512 bits |
| State recovery | One-round state recovery by linear solving | Does not extend to the full permutation |
| Division property | Exact method reach of 10 rounds in each direction, 20 rounds inside-out, for every cube | This is the reach of the method, not a 20-round integral attack |

The division-property result is obtained by combining degree arguments, trail stitching and exact completion of reduced suffixes with CP-SAT. At 11 rounds, verified monomial trails exist for every output bit in each direction, so the method no longer proves balance. Whether trails cancel modulo two and what integral distinguisher exists for the full permutation remain open questions.

The linear layer has 16 invariant subspaces. The current experiments indicate that the selected S-box does not preserve their individual lines; this does not amount to a general proof that the full round has no exploitable invariant structure.

For the derivations, experiment definitions and remaining attack space, see [`docs/PROOFS.md`](docs/PROOFS.md), §4.2 bis, and the BRUME-related tests under `tests/`.

---

## Authenticated-encryption modes

BRUME provides two different keyed-duplex constructions. They have separate profiles, initialisation domains, ciphertexts and proofs. A ciphertext produced by one mode is not expected to be accepted by the other.

### Sequential keyed duplex

The sequential mode absorbs the key, nonce and associated data, then encrypts by XORing the plaintext with the rate portion of the state. The ciphertext is absorbed back into the state. Padding and domain separation distinguish the AAD, text and final length phases. The tag is extracted from the final state.

| Profile | Key | Nonce | Rate | Capacity | Tag | Stated level |
|---|---:|---:|---:|---:|---:|---:|
| `BRUME-512` | 64 bytes | 24 bytes | 256 bits | 256 bits | 16 bytes | 128 bits |
| `BRUME-512-256` | 64 bytes | 24 bytes | 128 bits | 384 bits | 32 bytes | 256 bits |

The ideal-permutation analysis is given in [`docs/PROOFS.md`](docs/PROOFS.md), §4.3. It accounts for the total number of permutation calls, data processed, decryption queries and tag length. It does not prove that the concrete BRUME permutation behaves as a random permutation.

### Nonce policy

The API receives the nonce from the caller; it does not allocate or track nonces.

- **`BRUME-512`:** the proof permits random 24-byte nonces under the stated cost/advantage definition and usage bound. The nonce-collision term is at most `qₑ² / 2¹⁹³`. The documented 128-bit level is retained for up to `2⁶⁴` encryptions per key under that definition.
- **`BRUME-512-256`:** unique nonces per key are required to retain the stated 256-bit level. With random nonces, the collision term prevents that level; the proof estimates the collision-limited scale at roughly `2⁹⁶` encryptions.

For applications using the 256-bit profile, uniqueness must survive process restarts and must be coordinated across devices sharing a key. The implementation does not enforce this policy. The same policy applies to the corresponding parallel profiles.

### Parallel duplex (`Brume512P`)

The parallel mode is designed for larger messages. It first derives a common trunk state from the key, nonce and AAD. The message is split into 4 KiB leaves. Each leaf runs a keyed duplex derived from the trunk and a leaf index; the final state of each leaf produces a chaining value. The trunk absorbs the ordered chaining values, the number of leaves and the message length, then produces the tag.

Profiles:

- `BRUME-512p`;
- `BRUME-512-256p`.

The parallel mode has its own IV/domain separation and produces different ciphertexts from the sequential mode. Its proof is stated in §4.5 of [`docs/PROOFS.md`](docs/PROOFS.md). In addition to the sequential-mode terms, the bound includes a term for collisions among leaf chaining values. The same nonce policy applies as for the matching sequential profile.

A 4 KiB leaf size was selected from experiments with 2, 4 and 8 KiB leaves. On the benchmark machine, the parallel mode becomes useful when messages are large enough to amortise the per-leaf and root costs; the measured 16 MiB case is reported below. For short messages, the sequential mode is usually faster.

### Error-correction mode (`TE`)

The `TE` mode adds seven bytes of parity for each 64-byte ciphertext block. It uses per-bit-plane SEC-DED syndromes to correct one altered byte per block and detect many multiple-error patterns.

This mechanism is intended to handle accidental corruption. The parity data is **not authenticated** and does not provide adversarial integrity. The AEAD tag remains the cryptographic integrity check. The documented overhead is approximately 10.9% of ciphertext length.

---

## Hash functions

### Sequential sponge

`brume512_hash(data, out_len)` uses BRUME-512 as a sponge with a 256-bit rate and 256-bit capacity. The output length is selectable. Padding is injective and includes a domain value in the capacity.

The generic classical collision scale associated with the 256-bit capacity is `2¹²⁸`. The repository estimates the generic quantum collision scale at approximately `2⁸⁵`; this is a generic sponge estimate, not a cryptanalysis result against the concrete permutation.

### Tree hash

`brume512_hash_arbre(data, out_len)` is a separate function with separate test vectors and domain separation. Messages up to 8 KiB use a single-node domain. Larger messages are divided into 8 KiB leaves, each leaf is hashed independently, and a root sponge absorbs the ordered chaining values and tree metadata.

The construction currently uses one level of leaves and a 256-bit chaining value. The indifferentiability argument is documented in §4.4 of [`docs/PROOFS.md`](docs/PROOFS.md). It is proved in the stated ideal-sponge model, subject to the conditions in that section. The implementation processes leaves in batches and can use OpenMP.

The tree hash is **not interchangeable** with the sequential sponge hash. Applications must identify which function was used when storing or verifying digests.

---

## Sillage-SIG

### Construction

Sillage-SIG is a Fiat–Shamir signature scheme built from an MPC-in-the-Head protocol in the style of SDitH. Its underlying relation is binary syndrome decoding:

$$
H x = y, \qquad \operatorname{wt}(x) \leq w,
$$

with `H = [H' | I]`. The witness is represented using a polynomial relation over finite fields. The protocol checks the relation at four evaluation points using Beaver triples.

The virtual parties are arranged as a hypercube with `N = 2¹² = 4096` leaves. A GGM seed tree derives the shares. Each repetition hides one leaf, and the signature contains the required authentication path, commitment, auxiliary values and responses. Fiat–Shamir is applied in five passes.

### Parameters and sizes

| Parameter | Sillage-SIG-128 | Sillage-SIG-256 |
|---|---:|---:|
| Binary code `(n, k, w)` | `(2048, 1434, 103)` | `(4096, 2867, 206)` |
| Repetitions `τ` | 11 | 23 |
| Evaluation points `t` | 4 | 4 |
| Public key | 109 bytes | 186 bytes |
| Secret key | 464 bytes | 977 bytes |
| Signature | 8,522 bytes | 34,867 bytes |
| Classical ISD work-factor estimate | 160.3 bits | 316.2 bits |
| ROM forgery estimate in the stated theorem | 128.3 bits | 264 bits |

The work factors are estimates under the code-decoding models and parameter search documented in the repository. The signature sizes are fixed by the v0.4.0 format. The protocol and proof are new in v0.4.0; the proof is in [`docs/PROOFS.md`](docs/PROOFS.md), §3.

### Security qualifications

The EUF-CMA argument is in the random-oracle model and depends on the binary syndrome-decoding assumption H3, the hidden-seed entropy and the stated transcript/commitment properties. The repository also analyses strong unforgeability and executes selected attacks on reduced models.

The quantum analysis is not a complete QROM security proof for the instantiated scheme. The documented estimates include Grover-based forgery costs of approximately 64 and 132 bits for the two profiles, while the quantified QROM reductions in the proof document are substantially weaker and have explicit caveats. The profile labels therefore do not imply 128-bit and 256-bit quantum security.

---

## C implementation and SIMD

The `sillage/c/` directory contains the C implementation of BRUME, the AEAD modes, the hash functions, Sillage-KEM, Sillage-SIG and SHAKE256 support code. The C API is exposed to Python through `ctypes` in `sillage/sillage_c.py` and used by the public wrappers in `sillage/rapide.py`.

### BRUME kernels

The C implementation contains several execution paths:

- **AVX2, one state:** the S-box and GF(16) multiplication use `vpshufb` with lookup tables held in vector registers. The diffusion is expressed using fixed byte rotations and swaps derived from the Cayley-graph generators. The state does not index a conventional memory table in this kernel.
- **AVX2, 32-state batches:** the state is transposed so that the same nibble position from 32 independent states is processed in parallel. The substitution and diffusion are applied vertically across the batch. This path is used by multi-message AEAD and hashing.
- **ARM NEON:** corresponding single-state and batched kernels are present. The batch implementation processes 16 states at a time internally. Output conformance has been tested under QEMU when the cross-compiler and emulator are available; native ARM timing and side-channel measurements have not been reported.
- **Reference path:** the table-based permutation is retained as a reference implementation. It is used for cross-checking and should not be treated as a constant-time fallback.

The AVX2 path is selected at compile time by the current Makefile's `-march=native` flags. The repository does not yet provide a general runtime dispatcher across separately compiled CPU backends.

### Parallel processing

The multi-message API groups independent states into batches and distributes batches across available cores with OpenMP. The parallel AEAD mode also distributes message leaves across worker threads. OpenMP scheduling and the number of threads affect throughput; single-core and multi-core measurements are identified separately in the benchmark report.

### Side-channel testing

The C paths have been tested with dudect-style timing experiments and, for KEM and SIG, Valgrind/ctgrind checks and control-flow instrumentation. The current results did not detect secret-dependent timing or control-flow differences in the tested builds and inputs. These are empirical checks, not a proof of constant-time execution. A key-dependent timing difference in the AEAD, tied to where the 64-byte duplex state fell within a cache line, was found and fixed on 2026-11-02 by aligning that state to 64 bytes (`docs/AUDIT_REPORT.md`, errata of 2026-11-02). Results depend on compiler, flags, CPU, operating system and test methodology.

The Python reference implementation is not constant-time. The generic table-based BRUME reference path is also not intended as a constant-time implementation. NEON output conformance under QEMU does not establish native timing behaviour.

---

## Tests and cryptanalysis

Run the complete suite with:

```bash
python3 -m tests.run_all
```

The orchestrator runs the Python tests concurrently and schedules the intensive C/OpenMP tests after them. Each test writes a JSON result under `resultats/` and a log under `resultats/logs/`; the orchestrator writes `resultats/SYNTHESE.md` and `resultats/synthese.json`.

Useful subsets and options:

```bash
python3 -m tests.run_all aead kem       # select test groups
python3 -m tests.run_all -j 4           # use four concurrent Python test workers
SILLAGE_INTENSITE=8 python3 -m tests.run_all c_integral c_sac
python3 -m tests.noyau_c                # C kernel conformance and throughput
python3 -m tests.bench_c                # C implementation benchmark
python3 -m tests.bench_tailles          # reference implementation size/throughput sweep
python3 -m tests.empreintes             # source, KAT and result fingerprints
```

For a longer campaign:

```bash
./scripts/rundenuit.sh 10
```

To resume a campaign using the repository's resume script:

```bash
./scripts/reprendre_nuit.sh 10
```

For a long run on any machine, `./scripts/runlong [hours]` checks it, starts the campaign in the background, monitors temperature and stuck campaigns, resumes after an interruption, and writes a results archive; see [`docs/CAMPAIGN_24H.md`](docs/CAMPAIGN_24H.md).

On Windows, `scripts/rundenuit.cmd [hours]` runs the same campaign inside WSL 2, blocks sleep, and copies the results archive back to Windows; see the same guide.

The extended campaign is compute-intensive and uses all available cores during some C tests. Its outputs are generated locally; not all raw campaign files are committed.

### Coverage by area

The 51 tests in `tests/run_all.py` cover the following areas. Individual test modules and C programs contain the precise parameters and assertions.

| Area | Main checks and experiments | Selected modules / programs |
|---|---|---|
| Functional behaviour | KATs, round trips, malformed inputs, API behaviour, table fingerprints | `test_fonctionnel`, `test_aead`, `test_kem`, `test_sig`, `test_te` |
| BRUME structure | S-box properties, exact branch number, diffusion support, graph invariants, self-equivalences | `test_branch_exact`, `test_symetries_invariants`, `diffusion_support`, `test_brume_algebre` |
| Differential and linear analysis | Trail search, beam search, two-round differentials and hulls, truncated patterns, impossible differentials, zero correlations | `test_banc_cryptanalyse`, `test_diff_lin_empirique`, `test_cycles`, `test_beam_trails`, `test_hull`, `structure_miss`, `brume_attaques` |
| Integral and algebraic analysis | Degree bounds, cube sums, division-property trails, forward/inverse reach, reduced-state models | `test_integral_degre`, `test_division_property`, `test_dp_modele`, `test_dp_tous_cubes`, `test_dp_exact`, `test_dp_validation`, `test_c_integral`, `test_c_degre`, `test_c_cube_init`, `mini_brume` |
| AEAD and hash modes | Padding and domain separation, model-to-implementation comparison, tamper rejection, tree-hash conditions, parallel-leaf alterations | `test_mode_aead`, `test_aead_modele`, `test_aead_parallele`, `test_hachage`, `test_hachage_arbre`, `test_indiff_arbre` |
| KEM assumptions and estimators | Error distributions, δ-bound experiments, reduced-instance ISD, estimator consistency, parity and correlation checks | `test_isd_parametres`, `test_c_kem_bruit`, `isd_reel`, `isd_comparaison`, `kem_distributions` |
| Signature protocol | Reduced-model checks, intermediate-scale Kales–Zaverucha attack against the C verifier, challenge distribution, false-positive/hidden-party analysis, malformed signatures, witness-hiding tests | `test_sig_modele`, `sig_kz`, `sig_flux` |
| C implementation | Byte-for-byte conformance, SIMD output comparison, API interoperability, fuzzing, guard pages, UBSan, Valgrind/ctgrind and dudect-style timing tests | `test_c_impl`, `test_api_c`, `test_c_simd`, `test_c_fuzz`, `test_c_kem_valgrind`, `test_c_sig_valgrind`, `test_c_temps` |
| Statistical tests | Avalanche/SAC measurements and statistical batteries on generated streams and hash outputs | `test_diffusion_stats`, `test_c_sac`, `test_c_statistiques` |

The reduced-model tests are useful for checking proof steps and attack code. They do not establish that the same attack or proof condition scales unchanged to the full 512-bit construction.

### Latest committed test summary

The committed [`resultats/SYNTHESE.md`](resultats/SYNTHESE.md) reports the following run:

- **533 / 534 controls passed**;
- **53 tests**;
- **3,530 seconds** total runtime;
- run timestamp recorded as **31 October 2026, 18:57**.

The one failed control, `Sillage-256_D_minimal`, was a sampling artifact of the test: it drew only 3 random keys, for a true rate of about 43 %, so it failed by chance about once in 5.5 runs. The test now draws 30 keys and passes when run alone; the full suite has not been rerun since.

This is a snapshot of one test run on the machine used to produce the report. It is not a statement that every possible input, compiler, architecture or adversarial strategy has been tested. In particular, the full suite does not prove the hardness assumptions, the security of the full BRUME permutation or the completeness of the QROM arguments.

---

## Measured performance

The committed C benchmark [`resultats/BENCH_C.md`](resultats/BENCH_C.md) was produced on:

- **CPU:** AMD Ryzen 5 5600G with Radeon Graphics (6 cores / 12 threads);
- **Compiler:** GCC 13.3.0;
- **Flags:** `-O3 -march=native` and OpenMP;
- **Python reference:** Python 3.12.3;
- **Date:** 31 October 2026.

Unless stated otherwise, single-core values are reported. Multi-core rows use all 12 hardware threads. These figures are measurements of this implementation on this machine; they should not be treated as portable performance guarantees.

### Selected C measurements

| Operation | Measured result |
|---|---:|
| BRUME-512 permutation, AVX2, one state | 0.390 µs |
| BRUME-512 permutation, table reference | 4.88 µs |
| BRUME-512 permutation, 32-state batch | 193 ns per state |
| BRUME-512 AEAD, 1 MiB, profile 128 | about 83 MiB/s |
| BRUME-512-256 AEAD, 1 MiB | about 41 MiB/s |
| Tree hash, 16 MiB, one core | 161 MB/s |
| Tree hash, 16 MiB, 12 threads | 793 MB/s |
| Parallel AEAD, 16 MiB, one core | 150 MB/s |
| Parallel AEAD, 16 MiB, 12 threads | 777 MB/s |

### KEM and signature timings

| Operation | Sillage-128 / SIG-128 | Sillage-256 / SIG-256 |
|---|---:|---:|
| KEM key generation | 6.27 ms | 26.7 ms |
| KEM encapsulation | 0.206 ms | 1.19 ms |
| KEM decapsulation | 0.317 ms | 1.86 ms |
| SIG key generation | 0.276 ms | 1.04 ms |
| SIG signing, one core | 34.4 ms | 121 ms |
| SIG verification, one core | 34.3 ms | 121 ms |
| SIG signing, 12 threads | 5.47 ms | 18.4 ms |
| SIG verification, 12 threads | 6.5 ms | 17.8 ms |

### Parallel AEAD scaling

For a single 16 MiB message, the benchmark records approximately 86 MB/s for sequential AEAD, 150 MB/s for the parallel mode on one core, and 777 MB/s for the parallel mode on 12 threads. The parallel mode has additional per-leaf and root work; the speed-up is workload- and machine-dependent.

For multi-message AEAD with a total of 32 MiB, the 12-thread throughput ranges from 157 MB/s for 64-byte messages to 685 MB/s for 16 KiB messages. When the key is shared across messages, the measured figures are 195 MB/s and 690 MB/s respectively. The full size sweep is in [`resultats/BENCH_C.md`](resultats/BENCH_C.md).

The Python/NumPy implementation is a reference implementation, not the performance target. Its timings are recorded separately in [`resultats/BENCH_TAILLES.md`](resultats/BENCH_TAILLES.md).

---

## Security assumptions and limitations

The status of each claim matters. The repository distinguishes exact structural results, bounds proved in a specified model, computational estimates, reduced-model experiments and open assumptions. They should not be conflated.

### BRUME-512

- The S-box properties, graph data, branch number and diffusion supports are checked exhaustively or by the documented certificates.
- The 128-active-S-box wide-trail lower bound is structural. The stated 32-round differential-characteristic and linear-trail probabilities use the independent-round Markov model.
- Aggregated differentials and linear hulls beyond the proven two-round bounds remain open. Experimental clustering measurements do not replace a general proof.
- The mode proofs model BRUME as an ideal permutation. They do not prove that the concrete 32-round permutation is ideal or pseudorandom.
- Reduced-state, cube, boomerang and differential experiments constrain particular attack families; they do not establish security against all attack classes.

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

- Sequential and parallel AEAD bounds are proved in an ideal-permutation model and under the nonce restrictions stated above. The quantum Q1 setting, where the permutation can be queried in superposition, has not been analysed. Grover key search against a 512-bit key gives a nominal `2²⁵⁶` work factor, but this is not a proof of a 256-bit quantum security level for the mode.
- The parallel mode includes a separate proof term for leaf chaining-value collisions. Reduced-model forgeries are used to check selected terms, not to prove the full-size construction.
- The tree-hash proof is in the stated ideal-sponge model and has been tested on a reduced model; independent human review remains pending. It does not establish the security of the concrete BRUME permutation.
- The TE parity data is not authenticated. Only the AEAD tag protects against adversarial modification.

### Implementation and side channels

- The Python reference code is not constant-time.
- The AVX2/NEON kernels are designed to avoid state-dependent memory lookups and branches. The current x86 timing and control-flow tests found no secret-dependent behaviour in their tested configurations; this is not a formal guarantee for every compiler or CPU.
- The NEON path has output-conformance tests under QEMU, but no native ARM timing or side-channel campaign is reported.
- The table-based reference permutation is retained for correctness comparisons and is not a constant-time backend.
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
│   ├── SPEC.md              Normative specification (English)
│   ├── PROOFS.md            Proofs, assumptions and parameter derivations
│   ├── AUDIT_REPORT.md      Development audit history and corrected issues
│   ├── LEADS.md             Measured optimisations and research leads
│   ├── DESIGN_NOTE.md       Original design note
│   ├── CAMPAIGN_24H.md      Running the long campaigns on another machine
│   ├── GPU_CRYPTANALYSIS_PLAN.md  GPU cryptanalysis plan
│   └── VOLE_CODE_REVIEW.md  Review of the VOLE-in-the-Head prototype
├── sillage/
│   ├── sillage_common.py    Rings, sparse vectors, SHAKE helpers and estimators
│   ├── sillage_kem.py       Sillage-KEM reference implementation
│   ├── sillage_sig.py       Sillage-SIG reference implementation
│   ├── brume512.py          BRUME permutation, modes and hash functions
│   ├── brume512_tables.py   Frozen S-box, graph and coefficient tables
│   ├── select_params.py     Parameter/table generation
│   ├── rapide.py            Public API with C backend and Python fallback
│   ├── sillage_c.py         ctypes bindings to the C library
│   ├── demo.py              End-to-end example
│   └── c/
│       ├── brume512.c       BRUME reference and sequential modes
│       ├── brume512_avx2.c  AVX2 and NEON kernels, batches and parallel AEAD
│       ├── brume512_simd.h  Generated SIMD diffusion tables/macros
│       ├── brume512_tables.h Generated BRUME tables
│       ├── kem.c            KEM implementation
│       ├── sig.c            Signature implementation
│       ├── isd.c            ISD estimators
│       ├── commun.c         SHAKE256 and common C routines
│       ├── bench.c          C benchmarks
│       └── Makefile
├── tests/
│   ├── run_all.py           Test orchestrator
│   ├── test_*.py            Functional, proof-model and cryptanalysis tests
│   ├── nuit_brume.py        Extended BRUME campaign
│   ├── c/                   C/OpenMP cryptanalysis, validation and size-study programs
│   └── gpu/                 CUDA cryptanalysis campaigns (byte-for-byte conformant to the C code)
├── prototypes/              Measured prototypes that are not part of the suite
│   ├── vole/                VOLE-in-the-Head signature over regular SD (docs/LEADS.md, lead 9)
│   ├── brume_bitslice/      Bitsliced 256-state BRUME-512 kernel (docs/LEADS.md, lead 10)
│   └── brume_sbox8/         Idea note: BRUME with 8-bit S-boxes (not implemented)
├── resultats/
│   ├── SYNTHESE.md          Latest committed test summary
│   ├── BENCH_C.md           C benchmark report
│   ├── BENCH_TAILLES.md     Python reference size/throughput report
│   ├── EMPREINTES.md        Source and test fingerprints
│   ├── pistes_division.json Division-property certificates
│   └── pistes_exactes.json  Exact-trail certificates
└── scripts/                 Campaign launchers, run from the repository root
    ├── rundenuit.sh         Extended (night) campaign
    ├── reprendre_nuit.sh    Resume an interrupted campaign
    ├── runlong              Long campaign in the background, with monitoring and resume
    ├── preparer_campagne.sh Machine check and Python environment setup
    ├── runspecial           Targeted dudect measurements (timing investigations)
    ├── rungpu               GPU cryptanalysis campaigns (tests/gpu)
    ├── surveillance_gpu     Watches the GPU during a campaign; reboots the host if the card drops off the bus
    ├── rungpu2080           The same on a slower card (e.g. RTX 2080): extended plan, 72 h
    ├── rungpu_cloud         The same on a rented multi-GPU machine, time-bounded (10 h)
    ├── rundenuit.cmd, .ps1  Windows launcher (runs the campaign in WSL 2)
    └── rundenuit_wsl.sh     Linux side of the Windows launcher
```

Generated binaries, per-test JSON files and raw campaign logs are not all committed. They are produced locally when the corresponding commands are run. The `.gitignore` file documents which result files are retained in the repository.

Copyright (C) 2026 Spider4Tech. This project is free software, released under the [GNU Affero General Public License, version 3](LICENSE) (AGPL-3.0-only). It comes with no warranty. The licence does not change the warning above: this is a research prototype, not for production use.

---

## Development roadmap

The current research priorities recorded in the project are:

1. **BRUME cryptanalysis:** improve the analysis of aggregated trails, the actual integral reach, boomerang behaviour and attacks against the keyed modes. The exact division-property reach is established as a method result; the real integral distinguisher remains open.
2. **Sillage-KEM:** seek a tighter correctness bound that accounts for XOR cancellations without adding an unsupported independence assumption (a parameter search at equal guarantees gains only about 1 and 2 %, [`docs/LEADS.md`](docs/LEADS.md), lead 9); continue structured and multi-block decoding attacks; improve the classical and quantum cost models.
3. **Sillage-SIG:** strengthen the protocol analysis, evaluate VOLE-in-the-Head as the main route to smaller signatures (a prototype in `prototypes/vole/vole_proto.c` measures 4,112 and 15,906 bytes; it is not a format of this suite, and the conditions for adopting it are listed in [`docs/LEADS.md`](docs/LEADS.md), lead 9), and determine what additional work is required for a meaningful QROM security statement.
4. **AEAD modes:** continue checking the correspondence between the proof models and the C/Python implementations, including nonce handling, multi-user use and parallel-leaf boundary cases.
5. **C portability:** measure the NEON implementation on native ARM hardware, improve runtime backend selection, and continue testing across compilers and CPU generations.
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
| C implementation | State-indexed tables and secret-dependent operations produced side-channel concerns | Added AVX2/NEON kernels, masked operations, fixed-work sampling and dedicated timing/control-flow tests |
| Division property | Earlier upper-bound claims were limited to particular cubes | Extended the trail construction and verification to all 512 bit cubes; exact method reach documented as 10 rounds per direction |

The full issue history, including detection methods and fixes, is maintained in [`docs/AUDIT_REPORT.md`](docs/AUDIT_REPORT.md).

---

## Continuous integration

On every push and pull request, the C/C++ workflow:

- builds the C library, the benchmark and the native test programs;
- runs the C review checks (`tests/c/revue_c.c`), the exact-spectrum checks of Lemma 0 (`tests/c/h1p_fourier.c`) and the VOLE prototype's known-answer tests;
- fuzzes the VOLE verifier briefly under AddressSanitizer and UndefinedBehaviorSanitizer;
- checks that the generated C tables match their Python generator;
- runs three quick Python tests: known-answer tests, the TE mode, and byte-for-byte conformance between C and Python.

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
- [`resultats/BENCH_TAILLES.md`](resultats/BENCH_TAILLES.md) — Python reference throughput and message-size measurements.
