# C code review — SILLAGE-VOLE prototype

*English translation of [`REVUE_CODE_VOLE.md`](REVUE_CODE_VOLE.md). The review describes the code at the commit it examined; how each finding was handled since is recorded in [`LEADS.md`](LEADS.md), lead 9 (“Code review”).*

**Code commit reviewed:** `59672814ed8a70b27464cdae8a95cbc5b398e351`  
**Repository:** `Spider4Tech/sillage-brume`  
**Review date:** 31 October 2026  
**Scope:** `tests/c/vole_proto.c`, `tests/c/vole_params.c` and their direct C dependencies, as well as the test harness and the result notes.  
*Since this review, the files it examined have moved to `prototypes/vole/`; the paths below are those of the commit reviewed.*

**Nature:** a static review of the source code and of its cross-file consistency. This document is neither a certification, nor a security proof, nor an independent cryptographic audit of the protocol.

---

## 1. Executive summary

The commit provides a substantial experimental prototype: key generation, construction of a seed tree, production of the commitments, aggregation of the VOLE views, verification, an attack on a reduced model, size estimation and timing are gathered in a self-contained C program. The prototype is concrete enough to support a performance study and an analysis of the construction.

The review does not, however, justify integrating it into the official SILLAGE-SIG format. Several implementation points must be settled before the code is treated as a stable basis:

1. **The displayed VOLE-128 public-key size is wrong for the bytes actually committed in the transcript: 109 bytes are required, not 93**, with the current behaviour.
2. The helpers `H()` and `H4()` do not apply exactly the same domain convention. The proof will have to deal with the construction actually coded, and the transcripts will have to be made canonical.
3. `verifier()` does not receive the length of the signature buffer; it therefore cannot validate a truncated or over-long external input.
4. Dynamic allocations are numerous and their return values are not checked systematically.
5. The generation path handles secret data through divisions, branches and memory accesses that depend on secrets; the prototype cannot be qualified as constant-time.
6. The code relies on native memory representations for several hashed or serialised fields.
7. The program's checks are mainly round-trip tests and targeted alterations; they do not replace KATs, differential tests of the constraints, fuzzing and sanitizers.
8. The `vole_params` tool explores a limited, discrete domain. It does not demonstrate a global optimum nor coverage of all relevant attacks.

**Recommended decision:** keep the prototype as a research branch, do not change the official SIG format, first fix the measurement gaps, memory contracts and encodings, then complete the independent tests and the proof.

A P1 level marks a point to fix before exposure in an API or integration into the format. It does not mean that a practical cryptographic attack has been demonstrated. Theoretical security findings (EUF-CMA, QROM, RSD reduction) remain separate from code defects.

---

## 2. Scope, method and limits of the verification

### 2.1 Sources examined

- `tests/c/vole_proto.c`: prototype, keys, GGM tree, VOLE aggregation, algebraic constraints, signing, verification, reduced attack and timing.
- `tests/c/vole_params.c`: size computation, ISD estimation and parameter search.
- `tests/c/Makefile`: build rules for the C programs and the `compression` target.
- `tests/run_all.py`: integration of the prototype into the test suite.
- `tests/c/resultat.h`: recording of the checks and exit code.
- `sillage/c/commun.c` and `sillage/c/sillage.h`: SHAKE, parallel H4, system randomness and carry-less multiplication.
- `sillage/c/isd.c`: estimators used by `vole_params`.
- `docs/PISTES.md`: description of the measurements and adoption conditions.

### 2.2 Code anchoring

The review of the C code covers the content at commit `59672814ed8a70b27464cdae8a95cbc5b398e351`.

At the time this review was published, `main` also includes the later commit `9a7ae4675313062359f2b0822c1396169a00950f`, which adds `tests/c/rsd_attaques.c` and updates `docs/PISTES.md` and `tests/c/Makefile`. Comparing the commits shows that this later change modifies neither `vole_proto.c` nor `vole_params.c`. The new `rsd_attaques.c` tool is not audited in this report; the RSD figures published in the recent documentation are therefore not validated by this review.

### 2.3 What was checked and what was not

The findings on memory flow, dimensions, calls and encodings are established by reading the sources and cross-checking calling and called functions.

The arithmetic in GF(2^lambda) was checked independently: the two reduction polynomials were verified irreducible over GF(2), then 1 000 random products per width were compared with a reference polynomial multiplication, reproducing the carry-less algorithm and its reduction. This check validates the reproduced mathematical model, not the C binary, the compilation, or the PCLMUL/PMULL instructions.

**No compilation or execution of the C binary was carried out in this environment.** Local cloning failed for lack of network resolution to GitHub. It is therefore not claimed that the build, the tests, the sanitizers, Valgrind, dudect or the benchmarks were run during this review. The performance results recorded in the repository are treated as results reported by the project, not as measurements reproduced here.

---

## 3. Findings to fix

### V-01 — P1 — VOLE-128 public-key size underestimated by 16 bytes

**Locations:** `tests/c/vole_proto.c`, definition of `vpk_t`, `keygen()`, `developper_H()`, calls to `H('m', ...)` and size display.

The public working structure contains a 32-byte seed and a 256-byte array `y`. `keygen()` fills the 32 seed bytes with `sl_alea(pk->seed, 32)`. For VOLE-128, `developper_H()`/`H4()` only consumes `c->Bl` bytes of this seed, with `Bl = lambda/8 = 16`.

However, `signer()` and `verifier()` hash the whole structure with `H('m', pk, sizeof *pk, ...)`. The last 16 random bytes of `seed` are therefore bound to the transcript, even though they are not used to expand H. They must be kept to reproduce this transcript. The array `y` is only filled on `c->cB` bytes; the remaining bytes are initialised to zero by `keygen()` and can be rebuilt from the compact representation.

The display computes `c.Bl + c.cB`. For VOLE-128, `c.Bl` is 16 and `c.cB` is 77: the report shows 93 bytes. Yet, with the current behaviour, 32 bytes of `seed` and 77 bytes of `y` must be kept, i.e. **109 bytes**. For VOLE-256, 32 + 153 = 185 bytes, which matches the current display.

**Consequence:** the VOLE-128 public-key size comparison in `docs/PISTES.md` is underestimated by 16 bytes, unless the protocol is changed so that the 16 surplus seed bytes are no longer generated or hashed.

**Fix:** choose one of the two behaviours explicitly:
- keep a 32-byte seed, use and hash all of it, and state 109 bytes for VOLE-128;
- define a 16-byte seed for VOLE-128, generate exactly that seed, and hash a canonical compact serialisation of 16 + 77 bytes.

In both cases, do not use `sizeof(struct)` as a cryptographic encoding. Define an explicit public-key encoder and pass exactly its bytes to the transcript.

**Qualification:** a measurement/encoding error shown by the code; not a demonstrated cryptographic attack.

### V-02 — P1 before the proof — `H()` and `H4()` do not use the same domain convention

**Locations:** `tests/c/vole_proto.c`, `H()` and `H4()`; `sillage/c/commun.c`, `sl_shake4()`.

`H()` absorbs the prefix `SILLAGE-VOLE`, then the domain byte and the supplied fields. `H4()`, on the contrary, builds a message of the form `salt || dom || idx || seed`, then calls `sl_shake4()`. `sl_shake4()` applies SHAKE to the bytes passed; it does not add the `SILLAGE-VOLE` prefix.

The visible domains of `H4()` (`'H'`, `'n'`, `'l'`) are distinct from the domains currently used by `H()`. I therefore do not conclude that an exploitable collision exists. The finding is more precise: two families of functions that take part in the same transcript do not apply the same prefix and separation convention.

**Consequence:** the proof must model exactly these calls and their bytes, not an abstract function H that would not match the code. A later change in the domains or a reuse of the helpers could make the separation ambiguous.

**Fix:** define a single transcript grammar: protocol identifier, version, profile/parameter identifier, domain, typed fields, lengths and integer encoding. Make the four outputs of `H4()` correspond exactly to four scalar calls of this grammar. Add KATs for each domain and each profile.

This point does not by itself demonstrate a cryptographic weakness; it prevents the hashing convention from being considered fully formalised.

### V-03 — P1 before exposure — `verifier()` does not receive the signature length

**Locations:** `tests/c/vole_proto.c`, `verifier()`, computation of field pointers and reading of the counter.

`verifier()` receives a pointer `sig`, but no length. It computes the field addresses and reads in particular the final counter without being able to check that the buffer actually contains the expected bytes.

In the current harness, the pointer comes from a buffer allocated with `taille_sig(c)`. The review therefore does not find an out-of-bounds read in this nominal internal call. However, the function's contract does not allow checking an arbitrary signature received from a caller.

**Fix:** add `siglen`, check the pointers, require a length exactly equal to the expected length and validate each offset before any read. Required tests: zero length, 1, size−1, size, size+1 and truncation at every field boundary.

### V-04 — P1 before integration — Unchecked allocation returns

**Locations:** `repetition()`, `lignes_M()`, `contraintes_poly()`, `contraintes_val()`, `signer()` and `verifier()` in `tests/c/vole_proto.c`.

The prototype performs dynamic allocations for the commitments, vectors, matrices and temporary buffers. The return values of `malloc()`/`calloc()` are not checked systematically before use. Visible examples: `S` in `repetition()`, `rows` in `lignes_M()`, `acc/A/Bb` in the constraint functions and the series of buffers in `signer()`/`verifier()`.

**Consequence:** an allocation failure can lead to a NULL dereference or undefined behaviour. The fixed test parameters do not guarantee that every allocation will succeed on every machine.

**Fix:** centralise allocations, check size multiplications, propagate an explicit error, release resources on a single exit path and add allocation-failure injection. Do not turn a memory fault into a partial signature.

### V-05 — P1 if constant time is required — Secret data used in the generation flow

**Locations:** `bits_temoin()` and `keygen()` in `tests/c/vole_proto.c`.

`bits_temoin()` converts positions derived from the witness into coordinate digits with division and modulo. The dividend comes from `pos`, hence from positions tied to the secret.

`keygen()` computes `q` from `pos[i]`, then branches on `q < c->k`. Depending on this branch, it reads a column of `cols` at an address that depends on `q`, or updates a bit of `y` that depends on `q`. The path and the memory addresses may therefore depend on the secret positions.

**Consequence:** the source code does not allow these paths to be qualified as constant-time. A timing or microarchitectural leak is plausible; no practical attack is demonstrated by this review.

**Fix:** analyse `keygen()` and the witness preparation as operations that handle secrets. Replace branches and indexed accesses with a construction with fixed time and memory accesses. Check the machine code on the targeted compilers and architectures, then run a dudect/Valgrind campaign. The tests should cover the exact compilation options adopted.

The project documentation already flagged the division in `bits_temoin()` and the branch in `keygen()`; the review confirms this point and specifies the dependency of the accesses to `cols`.

### V-06 — P2 — Native, non-canonical encodings in the transcript and the signature

**Locations:** `H4()`, `H('r', ...)`, `H('m', ...)`, `H('d', ...)` and writing/reading of `ctr` in `tests/c/vole_proto.c`.

Values are hashed or serialised from their native memory representation:
- `idx` in `H4()`;
- the `pos` array of `uint16_t`;
- the `ctr` counter of `uint32_t`;
- the whole `vpk_t` structure.

The code defines no normative byte order for integers. The signature writes `ctr` by `memcpy()` of its memory representation, and the verifier reads it back the same way. This works on a given architecture, but ties the format to the endianness and to the representation used.

I do not assume that padding exists in the current definition of `vpk_t`; the problem is the direct use of a C representation as a normative serialisation.

**Fix:** explicitly encode each integer (for example in little-endian), each field and each length. Never hash `sizeof(struct)` directly. Add identical KATs on x86-64 and ARM64; if relevant, include a big-endian target under emulation.

### V-07 — P2 — `verifier()` accepts a pre-expanded matrix H without proving its link to `pk`

**Location:** signature of `verifier()` and call to `melanges()`.

`verifier()` receives `pk` and `cols`. `pk` contains the public seed; `cols` contains the columns expanded from that seed in the current `keygen()` path. `verifier()` does not check that `cols` actually corresponds to `pk->seed`.

The test program does provide the two corresponding objects, so the nominal path tested is consistent. The internal contract is nevertheless fragile: a caller may supply a matrix coming from another seed.

**Fix:** in a final API, expand H from the public seed or encapsulate the cache in an opaque object that carries the identity of the canonical key. Add a test that deliberately pairs a matrix with another key and must fail.

This finding concerns the contract and the integrity of the cache, not a demonstrated forgery of the current test.

### V-08 — P2 — Secrets and intermediates not erased before `free()`

**Locations:** releases in `signer()` and `verifier()`.

Several buffers that contain the witness, tree seeds, masks or intermediates derived from the secret are released without prior erasure. The project already exposes `sl_effacer()`, but the prototype does not use it in these paths.

**Consequence:** the contents may remain in freed memory until reused. This is not a demonstrated remote attack, but a gap in memory hygiene.

**Fix:** classify the buffers (secret, sensitive derivative, public), erase the sensitive buffers with a primitive that the optimiser cannot remove before releasing them, and also handle early exits/errors.

### V-09 — P2 — The test binary returns 0 even if a check fails

**Location:** `tests/c/resultat.h`, `res_ecrire()`.

`res_ecrire()` aggregates the booleans into `ok` and correctly displays the overall status, but unconditionally returns 0 at the end. The Python orchestrator inspects the booleans in the JSON and detects false checks. A direct run of the binary may, however, interpret the zero exit code as a success.

**Fix:** return `ok ? 0 : 1` and check write/close errors. This helper predates the prototype, but the new prototype relies on it.

### V-10 — P2 — Test coverage insufficient for cryptographic confidence

**Locations:** `main()` of `tests/c/vole_proto.c` and the test entry in `tests/run_all.py`.

The visible checks cover acceptance of an honest signature, some field mutations, another message, a modified key, the size reduction, an attack on a reduced model and the rejection of a false witness on that model.

They are not enough to validate independently:
- the finite-field arithmetic in the C binary;
- the H4/scalar equivalence;
- the tree and the computation of the number of openings on all small cases;
- the algebraic equivalence of `contraintes_poly()` and `contraintes_val()`;
- verification inputs of arbitrary length;
- the allocation/RNG failure paths;
- robustness under ASan/UBSan and fuzzing.

The offset-based alterations target the main sections written by the signer. The region of the challenge commitments has no guaranteed dedicated mutation; random flips do not replace a test of each field.

**Fix:** separate invariant tests from benchmarks; publish KATs; add an independent GF(2^lambda) reference; test H4 against four scalar outputs; test reduced trees exhaustively; compare the constraint functions by controlled random generation; add fuzzing of the verifier once `siglen` is added; run the sanitizers.

A successful signer–verifier round trip is not a proof of soundness.

### V-11 — P2 — Exploratory benchmark, not yet a statistical characterisation

**Location:** `main()` of `tests/c/vole_proto.c`.

The program measures 30 signatures per profile on a single key and a fixed message. It publishes an average signing time; verification is timed only once per thread configuration. There is no median, spread, percentiles, confidence interval or separate warm-up.

The matrix H is expanded in advance and reused. Its cost is measured separately, which may correspond to a server-cache scenario. Cold-H and warm-H scenarios should nevertheless be published separately.

**Fix:** measure several keys, several message sizes, several verification repetitions and explicitly fixed thread counts. Publish mean, median, p90/p95 and spread. Include keygen, the cost of expanding H, wall-clock time and the full environment (CPU, compiler, options, OpenMP, frequency, code version). Grinding in particular makes the distribution of signing time relevant.

### V-12 — P2 — `vole_params` does not prove a global optimum

**Locations:** `tests/c/vole_params.c` and functions called in `sillage/c/isd.c`.

The grid only covers `w` from 36 to 240 in steps of 4, fixes `d` at 4 and limits `n` to 40 000. `n` is a multiple of `w` and the search relies on a bisection that assumes the estimated criterion evolves monotonically. This monotonicity is not demonstrated in the code. `cout_temoin()` uses a greedy construction of the arities `mu`; the code does not establish that it globally minimises the cost for all candidates.

`sd_cout()` compares Prange, two-list and BJMM with the explicit internal bounds of its calls. It is a fixed selection of estimators and parameter ranges, not an enumeration of all ISD or RSD-specific attacks.

The `formule_de_taille_retrouve_sdith2` check verifies that the size formula reproduces reference sizes. It validates neither the optimality of the grid nor the assumptions of the RSD reduction.

**Fix:** present the output as the best candidate found in the grid; record the bounds and the optimisation parameters; check monotonicity; compare with an exhaustive search over reduced ranges and with a denser exploration around the minima; distinguish the reduction cost from the direct-attack cost.

### V-13 — P2 — RNG errors turned into `abort()`

**Locations:** calls to `sl_alea()` in `keygen()`, `signer()` and the attack path.

A `getrandom()` error is turned into `abort()`. For a research executable, this causes a visible stop, but provides no reusable error contract and does not guarantee the cleanup of allocated resources.

**Fix:** propagate an error, clean up and erase the sensitive buffers, and never return a partial signature. Add a test with a simulated failing RNG.

### V-14 — P3 — Unused allocations and bundled responsibilities

**Locations:** `repetition()` and `signer()`.

The `tmp` buffer allocated in `repetition()` and the `uu` buffer allocated in `signer()` are released without being used. The same file moreover combines protocol logic, the reduced-model attack, serialisation, benchmark and tests.

**Fix:** remove the unused allocations and consider a gradual split of the code into modules (finite field, transcript, tree/commitments, signer, verifier, reduced attack, benchmark). Make this split without any concurrent algorithmic change and compare the KATs before/after.

---

## 4. Positive points checked

### 4.1 Multiplication in GF(2^lambda)

`fmul()` computes a carry-less product of 64-bit words, followed by a reduction. The polynomials given by the constants are:

- 128 bits: x^128 + x^7 + x^2 + x + 1 (low constant 0x87);
- 256 bits: x^256 + x^10 + x^5 + x^2 + 1 (low constant 0x425).

The independent arithmetic model passed the irreducibility checks and 1 000 comparisons of random products per width with a binary-polynomial reference. This supports the mathematical consistency of the implemented reduction.

**Limitation:** the C binary and the PCLMUL/PMULL backends were not run here. Adding a C reference test remains necessary.

### 4.2 Fixed dimensions of the prototype

For PR128, PR256 and PRTOY, the derived dimensions used for the challenges, the seeds, the H4 blocks, the WMAX/DMAX arrays, the temporary buffers of `repetition()` and the transposed vectors stay within the declared fixed capacities (WMAX=4, DMAX=6, ch[64] and the corresponding local buffers). This holds for the hard-coded profiles, not for a future free parameterisation. `ctx_init()` should refuse any combination exceeding these capacities, or replace them with checked allocations.

### 4.3 Internal convention of the interleaved tree

For the current profiles, N=2^kappa and L=tau*N. The leaves are placed at index L + i*tau + e, with i in [0,N) and e in [0,tau). The maximum index is 2L−1; the buffer of 2L nodes covers it. `marquer()` and `repetition()` use this same convention.

This confirms an internal indexing consistency. It does not show that this layout is the one expected by the theoretical proof, nor that the opening probability of the reference document still applies. An exhaustive validation on small trees is necessary.

### 4.4 Signature size formula

`taille_sig()` matches the fields that `signer()` actually copies into the buffer: salt, h3, aux, ut, dw, ab coefficients, openings, selected commitments and counter. For both current profiles, 4 112 and 15 906 bytes match the coded dimensions.

This consistency validates neither the transcript, nor the security, nor the VOLE-128 public-key size.

### 4.5 Sampling of positions within blocks

`keygen()` uses rejection before reduction modulo. For blocks of size 245 and 253, the threshold 65536 − 65536 % block removes the modulo bias, assuming uniform draws of the words supplied by `sl_alea()`. The blocks are disjoint and `q=i*block+pos[i]`, so the mechanism selects one position in each block with no collision between blocks.

This validates this sampling mechanism for the present parameters, not the hardness of RSD nor the cryptographic quality of the overall distribution.

---

## 5. Prioritised recommendations

### Batch A — Before republishing the figures

1. Fix the size and encoding of the VOLE-128 public key.
2. Define a canonical serialisation of each transcript field.
3. Unify the domain convention of H() and H4().
4. Add `siglen` to the verifier and validate the bounds before any read.
5. Check all allocations and propagate errors.
6. Make `res_ecrire()` return a non-zero code if a check fails.

### Batch B — C tests to add

1. An independent reference for `fmul()` in C, software and hardware backends.
2. KATs for the H/H4 domains, keys, commitments, challenges, openings and signatures.
3. A test of H4 against four scalar calls.
4. Exhaustive tests on small trees for `marquer()`, GGM reconstruction and the number of openings.
5. Differential tests of `contraintes_poly()` and `contraintes_val()` on valid and invalid witnesses.
6. Tests of truncated, over-long and modified signatures at every boundary.
7. Fuzzing of the verifier and ASan/UBSan/Valgrind runs.
8. Injected allocation and RNG failures.
9. A matrix H inconsistent with the public seed.
10. x86-64/ARM64 tests on the same KATs.

### Batch C — Security of the implementation and of the protocol

1. A constant-time study of keygen and the signer, with a check of the machine code.
2. Classification and erasure of secrets and intermediates.
3. A formal analysis of the transcript actually produced, including H4.
4. An EUF-CMA proof specific to this construction, with an independent human review.
5. An analysis of RSD attacks and of the reduction's assumptions, separate from the ISD estimates.
6. A specific QROM analysis; do not infer a quantum level from these benchmarks.

### Batch D — Parameters and performance

1. Present `vole_params` as a grid search, not a global optimum.
2. Check monotonicity experimentally before using the bisection.
3. Extend or document the optimisation ranges of the estimators.
4. Redo the benchmarks on several keys and message sizes.
5. Publish cold H and warm H, keygen, signing and verification separately.
6. Keep the raw data, compile the same sources/options and fix the threads explicitly.

---

## 6. Maturity table

| Area | State confirmed by the review | Action |
|---|---|---|
| GF(2^lambda) | Arithmetic model checked on samples; C binary not run | Independent C KAT |
| Public key | 16-byte gap in the VOLE-128 size | Fix format and measurement |
| H / H4 | Different prefixes and grammars | Make transcripts canonical |
| GGM tree | Consistent internal indexing | Exhaustive tests and opening proof |
| Algebraic constraints | Signer/verifier functions present | Independent differential tests |
| Verifier | No input length | Add siglen and a bounded parser |
| Allocations | Unchecked returns | Centralised error handling |
| Constant time | Visible secret dependencies | Machine-code audit and leakage tests |
| Tests | Targeted checks, without a complete independent campaign | KATs, fuzzing, sanitizers |
| Benchmarks | Exploratory measurements | Multi-key, multi-message distribution |
| Parameters | Limited grid | Do not claim a global optimum |
| EUF-CMA / QROM proof | Not provided for this construction | Cryptographic blocker |

---

## 7. Conclusion

The prototype is a useful research basis. The coded signature sizes are consistent with the fields produced; the finite-field arithmetic is consistent with the checked arithmetic model; the tree uses a consistent indexing convention within the code; the per-block sampling avoids the modulo bias for the current sizes.

The gaps to fix are equally concrete. The most immediate one for the published results is the underestimated VOLE-128 public key. For software quality, the verifier's limits, the unchecked allocations, the native encodings and the tests' exit code must be fixed. For implementation security, the secret dependencies of the generation path prevent a constant-time qualification. Finally, these code checks replace neither an EUF-CMA proof, nor the RSD analysis, nor the QROM analysis.

**Decision: keep the prototype outside the official format, fix the measurement/encoding and C robustness problems, then continue the independent tests and the mathematical analysis.**

The review concludes neither that the scheme is broken nor that it is secure. It delimits what was checked in the sources, what is consistent, what remains to be tested and the minimum conditions to meet before granting more confidence to the code.
