# Migration v0.6: BRUME-1024q replaces BRUME-512

Written on 13 November 2026, after the author's decision: **in v0.6, BRUME-1024q replaces the classical BRUME-512** in the
suite. This document lists what the change touches, the decisions it needs, and the order of work. **Nothing in `sillage/`
is modified before the author has validated it.**

The reference of BRUME-1024q is `prototypes/brume_q/b1024/SPEC.md` (draft v0.6-1). The state of the prototype is in its
README, `ROADMAP.md`, `AEAD_SECURITY.md` and `DOMAINS.md`.

## 1. What the change touches, and what it does not

**Not touched.** Sillage-KEM, the signature (Sillage-SIG v0.5, VOLE) and their tests. They use SHAKE256, never BRUME
(checked: no reference to BRUME in `kem.c`, `sig.c`, `vole.c`, `sillage_kem.py`, `sillage_sig.py`).

**Touched:**

| Area | Today (v0.5) | Files |
|---|---|---|
| Permutation | BRUME-512 (128 nibbles, D₁₂₈), AVX2 and NEON constant-time kernels, table fallback refused unless `SL_REPLI_NON_CT` | `sillage/c/brume512*.{c,h}`, `brume512_tables.h`, `gen_tables.py`, `sillage/brume512*.py` |
| Hashing | `sl_hash` (sponge), `sl_hash_arbre` (tree), `sl_hash_multi` | `sillage.h`, `brume512.c`, `brume512_avx2.c` |
| AEAD | Two profiles (0: c = 256, classical 128 bits; 1: BRUME-512-256, c = 384); context API; multi-message API | idem |
| Parallel AEAD | `sl_aead_p_*` (parallel duplex BRUME-512p) | idem, `docs/PROOFS.md` § 4.5 |
| TE mode | `sl_te_*` (7 bytes of corrections per 64-byte block) | idem |
| Python | Reference `sillage/brume512.py` and bindings `sillage_c.py`; about 53 test files use BRUME | `sillage/`, `tests/` |
| Proofs | § 4 of `docs/PROOFS.md`: permutation, AEAD (Theorem 14, plaintext-overwrite orientation), tree, parallel duplex | `docs/PROOFS.md`, `docs/AUDIT_REPORT.md` |
| Cryptanalysis in the battery | Trails, branch number, division property, degree, integral, cycles, symmetries, all for 128 nibbles | `tests/` |
| KATs, README, demo, benches | BRUME-512 | various |

## 2. Decisions for the author

| # | Question | Options | Recommendation |
|---|---|---|---|
| D1 | **Python** ("Python frozen, new work in C") | (a) Keep `brume512.py` and its Python tests as history of v0.5, and write the v0.6 tests in C, run by `run_all` (the `c:` entries already exist). (b) Write a Python reference of BRUME-1024q | **(a)**. The prototype already has a dense reference in C and all its checks in C |
| D2 | **AEAD profiles** | (a) One profile: BRUME-1024q, c = 384. (b) Keep two profiles | **(a)**. Profile 0 (c = 256) only gave 2^85 against quantum collisions; profile 1 is replaced by a faster and stronger one |
| D3 | **API** | (a) Keep the signatures (`profil` = 0 only, 64-byte key, 24-byte nonce, `outlen` free) and change the outputs. (b) A new API | **(a)**. Keys and nonces already have the same sizes. The tag is 32 bytes, as in v0.5 profile 1 (`PROFIL[1].tag = 32`, rate 16 bytes, λ = 256); v0.5 profile 0 had a 16-byte tag and a 32-byte rate |
| D4 | **Parallel AEAD (`sl_aead_p_*`) and TE mode (`sl_te_*`)** | (a) Drop them in v0.6. (b) Port them, each with a new design and proof. (c) Keep them on BRUME-512 | To decide. (c) would keep two permutations, against the aim of the change. The prototype's `aead_multi` covers batches of messages, not one message in parallel |
| D5 | **Default digest** | 32 bytes (v0.5 `sl_hash`) or 64 bytes (1024q) | 64 bytes. At c = 384 the generic quantum level is 128 bits; a 32-byte digest would cap quantum collisions at 2^85 |
| D6 | **Platforms** | 1024q has AVX2 kernels and a dense reference (not constant-time) | Write a **portable constant-time** kernel (bitsliced across nibbles on 64-bit words, S-box circuit and masks per position) before v0.6, then NEON. The suite refuses non-constant-time fallbacks, and this rule must hold for 1024q |
| D7 | **Gate for v0.6** | When is v0.6 called ready? | At least: `SPEC.md` written and checked by a second implementation; the AE step of `AEAD_SECURITY.md` written; § 4 of `PROOFS.md` rewritten for 1024q (SpongeWrap orientation); the battery ported and complete; human review still open (as for v0.5) |

## 3. Order of work (proposed)

1. **`SPEC.md`** (draft v0.6-1 written) and a second, portable implementation written from it alone (`spec_ref.c`).
   - **It reproduces the 18 KATs on x86-64 and on ARM64** (qemu, aarch64 gcc 15).
2. **Portable constant-time kernel** (D6), checked by ctgrind and dudect.
3. **The AE step** of the AEAD proof (`AEAD_SECURITY.md` § 4 (b)), and the rewrite of `PROOFS.md` § 4 for 1024q.
4. **`sillage/`**:
   - new files `brume1024.{c,h}`, with the generated tables and the constant-time kernels;
   - `sillage.h` adapted according to D3 and D4;
   - `brume512*` kept or removed according to D1 and D4.
5. **Battery**: port the BRUME tests to C on 1024q.
   - Functional, modes, API, fuzzing, constant time, Valgrind: from the prototype's checks and campaigns.
   - Cryptanalysis: C3 certificates, impossible differentials, aggregation, cubes, then boomerang and division property.
6. **KATs v0.6**, README, `AUDIT_REPORT.md`, benches, Dossier.

## 4. What does not change

- **The rules.**
  - No security traded for a negligible gain.
  - Better to over-verify.
  - The full battery before any commit.
  - Constant time measured on two machines.
  - No credentials or machine details in the repository.
- **The status: research, not for production**, until a human review.
