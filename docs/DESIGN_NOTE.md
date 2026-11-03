# The proposed paradigm: “cryptography by decoding” (working name: SILLAGE)

*English translation of [`guide.md`](guide.md), the original design note. It is kept for its history: the constructions described in [`PROOFS.md`](PROOFS.md) and the README have since departed from it in several places (the KEM is quasi-cyclic rather than an Alekhnovich-style LPN scheme, and the signature is a hypercube MPC-in-the-Head over plain binary syndrome decoding, without the tensor twist). The broken mathematical layout of the original has been restored.*

A single unifying principle for the whole suite:

> Every secret lives on the other side of a noisy channel. The adversary must decode a random channel (NP-hard). The key holder decodes a structured channel (easy for them).

Three primitives, one law. And an engineering principle I consider essential for this use case:

> **“Novelty with safe degradation”:** every new component is designed so that, if it were broken, it would collapse to the best-studied hard problem — never to an unknown weakness.

## 2.1 — KEM “Sillage-KEM” (key exchange)

Skeleton (the LPN family in the Alekhnovich regime, 2003 — under-exploited):

- **Public key:** `(A, B = A·S ⊕ E)` with `A` a random `n × m` matrix, `S` a uniform secret, and `E` a sparse noise (each column of weight `t ≈ √m`).
- **Encapsulation:** draw a sparse `R`, compute `U = A·R` and `V = B·R ⊕ Enc_C(μ)`, where `μ` is the session secret and `C` an error-correcting code.
- **Decapsulation:** `V ⊕ S·U = E·R ⊕ Enc_C(μ)` — the product of two sparse vectors is sparser still, so `C` decodes and returns `μ`.

No exploitable algebraic structure (everything is binary, noisy and sparse). Two research twists I add:

- **Noise cascade:** `E = E₁ ⊕ M(E₂)` with `M` a public mixer — two independent noise regimes; an attack targeting one regime no longer sees the expected distribution. Open research question: the real gain remains to be quantified.
- **Tensor generation of `A`:** `A` derived from slices of a 3-tensor of constrained rank (compressed public key, and the attacker faces tensor rank and LPN at the same time). But — and this is the safe-degradation principle — the structure never carries security: in the worst case, one falls back to plain LPN.

## 2.2 — Symmetric encryption “BRUME” (the conceptual successor of AES)

The genuinely new angle: a **self-correcting cipher** — decryption is a syndrome decoding. Native consequences: any alteration of the ciphertext is detected by construction (intrinsic tamper evidence, resistance to fault attacks).

Architecture of the permutation (sponge/duplex mode, 512-bit state, 512-bit key → 256-bit security after Grover):

- **Diffusion:** no MixColumns — the state lives on the vertices of a 6-regular Ramanujan expander graph, with linear operations along the edges. Proven expansion → provable diffusion bounds, unlike an ad hoc SPN.
- **Non-linearity:** co-optimised 4-bit S-boxes (non-linearity ≥ 8, algebraic immunity ≥ 4, minimal differential uniformity) — a concrete research programme in itself.
- **Mode:** duplex with a 128-bit tag (IND-CCA on top of the self-correction, which itself detects faults).

## 2.3 — Signatures “Sillage-SIG”

No naive Stern (too heavy). Modern basis: MPC-in-the-Head on the syndrome-decoding relation (the SDitH/PERK family — NIST's “additional signatures” process treats it as a serious approach). My twist, again with safe degradation: the proven relation is `e = e₁ ⊗ e₂ + e_n` — the witness decomposes as a tensor and communication drops; if the tensor structure were attacked, the protocol falls back to ordinary syndrome decoding. Safety net: a Merkle layer over the BRUME permutation (hashing = the oldest assumption in all of cryptography).

## Important information

This is an experimental research project, not a production one: there is therefore no point in suggesting existing cryptographic systems to replace BRUME or SILLAGE.

Code in C only, tests included.
