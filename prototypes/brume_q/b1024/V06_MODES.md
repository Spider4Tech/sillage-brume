# BRUME-1024q, v0.6: the TE mode and the parallel AEAD (design and proofs before any code)

Written on 14 November 2026, after the author's decision D4 (`docs/MIGRATION_V06.md`): **the parallel AEAD and the TE mode
are ported to BRUME-1024q**, since BRUME-512 leaves the suite. Following the rule "a function change comes with its
argument first", this document gives each mode, its proof, and what is checked mechanically. **The parameters of § 2.1
were approved by the author on 14 November, and the parallel AEAD is implemented in the prototype** (§ 2.5); the TE
layer is reused as it is at the migration.

Status of the proofs: ours, not reviewed, in the ideal-permutation model, built on `AEAD_SECURITY.md` (Theorem 1′,
§ 4 bis; Theorem Q, § 4 quinquies; § 4 sexies).

## 1. TE mode (self-correcting) on BRUME-1024q

**Definition.** Unchanged from the suite (`docs/SPEC.md` § 2.7), on top of the BRUME-1024q AEAD instead of BRUME-512:
- the AEAD output X is cut into 64-byte blocks, and each block receives 7 parity bytes (`C₀`, then 8 Hamming syndromes
  by bit plane);
- decryption corrects at most one altered byte per block, refuses inconsistent syndromes, then runs `aead_ouvrir` on the
  corrected X.

Write par(X) for the parities and corr(X′, π′) for the corrected string (or ⊥). Both are **public deterministic
functions**: they involve neither the key nor the permutation.

**The notion.** Flipping one byte of a ciphertext yields another valid ciphertext, by design: the strict "integrity of
ciphertexts" notion cannot hold, and is not the goal. The notion is **AE up to the public correction**:
- encryption returns (X, par(X)) in the real world and ($, par($)) in the ideal world, with $ uniform of the same
  length;
- decryption of (N, A, X′, π′) computes X = corr(X′, π′), and returns ⊥ if X = ⊥;
- if (N, A, X) was output by an encryption, both worlds return its message;
- otherwise the real world returns `aead_ouvrir`(N, A, X), and the ideal world returns ⊥.

**Proposition TE.** For every adversary A against the TE mode, there is an adversary B against the AEAD (game of
`AEAD_SECURITY.md` § 4 bis) with the same numbers of queries, the same amount of data and the same queries to P, such
that Adv^{AE-TE}(A) = Adv^{AE}(B).

*Proof.* B forwards each encryption query and appends par(X). For a decryption query it computes X = corr(X′, π′); it
answers ⊥ if X = ⊥, the logged message if (N, A, X) is in its log of encryption outputs, and otherwise forwards
(N, A, X) to its own decryption oracle. That last query is allowed, since it is not an encryption output. A's queries
to P are forwarded. In the real world B simulates the real TE game, and in the ideal world the ideal one, exactly. ∎

**Consequences.**
- Every bound of the AEAD transfers unchanged:
  - classical: Theorem 1′ and § 4 bis;
  - Q1: Theorem Q and its corollary;
  - Q2d (§ 4 sexies): the wrapper computes corr and the log test reversibly, which is the same blocking as in that proof.
- The tag remains the only integrity guarantee, as in the suite (`docs/PROOFS.md` § 4.3, remark 1). The parities only
  correct accidental errors.
- **Port:** the TE layer depends neither on the permutation nor on the rate. Its code and tests can be reused as they
  are, over the new AEAD.

## 2. Parallel AEAD on BRUME-1024q

### 2.1 Construction (approved and implemented, 14 November)

The same key (64 bytes), nonce (24 bytes) and tag (32 bytes) as the sequential AEAD; r = 640, c = 384.
- **Initial state:** key ‖ nonce ‖ 0 ‖ frame, the frame being the sequential AEAD's except:
  - byte 127, low nibble = **6** (parallel AEAD; 3 is the sequential AEAD, 5 the sponge);
  - byte 122 = log₂ B = **13**.

  So the initial states of the two AEADs differ for every key and nonce.
- **Trunk:** the AAD phase of the sequential AEAD (XOR into the rate, pad 0x01, `DOM_AAD` = 1 on the last block). Its
  final state S_A is never output.
- **Leaf j**, for 0 ≤ j < k = max(1, ⌈ℓ/B⌉), B = 8 192, starting from S_A:
  1. XOR (le64(j) ‖ 0x01 ‖ 0*) into the rate, `DOM_FOURCHE` = 5, P;
  2. XOR 0^r, `DOM_FOURCHE2` = 3, P;
  3. chunk j (bytes [jB, min((j + 1)B, ℓ))) is encrypted exactly as the text phase of the sequential AEAD (SpongeWrap
     orientation; full blocks without domain; last block, possibly empty, padded with 0x01 and `DOM_TEXTE` = 2).

  CV_j = the first **64 bytes** of the rate after the last permutation of the leaf.
- **Root**, starting from S_A: absorb CV₀ ‖ … ‖ CV_{k−1} ‖ le64(k) ‖ le64(ℓ) (XOR into the rate, pad 0x01,
  `DOM_RACINE_P` = 4 on the last block; not the tree root's `DOM_RACINE` = 9). **Tag** = the first 32 bytes of the rate after the last permutation.
- **Decryption** decrypts all leaves (overwriting the rate with the ciphertext, as in the sequential AEAD), computes the
  CVs and the root, and compares tags in constant time. **Nothing is released before the check**; the output is wiped on
  failure.

**Why these choices.**
- *Domains.* They are distinct within the construction, and the mode nibble separates it from the others. Value 4 is
  free in mode 6: it was the retired length domain of the sequential AEAD (mode 3).
- *Two fork calls.* They keep the suite's structural argument (`docs/PROOFS.md` § 4.5). From a fixed secret state with
  known differences on 64 bits, the first keystream comes after two calls, i.e. 64 rounds.
- *CV of 64 bytes.* A collision of two CVs costs 2^(512/3) quantum (BHT), above the 2^128 target; 32 bytes would give
  2^85.
- *B = 8 192.* The leaf size of the tree. Each leaf then has 105 calls: 2 forks, 102 full blocks and 1 last block.

The cost is two fork calls per leaf and a root; it pays off only for long messages. The leaves are independent, so the
256-state bitsliced kernel applies to them (not measured).

### 2.2 Encoding (Lemma 5′, checked mechanically)

**Lemma 5′.**
1. Distinct (A, C) under one nonce give distinct final paths of the root.
2. The final path of leaf j determines (A, j, chunk j).
3. No final path (root or leaf) is a strict prefix of another.
4. The role of a call can be read from its last entry: a keystream path ends with domain 3 or 0, a CV path with domain 2,
   the tag path with domain 4.
5. The root's final path decodes as (A, k, ℓ, CV list), the content having a fixed-length structure once k is known.

*Proof.* The trunk is the AAD phase of § 4 bis, decodable (`decoder_chemin`). After S_A, the first entry of a leaf
carries domain 5. That of the root carries domain 0 or 4. They differ in the capacity, which the data never touch. Two
leaves differ in their first entry (index j). Within a leaf, domain 2 appears only on the last entry, and 0x01 padding
is injective. Within the root, domain 4 appears only on the last entry. ∎

*Mechanical check:* `v06_verif/chemins_paralleles.py`, on 492 configurations (B ∈ {80, 160, 200, 8 192}; lengths around
the block and leaf boundaries), checks points 1 to 5. Its witnesses fail as expected:
- without the leaf index, two identical full leaves have the same path;
- without the fork domain, a leaf path starts like a possible root path.

### 2.3 Classical security

**Theorem P (classical, ideal permutation).** Let F_E be the total number of leaves over the encryption queries
(F_E ≤ q_e + σ_E/105). Then

    Adv^AE ≤ (2(σ_D + F_E) + 5)·N/2^384 + 2·q_iv·N/2^512 + q_d/2^256 + σ_D/2^512 + (terms negligible as in § 4 bis).

*Proof.*
- *Step 1 (KD′ → IXIF′).* As in § 4 bis, B makes the calls of each query, replaying the trunk from Init. Identical calls
  (same path, same entry) are counted once (DMV17 p. 618).
  - The only new calls on an existing path are those that leave S_A: k + 1 calls per encryption, of which k are on a
    repeated path. They contribute F_E to L.
  - For a decryption, each of its calls is counted at most once in L + Ω.
  - Hence L + Ω ≤ σ_D + F_E. Theorem 1′ gives the first two terms.
- *Step 2 (G1 → G2, decryption returns ⊥).* Unchanged: nothing is released before the check.
- *Step 3 (bad event).* Take a forgery (N, A, C, T) that is not an encryption output, and P′ the final path of its root.
  - **(a) P′ is not the root path of an encryption.** By point 4 of Lemma 5′, P′ is neither a keystream path nor a CV
    path. So RO(P′) is uniform given the view: 2^−256.
  - **(b) P′ is the root path of an encryption** (N, A, C*, T*). By point 5, the CV list, k and ℓ are those of the
    encryption.
    - If C = C*, then T ≠ T* and the computed tag is T*: rejected.
    - Otherwise some chunk j differs. With the same keystream prefix, its plaintext differs at the first differing block,
      so its final leaf path differs from that of the encryption (point 2). It is also no other revealed or used path:
      the leaves of other queries have another trunk, those of the same query another index.
    - CV′_j is then uniform, and equals CV*_j, as (b) requires, with probability 2^−512. Over the decryption leaves:
      σ_D/2^512.
- Summing gives the bound. ∎

**Instantiation.** For q_e, σ_E ≤ 2^64, F_E ≤ 2^65, which adds at most 2^−190 at N = 2^128. The classical level is that of the
sequential AEAD.

### 2.4 Quantum security

- **Q1.** Theorem Q (§ 4 quinquies) handles any tree of nodes. S_A is a parent with k + 1 children, the case Lemma D
  treats explicitly. With σ = σ_E + σ_D counting all calls:
  Adv^AE ≤ Θ(σ, q_Q) + q_d/2^256 + σ_D/2^512. This is the same order as the sequential AEAD: about 127 bits in the
  cost/advantage sense for σ ≤ 2^64.
- **Q2d** (decryption in superposition, encryption classical): the corollary of § 4 sexies applies unchanged. It only
  uses the Q1 bound for one forgery.
- **Encryption in superposition: not covered**, even confined to the last block. The CVs feed the root, so a superposed
  last block puts several calls in superposition (§ 4 septies).

### 2.5 Implementation (14 November)

- `aeadp()` and `aeadp_ouvrir()` in `brume1024.c`. The kernel computes the leaves in parallel (OpenMP) into a buffer of
  CVs; without the buffer (allocation failure, or the dense reference) it goes leaf by leaf, with the same outputs.
- **3 new checks (33/33)**, also under ASan and UBSan:
  - the kernel against the dense reference at the leaf boundaries, with decryption;
  - 13 alterations rejected with the output wiped;
  - independent leaves, separation from the sequential AEAD, the fallback giving the same outputs, length limits.
- **5 KATs** (`aeadp_*`, 1 to 3 leaves); the 18 earlier ones are unchanged. `spec_ref.c`, written from § 2.1 alone,
  reproduces the 23 vectors, also with the portable kernel.
- **12 planted defects, all detected.**
  - The 7 that change the function are caught by the KATs: leaf index, fork domain, length, CV size, mode, root domain,
    text domain.
  - The 5 that change the behaviour are caught by the new checks: no wiping, tag compared on 16 bytes, CV misplaced in
    the parallel path, input misplaced in the fallback, plaintext absorbed in decryption.
- ASan found an overflow of one byte **in the test itself** (the "extended" case decrypted into a buffer one byte too
  short), fixed.

### 2.6 What remains

- Tests modelled on `tests/test_aead_parallele.py`: executed attacks on a reduced duplex (altered leaf, swapped leaves,
  short CV).
- dudect and ctgrind on `aeadp_ouvrir`.
- The integration in `sillage/` at the migration, with the speed measured (the bitsliced kernel on the leaves).
- A human review of Proposition TE and of Theorem P.
