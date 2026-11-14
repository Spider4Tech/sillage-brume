# BRUME-1024q — security of the AEAD (full-state keyed duplex, SpongeWrap orientation)

Written on 13 November 2026, revised the same day after the change of orientation (§ 6) decided by the author. The AE
step (§ 4 bis) and the partial flag (§ 4 ter) were added on the evening of 13 November. **Status: a reduction to DMV17
Theorem 1, written in full (§ 4 bis); Theorem 1 itself is taken from the paper, and its extension to the partial flag
is our reading of its proof (§ 4 ter).**

**Reference.** The paper read is Daemen, Mennink, Van Assche, *Full-State Keyed Duplex with Built-In Multi-user Support*,
ASIACRYPT 2017, LNCS 10625, pp. 606–637 (CWI copy of the Springer version). It is called **DMV17** below, and page numbers
are those of the proceedings.
- Everything attributed to DMV17 was read in the text.
- What is not in the paper is marked as such.

**Rule.** No fabricated proof. A bound that is not obtained stays **unknown**.

## 1. The mode, exactly (from `brume1024.c`)

**State and constants.**
- b = 1 024 bits, rate r = 640 (bytes 0..79), capacity c = 384 (bytes 80..127).
- Permutation P = BRUME-1024q with 32 rounds.
- Key k = 512 bits, nonce 192 bits, tag 256 bits.

**Initial state** (`etat_aead`):

| Bytes | Content | Part |
|---|---|---|
| 0..63 | key | rate |
| 64..79 | nonce, first 16 bytes | rate |
| 80..87 | nonce, last 8 bytes | **capacity** |
| 88..120 | zero | capacity |
| 121..127 | frame (rounds, rate, width, 'q', mode 3) | capacity |

**The nonce straddles the rate and the capacity.** This does not matter for DMV17, whose initial state is K ‖ iv with iv
the last b − k bits, whatever the split between rate and capacity. It is stated here so that nobody describes the nonce as
being "in the rate".

```
Enc(K, N, A, M):
  S ← P(K ‖ N ‖ 0^264 ‖ frame(3))                        # 1 call
  for each 80-byte block a_j of A ‖ 0x01 ‖ 0*:           # ≥ 1 block
      S.rate ⊕= a_j ; if last: S[127] ⊕= DOM_AAD·16 ; S ← P(S)
  for each full block m_i of M (80 bytes):
      Z ← S.rate ; c_i ← m_i ⊕ Z ; S.rate ← c_i ; S ← P(S)        # = S.rate ⊕= m_i : the rate holds the CIPHERTEXT
  last block m* (0 ≤ ℓ = |m*| < 80):
      Z ← S.rate ; c* ← m* ⊕ Z[0..ℓ) ; S.rate[0..ℓ) ← c* ; S.rate[ℓ] ⊕= 0x01 ; S[127] ⊕= DOM_TEXTE·16 ; S ← P(S)
  S.rate[0..8) ⊕= le64(|M|) ; S.rate[8] ⊕= 0x01 ; S[127] ⊕= DOM_FINAL·16 ; S ← P(S)
  T ← S.rate[0..32)
Dec (aead_ouvrir): same, the rate being overwritten by c_i; tags compared in constant time; on failure the output is wiped
  and −1 returned (no release of unverified plaintext, "no RUP").
```

**Cost.** 1 (init) + ⌈(|A| + 1)/80⌉ + ⌊|M|/80⌋ + 1 + 1 permutations, that is 4 for a short message.

**Two implementations, checked identical.**
- `aead()` is the one used, in its one-state, 32-state and 256-state versions.
- `aead_kd()` writes the mode as a sequence of calls to DMV17's Algorithm 1, transcribed literally (check
  `aead_identique_a_la_reference_dmv17_litterale_chiffrement_et_dechiffrement`, and the long campaign).

## 2. The DMV17 construction

**Algorithm 1** (p. 615), the keyed duplex KD, requires r < b and k ≤ b.

| Interface | Steps |
|---|---|
| `KD.Init(δ, iv, σ, flag)` | s ← f(K[δ] ‖ iv); Z ← ⌊s⌋_r; if flag then σ̄ ← σ̄ + Z; s ← s + σ; return Z |
| `KD.Duplexing(σ, flag)` | s ← f(s); Z ← ⌊s⌋_r; if flag then σ̄ ← σ̄ + Z; s ← s + σ; return Z |

Here σ ∈ Z₂ᵇ (full state), iv ∈ Z₂^{b−k}, and σ̄ is the outer (r-bit) part.

**Re-phasing** (p. 609, p. 614). Each call applies f, then gives the output, then injects the input. The user must
provide σ **before** receiving Z.

**The flag** overwrites the outer part with σ̄ (p. 614): "Switching between adding the plaintext block (for encryption)
and overwriting with the ciphertext block (for decryption) is the purpose of the flag".

**Resources** (§ 4.1, pp. 618–619):
- N: offline queries to f;
- M: unique construction queries;
- q: initialisations;
- q_iv: the iv multiplicity;
- **Ω: queries with flag = true**;
- **L: M minus the number of distinct paths**.

The paper says (p. 619): "In every query with flag equal to true, the adversary can force the outer part of the input to f
in a later query to a chosen value α".

**Theorem 1** (pp. 619–620), for f a random permutation, the ideal XIF built on a random oracle, and N + M ≤ 0.1·2^c:

    Δ ≤ (L+Ω)N/2^c + 2ν_{r,c}^{2(M−L)}(N+1)/2^c + C(L+Ω+1, 2)/2^c + (M−q−L)q/(2^b−q) + M(M−L−1)/2^b
        + (M−q−L)q/2^{H_min(D_K)+min{c,b−k}} + q_iv N/2^{H_min(D_K)} + C(u,2)/2^{H_coll(D_K)}.

**For the AE use** (p. 610): "in implementations of duplex-based authenticated encryption schemes that respect the nonce
requirement and do not release unverified plaintext, we have L = Ω = 0". The dominant terms are then
q_iv N/2^k + N/2^{c−1} (eq. (3), for r > 2 log₂ M + c).
- **This sentence is an assertion of the paper; its proof (the AE game reduced to KD) is not in this text.** The paper
  bounds KD against the ideal XIF.
- The model is an ideal permutation with **classical** queries. There is no quantum analysis.

## 3. Mapping, hypothesis by hypothesis

| DMV17 | BRUME-1024q | Satisfied? |
|---|---|---|
| r < b, k ≤ b | 640 < 1 024, 512 ≤ 1 024 | yes |
| Init: s ← f(K[δ] ‖ iv), key in the first k bits | K in bytes 0..63, iv = bytes 64..127 = N ‖ 0^264 ‖ frame | yes (§ 1: the nonce straddles the rate and the capacity, without effect here) |
| σ ∈ Z₂ᵇ (full state) | σ in the rate, plus the domain nibble in byte 127 (capacity) | yes: a special case of σ ∈ Z₂ᵇ |
| Re-phasing: f, then Z, then σ | each call: P, then the rate is read, then the input is injected | yes |
| AAD blocks | σ = padded block, flag = false | yes |
| **Text, encryption** | σ = m_i (plaintext), **flag = false**; the outer part becomes Z ⊕ m_i = c_i, not chosen by the adversary | yes |
| **Text, decryption** | σ = c_i, **flag = true** (overwrite). For the last partial block (ℓ < 80 bytes), the overwrite covers the ℓ first bytes only, and the rest of the rate keeps Z. | full blocks: yes. **Last partial block: a deviation** from Algorithm 1, whose flag overwrites the whole outer part. It is written that way in `aead_kd` (flag on nv = ℓ bytes). **Covered in § 4 ter**: it is a "partial flag" call, counted in Ω |
| Length block, tag | flag = false; the tag is the output Z of one more call | yes |
| Path of the ideal XIF (σ after the flag adjustment) | encryption: σ = m_i; decryption: σ̄ + Z = c_i ⊕ Z = m_i | the same path for Enc and Dec of the same (N, A, C), as required |
| k + c ≤ b − 1 | 512 + 384 = 896 ≤ 1 023 | yes |
| N + M ≤ 0.1·2^c | 2^c = 2^384 | yes for any realistic budget |
| r > 2 log₂ M + c (ν ≈ 1) | M < 2^128 | yes (Lemma 4: ν^M_{r,c} = 1 for M ≤ 2^{(r−c)/2} = 2^128) |

## 4. What can be stated, and what cannot

**(a) The keyed-duplex part: covered by DMV17 Theorem 1 (classical).**
- In the SpongeWrap orientation, encryption is flag = false. **Ω counts only the decryption blocks**, and L counts the
  replays of path prefixes, from decryption queries or nonce reuse.
- With uniform keys (H_min = H_coll = 512), the dominant terms are:

      (L + Ω)N/2^384 + 2(N+1)/2^384 + q_iv N/2^512 + C(u, 2)/2^512 + C(L+Ω+1, 2)/2^384.

- **If the assertion of p. 610 holds (L = Ω = 0 for nonce-respecting, no-RUP AE)**, what remains is
  q_iv N/2^512 + 2(N+1)/2^384: **about 383 bits classically against state recovery**, independent of the amount of data,
  for M < 2^128.
- **Before the change (plaintext overwriting the rate)**, encryption blocks counted in Ω, giving 384 − log₂(L + Ω) bits.
  This erosion has gone.
- **Not checked here:** the paper's proof (§§ 5–6).

**(b) The AE step (ideal XIF → privacy and authenticity): written in § 4 bis.** Its result differs from the assertion of
p. 610 on one point, stated plainly: **the reduction does not give L = Ω = 0.** A decryption query is simulated with
flag = true on its text blocks, and its prefix may repeat the path of an encryption, so the decryption blocks count in
L + Ω (at most σ_D − 2q_d, σ_D being the number of calls made by decryption queries). Encryption data no longer appear in the
leading term.

**(c) Multi-user.**
- The key-guessing term is q_iv N/2^512, with q_iv at most the number of users that reuse the same nonce.
- The key-collision term is C(u, 2)/2^512.

**(d) Quantum, model Q1. Not demonstrated** (DMV17 is classical). Heuristic costs:

| Attack | Cost | Status |
|---|---|---|
| Key search (Grover) | 2^256 | generic |
| State recovery (Grover on the inner part) | ≈ 2^192 | heuristic. The multi-target erosion in √Ω of the former orientation is gone, since the adversary no longer chooses the outer part during encryption |
| Tag guessing | q_d/2^256 | generic |

Q2 is **not claimed**.

**(e) Nonce reuse.** It is not covered: L > 0. **The exact leakage** (13 November, evening), for two encryptions under
the same key and nonce of (A, M) and (A', M'):
- the keystream of text block t depends only on the path before it: the iv, the AAD entries and the entries σ̃ of the text
  blocks 0 … t − 1 (the padded plaintext blocks; for the last one, the padding and the `DOM_TEXTE` nibble);
- so the keystreams of block t **coincide if and only if** A = A' (same AAD entries) and the entries of blocks 0 … t − 1
  coincide;
- consequence: c ⊕ c' = m ⊕ m' on every block **up to and including the first block whose entry differs**, and nothing
  after it. In particular, if M' is a prefix of M with ⌊|M'|/80⌋ = j, then C' is the prefix of C up to block j included;
- the tags are equal if and only if (A, M) = (A', M') (determinism).

Check `nonce_reutilise_fuite_exacte_flux_egal_ssi_chemin_egal_aux_frontieres`. It measures the real `aead()` and predicts
with the paths recorded by `aead_kd_chemin()`. The grid: AAD of 0, 79 and 80 bytes, crossed (equal or different); texts of
0, 1, 79, 80, 81, 159, 160, 161 and 200 bytes, crossed; M' a prefix or extension of M, or M with one byte changed at the
start, middle or end. Both directions are checked: an equality where predicted (1 269 blocks), and an inequality elsewhere
whenever at least 8 bytes overlap (false equality ≤ 2^−64). Planted defects (prediction one block too short or too long)
are caught.

**(f) Release of unverified plaintext (RUP).** The SpongeWrap orientation requires that nothing is released before the tag
check. Otherwise the decryption blocks, which are flag = true, let the adversary choose the outer part again.
- `aead_ouvrir` guarantees it: it decrypts, compares, and wipes on failure.
- `aead(…, dech = 1, …)` does not compare: it is internal and must not be exposed.

## 4 bis. The AE step, written

**Game.** Keys K[0..u−1] drawn uniformly (with or without replacement), f a random 1 024-bit permutation. The adversary A
has three oracles:
- Enc(δ, N, A, M): **nonce-respecting**, never the same (δ, N) twice;
- Dec(δ, N, A, C, T): never on a tuple returned by Enc;
- f and f⁻¹.

In the real world, Enc and Dec are the mode, with `aead_ouvrir` for decryption. In the ideal world, Enc returns
|M| + 256 uniform bits, Dec always returns ⊥, and f is the same.

    Adv^AE(A) = | Pr[A^{Enc_K, Dec_K, f} = 1] − Pr[A^{$, ⊥, f} = 1] |.

Resources of A:
- q_e and q_d queries;
- σ_E and σ_D calls of the keyed duplex made by these queries (a query makes ⌈(|A|+1)/80⌉ + ⌊|M|/80⌋ + 3 calls);
- σ_D^txt ≤ σ_D, the text calls of the decryptions;
- N primitive queries.

**Proposition (AE step).**

    Adv^AE(A) ≤ Δ_B(KD′_K, f ; IXIF′_RO, f) + q_d / 2^256,

where KD′ and IXIF′ are KD and IXIF with the partial flag of § 4 ter, and B has the same N and:
- M ≤ σ_E + σ_D;
- q ≤ q_e + q_d;
- q_iv ≤ the number of users using the same nonce, in Enc or Dec queries (≤ u; 1 with global nonces);
- Ω ≤ σ_D^txt;
- L ≤ q_d.

**Proof.**

*Step 0, the mode as calls.* A query is the sequence of calls of `aead_kd`:
- Init with σ = the first AAD block, then one Duplexing per further AAD block;
- one Duplexing per text block, whose Z is the keystream of that block;
- one Duplexing for the length block;
- one Duplexing with σ = 0, whose Z gives the tag (first 256 bits).

The checks `aead_identique_a_la_reference_dmv17_litterale_…` and the long campaigns check that `aead()` computes exactly
this. In decryption, the text calls carry the partial flag on ℓ bytes (ℓ = 80 for a full block, the length of the last
one otherwise). Their path entry is σ̃ = c ⊕ Z on ℓ bytes, plus the padding = **the padded plaintext block, as in
encryption**. Check `etape_ae_chemin_du_dechiffrement_egal_au_chiffrement_decodable_et_roles`: equal recorded paths on the
8 × 8 grid of AAD and text lengths around 0, 80 and 160.

*Step 1, from KD′ to IXIF′.* B runs A and forwards its primitive queries.
- For Enc, B makes the calls of step 0 with flag = false and returns (C, T).
- For Dec, B makes them with the partial flag on the text calls. It computes m_t = c_t ⊕ Z_t, then compares the tag of
  the last call with T, and returns M or ⊥.

Each AE query is processed in full before the next one, so B's transcript is a valid transcript of the keyed duplex. With
KD′_K, B simulates the real game exactly. With IXIF′_RO, it simulates the game AE[IXIF′], called G1.

Resources:
- Two calls of the same encryption query have paths of different lengths.
- Two calls of different encryption queries have different initial tuples (Encode(δ), iv), since iv = N ‖ 0^264 ‖ frame is
  injective in N and (δ, N) is never repeated.
- So the σ_E encryption calls have pairwise distinct paths.
- **L ≤ q_d.** Identical calls (same path, same σ̃) are counted once (DMV17 p. 618). A decryption that shares a prefix
  with an earlier query makes identical calls up to the first call where it diverges, and only that call has a repeated
  path. So each query contributes at most one repeated path. An encryption contributes only if its nonce was used before by
  a decryption, and nonces are unique in encryption, so it can be charged to that decryption. Hence L ≤ q_d. This is the
  argument of Mennink 2023 (proof of Theorem 7, ToSC 2023(2), p. 34). The first version of this section had the weaker
  L ≤ σ_D.
- The flagged calls are the text calls of the decryptions: Ω ≤ σ_D^txt. Every query makes at least 3 calls that are not text
  calls (first AAD block, length, tag), so L + Ω ≤ q_d + σ_D − 3q_d = σ_D − 2q_d.

*Step 2, from G1 to the ideal world.* G2 is G1 with Dec always returning ⊥ (it still evaluates RO). Let "bad" be the event
that a Dec query computes a tag equal to its T. G1 and G2 are identical until bad, **because `aead_ouvrir` releases nothing
when the tag is wrong (no RUP)**.

In G2, the view of A is the Enc outputs, the ⊥ answers and f, and f is independent of RO. An Enc output reveals:
- RO(P_t), truncated to the length of block t, for each keystream path P_t;
- the tag RO(P_fin), truncated to 256 bits.

These paths are pairwise distinct across all Enc queries (step 1). A value of RO sampled by a Dec query is never revealed in
G2. Hence the Enc outputs are uniform and independent, and **G2 is the ideal world**: Adv^AE(A) ≤ Δ_B + Pr_G2[bad].

*Step 3, Pr[bad] ≤ q_d/2^256.* Take a Dec query (δ, N, A, C, T), and let P′_fin be its final path (iv, AAD entries, text
entries, length entry).
- **(a) P′_fin is not the final path of an Enc query.** P′_fin ends with an entry whose role nibble is `DOM_FINAL`. Every
  keystream path ends with an entry of nibble `DOM_AAD` (the first text block) or 0 (a full text block). So P′_fin is not
  a revealed path, and RO(P′_fin) is uniform and independent of the view of A in G2, of which T is a function. Hence
  Pr[T = tag] = 2^−256.
- **(b) P′_fin is the final path of an Enc query** (δ, N, A₀, M₀) → (C₀, T₀). The path decodes uniquely (decoder
  `decoder_chemin`, a left inverse of the encoding (A, M) ↦ path). So A = A₀ and the decrypted text is M₀. Its keystream
  paths are the prefixes of the same path, so the keystream is the same and C = C₀. The query is then (δ, N, A₀, C₀, T)
  with T ≠ T₀, since it was not returned by Enc. The computed tag is T₀, and the query is rejected: never bad.

A union bound over the q_d queries gives q_d/2^256. ∎

**The checked facts the proof uses.**

| Fact | Check |
|---|---|
| The path of a decryption equals that of the encryption, partial last block included | `etape_ae_chemin_du_…` (8 × 8 grid) |
| The final path decodes into (A, M), so the encoding is injective | same check: `decoder_chemin` on the grid, plus 4 altered paths (domain, padding, capacity, length) that must not decode into (A, M); planted defect (decoder accepting any nibble) caught |
| Roles: keystream after an entry of nibble `DOM_AAD` or 0, tag after `DOM_FINAL`, σ = 0 for the tag call, ⌈(\|A\|+1)/80⌉ + ⌊\|M\|/80⌋ + 3 calls | same check |
| `aead()` = the sequence of calls | `aead_identique_a_la_reference_dmv17_litterale_…`, campaigns (739 million cases) |
| No release on failure | `aead_ouvrir_verifie_rejette_les_alterations_et_n_en_rend_rien` (383 alterations) |

**Numerical bound.** We use Theorem 1′ (§ 4 quater: the paper's Theorem 1 with the repairs of F2 and F3 and the direct
multicollision bound F4) plus the proposition, with L + Ω ≤ σ_D − 2q_d ≤ σ_D, σ = σ_E + σ_D ≤ 2^127, and
q = q_e + q_d:

    Adv^AE ≤ (2σ_D + 5)·N/2^384 + 3·C(σ_D+1, 2)/2^384 + 2·q_iv·N/2^512 + q_d/2^256
             + 5σ²/2^640 + 2σq/2^895 + 3σ²/2^1024          (+ 2·C(u,2)/2^512 with replacement).

The version written first used the paper's simplified form: 2σ_D·N/2^384 + 2(N+1)/2^384 + …. Theorem 1′ costs one bit
more.

How to read it, classically, in the ideal-permutation model:
- **Encryption data do not erode security.** σ_E appears only in negligible terms, as long as σ ≤ 2^127.
- **The leading term is in the decryption calls**: σ_D·N ≈ 2^383 is needed. For example, with σ_D ≤ 2^64 and
  N ≤ 2^256, the term is at most 2^−63.
- **Independent confirmation.** Mennink, *Understanding the Duplex and Its Security* (ToSC 2023(2)), Theorem 7
  (MonkeySpongeWrap), reduces the AE game to the keyed duplex in the same three steps:
  1. KD → IXIF;
  2. IXIF → ⊥ for decryption, costing q_d/2^t thanks to the domain separators;
  3. IXIF → random.

  It counts L ≤ q_d and Ω ≤ σ_d − 2q_d, and obtains the leading term σ_d·N/2^c. Ours is (2σ_D + 5)·N/2^c. The factor 2 comes
  from repair F3 (§ 4 quater): Mennink uses the paper's Theorem 1 as stated.
- Key search: q_iv·N/2^512. Tag guessing: q_d/2^256.

**What the proposition does NOT give.**
- **The regime L = Ω = 0 of p. 610**, that is, removing σ_D from the leading term. It would need an analysis of the AE game
  itself, not a black-box use of Theorem 1, and that analysis is not written. Whether the term is tight is not studied
  either.
- **~~Why σ_D·N is probably not tight~~: withdrawn (14 November).** A heuristic written on 13 November said that, without
  RUP, decryption queries could only test guesses one at a time, so that the generic attack would cost about q_d/2^c with
  no factor N. **This is wrong.** Gilbert, Heim Boissier, Khati and Rotella, *Generic Attack on Duplex-Based AEAD Modes
  Using Random Function Statistics* (EUROCRYPT 2023), give a generic attack using many decryption queries, of total time
  2^{3c/4}, with N ≈ σ_d ≈ 2^{3c/4}. We know it as cited by Mennink 2023, § 9.3; the paper itself is not read. Mennink notes
  that the attack does not contradict the duplex bound.
  - So decryption queries do help an offline attacker.
  - The σ_D·N term cannot be dropped in general, and the regime L = Ω = 0 is out of reach for this kind of mode: Mennink
    calls the claim "L = Ω = 0" incorrect (§ 9.3), about the Xoodyak designers, who quoted it from DMV17 p. 610.
  - A gap remains between that attack (N·σ_d ≈ 2^{1.5c}) and the bound (N·σ_d ≈ 2^c).
  - For c = 384, the attack costs about 2^288.
- **Gilbert et al. 2023 and BRUME-1024q** (paper read on 14 November).
  - **The attack needs two conditions, and our mode meets both.**
    - In decryption, the ciphertext overwrites the outer part. That is the SpongeWrap orientation, decided on 13
      November.
    - The tag is determined by the state before the final phase. Ours is a public length block, then P, with no key.

    The modes that frustrate the attack add the key in the final phase (Ascon, NORX v3) or use a feedback function
    (Beetle).
  - **The mechanism.** A ciphertext made of one block β repeated ℓ times makes the inner state iterate x ↦ ⌈P(β ‖ x)⌉_c.
    Offline, the adversary finds a β whose functional graph has a large component with a short cycle. It then submits
    5 decryptions of length ℓ = 3·2^{c/2} blocks and runs through the cycle.
  - **The cost.** 21·2^{3c/4} calls to P, that is 2^292.4 for c = 384. A forgery then gives **the key** (§ 3.7): the
    returned plaintext lets one go back to the state after initialisation, and our P_init = P(K ‖ N ‖ 0 ‖ frame) can be
    inverted for a known N.
  - **Length.** The published attack needs ciphertexts of ℓ = 3·2^{c/2} ≈ 2^193.6 blocks. BRUME-1024q encodes |M| on
    8 bytes (le64), so |M| < 2^64 bytes, about 2^57.7 blocks. **The published version therefore does not apply as is.**
    Variants for bounded lengths have not been studied.
    - `SPEC.md` does not state the maximum length explicitly. **Proposed, an author decision:** write |A|, |M| < 2^64
      bytes in `SPEC.md`, and have the implementation reject longer inputs.
  - **This is consistent with the bound.** The attack has σ_d·N ≈ 2^488 ≫ 2^383. Even without the length limit it would
    stay above 2^256, while our key has 512 bits.
- The variant suggested on p. 614 (encrypt as C = P + M·Z with M + I invertible) would make Ω = 0. It would not remove L,
  because a decryption that keeps the prefix of an encryption repeats its paths. So it **would not remove σ_D from this
  bound**: it changes the format for no gain here, and is not proposed.
- **Q1** (§ 4 (d)).
- **BRUME-1024q as an ideal permutation** (cryptanalysis, `ROADMAP.md` § 3).

## 4 ter. Theorem 1 with a partial flag (our reading of the proof)

KD′ replaces "if flag then σ̄ ← σ̄ + Z" with "σ ← σ + (D_ℓ(Z) ‖ 0^c)". D_ℓ keeps the first ℓ bytes of Z and sets the rest
to zero, with ℓ ∈ {0, …, 80} chosen by the caller: ℓ = 0 is flag = false, and ℓ = 80 is flag = true. IXIF′ appends the same
σ̃ = σ + D_ℓ(Z) to its path. **Claim: Theorem 1 holds for (KD′, IXIF′), with Ω = the number of calls with ℓ > 0.** This is
not a statement of the paper. Here is the check, place by place: Ω and the flag appear in the proof only at the places
listed below (search of the text).
- **Transcripts** (§ 4.1, p. 618): tuples (Path, Z, σ̃). They are defined from σ̃, whatever rule produces it.
- **Lemma 2** (§ 5, pp. 621–622). The ratio for good transcripts only counts the inputs and outputs of φ and π, and does
  not depend on the flag. A t-collision does not involve σ. An s-collision (s = t + σ̃) is bounded as follows:
  - for pairs where the adversary may choose the outer part of s (at most C(L+Ω+1, 2) pairs), by 2^−c, because the inner
    parts of distinct paths are independent and uniform;
  - for the other pairs, by 2^−b, using that σ̄ is fixed before the uniform Z.

  A call with 0 < ℓ < 80 is counted in Ω. The bound 2^−c holds for it whatever its outer part, and it is excluded from the
  pairs bounded by 2^−b.
- **Lemma 3** (§ 6):
  - The identity KD = RD^{I,E} (§ 6.2, p. 624) holds for any rule computing σ̃ from (σ, Z), as long as both sides apply
    it.
  - Ω appears only in § 6.4 (pp. 628–629): the threshold T_fw = L + Ω + ν, where "the L + Ω queries are manipulated to hit
    the same outer value" (worst case). A partial-flag call is at worst such a query. The other queries are those whose
    outer part Z + σ̄ the adversary does not control, and their multicollision count is unchanged.
  - § 6.3 (the permutation setup) does not involve the flag.

**Limits.**
- This section checks only the places where the flag enters. The rest of the proof is checked in § 4 quater, which finds
  two steps to correct (F2, F3) and replaces §§ 6.5–6.6 for our parameters (F4).
- Counting partial-flag calls in Ω is conservative: such a call controls only ℓ bytes of the outer part.

## 4 quater. The proof of Theorem 1, checked step by step for our parameters

Done on the evening of 13 November 2026, on the text of DMV17 (pp. 617–634), then **re-checked point by point the same
night**. The re-check withdrew one finding (F1), confirmed F2 and F3 by simulation on reduced models, and found a gap in our
own repair, now closed. **Status: our check, not a peer review.**

The parameters are:
- b = 1 024, r = 640, c = 384, k = 512 (k + c = 896 ≤ b − 1);
- keys uniform, independent (H_min = H_coll = 512) or without replacement;
- M − L ≤ 2^127 and M + N ≤ 0.1·2^c.

### Step by step

| Step (DMV17) | What it claims | Verdict |
|---|---|---|
| (9)–(10), p. 620: triangle inequality through RD; f does not help against (RD, IXIF) | RD calls secret φ, π independent of f; IXIF calls RO independent of f | correct |
| Lemma 2 (§ 5): good-transcript ratio | real: q pairs of φ, M − q − L of π; ideal: 2^{−(M−L)b}; the ratio is ≥ 1 because M − L = q + (M − q − L) distinct paths | correct |
| Lemma 2: t-collisions | C(M−L, 2)/2^b, since distinct paths have independent RO‖RO′ values | correct |
| Lemma 2: s-collisions, "S ≤ C(L+Ω+1, 2)" | the pairs where the adversary forces the outer part are bounded by 2^−c, all others by 2^−b | **(F2) the written bound on the bad event is false in general; exceeded by 20σ in simulation.** Correct when the outer parts of the uncontrolled queries are pairwise distinct (below) |
| § 6.1, (16): split on μ_fw ≤ T_fw | hybrid argument, then max(Pr_O, Pr_P)(μ_fw > T_fw) | correct as an inequality; **(F3) the claimed bound on Pr_O is false: exceeded by a factor 28 in simulation**, within the theorem's resources (below) |
| § 6.2, (17)–(19): KD = RD^{I,E} with the inner masking key κ | checked: the invariant s_KD = s_RD + (0^r ‖ κ) holds after Init, after each injection, and through E; the outer parts are equal. It holds for any rule computing σ̃ from (σ, Z), so for the partial flag | correct |
| § 6.3: transcripts, the list of bad events (20)–(27) | all input and output collisions between f, I and E (f–f, I–I outputs, E–E are excluded by attainability; I–I inputs = (23)) | complete: the 3 × 3 pairs, inputs and outputs, are all covered |
| § 6.3: good-transcript ratio | real: q′ + M′ + N distinct pairs of f; ideal: separate φ, π, f; K and κ have the same law in both worlds | correct |
| (20) q_iv·N/2^{H_min} | for each f query, at most q_iv init tuples with the same iv | correct |
| (21) T_fw·N/2^c and (24)/(25) T_bw·N/2^c | per f query, at most T_fw (resp. T_bw) tuples with the same outer part; κ uniform | correct |
| (22) M′q′/2^{H_min + min(c, b−k)} | k + c ≤ b: K and κ occupy disjoint bits, 2^{−(H_min + c)} per pair | correct (our case k + c ≤ b) |
| (23) C(u, 2)/2^{H_coll} | key collisions | correct |
| (26) M′q′/(2^b − q′) | "φ is queried at most q′ times" | correct (first reading wrong, F1 withdrawn below): for each pair the unconditional probability is ≤ 1/(2^b − q′), and even exactly 2^−b when the π output comes later |
| § 6.4: q′ ≤ q, M′ ≤ M − q − L | distinct E queries ↔ distinct paths of duplexing calls; the q init paths are distinct | correct |
| § 6.4: T_bw = ν^{2(M−L)}, T_fw = L + Ω + ν^{2(M−L)} | balls whose bin probability is ≤ 2·2^−r; Lemma 6 | in P: correct. In O: see (F3). For our parameters: replaced by a direct birthday bound (F4) |
| §§ 6.5–6.6 (Lemmas 4–6) | bounds on ν | **not needed for our parameters** (F4) |

### The findings, after the re-check

**(F1) Term (26): withdrawn.** The first reading bounded each pair by its worst conditional probability and concluded that
1/(2^b − q′) only covers one order of sampling. That was wrong.
- Take a φ output t and a later π output t′. The π outputs on distinct inputs form a draw without replacement, independent
  of φ and of how the inputs are chosen.
- Hence Pr[t′ = t] = (1 − (j−1)/2^b)·1/(2^b − j + 1) = 2^−b, where j is the rank of t′ among the π outputs.
- In the other order, the bound 1/(2^b − q′) of the text holds directly.

So the paper's term M′q′/(2^b − q′) is correct. Its justification is terse, but it is right.

**(F2) The count S of Lemma 2: confirmed.** Call a query **controlled** if it has a repeated path or a flag (L + Ω of
them), and **uncontrolled** otherwise.
- **What the text does.** It bounds by 2^−b every pair made of a controlled and an uncontrolled query.
- **Why that is wrong.** The adversary sees the outer part s̄ = Z + σ̄ of each earlier query. A flagged query can set its own
  outer part to the most frequent value among the uncontrolled ones. It then collides with each of them with probability
  2^−c, because distinct paths have independent inner parts that are never revealed.
- **The correct count.** Each controlled query contributes (number of earlier controlled queries + μ_u)·2^−c, where μ_u is
  the largest number of uncontrolled queries sharing an outer part.
  - If μ_u ≤ 1, the sum is the paper's C(L+Ω+1, 2)/2^c.
  - Otherwise up to (L+Ω)(μ_u − 1 − M_u/2^r)/2^c is missing beyond the paper's 2^−b allowance.
- **Simulation** (`dmv17_verif/f2_lemme2.c`, ideal world of Lemma 2: r = 4, c = 16, 16 uncontrolled queries, 8 flagged,
  2·10^7 trials):

  | Adversary | Pr[s-collision] | Bound written p. 622 | Gap |
  |---|---|---|---|
  | outer part = the most loaded value | 9.13·10^−4 ± 0.07·10^−4 | 7.78·10^−4 | **+20σ** |
  | witness: outer part drawn at random | 6.67·10^−4 | 7.78·10^−4 | −19σ |

  The excess comes exactly from the adaptive choice of α.
- **What this shows.** The bound the proof puts on the bad event is false. It does not show that the statement of Lemma 2
  is false: the bad event is only a sufficient condition for the gap between the worlds.
- **Repair.** Pr[μ_u ≥ 2] ≤ C(M−L, 2)/2^r, since each uncontrolled outer part is uniform and fixed before Z. Conditioned on
  μ_u ≤ 1, the paper's count holds. Hence **Lemma 2′:** Δ(RD; IXIF) ≤ C(L+Ω+1, 2)/2^c + M(M−L−1)/2^b + C(M−L, 2)/2^r.
- For the general theorem it matters only when M approaches 2^r, which is possible for r < c. For us it is negligible.

**(F3) Pr_O(μ_fw > T_fw), § 6.1 and § 6.4: confirmed.** The paper says the bound ν/2^c on Pr(μ_fw > T_fw) "applies to both
O and P". The reason given is that every state is drawn from at least 2^b − M − N values (p. 628).
- **In O = (KD, f), this is false.** The adversary can recover a construction state by queries to f, then predict each next
  Z and choose σ̄ = Z ⊕ α. It does so without any flag or repeated path (L = Ω = 0), so these queries are not counted in T_fw.
- **Simulation** (`dmv17_verif/f3_lemme3.c`, real world: b = 16, r = 4, c = 12, k = 4, f a random permutation, 2·10^4
  trials). The resources are q = 1, L = Ω = 0, M = 11 and N ≤ 398, so N + M ≤ 0.1·2^c as the theorem requires. ν^{22}_{4,12}
  = 7 is computed exactly by `nu_exact.py`, so T_fw = 7.

  | Adversary | Pr_O(μ_fw > 7) | Claimed bound ν/2^c |
  |---|---|---|
  | state recovery, then forced outer parts | **0.048 ± 0.0015** | 0.0017, so **28 times smaller** |
  | witness: same queries, no attack | 0 | 0.0017 |

- **What this shows.** The proof step is wrong. Theorem 1 itself is not contradicted: its term T_fw·N/2^c ≈ 0.68 covers this
  attack.
- **The same gap in P** (found during the re-check, not simulated). In RD, a query with a fresh path but whose state
  repeats an earlier state, after an s-collision, has a Z that is not fresh either. The claim "drawn from at least
  2^b − M − N values" therefore needs the event "no s-collision in RD". Its probability is at most 2·(bound of Lemma 2′):
  Lemma 2's H-coefficient argument bounds the statistical distance of the transcripts, with t disclosed, by
  Pr_IXIF[bad].
- **Repair**, which closes both gaps:
  - Let C′ run B, stop as soon as μ_fw exceeds T_fw, and output 1. C′ never exceeds T_fw + 1, so
    Pr_O(μ_fw > T_fw) ≤ Pr_P(μ_fw > T_fw) + Δ_{C′}, and Δ_{C′} is bounded by (28) with T_fw + 1.
  - Pr_P(μ_fw > T_fw) ≤ Pr_RD[s-collision] + Pr[uncontrolled multicollision].

**(F4) Multicollisions without §§ 6.5–6.6.** Take T_bw = 1 and T_fw = L + Ω + 1. In the permutation setup, every output of φ
or π falls in a given bin with probability ≤ 2^c/(2^b − M) ≤ 2^{1−r}, conditionally on the past. A union bound over pairs
gives:
- Pr_P(μ_bw > 1) ≤ C(M−L, 2)·2^{1−r} ≤ (M−L)²/2^r;
- Pr_P(μ_fw > L + Ω + 1) ≤ 2·(Lemma 2′) + (M−L)²/2^r. The first term covers the s-collisions of F3; the second covers two
  fresh uncontrolled outer parts that coincide.

For M − L ≤ 2^127, the multicollision terms are ≤ 2^−386. Nothing from Lemmas 4–6 is used.

### Second pass on F2 and F3 (13 November, night)

**F2, exact computation** (`dmv17_verif/f2_exact.py`, rational arithmetic, no sampling). The probability is summed over the
partitions of the uncontrolled outer loads. Results for r = 4, c = 16:

| Mu, Om | Exact, adversary | Exact, witness (random α) | Bound p. 622 | Ratio adversary / bound |
|---|---|---|---|---|
| 16, 8 | 9.171·10^−4 | 6.636·10^−4 | 7.782·10^−4 | **1.178** |
| 16, 1 | 1.614·10^−4 | 1.297·10^−4 | 1.440·10^−4 | **1.121** |
| 32, 4 | 8.591·10^−4 | 6.864·10^−4 | 7.439·10^−4 | **1.155** |
| 8, 8 | 7.056·10^−4 | 5.149·10^−4 | 6.294·10^−4 | **1.121** |
| 4, 8 | 5.974·10^−4 | 4.634·10^−4 | 5.779·10^−4 | **1.034** |
| 24, 16 | 3.063·10^−3 | 2.458·10^−3 | 2.689·10^−3 | **1.139** |

- The bound is exceeded in every adversarial case, and the witness is always below it.
- The C simulations agree with the exact values to within 1σ.
- The union prediction C(Ω,2)/2^c + Ω·E[load of α]/2^c + C(Mu,2)/2^b matches the exact value to 0.1 %. For Mu = 16,
  E[load of α] = 3.08, whereas the paper's count allows the equivalent of 1 + Mu/2^r = 2. The mechanism is therefore the one
  described.

**F2, tighter repair (Lemma 2″).** In a bin, μ − 1 ≤ C(μ, 2) ≤ the number of uncontrolled pairs with equal outer parts, so
E[μ_u] ≤ 1 + C(M_u, 2)/2^r. Hence:

    Pr[s-collision] ≤ C(L+Ω+1, 2)/2^c + (L+Ω)·C(M−L, 2)/2^b + C(M, 2)/2^b.

This is checked exact ≤ bound on 8 configurations, including the extremes (2, 30) and (40, 2): `f2_reparation_20261113.txt`.
For our parameters Lemma 2′ and Lemma 2″ differ only by negligible terms.

**F2, the statement of Lemma 2.** It is not shown false. To detect a collision, a distinguisher needs further calls on both
sessions, and those calls enlarge the M(M−L−1)/2^b term of the statement. We did not find a configuration in which the
advantage provably exceeds it. **Open.**

**F3, independent reimplementation and prediction** (`dmv17_verif/f3_independant.py`: Python, numpy PCG64, other seeds).
The prediction is the probability of finding the true state before a false candidate, which passes both checks with
probability 2^−2r and stops the search: Σ_{i ≤ G} 2^−c(1 − 2^−2r)^{i−1}, with G guesses.

| c | ν (exact) | N ≤ | Measured Pr_O(μ_fw > ν) | Prediction | Claimed ν/2^c | Ratio |
|---|---|---|---|---|---|---|
| 10 | 6 | 92 | 0.0663 ± 0.0018 | 0.0658 | 0.0059 | 11 |
| 12 | 7 | 398 | 0.0470 ± 0.0015 (C: 0.0481 ± 0.0015) | 0.0475 | 0.0017 | 28 |
| 14 | 8 | 1 626 | 0.0174 ± 0.0019 | 0.0156 | 0.00049 | 36 |

- The two implementations and the prediction agree.
- The ratio grows with c. The attack's success depends on N, while the claimed bound ν/2^c does not.
- The theorem's own terms (T_fw·N/2^c, 2ν(N+1)/2^c) cover the attack, so Theorem 1 is not contradicted.

**Literature read on 14 November: Mennink, *Understanding the Duplex and Its Security*, ToSC 2023(2), pp. 1–46 (ePrint
2022/1340, PDF provided by the author of this project).**
- **The "certain issue" it mentions** (§ 8.3, p. 26) concerns **the same sentence as F2**: "Note that S ≤ C(L+Ω+1, 2)". Its
  remark goes **the other way**. The count is *lossy* (too pessimistic) for modes such as Ascon-PRF, where the
  adversary never learns the outer parts it could force. Mennink then drops the term, together with the L + Ω of T_fw.
  It does not say that the count can be too optimistic, as F2 shows.
- **Dobraunig–Mennink 2019** (ASIACRYPT 2019; restated as Mennink's Theorem 2, a different proof) has the term
  ν^M_{r,c}·(L+Ω)/2^c: the controlled queries multiplied by the multicollision of the other outer parts. **That is exactly
  the term F2 finds missing from DMV17's Lemma 2.** So F2 agrees with an independent bound. Mennink also corrects a typo in
  it (footnote 1, p. 14: a missing max). DM19 itself is not read.
- **Mennink's Theorem 1** restates DMV17's bound unchanged. Remark 4 discusses the draws without replacement of the
  multicollision function, but not the real-world issue of F3. **F3 is not mentioned.**
- **His Theorem 7** is our AE step (§ 4 bis), with a tighter L that we now use.

**Full version of DMV17 read on 14 November** (ePrint 2017/498, 32 pages, PDF dated 1 September 2017, provided by the
author of this project):
- **F2:** the passage on S (§ 5) is word for word the one of the proceedings.
- **F3:** the passages are also word for word those of the proceedings:
  - § 6.1: "the bound we will derive on Pr(μ_fw > T_fw) in fact applies to both O and P";
  - § 6.4: "the states are generated from a set of size at least 2^b − M − N (for both O and P)", and
    T_fw = L + Ω + ν^{2(M−L)}_{r,c}.
- **The statement of Theorem 1** is the same, up to layout.

So **the full version does not treat F2 or F3**.

**Dobraunig–Mennink 2019 read on 14 November** (*Leakage Resilience of the Duplex Construction*, ASIACRYPT 2019,
ePrint 2019/225, PDF provided by the author of this project). It is an independent proof (§ 5.4): an RP-to-RF switch,
then bad events col_cc, col_cp, mc_in, mc_out and key, all analysed directly in the real world.
- **F2 is handled correctly there.** When a "fix" query (flag, or sibling of an earlier call) chooses its outer part, the
  proof counts "at most ν … queries of type full whose outer part equals left_r(T_l)" and at most ν_fix − 1 fixed ones
  (proof of Lemma 2, p. 20). This gives the term ν^M_{r,c}(L+Ω)/2^c, exactly what DMV17's count misses. **F2 is therefore
  a flaw of the DMV17 proof that the later DM19 proof does not have.** Neither DM19 nor Mennink 2023 points it out as a
  flaw of DMV17.
- **F3, the same writing, without consequence.** DM19 (18c) bounds Pr(mc) ≤ 2ν/2^c with no condition: "the state values T_i
  are randomly generated using a random function f". In the real world this is false after a state recovery, as in F3.
  - Our simulation `f3_lemme3.c` also triggers mc_in: all its 10 duplexing calls are of type full, ν^{11}_{4,12} = 5 is
    computed by `nu_exact.py`, and Pr ≥ 0.048 against 2ν/2^c = 0.0024.
  - **But in DM19 the repair is free.** It is enough to bound mc only while no col has occurred, using the first time τ_col
    or τ_mc. Then Pr(col) ≤ Σ_l Pr(col(l) ∧ ¬col(<l) ∧ ¬mc(≤l)) + Pr(mc before any col). Before any col, the "full" states
    are fresh outputs of the random function f, so the balls-and-bins argument holds and gives 2ν/2^c. The other sums
    keep their values.
  - **So DM19's Theorem 1 holds as stated.** In DMV17, by contrast, the gap sits between two worlds through hybrid (16),
    and the repair costs a factor 2.
- **Cross-check for our AEAD.** Mennink's Theorem 7(ii) (MonkeySpongeWrap, based on DM19) has the leading terms
  2ν^σ_{r,c}(N + σ_d + q_e)/2^c + (σ_d·N + C(σ_d, 2))/2^c. For our parameters ν^σ_{640,384} = 1 as long as σ ≤ 2^128. This
  agrees, one bit tighter, with our (2σ_D + 5)·N/2^384.
  - DM19's proof uses the flag only to classify a call as "fix": the adversary may have set the outer part, and
    right_c(T_i) keeps its entropy. So it also covers the partial flag of § 4 ter.
  - Our mode differs from MonkeySpongeWrap: AAD and length blocks, frame, partial last block. So this is a cross-check,
    not a substitute for § 4 bis. Theorem 1′ remains the bound we use.

**Gilbert, Heim Boissier, Khati, Rotella 2023 read on 14 November** (EUROCRYPT 2023, ePrint 2023/262). See § 4 bis, "What
the proposition does NOT give", for its consequences for our mode.

**Conclusion of the literature check.**
- **F2:** a real flaw of the DMV17 proof (bound on the bad event exceeded, exact computation). The later DM19 proof does
  not have it. Neither DMV17 (both versions) nor Mennink 2023 points it out.
- **F3:** a real flaw of the DMV17 proof (×28 in simulation). The same unconditional writing appears in DM19 (18c), but
  there the repair is free. Not pointed out in the four texts read.
- **Theorem 1 of DMV17** is not shown false. A correct bound of the same kind exists independently: DM19, as restated by
  Mennink 2023, Theorem 2.
- **Novelty** of F2 and F3 is established only with respect to these four texts.
- Telling the authors is an author decision. A human review should come first.

**Literature (first note, 13 November).** Mennink, *Understanding the Duplex and Its
Security*, ToSC 2023(2), pp. 1–46 (ePrint 2022/1340), reportedly says there is "a certain issue in the proof of Daemen et
al.". We have not read it:
- the journal site and ePrint both refuse automated fetches, and they are not circumvented;
- the full version of DMV17 (ePrint 2017/498) has not been read either.

F2 and F3 may already be known, or corrected there. **Until these are read, F2 and F3 are "found by us, not known to be
new".**

### Theorem 1′ (what we use)

For KD′ (partial flag allowed) against IXIF′, under the parameters above, with Λ = C(L+Ω+1, 2)/2^c + M(M−L−1)/2^b +
C(M−L, 2)/2^r (Lemma 2′):

    Δ ≤ 3·Λ + (2(L+Ω) + 5)·N/2^c + 3(M−L)²/2^r
          + 2·[ (M−q−L)q/(2^b − q) + (M−q−L)q/2^{k+c} + q_iv·N/2^k + C(u, 2)/2^{H_coll} ]

How it is obtained:
- Λ comes once from Lemma 2′ and twice from Pr_RD[s-collision].
- (28) is applied twice, with T_fw = L + Ω + 1 and L + Ω + 2, and T_bw = 1.
- (M−L)²/2^r is counted three times: twice from μ_bw and once from μ_fw.

Compared with the paper's simplified form, the leading term goes from (L+Ω)N/2^c + 2(N+1)/2^c to (2(L+Ω) + 5)·N/2^c: **one
bit**. C(L+Ω+1, 2)/2^c is now counted three times; this is negligible for us.

**Limits.**
- This is our check, not a peer review.
- The H-coefficient lemma (Lemma 1, Chen–Steinberger) is taken as known.
- F2 and F3 are shown on reduced models. They show that two steps of the proof are false as written. They do not show that
  Theorem 1 is false.

## 5. Verdict

**The AE security is reduced to DMV17 Theorem 1, classically, in the ideal-permutation model** (§ 4 bis), and that theorem
was checked for our parameters (§ 4 quater, Theorem 1′). The bound is (2σ_D + 5)·N/2^384 + 2·q_iv·N/2^512 + q_d/2^256 +
negligible terms, and encryption data do not erode it.
1. **What is ours and written in full:** the AE step (§ 4 bis), with the facts it uses checked by code (24 checks, planted
   defects caught).
2. **What is taken from the paper:** the proof of Theorem 1. We checked it step by step for our parameters (§ 4 quater).
   Two steps of the text are false as written, and each is shown false by a simulation on a reduced model: the count S of
   Lemma 2 (F2) and the bound on Pr_O(μ_fw > T_fw) (F3). A third suspicion, about term (26), was withdrawn on re-check. Both
   steps are repaired at the cost of constant factors, and §§ 6.5–6.6 are replaced by a birthday bound. We use the
   resulting Theorem 1′, together with the partial flag (§ 4 ter). This is our check, not a peer review.
3. **Not obtained:** the regime L = Ω = 0 asserted p. 610. Our leading term keeps the decryption calls (σ_D).
4. **Quantum (Q1):** heuristic only.
5. **BRUME-1024q as an ideal permutation** rests on the cryptanalysis, which is not finished.

## 6. History of the change

**Until 13 November 2026, the rate was overwritten by the plaintext**, the orientation of the suite (`docs/PROOFS.md`,
Lemma 1).
- In DMV17's interface, that is flag = true at encryption: every encrypted block counted in Ω. The cost is
  384 − log₂(L + Ω) bits classically, and an erosion in √Ω in the quantum heuristic. The paper (p. 609) describes this
  effect: an adversary who can force the outer part gives "a term in the bound at worst MN/2^c".
- **The author decided to switch to the SpongeWrap orientation**, at no cost in speed (the same permutations).
- What changed:
  - 4 AEAD KATs changed (`kat_b1024.h`), while the 14 others are unchanged;
  - `aead_lot32` and `aead_lot256` were adapted;
  - the checks were extended (literal DMV17 reference).
- **The suite (BRUME-512) is not modified.** The remark on its Theorem 14, remark 2, is to be passed on to the human review
  of `docs/PROOFS.md`. Its σN/2^c bound is consistent; the improvement promised by "finer analyses (DMV17)" does not apply
  to its encryption blocks.
- **Merging the length block** (4 → 3 permutations) is a separate question, kept out of this change. Per the author's
  rule, no security is traded for speed before its argument is written. Its argument is now written: § 6 bis.

## 6 bis. Merging the length block: feasibility (14 November, proposal, author decision)

**What it means.** Drop the length block. The last text block, which already carries the padding 0x01 and `DOM_TEXTE`,
becomes the last absorbed block, and the tag is read after its permutation:

```
  last block m* (0 ≤ ℓ < 80): Z ← S.rate ; c* ← m* ⊕ Z[0..ℓ) ; S.rate[0..ℓ) ← c* ; S.rate[ℓ] ⊕= 0x01 ; S[127] ⊕= DOM_TEXTE·16 ; S ← P(S)
  T ← S.rate[0..32)                                          # the length block and its P are gone
```

This is SpongeWrap's own layout: Bertoni et al.'s SpongeWrap, Ascon and Xoodyak have no length block either. They rely
on padding and domain separation, as we already do.

**Why the length block carries nothing the proof needs.**
- *Injectivity.* The encoding (A, M) ↦ path is already injective without the length: the padding 0x01 ends each phase,
  and the nibble of byte 127 tells the phases apart. `decoder_chemin` recovers (A, M) from the AAD and text entries alone.
  It reads the length only to check it against what it has already decoded (`v != lm`), and `DOMAINS.md` § 4 already
  calls the length "redundant with the padding of the text".
- *Step 3 (a) of § 4 bis* needs the last entry of a final path to have a role that no keystream path ends with. Today
  that role is `DOM_FINAL`. After the merge it is `DOM_TEXTE`. Every keystream path still ends with an entry of nibble
  `DOM_AAD` (first text block) or 0 (a full text block): the keystream of the last text block is read **before** its entry is
  absorbed. So a final path is still never a revealed keystream path, and the argument holds word for word.
- *Step 3 (b)* (the final path of an Enc query decodes into the same (A, C)) is unchanged, since the decoder never
  needed the length.
- *Resources.* A query makes one call fewer. Its non-text calls are now the first AAD block and the tag call, so
  L + Ω ≤ σ_D − q_d instead of σ_D − 2q_d. The bound keeps the same form, (2σ_D + 5)·N/2^384 + 2q_iv·N/2^512 +
  q_d/2^256 + negligible terms, with σ_D smaller by one call per decryption. **No term gets worse.**
- *The flag.* In decryption the last text call keeps its partial flag on ℓ bytes (§ 4 ter). The tag is then the Z of the
  next call (σ = 0), as today after the length call. This is the configuration § 4 ter already covers.
- *Gilbert et al. 2023.* Its two conditions are unchanged: the ciphertext overwrites the rate, and no key enters the final
  phase. Removing the length block neither helps nor hinders that attack. The defence remains the length limit of
  `SPEC.md` § 3.5, which is a rejection rule, not an encoding. The limit stays as it is.
- *Nonce reuse.* The keystream is unchanged block for block. The exact leak of § 4 (e) is the same.
- *Q1 (quantum).* The heuristic argument is untouched: same state, same capacity, same key.

**What is lost.** Only an explicit, redundant binding of |M| into the tag, which would catch an implementation that pads
wrongly. That defect is already caught by the KATs, by the decoder check and by the 383 alterations.
- *Alternative B*, if the author wants to keep it: XOR le64(|M|) into the capacity of the last text block (bytes 88..95,
  which are zero there). DMV17 absorbs a full b-bit σ, so this stays within the model. It costs nothing in speed, but
  it adds a field the proof does not use and that must be specified and tested.
- **Recommendation: option A** (plain removal).

**Gain** (to be measured; estimated from the cost in permutations). A query costs 3 + ⌈(|A|+1)/80⌉ + ⌊|M|/80⌋
permutations instead of one more: −25 % below 80 bytes of A and of M, −20 % up to 159 bytes, about −6 % at 1 KiB, nothing
for long messages. One 1 024-bit permutation is about 0.55 µs on Zen 3 (README § 4.1). Against BRUME-512 at c = 256,
the empty message would go from ×0.87–0.91 to about ×1.16–1.21, the only case where BRUME-1024q still loses, and 64 bytes
would go from ×1.11 to about ×1.4. The bitsliced multi-message AEAD gains in the same proportion.

**Cost of the change** (prototype only; the suite is not touched).
- Format: the 5 AEAD KATs change (`aead_0`, `aead_16`, `aead_64`, `aead_1000`, `aead_64_sans_aad`); the 13 others do not.
  `SPEC.md` § 3.5 and § 4, `DOMAINS.md` § 4 (`DOM_FINAL` becomes unused in the AEAD; keep the value reserved).
- Code, about ten places: `aead()`, `aead_lot32`, `aead_lot256` (bitsliced length constants), the literal DMV17 reference
  `aead_kd_chemin`, `decoder_chemin` (final role `DOM_TEXTE`, no length entry), the role check (calls:
  ⌈(|A|+1)/80⌉ + ⌊|M|/80⌋ + 2, last absorbed entry `DOM_TEXTE`), the domain check, and the decoder's "length" alteration,
  which no longer exists and must be replaced (for example a final entry with nibble `DOM_AAD`).
- This document: § 1 (mode, cost), § 4 bis (step 0, step 3 (a), resources, table of facts).
- Re-verification: the 27 checks, the planted defects of the AE-step checks, ctgrind and dudect (open, accept, reject),
  the equivalence and forgery modes of the campaign over a few hours, and a mutation pass on the changed functions.

**Verdict: feasible, with no security traded.** The security argument transposes without a new idea. It is the AE step
of § 4 bis with one role renamed and one call fewer. The work is a format change of the prototype and its
re-verification, not new research. **Decision of the author**: option A, option B, or keep the length block.

## 7. What remains (`ROADMAP.md` § 1)

1. ~~Write the AE step~~: done (§ 4 bis, § 4 ter). Open: an analysis of the AE game itself that would remove σ_D from
   the leading term (the p. 610 regime), if one is wanted.
2. ~~Check the proof of DMV17 Theorem 1~~: done for our parameters, then re-checked (§ 4 quater: F2 and F3 confirmed by
   simulation, F1 withdrawn, Theorem 1′). Open: a human review of F2 and F3, and perhaps a message to the authors (an author
   decision).
3. A Q1 analysis beyond heuristics, if a usable quantum result for the keyed duplex exists.
4. Pass the remark of § 6 on to the review of `docs/PROOFS.md` (suite).
