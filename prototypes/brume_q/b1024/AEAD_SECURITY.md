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
  T ← S.rate[0..32)                                       # no length block since 14 November (option A, § 6 bis)
Dec (aead_ouvrir): same, the rate being overwritten by c_i; tags compared in constant time; on failure the output is wiped
  and −1 returned (no release of unverified plaintext, "no RUP").
```

**Cost.** 1 (init) + ⌈(|A| + 1)/80⌉ + ⌊|M|/80⌋ + 1 permutations, that is 3 for a short message (4 until the length block
was merged, 14 November, § 6 bis).

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
| Tag | flag = false, σ = 0; the tag is the output Z of one more call, after the last text block | yes |
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
L + Ω (at most σ_D − q_d, σ_D being the number of calls made by decryption queries). Encryption data no longer appear in the
leading term.

**(c) Multi-user.**
- The key-guessing term is q_iv N/2^512, with q_iv at most the number of users that reuse the same nonce.
- The key-collision term is C(u, 2)/2^512 in Theorem 1 (keys drawn with replacement), doubled to 2·C(u, 2)/2^512 in the
  AE bound (§ 4 bis); it is 0 when the keys are drawn without replacement.

**(d) Quantum, model Q1. Not covered by DMV17** (classical); **our proof in § 4 quinquies** (14 November, not reviewed). The 2^128 of `SPEC.md` § 5 is the generic BHT cost
of a collision search on the sponge (c = 384); it is **not** a 128-bit quantum guarantee for the AEAD. Heuristic costs:

| Attack | Cost | Status |
|---|---|---|
| Key search (Grover) | 2^256 | generic |
| State recovery (Grover on the inner part) | ≈ 2^192 | heuristic. The multi-target erosion in √Ω of the former orientation is gone, since the adversary no longer chooses the outer part during encryption |
| Tag guessing | q_d/2^256 | generic |

Q2 is **not claimed** (§ 4 sexies: analysis of the known attack families, no proof).

**(d bis) Q1 against the literature (read on 14 November 2026).** Two papers of 2025 treat exactly this model, classical
queries to the keyed mode and quantum queries to P and P⁻¹, for the **Ascon AEAD mode**. Neither covers our mode.

*What they prove.*

| Paper | Technique | Result (single user) | Restrictions |
|---|---|---|---|
| Lang, Lucks, Mennink, Talnikar, ePrint 2025/411 | semi-classical one-way to hiding | Theorem 3: secure while q_P ≪ min(2^(k/2), 2^(c/2)/√σ), for σ ≪ 2^((c−r)/2) | nonces from a predefined set N, whose size enters the bound; **one** forgery attempt |
| Hosoyamada, ePrint 2025/1059 (ASIACRYPT 2025) | the mode seen as an iterated tweakable Even–Mansour with a low-entropy key; a new resampling lemma (after Alagic et al., EUROCRYPT 2022 and 2024) | Theorems 3 and 4: besides the classical terms, 4·√(σ²·q_Q/2^κ) + 2σ²/2^κ + 2·√(2σ·q_Q²/2^κ), so secure while σ²·q_Q ≪ 2^κ and σ·q_Q² ≪ 2^κ; "about min(2^(c/3), 2^(κ/3))" is the balanced point σ ≈ q_Q | none on nonces or forgeries; also nonce misuse and release of unverified plaintext |

Here σ counts the permutation calls made by the classical queries, q_P or q_Q the quantum queries, k or κ the key
length (κ ≤ c in Ascon). Hosoyamada also proves the PRF security of the inner-keyed and full-keyed sponges (Theorems 5
and 6, same terms) and of the outer-keyed sponge and KMAC (Theorem 7, under κ > r). He states that his bounds are
capped by those of Even–Mansour, that he knows no matching attack, and that he expects them not to be tight.

*Why our mode is not covered.*

| | Ascon mode | Our mode |
|---|---|---|
| Key | κ ≤ c bits, XORed into the **inner** part after the initialisation and around the finalisation | 512 bits in the **outer** part of the initial state (bytes 0–63 of the 80-byte rate), never added again |
| Even–Mansour view | exact: the key additions telescope, the mode is an iteration of one tweakable Even–Mansour cipher with one key | no key addition to telescope. After the first call, the secret is the inner part of P(K ‖ N ‖ IV), **a different one for each nonce** |
| Tag | read after a key addition | read without the key (the condition of Gilbert et al., § 4 quater) |

- Lang et al.'s puncture set is tailored to Ascon's key additions.
- Hosoyamada's Theorems 3 to 6 need one key that masks the inner part before and after each call. Theorem 7 (key
  absorbed first, as ours) needs κ > r; ours has κ = 512 < r = 640, in one block.
- His conclusion says that the full-keyed duplex of Mennink–Reyhanitabar–Vizár 2015, SpongeWrap and MonkeySpongeWrap
  "could also be proven analogously". This is announced, not proved, and the full-keyed duplex meant there has its key
  in the inner part, unlike DMV17's and ours.

*Generic attacks in Q1* (Lang et al. § 7, transposed to c = 384, b = 1 024, k = 512):

| Attack | Cost for us | Remark |
|---|---|---|
| Key search (Grover) | 2^(k/2) = 2^256 | |
| Search of the inner part of one state (Grover), their § 7.2 | 2^(c/2) = **2^192** | the figure of (d), now with a source. An attack cost, not a bound |
| One of 2^ζ whole states (their § 7.3, in the manner of BHT) | 2^((b−ζ)/2): 2^480 with 2^64 nonces | irrelevant at b = 1 024 |
| Multi-target search on the inner part | 2^((c−log₂ D)/2) with D states **of the same outer part** | needs the adversary to fix the outer part. Encryption: the outer part is the ciphertext, which the adversary does not choose, as a query is a whole message (this is also the interface of DMV17, where σ is given before Z is returned). Decryption: the adversary does choose it, but nothing is returned without a valid tag, so a guess is only tested online. **An interface that returned ciphertext blocks before taking the next plaintext blocks would give this attack its D targets** |

*What can be said, and what cannot.*
- No **published** Q1 theorem covers our mode. § 4 quinquies gives our own proof (not reviewed), by the same method.
- The best generic Q1 attack we know costs 2^192; nothing found goes below.
- **If** bounds of the two forms above held for our mode with κ replaced by c = 384, they would give q_Q ≪ 2^192/√σ:
  2^160 quantum queries for σ = 2^64 blocks, and the 2^128 target up to σ = 2^128 blocks. This is an indication of the
  order to expect, not a claim.
- **A route to a proof, not a proof.** (1) The initialisation: P(K ‖ N ‖ IV) as a function of N, with K secret in the
  outer part and quantum access to P; one call, no output mask, so not an Even–Mansour cipher (a one-way-to-hiding
  argument is the natural tool, with a term of the order of q_Q·√(q/2^512)). (2) After it, for each nonce, the mode
  **is** an iteration of the single-key Even–Mansour cipher x ↦ P(x ⊕ (0 ‖ i)) ⊕ (0 ‖ i), with i the inner part of the
  state after the initialisation: Hosoyamada's Proposition 1 applies to one nonce. (3) Going from one nonce to q
  nonces needs a multi-key version of that proposition; a plain hybrid would multiply the bound by q. (4) The
  classical step, with secret random permutations in place of the ciphers, is our AE step (§ 4 bis). **§ 4 quinquies
  replaces this route by a direct one**: the hybrid of the Even–Mansour proofs is run on the calls of the duplex
  themselves, the hidden inner part playing the role of the key, which treats (1), (2) and (3) at once and loses nothing
  in the number of nonces.

**(e) Nonce reuse.** It is not covered: L > 0. **The exact leakage** (13 November, evening), for two encryptions under
the same key and nonce of (A, M) and (A', M'):
- the keystream of text block t depends only on the path before it: the iv, the AAD entries and the entries σ̃ of the text
  blocks 0 … t − 1 (the padded plaintext blocks; for the last one, the padding and the `DOM_TEXTE` nibble);
- so the keystreams of block t **coincide if and only if** A = A' (same AAD entries) and the entries of blocks 0 … t − 1
  coincide;
- consequence: c ⊕ c' = m ⊕ m' on every block **up to and including the first block whose entry differs**, and nothing
  after it. In particular, if M' is a prefix of M with ⌊|M'|/80⌋ = j, then C' is the prefix of C up to block j included;
- the tags: (A, M) = (A', M') implies T = T' (determinism). The converse does **not** hold in general: T has 256 bits,
  so distinct pairs can share a tag (a collision, probability about 2^−256 per pair in the ideal model). The check observes
  that the tags of the distinct pairs of its grid differ; that is an observation on a finite grid, not a proof of
  injectivity, and the reduction of § 4 bis does not use it (it uses equality of paths and the decoding of the final path).

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
- σ_E and σ_D calls of the keyed duplex made by these queries (a query makes ⌈(|A|+1)/80⌉ + ⌊|M|/80⌋ + 2 calls);
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
- one Duplexing per text block, whose Z is the keystream of that block; the last one carries the padding 0x01 and
  `DOM_TEXTE`;
- one Duplexing with σ = 0, whose Z gives the tag (first 256 bits).

(Until 14 November a Duplexing for a length block came before the tag call; it is merged, § 6 bis.)

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
- The flagged calls are the text calls of the decryptions: Ω ≤ σ_D^txt. Every query makes at least 2 calls that are not text
  calls (first AAD block, tag), so L + Ω ≤ q_d + σ_D − 2q_d = σ_D − q_d. (With the length block it was σ_D − 2q_d, for one
  call more per query: σ_D itself is smaller by one call per decryption now.)

*Step 2, from G1 to the ideal world.* G2 is G1 with Dec always returning ⊥ (it still evaluates RO). Let "bad" be the event
that a Dec query computes a tag equal to its T. G1 and G2 are identical until bad, **because `aead_ouvrir` releases nothing
when the tag is wrong (no RUP)**.

In G2, the view of A is the Enc outputs, the ⊥ answers and f, and f is independent of RO. An Enc output reveals:
- RO(P_t), truncated to the length of block t, for each keystream path P_t;
- the tag RO(P_fin), truncated to 256 bits.

These paths are pairwise distinct across all Enc queries (step 1). A value of RO sampled by a Dec query is never revealed in
G2. Hence the Enc outputs are uniform and independent, and **G2 is the ideal world**: Adv^AE(A) ≤ Δ_B + Pr_G2[bad].

*Step 3, Pr[bad] ≤ q_d/2^256.* Take a Dec query (δ, N, A, C, T), and let P′_fin be its final path (iv, AAD entries, text
entries).
- **(a) P′_fin is not a keystream path.** P′_fin ends with the entry of the last text block, whose role nibble is
  `DOM_TEXTE`. Every keystream path ends with an entry of nibble `DOM_AAD` (the first text block) or 0 (a full text block):
  the keystream of a block is read **before** that block's entry is absorbed, and no text block follows a `DOM_TEXTE`
  entry. So P′_fin is not a revealed keystream path, and RO(P′_fin) is uniform and independent of the view of A in G2, of which T is a function. Hence
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
| The final path decodes into (A, M), so the encoding is injective | same check: `decoder_chemin` on the grid, plus 4 altered paths (domain, padding, capacity, last block) that must not decode into (A, M); planted defect (decoder accepting any nibble) caught. Every rejection branch returns exactly −1: `decodeur_chemin_rejette_exactement_chaque_forme_invalide_et_garde_nch` |
| Roles: keystream after an entry of nibble `DOM_AAD` or 0, tag after the `DOM_TEXTE` entry of the last text block, σ = 0 for the tag call, ⌈(\|A\|+1)/80⌉ + ⌊\|M\|/80⌋ + 2 calls | same check |
| `aead()` = the sequence of calls | `aead_identique_a_la_reference_dmv17_litterale_…`, campaigns (739 million cases) |
| No release on failure | `aead_ouvrir_verifie_rejette_les_alterations_et_n_en_rend_rien` (383 alterations) |

**Numerical bound.** We use Theorem 1′ (§ 4 quater: the paper's Theorem 1 with the repairs of F2 and F3 and the direct
multicollision bound F4) plus the proposition, with L + Ω ≤ σ_D − q_d ≤ σ_D, σ = σ_E + σ_D ≤ 2^127, and
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
  2^{3c/4}, with N ≈ σ_d ≈ 2^{3c/4}. First known through Mennink 2023, § 9.3; the paper itself was read on 14 November (below). Mennink notes
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
    - The tag is determined by the state before the final phase. Ours is P after the last text block, with no key (until
      14 November: a public length block, then P).

    The modes that frustrate the attack add the key in the final phase (Ascon, NORX v3) or use a feedback function
    (Beetle).
  - **The mechanism.** A ciphertext made of one block β repeated ℓ times makes the inner state iterate x ↦ ⌈P(β ‖ x)⌉_c.
    Offline, the adversary finds a β whose functional graph has a large component with a short cycle. It then submits
    5 decryptions of length ℓ = 3·2^{c/2} blocks and runs through the cycle.
  - **The cost.** 21·2^{3c/4} calls to P, that is 2^292.4 for c = 384. A forgery then gives **the key** (§ 3.7): the
    returned plaintext lets one go back to the state after initialisation, and our P_init = P(K ‖ N ‖ 0 ‖ frame) can be
    inverted for a known N.
  - **Length.** The published attack needs ciphertexts of ℓ = 3·2^{c/2} ≈ 2^193.6 blocks. BRUME-1024q limits |M| to less
    than 2^64 bytes (`SPEC.md` § 3.5), about 2^57.7 blocks. **The published version therefore does not apply as is.**
    Variants for bounded lengths have not been studied.
    - Since 14 November `SPEC.md` § 3.5 states |A|, |M| < 2^64 bytes and the implementation rejects longer inputs (bound
      2^63 − 1 in this implementation). **This is a rule of use that keeps the published form out of reach, not a
      security proof:** a variant adapted to bounded lengths is not excluded.
  - **This is consistent with the bound.** The attack has σ_d·N ≈ 2^488 ≫ 2^383.
  - **What the cost does and does not say.** 2^292.4 is a **classical** cost. It must be compared with classical
    targets: it is above the classical AEAD level that the bound gives (≈ 2^256, set by the tag and by σ_D·N ≈ 2^383),
    and **below** classical key search (2^512). It must **not** be compared with Grover (2^256): that is a quantum
    cost, in another model, and the comparison says nothing about which attack is the more dangerous. A quantum version
    of this attack is not studied (Q1, § 4 (d)).
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
  it (footnote 1, p. 14: the max in max{(ν_fix − 1)/2, 0}, for ν_fix = 0). DM19 itself was read afterwards (below).
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
  (proof of Lemma 2, p. 20). This gives the term ν^M_{r,c}(L+Ω)/2^c, exactly what DMV17's count misses.
  **Replayed numerically (14 November, `dmv17_verif/f2_dm19.py`):** the exact collision probability of the F2 adversary
  (`f2_exact.py`, r = 4, c = 16, six (Mu, Ω) cases), which exceeds DMV17's written bound by ×1.03 to ×1.18, is **0.36 to
  0.62 times** the corresponding DM19 terms ([C(Mu,2) + Mu·Ω]/2^b + [ν·Ω + max{(ν_fix − 1)/2, 0}·Ω]/2^c + 2ν/2^c, with
  ν_fix = Ω, read in Mennink 2023, Theorem 2, (6a)). The ν_fix term is needed for that: without it, the case Mu = 24,
  Ω = 16 would exceed. **F2 is therefore
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
  - Our mode differs from MonkeySpongeWrap: AAD blocks (domain on the last), frame, partial last block. So this is a cross-check,
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

**Literature (first note, 13 November; superseded: all four texts were read on 14 November, above).** Mennink,
*Understanding the Duplex and Its Security*, ToSC 2023(2), pp. 1–46 (ePrint 2022/1340), reportedly says there is "a
certain issue in the proof of Daemen et al.". At the time it was not read:
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

## 4 quinquies. Q1: the keyed duplex against a quantum adversary (written on 14 November 2026)

**Status: our proof, not reviewed.** It follows the method of Alagic–Bai–Katz–Majenz (EUROCRYPT 2022) and of Hosoyamada
(ASIACRYPT 2025, ePrint 2025/1059), and rests on two lemmas taken from these papers, **both checked against their
text**: Lemma R is Hosoyamada's Lemma 3, and Lemma A is Lemma 3 of Alagic et al. (ePrint 2021/1601, read on 14 November
after a first draft that restated it from memory: the statement, the constant 2q·√ε and the expectation taken with the
unreprogrammed oracle are as used here). **Their proofs were re-read** (below): they hold, apart from one misstated
auxiliary lemma that we repair. The algebraic identities of our proof and those of the lemmas are machine-checked
(`q1_verif/`); nothing here tests a quantum adversary.

**Model (Q1).** f is a uniform random permutation of {0,1}^b, b = r + c. The adversary A has quantum access to f and
f⁻¹ (q_Q queries) and **classical** access to the keyed duplex KD′ of § 2 and § 4 ter (Init and Duplexing, with the
flag and the partial flag), for u users with independent uniform k-bit keys. Let κ = min(k, c); for us κ = c = 384.

**Nodes.** Every call of the duplex has a path (DMV17 § 2.3): (δ, iv) for an Init, and the parent's path followed by the
effective entry σ̃ for a Duplexing (σ̃ = σ, or σ ⊕ (Z ‖ 0) on the flagged bytes). A **node** is a distinct path. Node v
has an input x_v and an output y_v:

    x_v = K[δ] ‖ iv        (Init)            x_v = y_p ⊕ σ̃      (Duplexing, p the parent of v)
    y_v = f(x_v)            (real world)      the call returns Z_v = the outer part of y_v.

A call on an existing path returns the recorded value and creates no node. Let M bound the number of nodes. The
**ideal world** gives every new node a fresh uniform y_v, independent of f, and returns its outer part: this is IXIF′
exactly. Write y_v = (z_v ‖ w_v), outer and inner part.

**Lemma D (deferred sampling; stated precisely after an external review of 14 November).** Consider an experiment, or a
phase of one, in which every node is answered ideally and no other part of the construction reads a key or an inner
part. (This holds for the ideal world, for phase 1 of every hybrid below, and, in § 4 septies, once each superposed call
has been replaced by its ρ.) Sample in advance: f; the keys K[0..u−1]; one fresh output y_n = (z_n ‖ w_n) for each node
index n, in order of creation. The answers are the z_n. A child of p receives σ̃, a function of σ and z_p only. Whether a
call creates a node depends only on the paths, i.e. on the adversary's inputs. **So the complete state of the adversary
(all its registers, measurements purified) and all its choices are functions of (f, z_1, z_2, …, its coins). The family
(K, w_1, w_2, …) is independent of them**: uniform and independent of f, the z's and the adversary's state, whatever its
adaptivity. Three cases deserve to be spelt out:
- *a key used by several Inits*: an Init answered ideally does not read K[δ], so K[δ] stays uniform given the state,
  whatever the number of earlier Inits of user δ;
- *a parent with several children*: the children receive σ̃ computed from z_p, and their outputs are fresh, so w_p stays
  uniform given the state, whatever the adversary chose after seeing z_p;
- *quantum queries to f*: f is sampled independently of (K, w), so its queries, in superposition or not, carry no
  information on them.

The proof uses two consequences. Both hold given the complete state of the adversary at the moment a node is requested
in such a phase; the inputs σ, iv may be chosen adaptively, and that choice is a function of the state.
- **(F-a)** For the node v requested now, x_v = K[δ] ‖ iv (Init) or (z_p ⊕ σ̃_out ‖ w_p ⊕ σ̃_in) (Duplexing). Given the
  state, it is uniform over a set of size at least 2^κ, κ = min(k, c): it has the min-entropy that Lemma R requires.
- **(F-b)** For a fixed t: Pr[x_v = t] ≤ 2^−κ and Pr[y_v = t] ≤ 2^−c. For two nodes v ≠ v′ of the phase,
  Pr[x_v = x_v′] ≤ 2^−κ:
  - two Inits of one user have different iv;
  - two Inits of users δ ≠ δ′ need K[δ] = K[δ′], probability 2^−k (0 for keys drawn without replacement);
  - an Init and a Duplexing need w_p ⊕ σ̃_in = the inner part of K[δ] ‖ iv. That part is public for us (k = 512 < r), and in
    general involves at most k key bits. Probability at most 2^−κ, w_p being independent of the key and of the choice of
    σ̃;
  - two Duplexings of different parents need w_p ⊕ w_p′ = a value fixed by the state: 2^−c;
  - two children of one parent have different σ̃, hence different inputs.
- **Where they are used.** (F-a) at the end of stage 1 in step (i) below: the hidden values are those of a phase where
  everything is ideal. (F-b) in steps (ii) and (iii): the hidden values sampled in stage 2, or by B in Lemma A, are those
  of nodes created in the ideal phase, never read before. In the real phase 2 the values are read, and no property of
  this kind is claimed there.

**Lemma R (resampling; Hosoyamada 2025, Lemma 3).** Stage 1: a random permutation P₀ is drawn, D runs with quantum
access to P₀ and P₀⁻¹ and at most q queries, then outputs a distribution 𝒟 on {0,1}^b of min-entropy at least κ.
Stage 2: s₀ ← 𝒟, s₁ uniform, P₁ = P₀ ∘ swap(s₀, s₁), b a uniform bit; D receives s₀, s₁ and quantum access to P_b and
P_b⁻¹, and outputs b′. Then |Pr[b′ = 1 | b = 1] − Pr[b′ = 1 | b = 0]| ≤ 4·√(q/2^κ).

**Lemma A (arbitrary reprogramming; Alagic et al. 2022, Lemma 3).** Phase 1: D outputs a
function F and a randomised algorithm 𝓑 whose output is a set B of pairs (point, new value), each point at most once;
let ε = max over points t of Pr[t is reprogrammed]. Phase 2: 𝓑 is run, F₁ is F reprogrammed on B, F₀ = F, b a uniform
bit; D makes quantum queries to F_b, q in expectation when the oracle is F₀. Phase 3: D loses its oracle, receives the randomness of 𝓑, and
outputs b′. Then |Pr[b′ = 1 | b = 1] − Pr[b′ = 1 | b = 0]| ≤ 2q·√ε. A permutation with its inverse is the function
(direction, point) ↦ value.

**The proofs of the two lemmas, re-read (14 November).** Both hold; one intermediate statement of the 2022 paper is
false as printed, without consequence. Program: `q1_verif/lemmes_sources.py`.

- **Lemma A** (Alagic et al., § 4.1). Every step was followed: the execution as a channel with a control qubit per
  query, the hybrid on the number of queries answered by F₀, the reduction to the branch where a query is made (weight
  p_k, whence the *expected* number of queries, counted with F₀), the purification, and E‖Π_{B₁}ψ‖² ≤ ε. The states
  before each query do not depend on the randomness of 𝓑, which is what lets D receive it in phase 3. Nothing to
  report.
- **Lemma R** (Hosoyamada, appendix B, built on Alagic et al., § 4.2). Followed: the superposition oracle for a
  permutation and its inverse; the commutation of the swap of two oracle registers with a forward query projected away
  from s₀, s₁ and with an inverse query projected away from the values f(s₀), f(s₁) (checked exhaustively on the 256
  functions of 2 bits to 2 bits, with a witness); the invariance of the "good" part of the state; the two averages
  2·2^−n; Hosoyamada's purification over the choice of the distribution, where min-entropy κ gives the factor 2^(n−κ);
  and the constants, which do give 4·√(q/2^κ).
- **The gentle measurement lemma of the 2022 paper (its Lemma 8) is false as printed.** It states
  1 − |⟨ψ|P_q⋯P_1|ψ⟩|² ≤ Σ ε_i for projectors with ‖(1 − P_i)ψ‖² ≤ ε_i. One projector already gives 2ε − ε² > ε; even
  without the square, two rank-one projectors at angles +θ and −θ from ψ give about 3θ² against Σ ε_i = 2θ².
- **What the proof needs still holds, with a better constant.** The lemma is used only for ‖ψ_bad‖² ≤ 2·Σ ε_i, where
  ψ_bad = ψ − z·P_q⋯P_1ψ. Let δ_i = ψ − P_i⋯P_1ψ. Then δ_i = (1 − P_i)ψ + P_i·δ_{i−1}, an orthogonal sum, so
  ‖δ_i‖² ≤ ε_i + ‖δ_{i−1}‖² and **‖ψ − P_q⋯P_1ψ‖² ≤ Σ ε_i**; the phase z of the paper can only decrease the norm.
  (20 000 random cases: largest ratio 1.0000.) Hence both resampling lemmas hold as stated, and could be stated with
  2√2 in place of 4. We keep the published constant.
- Two misprints in Hosoyamada's appendix B, without consequence: ψ_bad is defined as "ψ − ψ_bad" (read ψ_good), and the
  index i is missing in the definition of ε_i.
- This is our reading, not a review by the authors' peers; the finding on Lemma 8 could be reported to the authors (an
  author decision, as for F2 and F3).

**Theorem Q.** For every adversary A as above, creating at most M nodes and making at most q_Q quantum queries,

    Δ_A(KD′_K, f ; IXIF′, f)  ≤  4·M·√(q_Q / 2^κ)  +  2·q_Q·√(2M / 2^κ)  +  M² / 2^(κ+1)  +  3M² / 2^(b+1).

**Proof.** Number the nodes 1, 2, … in order of creation. For a list T_j = ((x_1, y_1), …, (x_j, y_j)) and a
permutation P, let

    S_{T_j, P} = swap(P(x_1), y_1) ∘ … ∘ swap(P(x_j), y_j),        P^{T_j} = S_{T_j, P} ∘ P.

P^{T_j} differs from P at most at the points x_i and P⁻¹(y_i), and its inverse differs from P⁻¹ at most at the points
P(x_i) and y_i (identity I4 of the program).

*Hybrid H_j* (0 ≤ j ≤ M). Phase 1: A runs in the ideal world, with f as primitive, until it asks for node j + 1.
Phase 2: the hidden values (keys, w's) are sampled, which fixes T_j; from now on the primitive is Q = f^{T_j}, and the
duplex **continues**: an existing node keeps its recorded (x, y), a new node v gets x_v = y_p ⊕ σ̃ (or K[δ] ‖ iv) and
y_v = Q(x_v). H_0 is the real world (T_0 is empty), and H_M is the ideal world (phase 2 never starts).

*Three more experiments*, with s₀ = x_{j+1}:
- H*_j: as H_j, but phase 2 uses f⁽¹⁾ = f ∘ swap(s₀, s₁) in place of f, with s₁ uniform: Q* = (f⁽¹⁾)^{T_j};
- H′_j: phase 1 lasts until node j + 1 has received its (ideal) answer, and phase 2 starts **at once** with Q = f^{T_{j+1}};
- H_{j+1}: the same, but phase 2 starts only when node j + 2 is asked for.

*(i) |Pr[A(H_j) = 1] − Pr[A(H*_j) = 1]| ≤ 4·√(q_Q/2^κ).* Build D for Lemma R. In stage 1, D runs A in the ideal world
with P₀ as primitive. It samples only the z's, which is all the answers need (Lemma D), and makes no query of its own. When
A asks for node j + 1, D outputs the distribution of s₀ = x_{j+1}: K[δ] ‖ iv with K[δ] uniform, of min-entropy k, or
(z_p ‖ w_p) ⊕ σ̃ with w_p uniform, of min-entropy c. Neither K[δ] nor w_p has been used. In stage 2, D reads K[δ] or
w_p off s₀, samples the other hidden values, computes T_j, and runs phase 2 with P_b in place of f (the values
P_b(x_i) are classical queries; stage 2 has no query limit). b = 0 is H_j and b = 1 is H*_j, exactly.

*(ii) |Pr[A(H*_j) = 1] − Pr[A(H′_j) = 1]| ≤ j/2^κ + 3j/2^b.* Couple the two experiments by y_{j+1} = f(s₁): s₁ is
uniform and independent of everything else, so y_{j+1} is uniform and independent of f and of phase 1, as H′_j requires.
Let E1 be the event that some x_i, i ≤ j, lies in {s₀, s₁}, and E2 the event that y_{j+1} lies in some {f(x_i), y_i},
i ≤ j. By (F-b) and the uniformity of s₁ and y_{j+1}, Pr[E1] ≤ j/2^κ + j/2^b and Pr[E2] ≤ 2j/2^b. Outside E1,

    Q* = S_{T_j, f⁽¹⁾} ∘ f ∘ swap(s₀, s₁) = S_{T_j, f} ∘ swap(f(s₀), f(s₁)) ∘ f = S_{T_{j+1}, f} ∘ f = f^{T_{j+1}}

(identities I1 and I2), so the primitives of the two phases 2 are the same permutation. Outside E2 as well, node j + 1
receives Q*(s₀) = S_{T_j, f}(y_{j+1}) = y_{j+1} in H*_j (I3), its answer in H′_j. The two experiments then continue
identically.

*(iii) |Pr[A(H′_j) = 1] − Pr[A(H_{j+1}) = 1]| ≤ 2·q_{j+1}·√(2(j+1)/2^κ)*, where q_{j+1} is the expected number of
quantum queries between the answer to node j + 1 and the request for node j + 2. The two experiments differ only by
the primitive during that segment: f^{T_{j+1}} or f. Build D for Lemma A. In phase 1, D samples f itself and runs A in
the ideal world until node j + 1 is answered, sampling only the z's; it outputs F = (f, f⁻¹) and the algorithm 𝓑 that
samples the hidden values, computes T_{j+1} and returns the points where f^{T_{j+1}} and its inverse differ from f and
f⁻¹. In phase 2, D runs the segment (calls on existing paths are answered from the z's). In phase 3, D receives the
hidden values and runs the rest, which is the same in both experiments; it knows f. A fixed forward point t is
reprogrammed only if t = x_i or f(t) = y_i for some i ≤ j + 1, a fixed inverse point only if f⁻¹(t) = x_i or t = y_i:
by (F-b), ε ≤ 2(j+1)/2^κ.

*Comparison with the source proofs.* (iii) is Lemma 6 of Alagic et al., with the same use of Lemma A (D samples the
permutation itself, the permutation and its inverse are one function of (direction, point)). (i) and (ii) are their
Lemma 7. Their hybrids answer the later classical queries with the cipher on the **unreprogrammed** permutation, which
costs them a third bad event and a second application of the resampling lemma (their constant 8). Ours, like
Hosoyamada's, continue on the reprogrammed permutation, so that after (ii) the two experiments are the same and no
such event is needed.

*Sum.* In H_{j+1}, everything before the request for node j + 2 is the ideal world, so q_{j+1} is the expected number
of queries of A in that segment **of the ideal world**; the segments are disjoint, hence Σ_j q_{j+1} ≤ q_Q. With
Σ_{j<M} j ≤ M²/2, this gives the bound. ∎

**Corollary (AE in Q1).** The AE step of § 4 bis only wraps the adversary and forwards its primitive queries, and its
steps 2 and 3 are information-theoretic with f independent of the random oracle. So, with quantum primitive queries,

    Adv^AE(A)  ≤  4·σ·√(q_Q / 2^384)  +  2·q_Q·√(2σ / 2^384)  +  σ² / 2^385  +  3σ² / 2^1025  +  q_d / 2^256,

where σ = σ_E + σ_D is the number of calls made by the queries. Nonces must be unique in encryption and nothing is
released before the tag is checked, as in § 4 bis; nothing is required of the nonces across users.

| σ (calls) | q_Q (quantum queries) | bound, without q_d/2^256 |
|---|---|---|
| 2^48 | 2^128 | 2^−38.5 |
| 2^64 | 2^128 | 2^−30.5 |
| 2^64 | 2^150 | 2^−8.5 |
| 2^96 | 2^128 | 2^−14.5 |

**What it says, and its limits.**
- **Two readings of the bound** (σ = 2^64). As an advantage, it is 2^−30.5 at q_Q = 2^128 and reaches 1 near
  q_Q = 2^158.5 (second term). As a **level in the cost/advantage sense of the suite** (λ bits when
  Adv ≤ (q_Q + q_d)/2^λ + 2^−λ, the notion under which AES-128 has 128 bits), 2√q ≤ q + 1 gives
  4σ·√(q_Q/2^384) ≤ (q_Q + 1)·2σ/2^192: **about 127 bits for σ ≤ 2^64**, 143 bits for σ ≤ 2^48. It is not an
  advantage of 2^−128 after 2^128 queries; the generic search for an inner part gives about q_Q²/2^384, which this bound
  does not reach.
- It is a proof that the mode has no structural weakness in Q1 up to about q_Q ≈ 2^192/√σ, the order of the two theorems
  on the Ascon mode (§ 4 (d bis)). With σ ≤ 2^64 the bound is below 2^−30 at 2^128 quantum queries.
- **The bound is probably not tight.** The best attack we know costs 2^192 whatever σ (§ 4 (d bis)); the bound allows
  about 2^158 at σ = 2^64. The gap is the same as in the papers it follows.
- It does not use L, Ω or the multiplicity ν: here the adversary's control of the outer part costs nothing more, because
  only the c hidden bits are counted. It is therefore **weaker than Theorem 1′ classically** (σ·√q against σ_D·N/2^384)
  and does not replace it.
- The key need not be longer than c: the first term for an Init node would use k = 512, and κ = 384 is the minimum.
- **Not covered:** Q2 (superposition queries to the mode, § 4 sexies), nonce reuse, release of unverified plaintext, and any
  interface that lets the adversary learn a hidden inner part.
- **To do before relying on it:** a human review of (i)–(iii) and of Lemma D, which an external review (14 November)
  asked to be stated as a conditional invariant on the complete state of the adversary; it now is.

## 4 sexies. Q2: superposition queries to the mode (14 November 2026)

**Status.** Full Q2 is **not claimed and not proved**. One restricted model is **covered by a corollary of § 4
quinquies**: superposition **decryption** queries with classical encryption queries (model "Q2d"), with a weak bound.
Under the strongest notions, with challenges in superposition, the encryption part alone is **broken**, as for every
scheme that XORs a keystream. Read for this section: Bonnetain–Schrottenloher (ePrint 2023/1306), Lang–Lucks (ePrint
2023/218), Janson–Struck (ePrint 2022/139), Alagic–Carolan–Majenz–Tokat (ePrint 2025/731). Ambainis–Hamburg–Unruh (ePrint 2018/904), read afterwards, whose Theorem 3 carries the corollary. Not read: Kaplan et
al. 2016 (the file fetched as ePrint 2016/066 is another paper: our reference was wrong).

**The models** (Lang–Lucks, Definitions 4 and 8; Janson–Struck § 5.1).
- **Q2:** encryption queries with header and message in superposition; **the nonce is classical and never repeated**
  ("the established approach": the nonce is a counter or a value drawn by the sender); decryption queries with nonce,
  header and ciphertext in superposition. Challenge queries are classical (Boneh–Zhandry).
- **Q2d:** the same with **classical** encryption queries; only decryption is in superposition. Q2 ⇒ Q2d ⇒ Q1.
- **Challenges in superposition** (Gagliardoni–Hülsing–Schaffner; Mossayebi–Schack): strictly stronger notions, defined
  for encryption schemes only; none exists for AEAD (Janson–Struck § 5.2).

**1. Challenges in superposition: the encryption part alone fails; with the tag, nothing is known.** Janson–Struck
(Theorems 19 and 21) break the encryption part of the sponge AEAD Slae with a Hadamard test, and note that the weakness
"lies in the one-time pad approach". It transposes word for word to our first text block: C₁ = M₁ ⊕ Z₀ with Z₀
independent of M₁, so the uniform superposition of all M₁ is left unchanged by encryption, while a basis state is not.
Every mode that XORs a keystream has this property. They add that the attack "does not necessarily extend" to the full
AEAD, because the tag register is entangled with the ciphertext; we agree (for a tag that behaves as a random function
of the ciphertext, the test succeeds with a probability of the order of 2^−256). We claim nothing in these notions.

**2. Hidden shift in one query (Bonnetain–Schrottenloher): does not apply.** Their attack turns one superposition query
into a phase oracle x ↦ g(x ⊕ s′), where **g is a known function whose Walsh transform is computable** (products of
functions of one AES round) and s′ a secret part of the state. For us the keystream of block t is outer(P((M_{t−1} ⊕
Z_{t−1}) ‖ i)): the shift Z_{t−1} is public anyway, and the function is unknown, since it depends on the hidden inner
part i through 32 rounds of a 1 024-bit permutation. Their own discussion gives this as the case where the method
stops: "though we do have a shifted function, the function is now unknown … and more complex". Seen on the whole
state, the query covers only the outer coordinates of a shift whose secret part is inner.

**3. Period finding across queries: does not apply as it is** (unchanged from the first draft, now with the source):
"this strategy breaks down if the period changes at each query, e.g., if it depends on a nonce" (Bonnetain–
Schrottenloher, abstract and § 1). Moreover the key is concatenated with the nonce, not added, and the adversary's
inputs reach the rate only.

**4. Q2d: a corollary of Theorem Q (ours).** Let A make classical nonce-respecting encryption queries (σ_E calls),
q_d superposition decryption queries, each of at most ℓ calls, and q_Q quantum queries to P. Write Θ(σ, q_Q) for the
bound of Theorem Q. Then

    Adv^AE_Q2d(A)  ≤  Θ(σ_E, q_Q)  +  2·q_d·√( Θ(σ_E + ℓ, q_Q) + 2^−256 ).

**Lemma O (one-way to hiding; Ambainis–Hamburg–Unruh, ePrint 2018/904, Theorem 3, read on 14 November).** Let G, H be
functions that agree outside a set S, and z a string, with any joint distribution. Let A make its oracle queries at
depth d, and let B^G run A^G(z) until just before a uniformly chosen query, measure the query input and output the
result T. Then |Pr[A^H(z) = 1] − Pr[A^G(z) = 1]| ≤ 2d·√(Pr[S ∩ T ≠ ∅]). Other oracles of A may be encoded in z, as
complete descriptions (their remark after Theorem 1).

*Proof of the corollary (rewritten on 14 November after an external review).*
- **Fixed oracles.** Extend the inputs with a null input ∅. Let H(x) = Dec_K(x) and G(x) = ⊥ for every tuple x, and
  H(∅) = G(∅) = ⊥. Let S be the set of **valid** tuples (Dec_K(x) ≠ ⊥). S depends only on (K, P), not on the run: it is
  fixed, as Lemma O requires. H and G agree outside S.
- **The algorithm of Lemma O is not an adversary.** Let A_O run the Q2d adversary A. It answers A's encryption queries
  and P-queries from z = (K, P) (Lemma O allows any z, "additional oracles encoded as complete descriptions"). It gives
  A's decryption queries to its oracle through a **unitary blocking**. It keeps the classical list L of encryption outputs,
  which grows adaptively. It computes the bit [x ∈ L] into an ancilla, swaps the query register with a register holding ∅
  under that bit, queries, swaps back and uncomputes the bit. A blocked input reaches the oracle as ∅ and gets ⊥; it is
  kept in the other register, so the operation is unitary (the first draft "redirected" several tuples onto one, which is
  not). With H, A_O reproduces the real Q2d game; with G, the game where decryption always returns ⊥.
- **Lemma O:** |Pr[A_O^H = 1] − Pr[A_O^G = 1]| ≤ 2d·√p, with d the depth of A's decryption queries (d ≤ q_d) and
  p = Pr[S ∩ T ≠ ∅ : T ← B^G]. B^G runs A_O^G until just before a uniformly chosen query level, then measures the query
  registers.
- **Bounding p by a genuine Q1 forger.** Let F be an adversary with a classical encryption oracle and quantum access to
  P, **without the key and without any description of P**. F runs A and answers its encryption queries with its oracle,
  recording L. It answers A's P-queries with its own P. It answers A's decryption queries with ⊥ through the same
  blocking, which needs only L. At the chosen level it measures the query registers and submits what it got as
  forgeries. Every answer that B^G computes from z is exactly what F's oracles return, so F's run has the distribution of
  B^G's run. The key and the description of P serve only A_O and B, which are devices of Lemma O; F reproduces their
  output distribution through oracle access. A measured value in S is a valid tuple that is not in L at that time (a
  blocked tuple was replaced by ∅): a forgery, since F stops there. F makes σ_E classical encryption calls, at most
  q_Q quantum queries to P, and submits the measured tuples: w of them if A makes up to w decryption queries in
  parallel, one if A is sequential. By the corollary of § 4 quinquies with w decryptions,
  p ≤ Θ(σ_E + wℓ, q_Q) + w/2^256.
- **The last step:** the game with G against the ideal world is the Q1 game without decryption: Θ(σ_E, q_Q). Altogether,
  for a sequential adversary (w = 1, d ≤ q_d), the bound stated above holds; in general, replace ℓ by wℓ and 2^−256 by
  w·2^−256. ∎

The objection of the review was that "z describes K and P" takes the forger out of Q1. The forger to which the Q1 bound
is applied is F, which has neither; z appears only in the analysis, as Ambainis–Hamburg–Unruh allow. The other two
remarks were right and are fixed above: the redirection was not unitary, and the dependence on the adaptive list L,
now confined to the blocking with S fixed.

Table: sequential adversary, ℓ ≤ σ_E (each superposed decryption makes at most σ_E calls), Θ(σ_E + ℓ, q_Q) ≤ Θ(2σ_E, q_Q).

| σ_E | q_Q | q_d (superposed decryptions, sequential) | bound |
|---|---|---|---|
| 2^32 | 2^64 | 2^40 | 2^−14 |
| 2^48 | 2^96 | 2^20 | 2^−14 |
| 2^64 | 2^128 | 2^10 | 2^−4 |
| any | 0 (tag term alone) | 2^120 | 2^−7 |

- The tag term, 2·q_d/2^128, **is tight up to the constant**: Grover's search on the tag forges in about 2^128
  superposition decryptions, for any AEAD with a 256-bit tag.
- The other term is weak because of the square root: this is a statement of principle, not a comfortable margin.
- **The reservation of the first draft is lifted.** The original was read: its Theorem 2 does run A with the oracle that
  never finds, and its Theorem 3, used here, gives the result directly with a better constant (2d·√P against
  4d·√P through Theorems 1 and 2), with the measuring experiment run on G. **Its proof was followed** (Lemma 8: with
  D_i the squared distance of the two states after i queries and B_i the weight of the i-th query on S,
  √D_i ≤ √D_{i−1} + 2·√B_i, since the two oracles differ only on S and their difference has norm at most 2; then
  Jensen; Lemma 9 averages over G, H, S, z). Nothing to report beyond two harmless misprints.
- **A remark on Lang–Lucks, Theorem 7** (our reading). It states Adv ≤ 4·√(q + 1)·√Adv(1PO) + Adv(1CPA), its proof
  setting Adv(1PO) = P_find. A Q1 forger cannot run the punctured oracle: what it can do is measure one query, which is
  the experiment of Lemma O and gives q·√Adv(1PO) in place of √(q + 1)·√Adv(1PO). The statement as printed is
  contradicted by Grover's search on the tag: with a 256-bit tag and q = 2^128 it would bound the advantage by about
  2^−62, while that search wins. The qualitative result (Q1 privacy and authenticity imply Q2d security) stands.

**5. Encryption in superposition (IND-qCPA): last block covered by § 4 septies; two blocks or more open.**
- For a **stream cipher**, superposition learning queries give nothing more than classical ones, so Q1 privacy is
  enough (Anand et al. 2016, as used by Janson–Struck § 5.4). Our keystream is independent of the message for the
  first block only: afterwards it depends on the previous ciphertext block, and the tag depends on everything.
- **Nonce-based key derivation** turns a Q2d-secure scheme into a Q2-secure one (Lang–Lucks, Theorem 8), provided the
  derivation is a PRF. Our initialisation P(K ‖ N ‖ IV) looks like one, but its 1 024-bit output is not a PRF against
  an adversary with P⁻¹ (one inverse query on the output returns K ‖ N ‖ IV): the theorem does not apply as a black
  box. A direct proof would have to keep the inner part hidden while the data phase runs in superposition, which the
  method of § 4 quinquies cannot do (it follows a classical transcript).
- **Why Lemma O does not do it either.** One would puncture P on the states the construction visits. After a first
  block in superposition, the states of the second call are (C₂ ‖ i(C₁)) for **all** values of C₁: up to 2^640
  branches, each with its own inner part, against 2^384 inner values. The set to puncture is then essentially the whole
  domain, and the lemma says nothing. A superposition confined to **one** call after a classical prefix keeps a single
  hidden inner part and could be treated; we have not written it, as it would cover single-block messages only. The
  general case needs the kind of technique built for the plain sponge by Alagic et al. 2025.
- The quantum indifferentiability of the sponge (Alagic et al. 2025, Theorem 1.2: O(√(ℓ³q⁹·2^−min(r,c))) up to the
  exact root, about 2^43 queries for us) concerns the plain sponge hash, with queries in superposition; our mode is
  not a plain sponge (overwriting in decryption, domain constants in the capacity, nonce in the capacity).

**Generic costs in Q2:** key 2^256 (Grover, with P offline); inner part of one state 2^192; forgery 2^128
superposition decryptions.

**Position.**
1. **Q2 stays outside the claims** (`SPEC.md` § 5). The mode is specified for classical implementations.
2. **Q2d** (decryption in superposition, encryption classical): covered by the corollary above (ours, not reviewed),
   with a bound that is meaningful only for a moderate number of superposition decryptions.
3. **Encryption in superposition, classical unique nonces:** proved when confined to the last text block (§ 4 septies);
   for two blocks or more, no proof; the two published attack methods that survive
   a change of nonce (hidden shift in one query) or need none (period finding) do not apply, for reasons of design:
   **the key is concatenated, not added; the adversary's inputs never reach the capacity; a full permutation separates
   two blocks.** A variant that lost one of these would have to be re-examined; in particular a full-state absorption
   of the data, which DMV17 allows.
4. **Challenges in superposition:** the encryption part alone fails, like every keystream-XOR scheme; nothing is
   claimed.
5. Outside these conditions nothing is said: nonces in superposition, nonce reuse, release of unverified plaintext.

**To do:** a human review of the corollary; Kaplan et al. 2016 (CRYPTO 2016) for completeness; an IND-qCPA argument
is research, for the reason given in point 5. (Since then, IND-qCPA is proved for superposition confined to the last text
block: § 4 septies, Theorem Q2-1; two blocks or more stay open.)

## 4 septies. Q2: superposition in the last block (written on 14 November 2026)

**Status: our proof, not reviewed.** It covers superposition **confined to the last text block**; § 4 sexies explains
why two or more blocks in superposition are out of reach of the method. Tools: Lemma O (Ambainis–Hamburg–Unruh, read,
proof followed), the hybrid of Theorem Q (§ 4 quinquies), and three lemmas proved here. Lemma U is checked exhaustively
by `q1_verif/couture.py`; nothing here tests a quantum adversary.

**Model.** Encryption queries are nonce-respecting, with a classical nonce. The AAD and every text block except the last
are classical. The last text block m (0 ≤ |m| < 80 bytes, its length included) may be in superposition. The adversary has
quantum access to P and P⁻¹ (q_Q queries) and makes q_s such superposition queries; σ counts the calls of all queries
except the superposed last calls. There is no decryption oracle: the two notions below do not have one.

**What a superposed query computes.** Let v be the node of its last classical call, with output y_v = (z ‖ w). The last
call evaluates P at e(m) = y_v ⊕ (m ‖ 0x01 ‖ 0* ‖ δ_T), δ_T being the `DOM_TEXTE` constant in the capacity. All these
points lie in the **coset** H = {x : inner(x) = w ⊕ δ_T}: one hidden inner value, 2^640 points. The answer is
(m ⊕ z[0..|m|), trunc_256 P(e(m))). Messages of 80 bytes or more in superposition, superposed AAD, and even an empty
message with superposed AAD put two calls or more in superposition: not covered.

**Lemma U (stitching; checked exhaustively on |X| ≤ 7 by `couture.py`).** Let φ be a uniform permutation of X, H ⊂ X, and
ψ: H → X a uniform injection independent of φ. Let A = ψ(H), Y = φ(H), and π a uniform bijection from A∖Y onto Y∖A.
Define φ' = ψ on H, and on X∖H: φ'(x) = φ(x) if φ(x) ∉ A, π(φ(x)) otherwise. Then φ' is a **uniform** permutation, for
every fixed H, and φ'|_H = ψ. It differs from φ in the forward direction only on H ∪ φ⁻¹(A∖Y), and in the inverse
direction only on A ∪ Y.
*Proof.* φ' is a bijection: H goes onto A, and X∖H onto (Y^c ∖ A) ∪ (Y ∖ A) = A^c. For any permutation τ of X, replacing
(φ, ψ, π) by (τφ, τψ, τπτ⁻¹) leaves their joint law unchanged and turns φ' into τφ'. So the law of φ' is invariant under
left composition by every permutation: it is uniform. The modified points can be read off the definition. ∎

**Lemma L (load).** For a uniform injection ψ of a set of at most 2^640 points into {0,1}^1024, each 256-bit prefix t is
the prefix of more than 2^385 of the images with probability at most exp(−2^384/3) (Chernoff, the counts being
hypergeometric). Conditioned on all the 256-bit prefixes of the images of a subset E ⊂ H, any fixed y ∈ {0,1}^1024 lies in
ψ(H) with probability at most 2^385/(2^768 − 2^640) + 2^640/(2^1024 − 2^640) ≤ 2^−382.

**Lemma F (two pairs from one query; ours).** Let R: X → {0,1}^n be uniform, or a truncated uniform injection (values
then within a factor 1 + 2^−383 of uniform given the others). An algorithm that makes one quantum query to R and outputs
(x₁, t₁, x₂, t₂) with x₁ ≠ x₂ has t₁ = R(x₁) and t₂ = R(x₂) with probability at most 6.01·2^−n.
*Proof.* After the query the state is Ψ = Σ_x β_x|x⟩X_{R(x)}|χ_x⟩, then a unitary V. Fix x₁ ≠ x₂, write a = R(x₁),
b = R(x₂), B_i = β_{x_i}|x_i⟩X_{R(x_i)}|χ_{x_i}⟩, and Γ = Ψ − B₁ − B₂, which does not depend on (a, b). With Π the
projector on the outputs (x₁, a, x₂, b), ‖ΠVΨ‖² ≤ 3(‖ΠVΓ‖² + ‖ΠVB₁‖² + ‖ΠVB₂‖²), and (a, b) is uniform given Γ.
(1) E‖ΠVΓ‖² = 2^−2n·‖Π_{x₁·x₂·}VΓ‖² ≤ 3·2^−2n(‖Π_{x₁·x₂·}VΨ‖² + ‖Π_{x₁·x₂·}VB₁‖² + ‖Π_{x₁·x₂·}VB₂‖²); summed over
(x₁, x₂), each of the three sums is at most 1 (the projectors Π_{x₁·x₂·} are orthogonal), hence at most 9·2^−2n.
(2) Averaging over b first, E‖ΠVB₁‖² ≤ 2^−n·E‖Π_{x₁·x₂·}VB₁‖², whose sum over (x₁, x₂) is at most 2^−n·Σ|β_{x₁}|² = 2^−n.
(3) Likewise for B₂. Total: 3(9·2^−2n + 2·2^−n) ≤ 6.01·2^−n. ∎

**The one-block ideal world W₁.** The classical calls are answered as in IXIF′ (fresh outputs), and the j-th superposed
query by (m ⊕ z_j[0..|m|), trunc_256 ρ_j(m)), with z_j fresh and ρ_j an injection that is uniform and independent of
everything else.

**Theorem Q2-1.** With Θ(σ, q_Q) the bound of Theorem Q,

    Δ(real, W₁)  ≤  Θ(σ, q_Q)  +  q_s·[ (q_Q + 2σ)·2^−190  +  σ·2^−380 ].

**Proof.** Run the hybrid of Theorem Q on the classical nodes, with one addition. When the parent v of a superposed
query becomes ideal (node j + 1 = v), steps (i) and (ii) are unchanged. Step (i) counts only the adversary's queries:
the superposed calls whose parents are already ideal use their ρ, not P. Step (ii) leaves v with a fresh output (z, w)
and the primitive f^{T_{j+1}} for the rest. **One step is added before (iii)**, which replaces the superposed call on the
coset H = H_{w⊕δ} by ρ:
- *World R*: the adversary and the construction use f, then f^T; the superposed call uses f^T on H. This is the current
  hybrid.
- *World I*: the same, except that the superposed call uses ψ|_H, with ψ an independent uniform permutation.
By Lemma U applied to (f, ψ, H), f' = stitch(f, ψ) is uniform, independent of w, and equal to ψ on H. The world where
everything uses f' is therefore World R, as long as no point of T lies in the modified set (bad event below). Apply
Lemma O with the oracles f' (H-side) and f (G-side), which agree outside S = H ∪ f⁻¹(A∖Y) (forward) and A ∪ Y
(inverse). Everything else goes into z: the fresh values, w, ψ, and the transcript T, from which f^T is computed with
one query per access plus the |T| classical queries f(x_i). The depth is d ≤ q_Q + 2σ. As in § 4 sexies, z serves
only the algorithm of Lemma O, which simulates the game; P_guess concerns the query registers of the adversary and of
the construction's calls, whose distribution is that of the game itself. No adversary is given z.
*P_guess* is measured in World I, where the superposed call depends on ψ only, and w enters no view: for every fixed w,
m ↦ ψ(e(m)) is a uniform injection. Hence a measured forward x lies in H with probability 2^−384, and f(x) lies in
A = ψ(H) with probability at most 2^−382 (Lemma L: the view holds only 256-bit prefixes of ψ). A measured inverse y lies
in Y = f(H) with probability 2^−384, and in A with probability at most 2^−382. So P_guess ≤ 2^−382.3 + exp(−2^384/3),
and Lemma O costs 2d·√P_guess ≤ (q_Q + 2σ)·2^−190.
*Bad event*: a point x_i, f(x_i) or y_i of T lies in S. Each does so with probability at most 2^−382, so in all at most
σ·2^−380.
Finally, in World I the call ψ|_H∘e is a uniform injection independent of everything, which is ρ_j. Step (iii) then
proceeds as in Theorem Q: the superposed call no longer uses w, so (F-a) holds again. Summing over the q_s superposed
queries gives the bound. ∎

**Corollaries.**
- **Privacy (IND-qCPA, Boneh–Zhandry: superposed learning queries, classical challenge on a fresh nonce):**
  Adv ≤ 2·Δ(real, W₁). In W₁ the challenge is a fresh path, independent of the bit.
- **Authenticity (plus-one, as in Lang–Lucks: after q encryption queries, output q + 1 distinct valid tuples):**
  Adv ≤ Δ(real, W₁) + (q + 1)·2^−256 + q_s·6.01·2^−256. In W₁ some nonce must carry two of the tuples, or one tuple must
  use an unqueried nonce. A tuple whose final path is not the final path of a classical query, and not
  "prefix of a superposed query + last block", is fresh: 2^−256. Two tuples on the same superposed prefix are two pairs
  (m, ρ_j(m)) from one quantum query: Lemma F.

| q_s (superposed queries) | q_Q | σ | Δ(real, W₁), main new term |
|---|---|---|---|
| 2^32 | 2^128 | 2^64 | 2^−30 |
| 2^64 | 2^100 | 2^64 | 2^−26 |
| 2^20 | 2^150 | 2^48 | 2^−20 |

**What it says.** A quantum adversary that can query encryption in superposition over a short last block (fewer than
80 bytes, with the rest classical) gains nothing structural: the cost is the product (number of superposed queries) ×
(queries to P), up to about 2^189. That is the order of the search for a hidden inner part, 2^192 per state.

**What it does not cover, and why.**
- **Two blocks or more in superposition**, including superposed AAD. After the first superposed call, each branch has its
  own hidden inner part, and the 2^640 branches cover all 2^384 inner values. There is no hidden coset left to stitch:
  the set S of Lemma O becomes the whole space. This is the internal-collision problem of the plain sponge, which needed
  the techniques of Alagic–Carolan–Majenz–Tokat (2025, bound about 2^43 queries). Their theorem covers the plain sponge
  from the zero state, not our mode: secret initial state, a domain constant in the capacity before the tag. **Open.**
- **Encryption and decryption both in superposition**: no standard notion; not treated. Decryption alone in superposition
  is § 4 sexies, point 4.
- **Challenges in superposition**: the encryption part fails for every keystream-XOR scheme (§ 4 sexies, point 1).

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
4. **Quantum (Q1):** our own proof (§ 4 quinquies, 14 November), **not reviewed**, by the method of the Even–Mansour
   proofs: 4σ·√(q_Q/2^384) + 2q_Q·√(2σ/2^384) + small terms + q_d/2^256, below 2^−30 at 2^128 quantum queries and 2^64
   calls. It rests on two published lemmas, whose statements and proofs were re-read (one auxiliary lemma of the 2022
   paper is false as printed; what is needed from it holds). Probably not tight: the best known attack costs 2^192.
   **Full Q2 is not claimed** (§ 4 sexies). Decryption in superposition with classical encryption (Q2d) is covered by a
   corollary, with a weak bound. Encryption in superposition confined to the last block is covered by Theorem Q2-1
   (§ 4 septies): IND-qCPA and plus-one authenticity up to about 2^189 (superposed queries × queries to P). The published superposition attacks that survive a nonce do not apply. Under notions
   with challenges in superposition the encryption part alone fails, as for every keystream-XOR scheme.
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
- **Merging the length block** (4 → 3 permutations) was a separate question, kept out of this change. Per the author's
  rule, no security is traded for speed before its argument is written. The argument was written first (§ 6 bis), then the
  change was made on 14 November (option A).

## 6 bis. Merging the length block (14 November): argument, then option A adopted

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

**Gain** (estimated first from the cost in permutations; **measured after the change**, 5600G: 0 B 3.08 → 2.31 µs, 64 B
3.07 → 2.32 µs, 1 KiB 12.2 → 11.5 µs; empty message ×1.15 against BRUME-512 at c = 256, 64 B ×1.45–1.53). A query costs 3 + ⌈(|A|+1)/80⌉ + ⌊|M|/80⌋
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
- Re-verification: the 29 checks, the planted defects of the AE-step checks, ctgrind and dudect (open, accept, reject),
  the equivalence and forgery modes of the campaign over a few hours, and a mutation pass on the changed functions.

**Verdict: feasible, with no security traded.** The security argument transposes without a new idea. It is the AE step
of § 4 bis with one role renamed and one call fewer. The work is a format change of the prototype and its
re-verification, not new research.

**Decision (author, 14 November): option A.** Done the same day, on a separate branch merged only after re-verification:
- code: `aead()`, `aead_lot32`, `aead_lot256`, `aead_kd_chemin`, `decoder_chemin`, the domain check, the AE-step and
  decoder checks; `DOM_FINAL` removed (the value 4 stays unused in the AEAD);
- the 5 AEAD KATs regenerated (kernel and dense reference agreeing), the 13 others unchanged; `spec_ref.c`, rewritten from
  `SPEC.md` § 3.5 alone, reproduces the 18 vectors (the previous `spec_ref.c` reproduces 13 of them, exactly the
  non-AEAD ones);
- this document (§ 1, § 4 bis), `SPEC.md` § 3.5, `DOMAINS.md` § 4;
- re-verification: see `ROADMAP.md` (29 checks, campaign, ctgrind and dudect, fourth mutation pass).

## 7. What remains (`ROADMAP.md` § 1)

1. ~~Write the AE step~~: done (§ 4 bis, § 4 ter). Open: an analysis of the AE game itself that would remove σ_D from
   the leading term (the p. 610 regime), if one is wanted.
2. ~~Check the proof of DMV17 Theorem 1~~: done for our parameters, then re-checked (§ 4 quater: F2 and F3 confirmed by
   simulation, F1 withdrawn, Theorem 1′). Open: a human review of F2 and F3, and perhaps a message to the authors (an author
   decision).
3. Q1 (§ 4 quinquies): a human review of the proof; perhaps a note to the authors about Lemma 8 of Alagic et al.
   (author decision). Q2 (§ 4 sexies): a human review of the Q2d corollary.
4. Pass the remark of § 6 on to the review of `docs/PROOFS.md` (suite).
