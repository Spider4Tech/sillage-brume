# BRUME-1024q — specification

Version: **draft v0.6-1**, 13 November 2026. **Status: research, not reviewed, not for production.**

On 13 November 2026 the author decided that BRUME-1024q replaces BRUME-512 in v0.6 (`docs/MIGRATION_V06.md`). This
document is meant to be **sufficient to write an independent implementation**. Each section says what is normative. The
prototype `brume1024.c` is one implementation of it; when they disagree, the disagreement is a defect to report.

## 1. Conventions

- **Nibbles.** A state is 256 nibbles x[0..255], each in GF(2⁴). It is stored in 128 bytes:
  - nibble 2i is the **low** nibble of byte i;
  - nibble 2i + 1 is the **high** nibble of byte i.
- **Field.** GF(2⁴) = GF(2)[t]/(t⁴ + t + 1): the nibble value Σ b_k 2^k is the polynomial Σ b_k t^k. Multiplication is ·,
  addition ⊕.
- **Rate and capacity.** Bytes 0..79 (nibbles 0..159) form the **rate** (r = 640 bits). Bytes 80..127 form the **capacity**
  (c = 384 bits).
- **Byte strings.** They are indexed from 0. le64(n) is n on 8 bytes, little-endian. be64(n) is n on 8 bytes, big-endian.

## 2. The permutation P

### 2.1 S-box (normative)

S = [10, 13, 4, 1, 2, 6, 5, 0, 11, 15, 14, 12, 7, 8, 9, 3], that is S(0) = 0xA, …, S(15) = 0x3 (the S-box of SILLAGE v0.5,
"AD412650BFEC7893").

### 2.2 Linear layer M (normative)

M is a 256 × 256 matrix over GF(2⁴), supported on a Cayley graph of the dihedral group D₂₅₆:
- **Vertices.** v = 128·f + i, with f ∈ {0, 1} and i ∈ Z/128.
- **Generators.** K = (K₀, …, K₅) = (0, 105, 71, 76, 72, 31). The neighbour of v through K_g is:

      nbr(v, k) = 128 + ((i + k) mod 128)   if f = 0,
      nbr(v, k) = (i − k) mod 128           if f = 1.

- **Row v of M** has exactly 7 nonzero entries:

      M[v][v] = CS[v],   M[v][nbr(v, K_g)] = CG[g][v]   (g = 0..5).

- **Values.** CS[256] and CG[6][256] are the arrays `B1_CS` and `B1_CG` of `b1024_tables.h`, and K is `B1_K`.
- **Fingerprint.** SHAKE256 of K ‖ CS ‖ CG, one byte per value, 6 + 256 + 1 536 bytes, 32 output bytes:
  `6439f5c30aa7f23c48068818c9b654a3465a14e78fdab723beff219ecd7a0040`.

  An implementation that reads the tables from elsewhere must reproduce this fingerprint.
- **Origin (informative).** The values come from a seeded search under fixed constraints (`gen_b1024.c`):
  - B = 8 exact, for differences and for masks;
  - M invertible;
  - an asymmetric weighted graph (Weisfeiler–Lehman 256/256);
  - order of M greater than 256;
  - λ* = 3.796.

### 2.3 Round constants (normative)

Let F be the first 48 × 256 = 12 288 bytes of SHAKE256 of the 16 ASCII bytes `BRUME-1024-v1-RC` (no terminator). Then
RC[r][j] = F[256·r + j] mod 16, for r < 48 and j < 256. Only the first 32 rounds are used. This table is `B1_RC`; it was
re-derived independently (Python's hashlib) on 13 November 2026, and is identical.

### 2.4 Round and permutation (normative)

    round_r(x):   x[j] ← S(x[j] ⊕ RC[r][j])  for every j;   then x ← M·x, that is x[v] ← Σ_u M[v][u]·x[u]
    P(x) = round_31 ∘ … ∘ round_1 ∘ round_0 (x)        (32 rounds)

## 3. Frame, modes and domains (normative)

### 3.1 Profile frame

The profile frame fills bytes 121..127 of a state:

| Byte | 121 | 122 | 123 | 124 | 125 | 126 | 127 |
|---|---|---|---|---|---|---|---|
| Value | 32 (rounds) | 0 | 0 | 160 (rate in nibbles) | 0x10 | 0x71 (`'q'`) | mode |

The mode is **5** for the unkeyed sponge and **3** for the AEAD.

### 3.2 Sponge with domains

    Sponge(M, dom, ℓ):
      s ← P(0^121 ‖ frame(5))
      split M ‖ 0x01 ‖ 0* into 80-byte blocks m_1 … m_n   (n = ⌊|M|/80⌋ + 1 ; 0x01 goes at offset |M| mod 80 of m_n)
      for i < n:  s[0..80) ⊕= m_i ; s ← P(s)
      s[0..80) ⊕= m_n ; s[127] ⊕= dom·16 ; s ← P(s)
      output: the first ℓ bytes of s[0..80) ‖ P(s)[0..80) ‖ P(P(s))[0..80) ‖ …

Domains: SEQ = 0 (XOF), FEUILLE = 8, RACINE = 9, SEUL = 10.

### 3.3 XOF

XOF(M, ℓ) = Sponge(M, 0, ℓ).

### 3.4 Default hash (tree)

    H(M, ℓ):   (the default digest has ℓ = 64)
      if |M| ≤ 8192 : return Sponge(M, 10, ℓ)
      k ← ⌈|M| / 8192⌉ ; leaves L_1 … L_k of 8 192 bytes (the last one may be shorter, never empty)
      CV_i ← Sponge(L_i, 8, 64)
      return Sponge(CV_1 ‖ … ‖ CV_k ‖ be64(k) ‖ 0x00 0x00 0x20 0x00, 9, ℓ)

### 3.5 AEAD (full-state keyed duplex, SpongeWrap orientation)

Key K of 64 bytes, nonce N of 24 bytes, associated data A, plaintext X, tag of 32 bytes.
**Lengths: |A| < 2^64 bytes and |X| < 2^64 bytes** (|X| is encoded by le64). An input beyond these limits is rejected; it
is never processed with a truncated length. (Decision of 14 November 2026.)

*Implementation note (informative).* On a 64-bit platform `size_t` cannot express 2^64, but the index computations of
the block loops overflow as soon as a length exceeds 2^64 − 81. The prototype therefore rejects |A| or |X| above
2^63 − 1 bytes (the largest C object, `PTRDIFF_MAX`), which is stricter than the limit above. `aead()`, `aead_ouvrir()`
and `aead_multi()` return −1 without reading or writing anything; `aead_multi()` also rejects n·|X| above that bound.
Check `longueurs_hors_limite_rejetees_sans_lecture_ni_ecriture`.

    Enc(K, N, A, X):
      s ← P(K ‖ N ‖ 0^33 ‖ frame(3))
      split A ‖ 0x01 ‖ 0* into 80-byte blocks a_1 … a_n (n = ⌊|A|/80⌋ + 1)
      for i ≤ n:  s[0..80) ⊕= a_i ; if i = n: s[127] ⊕= 1·16 ; s ← P(s)
      for each full block x_i (80 bytes) of X:
          c_i ← x_i ⊕ s[0..80) ; s[0..80) ← c_i ; s ← P(s)
      last block x* of ℓ bytes (0 ≤ ℓ < 80):
          c* ← x* ⊕ s[0..ℓ) ; s[0..ℓ) ← c* ; s[ℓ] ⊕= 0x01 ; s[127] ⊕= 2·16 ; s ← P(s)
      s[0..8) ⊕= le64(|X|) ; s[8] ⊕= 0x01 ; s[127] ⊕= 4·16 ; s ← P(s)
      T ← s[0..32) ;  return (C = c_1 ‖ … ‖ c*, T)

    Dec(K, N, A, C, T): the same, the rate receiving the ciphertext bytes (s[0..80) ← c_i, s[0..ℓ) ← c*), the plaintext
      being c ⊕ (rate before replacement). The recomputed tag is compared with T in constant time. If they differ, the
      plaintext is wiped and nothing is returned.

**Rules.**
- No plaintext is released before the tag is checked.
- The nonce must be unique per key. Nonce reuse leaks c ⊕ c′ = x ⊕ x′ on every block up to and including the first block
  whose padded entry differs, and nothing after (`AEAD_SECURITY.md` § 4 (e)).
- The length limits above are part of the security argument. The generic attack of Gilbert et al. (EUROCRYPT 2023)
  applies in principle to this mode: the ciphertext overwrites the rate at decryption, and the tag does not involve the
  key. In its published form it needs ciphertexts of about 3·2^{c/2} blocks, far beyond 2^64 bytes
  (`AEAD_SECURITY.md` § 4 bis).

### 3.6 Separation (informative)

`DOMAINS.md` gives the separation:
- the AEAD's initial state differs from the sponge's at byte 127 for every key;
- the domains are distinct within each construction.

## 4. Test vectors (normative)

**Inputs:**
- message m[i] = i mod 251;
- key K[i] = i (i < 64);
- nonce N[i] = 0x80 + i (i < 24);
- associated data A = m[1000..1009) (9 bytes), or empty where stated.

**Outputs.** They are in `kat_b1024.h`, and as text in `kat_b1024.txt` (same values):

| Name | Function |
|---|---|
| `hachage_<L>` | H(m[0..L), 64) |
| `hachage_abc` | H("abc", 64) |
| `xof_<L>` | XOF(m[0..L), 200) |
| `aead_<L>`, `aead_64_sans_aad` | T ‖ SHAKE256(C)[0..32), with X = m[0..L) and A as above (empty for `sans_aad`) |

- H("") = `95ee2e0b…5d255e95`.
- H("abc") = `062a5ef2…5f776916`.

The full values are in the files.

## 5. Security claims (informative; see the documents cited)

| Claim | Status | Where |
|---|---|---|
| Generic quantum level of the sponge, c = 384: 2^128 (BHT) | generic attack cost, not a proof | README § 5 |
| Bound on characteristics: C3 ≥ 21, 218 active S-boxes over 32 rounds | certified (two LRAT checkers) | README § 3 |
| Aggregation at 2 rounds: max DP 2^−16, max hull 2^−7.83 | exact, confirmed empirically | `agregation2.c` |
| AEAD (classical, ideal permutation): Adv ≤ (2σ_D + 5)·N/2^384 + 2·q_iv·N/2^512 + q_d/2^256 + negligible terms | AE step written; DMV17 Theorem 1 checked for our parameters and repaired (Theorem 1′); agrees with Mennink 2023 Th. 7 / Dobraunig–Mennink 2019; not peer reviewed | `AEAD_SECURITY.md` §§ 4 bis–4 quater |
| Constant time | measured (dudect, ctgrind) on two machines, AVX2 kernels | README |

Not claimed:
- security against superposition queries to the keyed construction (Q2);
- anything beyond the analyses cited.
