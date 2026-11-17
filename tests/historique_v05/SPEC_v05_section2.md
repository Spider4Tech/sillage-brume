# docs/SPEC.md § 2 of v0.5 (BRUME-512), kept as history

*Removed from `docs/SPEC.md` at v0.6 (17 November 2026). Text unchanged.*

## 2. BRUME-512

### 2.1 Frozen tables

The S-box, the group, the generators and the 128 × 128 coefficient matrix are **frozen tables**, stored in
[`sillage/brume512_tables.py`](../sillage/brume512_tables.py) (SHA-256
`c792bdd3fe405c471127651fec515cfa33f8b69c5d11f03f8f2a295bbb048667`; the generated C header `sillage/c/brume512_tables.h` holds the same data).
The group, the generators and the coefficients come from a seeded search (`sillage/select_params.py`), which
`tests/test_select_params.py` reruns to find exactly these tables. It also checks the stated selection criteria, and regenerates
the C headers byte for byte.

- **S-box (v0.5)** `S = [10, 13, 4, 1, 2, 6, 5, 0, 11, 15, 14, 12, 7, 8, 9, 3]` (`AD412650BFEC7893`; differential uniformity 4,
  linearity 8, degree 3, inverse of degree 3, no fixed point). This is candidate CAND_A1 of the S-box tie-break of 11 November 2026
  (`prototypes/brume_sbox6/departage/`, decision rule fixed in `PROTOCOLE.md` before any computation, results in `RAPPORT.md`). It
  is in the same optimal family as the v0.4 S-box `891AC406DF37E2B5` (still reproduced by `gen_sbox`), and better at 2 and 3 rounds:
  D3 86 against 83 bits, L3 40 against 39, D2 2^−16.000 against 2^−15.989, 3-round boomerang 2^−8.753 against 2^−8.476.
  **Changing it changes every BRUME-512 output** (AEAD, hashing, TE): the v0.4 KATs and ciphertexts are no longer valid.
- **Group** D₁₂₈ = ℤ/64 ⋊ ℤ/2. Element `a` encodes `(a mod 64, ⌊a/64⌋ mod 2)`; the product is
  `(a₀, a₁)·(b₀, b₁) = (a₀ + (−1)^{a₁}·b₀ mod 64, a₁ ⊕ b₁)`.
- **Generators** `GENS = [85, 64, 71, 109, 72, 126]` (six reflections, hence involutions).
- **Graph.** Vertex `x` is adjacent to `x·g` for every generator `g` (6-regular). The linear layer has support
  `A ⊕ I` (adjacency plus the diagonal): every output nibble depends on 7 input nibbles.
- **Coefficients** `COEF[j][i] ∈ GF(16)`, non-zero exactly on the support (`COEF` in the tables file).

### 2.2 The permutation

- **Round constants.** `RC = SHAKE256("BRUME-v1-RC")`, first `128 × 32` bytes; `RC[r][j] = byte (128·r + j) mod 16`, for
  `r < 32`, `j < 128`.
- **Linear layer.** `M(y)_j = ⊕_i COEF[j][i] · y_i` over GF(16).
- **Round** `r`: `x ← M(S(x ⊕ RC[r]))`, the S-box applied to each nibble.
- **BRUME-512** = rounds `0, 1, …, 31`. Reduced versions `BRUME-512[R]` (rounds `0 … R − 1`) exist for analysis only.

The **rate** is nibbles `0 … 63` (bytes 0 … 31 of the state, 256 bits); the **capacity** is nibbles `64 … 127`. Domain bits
are XORed into **nibble 127** (the high half of byte 63).

### 2.3 Hash (`brume512_hash`, `sl_hash`)

Sponge, rate 32 bytes, capacity 256 bits. `Sponge(m, dom, ℓ)`:
1. state ← 0; pad `m ‖ 0x01 ‖ 0x00*` to a multiple of 32 bytes (at least one byte of padding);
2. for each 32-byte block: XOR it into bytes 0 … 31; before the **last** block's permutation, XOR `dom` into nibble 127; apply BRUME-512;
3. output: bytes 0 … 31 of the state, then permute, and so on, truncated to `ℓ` bytes.

`brume512_hash(m, ℓ) = Sponge(m, 0, ℓ)`.

### 2.4 Tree hash (`brume512_hash_arbre`, `sl_hash_arbre`)

Leaves of `B = 8192` bytes; chaining values of 32 bytes; domains `LEAF = 8`, `ROOT = 9`, `SINGLE = 10`.
- if `|m| ≤ B`: output `Sponge(m, SINGLE, ℓ)`;
- otherwise cut `m` into `k` leaves `m₀, …, m_{k−1}` (the last may be shorter), `CV_i = Sponge(m_i, LEAF, 32)`, and output
  `Sponge(CV₀ ‖ … ‖ CV_{k−1} ‖ be64(k) ‖ be32(B), ROOT, ℓ)`.

### 2.5 AEAD (`Brume512`, `sl_aead_*`)

| Profile | Key | Nonce | Tag | λ | Rate (nibbles / bytes) |
|---|---|---|---|---|---|
| BRUME-512 | 64 B | 24 B | 16 B | 128 | 64 / 32 |
| BRUME-512-256 | 64 B | 24 B | 32 B | 256 | 32 / 16 |

Domains: `AAD = 1`, `TEXT = 2`, `FINAL = 4`. Below, `rb` is the rate in bytes, and blocks are XORed into bytes `0 … rb − 1`.

- **IV.** State 0, then nibbles `120 … 126` ← the first 7 nibbles of the bytes `(rate_nibbles, tag_len, λ mod 256, 3)`; then
  apply BRUME-512.
- **Absorb(state, d, dom).** Pad `d ‖ 0x01 ‖ 0x00*` to a multiple of `rb` (at least one byte); XOR the blocks in, permuting
  between blocks; after the last block, XOR `dom` into nibble 127 and permute.
- **Initialisation.** `state ← Absorb(BRUME(IV), key ‖ nonce, 0)`, then `state ← Absorb(state, aad, AAD)`.
- **Data phase (encryption).** For `i = 0, rb, 2·rb, …, |p|` (that is, `⌊|p|/rb⌋ + 1` steps, the last one possibly empty):
  `ks` = bytes `0 … rb − 1` of the state; `c_i = p_i ⊕ ks` (truncated to the chunk); the block absorbed is `c_i` if full, otherwise
  `c_i ‖ 0x01 ‖ 0x00*` padded to `rb`; XOR it in (overwriting nothing: the duplex XORs the **ciphertext** block into the rate)
  and permute. Decryption is identical, with the ciphertext chunk absorbed.
- **Finalisation.** XOR `TEXT` into nibble 127 and permute; `state ← Absorb(state, le64(|p|), FINAL)`; the tag is the first
  `tag_len` bytes of the rate outputs, permuting between rate blocks.
- **Decryption** recomputes the tag and compares it in constant time; on mismatch, no plaintext is released.

### 2.6 Parallel AEAD (`Brume512P`, `sl_aead_p_*`)

Same profiles, named BRUME-512p and BRUME-512-256p; leaves of `F = 4096` bytes; extra domains `START = 3`, `FORK = 5`,
`LEAF_END = 6`.
- **IV**: the sequential IV, with nibbles `116 … 119` ← the first 4 nibbles of the bytes `(12, 1)` (log₂ F, version).
- **Trunk**: the sequential initialisation (key, nonce, AAD) on this IV.
- **Leaf** `j`, data `d_j` (the j-th slice of `F` bytes; `k = max(1, ⌈|p|/F⌉)` leaves): copy the trunk; XOR
  `le64(j) ‖ 0x01`, zero-padded to `rb`, into the rate; XOR `FORK` into nibble 127, permute; XOR `START` into nibble 127, permute;
  run the data phase on `d_j`, XORing `LEAF_END` into nibble 127 together with the final (padded) block; `CV_j` = the first `λ/4`
  bytes of the final state.
- **Tag**: `Absorb(trunk, CV₀ ‖ … ‖ CV_{k−1} ‖ le64(k) ‖ le64(|p|), FINAL)`, then the tag is extracted as in § 2.5.

### 2.7 Self-correcting mode (TE)

On top of the sequential AEAD: the ciphertext is cut into 64-byte blocks (the last zero-padded for parity computation only);
each block gets 7 parity bytes: `C₀ = ⊕` of its 64 bytes, then 8 Hamming syndromes of 6 bits, one per bit plane `k`
(`s_k = ⊕` of the positions `j ∈ [1, 63]` whose byte has bit `k` set), packed big-endian as `s₇ ‖ … ‖ s₀` in 48 bits.
`meta = be64(|c|)`. Decryption corrects at most one altered byte per block (any error value), refuses inconsistent
syndromes, then verifies the AEAD tag, which remains the only integrity guarantee.

### 2.8 Known answers

| Input | Output (hex) |
|---|---|
| `BRUME-512(0⁶⁴)` (all-zero state) | `c80a7134946249362217cd150258d08ad18001e0b769873f0ae4607d7a179edc1fd2d7d6491ed67a571b2bbc5955298efe13aa5d1549cba8354634dadd825062` |
| `brume512_hash("", 32)` | `add8e16009589a20c5a6a90d6ff9b2d58916eaeb75601a82844f95ee55874c91` |
| `brume512_hash("abc", 32)` | `ee435ab11261ec3e85af77ef4564a7c2cf7bf98a804348768d94500ac1341aa1` |
| `brume512_hash_arbre("abc", 32)` | `5dd6ff9f3dd9a66fa43ce2c63cb53301e0bfafca2643cd298604992df9b8d63d` |
| `brume512_hash_arbre("A" × 20000, 32)` | `106d008621c2e91067cdca7de5bcc450342fe62885a764048dc55e5ce99dff1d` |
| BRUME-512, key `00…3f`, nonce `00…17`, AAD `"kat"`, plaintext `"SILLAGE"`: `ct ‖ tag` | `341aa9cfc83ccfa47b21aa53bfe914b7ccefed8fd2bac8` |
| BRUME-512-256, same inputs | `966f3c5af2b9518187e7b80760743312caafa965a5098de50221fede692b6ff2d9b900d5daa64b` |
| BRUME-512p, same inputs | `4d7340d7dde902573da0192c7cd75ff77ed52fe9c97482` |

All eight are produced identically by the Python reference and by the C library (v0.5, S-box `AD412650BFEC7893`; the v0.4 values
are in the git history).

