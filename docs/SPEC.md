# SILLAGE v0.5 — Specification

*Normative description of the algorithms, encodings and parameters, written for reviewers and for independent
re-implementation. Written on 2026-11-03 from the reference implementation (`sillage/*.py`), and cross-checked with the C library
(`sillage/c/`), which produces byte-identical outputs. Where this text and the reference implementation disagree, the
implementation defines v0.4 and the discrepancy is a bug in this document. Security arguments are not repeated here: see
[`PROOFS.md`](PROOFS.md).*

Status: research prototype, not for production. Outputs are frozen for v0.5 (any change alters the known-answer vectors). v0.5 changes the BRUME-512 S-box (§ 2.1) and the signature (§ 4 bis).

## 1. Conventions

- **Bytes and bits.** A vector of `m` bits is stored in `⌈m/8⌉` bytes; bit `i` is bit `i mod 8` (least significant first) of
  byte `⌊i/8⌋`. Padding bits of the last byte are zero; a decoder **rejects** non-zero padding bits wherever stated.
- **Nibbles.** A BRUME state is 128 nibbles (values in `[0, 16)`); nibble `j` is the low half of byte `⌊j/2⌋` if `j` is even, the
  high half otherwise. Equivalently, nibble `j` occupies bits `4j … 4j + 3` of the 512-bit state.
- **Integers.** `be32(x)`, `be64(x)`: big-endian encodings; `le64(x)`: little-endian. `‖` is concatenation.
- **GF(16)** = `GF(2)[X]/(X⁴ + X + 1)`, an element `Σ b_i X^i` encoded by the integer `Σ b_i 2^i`.
- **SHAKE.** `SHAKE256` as in FIPS 202. Three derived functions are used throughout:
  - `Hd(dom, x₁, …, x_k; ℓ) = SHAKE256(dom ‖ "|" ‖ x₁ ‖ … ‖ x_k)`, first `ℓ` bytes (`dom` is an ASCII string);
  - **integer stream** `Stream(dom, seed)`: block `c = 0, 1, …` is `SHAKE256(dom ‖ "|bits|" ‖ seed ‖ "|" ‖ be64(c))`, first 64 bytes,
    read as 16 big-endian 32-bit integers; the stream is the concatenation of the blocks;
  - **sparse vector** `Sparse(seed, w, m, dom)`: let `span` be the smallest power of two `≥ m`; read integers `r` from
    `Stream(dom, seed)`, set `r ← r mod span`, keep `r` if `r < m` and `r` was not kept before, until `w` positions are kept. The
    result is the set of positions (and, as a vector, the indicator of that set). *(The C code consumes a fixed number of integers
    for constant time; the kept positions and their order are the same.)*
  - **permutation** `Perm(seed, m, dom)`: Fisher–Yates on `π = (0, 1, …, m − 1)`: for `i = m − 1` down to `1`, let `mask` be the smallest
    power of two `≥ i + 1`; read integers `r` from `Stream(dom, seed)`, `r ← r mod mask`, until `r ≤ i`; swap `π[i]` and `π[r]`.

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

## 3. Sillage-KEM

### 3.1 Parameters

`R = GF(2)[z]/(zⁿ − 1)`, n prime and 2 primitive modulo n (so that `zⁿ − 1 = (z − 1)·Φₙ` with `Φₙ` irreducible).

| | n | k (μ bits) | w | w_e | D | n₂ = (k/8)·128·D | λ | ss bytes | θ |
|---|---|---|---|---|---|---|---|---|---|
| Sillage-128 | 50 021 | 128 | 75 | 25 | 14 | 28 672 | 128 | 32 | 0.7 |
| Sillage-256 | 170 003 | 256 | 140 | 64 | 28 | 114 688 | 256 | 64 | 0.7 |

Sizes (bytes): `pk = 32 + ⌈n/8⌉`, `sk = 3·⌈n/8⌉ + 64`, `ct = ⌈n/8⌉ + ⌈n₂/8⌉`: 6 285 / 18 823 / 9 837 for Sillage-128 and 21 283 / 63 817 / 35 587 for Sillage-256.

### 3.2 Derived public objects

From `σ_h` (32 bytes):
- `h = Hd("SILLAGE-KEM|h", σ_h; ⌈n/8⌉)`, read as an element of R (bits `≥ n` cleared);
- `π = Perm(σ_h, n₂/8, "SILLAGE-KEM|pi")`, a permutation of the **bytes** of an `n₂`-bit vector.

Message code (fixed per level): `Q = (Perm(be32(D), 128·D, "SILLAGE-KEM|rm")[q] mod 128)_{q < 128·D}`, so that every point of `GF(2)⁷`
appears D times. The codeword of a byte `b` is the 128·D-bit word whose bit `q` is `⊕_{t<7} b_t·(Q[q])_t ⊕ b₇` (first-order
Reed–Muller code RM(1, 7), each evaluation point repeated D times). `cw(μ)` concatenates the codewords of the k/8 bytes of μ.

### 3.3 Algorithms

- **KeyGen.** Draw `σ_h, σ_rej` (32 bytes each). Repeat: draw two fresh 32-byte seeds and set
  `x = Sparse(seed₁, w, n, "eph")`, `y = Sparse(seed₂, w, n, "eph")`; **until** the per-key decryption-failure bound of
  PROOFS § 2.3 is `≤ 2^{−λ}` (reference: `sl_kem_borne`; about 7 % and 6 % of draws are rejected). Then `s = x·h + y` in R.
  `pk = σ_h ‖ s`; `sk = x ‖ y ‖ σ_h ‖ σ_rej ‖ s` (each ring element on `⌈n/8⌉` bytes).
- **Enc(pk, μ)**, deterministic: `pkh = Hd("SILLAGE-KEM|pkh", pk; 32)`; `coins = Hd("SILLAGE-KEM|coins", μ, pkh; 32)`;
  `r₁ = Sparse(coins, w, n, "SILLAGE-KEM|r1")`, `r₂ = Sparse(coins, w, n, "SILLAGE-KEM|r2")`,
  `e₁ = Sparse(coins, w_e, n₂, "SILLAGE-KEM|e1")`, `e₂ = Sparse(coins, w_e, n₂, "SILLAGE-KEM|e2")`;
  `u = r₁·h + r₂`; `v = (r₁·s mod (zⁿ − 1)) restricted to its first n₂ coefficients ⊕ cw(μ) ⊕ e₁ ⊕ π(e₂)`, where byte `i` of
  `π(e₂)` is byte `π[i]` of `e₂`. `ct = u ‖ v`.
- **Encaps(pk).** Reject pk if the padding bits of `s` are non-zero. Draw μ (k/8 bytes); `ct = Enc(pk, μ)`;
  `K = Hd("SILLAGE-KEM|ss", μ, ct; ss)`.
- **Decaps(sk, ct).** Let `ok = 1` and `ok = 0` if the padding bits of `u` or `v` are non-zero. `w' = v ⊕ (x·u restricted to n₂)`.
  Decode each 128·D-bit block of `w'`: `T[i] = D − 2·#{q : Q[q] = i, bit q set}`, apply the fast Walsh–Hadamard transform over
  128 points, take the first `u` maximising `|T[u]|`, and output the byte `u + 128·[T[u] < 0]`; this gives μ'. Recompute
  `ct' = Enc(σ_h ‖ s, μ')` and set `ok = 0` if `ct' ≠ ct`. Output `Hd("SILLAGE-KEM|ss", μ', ct; ss)` if ok, otherwise
  `Hd("SILLAGE-KEM|rej", σ_rej, ct; ss)`. The re-encryption is always computed and the choice is made by masking (constant time).

## 4. Sillage-SIG v0.4 (reference, superseded by § 4 bis)

*Since v0.5, the signature of the suite is § 4 bis. This section and its code (`sillage/sillage_sig.py`, `sillage/c/sig.c`,
`sl_sig_*`, `SillageSIG`) are kept unchanged as a reference.*

MPC-in-the-Head over binary syndrome decoding, hypercube sharing, five-pass Fiat–Shamir. This section fixes the parameters,
the hashing, the tree and the encodings. The share arithmetic of step 3 is given as formulas in PROOFS § 3.2; its exact
bit layout is the one of the reference implementation (`sillage/sillage_sig.py`, C `simuler` in `sillage/c/sig.c`).

### 4.1 Parameters

| | n | k | r = n − k | w | F_poly = GF(2^e) | K = GF(2^{ep}) | t | N = 2^D | τ | sb | hb |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Sillage-SIG-128 | 2 048 | 1 434 | 614 | 103 | e = 11, `X¹¹ + X² + 1` | ep = 44, `X⁴⁴ + X⁵ + 1` | 4 | 2¹² | 11 | 17 | 32 |
| Sillage-SIG-256 | 4 096 | 2 867 | 1 229 | 206 | e = 12, `X¹² + X³ + 1` | ep = 48, `X⁴⁸ + X⁹ + X⁷ + X⁴ + 1` | 4 | 2¹² | 23 | 33 | 64 |

The embedding `φ : F_poly → K` maps `X` to `g = 0x110004f8689` (resp. `0x1c48e8c6fad3`), a root in K of the defining polynomial of
F_poly. The point `f_i ∈ F_poly` is the element whose polynomial-basis representation is the integer `i`.

Byte lengths: `xb = ⌈k/8⌉`, `qb = ⌈w·e/8⌉`, `pts = ⌈t·ep/8⌉` (t elements of K, packed on `ep` bits each, little-endian bit order);
a **share** is `x_A ‖ Q ‖ P ‖ a ‖ b ‖ c` (`xb + 2·qb + 3·pts` bytes, unused bits zero); `aux` is `x_A ‖ Q ‖ P ‖ c` (`xb + 2·qb + pts` bytes).
Sizes: pk 109 / 186 B, sk 464 / 977 B, signature 8 522 / 34 867 B.

### 4.2 Keys

- `pk = seed ‖ y`, `seed` 32 bytes, `y ∈ GF(2)^r` on `⌈r/8⌉` bytes (non-zero padding is rejected).
- `H'` (r × k): column `j` is the first `⌈r/8⌉` bytes of `SHAKE256("SILLAGE-SIG|Hcol|" ‖ be64(j) ‖ "|" ‖ seed)`, bits `≥ r` cleared.
- Witness: `x = (x_A, x_B) ∈ GF(2)^k × GF(2)^r` of weight w with `x_B = y ⊕ H'·x_A`. KeyGen draws `x = Sparse(g, w, n, "SILLAGE-SIG|x")`
  (g random, 32 bytes), sets `Q = Π_{x_i = 1}(X + f_i)` (monic, degree w) and `P = Σ_{x_i = 1} Q/(X + f_i)` over F_poly, and
  `sk = x_A ‖ (q₀, …, q_{w−1}) ‖ (p₀, …, p_{w−1})` (coefficients on e bits each; the leading 1 of Q is implicit); `y = H'·x_A ⊕ x_B`.

### 4.3 Signing

With `pkh = Hd("SILLAGE-SIG|pkh", pk; hb)`, `mh = Hd("SILLAGE-SIG|msg", m; hb)`, a fresh 32-byte `salt`, and
`mseed = Hd("SILLAGE-SIG|mseed", sk, salt, mh; hb)`. Node messages:
`M_tag(i, s) = "SILLAGE-SIG|" ‖ tag ‖ "|" ‖ salt ‖ be32(rep) ‖ be32(i) ‖ s`.

For each repetition `rep < τ`:
1. **Tree.** Heap-indexed GGM tree, nodes `1 … 2N − 1`, leaf `i` at node `N + i`. Root seed
   `Hd("SILLAGE-SIG|r", mseed, be32(rep); sb)`; the two children of node `j` are the first `2·sb` bytes of `SHAKE256(M_a(j, s_j))`.
2. **Leaves.** Share `i` = first bytes of `SHAKE256(M_f(i, s_{N+i}))` (masked); commitment `com_i = SHAKE256(M_c(i, s_{N+i}))`
   (hb bytes) for `i < N − 1`.
3. **Correction.** With `Σ` the sum of the N shares: `aux = (x_A, Q, P) ⊕ Σ(x_A, Q, P)` and `aux_c = a·b ⊕ Σ c` (with `a, b`
   the summed a and b, product in K coordinate by coordinate); aux is added to share `N − 1` (fields x_A, Q, P, c);
   `com_{N−1} = SHAKE256(M_c(N − 1, s_{2N−1}) ‖ aux)`.
4. `hs_rep = Hd("SILLAGE-SIG|com", salt, be32(rep), com₀ ‖ … ‖ com_{N−1}; hb)`.

Then `h₁ = Hd("SILLAGE-SIG|h1", salt, pkh, mh, hs₀ ‖ … ‖ hs_{τ−1}; hb)`. **Challenge 1**: `Hd("SILLAGE-SIG|ch1", h₁; 12·τ·t)`, read per
(rep, j) as `r` = 6 bytes little-endian and `ε` = the next 6 bytes, each masked to ep bits.

For each repetition, **hypercube**: for `d < D`, side 1 is the sum of the shares whose index has bit d set, side 0 the rest; the total
(all shares) carries the public constants. Each side computes, linearly in its share, `α_s, β_s, v_s` as in PROOFS § 3.2. The
**broadcast** of a repetition is `α ‖ β ‖ (α₁^{(d)} ‖ β₁^{(d)} ‖ v₁^{(d)})_{d < D}` (each `pts` bytes), α and β being the opened totals.
`h₂ = Hd("SILLAGE-SIG|h2", salt, pkh, mh, h₁, broadcasts of all repetitions; hb)`. **Challenge 2**: `Hd("SILLAGE-SIG|ch2", h₂; 2·τ)`,
`i*_rep` = 2 bytes little-endian masked to D bits.

**Signature** `= salt ‖ h₁ ‖ h₂ ‖ ∏_rep (sibling seeds of the path of i*, from the leaf up (D × sb) ‖ com_{i*} ‖ aux ‖ α ‖ β)`,
with **aux = 0** when `i* = N − 1`.

### 4.4 Verification

Reject unless: the length is exact; the padding bits of `y`, and the unused bits of every `aux`, are zero; `aux = 0` whenever
`i*_rep = N − 1`. Recompute challenge 2 from h₂, every leaf except `i*` from the sibling seeds, the commitments (taking `com_{i*}`
from the signature) and `hs_rep`; for each `d`, simulate the side that does not contain `i*` and deduce the other
(`α_{1−s} = α ⊕ α_s`, `β_{1−s} = β ⊕ β_s`, and `v₀ ⊕ v₁ = 0`); recompute h₁ and h₂ and accept if and only if both equal the
signature's values (compared in constant time).

## 4 bis. Sillage-SIG v0.5: VOLE-in-the-Head over regular syndrome decoding

Implementation `sillage/c/vole.c` (C only, no Python reference); API `sl_vole_*` (`sillage.h`), `SillageVOLE` (`sillage/rapide.py`).
Security: PROOFS § 3 bis (Lemmas 17.1 and 17.2, Theorems 17 and 17-Q, Propositions 17.3 and 17.4). The exact bit layout of the
constraint polynomials (step 5) is the one of `contraintes_poly` / `contraintes_val` in `vole.c`; everything else is fixed below.

### 4 bis.1 Parameters

| Profile | id | λ | n | r = n − k | w | block b = Π μ | μ | d | τ | κ (N = 2^κ) | wpow | T_open | B | pk | sk | signature |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| VOLE-128 | 0 | 128 | 19 456 | 720 | 76 | 256 | (4,4,4,4) | 4 | 11 | 11 | 10 | 107 | 16 | 106 | 182 | 4 235 |
| VOLE-256 | 1 | 256 | 38 912 | 1 432 | 152 | 256 | (4,4,4,4) | 4 | 21 | 12 | 7 | 216 | 16 | 211 | 363 | 16 122 |
| VOLE-128f | 2 | 128 | 19 456 | 720 | 76 | 256 | (4,4,4,4) | 4 | 16 | 8 | 3 | 101 | 16 | 106 | 182 | 5 193 |
| VOLE-256f | 3 | 256 | 38 912 | 1 432 | 152 | 256 | (4,4,4,4) | 4 | 32 | 8 | 3 | 207 | 16 | 211 | 363 | 20 467 |

`r = ⌈log₂ C(n, w)⌉` rounded up to a multiple of 8 (Lemma 17.2). Field `GF(2^128) = F₂[x]/(x^128 + x^7 + x^2 + x + 1)`,
`GF(2^256) = F₂[x]/(x^256 + x^10 + x^5 + x^2 + 1)`; a byte string of λ/8 bytes is an element, bit i (little-endian within and across
bytes) being the coefficient of `x^i`. Seeds have `sb = λ/8 + 1` bytes, hashes `hb = 2λ/8`, the salt 32 bytes.

### 4 bis.2 Hashing

Every hash is SHAKE256 of `P ‖ dom ‖ fields`, with the 14-byte prefix `P = "SILLAGE-VOLE" ‖ 0x02 ‖ c`, where the profile byte is
`c = λ/64 + 64·[f profile]` (0x02, 0x04, 0x42, 0x44). Field lengths are fixed per profile and domain; the message is always last.

| dom | input fields | output |
|---|---|---|
| `H` | `seed_H` (λ/8), LE32(j), `seed_H` | column j of H′, r/8 bytes (j < k) |
| `m` | `enc(pk)`, message | `hm`, hb |
| `r` | positions (LE16 each), salt, `hm` | root seed, sb |
| `n` | salt, LE32(node), seed | the two child seeds, 2·sb |
| `l` | salt, LE32(leaf node), seed | `com` (hb) ‖ `r` (nb) |
| `c` | salt, LE32(e), the N commitments of repetition e | hb |
| `C` | salt, `hm`, the τ hashes of `c` | t, hb |
| `A` | t, `aux` | `h1`, hb |
| `M` | `h1` | the rows of M′ |
| `v` | `h1`, `ht` | `hv`, hb |
| `2` | `hv`, `ut`, `dw` | `h2`, hb |
| `g` | `h2` | γ: m elements of λ/8 bytes, `m = r + w·Σ_t (μ_t − 1)(μ_t − 2)/2` |
| `3` | `h2`, α | `h3`, hb |
| `d` | `h3`, LE32(ctr) | challenge: τκ bits, then wpow bits |

### 4 bis.3 Keys

`H = [H′ | I_r]`, `H′` expanded column by column from `seed_H` (domain `H`). The secret positions `p_1, …, p_w ∈ [0, 256)` are
drawn uniformly (16-bit draws, rejection below `65 536 mod b`), and `x` has a 1 at `(i − 1)·b + p_i`. `pk = seed_H ‖ y` with
`y = Hx` (r/8 bytes, row i = bit i); `sk = pk ‖ p_1 ‖ … ‖ p_w` (one byte each).

*Witness bits.* For block i, `p_i` is written in mixed radix `(μ_1, …, μ_d)`, most significant digit first. Digit t is
committed as `μ_t − 1` bits (bit k = [digit = k]). The bits of block i are at offset `i·Σ(μ_t − 1)`, digit-major. That is
`witb = w·Σ(μ_t − 1)` bits (912 and 1 824), padded with zeros to `witB` bytes.

### 4 bis.4 Signing

1. `salt` uniform; `hm = H_m(enc(pk) ‖ m)`; root `= H_r(pos, salt, hm)`.
2. **Tree.** Heap of `2L` nodes, with `L = τ·N`: node x has children `2x` and `2x + 1`, and the root is node 1. Children
   come from `H_n`. The leaf of repetition e and index i is node `L + i·τ + e`. Each leaf gives `(com, r) = H_l(salt, node, seed)`,
   where r has `nb = witB + (d − 1)·λ/8 + (λ + B)/8` bytes.
3. **VOLE.** `u_e = ⊕_i r_{e,i}`, `v_{e,b} = ⊕_{i : bit b of i = 1} r_{e,i}`. `aux_e = u_0 ⊕ u_e` for `1 ≤ e < τ`.
   `h1 = H_A(H_C(salt, hm, (H_c(salt, e, com_{e,0..N−1}))_e), aux)`.
4. **Consistency check.** M is read from `H_M(h1)`: `λ + B` rows of `⌈(8·nb − λ − B)/8⌉` bytes. Row ρ of `M·z` is
   `parity(row_ρ ∧ z[0, 8nb − λ − B)) ⊕ z[8nb − λ − B + ρ]`. `ut = M·u_0`, `ht_{e,b} = M·v_{e,b}`, `hv = H_v(h1, ht)`.
   `dw = wit ⊕ u_0[0, witb)`, with zero padding. `h2 = H_2(hv, ut, dw)`.
5. **Constraints.** `V_j = Σ_{e,b} bit_j(v_{e,b})·x^{eκ+b}`. The constraints of § 3 bis.1 are evaluated on `p_j(X) = w_j X + V_j`,
   homogenised to degree d and mixed by γ. The mask is `Σ_{t=1}^{d−1} (a_t X + b_t) X^{t−1}`, where `a_t` is section t of
   `u_0` after the witness and `b_t = Σ_l x^l V_{o_t + l}`. α is the d coefficients of degree `< d` (d·λ/8 bytes), and
   `h3 = H_3(h2, α)`.
6. **Grinding.** ctr is the smallest counter such that `H_d(h3, ctr)` has its wpow bits after the τκ challenge bits equal to zero,
   and the opening needs at most `T_open` nodes. Then `ch_e` = bits `[eκ, eκ + κ)` (the hidden leaf of repetition e), and
   `Δ = Σ bit_{eκ+b}·x^{eκ+b}`. The nodes to open are the siblings of the union of the hidden paths, in increasing order; their
   number is `|M| − 2τ + 1`.
7. **Signature** (fixed length): `salt (32) ‖ h3 (hb) ‖ aux ((τ − 1)·nb) ‖ ut ((λ + B)/8) ‖ dw (witB) ‖ α (d·λ/8)`
   `‖ opened nodes (T_open × sb, zero padding) ‖ hidden commitments (τ × hb) ‖ LE32(ctr)`.

### 4 bis.5 Verification

The verifier first rejects any of the following:
- a wrong length;
- a challenge that fails the grinding or opening rule;
- non-zero padding in `dw` or in the node slots.

It then rebuilds the opened subtree. For each repetition, it takes `q_{e,b} = ⊕_i ((i ⊕ ch_e)_b)·r_{e,i}`, with the hidden
leaf at zero, corrects it by `ch_{e,b}·aux_e` (e ≥ 1), and recomputes `h1`, `ht_{e,b} = M·q_{e,b} ⊕ ch_{e,b}·ut`, `hv`, `h2` and `h3`. It
rejects unless `h3` is equal. Finally, it checks `M(Δ) + Σ_j γ_j F_j(q) = Σ_l α_l Δ^l` with `q_j = V_j′ ⊕ Δ·dw_j`.

### 4 bis.6 Known answers

`tests/test_vole.py` and `prototypes/vole/vole_proto.c --kat`. The deterministic randomness is
`SHAKE256("SILLAGE-VOLE|kat" ‖ LE32(counter))`, starting from counter 0, for keygen and then the salt. The message is `"kat"`.
The answer is the first 16 bytes of `SHAKE256(enc(pk) ‖ σ)`:
VOLE-128 `8fabe81d59149d399137b2ee2726026a`, VOLE-256 `4de2f87cc8e8f3a7c8d62f6cf0aa536f`, VOLE-128f
`80bb49defc6b099c30746594c8a225cb`, VOLE-256f `677048f63679d5518fc4f5813821cc73`. They are identical on x86-64 and ARM64, with 1 and 12
threads.

### 4 bis.7 Normative annex: the constraint system

This annex defines step 5 of § 4 bis.4 and the final check of § 4 bis.5 completely. A second implementation, written from this
text only (`contraintes_annexe` in `prototypes/vole/vole_proto.c`, which uses neither the incremental tensor product nor the γᵀH
table of `vole.c`), gives the same coefficients as the library on valid and invalid witnesses, for the four profiles (control
`*_contraintes_conformes_a_l_annexe_normative`).

**Notation.** Arithmetic is in `F = GF(2^λ)` (§ 4 bis.1), where addition is XOR. `sw = Σ_t (μ_t − 1)` (12). Block
`i ∈ [0, w)` owns the witness bits `o_{i,t} + v`, with `o_{i,t} = i·sw + Σ_{t' < t} (μ_{t'} − 1)` for digit t and `v ∈ [0, μ_t − 1)`.
The witness bit is `b_j ∈ {0, 1}`; for the signer, `V_j ∈ F` is the VOLE tag of bit j (`V_j = Σ_{e,b} bit_j(v_{e,b})·x^{eκ+b}`).

**Digit polynomials.** These are degree-1 polynomials in F[X]:

```
P_{i,t,v}(X)      = b_{o+v}·X + V_{o+v}                          (v < μ_t − 1, o = o_{i,t})
P_{i,t,μ_t−1}(X)  = (1 ⊕ Σ_{v<μ_t−1} b_{o+v})·X + Σ_{v<μ_t−1} V_{o+v}
```

The last coordinate is not committed. On the verifier side, `P_{i,t,μ_t−1}(Δ) = Δ + Σ_v q_{o+v}`.

**Positions.** For `q ∈ [0, b)`, the digits are `δ_t(q) = ⌊q / Π_{t'>t} μ_{t'}⌋ mod μ_t` (most significant first). The polynomial of
position `j = i·b + q` is `Q_j(X) = Π_{t<d} P_{i,t,δ_t(q)}(X)`, of degree ≤ d, whose leading coefficient is the j-th bit of x when the
digits are one-hot.

**The m constraints and the order of γ.** `γ = (γ_0, …, γ_{m−1})` is read from `H_g(h2)`, λ/8 bytes per element, in this order:
1. `γ_ρ` for `ρ < r`: syndrome row ρ, `F_ρ(X) = Σ_{j<n} H_{ρ,j}·Q_j(X) + y_ρ·X^d`, where `H_{ρ,j}` is bit ρ of column j of H′
   for `j < k`, and `[ρ = j − k]` for `j ≥ k`;
2. then, for `i = 0, …, w − 1`, `t = 0, …, d − 1`, `0 ≤ v < x < μ_t − 1` (in this nested order), one element per pair:
   `F_{i,t,v,x}(X) = X^{d−2}·P_{i,t,v}(X)·P_{i,t,x}(X)`.

So `m = r + w·Σ_t (μ_t − 1)(μ_t − 2)/2` (1 632 and 3 256); every element of γ is used exactly once (checked: the count equals m).
All constraints are homogeneous of degree d. Their leading coefficients are `(Hx + y)_ρ` and `b_v·b_x`.

**Combined polynomial.** `C(X) = Σ_{k<m} γ_k·F_k(X) = Σ_{l=0}^{d} C_l X^l`, and `C_d = Σ_k γ_k·f_k(b)`, where `f_k` is the leading
coefficient of `F_k`.

**Mask.** Let `ω = 8·witB` be the first bit after the witness. For `t = 1, …, d − 1`:
- `a_t ∈ F` is the λ bits `u_0[ω + (t − 1)λ, ω + tλ)`, read as a field element;
- `b_t = Σ_{l<λ} x^l·V_{ω+(t−1)λ+l}`.

The mask is `M(X) = Σ_{t=1}^{d−1} (a_t X + b_t)·X^{t−1}`, of degree `≤ d − 1`.

**Response.** `α_l` = the coefficient of `X^l` in `C(X) + M(X)`, for `l = 0, …, d − 1`.

**Verification.** With `q_j` the verifier's tags (`q_j = V_j + Δ·b_j` for the witness bits, after the correction by `dw`;
`q_j = V_j + Δ·u_{0,j}` for the mask bits):

```
Σ_k γ_k·F_k(Δ; q) + Σ_{t=1}^{d−1} (Σ_l x^l·q_{ω+(t−1)λ+l})·Δ^{t−1}  =  Σ_{l<d} α_l·Δ^l
```

Here `F_k(Δ; q)` replaces each `P_{i,t,v}(Δ)` by `q_{o+v}`, and `P_{i,t,μ−1}(Δ)` by `Δ + Σ_v q_{o+v}`. The left-hand side equals
`C(Δ) + M(Δ)`. The check is therefore `C_d·Δ^d = 0`, i.e. `C_d = 0`, since `Δ ≠ 0` except with probability `2^{−τκ}`.

**What this guarantees** (proofs in PROOFS § 3 bis):
- *Completeness.* A valid witness gives one-hot digits, so `f_k(b) = 0` for every k and `C_d = 0`.
- *Soundness of the system (Lemma 17.1).* `f(b) = 0` for every k if and only if each block of x is one-hot over its 256 positions
  and `Hx = y`, i.e. x is regular of weight w.
- *γ.* γ is the output of the random oracle `H_g` on h2, which is fixed after the witness (`dw` is in its input): it is uniform and
  independent of `f(b)`. For `f(b) ≠ 0`, `Pr[C_d = 0] = 2^{−λ}`. This is the γ term of Theorem 17, executed on a reduced model.
- *Mask and zero knowledge.* `a_t` is uniform and used only here. `α_1, …, α_{d−1}` are therefore uniform, and `α_0` is fixed by the
  equation.
- *No unbound constraint.* Every one of the m constraints has its own coefficient, and γ is bound to the transcript through h2.

## 5. Conformance

- Python reference ↔ C: `tests/test_c_impl.py` (outputs compared byte for byte, all primitives), `tests/test_api_c.py` (public API).
- Known answers of § 2.8: `tests/empreintes.py` (written to `resultats/EMPREINTES.md`).
- The KEM and the signature have no fixed-seed key generation in the public API; their conformance is checked by running the same
  derandomised steps in both implementations (`tests/test_c_impl.py`).
