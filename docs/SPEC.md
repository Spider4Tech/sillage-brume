# SILLAGE v0.4 — Specification

*Normative description of the algorithms, encodings and parameters, written for reviewers and for independent
re-implementation. Written on 2026-11-03 from the reference implementation (`sillage/*.py`), and cross-checked with the C library
(`sillage/c/`), which produces byte-identical outputs. Where this text and the reference implementation disagree, the
implementation defines v0.4 and the discrepancy is a bug in this document. Security arguments are not repeated here: see
[`PROOFS.md`](PROOFS.md).*

Status: research prototype, not for production. Outputs are frozen for v0.4 (any change alters the known-answer vectors).

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

The S-box, the group, the generators and the 128 × 128 coefficient matrix are **frozen tables**, produced once by a seeded search
(`sillage/select_params.py`) and stored in [`sillage/brume512_tables.py`](../sillage/brume512_tables.py) (SHA-256
`3c621e2c86896d46b198301afbe41dd374c7d9f7bd7b78473fa4117765c7c111`; the generated C header `sillage/c/brume512_tables.h` holds the same data).
`tests/test_select_params.py` reruns the search with its seeds and finds exactly these tables. It also checks the stated
selection criteria, and regenerates the C headers byte for byte.

- **S-box** `S = [8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5]` (differential uniformity 4, linearity 8, degree 3).
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
| `BRUME-512(0⁶⁴)` (all-zero state) | `2f886ce9014208dbb42ab871d3a95c7e80dfe9d1929b748b3465cb22582b8242881d0ac0af878e6f67d2308f1fb9ce7fa968c68fba9413a5b5ba606661cbd194` |
| `brume512_hash("", 32)` | `32880959113386339394dd1f4f4642f4a2468b4d95fd54ee2efbe2f5eacb3aac` |
| `brume512_hash("abc", 32)` | `ce516e8c2af5a81909dbfb9d59225809c86dfcb8e13998392962fd65691dd7bd` |
| `brume512_hash_arbre("abc", 32)` | `5dd1dcb0b955987a48097577392c12507b5c4f5726a5ba73687c45bb4496c115` |
| `brume512_hash_arbre("A" × 20000, 32)` | `a0794d96a006a9723120b7ac10b8105d11dcec41033937421a82539ce239757c` |
| BRUME-512, key `00…3f`, nonce `00…17`, AAD `"kat"`, plaintext `"SILLAGE"`: `ct ‖ tag` | `1e27b2f1c1e6f77ee42d609bce1c6643ec0525ab11e3fc` |
| BRUME-512-256, same inputs | `427ff953fff1f93cbef77913e008c9177ca55a11000c8ce385a4f05600ff1b2061a1c2caad70f6` |
| BRUME-512p, same inputs | `2bd5853b6dc2c65ab7b555e169695de65ecb2c365eaffa` |

All eight are produced identically by the Python reference and by the C library.

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

## 4. Sillage-SIG

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

## 5. Conformance

- Python reference ↔ C: `tests/test_c_impl.py` (outputs compared byte for byte, all primitives), `tests/test_api_c.py` (public API).
- Known answers of § 2.8: `tests/empreintes.py` (written to `resultats/EMPREINTES.md`).
- The KEM and the signature have no fixed-seed key generation in the public API; their conformance is checked by running the same
  derandomised steps in both implementations (`tests/test_c_impl.py`).
