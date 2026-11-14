# BRUME-1024q — domain separation

Written on 12 November 2026 (roadmap, priority 1). This table describes the prototype `brume1024.c` as it is; the
checks are part of its run (`separation_des_domaines_structurelle`, `kat_figes_*`).

## 1. State layout

The state is 128 bytes (1 024 bits):
- **rate**: bytes 0..79 (640 bits);
- **capacity**: bytes 80..127 (384 bits).

The profile frame occupies bytes 121..127 of the state before the first permutation (`cadre_iv()`):

| Byte | Value | Meaning |
|---|---|---|
| 121 | R (32) | number of rounds |
| 122, 123 | 0 | reserved |
| 124 | 160 | rate in nibbles |
| 125 | 0x10 | width 1 024 |
| 126 | `'q'` | quantum profile |
| 127, low nibble | 5 or 3 | **mode**: 5 = unkeyed sponge, 3 = AEAD |

**Domains** go in the high nibble of byte 127, a capacity byte. They are XORed into the state together with the last
block of each phase, just before its permutation. All other blocks carry domain 0.

## 2. Initial states (before the first permutation)

| Construction | State before the first permutation | Used by |
|---|---|---|
| Unkeyed sponge | 0^121 ‖ frame(mode 5) | XOF, single message, tree leaves, tree root (one P(IV) cached per profile) |
| AEAD (full-state keyed duplex) | key (bytes 0..63, rate) ‖ nonce (64..87: bytes 64..79 in the rate, **80..87 in the capacity**) ‖ 0^33 (88..120) ‖ frame(mode 3) | encryption, decryption, multi-message batches |

**The two states differ at byte 127 for every key and every nonce.** The key and nonce never reach bytes 88..127.
This is checked on extreme keys and nonces (all 0, all 0xFF, the bytes of the sponge state itself) and on random ones.
Guard bytes after the key and nonce buffers catch a copy that overruns.

## 3. Unkeyed sponge (mode 5)

- **Absorption.** Blocks of 80 bytes are XORed into the rate. The last block is padded with 0x01 then zeros
  (byte-level pad10*). Since this padding is injective and every message ends with a padded block, the sequence of
  blocks determines the message. The last block also receives the domain.
- **Squeezing.** 80 bytes per permutation.

| Domain | Value | Construction | Output |
|---|---|---|---|
| `DOM_SEQ` | 0 | sequential sponge, used as a XOF | any length |
| `DOM_FEUILLE` | 8 | tree leaf (8 192 bytes, the last one possibly shorter) | CV of 64 bytes |
| `DOM_RACINE` | 9 | tree root | default hash output (64 bytes) |
| `DOM_SEUL` | 10 | default hash of a message of at most 8 192 bytes (single leaf, no tree) | 64 bytes |

**Root message:** CV₁ ‖ … ‖ CV_k ‖ k (8 bytes, big-endian) ‖ 0x00 0x00 ‖ leaf size (2 bytes, big-endian, 0x2000), for
k ≥ 2 leaves.

- The default hash is `DOM_SEUL` up to 8 192 bytes, and the tree (leaves `DOM_FEUILLE`, root `DOM_RACINE`) above. A
  message is therefore hashed in exactly one of the two ways.
- `DOM_SEQ` = 0 is also the domain of non-final blocks. This is not ambiguous: the end of the input is marked by the
  padding, and the XOF is a separate function from the default hash, distinguished from it by its final domain (0
  against 9 or 10).

## 4. AEAD (mode 3)

| Phase | Blocks | Domain on the last block | Notes |
|---|---|---|---|
| Initialisation | P(key ‖ nonce ‖ 0 ‖ frame(3)) | — | 1 permutation |
| Associated data | XOR into the rate, pad 0x01 | `DOM_AAD` = 1 | always at least one block (an empty AAD gives a block holding only the padding) |
| Text | ciphertext = text ⊕ rate; the rate then holds the **ciphertext** (encryption: the plaintext is XORed; decryption: the rate is overwritten by the ciphertext), on full blocks and on the first ℓ bytes of the last block (0 ≤ ℓ < 80), whose remaining bytes keep the keystream; the last block then receives the pad 0x01. **SpongeWrap orientation since 13 November 2026** (`AEAD_SECURITY.md` § 6); before, the rate held the plaintext | `DOM_TEXTE` = 2 | always ends with a padded block |
| Tag | first 32 bytes of the rate, after the permutation of the last text block | — | no further permutation |

- The two end-of-phase domains are **non-zero and distinct**, and the phases always come in the same order. Each phase ends with exactly one tagged permutation call, so the phase boundaries can be read from the
  sequence of calls.
- Within a phase, the end of the data is marked by the padding.
- **No length block since 14 November 2026** (option A, `AEAD_SECURITY.md` § 6 bis). The length block (le64 of the text
  length, pad 0x01, domain `DOM_FINAL` = 4) was redundant with the padding of the text; it cost one permutation per
  message. The value 4 is no longer used in the AEAD. The lengths stay limited (`SPEC.md` § 3.5): that is a rejection
  rule, not an encoding.

## 5. Across constructions

- **Sponge and AEAD** start from different states for every key (§ 2). Sharing a permutation input between them would
  require an inner collision on a 384-bit capacity, or guessing the 512-bit key.
- **Within the sponge family**, two different functions on the same message differ in the capacity at their last
  absorption call (domains 0, 8, 9 and 10).
- The run checks this on 4 domains × 3 lengths around the rate (0, 79, 80 bytes): all 12 outputs are distinct.

## 6. What is checked

`separation_des_domaines_structurelle`:
1. mode and domain values are below 16 and pairwise distinct within each construction, and the AEAD domains are
   non-zero;
2. the AEAD initial state, for extreme and random keys and nonces, puts the key only in 0..63 and the nonce only in
   64..87, has the frame at 88..127, and differs from the sponge's initial state at byte 127;
3. the cached P(IV) equals the direct computation;
4. one message under four domains gives four distinct outputs, at three lengths.

`kat_figes_noyau_avx2`, `kat_figes_reference_dense`:
- 18 frozen KATs (`kat_b1024.h`, profile R = 32):
  - the default hash at 0, 1, 3 ("abc"), 79, 80, 81, 8 192, 8 193, 3·8 192 + 5, 100·8 192 + 77 and 300·8 192 + 5 bytes (the last
    one goes through the bitsliced 256-leaf batches on one thread, and through the 32-leaf batches on 12 threads: same value);
  - the XOF at 0 and 200 bytes, with 200 output bytes;
  - the AEAD at 0, 16, 64 and 1 000 bytes, plus 64 bytes without AAD, giving tag ‖ SHAKE256(ciphertext)[0..31].
  - History: on 13 November 2026 the 4 AEAD KATs with text changed with the SpongeWrap orientation, deliberately; the 14
    others did not.
- They are recomputed by the AVX2 kernel and, except the 100- and 300-leaf trees, by the dense reference (16 of 18). The tree reference
  `arbre_ref()` rewrites the root framing separately from `arbre()`.
- `brume1024 kat > kat_b1024.h` regenerates the file only if the kernel and the reference agree. It must not be rerun
  to make a check pass: a difference means the function changed.

**Mutation tests** (12 November 2026, on a copy): every one of the following is caught:
- one KAT character changed;
- AEAD text padding 0x01 → 0x02;
- nonce copied over 25 bytes;
- nonce placed at offset 100;
- AEAD mode equal to the sponge mode;
- `DOM_RACINE` equal to `DOM_FEUILLE`;
- leaf count of the root in little-endian in `arbre()` only.

**Not covered here:** the security argument itself (`AEAD_SECURITY.md`) and side channels (dudect and ctgrind, `README.md`).
