# BRUME with 8-bit S-boxes — idea note (nothing implemented, nothing measured)

Recorded on 2026-11-03. Everything below is reasoning from instruction throughputs measured on a Zen 3 (see
[`docs/LEADS.md`](../../docs/LEADS.md), lead 10) and from the AES wide-trail literature. It is **not** a measurement.

## The idea

Replace the 4-bit S-box over 128 nibbles (GF(16) coefficients, 6-regular Cayley graph of D₁₂₈) by an 8-bit S-box over
64 bytes (GF(256) coefficients, a similar weighted graph on 64 vertices, e.g. D₆₄). State size (512 bits), rate and
capacity are unchanged. This would be a new version (v1.0): outputs, KATs and proofs all change.

## Performance (estimates)

| Item | Now (4-bit) | 8-bit |
|---|---|---|
| S-box layer | 1 `vpshufb` per 32 nibbles | AES S-box in hardware: `vaesenclast` (VAES, ARM `aese`), 2 instructions for 64 bytes. A custom 8-bit S-box would cost ≈ 16 lookups and blends per register |
| Multiplication by a constant | log/exp tables: add, sub, min, `vpshufb` | GF(256): two table lookups (low and high nibble) and an XOR without GFNI; one `gf2p8mulb` with GFNI (Zen 4, Ice Lake and later), whose polynomial 0x11B is the AES one |
| Operations per round | ≈ 168 | ≈ 90 without GFNI, far fewer with it |
| Rounds | 32 | 11 to 16 for the same proved bound (see below) |

Expected gain on a single state: ×3 to ×4 without GFNI, more with it. The 4-bit design stays better on a CPU with neither
AES instructions nor GFNI, and in bitsliced code.

## Security (what changes)

- **For:** maximal differential probability 2⁻⁶ per active S-box instead of 2⁻²; strong linear resistance; a wide-trail
  argument as for the AES. At 4 active S-boxes per round, 24 proved bits per round instead of 8, hence about a third of the rounds.
- **Against:**
  - the inversion in GF(256) has a very studied algebraic structure (degree 7, 39 quadratic equations, a simple closed
    form); the current 4-bit S-box has no known structure;
  - the graph has to be redesigned and re-analysed from scratch: branch number, asymmetry (Weisfeiler–Lehman), symmetry tests;
  - the 2-round capacity recovery (`tests/c/brume_gd2.c`, ≈ 2⁹⁷) exploits the bipartite structure of the graph (all generators
    are reflections), which would remain;
  - the S-box would be the public AES one: the original-construction argument is lost.

## What it would invalidate

Every KAT; the proofs that depend on the S-box and the graph (Theorems 9 and 10, division-property reach, § 4.2 bis);
all the cryptanalysis tools (`tests/c/*`, `tests/gpu/*`, the SAT models); the GPU kernel (the ANF circuit no longer
applies; an 8-bit table in shared memory has bank conflicts).

## If it is ever tried

1. Pick the graph (64 vertices, degree 7) and compute its branch number with CP-SAT, as for the current one.
2. Write the AVX2 round (VAES + nibble-table multiplication) and measure cycles per state with
   [`../brume_bitslice/compteurs.h`](../brume_bitslice/compteurs.h), on an idle core.
3. Port to GFNI and measure on a machine that has it (the current one does not).
4. Only if the gain holds: redo the cryptanalysis (differential, linear, division property, invariants, guess-and-determine).
