# BRUME with 8-bit S-boxes — design analysis (nothing implemented)

Recorded on 2026-11-03, revised the same day. S-box properties are computed exactly; instruction throughputs are
measured on a Ryzen 5 5600G (Zen 3); everything else (operation counts, round numbers, speed-ups) is an **estimate**.

## The idea

Replace the 4-bit S-box over 128 nibbles (GF(16) coefficients, weighted 7-regular Cayley graph of D₁₂₈) by an 8-bit
S-box over 64 bytes (GF(256) coefficients, a weighted graph on 64 vertices, e.g. D₆₄). State size (512 bits), rate and
capacity are unchanged. It would be a new version (v1.0): outputs, KATs and proofs all change.

## S-box properties (computed)

| | BRUME, 4 bits | AES, 8 bits |
|---|---|---|
| Differential uniformity | 4 (max DP 2⁻²) | 4 (max DP 2⁻⁶) |
| Maximal correlation | 2⁻¹ (ELP 2⁻²) | 2⁻³ (ELP 2⁻⁶) |
| Algebraic degree (S and S⁻¹) | 3 | 7 |
| Quadratic relations | 21 in 8 variables | 39 in 16 variables |

Each active S-box is worth 6 bits instead of 2, against differential and linear attacks alike.

## Rounds

- **Proved bound.** With a branch number of 8 over 2 rounds (to be checked for the new graph: it is at most 8, a column having 7
  non-zero terms), at least 4 S-boxes are active per round on average: 24 proved bits per round instead of 8, so 2⁻²⁵⁶
  after ≈ 11 rounds instead of 32.
- **But the round count is not set by that bound alone.** In the current design, the longest distinguisher is the integral one
  (division property: 10 rounds per direction, 20 inside-out out of 32). With degree 7 the degree grows faster, so the reach
  should shrink, but it has to be **computed** for the new graph. A reasonable target is 16 to 24 rounds, i.e. 1.3 to 2 times
  fewer than today, not 3.

## Performance (estimates; measured throughputs: `vaesenclast` ymm and `vpshufb` ymm 2 per cycle on Zen 3)

The S-box layer is cheap: the AES S-box comes out of `vaesenclast` (VAES, 64 bytes in 2 instructions; ShiftRows is folded
into the layout). An affine-equivalent S-box costs ≈ 8 more operations per register (affine maps on bytes by two nibble
lookups). A non-AES 8-bit S-box would need ≈ 16 lookups and blends per register.

**The linear layer is the crux.** BRUME's coefficients differ for every edge and every node (the source of its asymmetry:
128 Weisfeiler–Lehman colours). In a register, each byte must then be multiplied by **its own** constant.

| Kernel | 4 bits today | 8 bits | Verdict |
|---|---|---|---|
| One state, x86 **with GFNI** (Zen 4, Ice Lake and later) | 168 operations per round, ≈ 88 with GFNI (lead 10) | ≈ 62 per round (`gf2p8mulb` with per-byte constants, polynomial 0x11B = AES), on 16 to 24 rounds | **×3 to ×5** against today, ×1.5 to ×2.5 against 4 bits with GFNI |
| One state, x86 **without GFNI** (this Zen 3) | 168 per round | log/exp tables do not fit `vpshufb` (256 entries); per-byte constants need a bit decomposition, ≈ 32 operations per register and edge, ≈ 480 per round | **≈ 1.5 to 2 times slower** |
| Batches of 32 (one register = one position for 32 states) | 1 `vpshufb` per product, 896 products | constant per register: 2 `vpshufb` per product, 448 products, on fewer rounds | ×1.3 to ×2 |
| Bitsliced (256 states) | S-box 25 gates, ≈ 8 XORs per edge | AES S-box ≈ 113 gates, ≈ 32 XORs per edge: about twice the work per bit and per round | ≈ even |
| ARM NEON | `vqtbl1q_u8` | `vmull_p8` (per-lane carry-less product) and a reduction, ≈ 5 operations per 16 bytes | plausible gain |

The fast single-state case without GFNI only exists if the coefficients are the same for all nodes of a generator (then 2
lookups per register and edge). That is exactly what [`docs/LEADS.md`](../../docs/LEADS.md) advises against: it gives up the
asymmetry of the weighted graph.

## Security (what changes)

- **For:** 6 bits per active S-box instead of 2; faster degree growth (degree 7 in both directions), hence presumably fewer
  rounds of integral and cube distinguishers; an S-box (and a wide-trail argument) studied for 25 years.
- **Against:**
  - more algebraic structure: the inversion in GF(256) is x²⁵⁴ up to an affine map; AES has resisted algebraic attacks, but
    for an unkeyed permutation (hashing) this structure matters more than in a block cipher;
  - the graph on 64 vertices has to be designed and analysed again: branch number, asymmetry, symmetry tests;
  - independent of the S-box: the bipartite structure of the graph (all generators are reflections) would remain, together with
    the 2-round result (`tests/c/brume_gd2.c`);
  - the original-construction argument is lost if the S-box is the AES one.

## What it would invalidate

Every KAT; the proofs tied to the S-box and the graph (Theorems 9 and 10, division-property reach, § 4.2 bis); all
cryptanalysis tools (`tests/c/*`, `tests/gpu/*`, the SAT models); the GPU kernel.

## Recommendation

The decisive question is the target hardware. If BRUME must be fast on x86 processors without GFNI (Zen 2 and Zen 3,
Intel before 2019), the 8-bit version loses on the single-state path, which carries the sequential AEAD and hashing. If GFNI
can be assumed (x86 since about 2021, ARM with `vmull_p8`), it is the better design for speed. A cheaper first step either way:
GFNI for the current 4-bit design (lead 10, about ×2, no format change).

## If it is ever tried, in this order

1. Design the 64-vertex graph; compute its branch number (CP-SAT) and its division-property reach (the existing tools adapted): these
   numbers fix the round count, and the round count decides the performance.
2. Only then write the kernels: AVX2 + VAES with bit decomposition (this machine), GFNI (on a machine that has it), batches; measure
   with [`../brume_bitslice/compteurs.h`](../brume_bitslice/compteurs.h) on an idle core.
3. Only if the gain holds: redo the cryptanalysis (differential, linear, division property, invariants, guess-and-determine).
