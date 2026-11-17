# Level 3: attack models for the full 32 rounds (BRUME-1024q)

> **v0.6 (17 November 2026).** This document now lives in `docs/brume1024/`. BRUME-1024q is the permutation of the suite: its code is `sillage/c/brume1024.c` and its checks are in the battery (`tests/c/brume1024.c`, `tests/c/brume1024_api.c`, `tests/test_b1024_*.py`). File names cited below without a path are documents of this folder (`*.md`) or tools of `prototypes/brume_q/b1024/` (programs, scripts, `dp1024/`, `gpu/`, `cm26_verif/`, …); `brume1024.c` meant the prototype, whose code is now the library.

Written on 17 November 2026 (ROADMAP § 3, "Level 3"). This is the argument that must come **before** any computation
aimed at 32 rounds: which oracle the attacker has, what he wants, what it costs generically, and therefore what would
count as a break. Nothing is computed here; the table of § 4 only gathers the measured reaches.

## 1. Oracles

| Oracle | What the attacker has | Secret |
|---|---|---|
| **O1, bare permutation** | P and P⁻¹ (32 rounds), evaluated at will | none |
| **O2, unkeyed modes** | the sponge hash, the XOF and the tree (SPEC.md §§ 3.2–3.4), hence P and P⁻¹ too | none |
| **O3, keyed AEAD** | Enc and Dec (sequential or parallel AEAD, SPEC.md § 3.5) under one or u keys, nonce-respecting, no release of unverified plaintext; P and P⁻¹ | 512-bit keys |

Quantum versions: O1 and O2 with quantum queries to P and P⁻¹; O3 in model Q1 (classical queries to the mode, quantum
queries to P). Q2 (superposition queries to the keyed mode) is not claimed (SPEC.md § 5) and is not a level-3 target.

## 2. Goals and generic costs (what an attack must beat)

| Oracle | Goal | Generic cost, classical | Generic cost, quantum |
|---|---|---|---|
| O2 | collision (any output, tree included) | 2^192 (birthday on c = 384) | 2^128 (BHT; proved ≥ 2^123.8 for a random permutation, `SPONGE_QROM.md`) |
| O2 | preimage, second preimage (512-bit digest) | 2^192 (the flat-sponge bound min(2^n, 2^{c/2}) with n = 512) | 2^128 (proved ≥ 2^124.1 for preimages) |
| O3 | forgery | q_d/2^256 per attempt; state or key recovery below | 2^128 (Grover on the tag) |
| O3 | inner-state recovery | N·σ_D ≈ 2^384 (Theorem 1′: (2σ_D + 5)·N/2^384), so 2^192 each with many decryption calls | 2^192 (Grover on the 384-bit inner part; Q1 bound, `AEAD_SECURITY.md` § 4 (d bis)) |
| O3 | key recovery | 2^512; Gilbert et al. 2^{3c/4} = 2^288 needs ciphertexts beyond the 64-bit length limit | 2^256 |
| O1 | distinguisher from a random permutation | none defined: P is public and fixed | — |

**The claim to test.** BRUME-1024q targets 128 bits of quantum security, and the generic classical costs above are at
least 2^192. A **level-3 break** is any of:

1. an attack on O2 or O3 below its generic cost in the table, classical or quantum;
2. a distinguisher on O1 whose cost is below **2^192 classical or 2^128 quantum**, the level the sponge claims; a
   property of P (zero sums, structured pairs) that needs more is a structural observation, not a break, and is
   recorded as such.

Costs are counted in evaluations of P (or P⁻¹), memory included at the same price, data and time not separated.

## 3. How a reduced-round result reaches 32 rounds

A reduced-round distinguisher at r rounds becomes a full-round attack only if the remaining 32 − r rounds are covered:

- **Free rounds.** A round whose effect is known can be added at no cost: the first constant addition, the linear layer
  of the last round (linear, public: an output condition can be moved through M⁻¹), and, in O2 and O1, rounds in which
  the attacker controls values (message modification at the start, inside-out from the middle).
- **Probabilistic rounds.** Extending a differential or linear distinguisher by k rounds costs the k-round probability,
  bounded by the certified active S-box counts (A(k) of `DIFF_LIN.md`): 2^{−2A(k)} for differences, 2^{−2A(k)} in data
  for correlations.
- **Key-recovery rounds** (O3 only). The key enters only the initial state (full-state keyed duplex); the attacker never
  sees a state next to the key except through 32 rounds of P, so no partial-key guessing round is available. The
  standard "add r rounds of key recovery" technique does not apply in this mode.
- **Inside-out.** For O1, a property can be built from the middle in both directions; the reach is the sum of the
  forward and backward reaches (the exact division property gives 22 or 23 rounds that way, below).

## 4. Reaches measured so far (updated on 17 November, after the algebraic, rebound and differential-linear studies)

| Family | Reach (rounds) | Kind | Where |
|---|---|---|---|
| Statistical battery, avalanche | 4 forward, 2 backward | measured | ROADMAP § 3 |
| Cubes, zero sums (measured) | 5 | measured | `resultats/cubes_1024q.md` |
| Exact division property | 11 backward, 11 or 12 forward; **22 or 23 inside-out** | proved / verified | `dp1024/` |
| Truncated differentials | free to 4; nothing found at 5–7 (model UNKNOWN, empirical scan conforming) | measured | `ETUDE_GROUPE_STRUCTURE.md` |
| Boomerang | 3 (2^−19.4); < 2^−32 at 4 | measured | ROADMAP § 3 |
| Impossible differentials, zero correlation | 5 | structural | ROADMAP § 3 |
| Differential-linear | 7–8 within 2^128 data, 8–9 within 2^192 (model, and model × 2^11 after the gap measured at 4 rounds); measured \|ε\| < 2^−11.4 at 5 and 6 | model + measured | `DIFF_LIN.md` |
| Collision of the sponge (rebound type) | 3 at about 2^92 (optimal in the model, validated on groups of up to 6 nibbles); 4 to 6 not found below 2^192, not excluded (lower bounds 88–140 bits) | model + measured | `REBOND.md` |
| Direct algebraic (CICO, SAT) | 3 with an advantage over brute force (4 with the linear-structure round) | measured | `ALGEBRIQUE.md` |
| Characteristics (any differential or linear trail) | none beyond 2^−448 / 2^−224 over 32 rounds (224 active S-boxes) | certified, Markov | README § 3 |

**Margin.** The largest reach is the inside-out zero-sum of the division property, 22 or 23 rounds, that is 9 or 10
rounds of margin. It is a structural property with a cost of about 2^1023 evaluations, far above 2^192: by the
definition of § 2 it is not a break. Among families that give attacks or distinguishers below 2^192, the largest reach
is 8 or 9 rounds (differential-linear, model; 9 with the pessimistic correction of `DIFF_LIN.md`), so a margin of
23 rounds or more.

## 5. What a level-3 campaign would do

Each item states the oracle, the goal, and the cost to beat.

1. **O2, collisions with more message freedom.** Multi-block rebound: use several blocks to pay for more rounds of the
   path (`REBOND.md` models only round 0). Target: the largest R with cost < 2^192; for 32 rounds, the path would need
   about 28 more rounds of probability, which the active S-box bound (A(28) ≥ 196, so 2^−392) excludes in the Markov model.
2. **O1, inside-out zero sums and cube attacks** at the 22–23 rounds of the division property: how many more rounds can
   be added with conditional cubes or linearisation of the first round (the trick of `ALGEBRIQUE.md`), and at what
   cost. A break needs 32 rounds below 2^192, which would need about 10 more rounds.
3. **O3, the keyed duplex.** All the attacker's data pass through 32 rounds of P between the key and any output. A
   distinguisher of P on less than 32 rounds gives nothing here unless it composes with the duplex calls (state
   recovery through repeated calls). Bound to beat: (2σ_D + 5)·N/2^384.
4. **Quantum versions** (O1, O2): Grover-accelerated versions of items 1 and 2, compared with 2^128.
5. **Third-party cryptanalysis.** The main missing item: everything above is our own analysis.

**Decision for now.** None of the items above is computed until the running studies (algebraic, rebound,
differential-linear) give their reaches: they set the starting points. Items 1 and 2 are the first to run then, since
they have the largest reach today.

**17 November: the three studies are done** (table of § 4). Starting points: rebound 3 rounds, with 4 to 6 not settled
by the search; differential-linear 7 to 9 rounds; algebraic 3 to 4; division property 22 to 23 (structural). None of
them comes near 32 rounds below 2^192. Items 1 and 2 are not started: they are research campaigns, and the next work
chosen is the implementation of the v0.6 modes, which does not depend on them.
