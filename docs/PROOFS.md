# Security proofs — SILLAGE v0.6

*Section numbers are stable: the “PROOFS § n” references in the code point to this text.*

This document collects the statements and proofs behind the suite's claims.
Each statement gives its model (standard model, random oracle model ROM,
ideal permutation) and its assumptions. The corresponding numerical checks
are cited (`tests/…`). Every numerical instantiation in this text (Corollaries 11 and 14 bis and Theorems Q, 16 and P of § 4, the
tables of § 2.4, § 5 and § 5 bis) is recomputed from the constants of the code by
`tests/test_bornes_preuves.py`: if the code or the text changes without the other, the check fails.

Notation: `λ` security parameter; `negl` negligible; `wt` Hamming weight;
`R = F2[z]/(z^n − 1)`; `S_w^n` the set of vectors of weight w.

---

## 1. Assumptions

**Ring structure (parity invariant).** For an odd prime n,
`z^n − 1 = (z + 1)·Φ_n(z)` over F2. When 2 generates (Z/nZ)* (n an Artin
prime), Φ_n is irreducible and `R ≅ F2 × F_{2^{n−1}}`. The projection onto
F2 is evaluation at 1: `a(1) = wt(a) mod 2`. It is compatible with the
product, so for secrets of fixed weight w:

    s(1) = x(1)·h(1) ⊕ y(1) = (w mod 2)·(h(1) ⊕ 1),
    u(1) = r1(1)·h(1) ⊕ r2(1) = (w mod 2)·(h(1) ⊕ 1).

The parity of s and of u is therefore a public function of h and of the
(public) parity of w. It reveals nothing about x, y, r1, r2 beyond
w mod 2. But it makes **false** any assumption that compares s or u with
a uniform element of R: a distinguisher that tests the parity wins with
advantage 1/2. This is the case in HQC, whose decisional assumptions are
stated “with parity” (DQCSD-P). We do the same. v is not affected: it is
truncated to n₂ < n coordinates (n − n₂ = 21 349 and 55 315), and the sum
of the removed coordinates is unknown.

*History.* The initial v0.3 stated H1 and H2 without this constraint.
The flaw was raised by the external audit (point 1). It is checked by `tests/test_kem.py :: invariant_de_parite_*`.
It changes neither the scheme nor its outputs: it changes the statement of
the assumptions and the final game of the IND-CPA proof.

Write `R_β = {a ∈ R : a(1) = β}` for the set of elements of parity β, and
`β(h) = (w mod 2)·(h(1) ⊕ 1)`.

**(H1-P) Two-block decisional QCSD, with parity, on accepted keys.** For `h ← R`
uniform and `(x, y)` drawn as by `KeyGen` (uniform on `S_w^n × S_w^n`, conditioned on
acceptance in § 2.3), the pair `(h, x·h ⊕ y)` is indistinguishable from `(h, s)` with
`s ← R_{β(h)}` uniform.

*Why accepted keys (correction of 2026-11-02).* Acceptance E depends on (x, y), which
(h, s) determines. A statement about uniform secrets does not extend to accepted secrets: one only
gets `|Pr[D | E] − Pr_ideal[D]| ≤ (Adv + ε_rej)/(1 − ε_rej)`, and the additive term ε_rej
(7.1 % and 5.9 %, measured on 32 768 and 8 192 keys by `tests/c/kem_rejet.c`) is not negligible. The **search** form (recovering x, y) does transfer:
the conditioned distribution has density at most `1/(1 − ε_rej)` with respect to the uniform one, so
`Pr_E[A finds (x, y)] ≤ Pr[A finds (x, y)]/(1 − ε_rej)`. ISD costs remain valid on accepted
keys, up to log₂(1/(1 − ε_rej)) ≤ 0.11 bit. The decisional statement, for its part, is made on the
actual key distribution: the one that `tests/c/kem_distributions.c` tests (600 and 150 accepted keys).

*Rejection does not show in the public key* (`tests/c/kem_rejet.c`, a detection test). On 32 768 keys at 128 bits (2 330 rejected)
and 8 192 at 256 bits (487), drawn exactly as by `KeyGen`, none of the five non-linear statistics of s tested (weight,
transitions at steps 1 and 2, triples of ones, `wt(s ∧ z⁷s)`) separates accepted from rejected keys: |z| ≤ 1.79 against a threshold of 4.5, for a detectable
mean shift of 0.10 and 0.21 standard deviations of one key. The parity of s is the same for every key (Lemma 0). On the secret side, the
bound obviously separates the two classes (z = 151 and 77). This does not prove H1-P on accepted keys, but no trace of rejection appears.

**(H2-P) Truncated three-block decisional QCSD, with parity.** For `h ← R`
uniform, `s ← R_{β(h)}` uniform, `r1, r2 ← S_w^n` and `e = e1 ⊕ π(e2)`
(`e1, e2 ← S_we^{n2}`, π a public permutation), the quadruple
`(h, s, r1·h ⊕ r2, (r1·s)|_{n2} ⊕ e)` is indistinguishable from `(h, s, u, v)`
with `u ← R_{β(h)}` and `v ← F2^{n2}` uniform.

**(H3) SD (syndrome decoding) for the signature.** For `H = [H' | I]`, `H'`
uniform with `r` rows and `k` columns (derived from a public seed), and
`x ← S_w^n`, finding `x'` of weight ≤ w such that `H·x' = H·x` is hard.
The systematic form loses nothing (a random code reduces to it by elimination), and
`log₂ C(n, w) < r` makes the solution unique in general: weights < w add nothing.

**Lemma 0 (exact linear spectrum of H1-P and H2-P).** Let `h̄(z) = h(z^{−1})`,
`κ^{(N)}_w(t) = K_w(t)/C(N, w)` the normalised Krawtchouk polynomial (`= E[(−1)^{⟨a, x⟩}]` for
`x ← S_w^N` and `|a| = t`), and `b̃ ∈ R` the vector `b ∈ F2^{n2}` placed on the n2 kept positions.
For every h, every s, every permutation π and all `a ∈ R`, `b ∈ F2^{n2}`:

    x, y ← S_w^n :                 E[(−1)^{⟨a, x·h ⊕ y⟩}] = κ_w(|a|) · κ_w(|a·h̄|)
    r1, r2 ← S_w^n, e1, e2 ← S_we^{n2} :
        E[(−1)^{⟨a, r1·h ⊕ r2⟩ ⊕ ⟨b, (r1·s)|_{n2} ⊕ e1 ⊕ π(e2)⟩}] = κ_w(|a|) · κ_w(|a·h̄ ⊕ b̃·s̄|) · κ_we^{(n2)}(|b|)²

*Proof.* `⟨a, r·h⟩ = Σ_k a_k Σ_i r_i h_{k−i} = ⟨a·h̄, r⟩`, and likewise `⟨b, (r1·s)|_{n2}⟩ = ⟨b̃·s̄, r1⟩`,
`⟨b, π(e2)⟩ = ⟨π^{−1}(b), e2⟩` with `|π^{−1}(b)| = |b|`. The exponent is therefore
`⟨a·h̄ ⊕ b̃·s̄, r1⟩ ⊕ ⟨a, r2⟩ ⊕ ⟨b, e1⟩ ⊕ ⟨π^{−1}(b), e2⟩`, a sum of forms in independent
secrets: the expectation is the product of the four factors. (H1-P: likewise with x, y.) ∎

*Corollary (the only linear invariant, at every size).* For `0 < w < n`, `|κ_w(t)| = 1` if and
only if `t ∈ {0, n}`. (H1-P): a test with bias ±1 requires `a, a·h̄ ∈ {0, 𝟙}`, hence `a ∈ {0, 𝟙}`:
this is the parity of s, with sign `(−1)^{β(h)}`, which the ideal distribution `R_{β(h)}` reproduces exactly. (H2-P),
for `0 < we < n2 < n` and n an Artin prime: one needs `a ∈ {0, 𝟙}`, `b ∈ {0, 𝟙}` and
`a·h̄ ⊕ b̃·s̄ ∈ {0, 𝟙}`. For `b = 𝟙`, this forces `b̃·s̄ ∈ {0, 𝟙}`, i.e. `b̃·s̄ ≡ 0 mod Φ_n` (since
`𝟙 = Φ_n`). As `F2[z]/Φ_n` is a field and `b̃ ∉ {0, 𝟙}`, this gives `s̄ ≡ 0`, that is
`s ∈ {0, 𝟙}`, which happens with probability `2^{−(n−1)}` for `s ← R_{β(h)}`. Outside this case, only the
parity of u is invariant. The rank measurement on reduced instances becomes a theorem.

*Reading.* A linear distinguisher for (H1-P) needs an a such that a and a·h̄ are both far from weight
n/2: a low-weight codeword of the code `{(a, a·h̄)}`, hence a decoding problem. For (H2-P),
a low-weight codeword of `{(a, b, a·h̄ ⊕ b̃·s̄)}`. Estimating the cost of that codeword with Prange
(p = 1) and the advantage with the bias, rotations of a included (`tests/c/h1p_fourier.c`, **heuristic**),
gives log₂(cost/advantage) ≈ 139.1 (H1-P) and 138.8 (H2-P) for Sillage-128, and 268.0 and 267.2 for
Sillage-256: of the same order as ISD (138.2 and 265.1), and not below. The lemma itself is
checked coefficient by coefficient, in integers, on exhaustive reduced instances.

The best known algorithm for (H1-P), (H2-P) and (H3) is ISD. The
parity constraint fixes only one public bit: it does not change ISD
costs. The costs are
estimated by `sillage_common.isd_estimate` (optimised Prange, Stern, Dumer,
BJMM, see § 5). For (H2-P), the three-block attack with unequal densities is
also taken into account (`SillageKEM.security_estimate`); it gains nothing over
two blocks. The values are checked by `tests/test_isd_parametres.py`.

---

## 2. Sillage-KEM

### 2.1 The underlying encryption scheme PKE

`KeyGen`: `x, y ← S_w^n` (rejected if the bound of §2.3 exceeds `2^−λ`),
`pk = (σ_h, s = x·h ⊕ y)`. `Enc(pk, μ; ρ)`: `(r1, r2, e1, e2) = Exp(ρ)`,
`u = r1·h ⊕ r2`, `v = cw(μ) ⊕ (r1·s)|_{n2} ⊕ e1 ⊕ π(e2)`. `Dec`:
maximum-likelihood decoding of `v ⊕ (u·x)|_{n2}`. The code `cw` carries one byte of μ per
block of `L = 128·D` bits (§2.3).

**Theorem 1 (IND-CPA).** Under (H1-P) and (H2-P), PKE is IND-CPA:
`Adv^{IND-CPA}_{PKE}(A) ≤ Adv^{H1-P}(B1) + Adv^{H2-P}(B2)`
(`Adv^{IND-CPA} = |Pr[b' = b] − 1/2|`, as in HHK17; that of a distinguisher, `|Pr[1 | real] − Pr[1 | ideal]|`).

*Proof.* Game 0: the real IND-CPA game, accepted keys. Game 1: `s` is replaced by a
uniform element of `R_{β(h)}`. B1 receives (h, s), draws b, simulates the challenge and returns [b' = b]; the
difference is bounded by (H1-P), stated on the distribution of accepted keys: no rejection factor
appears. Game 2: `(u, (r1·s)|_{n2} ⊕ e)` is replaced by
`(u, v')` with `u ← R_{β(h)}` and `v'` uniform. The difference is bounded
by (H2-P), since `s` now follows exactly the distribution of (H2-P). In
Game 2, `u` depends only on h, and `v = cw(μ_b) ⊕ v'` is uniform and
independent of b: the advantage is zero. ∎

*Check of the algebra used by the games* (`tests/test_kem_lemme3.py`): on real encapsulations, with the coins recomputed
from (μ, H(pk)), `v ⊕ (u·x)|_{n2} ⊕ cw(μ)` equals `(r1·y ⊕ r2·x)|_{n2} ⊕ e1 ⊕ π(e2)` bit for bit: the terms `r1·x·h` cancel
and the noise does not depend on μ.

*Correction (2026-11-02).* The previous version bounded Game 1 by `Adv^{H1-P}/(1 − ε_rej)`, with
H1-P on uniform secrets. That factor holds for a search event, not for a distinguishing
advantage (see “Why accepted keys”, § 1): the correct bound would have a non-negligible additive
term ε_rej. H1-P is now stated on the actual key distribution.

Since `|M| = 2^k ≥ 2^λ`, we also have
`Adv^{OW-CPA} ≤ Adv^{IND-CPA} + 2^{−k}`.

### 2.2 FO transform with implicit rejection

The KEM is exactly `U^⊥̸(T[PKE, G], H)` in the sense of Hofheinz–Hövelmanns–
Kiltz (TCC 2017):

- `T`: derandomised encryption, with `ρ = G(μ, H(pk))` (`SILLAGE-KEM|coins`);
- `U^⊥̸`: `K = H(μ, ct)` (`SILLAGE-KEM|ss`). On a decoding failure
  **or** a mismatch at re-encapsulation, `K = H'(σ_rej, ct)`, where `σ_rej` is
  a 256-bit secret seed and `H'` is domain-separated;
- non-canonical encodings (`u ≥ 2^n`, `v ≥ 2^{n2}`) are rejected.

**Theorem 2 (IND-CCA, ROM).** If PKE is δ-correct and IND-CPA, then for
every IND-CCA adversary `A` making `q_G`, `q_H` oracle queries and
`q_D` decapsulation queries, there is `B` with the same running time such that

```
Adv^{IND-CCA}_{KEM}(A) ≤ 2·q_G·δ + 3·Adv^{IND-CPA}_{PKE}(B)
                         + (2q_G + q_H + 1)/2^k + q_H/2^{256}
```

(HHK17, Th. 3.2 for `T` and Th. 3.4 for `U^⊥̸`, composed; the exact
constants are detailed there). In the QROM, the same scheme falls under the theorems of
Bindel–Hamburg–Hövelmanns–Hülsing–Persichetti (TCC 2019) for `FO^⊥̸`, with
a quadratic loss.

*Conditions for applying the theorem, all checked:*
1. Deterministic encryption, randomness derived from μ: `SillageKEM._encrypt`.
2. Full re-encapsulation and comparison of `(u, v)` in `decaps`:
   `tests/test_kem.py :: fo_rejette_chiffres_non_honnetes`.
3. Deterministic implicit rejection, bound to the ciphertext and without exceptions:
   `rejet_implicite_deterministe`, `entrees_malformees_sans_exception`.
4. Proved δ-correctness: §2.3.

The IND-CCA reduction is unchanged: it only relies on the IND-CPA
security of PKE.

With `k = λ` and `δ ≤ 2^{−λ}` (§2.3), the term `2·q_G·δ` stays negligible
as long as `q_G ≪ 2^{λ−1}`.

**Implementation requirement.** The reduction assumes that the adversary
learns nothing beyond the output of Decaps. A decapsulation that
skipped re-encapsulation after a decoding failure would reveal that
failure through its response time: this is the oracle of reaction attacks
(Guo–Johansson–Stankovski 2016). Both implementations therefore always
re-encapsulate and select the secret with a mask (check:
`tests/test_c_temps.py`).

### 2.3 Proved δ-correctness (Chernoff bound certified per key)

`δ = E_{(pk,sk)} [ max_μ Pr_ρ [ Dec(sk, Enc(pk, μ; ρ)) ≠ μ ] ]`.

**The code.** Bit q of a block carries `b ⊕ ⟨u, P[q]⟩`, for the byte of μ `u | b << 7` (u on 7
bits). `P` is public: Fisher–Yates on `[0, 128·D)` (domain `SILLAGE-KEM|rm`), reduced modulo
128; each value of `[0, 128)` therefore has exactly D positions. This is RM(1,7) repeated D times and
spread pseudo-randomly. Decoding computes the Walsh transform of the 128 sums and
keeps the largest magnitude (on ties, the smallest u).

*Why `P`.* Without it, the supports S below are dense or periodic windows, and
the certified bound loses up to 30 bits (measured). The security of (H2-P) does not depend on it: `cw`
is public, and the IND-CPA proof masks it with a uniform `v'`.

**Lemma 3.** Let `S_{u,b} = {q : ⟨u, P[q]⟩ = b}`, `u ≠ 0`, `|S| = 64·D` (254 sets).
Decoding a block fails only if the noise has at least `32·D` bits on one of the `S_{u,b}`. And
for every `S`, this number of bits is at most `T1 + T2 + Te`, with `T1 = Σ_{a∈r1} |(S − a) ∩ y|`,
`T2 = Σ_{a∈r2} |(S − a) ∩ x|`, and `Te` the number of bits of `e1` and of `π(e2)` that fall in S.

*Proof.* The noise is `N = v ⊕ (u·x)|_{n2} ⊕ cw(μ) = (r1·y ⊕ r2·x)|_{n2} ⊕ e1 ⊕ π(e2)`, since the terms
`r1·x·h` cancel; it does not depend on μ. If another codeword c' is as close as the right codeword c,
`|S| − 2·wt(N ∩ S) ≤ 0` for `S = supp(c ⊕ c')`. If c and c' differ in u, S is an `S_{u,b}`. Otherwise
S is the whole block, with noise ≥ L/2, and one of the two halves `S_{u,0}`, `S_{u,1}` has at least `|S_{u,b}|/2`
bits, for every u. Finally, bit j of `r1·y` is the parity of the number of pairs
`(a, b) ∈ r1 × y` with `a + b ≡ j`: the number of bits set in S is at most the number of pairs that
fall in it, that is `T1`; likewise for `r2·x`, `e1`, `π(e2)`. ∎

*Check* (`tests/test_kem_lemme3.py`, added on 2026-11-05). P places each value of [0, 128) exactly D times, and the 254 sets
have 64·D bits. On real encapsulations of both levels, `wt(N ∩ S) ≤ T1 + T2 + Te` holds for each of the 254 sets of each block,
with T1, T2 and Te counted pair by pair. Without T2 the inequality fails on every encapsulation (witness: the check can fail).
On blocks with heavy noise (40 to 52 % of the bits), every wrongly decoded block has at least 32·D noise bits on some `S_{u,b}`,
and the decoder always returns a codeword at minimum distance (brute force over the 256 codewords of the block). A noise of exactly
32·D bits placed on the difference of two codewords makes decoding fail: the threshold of the lemma is reached. The margin returned
by `rm_decode` equals `max_S wt(N ∩ S) − 32·D`.

**Theorem 4.** Let `c_{y,S}(s) = |(S + s) ∩ y|`, `M_{y,S}(θ) = (1/n)·Σ_s e^{θ·c_{y,S}(s)}` (likewise
for x), and `p_e = |S|/n2`. For every `θ > 0`,

```
Pr[failure] ≤ (k/8) · 254 · max_S exp( −θ·32·D + w·ln M_{y,S}(θ) + w·ln M_{x,S}(θ)
                                       + 2·we·ln(1 + p_e(e^θ − 1)) ).
```

*Proof.* `r1` is a set of w distinct positions, uniform over `Z_n`: the coins come
from the oracle G. As a ranges over `Z_n`, `S − a` ranges over all translates of S: `|(S − a) ∩ y|`
follows the distribution of `c_{y,S}`. `T1` is therefore a sum of w draws **without replacement** from the multiset
`{c_{y,S}(s)}`. By Hoeffding's Theorem 4 (1963), `E[e^{θ T1}] ≤ M_{y,S}(θ)^w`. The same holds for
`T2`, and for `Te` with 2·we indicators of probability `p_e` (π is a bijection of positions).
`T1`, `T2`, `e1`, `e2` are independent. Markov is applied to `e^{θ(T1+T2+Te)}`. A block j shifts S by
`j·L`, which does not change the multiset (a ranges over all of `Z_n`), hence the union over the 254 sets
and the k/8 blocks. The bound holds for every μ. ∎

*Implementation.* `borne_echec_log2` and `sl_kem_borne` evaluate the bound at a fixed public θ (`theta = 0.7`),
for the 254 sets, replacing `e^{θc}` with `⌈2^{12}·e^{θc}⌉/2^{12}`, which upper-bounds it, and rejecting
any key with some `c > 15`. The C code computes the `c` values by a Walsh transform on registers, without
any key-dependent branch or memory access (Valgrind); only the worst product `M_x·M_y` is made
public. `keygen` rejects any key whose bound exceeds `2^{−λ}`. Hence **δ ≤ 2^{−λ} is proved** for the
distribution of keys produced. Medians measured on raw keys (`resultats/kem.json`): `2^{−146}` and `2^{−289}`; rejections 7.1 % and 5.9 % (`tests/c/kem_rejet.c`).

*Choice of θ (sensitivity, `python3 -m tests.test_kem_theta 3000 1500`, 3 000 and 1 500 raw keys; the battery runs 2 000 and 800).* Theorem 4 holds for every θ > 0, so
θ affects only the rejection rate and the reported bounds, never the guarantee δ ≤ 2^{−λ} for accepted keys. The sweep
reuses the per-support histograms of `c` (they do not depend on θ) and reproduces `borne_echec_log2` at θ = 0.7 to
10^{−13} bits.

| | Sillage-128 | Sillage-256 |
|---|---|---|
| rejection at θ = 0.7 | 6.4 % ± 0.45 | 5.8 % ± 0.6 |
| θ minimising the rejection (grid step 0.01) | 0.68–0.69 (6.33 %) | 0.68 (5.73 %) |
| window within 1 point of the minimum rejection | 0.65–0.75 | 0.64–0.73 |
| rejection at θ = 0.6 / 0.8 / 0.9 | 12.5 / 9.3 / 17.0 % | 9.9 / 10.3 / 20.5 % |
| rejection with θ optimised key by key | 6.30 % | 5.73 % |
| median bound at θ = 0.7 / per-key θ* | 2^{−147.3} / 2^{−152.3} | 2^{−288.6} / 2^{−293.6} |
| θ* per key: median (5 %–95 %) | 0.84 (0.68–0.99) | 0.80 (0.68–0.92) |
| θ* of keys within 8 bits of the threshold: median (5 %–95 %) | 0.71 (0.66–0.75) | 0.69 (0.66–0.71) |
| rejection with θ chosen per support before the union | 4.97 % | 4.93 % |

The bound is convex in θ, and θ* is where the tilted mean of `T1 + T2 + Te` reaches `|S|/2`. For a typical key,
`c(s)` is close to Poisson and `e^{θ*} ≈ (|S|/2)/E[T]`, which gives θ* ≈ 0.8. Keys with heavier tails reach the threshold
at a lower θ. Those keys decide rejection, and their θ* is 0.7: θ = 0.7 sits at the minimum of the rejection rate. It
costs 0.1 point against a per-key θ (+0.001 keygen draw on average) and about 5 bits on the *median* bound, which no
guarantee uses. The minimum is sharp. Moving to 0.6 or 0.8 multiplies rejections by 1.5 to 2, and at θ ≤ 0.5 almost every
key is rejected. Three further facts bound the choice:
- The integer table `⌈2^{12}·e^{θc}⌉/2^{12}` raises the bound by at most 0.036 bit, always upwards.
- No key out of 4 500 hit `c > 15`.
- `sl_kem_borne` stores `T[15]` in a `uint32`, so θ must stay below `ln((2^{32} − 1)/2^{12})/15 = 0.924`. Above that
  value the conversion overflows.

The only remaining gain allowed by the proof is a θ per support, which takes rejection from 6.3 % to 5.0 % (128) and from
5.7 % to 4.9 % (256). It would need a few tables in constant time, and it does not change any parameter.

*v0.3 correction.* v0.2 justified correctness with a Gaussian z-score
(bits assumed independent). The proved bound above shows that the
old parameters only guaranteed about `2^{−60}` to `2^{−75}`. The
resizing (§5) restores `δ ≤ 2^{−λ}`.

*v0.4 change: the repetition code `[k·d, k, d]` (`d = 531` and `953`) becomes this code.* Lemma 3 and
Theorem 4 keep their form (a group G becomes a support S, and 2 more hyperplanes per block only
cost a few bits in the union): δ remains proved, with no independence assumption. The gain comes from
a block of L bits decoding 8 bits, with the robustness of a repetition of L/2 bits for a single one.

*What the proof rules out.* `T1 + T2 + Te` ignores XOR cancellations: it requires a pair density
`2w²/n < 1/2`, hence `n ≈ 50 000` at w = 75. HQC-128 (4.4 KB, `n = 17 669`) works at a density of 0.62 with
an outer Reed–Solomon code, and its failure rate relies on an assumption of independent positions,
the one removed from v0.2. A martingale bound that accounts for cancellations
(`W = Σ_S (−1)^{N_i}`, exact contraction, Bennett's inequality) was evaluated: it only gains for
small S and does not improve these parameters. An outer code would need a joint bound over several blocks,
which the per-key computation does not provide. See `docs/LEADS.md`, lead 8.

### 2.4 Several keys and several ciphertexts

The theorems above target one key and one challenge ciphertext. With n keys and N challenge ciphertexts, the standard hybrid argument
multiplies the advantage by n·N at most. What matters is the actual gap, term by term.

- **Several keys.** Each key has its own `σ_h` (hence h), `σ_rej` and `(x, y)`; `ρ = G(μ, H(pk))` ties the coins to the public key.
  - *ISD:* attacking n keys at once costs no less than attacking one: the codes differ, no elimination is shared, and
    succeeding on one of the n after T iterations in total amounts to the single-key case. No known gain.
  - *Decryption failure:* δ ≤ `2^{−λ}` holds for **each** accepted key (§ 2.3); the term `q·δ` stays at worst `q·δ` in total, the
    queries being spread over the keys.
- **Several ciphertexts under one key.** This is where the loss is.
  - *Exhaustive search on μ:* encapsulation is deterministic in μ and `|M| = 2^k` with k = λ. An attacker holding N ciphertexts of
    the same key draws μ, recomputes `ct(μ)` and looks it up in a table of the N: cost `2^k/N` classically, `√(2^k/N)` with Grover. This is
    the `q/|M|` term of the bounds, multiplied by N. `H(pk)` in G prevents sharing this computation across keys.
  - *Decoding:* the N ciphertexts share the same code (same h); “decoding one out of many” (Sendrier) gains at most ≈ `√N` on the ISD cost
    of one ciphertext.

| N ciphertexts under one key | Sillage-128, classical / quantum | Sillage-256, classical / quantum |
|---|---|---|
| 1 | 128 / 64 | 256 / 128 |
| 2^32 | 96 / 48 | 224 / 112 |
| 2^64 | 64 / 32 | 192 / 96 |

(log₂ of the cost of the search on μ; decoding, ≈ 137 − ½·log₂ N classical bits at 128 bits, stays above.) Sillage-128 thus loses
log₂ N bits in the multi-ciphertext setting, like any FO-derived KEM whose message space has λ bits. If this model matters, k = 256 restores
the level: the v part of the ciphertext would go from `16·128·14` to `32·128·14` bits (≈ +3.6 KB, ciphertext ≈ 13.4 KB), with the δ bound to be redone.
This change is not made: it would alter the format.

---

## 3. Sillage-SIG

MPC-in-the-Head in the style of SDitH (Feneuil–Joux–Rivain, CRYPTO 2022), with hypercube sharing
(Aguilar-Melchor et al., EUROCRYPT 2023), over **binary** syndrome decoding (H3). This section
replaces the Stern protocol (v0.3, 134 and 536 KB), withdrawn in v0.4: the hard problem is the same, and
no new assumption is introduced (no rank metric, no restricted errors, no larger field).

### 3.1 Witness

`n = 2^e`, `F_poly = GF(2^e)`, `f_i` the element whose binary expansion is i, `F(X) = X^n + X = Π_i (X + f_i)`. Hence
`F'(f_i) = 1`. For `x ∈ F2^n`, S is the polynomial of degree < n with `S(f_i) = x_i`.

**Lemma A.** If `H·x = y` and `wt(x) ≤ w`, there exist a monic Q of degree w and P of degree < w such that
`S·Q = P·F`. Conversely, if `x_B = y + H'·x_A` and `S·Q = P·F` with Q monic of degree w, then
`H·x = y` and `wt(x) ≤ w`.

*Proof.* Forward direction: `Q = Π_{x_i=1}(X + f_i)` (completed to reach degree w) makes `S·Q` vanish on all of
`F_poly`, so F divides `S·Q`, of degree < n + w. Converse: `S(f_i)Q(f_i) = P(f_i)F(f_i) = 0`, so `x_i = 1`
implies `Q(f_i) = 0`, and Q has at most w roots. ∎

Implementation: `P = Σ_{x_i=1} Q/(X + f_i)` (since `F'(f_i) = 1`). Secret key `sk = x_A ‖ Q ‖ P`, without the leading
coefficient: `(xb + 2·qb)` bytes. Check: `tests/test_sig.py :: temoin_*_bien_forme`.

### 3.2 One repetition

`K = GF(2^{ep}) ⊃ F_poly`, with an embedding φ fixed by a root of the polynomial defining `F_poly`. `N = 2^D` leaves, a
GGM tree of seeds of `sb` bytes: `(children) = H_a(salt, rep, j, node)`.

1. *Shares.* Share of leaf i: `H_f(salt, rep, i, s_i) = (x_A, Q, P, a, b, c)_i`, with `a, b, c ∈ K^t`.
   `aux = (x_A, Q, P, a·b + c) + Σ_i (x_A, Q, P, c)_i`, added to leaf N − 1. Commitments
   `com_i = H_c(salt, rep, i, s_i)`, and `H_c(salt, rep, N−1, s_{N−1}, aux)` for the last one. The shares sum to the witness
   and to a triple `c = a·b`.
2. *Challenge 1.* `(r_j, ε_j) ∈ K²`, `j < t`.
3. *Hypercube.* For `d < D`, side 1: sum of the shares whose bit d is 1; side 0: the rest, which carries the constants
   (`y`, the leading coefficient `r^w`, and `α·β`). Each side computes, linearly in its share:
   `x_B = H'·x_A`, `S(r) = Σ_i x_i·L_i(r)` (`L_i(r) = F(r)/(r + f_i)`, and the unit vector if `r ∈ F_poly`), `Q(r)`, `P(r)`,
   ```
   α_s = ε·Q_s(r) + a_s,   β_s = S_s(r) + b_s,   v_s = c_s + α·b_s + β·a_s + ε·F(r)·P_s(r) (+ α·β on side 0).
   ```
   Broadcast: `(α, β)` opened and `(α_1, β_1, v_1)^{(d)}` for each d.
4. *Challenge 2.* `i* ∈ [0, N)`.
5. *Response.* The D sibling seeds of the path to `i*`, `com_{i*}`, `aux`, `α`, `β`, with `aux = 0` if `i* = N − 1`: the only share
   it corrects is then hidden, and the verifier does not use it. Any other value is rejected (unique encoding, Proposition 9).
   The verifier recomputes every share except `i*`. For each d, it simulates the side that does not contain `i*`, deduces the other (`α_{1−s} = α + α_s`,
   `v_{1−s} = v_s`, since `v_0 + v_1 = 0`), recomputes the commitments and broadcasts, and compares the hashes.

**Proposition 5 (completeness).** `(εQ + a)(S + b) = εQS + εQb + aS + ab`, so in characteristic 2,
`v_0 + v_1 = c + αb + βa + εF·P + αβ = ε(S·Q + P·F) + (a·b + c) = 0` for a witness. Checked by `verification`.

**Lemma 6 (false positive).** Fix shares summing to `(x̃_A, Q̃, P̃, a, b, c)`, with no witness (Lemma A:
`T = S̃Q̃ + P̃F ≠ 0`, of degree < n + w). Then, over uniform `(r, ε)`,
`Pr[∀j : ε_j T(r_j) + a_j b_j + c_j = 0] ≤ p = ((n + w)/2^{ep})^t`.

*Proof.* For one j: `Pr[T(r_j) = 0] ≤ (n + w − 1)/2^{ep}` (Schwartz–Zippel), and otherwise ε_j is determined,
probability `2^{−ep}`. The points are independent. ∎

**Proposition 6 (soundness of one repetition, hypercube).** Fix the commitments, `aux` and the broadcast. If there is no
false positive, at most one value of `i*` passes verification, barring a collision of `H_c`.

*Proof.* If a commitment has no known preimage, only that leaf can be hidden. Otherwise the shares are
defined. For each d, let `Wrong_d ⊂ {0, 1}` be the sides whose committed broadcast differs from the honest computation. If
`Wrong_d = ∅`, then the opened α and β are the true ones (sum of both sides), and `v_0 = v_1` gives
`ε·T(r) + ab + c = 0` at every point, a false positive. So `Wrong_d ≠ ∅` for every d. The verifier only simulates the
side without `i*`: that side must be honest, so `i*` must be on the wrong side for **every** d. This fixes all
the bits of `i*`. ∎

The corresponding attack is run on a reduced model (N = 8, no witness): accepted if and only if the challenge
hits the targeted leaf (`tricheur_accepte_ssi_defi_sur_la_cible`). False witnesses are rejected
(`faux_temoins_rejetes`: `x_A`, Q or P altered, dense preimage).

**Proposition 7 (HVZK, ROM).** For given `(r, ε, i*)`, the following simulator, which does not know x, produces a transcript
with the same distribution as the real one, as long as the adversary does not query the hidden point `(salt, rep, node)` of an ancestor of `i*` or
its seed: draw the sibling seeds, `com_{i*}`, `aux`, `α`, `β` uniformly, then compute what the verifier computes.

*Distributions.* In the real execution, as long as `s_{i*}` is not queried, the hidden share is uniform and independent of the
rest. `aux` is masked by its fields `(x_A, Q, P, c)`, α and β by its fields `a` and `b`, which are disjoint: they are uniform
and independent. The sibling seeds are outputs of `H_a` on hidden ancestors, hence uniform. The deduced
values agree, since `v_0 + v_1 = 0` for the honest prover. If `i* = N − 1`, `aux` is not transmitted: the simulator sets it to 0. A query targets only one `(salt, rep, node)`, hence at most `q/2^{8·sb}` over the whole execution,
with no multi-target gain. ∎

*Check* (`tests/test_sig_hvzk.py`, added on 2026-11-05, reduced model of `tests/test_sig_modele.py`: n = 16, w = 2, GF(16) ⊂ GF(256),
N = 4). The simulator above, with `H_1` and `H_2` programmed on what the verifier computes, is accepted by the **real** verifier,
for every i*, on a public key with two witnesses and on a public key with no witness of weight ≤ w. At fixed (r, ε, i*), every
transmitted field (α, β, the fields of aux, the first bytes of the path and of `com_{i*}`, and the pairs (α, β), (α, c_aux)) is
uniform on its domain. The two witnesses of the same public key are not distinguished, nor the real transcript from the simulated
one (χ² tests, Bonferroni threshold 10⁻³ over 50 tests). For i* = N − 1 the transmitted aux is 0. Witness: a prover whose mask a
is zero (α = ε·Q(r) revealed) is detected by the same tests.

Unlike Stern, no hidden point is related to the solution of (H3): the commitments are on seeds
of full entropy. `attaque_graine_reduite_retrouve_la_cle` runs the attack with 16-bit seeds: enumerating the hidden
seed yields `x_A`, Q and P, then a forgery. `|seed|` therefore bounds the level, like `|σ_π|` for Stern.

### 3.3 Five-pass Fiat–Shamir

Signature: `salt ‖ h1 ‖ h2 ‖ (path ‖ com_{i*} ‖ aux ‖ α ‖ β)_{rep < τ}`, with
`h1 = H_1(salt, H_pk(pk), H_m(m), (H_com(salt, rep, com_0…com_{N−1}))_rep)`, `(r, ε) = G_1(h1)`,
`h2 = H_2(salt, H_pk(pk), H_m(m), h1, broadcasts)`, `i* = G_2(h2)` (D uniform bits per repetition). Fixed length. Hashes
of `ℓ = 2λ` bits; seeds of `λ + 8` bits (§ 5 bis).

The master seed is `H_mseed(sk, salt, H_m(m))`, with a random salt. A faulty random source therefore never repeats the seeds
from one message to another: two challenges on the same seeds would reveal the witness (`meme_sel_autre_message_aucune_graine_commune`).

**Theorem 8 (EUF-CMA, ROM).** Let F be a forger making `q_1`, `q_2`, `q_G`, `q_c`, `q_P`, `q_m` queries to `H_1`, `H_2`,
`G_1, G_2`, `H_c`, the seed and share derivations (`H_a, H_f`), `H_m`, and `q_S` signing queries. For every
integer `1 ≤ τ1 ≤ τ + 1`, there is a solver B for (H3) such that

```
Adv^{EUF-CMA}(F) ≤ (q_1 + 1)·P[Bin(τ, p) ≥ τ1]                false positives
                   + (q_2 + 1)·N^{−(τ−τ1+1)}                  hidden parties
                   + (q_1 + q_2)·q_G/2^ℓ                      challenge already queried
                   + (q_c + q_1 + q_2 + N·τ·(q_S + 1))²/2^ℓ   collisions, late preimages
                   + q_m²/2^{ℓ+1}                             collisions of H_m
                   + q_P/2^{8·sb}                             hidden seeds
                   + q_S²/2^{257} + q_S·q_G/2^ℓ + q_S(q_S + q_1 + q_2)/2^{256+ℓ}   programming
                   + 2·Adv^{H3}(B)
```

with B running in the time of F, plus N share evaluations and one check of Lemma A per query to
`H_1`. **The reduction loses no factor in q**: it does not use the forking lemma.

*Proof.* **Game 0**: the real game. B receives `(H', y)` and programs the columns of H' under `seed_H` (fresh).

**Game 1**: signatures are simulated without x. For each repetition, draw `(r, ε, i*)`, apply
Proposition 7, draw h1, h2 uniformly and program `G_1, G_2`, `H_1`, `H_2` accordingly. The games coincide
unless:
1. a hidden point is queried: `q_P/2^{8·sb}`, with `q_S²/2^{257}` for a repeated salt. Querying the master
   seed requires submitting sk to `H_mseed`, which gives a solution of (H3) that B recognises: hence a
   first `Adv^{H3}(B)` (Pr is measured in Game 1, where x plays no part);
2. a programmed point was already defined: `q_S·q_G/2^ℓ` for `G_1, G_2`, and, since the input of `H_1` contains the salt,
   `q_S(q_S + q_1 + q_2)/2^{256+ℓ}` for `H_1, H_2`.

**Analysis of a forgery in Game 1.** Let `(m*, salt*, h1*, h2*, …)` be a valid forgery. If `m*` has the same
image under `H_m` as a signed message, this is a collision (`q_m²/2^{ℓ+1}`). Otherwise, the inputs to `H_1` and `H_2` were not
programmed, and F queried them (at the cost of a +1 term each), `H_1` before `H_2`, barring a late preimage.

When F queries `H_1` on the input of `h1*`, B reads in the table the preimages of the hashes and commitments. A
preimage missing at that moment can only appear later by hitting a fixed value, or through a collision:
`(q_c + …)²/2^ℓ`. For the repetitions whose commitments all have a preimage, B evaluates the shares (the `H_f` are
thus fixed before `G_1(h1*)`), and tests Lemma A: a witness is the second `Adv^{H3}(B)`.

Otherwise, every repetition is witness-free, and `G_1(h1*)` is uniform and independent of the shares (except `q_1·q_G/2^ℓ`). By
Lemma 6, the number of repetitions with a false positive is dominated by `Bin(τ, p)`, and it reaches τ1 with probability at most
`P[Bin(τ, p) ≥ τ1]` per query to `H_1`. Otherwise, at least `τ − τ1 + 1` repetitions have no false positive. For a query
to `H_2` (broadcast fixed), Proposition 6 leaves each of them a single `i*`, and `G_2(h2)` is uniform (except
`q_2·q_G/2^ℓ`): probability at most `N^{−(τ−τ1+1)}`. ∎

This is the bound of the Kales–Zaverucha attack (2020): grind `h1` until τ1 false positives, then `h2` for the rest.
Parameters are set on both terms, not on `N^τ` alone.

*Execution on a reduced model* (`tests/test_sig_modele.py`, n = 16, w = 2, GF(16) ⊂ GF(256), N = 4, τ = 3, pk with no witness of
weight ≤ w, checked by enumeration). The attack, when run, produces forgeries accepted by the real verifier:

| Budget (q_1, q_2), false-positive threshold | Frequency (300 trials) | Theorem 8 bound |
|---|---|---|
| (10, 4), threshold 1 | 0.223 | 0.468 |
| (1, 16), no false positive | 0.26 | 0.659 |
| (40, 1), threshold 3 | 0.003 | 0.514 |

The bound upper-bounds each attack and is reached within a factor ≈ 2. On the same instances, Lemma A is checked
exhaustively over GF(8) (w = 1, 2, 3: for every x and every Q, `F | S·Q` if and only if the weight is allowed), the identity
`v_0 + v_1 = ε·T(r) + a·b + c` on the actual computation of the sides, and the exact count of Lemma 6 over K²: the worst cheater reaches
0.996 times the bound. The real verifier, with a forced challenge, only accepts the leaf predicted by Proposition 6, and every leaf
in case of a false positive. The polynomials of `F_poly` and `K` are irreducible (Rabin), and φ is a morphism, as Lemma 6
assumes.

*Intermediate scale, real C code* (`tests/c/sig_kz.c`, n = 64, k = 45, w = 3, GF(2^6) ⊂ GF(2^12), N = 2^8, τ = 4): the
attack is replayed against `sl_sig_verify` with no model. With a real witness, the verifier's recomputed view is compared
with the honest diffusion leaf by leaf (all N leaves of every repetition) and the signature is accepted. False positives are
detected by the exact condition ε·T(r) = 0 of Lemma 6, identical to `Rep.faux_positif` in the model. Every retained forgery
is accepted by the real verifier. The cheater enumerates the h2 targets without repetition (at most min(q_2, N^(τ−k))
distinct queries with k false positives): this is the optimal attacker of this family for a given q_2. A low-bound strategy
(q_1 = 25, q_2 = 2N² = 131072, threshold 2) has a Theorem 8 bound of ≈ 0.049; over 10,000 trials, 227 forgeries (frequency
0.0227, exact 95% CI [0.020, 0.026]): the bound holds and is loose only by a factor ≈ 2.2. The frequency also matches the
EXACT success probability of the strategy, 0.0222, computed from the false-positive rate measured over the campaign (0.0156
over 1.25 M repetitions, Lemma 6 bound: 0.0164): h1 stage 0.0348 measured vs 0.0352 predicted, h2 stage 0.652 vs
1 − e^{-1} ≈ 0.632. The two other strategies agree as well (three independent seeds: 171/900 vs 0.199; 288/450 vs 0.630).
This agreement check (99.9% CI) is what guarantees the harness is not weakened: a missed forgery would pass under the bound
unnoticed. Randomness is reproducible (`SIG_KZ_GRAINE`) and the strategies use independent streams. Quantitative measurement of
the D1 plan (N = 2^12, 2^35 to 2^42 trials) remains beyond CPU reach.

*GPU version* (`tests/gpu/sig_kz_gpu.{c,cu}`, launcher `./runtestg-gpu.sh`): same instance, same keys and same fake witness
(`tests/c/sig_kz_commun.h`). The GPU performs the full commitment of each h1 attempt (GGM tree, 4 × 256 leaves, aux,
commitments, challenges) and enumerates the h2 targets; the host recomputes every retained h1 in C, replays every success
and submits it to `sl_sig_verify`. The false-positive rate is exact there: T has 63 roots in K = GF(2^12), hence 0.015621
per repetition, which the campaign recovers (0.015640 over 101 M repetitions). The verifier's view for leaf c is derived,
axis by axis, from the views of leaves 0 and N − 1 (the simulated side depends only on bit d of c), which is checked leaf by
leaf. Over 1,000,000 low-bound trials: 22,525 forgeries, frequency 0.0225, exact 95% CI [0.0222, 0.0228], against an exact
prediction of 0.0223 and a bound of 0.0486; both stages agree separately (h1: 0.0354 measured, 0.0352 predicted; h2: 0.636
and 0.632). The two other strategies give 200 / 1,000 (prediction 0.200) and 320 / 500 (0.630). All 23,045 forgeries are
accepted by the real verifier. GPU = C conformance: h1 and false positives on 256 salts, h2 challenges on 256 targets.
Throughput: 5·10^5 h1 attempts per second (RTX 4070 Ti), about 300 times one CPU core; the host side (step 2) runs on every
core and does not change the results.

**Proposition 9 (unique encoding, SUF-CMA).** With `aux = 0` required when `i* = N − 1`, for every F as in Theorem 8,

```
Adv^{SUF-CMA}(F) ≤ Adv^{EUF-CMA}(F) [Theorem 8 bound] + (q_2 + 1)·N^{−τ} + q_P²/2^{16·sb+1}
```

*Proof.* Let `(m*, σ*)` be valid, where m* was signed (otherwise Theorem 8 applies) and σ* is not one of its responses. We exclude
hash collisions, already counted, and collisions of `H_a` (last term). Let `σ_i = (salt, h1, h2, …)` be a response for m*.
If `(salt*, h1*)` is that of no response, the input to `H_1` is not programmed, and the analysis of Theorem 8 applies
unchanged (a repetition reusing simulated commitments has a leaf with no preimage: at most one `i*`, Proposition 6).
Otherwise `h1* = h1`: commitments and hashes are those of `σ_i` (otherwise a collision), so each repetition has its hidden leaf, with no
known preimage (otherwise `q_P/2^{8·sb}`), and only the same `i*` can pass. If `h2* ≠ h2`, the input to `H_2` is new, and
`G_2(h2*)` returns these `i*` with probability `N^{−τ}`. If `h2* = h2`, then `i*`, the broadcast, α and β (hashed as is, canonical
encoding) are the same; so is `com_{i*}`. Another seed path would give other leaves, hence a collision of `H_c`
or of `H_a`. `aux` is bound by `com_{N−1}` if `i* ≠ N − 1`, and fixed to 0 otherwise. Hence `σ* = σ_i`. ∎

`N^{−τ}` is `2^{−132}` and `2^{−276}`, and `q_P²/2^{16·sb}` is negligible compared with `q_P/2^{8·sb}`: the level does not change.

*v0.4 correction.* The first draft transmitted `aux` as is, including for `i* = N − 1`, with nothing binding it: any
signature in which a repetition hid the last leaf (about 1 in 370) remained valid once `aux` was modified, i.e. a
malleability. Neither EUF-CMA nor the secret was affected. Found by re-reading the proof against the code, demonstrated, fixed.
Checks: `encodage_unique_modele` (every bit of every signature, for every hidden leaf), `c_aux_verrouille`.

**Proposition 10 (binding to the key and the message).** A signature valid for `(pk, m)` is valid for another `(pk', m')`, even
with `pk'` chosen by the attacker, only at the cost of a collision of `H_pk`, `H_m` or `H_1`: `σ` contains `salt` and `h1`, and `h1`, hashed over
`(salt, H_pk(pk), H_m(m), …)`, is recomputed at verification. Cost `2^{ℓ/2} = 2^λ`. This is the exclusive-ownership property (CEO, DEO) of Cremers
et al. (2021). Non-re-signability is not claimed: the signature depends on m only through `H_m(m)`.

**Corollary 8-mu (μ keys).** Let F target one of μ independent keys, each with its own seed `seed_H`, `q_S` counting all
signatures. The bound of Theorem 8 holds with `2·Adv^{H3-μ}` as its last term, `Adv^{H3-μ} ≤ μ·Adv^{H3}`, plus `μ²/2^{ℓ+1}`
(collision of `H_pk`).

*Proof.* `h1` and `h2` carry `H_pk(pk)`, and `G_1, G_2` depend on it through them: a query targets only one key, barring a collision. The hidden
points carry `salt`, drawn at random for each signature, and a query targets only one of them. The terms in q therefore take no factor μ. The
reduction receives μ instances of (H3) and applies Theorem 8 to the targeted key. ∎

The factor μ in the reduction corresponds to no known attack: each key has its own `H'`, with no shared precomputation, and an ISD
targets one matrix at a time. Splitting a budget T over μ keys gives the same total advantage `T/2^{cost}`.

**Security level (explicit query budget).** Same cost/advantage notion as in § 4.3: λ bits if
`Adv ≤ 2q/2^λ + 2·Adv^{H3}` for every `q ≤ 2^{λ−2}` (q bounds each counter), and if (H3) withstands 2^λ operations. With
`p = ((n + w)/2^{ep})^t` and `q_S ≤ 2^{64}`:

| Term | SIG-128 (N = 2¹², τ = 11, p = 2^{−131.7}, τ1 = 1) | SIG-256 (N = 2¹², τ = 23, p = 2^{−143.7}, τ1 = 2) |
|---|---|---|
| `(q_1 + 1)·P[Bin(τ, p) ≥ τ1]` | ≤ q·2^{−128.3} | ≤ q·2^{−279.5} |
| `(q_2 + 1)·N^{−(τ−τ1+1)}` | ≤ q·2^{−132} | ≤ q·2^{−264} |
| `q·q_G/2^ℓ`, collisions, `q_m²/2^{ℓ+1}` | ≤ q·2^{−128} | ≤ q·2^{−256} |
| `q_P/2^{8·sb}` | q·2^{−136} | q·2^{−264} |
| `q_S·q_G/2^ℓ` | ≤ q·2^{−192} | ≤ q·2^{−448} |
| ISD on (H3), § 5 | 160.3 b | 316.2 b |

Check: `tests/test_sig.py :: *_theoreme_8_atteint_lambda`, `*_tau_minimal`.

The factor `(q + 1)` is not a proof artefact, and the notion remains that of v0.3: forging costs about `2^λ`
queries. An advantage of at most `2^{−λ}` after `2^{64}` queries (the external audit's reading, point 4) would require
τ = 16, t = 6 and τ = 28, t = 5; this is not the notion adopted, since AES-128 does not satisfy it either.

*History.* v0.3 used Stern with ternary challenges (`t = 219` and `438`). Its corrections (σ_π and 2λ-bit hashes, Proposition 7
without “commitments hiding by entropy”, extraction without forking) carry over here: `|seed|` and `ℓ` follow the same
rules, and extraction reads the oracle table.

---

## 3 bis. VOLE-in-the-Head signature (the signature of v0.5, lead 9)

*Status: written on 11 November 2026, **not reviewed by a third party**. Since v0.5 (11 November 2026) this is the signature of
the suite (`sillage/c/vole.c`, SPEC § 4 bis); the MPC-in-the-Head signature of § 3 is kept as a reference. Test bench:
`prototypes/vole/vole_proto.c`; parameters: `prototypes/vole/vole_params.c`. The check names below are those of
`resultats/vole_proto.json` and `resultats/vole_params.json`. Revised on 12 November 2026: direct form of Lemma 17.2, the case
with no consistent repetition in Theorem 17, Lemma 17.6 (round-by-round soundness, for Theorem 17-Q).*

The construction follows the VOLE-in-the-Head line (FAEST: Baum et al., Crypto 2023; single GGM tree with `T_open` and
grinding: Baum et al., Asiacrypt 2024; SDitH v2.0 for the degree-d PIOP on regular SD). The arguments below are written for
the code as it is, term by term; nothing is imported from those papers as a black box.

### 3 bis.1 Relation, witness, assumption

Public key `(seed_H, y)`, `H = [H′ | I] ∈ F_2^{r×n}` expanded from `seed_H`, `n = w·b`. Secret: positions `p_1, …, p_w ∈ [0, b)`,
`x = Σ_i e_{(i−1)b + p_i}`, `Hx = y`.

*Witness.* The position p of a block is written in mixed radix `(μ_1, …, μ_d)`. Digit t is the unit vector `e_{δ_t} ∈ F_2^{μ_t}`;
its first `μ_t − 1` coordinates are committed, the last one is `1 ⊕ Σ` of the others. The block of x is the tensor product
`⊗_t e_{δ_t} ∈ F_2^{Π μ_t}`, of degree d in the committed bits.

*Constraints* (degree ≤ d, homogenised to degree d): for every block and digit, `b_v·b_{v′} = 0` for `v < v′ < μ_t − 1`; for every
row, `Σ_q H_{rq} x_q = y_r`, where `x_q` runs over the coordinates of the tensor products.

**Lemma 17.1 (exact blocks).** If `b = Π μ_t`, a binary assignment satisfies every constraint if and only if it encodes a regular
vector x of weight w with `Hx = y`. If `b < Π μ_t`, the satisfying assignments are exactly the vectors with at most one non-zero
coordinate per block and `Hx = y`; this includes `x = 0` when `y = 0`.

*Proof.* The pair constraints leave at most one committed bit at 1 per digit, and the last coordinate is 1 exactly when none is:
each digit vector is one-hot, so the tensor product is one-hot in `F_2^{Π μ}`. If `b = Π μ`, every coordinate is a column of the
block, hence exactly one non-zero per block. Otherwise, the syndrome constraint drops the coordinates `≥ b` (they multiply no column),
and a block whose one-hot coordinate is `≥ b` is empty. ∎

*History.* The first prototype had blocks of 245 and 253 positions for `Π μ = 256`. On 11 November 2026, the verifier
accepted signatures with empty blocks, all of them included, and `x = 0` on `y = 0`. There was no attack on an honest key (about
2^−14.3 and 2^−10.9 extra solutions per key), but the relation proved was not regular SD. `ctx_init` now refuses `b ≠ Π μ`, and
the profiles were re-chosen on a grid of exact blocks. Checks: `blocs_exacts_ancien_profil_245_refuse`,
`*_blocs_exacts_positions_extremes_acceptees` (positions 0 and 255 are real columns).

**(H3-R) Regular syndrome decoding.** For H as above and x regular of weight w with blocks of `b = 256`, finding a regular `x′`
with `Hx′ = Hx` is hard. Lemma 17.2 shows that, at the codimension chosen, this follows from (H3).

**Lemma 17.2 (exact reduction from (H3) to (H3-R), no heuristic).** Let `b = n/w` and let r be the codimension. Let A solve
(H3-R) on instances `([H′ | I], y)` of codimension r with probability ε in time t. Then:

*(i) direct form, for (H3) as stated in § 1* (systematic matrix `[H′ | I]`, `H′` uniform, x uniform of weight w): A itself,
run on the (H3) instance unchanged, solves (H3) with probability

```
ε_SD ≥ (b^w / C(n, w)) · ε .
```

*(ii) for SD with a uniform matrix H* (no systematic form): there is B, in time t + O(n·r²), with

```
ε_SD ≥ (b^w / C(n, w)) · Π_{i=1..r} (1 − 2^{−i}) · ε  ≥  0.2887 · (b^w / C(n, w)) · ε .
```

*Proof.* (i) The (H3) instance is `([H′ | I], y = [H′ | I]·x)` with `H′` uniform and x uniform of weight w, independent of `H′`.
The event "x is regular" depends on x alone and has probability exactly `b^w/C(n, w)`. Conditioned on it, x is uniform among
regular vectors and still independent of `H′`: `([H′ | I], y)` then follows exactly the distribution of the key generator, so A
succeeds with probability ε. Any regular x′ returned by A satisfies `[H′ | I]x′ = y` and `wt(x′) = w`, which is a solution of
(H3). (ii) B receives `(H, y = Hx)` with H uniform. It draws a uniform permutation σ of the columns and sets `Ĥ = H·σ`, with
`x̂ = σ^{−1}(x)` uniform of weight w and independent of Ĥ. It brings the last r columns of Ĥ to the identity by row operations S,
`(SĤ, Sy) = ([H″ | I], y″)`, and gives up if those columns are dependent (probability `1 − Π (1 − 2^{−i})`, independent of x).
Conditioned on the opposite, H″ is uniform and independent of x̂, so B is in case (i) with the instance `([H″ | I], y″)`; a
solution x′ gives `H·σ(x′) = y`. In both cases **no uniqueness is needed**, because no row is removed. ∎

*Correction of 12 November 2026.* The first version stated only (ii), for a uniform H, and Theorem 17 used it with the constant
`1/0.2887 ≈ 3.47`. But (H3) is stated in § 1 for the systematic form, and the passage from uniform-H SD to (H3) (§ 1: "a random
code reduces to it by elimination") only goes in one direction: hardness of uniform-H SD implies (H3), not the converse. Read
literally, the chain "(H3) ⇒ (H3-R)" therefore went through an assumption (uniform-H SD) that is not (H3). Form (i) removes the
detour: it reduces (H3-R) to (H3) itself, and it is 1.79 bits tighter. Form (ii) stays valid for those who prefer to assume
uniform-H SD. Measured: `reduction_directe_sd_systematique_vers_rsd_mesuree` (`vole_params`) runs A on systematic instances,
unchanged, and matches the prediction of (i).

This differs from Theorem 5.1 of SDitH v2.0, which removes `k_rsd − k_sd` rows and relies on a heuristic step (uniqueness of the
solution of the truncated system). The reduction itself does not need `r ≥ log₂ C(n, w)`: that condition chooses the
parameters, so that (H3) sits in the unique-solution regime where the ISD estimates apply. The cost of rigour is a larger
codimension, `⌈log₂ C(n, w)⌉` instead of `w·log₂ b + log₂ θ`: the public key gains a few bytes and γ a few elements, while **the
signature size does not change** (the witness has `w·Σ(μ_t − 1)` bits whatever the codimension). The loss in bits is
`log₂(C(n, w)/b^w)` with form (i), `log₂(C(n, w)/b^w) + 1.79` with form (ii).

*Hypotheses, stated explicitly.*
- **Matrix.** H′ is expanded from `seed_H` by SHAKE256 (domain `H`). In the ROM, these are uniform independent outputs: H′ is a
  uniform matrix, exactly the one of (H3), and the reduction B programs it with its instance. Outside the ROM, it would be an extra
  assumption, the same as for the current signature.
- **No θ.** Unlike Theorem 5.1 of SDitH v2.0, Lemma 17.2 removes no row. It has no density parameter θ, and no uniqueness hypothesis
  (Automated-review, point 3: the condition `k_rsd ≤ n − w·log₂(n/w) − log₂ θ` does not apply). The parameters take
  `r ≥ log₂ C(n, w)`, which guarantees that the SD solution is unique in expectation (`C(n, w)/2^r ≤ 1`); the reduction holds
  for every r.
- **Profiles f.** They share (n, r, w) with the short profiles, so the same estimates apply.

The parameter grid of `vole_params` still selects w with the constant of form (ii), which is more cautious, so the profiles of
v0.5 are unchanged. With form (i), the same target would allow a slightly smaller w: that would be a format change (new KATs),
not made here. The values of the parameters (`docs/LEADS.md`, lead 9) are those of `tests/c/rsd_attaques.c` from 11 November 2026:
`(19 456, 720, 76)` and `(38 912, 1 432, 152)`, best direct attack 264.0 and 525.0 bits. The version published before that date
still had the old instances.

*Measured* (`vole_params`, control `reduction_exacte_sd_vers_rsd_mesuree`): B is run with an exhaustive regular solver on random SD
instances. Its success rate matches the exact prediction of the lemma, including on instances that have several regular solutions.

*Consequence.* With the parameters below, **(H3-R) is no longer a separate assumption**: it follows from (H3), the binary
syndrome decoding problem of the current signature, here at rate `k/n ≈ 0.96` with a unique solution. What remains is the cost
of ISD on these instances, i.e. the estimators.

| Profile | μ | b | w | n | r = n − k | Witness | Guaranteed by Lemma 17.2 (our ISD), form (i) / (ii) | Best direct attack (ours / CryptographicEstimators) |
|---|---|---|---|---|---|---|---|---|
| VOLE-128, VOLE-128f | (4,4,4,4) | 256 | 76 | 19 456 | 720 | 912 bits | 162.4 / 160.6 b | 264.0 / 275.4 |
| VOLE-256, VOLE-256f | (4,4,4,4) | 256 | 152 | 38 912 | 1 432 | 1 824 bits | 317.8 / 316.0 b | 525.0 / 612.2 |

*On SDitH v2.0.* Its text requires `μ_1···μ_d = n/w` (§ 2), but its Table 3 has n/w = 185, 252 and 191 for `Π μ` = 192, 256 and
192. If implemented as written, the encoding then has positions past the block, and the relation proved would be "at most one
error per block" (Lemma 17.1). This was not checked against its reference implementation.

### 3 bis.2 The protocol, as coded

Hashes: `ℓ = 2λ` bits, with the prefix `SILLAGE-VOLE ‖ version ‖ profile ‖ domain` (`H_x` below names domain x). Seeds have
`λ + 8` bits, and the salt has 32 bytes. `E ⊂ GF(2^λ)` is the subspace spanned by `X^0, …, X^{τκ−1}`, of size `2^{τκ}`.

1. `hm = H_m(pk, m)`, random `salt`, root `= H_r(pos, salt, hm)`. A single GGM tree (`H_n`) over `L = τN` leaves, interleaved
   (leaf `L + i·τ + e`). Leaf: `(com, r) = H_l(salt, idx, seed)`, with `com` of 2λ bits and `r` of `nb` bytes.
2. Per repetition: `u_e = Σ_i r_{e,i}`, `v_{e,b} = Σ_i i_b·r_{e,i}`; `aux_e = u_0 ⊕ u_e` (e ≥ 1).
   `h1 = H_A(H_C(salt, hm, (H_c(salt, e, com_{e,·}))_e), aux)`.
3. VOLE check: `M = H_M(h1) = [M′ | I]`, with `λ + B` rows; `ut = M·u_0`, `ht_{e,b} = M·v_{e,b}`, `hv = H_v(h1, ht)`.
4. `dw = wit ⊕ u_0|_wit`, `h2 = H_2(hv, ut, dw)`, `γ = H_g(h2) ∈ GF(2^λ)^m`.
5. `C(X) = Σ_j γ_j F_j(X)`, where `F_j` is constraint j evaluated on `p(X) = w·X + V`. Mask `Σ_t (a_t X + b_t) X^{t−1}`, from the
   `d − 1` mask sections of `u_0` and their V. `α` = coefficients of degree `< d`; `h3 = H_3(h2, α)`.
6. Grinding: `H_d(h3, ctr)` gives `τκ` bits (`Δ ∈ E`, i.e. the hidden leaf of each repetition) and `wpow` bits that must be zero.
   The number of nodes to open must be `≤ T_open`.
7. `σ = salt ‖ h3 ‖ aux ‖ ut ‖ dw ‖ α ‖ opened nodes (T_open slots, zero padding required) ‖ hidden coms ‖ ctr`, of fixed length.

The verifier rebuilds `q_{e,b} = v_{e,b} ⊕ Δ_{e,b}·u_e` (corrected by `aux`), recomputes `ht`, `hv`, `h2` and `h3`, compares
`h3`, then checks `Σ_l α_l Δ^l = M(Δ) + Σ_j γ_j F_j(q)`.

### 3 bis.3 Theorem 17 (EUF-CMA, ROM)

**Theorem 17.** Let F be a forger making at most q oracle queries in total, signing queries included. F is normalised to
evaluate every point the verifier evaluates on its forgery, which adds at most one query per oracle. Among these queries, `q_1`
go to `H_A`, `q_2` to `H_2`, `q_3` to `H_d`, `q_P` to the seed derivations `H_n, H_l`, and `q_S ≤ 2^{64}` are signing queries.
There is a solver B of (H3-R) such that

```
Adv^{EUF-CMA}(F) ≤ q_1·C(τ, 2)·2^{−(λ+B)}            VOLE check
                   + q_2·2^{−λ}                          γ: invalid witness, degree-d term cancelled
                   + q_3·d·2^{−(τκ+wpow)}                Δ: root of the residual (guessed repetitions included)
                   + q_P/2^{λ+8}                         hidden seeds
                   + q·(q + τN(q_S + 1))/2^{2λ}          collisions and late preimages (2λ-bit hashes)
                   + 3·q_S·q/2^{2λ}                      programming of h1, h2 and (h3, ctr)
                   + 2·Adv^{H3-R}(B)
```

and, by Lemma 17.2 (i), `Adv^{H3-R}(B) ≤ (C(n, w)/b^w)·Adv^{H3}(B)`, B itself run on the (H3) instance: the scheme rests
on (H3) alone, as stated in § 1. (The first version wrote `3.47·(C(n, w)/b^w)·Adv^{H3}(B′)`, through form (ii), i.e. through
uniform-H SD; see the correction under Lemma 17.2.)

B runs in the time of F, plus one evaluation of the constraints per query to `H_2`. The reduction does not use the forking lemma
and loses no factor in q.

*Proof.* **Game 0** is the real game. B receives `(H′, y)` and programs the expansion of `seed_H`.

**Game 1: simulated signatures.** Signing queries are memoised on `(salt, H_m)`: the real signer is deterministic once `salt` and
`m` are fixed, so a repeated salt costs nothing. For a fresh query, the simulator:
- draws `salt`, and draws the challenges by running the real `ctr` loop on fresh uniform outputs, programming
  `H_d(h3, j)` for `j ≤ ctr`;
- draws the opened nodes (λ + 8 bits) and the hidden `com` of each repetition uniformly, and derives the verifier's `q`;
- draws `aux`, `dw`, `ut` and `α_1, …, α_{d−1}` uniformly, and solves `α_0` from the verification equation;
- computes the hashes and programs `H_A`, `H_2` and `H_3`.

Each of these values is uniform in Game 0 as well:
- `u_0` and `u_e` contain the `r` of the hidden leaf of their repetition, which is pseudo-random under a hidden seed, so `aux` and
  `dw` are uniform;
- the last `λ + B` bits of `u_0` appear only in `ut`, since `M = [M′ | I]`, so `ut` is uniform;
- `α_l`, for `l ≥ 1`, contains the mask coefficient `a_l`, a section of `u_0` used nowhere else;
- `α_0` is fixed by the equation.

The two games differ only in the following cases:
1. F queries a hidden seed. Each query names a single `(salt, idx)`, so the probability is `q_P/2^{λ+8}`.
2. F queries the root input `(pos, salt, hm)`. This gives pos, a solution that B recognises: the first `Adv^{H3-R}(B)`.
3. A programmed point was already defined. This costs `q_S·q/2^{2λ}` for each of the three programmed oracles, since their inputs
   contain a fresh 256-bit salt or a fresh 2λ-bit hash.

**Analysis of a forgery** `(m*, σ*)` with m* never signed. A collision of `H_m` with a signed message is counted in the collision
term. Otherwise, the inputs of `H_A`, `H_2` and `H_3` are not programmed, and F queried them in this order, barring a late preimage.

*(a) Extraction at the `H_A` query.* For each repetition, B reads the preimages of the commitments in the oracle table. A
preimage that appears later costs a collision or a late preimage. If every leaf of repetition e has a preimage, e is *open*: B
computes `ũ_e = Σ_i r_{e,i}`, `ũ′_e = ũ_e ⊕ aux_e` (with `aux_0 = 0`) and `ṽ_{e,b}`. If two leaves lack a preimage, the repetition
cannot pass. If exactly one lacks a preimage, it passes only if `ch_e` designates that leaf, and e is then *guessed*.

*(b) VOLE check.* `M = H_M(h1*)` is uniform and independent of the `ũ′`. For `z ≠ 0`, `[M′ | I]·z = 0` forces the head of z to be
non-zero (otherwise `Mz` is its non-zero tail), so the probability is `2^{−(λ+B)}`. A union over the pairs of open repetitions
gives `C(τ, 2)·2^{−(λ+B)}` per `H_A` query. Outside this event, the open repetitions with `M·ũ′_e = ut` share one value `u*`.

On repetition e, the verifier computes `ht_{e,b} = M·ṽ_{e,b} ⊕ Δ_{e,b}·(M·ũ′_e ⊕ ut)`. F fixed `hv` before Δ. For an open
repetition with `M·ũ′_e ≠ ut` (*inconsistent*), F must therefore have predicted all κ bits of `Δ_e`: for each b, the value of
`ht_{e,b}` inside the input of `hv` is either `M·ṽ_{e,b}` or `M·ṽ_{e,b} ⊕ (M·ũ′_e ⊕ ut)`, and these two differ, so it fixes
`Δ_{e,b}` (or no value fits, and the repetition cannot pass).

Let S be the set of guessed and inconsistent repetitions. A forgery requires `Δ|_S` to equal values fixed before the `H_d`
queries.

*(b′) No consistent repetition* (added on 12 November 2026; the first version passed over it). If no open repetition satisfies
`M·ũ′_e = ut`, the value u* of (c) is undefined, but then S contains every repetition: a forgery requires Δ to equal, on all its
τκ bits, a value fixed before the `H_d` queries. Each query succeeds with probability at most `2^{−τκ}·2^{−wpow}`, which is
already counted in the Δ term (`d ≥ 1`). From here on, at least one repetition is open and consistent.

*(c) γ.* The extracted witness is `w′ = dw* ⊕ u*|_wit`. It is fixed when F queries `H_2`, because `dw*` is part of that input and
`u*` is fixed since h1. If `w′` is a solution, Lemma 17.1 gives the second `Adv^{H3-R}(B)`. Otherwise, by Lemma 17.1, the
constraint vector `f(w′) ∈ F_2^m` is non-zero, and the leading coefficient of `C` is `C_d = Σ_j γ_j f_j(w′)`. Since γ is uniform,
`Pr[C_d = 0] = 2^{−λ}` per `H_2` query.

*(d) Δ.* There remains the case `C_d ≠ 0`. For `e ∈ S`, the verifier's values on repetition e are `ṽ ⊕` a constant fixed by the
guess, which is absorbed into V. For the other repetitions, `q_j = Ṽ_j ⊕ Δ·w′_j`. The check then reads `P(Δ) = 0`, where P has
degree d and leading coefficient `C_d`: the mask and the terms `α_l Δ^l` have degree at most `d − 1`. P therefore has at most d
roots. Each `H_d` query gives Δ uniform in E and `wpow` independent bits, so it succeeds with probability at most
`d·2^{−τκ}·2^{−wpow}`. The guesses on S only restrict which roots are usable, and `T_open` only removes challenges. ∎

**Lemma 17.5 (grinding and the opening limit do not change the Δ term).** Let `A(ch)` be the acceptance rule: the wpow bits that
follow the challenge must be zero, and the opening must have at most `T_open` nodes. A challenge accepted by the honest signer is
uniform over the admissible set, of proportion `P_open` (measured below). Its min-entropy is therefore `τκ + log₂ P_open`, and not
τκ. **The bound of Theorem 17 does not depend on it.** In the ROM, each query `H_d(h3, ctr)` returns a fresh uniform output. Whatever
the guesses and the d roots fixed beforehand, the forger wins only if the challenge is one of the roots (probability at most
`d·2^{−τκ}`) **and** the next wpow bits are zero (`2^{−wpow}`, independent). The opening condition can only reject: it removes outputs
and adds none. The optimal forger puts its roots in the admissible set, and its success per query is then exactly
`d·2^{−(τκ+wpow)}`; roots outside the set only lower it. The bound counts queries, not accepted challenges, so the conditional
entropy does not enter: the cost of grinding, `2^{wpow}/P_open` queries for the honest signer, gives the forger no shortcut. The
same reasoning holds for the RBR error of the Δ round (Theorem 17-Q) and for the "another ctr" term of Proposition 17.3.

Two consequences must be stated, and are:
1. **Zero knowledge.** The simulator of Game 1 must reproduce the conditional distribution. It does, because it runs the real `ctr`
   loop on fresh outputs and programs every point it tried. Acceptance depends only on the challenge, which is public: the
   rejection leaks nothing about the witness.
2. **Cost and entropy, measured** (`vole_proto`, 10^6 uniform challenges, the opening count of `ouverts()`, itself equal to
   `marquer()`). An independent Monte-Carlo estimate (external review, 3·10^5 tuples) agrees.

| Profile | P_open | Expected grinding `2^{wpow}/P_open` (measured over 40 signatures) | min-entropy of the accepted challenge |
|---|---|---|---|
| VOLE-128 | 0.1376 ± 0.0003 (review: 0.1376) | 7 441 (7 523) | 118.1 of 121 bits |
| VOLE-256 | 0.00517 ± 0.00007 (review: 0.00489) | 24 782 (26 893) | 244.4 of 252 bits |
| VOLE-128f | 0.00973 ± 0.0001 (review: 0.00994) | 823 (814) | 121.3 of 128 bits |
| VOLE-256f | 0.00364 ± 0.00006 (review: 0.00374) | 2 196 (2 589) | 247.9 of 256 bits |

Check: `*_grinding_conforme_a_p_open`. An exact count of the admissible tuples (dynamic programming over the interleaved tree)
would replace the estimate; it is not needed by the bound.

**Security level** (cost/advantage notion of § 3.3: λ bits if `Adv ≤ 2q/2^λ + 2·Adv^{H3-R}` for every `q ≤ 2^{λ−2}`).

| Term, coefficient of q | VOLE-128 (τκ = 121, wpow = 10) | VOLE-256 (τκ = 252, wpow = 7) | VOLE-128f (τκ = 128, wpow = 3) | VOLE-256f (τκ = 256, wpow = 3) |
|---|---|---|---|---|
| VOLE check, `C(τ,2)·2^{−(λ+16)}` | 2^{−138.2} | 2^{−264.3} | 2^{−137.1} | 2^{−263.0} |
| γ, `2^{−λ}` | 2^{−128} | 2^{−256} | 2^{−128} | 2^{−256} |
| Δ, `4·2^{−(τκ+wpow)}` | 2^{−129} | 2^{−257} | 2^{−129} | 2^{−257} |
| hidden seeds | 2^{−136} | 2^{−264} | 2^{−136} | 2^{−264} |
| collisions, `q ≤ 2^{λ−2}` | ≤ 2^{−130} | ≤ 2^{−258} | ≤ 2^{−130} | ≤ 2^{−258} |
| programming | 2^{−190.4} | 2^{−446.4} | 2^{−190.4} | 2^{−446.4} |
| **Total / (2·2^{−λ})** | **0.877** | **0.879** | **0.878** | **0.881** |
| with `wpow − 1` | 1.127 (fails) | 1.129 (fails) | 1.128 (fails) | 1.131 (fails) |

The "f" profiles take `N = 2^8` (τ = 16 and 32, `T_open` = 101 and 207, the values of SDitH2-fast): 5 to 10 times fewer leaves, a larger
signature, the same theorem.

The γ term cannot be reduced by grinding: going below 2^{−λ} would need a larger field or two draws of γ. Forging therefore costs
about 2^λ queries, as for Theorem 8. With 2^{λ−1} queries, the γ term contributes 1/2 and the Δ term 1/4 (q_3 at the same rate), so
the advantage stays below 1. One `H_2` query is far more expensive than one `H_d` query: it requires the m field elements of γ
and `γᵀH`. Checks: `*_theoreme_17_atteint_lambda`, `*_wpow_minimal`.

*See also.* QROM: § 3 bis.5. SUF-CMA, binding and several keys: § 3 bis.6.

### 3 bis.4 The three terms against executed attacks (reduced models)

`build/vole_proto`, on one thread, with reduced profiles: n = 128, blocks of 16 = 2^4, τ = 2, κ = 6. Every forgery is submitted to
the real verifier.

| Attack | Term | Measured | Prediction |
|---|---|---|---|
| Δ: no witness, α cancels the residual at d = 4 points of E, then grinding | `q_3·d·2^{−τκ}` | 600/600 accepted; 1 026 ± 39 then 961 ± 41 Δ queries (two runs) | 2^{12}/4 = 1 024 |
| γ (profile with γ in a subgroup of 2^{10} elements): no witness, the committed witness changes until `C_d = 0` | `q_2·2^{−λ}` (λ → 10) | 200/200 accepted; 1 044 ± 69 then 1 063 ± 71 h2 queries | 1 024 |
| VOLE check: inconsistent `aux` on repetition 1, its challenge guessed in advance, honest grinding | the inconsistency passes only on the guess | 119 then 77 accepted out of 6 400 | 6 400·2^{−6} = 100 (z = +1.9, −2.3) |
| same, grinding until the challenge equals the guess | cost ×2^κ | 300/300 accepted, 67.9 then 62.6 queries | 64 |

The measurements match the exact prediction of each strategy, not just the bound, so a weakened harness would show. With a
real witness and no attack, the reduced γ profile is accepted, and a false witness is rejected.
Checks: `reduit_attaque_delta_*`, `reduit_attaque_gamma_*`, `reduit_controle_vole_*`.

### 3 bis.5 Quantum random oracle (Theorem 17-Q)

Source: Baum, Beullens, Braun, Delpech de Saint Guilhem, Klooß, Majenz, Mukherjee, Orsini, Ramacher, Rechberger, Roy, Scholl,
*Shorter, Tighter, FAESTer: Optimizations and Improved (QROM) Analysis for VOLE-in-the-Head Signatures*, IACR ePrint 2026/164
(full version of the IACR 2025 paper; read on 11 November 2026). The same proof appears in FAEST v2, § 9.7.

**The tool: their Theorem 54** (round-by-round soundness ⇒ soundness of Fiat–Shamir in the QROM). Let IP be an interactive proof
with ℓ challenges, where the challenges indexed by S have round-by-round (RBR) error 0 and the others have error ε. Suppose the
challenges of S are derived by a function f^{H1} that preserves collision resistance and is sensitive (L queries), and the
others by `H2^i`. Then a static quantum adversary making `Q̃` queries satisfies

```
Adv^{Snd}(FS[IP]) ≤ 30·Q³·2^{−ℓ_out} + 10·Q²·ε,      Q = Q̃ + 2ℓ + 2(L − 1)·|S|.
```

The proof relies on a compressed-oracle search bound (their Lemma 25, from CFHL21 and AHJ+23).

**Application to this signature.** Their § 6.1 recasts the signature as a *non-standard* Fiat–Shamir transform of an interactive
proof IP+ in which **every oracle call is a challenge**. Its toy example is exactly our case: the commitment
`com_i = H(s_i, r_i)` becomes a challenge with RBR error 0, with no idealised commitment. For our protocol, the following are
challenges with RBR error 0, derived by parallel or sequential applications of the oracle:
- the GGM tree (`H_n`), the leaves (`H_l`, 4-way), `H_c`, `H_C`, `H_A`;
- `H_M`, `H_v` and `H_2` for the parts that only hash.

Three challenges have a non-zero error:
- the universal-hash key `M`: `C(τ,2)·2^{−(λ+B)}`;
- γ: `2^{−λ}`;
- Δ with grinding: `d·2^{−(τκ+wpow)}`, the guessed repetitions being included in the state function.

Hence `ε = 2^{−λ}`, and `ℓ_out = 2λ`.

**Theorem 17-Q (EUF-CMA, QROM, sketch).** With lossy keys (their § 5.1 and Theorem 56: the public key is replaced by a uniform
syndrome, at the cost of `Adv^{D-H3-R}`; a uniform y has a regular preimage with probability at most `b^w/2^r` = `2^{−112}` and
`2^{−216}`), and the reprogramming of the signing oracle by quantum-list unpredictability (their § 6.3):

```
Adv^{EUF-CMA} ≲ 2·[ Adv^{D-H3-R} + (30·Q³·2^{−2λ} + 10·Q²·2^{−λ}) / (1 − 2^{w·log₂ b − r}) ] + q_S·2·√(3Q)·2^{−λ} + (smaller terms)
```

| Proved level, log₂ Q where the bound reaches 1 (q_S = 2^{64}) | VOLE-128 / 128f | VOLE-256 / 256f |
|---|---|---|
| Theorem 17-Q | **61.8** | **125.8** |
| Best quantum attack (Grover on γ) | 64 | 128 |
| Theorem 8 (current SIG, Don–Fehr–Majenz, § 5 bis) | 32.2 | 68.2 |

The quantum proof is therefore almost tight, within 2.2 bits of Grover. The reduction available for the current signature
loses half of its bits. The quantum level remains about λ/2: no NIST quantum category is claimed for VOLE-128.
Check: `*_qrom_a_moins_de_3_bits_de_grover` (`vole_proto`).

**Lemma 17.6 (round-by-round soundness of IP+, 12 November 2026).** This is the counterpart of their Lemma 57 for FAEST, which
the first version of this section only cited.

*The interactive proof IP+.* As in their § 6.1 and § 6.6, every oracle call of the signer becomes a round of interaction, in the
order of § 3 bis.2. The prover sends the input of the call and the verifier answers with a uniform value of the output length.
- Signer-only calls are replaced by sampling: the root `H_r`, the salt, `H_m` (the message is fixed).
- Rounds of error 0: the GGM tree `H_n`, level by level; the leaves `H_l`, one round per leaf; `H_c`, `H_C`, `H_A` (challenge
  h1); `H_v` (hv); `H_2` (h2); `H_3` (h3).
- Rounds with a non-zero error, with an empty prover message: `M = H_M(h1)` and `γ = H_g(h2)`.
- A last round with prover message `ctr` and challenge `(Δ, z) = H_d(h3, ctr)`.

The verifier of IP+ is the verifier of § 3 bis.2, with three changes:
1. Every hash value it needs is read from the transcript, and it rejects if a value it needs is missing. In particular, the
   opened nodes and the leaves below them must have been expanded in the `H_n` and `H_l` rounds.
2. Instead of recomputing `hv`, `h2`, `h3`, it compares the values it recomputes (`ht`, then the inputs of `H_2` and `H_3`) with
   the prover messages of those rounds.
3. It rejects if a commitment of the `H_c` round has two preimages among the `H_l` rounds. This verifier is not efficient, as in
   their FAEST-EM case; only its soundness matters.

*Extraction from a prefix* (as in (a) of Theorem 17, but from the transcript, not from an oracle table). Once the `H_A` round is
in the prefix:
- a repetition e is *open* if each of its N commitments, as sent in the `H_c` round, is the output of exactly one earlier
  `H_l` round; this defines `ũ′_e` and `ṽ_e`;
- it is *guessed* if exactly one commitment has no such preimage;
- it is *dead* if two have none: by change 1, the verifier rejects any opening that contains both.
The rounds are ordered, so no preimage can appear after the `H_c` round: the "late preimage" of the ROM proof has no counterpart
in IP+. It goes, with the collisions, into the term `30·Q³·2^{−ℓ_out}` of Theorem 54, which pays for turning an FS forger into an
IP+ prover.

*State function*, for `pk ∉ L`, meaning that no regular x has `Hx = y` (by Lemma 17.1, no assignment satisfies the constraints):
- `B_M`: M is in the prefix, and two open repetitions e ≠ e′ have `ũ′_e ≠ ũ′_{e′}` and `M·(ũ′_e ⊕ ũ′_{e′}) = 0`.
- `B_γ`: γ is in the prefix, ¬B_M, and the set `C = {e open : M·ũ′_e = ut}` is not empty. C then defines u*,
  `w′ = dw ⊕ u*|_wit`, and `C_d = Σ_j γ_j f_j(w′) = 0`.
- `RBRState = B_M ∨ B_γ ∨ Acc`, where `Acc` (complete transcripts only) means that the verifier of IP+ accepts.

*The three properties of their Definition 48.*
1. **Empty prefix:** no M, no γ, no complete transcript, so the state is 0.
2. **Transitions.** `B_M` only depends on M and on values fixed before it (the commitments, the leaves, aux): it can only switch
   on at the M round. `B_γ` only depends on γ and on values fixed before it (ut and dw, sent in the `H_2` round): it can only
   switch on at the γ round. `Acc` only exists after the last round. Hence:
   - **error 0** at every other round;
   - **M round:** at most `C(τ, 2)·2^{−(λ+B)}`, because `ũ′` is fixed and M is uniform, by (b) of Theorem 17;
   - **γ round:** at most `2^{−λ}`. If C is empty, `B_γ` cannot occur. Otherwise, w′ is not a solution, so `f(w′) ≠ 0` and
     `Pr_γ[C_d = 0] = 2^{−λ}`, by (c);
   - **last round:** from a prefix with ¬B_M ∧ ¬B_γ, `Pr_{(Δ,z)}[Acc] ≤ d·2^{−(τκ+wpow)}`, by (b′) and (d). The values of the
     inconsistent and guessed repetitions are fixed by the prefix, C is empty or `C_d ≠ 0`, and P has at most d roots.
3. **Complete transcript with state 0:** then ¬Acc, so the verifier rejects.

So IP+ is RBR-sound with errors `C(τ, 2)·2^{−(λ+B)}`, `2^{−λ}` and `d·2^{−(τκ+wpow)}`, and 0 elsewhere. Their maximum is
`ε = 2^{−λ}`, the value used above. ∎

*Limitations.*
- This is still a sketch, **not reviewed**. Lemma 17.6 re-proves the RBR soundness (their Lemma 57). Four points remain cited,
  not re-proved:
  1. the conditions of Theorem 54 for our derivation functions: tree, leaves, `H_c` and `H_C` must be
     collision-resistance-preserving and sensitive (their Definition 53). These are parallel and sequential applications of one
     domain-separated oracle, the case they treat;
  2. the passage from an FS forger to an IP+ prover, the counterpart of their § 6.8, which uses the two changes 1 and 3 of the
     verifier;
  3. the reprogramming of the signing oracle (their § 6.3 and § 6.10);
  4. one difference to check against their proof: Theorem 54 is stated with a single output length `ℓ_out`, whereas our last
     challenge `(Δ, z)` only has `τκ + wpow` bits (131 to 259). This challenge feeds no later hash, so its collisions do not
     break the extraction of the prefix, but the database argument of their Lemma 25 should be re-read with this in mind.
- It needs **(D-H3-R)**, the decisional version (`(seed, y)` indistinguishable from `(seed, uniform)`), which is one more
  assumption than in the ROM. Its best known distinguishers are the search attacks.
- Their constants assume all oracles are instantiated from one oracle by domain separation, as here (prefix ‖ domain).

### 3 bis.6 Strong unforgeability, binding, several keys

**Proposition 17.3 (SUF-CMA, ROM).** For every F as in Theorem 17,

```
Adv^{SUF-CMA}(F) ≤ Adv^{EUF-CMA}(F) [Theorem 17 bound] + (q_3 + 1)·2^{−(τκ + wpow)}
```

*Proof.* Let `(m*, σ*)` be valid, where m* was signed and σ* is none of its responses. If m* was never signed, Theorem 17 applies.
We exclude the collisions already counted.

*Unique encoding.* σ has a fixed length. Each of its fields is either compared or hashed:
- `salt`: hashed in `H_C`, in `H_c` and in every `H_n` and `H_l`;
- `aux`: in `H_A`;
- `ut` and `dw`: in `H_2`, with the padding of `dw` required to be zero;
- α: in `H_3`;
- `h3`: compared;
- the hidden commitments: in `H_c`;
- the opened nodes: they go through `H_n` and then `H_l` into the commitments. Every revealed node has leaves below it, and the
  unused slots must be zero.

The only field that enters no hash is `ctr`, and it acts only through the challenge `ch = H_d(h3, ctr)`.

Let `σ_i = (salt, h3, …)` be a response for m*. Three cases:
1. **The input of `H_A` is that of no response.** The analysis of Theorem 17 applies unchanged. A repetition that reuses
   simulated commitments has a leaf with no preimage, the hidden one: it is "guessed".
2. **`h1* = h1_i` but the input of `H_2` or of `H_3` is new.** Every repetition then has a leaf with no preimage, so all are
   guessed, and Δ* must equal `Δ_i` on all τκ bits. A query to `H_d` on the new `h3*` succeeds with probability
   `2^{−(τκ+wpow)}`.
3. **`h3* = h3_i`.** Everything up to α is identical. If `ctr* ≠ ctr_i`, the challenge must be the same (otherwise the hidden
   leaves change and their seeds are unknown, at a cost of `q_P/2^{λ+8}`), which costs `2^{−(τκ+wpow)}` per `H_d` query. If
   `ctr* = ctr_i`, the openings are fixed by the challenge, and another opening would give other leaves, i.e. a collision on
   `h1`. Hence `σ* = σ_i`. ∎

The term is `2^{−131}` (128 and 128f) and `2^{−259}` (256 and 256f): it does not change the level. **It is reached by an executed
attack.** On the reduced model (τκ = 12, wpow = 0), searching for another `ctr` that gives the same challenge costs 3 939 queries
on average, against 4 096 predicted (z = −0.52, 200 trials), and the modified signature is accepted. All 7 744 signatures that
differ by one bit are rejected. This malleability is intrinsic to grinding with a free counter, as in FAEST and SDitH. Removing it
would require the verifier to check that no smaller `ctr` passes, i.e. to redo the grinding.
Check: `suf_encodage_unique_et_seule_malleabilite_ctr_au_cout_predit`.

**Proposition 17.4 (binding to the key and the message).** A signature valid for `(pk, m)` is valid for `(pk′, m′) ≠ (pk, m)`,
even with `pk′` chosen by the attacker, only at the cost of a collision of `H_m`, `H_C` or `H_A`.

*Proof.* `hm = H_m(enc(pk) ‖ m)`, where `enc` has a fixed length per profile (the profile is in the prefix) and the message comes
last, so the input is injective in `(pk, m)`. `h1 = H_A(H_C(salt, hm, …), aux)` is recomputed at verification, and the equality of
`h3` forces that of h1 and then of `hm`, barring a collision. The cost is `2^{ℓ/2} = 2^λ`. ∎

This is the exclusive-ownership property (CEO, DEO) of Cremers et al. (2021), as for Proposition 10. Non-re-signability is not
claimed: m enters only through `H_m(pk ‖ m)`.

*Randomness failure.* The root is `H_r(pos, salt, hm)`. With a fixed salt, the same message gives the same signature (the
simulator of Theorem 17 relies on this memoisation), and two messages share no seed. Measured with an imposed salt on VOLE-128:
identical signature, and 0 common opened seeds out of 107 × 107 pairs. Check: `liaison_cle_message_et_alea_defaillant`, which also
covers rejection under another key (another seed, with its own H), another message, and a modified y.

**Corollary 17-mu (μ keys).** As in Corollary 8-mu. `hm` carries `pk`, so a query to `H_C` and to the challenges that follow
targets a single key, barring a collision. The hidden points carry a fresh salt, and each key has its own `seed_H`. The terms in q
take no factor μ; the last term becomes `2·μ·Adv^{H3-R}`, i.e. `2·μ·(C(n, w)/b^w)·Adv^{H3}` by Lemma 17.2 (i), plus
`μ²/2^{ℓ+1}` for a collision of keys.

---

## 4. BRUME-1024q (v0.6)

*Since v0.6 (author's decision of 13 November 2026, `docs/MIGRATION_V06.md`), the suite's permutation is BRUME-1024q:
1 024 bits, sponge rate r = 640, capacity c = 384, 32 rounds, for the 128-bit quantum profile. The § 4 of v0.5
(BRUME-512: Theorems 9 to 16, the AEAD with two profiles, tree hashing and parallel duplex on 512 bits) is kept as
history in `tests/historique_v05/PROOFS_v05_section4.md`. This section states the results for BRUME-1024q and gives
their status; the full arguments are in `docs/brume1024/` (cited per statement). Every numerical instantiation below is
recomputed from the constants of the code by `tests/test_bornes_preuves.py`.*

**Status of everything in this section: written by us, not reviewed by a third party.** The permutation is new and its
cryptanalysis is our own (§ 4.2). Models: ideal permutation for the modes; Markov (independent rounds) for the bounds on
characteristics.

### 4.1 The permutation, and the certified bound on characteristics

*Definition (normative).* `docs/brume1024/SPEC.md` § 2: 256 nibbles over GF(2⁴) = GF(2)[t]/(t⁴ + t + 1); round
x ↦ M·S(x ⊕ RC_r), r = 0 … 31; S the 4-bit S-box of v0.5 (`AD412650BFEC7893`: differential uniformity 4, linearity
8); M the weighted Cayley graph of the dihedral group D₂₅₆ with shifts K = {0, 105, 71, 76, 72, 31} plus the identity
(7 terms per row). Test vectors: SPEC § 4, `docs/brume1024/kat_b1024.txt`.

**Theorem 9 (v0.6, certified).** For every non-zero input difference (resp. output mask), any differential
characteristic (resp. linear trail) of BRUME-1024q has at least B = 8 active S-boxes over 2 rounds, C₃ ≥ 21 over
3 rounds and C₄ ≥ 28 over 4 rounds.
*Proof.* B = 8 is exact (branch number of M and Mᵀ, recomputed). C₃ ≥ 21 and C₄ ≥ 28 are certified by SAT on a
truncated relaxation of the rounds, nibble 0 active at round 0 by the transitive automorphisms of the graph; every leaf
proof (1 599 for C₄) and every completeness proof of the splits is checked by two LRAT checkers; the linear CNF equals
the differential one because supp M = supp Mᵀ (`docs/brume1024/README.md` § 3, `prototypes/brume_q/sat/`, audit
`tests/test_b1024_certificats.py`). ∎

**Corollary 11 (v0.6).** Over 32 rounds a characteristic has at least 8·C₄ = **224** active S-boxes, so probability
at most (4/16)^224 = **2^−448**, and a linear trail correlation at most (8/16)^224 = **2^−224**, in the Markov model.
With 4 rounds left free: 7·C₄ = 196 active S-boxes, 2^−392 and 2^−196. With C₃ alone: 218 and 190.
This bounds single characteristics, not differentials or hulls (aggregation, § 4.2).

### 4.2 Cryptanalysis: what is established, and what is not

| Family | Reach (rounds of 32) | Kind | Where |
|---|---|---|---|
| Characteristics, any | none beyond 2^−448 / 2^−224 at 32 rounds | certified bound (Corollary 11), Markov | § 4.1 |
| Aggregation (differentials, hulls) | 2 rounds: max DP 2^−16, hull 2^−7.83 (exact); 3–4 rounds, one-nibble ends: factor ≤ 1.25 | exact at the ends computed | `ETUDE_GROUPE_STRUCTURE.md` § A, `tests/test_b1024_structure.py` |
| Statistical battery, avalanche | distinguished to 4 rounds forward, not at 5; SAC from 5 forward, 2 backward | measured | `tests/test_b1024_statistiques.py` |
| Cubes, zero sums (measured) | 5 | measured | `README.md` § 4 |
| Exact division property | 11 inverse, 11 or 12 forward: **22 or 23 inside-out**, at a cost of about 2^1023 | proved / verified trails | `README.md` § 5, `dp1024/` |
| Truncated differentials | nothing beyond free diffusion to 4 rounds; decision runs UNKNOWN at 5–7; real permutation conforming to 7 | model + measured | `ETUDE_GROUPE_STRUCTURE.md` § B |
| Impossible differentials, zero correlations | 5 | structural | `README.md` § 6 |
| Boomerang | 3 rounds (2^−19.4); below 2^−32 at 4 | measured (GPU) | `README.md` § 4 |
| Differential-linear | model: 7 rounds within 2^128 pairs, 8 within 2^192 (8 and 9 if the gap measured at 4 rounds, about 2^11, holds at every round); measured \|ε\| < 2^−11.4 at 5 and 6 | model + measured | `DIFF_LIN.md` |
| Sponge collision, rebound type | 3 rounds at 2^92 (optimal in the model); 4–6 not found below 2^192, not excluded by the solver's bounds | model + measured | `REBOND.md` |
| Direct algebraic (CICO by SAT) | advantage over brute force up to 3 rounds (4 with a linearised first round) | measured | `ALGEBRIQUE.md` |
| Invariants, Frobenius, invariant subspaces, local quadratic invariants | none, for any round or all rounds at once (families searched) | exact computation | `tests/test_b1024_structure.py` |

**Margins.** Among families that give an attack or a distinguisher below the claimed level (2^192 classical, 2^128
quantum), the largest reach is 8 or 9 rounds (differential-linear): a margin of at least 23 rounds. The largest
structural property is the inside-out zero sum of the division property, 22 or 23 rounds at about 2^1023 evaluations,
which is not a break (`NIVEAU3.md` § 2): a margin of 9 or 10 rounds on that criterion. Attack models for the full
32 rounds: `NIVEAU3.md`. Missing: third-party cryptanalysis.

### 4.3 AEAD (full-state keyed duplex)

*Mode (normative):* SPEC § 3.5. Key K of 512 bits in the rate of the initial state, nonce of 192 bits (the last 64 in
the capacity), frame of mode 3; AAD then text, the rate overwritten by the ciphertext (SpongeWrap orientation, no
length block since option A); tag = 256 bits of the rate after the last text block; nothing released before the tag is
checked. Lengths below 2^64 bytes (2^63 − 1 in the code).

**Security level.** The mode offers λ bits of security for a data limit σ ≤ σ_max if, for every adversary,
Adv^AE(A) ≤ (N + q_d)/2^λ + 2^{−λ}. This is the usual cost/advantage notion, that of the NIST categories: an advantage
close to 1 requires about 2^λ queries. It does not require that an adversary making 2^λ queries stay at an advantage of
2^{−λ}; no AEAD satisfies that requirement (tag guessing alone gives q_d/2^τ, exhaustive key search N/2^k).

**Theorem 14 (v0.6, classical, ideal permutation).** For a nonce-respecting adversary without release of unverified
plaintext, with u users, uniform independent 512-bit keys, N offline queries to P, σ = σ_E + σ_D duplex calls
(σ ≤ 2^127, N + M ≤ 0.1·2^384), q_iv initialisations and q_d decryption queries:
  Adv^AE ≤ (2σ_D + 5)·N/2^384 + 2·q_iv·N/2^512 + q_d/2^256 + 2·C(u, 2)/2^512 + negligible terms.
*Proof.* Reduction of the AE game to the keyed duplex (KD → IXIF → ideal), `AEAD_SECURITY.md` § 4 bis, on top of
Theorem 1′, our repaired form of Theorem 1 of Daemen–Mennink–Van Assche (ASIACRYPT 2017), checked step by step for our
parameters (`AEAD_SECURITY.md` §§ 4 ter–4 quater; the repair is needed: the published Theorem 1 is exceeded when
L + Ω > 0, `prototypes/brume_q/b1024/dmv17_verif/papier/`). It agrees with Mennink 2023 Th. 7 and Dobraunig–Mennink
2019. ∎

**Corollary 14 bis (v0.6).** With N = σ_D = q_iv = q_d = 2^64 and one user: the terms are 2^−255, 2^−383 and 2^−192;
the advantage is about **2^−192**, dominated by tag guessing. Forgery costs q_d/2^256 per attempt (256-bit tag); inner
state recovery needs N·σ_D ≈ 2^384, that is 2^192 each.

**Theorem Q (v0.6, model Q1: classical queries to the mode, quantum queries to P).** For σ calls and q_Q quantum
queries: Adv ≤ 4σ·√(q_Q/2^384) + 2q_Q·√(2σ/2^384) + σ²/2^385 + 3σ²/2^1025 + q_d/2^256, with no loss in the number of
nonces or users (`AEAD_SECURITY.md` § 4 quinquies; two published lemmas used, statements and proofs re-read). At
q_Q = 2^128 and σ = 2^64 it gives **2^−30.5**; the level in the suite's cost/advantage sense is about 127 bits for at
most 2^64 calls. Probably not tight (best known attack: 2^192, Grover on one inner part).
**Superposition queries to the mode (Q2): not claimed.** Proved by us: decryption in superposition with classical
encryption (weak bound, § 4 sexies) and encryption in superposition confined to the last text block (Theorem Q2-1,
§ 4 septies). Two blocks or more in superposition: open.

### 4.4 Hashing (sponge, XOF, tree)

*Modes (normative):* SPEC §§ 3.2–3.4. One unkeyed sponge (mode 5) with four domains: XOF (0), tree leaf (8), tree root
(9), single message ≤ 8 KiB (10). Default digest H: 64 bytes; the single-message sponge up to 8 192 bytes, otherwise
leaves of 8 KiB with 64-byte chaining values and a root that absorbs CV₁ ‖ … ‖ CV_k ‖ be64(k) ‖ 0x00 0x00 0x20 0x00.

**Separation (structural, checked).** The four functions are the same sponge with distinct domains in the capacity, and
the root encoding is injective; a message is hashed in exactly one of the two default ways (`DOMAINS.md`, checks
`separation_des_domaines_structurelle` of `tests/c/brume1024.c`). Classically, each function is a sponge with c = 384:
generic collision and preimage cost 2^192 (the flat-sponge bound with n = 512).

**Theorem 16 (v0.6, quantum queries to P and P⁻¹, random permutation).** For the whole family (XOF, single message,
leaf and root, hence the default hash with its tree): p_col ≤ (64/3)·T³/2^d + 384·T³/2^384 + 23 232·T²/2^1024 and
p_pre ≤ 48·T²/2^d + 192·T³/2^384, for T swap queries and a d-bit output. Success 1/2 needs about **2^123.8 standard
queries for a collision** and 2^124.1 for a preimage (best generic attack: 2^128).
*Proof.* Adaptation of Carolan–Majenz (arXiv 2609.28469, Theorem 5.5) to our frame and domains: only their counting
lemma (5.4) depends on the construction, and it is redone for the four domains, with one more forbidden event
(`SPONGE_QROM.md`). The counting lemma is checked exhaustively on small models (`tests/test_b1024_preuves.py`); the
chain of the article itself is re-derived and evaluated exactly for N ≤ 6 and N = 7 up to level 3 (`CM_VERIFICATION.md`). ∎
Not covered: indifferentiability (about 2^42.7 proved, Alagic–Carolan–Majenz–Tokat 2025), multi-target preimages.

### 4.5 Parallel AEAD (mode 6)

*Mode (normative):* SPEC § 3.5 bis. Trunk (AAD) → S_A; leaf j: two fork calls (le64(j) ‖ 0x01 with domain 5, then 0^r
with domain 3), then chunk j of B = 8 192 bytes as the text phase of § 4.3; CV_j = 64 bytes; root from S_A over
CV₀ ‖ … ‖ CV_{k−1} ‖ le64(k) ‖ le64(ℓ), domain 4; tag 32 bytes.

**Lemma 5′ (encoding, checked mechanically).** The map (A, X) ↦ paths of the duplex calls is injective, prefix-free
and role-preserving (`V06_MODES.md` § 2.2; `tests/test_b1024_preuves.py`, 492 configurations, two witnesses that fail).

**Theorem P (v0.6, classical, ideal permutation).** With F_E the number of leaves over the encryption queries
(F_E ≤ q_e + σ_E/105): Adv^AE ≤ (2(σ_D + F_E) + 5)·N/2^384 + 2·q_iv·N/2^512 + q_d/2^256 + σ_D/2^512 + negligible terms
as in Theorem 14. L + Ω ≤ σ_D + F_E feeds Theorem 1′; the term σ_D/2^512 is a CV collision (2^−448 at σ_D = 2^64).
In Q1, Theorem Q applies with the fork covered by its Lemma D; same level, about 127 bits. Encryption in superposition
is not covered (`V06_MODES.md` §§ 2.3–2.4). Per leaf of 8 192 bytes: 2 fork calls + ⌊8192/80⌋ + 1 = 105 permutations.

### 4.6 TE mode (self-correcting)

*Mode:* `docs/SPEC.md` § 2.7, on top of the AEAD of § 4.3 (SPEC § 3.7): 7 parity bytes per 64-byte block of the
ciphertext; decryption corrects at most one byte per block, refuses inconsistent syndromes, then checks the tag.

**Proposition TE (exact reduction).** For every adversary A against TE, in the notion "AE up to the public correction",
there is an adversary B against the AEAD with the same resources and Adv^{AE-TE}(A) = Adv^{AE}(B) (`V06_MODES.md` § 1).
Hence every bound of § 4.3 (classical, Q1, Q2d) transfers unchanged. The parities only correct accidental errors: the tag
remains the only integrity guarantee. Implemented in v0.6 (`sl_te_*`), checked by `tests/c/brume1024_api.c`.

### 4.7 Implementation

Constant time is measured, not proved: dudect (`tests/c/temps1024.c`, `tests/c/temps.c`) and Valgrind/ctgrind
(`tests/test_c_brume1024_valgrind.py`) on the AVX2 kernels, the portable kernel and the AEAD (accept and reject paths). A layout-dependent dudect signal of the portable kernel, seen
when GCC 13.3 inlined it into the timing harness on Zen 3, is removed by making the kernel non-inlinable
(`AUDIT_REPORT.md`, changes of 2026-11-17).
No table indexed by secret data: S is a register shuffle (AVX2) or a 17-gate circuit (portable, bitsliced). The
library's outputs are those of SPEC § 4, recomputed by a second implementation written from the specification alone
(`tests/test_b1024_seconde_implementation.py`).

## 5. Parameters that follow from the proofs

| | n | w | D | n₂ | ISD security | proved δ (median / threshold) | pk | ct |
|---|---|---|---|---|---|---|---|---|
| Sillage-128 | 50 021 | 75 | 14 | 28 672 | 138.2 b | ≈ 2^−146 / 2^−128 | 6 285 B | 9 837 B |
| Sillage-256 | 170 003 | 140 | 28 | 114 688 | 265.1 b | ≈ 2^−289 / 2^−256 | 21 283 B | 35 587 B |

The levels are **classical**. Prange–Grover quantum estimate: 91.7
and 158.4 bits, below 128 and 256: no quantum level is claimed.
w goes from 74 to 75 and from 139 to 140 so that every attack cost stays at least that of v0.3 (137.3 and 264.9 b;
91.1 and 158.0 b): at equal w, reducing n lowers the elimination cost by about one bit. `we` is the smallest value keeping
the classical level of v0.3: at `we − 1`, the three-block message attack, which sets the level, drops to 137.0 and 264.4 b.
(An earlier wording said that `we` keeps the three-block attack at the level of the two-block one. That is not what
happens: at the chosen `we`, the three-block attack is still the cheapest, 138.2 b against 138.6 b for key recovery.)
`w − 1` gives 136.7 and 263.6 b. Both minimality claims are checked by `test_isd_parametres`
(`<level>_w_minimal_au_niveau_v03`, `<level>_we_minimal_au_niveau_v03`).

Signature: `[n, k, w] = [2048, 1434, 103]` and `[4096, 2867, 206]`, N = 2¹², τ = 11 / 23, t = 4, `K = GF(2^{44})` and `GF(2^{48})`. Forgery
cost 2^{128.3} and 2^{264} (§ 3.3); ISD 160.3 / 316.2 bits.

| | pk | sk | signature | v0.3 (Stern) |
|---|---|---|---|---|
| SIG-128 | 109 B | 464 B | **8 522 B** | 133 917 B on average (×15.7) |
| SIG-256 | 186 B | 977 B | **34 867 B** | 536 326 B on average (×15.4) |

*Choice.* The code is near the Gilbert–Varshamov bound, with a unique expected solution (`log₂ C(n, w) < r`). At fixed ISD cost,
the witness size is `k + 2w·e` bits. It decreases as the rate rises, up to the
unique-solution limit (`log₂ C(n, w) < r`), reached near a rate of 0.727: 3 622 and 7 608 bits, against 3 700 and 7 811 bits at
the chosen rate of 0.70. (An earlier wording said that a rate of 0.7 minimises it.) The rate of 0.70 keeps a uniqueness
margin of 29.5 and 56 bits. At the limit, the margin is 1.2 and 2.7 bits, and the witness would be 2 to 3 % smaller. `n = 2^e` simplifies F. N = 2¹⁶ would give 6.9 KB
for a running time ×16.

### ISD comparison (log₂ of operations, code without quasi-cyclic credit)

| Code (n, k, w) | Prange | Stern | Dumer | BJMM | BJMM optimum (p, ε, l) | Grover: Prange | walk: Stern, Dumer | walk: BJMM |
|---|---|---|---|---|---|---|---|---|
| SIG-128 (2048, 1434, 103) | 208.6 | 182.6 | 182.2 | **160.3** | 52, 7, 234 | 114.4 | 92.6, 92.6 | 76.2 |
| SIG-256 (4096, 2867, 206) | 398.8 | 361.8 | 361.0 | **316.2** | 104, 14, 468 | 210.5 | 184.4, 184.4 | 151.5 |
| KEM-128 (100042, 50021, 150) | 182.4 | 159.8 | 159.8 | **154.2** | 6, 2, 78 | 107.3 | 90.9, 90.9 | 82.4 |
| KEM-256 (340006, 170003, 280) | 315.9 | 289.7 | 289.7 | **283.4** | 6, 2, 88 | 175.8 | 156.9, 156.9 | 146.5 |

Model: one elimination costs n·r operations (amortised), one list operation
costs 1. This is deliberately favourable to the attacker: free memory, including
2^{236} elements for SIG-256.

*Correction.* The original grid stopped at p ≤ 24, ε ≤ 12 and l ≤ 160, and the BJMM optimum
for the signature touched its boundary: 160.5 and 327.2 bits were overestimated, by 0.8
and 12.3 bits. The levels still hold (≥ 128 and ≥ 256). The optimum is now
checked to lie inside the grid. The KEM (p = 6) does not change.

*Validation on real attacks* (`tests/c/isd_comparaison.c`, the same instances for
each algorithm, each solution re-checked on H·e = s):

| n, w | Algorithm | Measured iterations | Model | Measured cost | Model |
|---|---|---|---|---|---|
| 240, 13 | Prange | 2^{13.62} | 2^{13.49} | 2^{28.43} | 2^{28.31} |
| 240, 13 | Stern p=2, l=6 | 2^{8.57} | 2^{8.77} | 2^{23.39} | 2^{23.59} |
| 240, 13 | Stern p=4, l=11 | 2^{6.17} | 2^{6.24} | 2^{21.22} | 2^{21.29} |
| 240, 13 | Dumer p=2, l=6 | 2^{8.60} | 2^{8.63} | 2^{23.42} | 2^{23.45} |
| 240, 13 | Dumer p=4, l=11 | 2^{5.73} | 2^{5.78} | 2^{20.83} | 2^{20.87} |
| 240, 13 | BJMM p=4, l=12, ε=0 | 2^{6.73} | 2^{4.42} | 2^{21.69} | 2^{19.45} |
| 240, 13 | BJMM p=4, l=18, ε=2 | 2^{7.26} | 2^{4.93} | 2^{22.55} | 2^{20.63} |

(Full measurements for n = 200, 240, 280: `resultats/isd_comparaison.json`.)

Prange, Stern and Dumer follow the model within 0.3 bit, in iterations as in
cost. BJMM needs about 4.4 to 5 times more iterations than the model (2.1 to 2.3 bits):
the model counts a representation that is always found, whereas the balanced split and the
filtering lose some. This bias is conservative. At these small sizes, elimination still dominates
and BJMM does not catch up with Dumer: the advantage of BJMM at large sizes rests on
the model, not on a measurement.

*Comparison with a third-party estimator* (CryptographicEstimators 2.1.1, Esser–Bellini;
values frozen in `tests/test_isd_parametres.py`):

| Code | Prange | Stern | Dumer | BJMM | Minimum margin of our estimator |
|---|---|---|---|---|---|
| SIG-128 | 217.1 | 193.6 | 193.2 | 177.6 | 8.5 b |
| SIG-256 | 408.1 | 373.8 | 373.0 | 342.5 | 9.3 b |
| KEM-128 | 195.5 | 173.9 | 174.0 | 174.0 | 13.1 b |
| KEM-256 | 330.6 | 305.5 | 305.6 | 305.6 | 14.7 b |

That tool's costs count bit operations, including vector sizes and the real cost of
elimination. Our model stays systematically below: the
stated levels are therefore conservative, by 8.5 to 26 bits depending on the case and the algorithm.

---

## 5 bis. Quantum adversary: what holds and what does not

The suite's 128 and 256 levels are **classical**. Against a
quantum adversary, the situation per component is as follows.

| Component | Best generic quantum attack | Quantum level | Proof model |
|---|---|---|---|
| Sillage-KEM | Accelerated ISD. Prange–Grover: ≈ 92 / 158 bits. Quantum walks with free QRAM: ≈ 67 / 129 bits | **between 67 and 92 / between 129 and 158 bits** depending on the model | FO with implicit rejection: known QROM reductions (Jiang et al. 2018; Bindel et al. 2019), with a quadratic loss in q and in √δ; not instantiated here |
| Sillage-SIG v0.5 (VOLE) | Grover on γ, √(2^{λ}) | **≈ 64 / 128 bits** | Theorem 17-Q (§ 3 bis.5, sketch): 61.8 / 125.8 bits proved, needs (D-H3-R) |
| Sillage-SIG v0.4 (reference) | Grover on forgery, √(2^{128.3}) and √(2^{264}) | **≈ 64 / 132 bits** | QROM: Don–Fehr–Majenz–Schaffner (2019, 2022), Aguilar-Melchor–Hülsing et al. (2021, multi-round), loss in O(q²); not instantiated here |
| BRUME-1024q AEAD | Grover key search (k = 512 bits): 2^{256}; inner-state recovery, Grover on 384 bits: 2^{192} | **≈ 127 bits** (cost/advantage, σ ≤ 2^64) | Q1 (classical queries to the mode, P in superposition): Theorem Q (§ 4.3), ours, not reviewed; Q2 not claimed |
| BRUME-1024q hashing | generic quantum collisions (Brassard–Høyer–Tapp): 2^{c/3} = 2^{128} with c = 384 | **128 bits** for collisions (generic); 2^{123.8} queries proved (Theorem 16, § 4.4) | quantum queries to P and P⁻¹, random permutation; indifferentiability only ≈ 2^{42.7} proved |

### Instantiating the QROM reductions

The levels above come from the best known attacks. The published reductions, applied as they stand, **prove markedly
less**. Notation: log₂ of the number q of queries at which the bound reaches 1. This is a lower bound proved under an assumption, not an attack.

*KEM.* Form of Hövelmanns–Hülsing–Majenz (2022), Theorem 8 and § 1, for FO with **explicit** rejection in the extended QROM:

```
Adv^{IND-CCA} ≲ 8·q²·δ  +  4·√(d·Adv^{IND-CPA}) + 8·q/√|M|  +  12·q_D·(q_G + 4·q_D)·2^{−γ/2}
```

`Adv^{IND-CPA}` is bounded by the cost of known attacks, `T²/2^{2b}` in Grover queries, with b the quantum level and d the depth.
Spreadness is rigorous: for fixed `r1`, `u` determines `r2`, so every ciphertext has probability ≤ `1/C(n, w)`, for every h, and
`γ ≥ log₂ C(n, w)`, i.e. 807 and 1 631 bits: this term is negligible.

| Term (bound = 1) | Sillage-128 | Sillage-256 |
|---|---|---|
| `8q²δ`, δ ≤ `2^{−λ}` | 62.5 | 126.5 |
| `8q/√|M|`, k = λ | 61 | 125 |
| IND-CPA, b = Prange–Grover, d = q | 59.8 | 104.3 |
| IND-CPA, b = Prange–Grover, d = 2^{40} | 69.7 | 136.4 |
| IND-CPA, b = walk with free QRAM, d = q | 43.2 | 84.7 |
| **Proved (d = q)** | **≈ 60** (43 with free QRAM) | **≈ 104** (85) |

The correctness term goes through FFP-CCA ≤ COR: with the key, decryption can be simulated, hence `8q²δ`, without a `q_D` factor, δ being bounded for each accepted key
(§ 2.3). This is a Grover search **with the secret key**, which a real adversary does not have; it is not the limiting term here. `|M| = 2^λ` gives `q/2^{λ/2}`.

*Implicit rejection and the key H(μ, ct): the bound applies, checked on 2026-11-03.* Sillage is `U^⊥̸(T[PKE, G], H)`, key `H(μ, ct)`,
rejection `H'(σ_rej, ct)`. Statements re-read in Bindel, Hamburg, Hövelmanns, Hülsing and Persichetti (TCC 2019) and in Hövelmanns, Hülsing and Majenz
(ASIACRYPT 2022, Remark 1):
- *BHH+19, Theorem 5*: for a dPKE, deriving the key from `(μ, ct)` or from `μ` alone gives exactly the same IND-CCA advantage, with explicit
  as with implicit rejection (indifferentiability argument: H is only called on `(μ, ct)` when `ct = Enc(pk, μ)`);
- *BHH+19, Theorem 3*: the advantage against implicit rejection is **equal** to the one against explicit rejection (the reduction draws the
  rejection key itself; here `H'` is a domain-separated oracle, which the reduction simulates);
- the HHM22 bound above, proved for explicit rejection and the key `H(μ)`, therefore holds **without loss** for Sillage.

Direct bound for implicit rejection (BHH+19, Theorems 1 and 2 and Lemma 6), which assumes the derandomised encryption to be ε-injective:
```
Adv^{IND-CCA} ≤ 2·√((d + 2)·Adv^{IND-CPA} + 8(q + 1)/|M|)  +  ((4d + 1)·δ + √(3ε))·(q + q_D) + ε  +  4·√(d·q/2^{256})  +  ε
```
*ε-injectivity.* Two distinct messages give the same ciphertext only with probability ≤ `2^{−γ}` (spreadness above), hence, over the
`2^{2k}` pairs, `ε ≤ 2^{2k−γ}` = `2^{−551}` and `2^{−1119}`: negligible. The last term is the 256-bit rejection key.

| Term (bound = 1, d = q) | Sillage-128 | Sillage-256 |
|---|---|---|
| IND-CPA, b = Prange–Grover | 60.5 | 105.0 |
| `8(q + 1)/|M|` under the root | 123 | 251 |
| `(4d + 1)·δ·(q + q_D)`, q_D ≤ q, δ ≤ `2^{−λ}` | 62.5 | 126.5 |
| rejection key, `4√(dq/2^{256})` | 126 | 126 |
| **Proved** | **≈ 60** | **≈ 105** |

The |M| term becomes negligible (123 bits instead of 61); the proved levels remain set by IND-CPA, as with HHM22. Papers:
BHH+19 read from the CASA (Bochum) repository, HHM22 from arXiv 2203.10182; the IACR ePrint refuses automated downloads.

*SIG.* Don–Fehr–Majenz (CRYPTO 2020), Corollary 13, for a proof with 2n + 1 passes, here n = 2:

```
Pr[FS accepts] ≤ (2q + 3)⁴/2 · ε_int + 2/|C|,     ε_int = (p + (1 − p)/N)^τ ≈ N^{−τ}
```

Hence `8q⁴·N^{−τ} ≤ 1`: **q ≈ 2^{32.2}** and **2^{68.2}**, to be compared with the 2^{64.1} and 2^{132} of the Grover attack. The loss in `q^{2n}` is
optimal for this general theorem (their Corollary 19), but nothing indicates that it is reached here, where the known attack stays in `q²`.

*Limitations.* This is a sketch. `ε_int` assumes perfectly binding commitments, whereas `H_c` is an oracle: one would need to instantiate the
*collapsing* property of `H_c`. Their Theorem 23 gives UF-CMA, and sUF-CMA if the responses are computationally unique (Proposition 9 is the classical
version), but without a numerical bound, and assuming the protocol is a quantum proof of knowledge, which has not been established here.

### Sillage-SIG: checking the quantum parameters

Bits in queries, then gates under MAXDEPTH (`SillageSIG.security_estimate()["quantique"]`):

| Attack | SIG-128 | SIG-256 |
|---|---|---|
| Grover on forgery | 64.1 | 132.0 |
| Grover on the seeds, √(2^{8·sb}) | 68.0 | 132.0 |
| Hash collisions (BHT, QRAM of 2^{ℓ/3}) | 85.3 | 170.7 |
| Prange–Grover ISD | 114.4 | 210.5 |
| Quantum-walk ISD (free QRAM) | 76.2 | 151.5 |
| **Effective** | **64.1** | **132.0** |
| Gates, MAXDEPTH = 2^{40} / 2^{64} / 2^{96} | 2^{114.1} / 2^{90.1} / 2^{82.4} | 2^{245.8} / 2^{221.8} / 2^{189.8} |
| AES-128 threshold (2^{170}/MAXDEPTH) | 2^{130} / 2^{106} / 2^{74} | |
| AES-192 threshold (2^{233}/MAXDEPTH) | | 2^{193} / 2^{169} / 2^{137} |
| **NIST quantum category** | **none** (≈ 16 bits short at 2^{40} and 2^{64}) | **3** (≈ 12 bits short of 5) |

*Comparison with v0.3 (Stern).* Effective 64.0 and 128.0; gates 2^{113.9} and 2^{242.0} at MAXDEPTH = 2^{40}; same categories; Prange–Grover
ISD 110.7 and 200.9: **everything is kept or better**, except one line that does not limit the level: the quantum
walk on ISD, with free QRAM, goes from 78.7 to 76.2 bits and from 156.7 to 151.5 bits (still 12 and 19 bits above
the effective level). The seeds are λ + 8 bits long for this reason: testing a seed now costs only one Keccak, against a whole stream and
a product H·u for σ_π, and the gate cost would drop by 4 bits without these 8 bits.

Gate model, coarse and favourable to the attacker: a forgery oracle of 4
Keccak-f[1600], of 76 800 Toffoli each (only `h2` and the challenges are recomputed) and of
depth 48; a seed oracle of one Keccak; total depth limited to MAXDEPTH via N·g·d/MD gates.

*Consequences.*
- **SIG.** The profiles only offer **about half** of their nominal level.
- **Lead 7.** It would require N^τ ≥ 2^{256}, 32-byte seeds and, for ISD, w = 204
  (n = 4 080, rate 1/2, Prange–Grover) or w = 278 (n = 5 560, walk with free QRAM). Check:
  `tests/test_isd_parametres.py :: sig_niveau_quantique`.
- **KEM.** It does not reach 128 / 256 quantum bits in queries. The low end
  assumes free QRAM and takes the whole quasi-cyclic credit (log₂ n), which
  overstates the attack: Grover only gets ½·log₂ n from it. Placing it in the NIST categories
  would require a gate model specific to its sizes. Done on 18 November 2026 for the whole suite
  ([`NIST_CATEGORIES.md`](NIST_CATEGORIES.md)): the KEM is limited by classical ISD, not by quantum ISD.
- **Hashing.** With c = 256, generic resistance to quantum
  collisions is about 2^{85}. It is 2^{128} classically.

---

## 6. What remains outside the proofs

- The hardness of (H1-P), (H2-P) and (H3) is an assumption, supported by the
  ISD estimators. These are validated on reduced instances
  (`tests/c/isd_reel.c`): the real cost of Prange follows the formula within 8 %,
  and the measured quasi-cyclic gain equals the log₂ n credit of
  the estimator. **Proved (Lemma 0):** the exact linear spectrum of H1-P and
  of H2-P, hence the parity of s (resp. of u) is the only linear invariant, at
  every size; a linear distinguisher amounts to a decoding
  problem, estimated at the level of ISD (`tests/c/h1p_fourier.c`, heuristic).
  No correlation between u, v and s is detected at full sizes
  (`tests/c/kem_distributions.c`). Still outside the proofs: non-linear
  distinguishers, and the transfer of H1-P from uniform secrets to accepted
  keys (stated as an assumption, § 1).
- BRUME-1024q (§ 4): every statement is ours and **not reviewed**; the permutation is new and its cryptanalysis is our
  own. Quantum indifferentiability of the hash: only ≈ 2^42.7 proved. Q2 (superposition queries to the keyed modes):
  not claimed beyond the two partial results of § 4.3.
- SIG: the MPC-in-the-Head protocol and Theorem 8 are new in v0.4, neither audited nor reviewed by a third party. They reuse
  published constructions (SDitH, hypercube, Kales–Zaverucha bound) and are run on a reduced model (`tests/test_sig_modele.py`),
  but the binary instance with rate 0.7 and n = 2^e has no dedicated third-party analysis, beyond generic ISD.
- VOLE-in-the-Head signature (§ 3 bis, the signature of v0.5). Theorem 17 (ROM), Propositions 17.3 (SUF-CMA) and 17.4 (binding)
  and Lemmas 17.1, 17.2, 17.5 and 17.6 were written on 11 and 12 November 2026, and **have not been reviewed by a third party**.
  With the direct form of Lemma 17.2, the scheme rests on (H3), as stated in § 1, alone in the ROM. The QROM sketch (Theorem
  17-Q) needs the decisional version (D-H3-R). Its round-by-round soundness is proved (Lemma 17.6), but four steps are still
  cited (§ 3 bis.5). The three soundness terms are matched by executed attacks on reduced models.
- BRUME-1024q, aggregation beyond 2 rounds: exact sums at chosen ends (factor ≤ 1.25), not a bound over all ends.
  Division property: 11 rounds per direction proved, 12 forward undecided; 22 or 23 inside-out is a structural property
  (about 2^1023), not an attack. Rebound collisions beyond 3 rounds: not found below 2^192, not excluded. Differential-linear:
  the model is off by about 2^11 at 4 rounds; it is not a bound (§ 4.2).
- QROM: reductions instantiated in § 5 bis; the KEM's implicit rejection is covered (BHH+19, Theorems 3 and 5); collapsing of `H_c` and
  quantum proof of knowledge of the signature not established. They prove markedly less than the levels of known attacks (≈ 60 / 105 bits
  for the KEM, ≈ 32 / 68 bits for the signature), which are themselves below the nominal levels.
- Several ciphertexts under one key (§ 2.4): Sillage-128 loses log₂ N bits by exhaustive search on μ (k = λ); no known gain with
  several keys.
- AEAD, parallel AEAD and TE (§§ 4.3–4.6): proofs written in the ideal-permutation model (Theorems 14, Q and P,
  Proposition TE), not reviewed by a third party. The AEAD rests on our repaired Theorem 1′ of DMV17. On ARM, the
  library uses the portable constant-time kernel (no NEON kernel yet); its outputs are checked, its timing on ARM is
  not measured.
- Side channels: BRUME-1024q, the KEM and the signature in C are constant-time by construction and by measurement
  (dudect); the Python code is not. BRUME-1024q, the KEM and the signature are additionally checked with Valgrind (no
  branch or memory access depending on a secret, `tests/test_c_brume1024_valgrind.py`, `tests/test_c_kem_valgrind.py`,
  `tests/test_c_sig_valgrind.py`). These are measurements, not a certification.
