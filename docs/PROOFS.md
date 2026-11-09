# Security proofs — SILLAGE v0.4

*Section numbers are stable: the “PROOFS § n” references in the code point to this text.*

This document collects the statements and proofs behind the suite's claims.
Each statement gives its model (standard model, random oracle model ROM,
ideal permutation) and its assumptions. The corresponding numerical checks
are cited (`tests/…`). Every numerical instantiation in this text (Corollaries 11, 14 bis and 14 ter, Theorems 14-mu
and 14-p, the tables of § 2.4, § 5 and § 5 bis) is recomputed from the constants of the code by
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

## 4. BRUME-512

**Theorem 9 (wide trail by pairs).** If
`B = min_{x≠0} wt(x) + wt(Mx) ≥ 8` (weights in nibbles), every
characteristic over 2r rounds activates at least 8r S-boxes.

*Proof.* Over two consecutive rounds, `wt(Δ_0) + wt(Δ_1) = wt(Δ'_0) + wt(M·Δ'_0) ≥ B`,
since the S-boxes are bijective. Sum over the r blocks. ∎

**Proposition 10 (B = 8 exactly).** If `wt(x) + wt(Mx) < 8`, then
`wt(x) ≤ 3` or `wt(Mx) ≤ 3`. Exhaustive enumeration of the vectors of weight
≤ 3 for M and for `M^{−1}` (reduced by a scalar of GF(16)) gives
minima of 8, 13, 17 and ≥ 99; B = 8 is reached at weight 1. In the linear case,
`L_c^T = G·L_c·G^{−1}` (G: Gram matrix of the trace), hence
`M^T_bin = (G⊗I)·M^T·(G^{−1}⊗I)`, which has the same activity patterns. We
certify `M^T` and `(M^T)^{−1}` in the same way. Check:
`tests/test_branch_exact.py`.

**Corollary 11.** At 32 rounds, every characteristic activates at least 128
S-boxes (certified, Theorem 9 and Proposition 10). **In the Markov
model** (independent rounds, as if each round had a uniform
subkey), its probability is the product of the local probabilities, hence
≤ `(2^{−2})^{128} = 2^{−256}` (U = 4), and every linear trail has a
correlation ≤ `(2^{−1})^{128} = 2^{−128}` (max|LAT| = 4).

*Scope.* BRUME-512 is an unkeyed permutation with fixed round
constants: the Markov model is an assumption there, not a fact.
These bounds concern a characteristic, not an aggregated
differential (Proposition 12). Neither one, on its own, proves the
resistance of the concrete permutation to all differential, linear and
structural attacks, which remains the ideal-permutation assumption
of the mode proofs.

**Proposition 10 bis (diffusion support, certified).** The six
generators of the Cayley graph of D₁₂₈ are reflections, with
s_a·s_b = r^{a−b}. The combinatorial support of M^r (diagonal included),
seen from one nibble, is 7, 37, 94 and 127 for r = 1 to 4, and 128 from
r = 5 on. 37 and 94 are exactly the group bounds:
6 reflections, then 31 rotations in at most 2 products, then 63
reflections in at most 3 products. The support of M⁻¹ is dense from r = 1
(111 to 125 nibbles) and complete from r = 2. The actual dependency through the
permutation (S-boxes included) coincides with the combinatorial support:
full diffusion in 5 rounds forward and 2 backward. The support of the
linear powers M^r over GF(16) is never complete: about one
coefficient in 16 is zero, as for any dense matrix. But these
cancellations do not compose through the S-boxes.

*Spectrum.* A graph generated by reflections is bipartite (rotations ↔
reflections). Its spectrum therefore contains the trivial values +6 and −6, and
λ* = 3.5076 denotes the largest |λ| among the other 126, below
2√5 ≈ 4.472. Check: `tests/c/diffusion_support.c`.

*Correction.* A version of the artifact stated “7, 49 then 128 in 3
rounds”, assuming growth in 7^r. The external audit pointed it out
(second pass, point 1). The test suite already measured 5 rounds.

**Proposition 12 (trail aggregation over 2 rounds, Park et al. 2003).** In
the Markov model,
`MEDP_2 ≤ max_u Σ_v DP(u,v)^8` and `MELP_2 ≤ max_u Σ_v LP(u,v)^8`. The
values are computed by `tests/test_hull.py`. For R ≥ 2 rounds,
`MEDP_R ≤ MEDP_2`, since `Σ_c DP_B(c, b) = 1` for every bijection B. Beyond
these bounds, aggregation is measured experimentally: the clustering
factor at 2 rounds in `test_hull` and `test_diff_lin_empirique`. There is
moreover a margin of more than 2 500 bits between the best
trails found at 14 rounds and the proved thresholds at 32 rounds.

**Proposition 12 bis (reach of the division property).** Let `x^u → y_j`
with `wt(u) = 511`. (i) *Lower bound.* As long as the Boura–Canteaut bound
on the degree stays < 511 (10 rounds in each direction, S-box of degree 3,
m = 4), all bits are balanced over the cube: a distinguisher on 10 rounds
in each direction, hence an inside-out zero-sum on 20 rounds. (ii) *Upper
bound.* If every output bit j admits at round R a monomial trail
`u → … → e_j` (a sequence of transitions each with a non-zero
coefficient in the exact table of the S-box with its constant, or in the
binary matrix of M), the division property no longer predicts any
balanced bit. If the trail to bit i extends by one round to a
set of bits J(i), then the coverage at round R+1 contains ∪ J(i), and
full coverage is maintained at every later round (induction). These
trails are built and re-checked with `tests/pistes_monomiales.py`.
**For the cube whose bit 0 is inactive**, full coverage is obtained
at round 15 forward and at round 12 backward: for this cube,
there is no DP distinguisher beyond 14 rounds forward and 11 backward.
Check: `tests/test_division_property.py` (trail cache:
`resultats/pistes_division.json`).

*Extension to all cubes.* An attacker chooses the inactive bit among
512, and the coefficients and round constants break every symmetry
between cubes: trails cannot be transported by an
automorphism. They are transported by splicing.

**Lemma 12 ter (splicing).** Let τ be a verified trail of cube 0 at
round R, and X its state after the first linear layer L₁. For a cube
a, if there is a trail prefix of cube a that ends exactly at X
after L₁, then the concatenation of this prefix and the suffix of τ is a
verified trail of cube a to the same bit, at the same round.

*Proof.* The transition rules are local: each depends only
on two consecutive states, the position and the round constant. The
suffix of τ, from X on, is unchanged. ∎

*Building the prefix.* The linear layer moves inactive bits
freely:
- *Backward (L then S).* X = all ∖ {k}. One needs an assignment from
  all ∖ {a} to X: each output of X receives an edge of L, each
  input emits at least one. Since |X| = 511, this is a perfect matching
  of the bipartite graph of L.
- *Forward (S then L).* In the exact table of the S-box (with
  the round-0 constant), choose an output v for the nibble of bit a. Then
  look for a surjective assignment from X onto the resulting state U₁:
  a Hopcroft–Karp matching that saturates U₁, after which each remaining
  output of X is attached to an active neighbour.

**Corollary 12 quater (upper bound, all cubes).** For each of the
512 cubes of dimension 511, every output bit admits a verified trail
at round 15 forward and at round 12 backward. Hence no DP distinguisher
exists, whatever the cube, beyond 14 rounds forward and
11 backward, i.e. 25 rounds inside-out. This also holds for cubes of
dimension < 511: such a cube J is contained in a cube I of dimension
511, and a monomial divisible by x^I is divisible by x^J.

*Check* (`tests/test_dp_tous_cubes.py`). The 27 cached trails
are spliced for each of the 512 cubes, i.e. 13 824 splicings, and
each resulting trail is re-checked by `verifier(…, inactif=a)`, which
ignores how it was built. No splicing fails. Coverage then
propagates as for cube 0: 512 bits at round 15 (forward) and at
round 12 (backward) for each of the 512 cubes. Duration: 9 minutes on 12
threads.

*Exact search* (`tests/dp_cpsat.py`, CP-SAT): same model, inactive
bit left free, weight windows without loss of correctness (weight
≤ D(R − t) from the end; weight ≥ 512 − D′(t) from the cube, by the
Boura–Canteaut 2013 theorem). The windows alone make the model
infeasible for R ≤ 10 in both directions, which recovers the lower bound.
The full model is too large to conclude at 11 rounds: 1.4 million
variables backward, one trail in 18 minutes at R = 12, and targeted
queries that do not conclude in 25 minutes. Linear cuts per
nibble (wt(u) ≤ 3·[v ≠ 0] + [v = F], cw(v) ≤ 3·[u ≠ F] + [u = 0],
checked on the 3 194 transitions of all exact tables) make
the Boura–Canteaut bound visible to the LP relaxation, without being enough.

**Lemma 12 quinquies (decomposition).** Let τ be a verified trail and i0
a layer. Every sequence of valid transitions that starts from the state of τ at
layer i0 and leads to e_j at round R gives, appended to the prefix of τ, a
verified trail to j at round R (locality of the rules, as in Lemma
12 ter). The prefix of τ may come from a trail with a different number
of rounds: the layers of the first rounds, constants included, are
the same.

*Implementation* (`tests/dp_queue.py`). The suffix is searched by CP-SAT
in a model reduced to the bits reachable from the fixed state and
co-reachable from the target bit: a few thousand variables, and
about one second per query instead of several hours.

**Theorem 12 sexies (exact reach of the division property).** For
every cube, and in each direction, the bit-based division property (exact
monomial trails, constants included) proves the balance of all
bits up to 10 rounds, and of no bit at 11 rounds. Its reach is therefore
**exactly 10 rounds per direction, and 20 rounds inside-out**.

*Proof.* The lower bound is Proposition 12 bis (i). For the upper
bound, `tests/test_dp_exact.py` exhibits, for cube 0, a
verified trail to each of the 512 bits at round 11, in each direction:
- *Forward.* No 11-round trail was known. The 9
  cached trails (12 and 13 rounds) are truncated at layers 10 and 12, and completed
  to an arbitrary bit at round 11: 18 base trails of 11 rounds. For
  each bit j, a base is then completed to j, starting from the
  latest cut (layer 18, then 16, 14 and 12).
- *Backward.* The 18 cached 11-round trails are completed from
  layer 18, then 16 and 14.

The 1 024 trails are re-checked by `verifier`, which ignores their
construction. All share with a cached trail the state that follows the
first linear layer. Splicing these trails onto the 512 cubes
is checked (Corollary 12 quater); by Lemma 12 ter, it applies
as is to the completed trails. A sample of 96 trails spliced onto
randomly drawn cubes is fully re-checked. Cubes of
dimension < 511 follow as in Corollary 12 quater. ∎

*Scope of the statement.* A trail shows that the method no longer proves
balance. It does not show that the sum over the cube is non-zero,
since trails in even number cancel. The actual integral distinguisher
could therefore go beyond 10 rounds. Measuring it exactly
would require counting trails modulo 2 (full monomial
prediction), which remains out of reach at this size. Empirically, the
cubes only distinguish 4 rounds forward and 3 backward.

Duration: 12 minutes on 12 threads for the search, 40 s to re-check
the cache (`resultats/pistes_exactes.json`).

**Proposition 12 septies (duality and degree sandwich).** For a permutation F on n bits, let
`σ(F, i, j) = ⊕_{x : x_i = 0} F_j(x)`. Then (i) `σ(F, i, j) = σ(F⁻¹, j, i)`. (ii) If `F = F2 ∘ F1` and `deg(F1⁻¹) + deg(F2) < n`, then
`σ(F, i, j) = 0`. For BRUME-512, `D(5) + D(5) = 486 < 512` recovers balance at 10 rounds, and `D(5) + D(6) = 665`: the degree argument alone stops there.

*Proof.* (i) Let `a = #{x : x_i = 0, F_j(x) = 1}` and `b = #{x : x_i = 1, F_j(x) = 0}`. `#{x_i = 1, F_j = 1}` equals both `2^{n−1} − a` and `2^{n−1} − b`, so `a = b`.
Now `σ(F, i, j)` is the parity of a, and `σ(F⁻¹, j, i)` that of b. (ii) With `z = F1(x)`,
`σ = Σ_z (1 + (F1⁻¹)_i(z))·(F2)_j(z)`. The first term is zero, F2 being balanced. The second is the sum over the whole space of a polynomial of degree < n, hence zero. ∎

The duality is checked exactly on mini-BRUME (`dualite_F_F_inverse_exacte_sur_les_cubes`).

### 4.2 bis Further cryptanalysis: what is established, and what is not

Three similar-looking statements do not have the same status:

| Statement | Nature | What it does not say |
|---|---|---|
| ≥ 128 active S-boxes per characteristic over 32 rounds | **proved and certified** (Theorem 9, Proposition 10), a property of the construction | nothing about probabilities, nor about aggregated differentials |
| Characteristic ≤ 2⁻²⁵⁶, linear trail ≤ 2⁻¹²⁸ | **Markov model**: an assumption, BRUME having no subkeys | nothing about the concrete permutation; at small scale, a fixed-constant instance deviates from the model by the key-to-key dispersion, not more (below) |
| 20 rounds inside-out | **exact reach of the division property** | it is not an actual integral attack on 20 rounds, nor a ceiling for such an attack |

The actual integral reach and aggregation beyond 2 rounds remain **open** at 512 bits. What follows sheds light on them without closing them.

**Exact model, mini-BRUME** (`tests/c/mini_brume.c`): same S-box, same form of linear layer, 24 and 32 bits, everything computed exactly. *This is not a proof for
512 bits*: the graph and the scale change.

| Question | 24 bits (8 instances) | 32 bits (4 instances) |
|---|---|---|
| Boura–Canteaut bound (rounds) | 4 | 4 |
| Actual integral reach, all bits zero | 4 | **5** |
| Next round: non-zero bits | ≈ 50 % (random) | ≈ 50 % |

At 32 bits, reality therefore exceeds the degree bound by one round. This may come from cancelling trails, which would make the division property misleading, or from a bound that is too loose.
Direct test, SAT solver with weight windows: of 20 queries at 5 rounds and 32 bits, **13 with no trail at all, 0 with a trail, 7 undecided** at 15 minutes. **No cancellation was
observed**: where the computation finishes, the division property sees this extra round. Caveat: 7 queries remain undecided, and this small-scale result does not guarantee 512 bits.

*Aggregation and Markov* (input nibble, exact distribution versus Markov chain and best trail, two α per instance, 8 instances).
Each round XORs its constant before the S-boxes, so with **independent uniform constants the Markov chain is exactly the average of
the real distribution over the constants** (Lai–Massey–Murphy for differences, Nyberg for LP). The test uses this to calibrate the
noise instead of assuming it: for each instance, α and R, 32 random constant sets give the same ratio, on the same 64 points chosen by
the model. Their mean is 1 in every case (check `markov_egal_a_la_moyenne_sur_les_constantes`); their spread σ is the actual deviation
of a fixed-constant instance from the model.

| Rounds | Actual peak / best trail | Actual / Markov, 64 points (diff.) | σ between constants (diff.; Poisson) | Exact LP / ELP, likewise | σ between constants (lin.; Poisson) | max \|z\| against the constants |
|---|---|---|---|---|---|---|
| 2 | ≤ 1.25 | 1.000 (exact, for every constant set) | 0 | 0.99 to 1.04 | 0.0025 (0.004) | 1.4 |
| 3 | ≤ 3.4 (peak chosen after the fact: biased upwards) | 0.95 to 1.12 | 0.025 (0.024) | 0.70 to 1.14 | 0.14 (0.047) | 1.9 |
| 4 | at noise level (random control: H_max = 16, actual ≤ 20) | 0.52 to 1.07 | 0.18 (0.16) | 0.73 to 1.16 | 0.18 (0.12) | 2.4 |
| 5 | likewise | 0.72 to 1.40 | 0.18 (0.18) | 0.72 to 1.33 | 0.17 (0.13) | 2.5 |

σ: median over the 16 (instance, α) cases; in brackets, what a Poisson noise of variance 2·N·p per point (N·p for c²) would give.
**No instance deviates from Markov more than a typical constant set does**: max |z| ≤ 2.5 over 128 cases, and the RMS of z is 0.7 to
1.0. At 3 rounds the differential spread matches Poisson (0.35 to 3.3 times it, depending on the case), but the linear spread is 2 to
17 times larger. A fixed-constant instance therefore stays within about 2.5 % (differential) and 14 % (linear) of the model at 3
rounds, on the 64 most probable points, and within about 18 % at 4 and 5 rounds, where the 24-bit space is saturated; this says
nothing about 512 bits.

*Correction (2026-11-04).* A previous version read the gap at 3 rounds as statistically clear (z = 4.6; 11 in the linear case).
That z assumed a Poisson noise of variance N·p per point, never checked, and missed the factor 2 for differences (each pair is
counted twice). Against the measured spread, the same cases give z = 1.8 and 1.9: the gap was an artefact of the noise model. The
reach thresholds of the test (H_max > 24, LP > 40/N, boomerang > 24/N) are now checked on the random permutation as well
(16, 31.2/N and 6/N).

**Boomerang** (`tests/c/brume_attaques.c`). S-box: max BCT = 10 out of 16, so a pass through the middle costs `2^{−0.7}` per active S-box, against `2^{−4}` for DDT². Measured, with δ = M·(one nibble):
**3 rounds** (z = 14.8 at 2²⁰ quartets, 16 combinations), nothing at 4 rounds and beyond at this scale. A first version, with δ on a single nibble, only saw 2 rounds: the dense M⁻¹ immediately activated more than
100 S-boxes. In the Markov model with the certified activities, `p²q² ≤ 2^{−4(A(r0) + A(r1))}`: with a single free middle round, `2^{−484}`; 2²⁵⁶ quartets only cover 16 rounds of trails. Rectangle and
amplified boomerang do no better here: they lose `2^{−b}`, b = 512.

**Impossible differentials and zero correlations by values.** Per nibble, the set of possible values is propagated through the DDT or LAT and through the actual coefficients. Values gain nothing over
activity alone: **5 rounds** in both cases, no contradiction at 6 rounds or beyond for one nibble in input and output (r1, r2 ≤ 7). 9.9 million actual differences stay within the sets.

**Graph structure** (`tests/test_brume_algebre.py`).
- *Cancellations.* No cycle of length 4, at most 1 common neighbour without the diagonal, at most 2 common outputs for two columns of M. Exact minimal neighbourhood of 7, 12, 17 nibbles for |S| = 1, 2, 3; by local search
  (upper bound) 22, 34, 55, 84, 101, 112 for |S| = 4, 8, 16, 32, 48, 64.
- *Rotational pairs.* An exactly symmetric pair survives no round: `S` being bijective, equality would require translation-invariant constants, and they agree on at most 23 % of the nibbles. Rotational-XOR variant:
  `M ⊕ T_h M T_h⁻¹` has rank ≥ 126 over GF(16) for every translation h. The coefficients agree on at most 9.8 % (6.7 % at random).
- *Invariant subspaces of M.* The binary minimal polynomial has degree 512, with factors of degrees 4, 8, 24 and 476: M is cyclic, and it has exactly **16 invariant subspaces**, one of dimension 4 (eigenvector over GF(16), λ = 3).
  They therefore exist, contrary to what a test restricted to small orders might suggest. They are harmless as such: these vectors have weights 119 and 118 nibbles, the S layer moves their line off every affine line (checked for each round and without constant), and a trail following them would activate more than 100 S-boxes per round.
- *Non-linear invariants with the actual constants: excluded* (`tests/c/invariants.c`). Criterion of Beierle, Canteaut, Leander and Rotella
  (CRYPTO 2017): an invariant g common to the S layer and to every “M then constant” layer has the whole of `W_M(D)` as linear
  structures, the smallest M-invariant subspace containing `D = {rc_i ⊕ rc_j}`; if `dim W_M(D) ≥ n − 1`, g is affine, which an S-box
  without an affine component forbids. With the 31 inner constants (rc₁ to rc₃₁), **dim W_M(D) = 512**: the non-linear invariant attack
  (Todo–Leander–Sasaki) and the invariant subspace attack do not apply, **whatever the S-box**. Three consecutive constants suffice
  (two: 508), so every reduced version of at least 4 rounds is covered. The 15 components of the S-box have degree 3. Control: with
  L = identity instead of M, W falls back to span(D), of dimension 30. Outside the criterion: invariants that change from round to round and
  closed-loop invariants (Beyne, ASIACRYPT 2018).

**Algebraic.** S-box: 21 quadratic relations, univariate polynomial of degree 14 with 15 terms over GF(16), a single Frobenius-equivariant point. State recovery (rate known at input and output, c unknown bits):
- **1 round: broken**, 256 bits recovered by linear solving (rate-capacity block of rank 64), without a solver;
- SAT, 20 to 25 s per case: up to 128 unknown bits at 2 rounds, 16 bits at 3 and 4 rounds, nothing at 5 rounds; no case at 256 bits, even at 1 round, where the dedicated attack does better. **SAT therefore underestimates dedicated attacks.**
- **2 rounds: the whole capacity (256 bits) recovered in ≈ 2^97**, by guess-and-determine (`tests/c/brume_gd2.c`). Every generator
  links half A (rate) to half B (capacity): after 2 rounds, each rate nibble depends on only 6 unknown nibbles, its neighbours
  in B (u + {0, 7, 8, 21, 45, 62} mod 64). Introducing the 64 unknowns in a chosen order, each completed equation filters by a
  factor 16; the maximal width (|V| − |E|) is 24 (greedy and simulated annealing, 24 on every seed; no pure propagation seed
  of size ≤ 8), hence 16²⁴ = 2⁹⁶ by depth-first enumeration, with negligible memory. Validated on the real 2-round BRUME, with an oracle
  supplying 21 unknowns: state recovered on 24 states out of 24, a single solution, nodes within 1.2 bits of the model (≈ 2^97.2).
- **3 rounds: this method stops.** Each rate nibble then depends on 63 of the 64 unknown nibbles.
- *Preimage of one block of the reduced hash*: 1 round broken (each output nibble depends on a single message nibble); at 2 rounds,
  31 message nibbles per output nibble, width 51, i.e. 2²⁰⁴, above the generic sponge bound (2¹²⁸): no attack.
The estimate by degree of regularity under the semi-regular assumption (2²⁴⁷ at 1 round) is contradicted by this 1-round attack: it is **not** a security argument, and it is not used as one.

**Activity.** CP-SAT on the truncated model only proves, within this budget, 12, 16 and 24 S-boxes over 3, 4 and 6 rounds, i.e. the 4r of Proposition 10: **128 at 32 rounds is not improved**. The trails found are well above (44 at 3 rounds).
Exact model (`tests/c/sat_trails.c`, method of Sun, Wang and Wang, ToSC 2021: bit-level linear layer, actual DDT and actual LAT,
CryptoMiniSat, each solution rechecked outside the solver): over 2 rounds, the minimum is **exactly 8** in differential and in linear,
reached (1 then 7 S-boxes, 7 then 1): the branch-number bound is tight. Over 3 rounds, in differential, “≤ 13”, “≤ 16” and “≤ 20” remain undecided at
600 s: the method does not scale to 128 S-boxes per round, as its authors also note for non-lightweight states.

Larger scales are planned in the `tests/nuit_brume.py` part of the night campaign.

### 4.3 Security of the AEAD mode (proof)

**Setting.** P is a random permutation of {0,1}^b, b = 512, available
to the adversary in both directions (N queries in total). Notation: rate
r, capacity c = b − r, tag of τ bits, key of k = 512 bits absorbed in m = k/r
blocks.

| Profile | r | c | τ | m |
|---|---|---|---|---|
| BRUME-512 | 256 | 256 | 128 | 2 |
| BRUME-512-256 | 128 | 384 | 256 | 4 |

**Security game** (all-in-one AE, Rogaway–Shrimpton 2006).
- *Real world:* (Enc_K, Dec_K, P^±). *Ideal world:* (Enc$, ⊥, P^±).
  Enc$(N, A, M) returns a uniform string of |M| + τ bits, and ⊥ rejects
  every decryption query.
- *Nonces:* A never makes two encryption queries with the same
  nonce. Decryption queries use arbitrary nonces,
  used before or not. Nonces are 24 bytes long, like those of
  XChaCha20: drawn at random, two of them coincide with probability at most
  `q_e²/2^{193}`. Theorem 14 assumes unique nonces and does not contain this term: see Corollary 14 ter.
- *Standard restriction:* A does not submit for decryption a
  quadruple (N, A, C, T) returned by an encryption query. It
  already knows the answer. Without this restriction, ⊥ would be trivially
  distinguishable. Likewise, without loss of generality, A does not repeat a
  query.
- *Equivalent formulation:* the ideal world stores the outputs of
  Enc$, returns the corresponding plaintext when one of them is submitted,
  and rejects all others.
- *Budgets:* A makes q_e encryptions, q_d decryptions and N queries to
  P^± in total. σ denotes the total number of calls to P made by the
  construction to answer encryption and decryption
  queries. A rejected decryption releases no plaintext (no
  RUP).

**Security level.** The mode offers λ bits of security for a data limit
σ ≤ σ_max if, for every adversary,

    Adv^AE(A) ≤ (N + q_d)/2^λ + 2^{−λ}.

This is the usual cost/advantage notion, that of the NIST categories:
an advantage close to 1 requires about 2^λ queries. It does not require
that an adversary making 2^λ queries stay at an advantage of 2^{−λ}.
No AEAD satisfies that requirement: tag guessing alone
gives q_d/2^τ, and exhaustive key search gives N/2^k, as
for AES-128.

**The mode, written as a duplex.** An input call (σ, dom) performs
`S ← P(S ⊕ (σ ‖ 0^c) ⊕ dom·e₁₂₇)`, where e₁₂₇ denotes the last nibble of the
capacity; the rate of S is read **before** the next call. The initial state
is S₀ = P(IV_profile), public.

**Lemma 1 (overwriting with the plaintext = absorbing the ciphertext).** Write
Z = rate(S) for the keystream of block i. The implementation replaces the rate with the
plaintext P_i when encrypting, and with Z ⊕ C_i when decrypting. Since
C_i = P_i ⊕ Z, in both cases

    new rate = Z ⊕ C_i = P_i.

This is exactly the duplex call (σ = C_i, 0), the ciphertext being XORed
into the rate. For the last, partial block of length ℓ < r: the first ℓ
bytes receive Z ⊕ C (same identity), byte ℓ receives
Z ⊕ 0x01 and the following ones are unchanged. This is the call
(σ = C ‖ 0x01 ‖ 0*, 0).

The mode is therefore a **keyed duplex that absorbs the ciphertext**. The input σ_i
is chosen after reading the keystream that precedes it, which is the standard
use of the duplex (the duplex is a sponge over the history of padded
inputs: Bertoni–Daemen–Peeters–Van Assche 2011). No “overwrite
flag” is needed. ∎

**Lemma 2 (injective, prefix-free encoding).** Let path(N, A, C) be the
sequence of duplex inputs:
1. the blocks of (K ‖ N ‖ 0x01 ‖ 0*), without domain;
2. the blocks of (A ‖ 0x01 ‖ 0*), the last one with dom = 1;
3. the full blocks of C, then (C_end ‖ 0x01 ‖ 0*), without domain;
4. (0^r, dom = 2);
5. (len(C) on 8 bytes ‖ 0x01 ‖ 0*, dom = 4).

This encoding is injective in (N, A, C), and no complete path is a strict
prefix of another.

*Proof.* The domain bits are in the capacity, which the data never
touch. They therefore split the sequence unambiguously:
- the key ‖ nonce phase has a fixed length (88 bytes);
- the AAD ends at the unique call carrying dom = 1;
- the ciphertext occupies the calls between that one and the unique dom = 2 call;
- the 10* padding is injective.

Finally, dom = 4 appears only at the last call of a path: a path that
contained another as a strict prefix would have a dom = 4 call
in the middle, which is impossible. ∎

*Mechanical check*: `tests/test_mode_aead.py` rebuilds the AEAD from
this encoding alone and an abstract duplex. It recovers exactly
the ciphertexts and tags of `Brume512` (two profiles, lengths 0 to
3r + 1, 200 and 1 000), and checks injectivity and prefix-freeness
on 441 boundary paths per profile.

**Lemma 3 (key absorption).** Write X₁ = S₀ ⊕ (K₀ ‖ 0) and
X_{j+1} = P(X_j) ⊕ (K_j ‖ 0), with S_K = P(X_m) the state after the key.
As long as no bad event has occurred, the answers of the
construction are independent of K. The probability that a query of A
to P hits X_m (forward) or S_K (backward) is then at most

    N/2^k + 2N/2^b + N/2^c.

*Proof.*
- A forward query q equals X_j only if its rate equals that of
  P(X_{j−1}) ⊕ K_{j−1} (probability 2^−r, since K_{j−1} is uniform and
  unknown) and its capacity equals cap(P(X_{j−1})).
- This capacity is known to A only if A itself queried X_{j−1}.
  Otherwise it is uniform among at least 2^c values.
- By induction, Pr[q = X_j] ≤ 2^−r · (Pr[q′ = X_{j−1}] + 2^−c), with
  Pr[q = X₁] = 2^−r since S₀ is public. Hence
  Pr[q = X_m] ≤ 2^−mr + 2^−c · Σ_{i ≥ 1} 2^−ir ≤ 2^−k + 2^{1−b}.
- Summing over the N queries gives the first two terms.
- A backward query equals S_K only if it guesses its capacity, hence
  N/2^c.

Reaching some X_j with j < m teaches nothing usable without the following
key blocks: this is why the N/2^r term of a naive analysis
disappears. ∎

**Lemma 4 (no capacity collision).** Consider the nodes of the
construction, that is the states reached by distinct paths,
outside the key phase. The probability that two distinct nodes have
P outputs with the same capacity, or that a query of A hits the input
or the output of a node, is at most

    σ²/2^{c+1} + 2σN/2^c.

*Proof.* Each output of P computed by the construction on a fresh
input is uniform among at least 2^b − σ − N values, hence the first
term for the C(σ, 2) pairs. The input of a node has the capacity
of the output of the preceding node, unknown to A in the absence
of a bad event: each query of A hits it with probability at
most 2^−c, in each direction, hence 2σN/2^c. ∎

**Theorem 14 (BRUME-AEAD).** Under these assumptions,

    Adv^AE(A) ≤ σ²/2^{c+1} + 2σN/2^c + N/2^c + N/2^k + 2N/2^b + σ²/2^{b+1} + q_d/2^τ.

*Proof.* In the absence of the events of Lemmas 3 and 4, each freshly
reached node returns a uniform output (up to σ²/2^{b+1}, for
the switch from random permutation to random function).
- *Confidentiality.* Two encryptions with distinct nonces have paths
  that diverge at the latest at the nonce block (Lemma 2). Their keystreams and
  tags are therefore fresh and uniform, and the ciphertexts follow the distribution
  of Enc$.
- *Integrity.* A decryption (N, A, C, T) that does not come from an
  encryption has a path distinct from every encryption path
  (Lemma 2), otherwise the tag is deterministic and T is rejected. From the
  first divergence node on, all nodes are fresh (Lemma 4),
  including the one that produces the tag after the dom = 4 call, since the
  encoding is prefix-free. T is then correct with probability 2^−τ (a
  tag spread over two blocks is fresh on both).
- *Plaintext.* No plaintext is released before the tag is checked.

Summing gives the bound. ∎

**Corollary 14 bis (instantiation, term by term).** With σ ≤ 2^64
blocks (over the whole lifetime of a key):

| Term | BRUME-512 (c = 256, τ = 128) | BRUME-512-256 (c = 384, τ = 256) |
|---|---|---|
| σ²/2^{c+1} | ≤ 2^−129 | ≤ 2^−257 |
| 2σN/2^c | ≤ N·2^−191 | ≤ N·2^−319 |
| N/2^c | N·2^−256 | N·2^−384 |
| N/2^k + 2N/2^b | ≤ N·2^−510 | ≤ N·2^−510 |
| σ²/2^{b+1} | ≤ 2^−385 | ≤ 2^−385 |
| q_d/2^τ | q_d·2^−128 | q_d·2^−256 |
| **Sum** | **≤ (N + q_d)·2^−128 + 2^−128** | **≤ (N + q_d)·2^−256 + 2^−256** |

This gives 128 bits (BRUME-512) and 256 bits (BRUME-512-256), in the sense
defined above, for σ ≤ 2^64. It is the σ²/2^{c+1} term that sets the
data limit, not 2σN/2^c.

**Corollary 14 ter (nonce policy).** Theorem 14 and Corollary 14 bis hold for **unique nonces** per key
(a persistent counter, which survives restarts and is not shared between devices). With **randomly drawn** nonces, one must
add `q_e²/2^{193}` to the advantage, i.e. `2^{−65}` at `q_e = 2^{64}`.
- *BRUME-512:* `q_e²/2^{193} ≤ q_e/2^{128}` as long as `q_e ≤ 2^{65}`. The 128-bit level, in the cost/advantage sense, therefore holds with
  random nonces up to `q_e = 2^{64}` encryptions per key.
- *BRUME-512-256:* `q_e²/2^{193} ≤ q_e/2^{256}` holds for no `q_e ≥ 1`. **The 256 bits require unique nonces.** With random nonces, the level is capped
  by collisions at about 96 bits of queries (advantage ≈ 1 around `q_e = 2^{96}`).

The code does not choose: the nonce is supplied by the caller. The same corollary applies to the parallel profiles (§ 4.5). Point raised by
an external audit: the term appeared in the text of the game, but neither in the theorem nor in the table.

*Check* (`tests/test_aead_modele.py`, added on 2026-11-05): on the reduced duplex with 8-bit nonces drawn at random and q_e = 8, an
adversary that looks for two equal nonces and tests C ⊕ C′ = M ⊕ M′ on the first block reaches an advantage of 0.107, against an exact
nonce-collision probability of 0.105 and a bound q_e²/2^{r+1} = 0.125; with unique nonces it never succeeds. The term is reached
and not exceeded.

*Reading the edge case.* With N = 2^128 and σ = 2^64, the bound gives an
advantage of about 2^−63 for BRUME-512. An adversary that has made 2^128
queries therefore only has an advantage of 2^−63, which is consistent with 128
bits in the cost/advantage sense. The first draft (“advantage ≤ 2^−62
or so; 128-bit security”) mixed up the two readings and was
rightly pointed out by the external audit (point 2). If one required an advantage of at most 2^−λ at N queries, one
would need log2 σ + log2 N ≤ c − λ − 1 (as well as q_d ≤ 2^{τ−λ}), as the
audit computes.

**Remarks.**
1. The TE mode adds parities that are a public function of the
   ciphertext: the adversary can compute them itself. Correction
   before the tag check therefore provides no additional oracle.
2. The bound is deliberately simple. Fine-grained analyses of the keyed
   duplex, which replace σN/2^c with multicollision terms
   (Daemen–Mennink–Van Assche 2017), can only improve it.
3. P is modelled as a random permutation. For BRUME-512, this
   rests on the absence of any known distinguisher on 32 rounds (§ 4.1–4.2 and
   the cryptanalysis in the audit report).
4. *Multi-user*: see Theorem 14-mu below.
5. *Separation between constructions.* Every AEAD path starts with
   P(IV_profile), whose capacity carries the profile parameters (nibbles
   120 to 126: rate, tag length, λ and version, not all zero). The hash sponges (sequential and
   tree) start from a state with zero capacity. The first
   calls are therefore distinct, and paths can only meet
   through a capacity collision, already counted in the terms in
   σ²/2^{c+1} and σN/2^c (σ and N counted over all constructions
   using P). SHAKE256 is only used by the KEM and the signature, with their own
   domain strings (“SILLAGE-KEM|…”, “SILLAGE-SIG|…”).

**Theorem 14-mu (BRUME-AEAD, μ users).** Let K_1, …, K_μ be μ independent,
uniform keys of k bits and a single
permutation P. The adversary queries Enc(i, ·) and Dec(i, ·). It respects
nonces for each user, with the same restriction as in the
single-user case. The ideal world has μ independent Enc$ oracles.
σ counts all calls to P by the construction, over all
users, including the m absorption calls of each key. Then

    Adv^{AE-mu}(A) ≤ σ²/2^{c+1} + 2σN/2^c + μN/2^c + μN/2^k + 2μN/2^b
                     + σ²/2^{b+1} + q_d/2^τ + μ²/2^{k+1}.

*Proof.* We repeat the proof of Theorem 14 with three changes.
1. *Lemma 3, applied to each user.* A forward query of A
   hits X^i_m with probability at most 2^{−k} + 2^{1−b}, and a
   backward query hits the state S^i_K with probability at most
   2^{−c}. The union bound over the μ users and the N queries
   gives μN/2^k + 2μN/2^b + μN/2^c.
2. *Lemma 4 over all nodes.* The nodes of all
   users, including those of the key phase, are outputs of
   P on distinct inputs. The terms σ²/2^{c+1} and 2σN/2^c
   therefore hold with the total σ. Two users whose keys share a
   prefix share the first states X_j, but their states
   diverge at the first differing key block. They only meet again
   through a capacity collision, already counted.
3. *Identical keys.* If K_i = K_j with i ≠ j, the two users
   are merged in the real world and independent in the ideal world.
   This happens with probability at most μ²/2^{k+1}.

Outside these events, each freshly reached node returns a
uniform output, independent from one user to another. The confidentiality and
integrity arguments of Theorem 14 apply user
by user, and the term q_d/2^τ counts all decryptions. ∎

*Instantiation.* For μ ≤ 2^{64} and σ ≤ 2^{64} in total:
- BRUME-512: μN/2^c ≤ N·2^{−192} and μ²/2^{k+1} ≤ 2^{−385}, hence
  Adv ≤ (N + q_d)·2^{−128} + 2^{−128}: 128 bits;
- BRUME-512-256: μN/2^c ≤ N·2^{−320}, hence 256 bits.

The data limit applies to the total over users, not to
each one, as for any mode with a shared capacity.

**Attacks run on a reduced duplex** (`tests/test_aead_modele.py`, random permutation on 16 bits). Forgeries go through
the model's real decryption.

| Term | Attack | Frequency | Expected | Bound |
|---|---|---|---|---|
| σ²/2^{c+1} | capacity collisions between nodes, σ = 14, c = 8 | 0.307 | | 0.383 |
| 2σN/2^c | constant plaintext: one query tests every node, then a forgery, N = 8, c = 10 | 0.117 | 0.109 | 0.666 (the whole bound) |
| 2σN/2^c, backward | backward queries, no multi-target, N = 48 | 0.061 | 0.047 | trivial |
| N/2^k | chained key guesses, m = 2, k = 8, N = 16 | 0.036 | 0.031 | 0.067 |
| μN/2^k | the same, μ = 8 keys, m = 1 | 0.217 | 0.25 | 0.627 |
| q_d/2^τ | guessed tags, q_d = 16 | 0.056 | 0.0625 | 0.0625 |

The chosen-plaintext attack shows that the σN term is real: with a constant input rate, one query tests every node at
once. The factor 2 of the term comes from the sum over both directions. The naive term N/2^r, ruled out in Lemma 3, would be 1 on this instance, against 0.036
measured. The N/2^c term of Lemma 3 is conservative: backward queries hit the state after the key with 2^{−b} per query (measured), none of its rates
being known.

### 4.4 Tree hashing (proof)

**The mode.** Write F_d(X, ℓ) for the BRUME-512 sponge (rate 256 bits,
10* padding) in which the domain d is XORed into the last nibble
of the capacity just before the final absorbing permutation; ℓ is the
output length. F_0 is the sequential hash `brume512_hash`. With
B = 8 192 bytes and chaining values (CV) of n = 256 bits:
- if |M| ≤ B: H(M) = F_SINGLE(M, ℓ);
- otherwise, M = M_0 ‖ … ‖ M_{k−1} (leaves of B bytes, the last one
  possibly shorter), CV_i = F_LEAF(M_i, 32), and
  H(M) = F_ROOT(CV_0 ‖ … ‖ CV_{k−1} ‖ k₆₄ ‖ B₃₂, ℓ).

Domains: LEAF = 8, ROOT = 9, SINGLE = 10. The leaves are
independent, hence the parallelism (batches of 32 states, all cores).

**Lemma 15 (independent domains).** Let D = {0, 8, 9, 10} and
Δ = D ⊕ D = {0, 1, 2, 3, 8, 9, 10} (|Δ| = 7). If P is a random
permutation, available in both directions, the family (F_d)_{d ∈ D} is
jointly indifferentiable from |D| independent extendable-output random
oracles (RO_d)_{d ∈ D}, with advantage at most

    7q(q + 1)/2^{c+1} + q²/2^{b+1}

for q calls to P or P⁻¹ in total (those of the adversary and those of the
construction). At c = 256, this is about 7q²/2^{257}.

*Proof.* We follow Bertoni, Daemen, Peeters and Van Assche (Eurocrypt 2008): a
simulator S holds P and P⁻¹ and maintains two sets of capacities.
- **R**, capacities of *rooted nodes*: initially, the zero capacity of the initial
  state. A node's path is the sequence of blocks that leads to it from the initial state.
- **O**, capacities of inputs queried outside every rooted path.

*Forward query x = (x_r ‖ x_c).*
1. If x_c = cap(T) ⊕ d with T a rooted absorbing node and d ∈ D, let
   X = path(T) ‖ (x_r ⊕ T_r). For d ≠ 0 and X well padded, the call is the final
   call of F_d(X): the rate of the answer is the first block of RO_d(X).
   For d = 0, the rate is block j of RO_0(X′), where X = X′ ‖ 0^{jr} and
   X′ is well padded; this is the standard reading of the sponge, since squeezing amounts
   to absorbing a zero block and a well-padded message does not end with a zero
   block. In every other case, the rate is uniform. The capacity of the answer
   is uniform, and this capacity is added to R.
2. If x extends a post-final state of F_d(X), d ≠ 0, with unchanged rate, answer with
   the next block of RO_d(X), likewise.
3. Otherwise, answer uniformly and add x_c to O.

*Backward query y.* S answers with a uniform x, and adds x_c to O.

*Bad event.* It occurs if:
- (a) an answer capacity added to R falls in (R ⊕ Δ) ∪ (O ⊕ D); or
- (b) the capacity x_c of a **backward** answer falls in R ⊕ D.

Outside this event: T and d are unique at each call (the cases δ ≠ 0 are specific
to separation through the capacity); no input already queried becomes a
rooted extension; and no rooted path leads to an answer chosen by
the adversary. The encoding (d, X) is injective: 10* padding is injective for fixed d, and d is
read from the capacity of the call. The simulation is therefore consistent with the (RO_d), and
the answers are uniform.

*Counting.* Each query adds at most one element to |R| + |O|: in case 1 or 2,
x_c is already tied to R and only the answer is added; in case 3 or backward,
only an input is added. So |R| + |O| ≤ i + 1 before query i + 1. Since the
capacity of each answer is uniform among 2^c values, the probability of
the event at this query is at most 7(i + 1)/2^c. Summing over i < q gives
7q(q + 1)/2^{c+1}. Finally, replacing the permutation's sampling without replacement
by this sampling costs q²/2^{b+1}. ∎

*Correction.* The old proof removed backward queries at the cost of q²/2^{b+1}, under
the mere replacement of P by a function, and then ignored them. This is insufficient:
a backward answer whose capacity equals cap(T) ⊕ d fixes the output of F_d on a
message, while the oracle knows nothing of it. This is a concrete distinguisher, with probability
of order q²/2^c, far above q²/2^{b+1} (`tests/test_indiff_arbre.py`:
0.0255 against 0.00019 for c = 16, b = 24, q = 80). It also claimed that “a final
call of F_d carries d ≠ 0”, which is false for d = 0: F_0 is handled as an ordinary
sponge. Nor did it count the inputs already queried (O). The
term changes little: the factor 7 remains, q² becomes q(q + 1).

*Why 0 ∈ D.* The family contains F_0, the sequential hash. The
lemma thus establishes the independence of the tree from
`brume512_hash` as well as that of its own nodes. For the tree's
domains alone, {8, 9, 10}, one would have D ⊕ D = {0, 1, 2, 3} and a
factor 4. We keep 7 to cover F_0.

*Consequence.* The first sketch gave q²/2^{c+1}: it forgot the
six non-zero values of Δ. The factor 7 has no effect on the level:
7q(q + 1)/2^{257} ≤ q/2^{128} for q ≤ 2^{126}.

**Theorem 16 (indifferentiability of the tree mode).** The mode
above is (i) tree-decodable, (ii) message-complete and (iii) final-node
separable, in the sense of definitions 5 to 7 of Bertoni–Daemen–Peeters–Van Assche
(“Sufficient conditions for sound tree and sequential hashing modes”,
IJIS 2014). It is therefore indifferentiable from an extendable-output random oracle,
with, for q < 2^n calls to P or P⁻¹ (cost of the queries to the mode included),

    Adv ≤ 7q(q + 1)/2^{c+1} + q²/2^{b+1} + q(q − 1)/2^{n+1}

The first and second terms come from Lemma 15. The last one is Theorem 1 of
BDPV for chaining values (CV) of n = 256 bits, which are indeed the first n
bits of the output of F_LEAF. This gives 128 bits of generic security (cost/advantage,
for q ≤ 2^{126}), like the sequential hash. The three conditions of this version of
BDPV suffice: the fourth one of the earlier versions (parameter completeness) was
withdrawn by its authors, and B is in any case fixed and written in the root.

*Proof of the three conditions.* Write F(d, X) = F_d(X): the domain is part of the
node (frame bits), and there is a single inner function in the sense of BDPV. A
*tree instance* is a root and the leaves that precede it, each with its
domain and its bits.
1. *Tree-decodable (def. 5).* Algorithm Adecode, linear, which reads only the instance:
   - root of domain SINGLE, of length ≤ B and with no other node: **compliant**;
   - root of domain ROOT: read B in the last 4 bytes and k in the 8
     before them; require B = 8 192, k ≥ 2 and a length of 32k + 12 bytes. Otherwise:
     incompliant. The CVs are then the first 32k bytes.
   - for i = 0, …, k − 1: if node i is missing, return **final-subtree-compliant**
     and the index i, with the position of its CV. If it is present, require the domain
     LEAF and a length of B bytes (1 to B for the last one). Otherwise: incompliant.
   - all present and nothing else: **compliant**.
   An instance cannot be both compliant and a final subtree, since the criterion
   is the presence of all nodes. The leaf-size test matters: without it,
   two different splittings of the same message would have the same structure.
2. *Message-complete (def. 6).* For every |M|, the tree contains all the bits of M,
   and Amessage concatenates them in order (or reads the single node).
3. *Final-node separable (def. 7).* An inner node is a leaf, of domain 8:
   alone, it is an incompliant instance, since the root must carry 9 or 10.

*Composition.* BDPV gives a simulator of F from the mode's oracle, and Lemma 15
a simulator of P from F. Their composition (Maurer–Renner–Holenstein) is
the simulator of the theorem, and the advantages add up (BDPV, § 7.1). Each node costs
at least one call to P: BDPV's node counter is ≤ q, and a call to P
triggers at most one query to F outside the bad event. ∎

*Mechanical check.* `tests/test_hachage_arbre.py`: a model of the
mode, written without `brume512.py` (the list of its nodes), reproduces
exactly the Python reference and the C implementation on 13 boundary
lengths (0, 1, 31 to 33, B − 1 to B + 1, 2B, 2B + 31, 3B − 1, 33B + 5,
40B) and two output lengths. It also checks:
- that the mode differs from the sequential hash, and that a root input, hashed
  as a message, does not reproduce the tree's output;
- that six structural alterations change the output: swapped
  leaves, a byte moved between two leaves, extension, truncation,
  duplicated leaf, flipped bit;
- that the short output is a prefix of the long output (extendable oracle), and does not
  depend on the number of threads; the avalanche within each leaf and the KATs.

`tests/test_indiff_arbre.py` (15 checks):
- Adecode and Amessage, as written above, on all small
  instances, including malformed ones (k, B, leaf lengths, domains);
- **the simulator of Lemma 15, composed with that of the mode**, on a reduced sponge.
  A distinguisher mixes forward and backward queries, roots over arbitrary CVs,
  and complete computations (sequential hash, single node, trees, long outputs). Over
  2 532 comparisons without a bad event, the simulator reproduces the
  oracles exactly; over 165 098 comparisons at reduced capacity, no inconsistency outside
  the bad event;
- the frequency of the bad event stays below the bound, closely: 0.221 for 0.251
  (c = 14, q ≈ 34), 0.184 for 0.207 (c = 18, q ≈ 124);
- the backward-query distinguisher mentioned above.

These tests exercise the simulator and the counting. They do not replace the proof.

*Remarks.*
1. **Status: proof completed, independent human review still to be done.** The review
   of 2026-10-30, carried out by an AI assistant (Claude) from the text of BDPV,
   found and fixed the flaws listed (backward queries, inputs already queried, case
   d = 0, BDPV conditions not checked against their definitions), then tested the
   result on a reduced model. This is neither peer review nor a formal proof
   (Coq, EasyCrypt): the mode remains a research construction, with no claim
   of an established guarantee until a third-party cryptographer has reviewed it.
2. The tree has a single level, which suffices up to 2⁶⁴ leaves. The
   root costs 32 bytes per 8 KiB leaf, i.e. 0.4 %.
3. The mode is a new function (new KATs). The sequential
   hash is unchanged.

---

### 4.5 Parallel duplex (BRUME-512p, BRUME-512-256p)

**Status: proof written in the random-permutation model, tied to the code and tested on a reduced model;
independent human review still to be done.** The sequential profiles are unchanged (same KATs). Implementation:
`Brume512P` (`sillage/brume512.py`), `sl_aead_p_encrypt` and `sl_aead_p_decrypt` (`sillage/c/brume512_avx2.c`).

**Construction.** Same r, c and τ as the sequential profile. B = 4 096 bytes, |CV| = 2λ bits (32 or 64 bytes).
The IV additionally carries log₂ B (byte 58) and the mode (byte 59), both zero in the sequential profile. Let ℓ be the length of the
ciphertext and k = max(1, ⌈ℓ/B⌉). Write (σ, dom) for a duplex call, as in § 4.3.
- *Trunk.* S₀ = P(IV); blocks of (K ‖ N ‖ 0x01 ‖ 0*); blocks of (A ‖ 0x01 ‖ 0*), the last one with dom = 1. This gives S_A,
  whose rate is never read.
- *Leaf j < k.* From S_A: (j on 8 bytes ‖ 0x01 ‖ 0*, dom = 5), then (0^r, dom = 3). Chunk j of the message is
  then encrypted as in § 4.3 (Lemma 1): full ciphertext blocks without domain, then (C_end ‖ 0x01 ‖ 0*, dom = 6).
  CV_j = the first |CV| bits of the final state.
- *Root.* From S_A: blocks of (CV₀ ‖ … ‖ CV_{k−1} ‖ k ‖ ℓ ‖ 0x01 ‖ 0*), k and ℓ on 8 bytes, the last block with
  dom = 4. The tag is extracted as in § 4.3.

**Lemma 5 (tree encoding).** Paths are injective and no path is a strict prefix of another.

*Proof.* The prefix (K, N, A) splits as in Lemma 2. After it, the first call of a leaf carries dom = 5 and that
of a root dom = 0 or 4: these inputs differ in the capacity, which the data do not touch. Two leaves with distinct
indices differ at that call. Within a leaf, dom = 6 appears only at the last call, and 10* padding is injective; within a
root, dom = 4 appears only at the last call, and the content has a fixed-length structure once k is known. ∎

*Mechanical check*: `tests/test_aead_parallele.py` rebuilds the mode from this encoding alone and recovers the
ciphertexts and tags of the reference and of the C code. It also checks Lemma 5 at leaf boundaries.

**Theorem 14-p.** Under the assumptions of Theorem 14, σ counting all calls to P (trunk, leaves, root):

    Adv^AE(A) ≤ σ²/2^{c+1} + 2σN/2^c + N/2^c + N/2^k + 2N/2^b + σ²/2^{b+1} + q_d/2^τ + σ/2^{|CV|}.

*Proof.* Lemmas 1, 3 and 4 apply as is. Lemma 4 is about the tree of nodes, and a tree already appears
in the sequential mode, where decryptions share a prefix. Lemma 5 replaces Lemma 2. Outside the events
of these lemmas, each fresh node returns a uniform output.
- *Confidentiality.* Two encryptions with distinct nonces have S_A values coming from distinct paths. Within one message, two
  leaves diverge at the fork. All keystreams and tags are therefore fresh.
- *Integrity.* Let (N, A, C, T) be a decryption that does not come from an encryption. If no encryption used (N, A), or
  if (k, ℓ) differs from that of the encryption, the root is a fresh path and T is correct with probability 2^−τ. Otherwise, C differs
  from C* in at least one leaf j. The final node of that leaf is fresh, so CV_j is uniform: it equals the CV of the
  encryption with probability at most 2^−|CV|, which the union bound over final nodes counts as σ/2^|CV|. Every other
  case gives a fresh root, then 2^−τ.
- *Plaintext.* The plaintext is only returned after the tag is checked, and zeroed otherwise. ∎

*Multi-user.* Theorem 14-mu extends in the same way, adding σ/2^|CV| with the total σ.

*Instantiation.* For σ ≤ 2^64: σ/2^|CV| ≤ 2^−192 (BRUME-512p) and 2^−448 (BRUME-512-256p). This term never dominates, and
Corollary 14 bis still holds: **128 and 256 bits, like the sequential profiles, under the same nonce policy (Corollary 14 ter)**. Only the amount of data for a given σ decreases:
132 calls for 128 data blocks (263 for 256 in BRUME-512-256p), i.e. about 3 %.

**Attacks run on a reduced duplex** (`tests/test_aead_parallele.py`, random permutation on 20 bits, r = 8, c = 12, 20 000 trials).

| Attack | Frequency | Expected |
|---|---|---|
| One altered leaf, 3-bit CV (σ/2^|CV| term) | 0.131 | 2⁻³ + 2⁻⁸ = 0.129 |
| One altered leaf, 12-bit CV (q_d/2^τ term) | 0.0038 | 2⁻¹² + 2⁻⁸ = 0.0042 |
| Two swapped leaves, 12-bit CV | 0.0040 | ≈ 2⁻⁸ |

**What the proof does not cover: the real P.** The proof idealises P. The fork gives the attacker a fixed secret state,
known differences on 64 bits and the output rate, for up to k leaves. It adds no power compared with the sequential
mode, which already allows the same through the nonce. Under one key, the state before the last nonce block is fixed; the attacker
chooses up to 192 bits there (BRUME-512), and reads the rate after two calls to P. This is the reason for the second call (dom = 3) of the fork:
it gives the same depth of two calls, i.e. 64 rounds, for fewer controlled bits. This is a structural argument, not a reduction.
The existing cryptanalysis (§ 4.1, 4.2) remains the only basis for the real P, and distinguishes nothing beyond a few rounds.

**Usage limits.** As in the sequential mode, a repeated nonce reveals the XOR of the plaintexts, here leaf by leaf. The mode is slower
on short messages: two fork calls per leaf and a root cost (64 bytes: 13 MB/s against 19). It only pays off beyond about
16 KiB, and the choice of profile is public.

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
| Sillage-SIG | Grover on forgery, √(2^{128.3}) and √(2^{264}) | **≈ 64 / 132 bits** | QROM: Don–Fehr–Majenz–Schaffner (2019, 2022), Aguilar-Melchor–Hülsing et al. (2021, multi-round), loss in O(q²); not instantiated here |
| BRUME-AEAD | Grover key search (k = 512 bits): 2^{256} | ≥ 128 bits expected, not proved | Q1 model (classical queries to the construction, P in superposition) not analysed |
| Hashing | generic quantum collisions (Brassard–Høyer–Tapp): 2^{c/3}, i.e. about 2^{85}, with a quantum memory of 2^{85} | ≈ 85 bits for collisions (more in cost models that count memory) | — |

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
  would require a gate model specific to its sizes, not done.
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
- Tree hashing: proof completed (Lemma 15, Theorem 16), reviewed by an AI
  and tested on a reduced model; **independent human review still to be done**.
- SIG: the MPC-in-the-Head protocol and Theorem 8 are new in v0.4, neither audited nor reviewed by a third party. They reuse
  published constructions (SDitH, hypercube, Kales–Zaverucha bound) and are run on a reduced model (`tests/test_sig_modele.py`),
  but the binary instance with rate 0.7 and n = 2^e has no dedicated third-party analysis, beyond generic ISD.
- Trail aggregation beyond 2 rounds: measurements and a
  margin are available, without a proved bound.
- Division property: the reach of the method is exact (10 rounds per
  direction, 20 inside-out, every cube: Theorem 12 sexies). This is not an actual integral attack on 20 rounds.
  The reach of the actual integral distinguisher remains open; it would require counting
  trails modulo 2; no cancellation was observed on a reduced model (§ 4.2 bis).
- Impossible differentials and zero correlations (truncated, patterns of weight ≤ 2): 5 rounds at most
  (`tests/c/structure_miss.c`). Exploiting the coefficient values gains nothing there for one nibble in input and output
  (`tests/c/brume_attaques.c`); this is not a bound for heavier patterns, nor for sets correlated across nibbles.
- Boomerang (3 rounds measured), integrals, algebraic, graph structure (§ 4.2 bis): attacks that were searched for, without a general bound.
  Excluded, on the other hand, by computation: non-linear invariants common to all rounds (BCLR criterion, dim W_M(D) = 512, § 4.2 bis).
- QROM: reductions instantiated in § 5 bis; the KEM's implicit rejection is covered (BHH+19, Theorems 3 and 5); collapsing of `H_c` and
  quantum proof of knowledge of the signature not established. They prove markedly less than the levels of known attacks (≈ 60 / 105 bits
  for the KEM, ≈ 32 / 68 bits for the signature), which are themselves below the nominal levels.
- Several ciphertexts under one key (§ 2.4): Sillage-128 loses log₂ N bits by exhaustive search on μ (k = λ); no known gain with
  several keys.
- AEAD mode: proofs written (Theorems 14 and 14-mu) in the
  random-permutation model, and tied to the code by
  `tests/test_mode_aead.py`. Each term is confronted with an attack run on a reduced duplex
  (`tests/test_aead_modele.py`). They have not been reviewed by a third party.
- Parallel duplex (§ 4.5): same status as the sequential AEAD mode, no third-party review. NEON: outputs
  checked under qemu; constant-time by construction, never measured, for lack of an ARM machine.
- Side channels: BRUME-512, the KEM and the signature in C are
  constant-time (dudect); the Python code is not. The KEM and the signature are additionally checked with
  Valgrind (no branch or memory access depending on a secret, `tests/test_c_kem_valgrind.py`,
  `tests/test_c_sig_valgrind.py`). These are measurements, not a certification.
