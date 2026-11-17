# Verification of Carolan–Majenz, *Compressed Permutation Oracles Revisited* (§ 3.3–§ 5.3)

> **v0.6 (17 November 2026).** This document now lives in `docs/brume1024/`. BRUME-1024q is the permutation of the suite: its code is `sillage/c/brume1024.c` and its checks are in the battery (`tests/c/brume1024.c`, `tests/c/brume1024_api.c`, `tests/test_b1024_*.py`). File names cited below without a path are documents of this folder (`*.md`) or tools of `prototypes/brume_q/b1024/` (programs, scripts, `dp1024/`, `gpu/`, `cm26_verif/`, …); `brume1024.c` meant the prototype, whose code is now the library.

Written on 16 November 2026; the exact runs for N = 6 and N = 7 were completed on 17 November. `SPONGE_QROM.md` uses the article ([CM], arXiv 2609.28469, v1 of 23 September 2026, the only
version on that date) through Lemma 5.1, Lemma 5.2 and Theorem 5.3, which rest on the soundness theorem (Theorem 4.2)
and on all of § 4. This note goes through that chain statement by statement. Each statement is:

- **re-derived**: the argument is redone here, by us, in a few lines;
- **checked exactly**: the operators are built from their definitions, as matrices, for small N, and the statement is
  evaluated (`cm26_verif/cpo_exact.py`; **done: N = 4, 5 and 6 at every level, and N = 7 up to level 3 (dimension of L_≤3 = 8 282); every check passes** (N = 6: 2 h 16 min, 3.6 GB; N = 7: 15 min, 8.1 GB; outputs in `cm26_verif/cpo_exact_N5.txt`, `_N6.txt`, `_N7.txt`, of which only the last 40 lines survive for N = 6, the final "TOUT PASSE" being printed only when every check of the run holds; at N = 7, t = 0, the measured value of (11) is 0.374, again about 1/√N));
- **checked as a formula**: the combinatorial or representation-theoretic formula the proof reduces to is evaluated in
  exact rational arithmetic for every partition up to N = 22 (`cm26_verif/representations.py`).

**Status.** No error that affects a statement was found. Four slips of writing (§ 3 below) do not change any result.
Every inequality that we could evaluate holds, with wide margins. **What remains unproven by us for all N** is listed
in § 4: two computational lemmas (4.13, and the seed structure in 4.15–4.16) are checked at N ≤ 7 and through their
formulas, not re-derived in general. This is not a substitute for peer review of the article.

## 1. The chain

Swap oracle and purification (§ 3.1) → compressed oracle cpO (Def. 3.6) → synthesis E_r, levels H_r, Gram G_r,
intertwiners V, Ṽ (§ 4.1) → one-query bounds (Prop. 4.7, Prop. 4.8) → soundness (Theorem 4.2, (31), Cor. 4.3) →
fundamental lemma (Lemma 5.1) → search bound (Lemma 5.2, Theorem 5.3) → sponge (Lemma 5.4, Theorem 5.5, redone for our
sponge in `SPONGE_QROM.md`).

## 2. Statement by statement

| Statement | Content | How | Result |
|---|---|---|---|
| Def. 3.4–3.6 | C_x swaps \|h⟩ and \|+_{x,h}⟩ on each block; M_y = C Q_y C†; cpO_x = I⊗M_⊥ + Σ S_y⊗M_y | built as matrices | C_x unitary and self-adjoint; M_⊥ + Σ M_y = I |
| Lemma 4.5 | Q_y H_r ⊆ H_{r−1} ⊕ H_r ⊕ H_{r+1} | re-derived (A.1); checked exactly | holds |
| Lemma 4.6 (17) | Σ_j E_j L_j M_y a = Q_y E_r a on K_r | checked exactly | holds (10⁻¹⁵) |
| Lemma 4.9 (36) | E_r E_r† is central, scalar C(N,r) f^{λ/(m)}/f^λ on S^λ⊗S^λ | re-derived (A.2); spectrum checked exactly, multiplicities (f^λ)² | holds |
| Lemma 4.9 (33)–(35) | G_r on λ = (m, µ): ∏(1 + µ′_c/(m−c+1)); λ_min = N/m; ‖G_r‖ ≤ exp(r/(N−2r+1)) | spectrum checked exactly; (36) = (33), min and max checked as formulas | holds; min reached at µ = (1^r) only |
| Lemma 4.10 | ΓV = I, V†V = G⁻¹, ‖V‖ ≤ 1; Ṽ isometry, ṼṼ† = Π_K, EṼ = G^{1/2}; zero sums (39); EV = I; POVM (41) | (39) re-derived (A.3); all checked exactly | holds |
| Theorem 4.2 (10) | Ṽ\|S_N⟩ = \|∅⟩ | checked exactly | holds |
| Lemma 4.11 | ∂†∂ = (2jI + A_d + A_i)/(n+1) (46); eigenvalue (47); ∂†∂ ⪰ ((n−j+1)/(n+1))(I − Π_K) (44); ker ∂ = K_j | (46) and (47) re-derived (A.4); (46), spectrum = (47), (44) and kernel checked exactly (j ≤ 3); the exchange argument checked as a formula | holds; the bound n−j+1 is never reached, the least value is n−j+2 |
| Lemma 4.12 | b⁻ ∈ K_{r−1} | checked exactly | holds |
| (26) | the three cross-level identities | checked exactly | holds |
| (48)–(51) | coefficients of M_y a, a ∈ K_r | checked exactly, coefficient by coefficient | holds |
| Lemma 4.13 (52) | Col(Θ)² ≤ 8/m, Row(Θ)² ≤ 22/m | checked exactly; the sums (59)–(62) and (63)–(66) checked as formulas | holds; measured ≤ 1.6/m and ≤ 0.9/m |
| Prop. 4.7 (23)–(25) | Col², Row² of z ≤ 64/m, of h⁰ ≤ 32/m, of h⁻ ≤ 24/m | checked exactly (under 3r + 2 ≤ N) | holds; measured ≤ 1/m, 0.12/m, 0.13/m |
| Lemma 4.14 (69), (70) | middle transition on K_r | checked exactly | holds |
| Lemma 4.15 | (73) 1 − h_α/g = 1/(m−d+2+η′_d); (75) f^λ/(N f^α) ≤ 1/(m−r); (76) ‖A − H¹¹G⁻¹‖ ≤ 2/m; H⁰⁰ ⪯ G/m, Σ_y H⁰⁰ ⪯ G; Col(C)² ≤ e/m, Row(C)² ≤ e²/m | (73), (75), (76) checked as formulas; operators checked exactly | holds |
| Lemma 4.16 | (77) h⁻ = V(G q G⁻¹ − q); (78) g_ν/g_λ product; (79) 0 ≤ 1 − ρ ≤ 4/m | (77) checked exactly; (78), (79) checked as formulas | holds; max m(1 − ρ) = 1.78 for N ≤ 22 |
| Prop. 4.8 (11), (29) | ‖(cpO(I⊗V) − (I⊗V)P)(I⊗Π_≤t)‖ ≤ 60/√(N−t) | re-derived (A.5); checked exactly from the definitions | holds; measured about 1/√N (0.44 at N = 5, t = 0, against 26.8) |
| Theorem 4.2 (12), (30) | the same with Ṽ: + (t+1)/(N−2t−1); ‖(Ṽ − V)Π_s‖ ≤ s/(2(N−2s+1)); inverse queries by F V = V Inv | re-derived (A.6); checked exactly, forward and inverse | holds |
| (31), Cor. 4.3 | δ_q ≤ 60q/√(N−q+1) + q(q+1)/(2(N−2q+1)); advantage ≤ 2δ_q | re-derived (A.6); summation checked for N < 400; random quantum algorithms (forward and inverse queries in superposition, q ≤ 2) simulated in both pictures | holds; e.g. N = 5, q = 2: δ = 0.45, advantage 0.17 |
| Lemma 5.1 (82), (81) | ‖(M − Q)L_≤q‖ ≤ √(2/(N−q)); fundamental lemma | re-derived (A.7); (82) checked exactly | holds; exact value max(1/√(N−q), √(2/s − 1/s²) at s = N−q+1) |
| Lemma 5.2 (85) | ‖B cpO (I−B) L_≤t‖ ≤ 2√(2s_t/(N−t)) | re-derived (A.8); checked exactly for three increasing properties (preimage, collision, fixed point), every x, forward and inverse | holds; largest ratio 0.66 |
| Theorem 5.3 (86) | composition of 5.1 and 5.2 | re-derived (A.8) | — |
| (88) | a_N ≤ √2, e_N ≤ 88T/√N | checked numerically in 400 digits (`constantes.py`) | holds |

## 3. Slips of writing found (none changes a result)

1. § 3, notation: "V ⊖ W the orthocomplement of V in W" for W ⊂ V; it is the orthocomplement of W in V (used that way
   in Def. 4.1).
2. Lemma 4.13: "the right-hand sides of (59)–(61) sum to at most 8m⁻¹" must include (62); with it, 1/m + r/m² + 4/M +
   r/(m²M) + (r−1)/M³ ≤ 8/m for r ≤ m (checked).
3. Lemma 4.15: "Col(C) ≤ e/m" should read Col(C)² ≤ e/m, which is what the next line uses (checked).
4. Lemma 4.11: the exchange raises the content by at least n − j + 2, not only n − j + 1 (the bound stated is weaker,
   hence still true).

Also: (82) is not tight on L_≤q, and cross-references write "Theorem 4.x" for lemmas and propositions.

## 4. What is not re-proved by us for every N

- **Lemma 4.13** (the incidence estimates (53)–(66)). Checked at N ≤ 7 on the operator Θ itself, through the
  coefficient formulas (48)–(51), and the final sums as formulas for all m < 300. The derivation of (53)–(58) for general
  N is the article's.
- **The seed structure in Lemmas 4.15–4.16** (rank-one seeds on each S_{N−1} branch, from Schur orthogonality (71) and
  multiplicity-free branching). Standard representation theory; checked at N ≤ 7 through (76), (77) and the family
  norms; the formulas (72)–(79) to which it reduces are checked for N ≤ 22.
- **Range.** Under the article's hypotheses (3r + 2 ≤ N), N ≤ 7 allows r ≤ 1 and two queries. The inequalities are
  also evaluated outside the hypotheses, for information: they held in every case tried.

The cryptographic use needs N = 2^1024. The constants of § 4 (60, 64, 32, 24) are far above what the computation shows
(the one-query error is about 1/√N): the proof is loose, which is safe.

## Appendix A. Re-derivations

**A.1 (Lemma 4.5).** For f ∈ I_r with x ∉ dom f: every completion φ of f has φ(x) ∉ im f, so Q_y|T_f⟩ =
(1/√m!) Σ_{φ ⊇ f, φ(x) = y}|φ⟩ = (N−r)^{−1/2}|T_{f[x↦y]}⟩ when y ∉ im f, and 0 otherwise. If x ∈ dom f, Q_y|T_f⟩ is |T_f⟩ or
0. So Q_y H_≤r ⊆ H_≤r+1; Q_y is self-adjoint, so it also maps H_r orthogonally to H_≤r−2.

**A.2 (36).** ⟨π|E_rE_r†|σ⟩ = Σ_{f ∈ I_r} ⟨π|T_f⟩⟨T_f|σ⟩ = (1/m!) #{f ⊆ π, f ⊆ σ} = (1/m!) C(fix(π⁻¹σ), r), a class function
χ of π⁻¹σ, so E_rE_r† is central and acts on S^λ⊗S^λ by (1/f^λ) Σ_τ χ(τ)χ^λ(τ). Now r!·C(fix τ, r) is the character of
S_N on injective r-tuples, that is of Ind from S_m of the trivial representation, so Σ_τ r!C(fix τ, r) χ^λ(τ) = N!·
dim(S^λ)^{S_m} = N! f^{λ/(m)}. The scalar is N! f^{λ/(m)}/(m! r! f^λ) = C(N, r) f^{λ/(m)}/f^λ.

**A.3 (39).** For a = Γ_r†ψ, a_f = ⟨Π_r T_f, ψ⟩. Every completion of h ∈ I_{r−1} sends u to some b ∉ im h, so
Σ_b |T_{h[u↦b]}⟩ = √(N−r+1)|T_h⟩ ∈ H_≤r−1, which Π_r kills. Same with the roles of domain and image exchanged.

**A.4 (46), (47).** (B^im)†B^im has diagonal j/(n+1) (each of the j pairs of f can be removed) and an entry 1/(n+1)
between f and g when they share h and the image b and differ only in the domain point: that is A_d. Likewise B^dom gives
j/(n+1) + A_i/(n+1). A_d = Σ (u u′) over a used and an unused domain point, the crossing part of the transposition
class sum: on the summand (α, λ, µ) the full sum acts by c(λ), the part inside the j used points by c(α), and the part
inside the n unused points, which carry the trivial representation of S_n, by C(n, 2). So A_d acts by
c(λ) − c(α) − C(n, 2), and similarly A_i with µ: this is (47).

**A.5 (Prop. 4.8).** With D_y = (M_yV − VQ_y)Π_r, the error is I⊗M_⊥V + Σ_y (S_y⊗D_y). M_⊥V = 0 (checked; it follows
from the zero sums), and Σ_y M_y = I − M_⊥, Σ_y Q_y = I give Σ_y D_y = 0 (28). Writing S_y = I + (S_y − I) and the input
as |⊥⟩ϕ_⊥ + Σ_z |z⟩ϕ_z: (S_y − I)|⊥⟩ = |y⟩ − |⊥⟩ and (S_y − I)|z⟩ = δ_{yz}(|⊥⟩ − |y⟩), so the error is
Σ_y |y⟩D_y(ϕ_⊥ − ϕ_y) + |⊥⟩Σ_y D_yϕ_y. The column bound on ϕ_⊥, ‖D_y‖ ≤ Col on ϕ_y, and the row bound on the last sum
give 3κ² = 1200/(N−r) with κ ≥ (8 + √32 + √24)/√(N−r), and three input levels per output level give 3600.

**A.6 (Theorem 4.2).** ‖(cpOṼ − ṼP)Π_≤t‖ ≤ ‖(cpOV − VP)Π_≤t‖ + ‖ΔΠ_≤t‖ + ‖ΔΠ_≤t+1‖ with Δ = Ṽ − V level-diagonal, and
‖ΔΠ_s‖ = max over the blocks of 1 − g^{−1/2} ≤ ½ log g ≤ s/(2(N−2s+1)) by (35) (1 − e^{−u} ≤ u). Hybrid: the
compressed and the Ṽ-image of the purified state start equal by (10); inter-query unitaries commute with Ṽ; before
query j + 1 the purified memory is in H_≤j; summing the one-query bounds gives (31). For an effect E, |⟨E⟩_ψ − ⟨E⟩_φ| ≤
2‖ψ − φ‖. Inverse queries: F V = V Inv (checked) conjugates the forward bound.

**A.7 (Lemma 5.1).** On a block based at h (s = N − |h|), M_y and Q_y are the rank-one projectors on |u_{h,y}⟩ and |h_y⟩,
with ⟨h_y|u_{h,y}⟩ = 1 − 1/s: the norm of the difference is the sine, √(2/s − 1/s²). The product M_ℓ⋯M_1 − Q_ℓ⋯Q_1
telescopes into ℓ terms each bounded by that norm, since the Q_i are diagonal and keep the level. The appended verifier
makes ℓ more queries, and |√p − √p′| ≤ δ_N(q + ℓ) because a projector is a contraction.

**A.8 (Lemma 5.2, Theorem 5.3).** cpO_x = (I⊗C_x)U_x(I⊗C_x) with U_x = I⊗Q_⊥ + Σ S_y⊗Q_y diagonal in the database, so
U_x commutes with B and ‖[B, cpO_x]‖ ≤ 2‖[B, C_x]‖. On a block where b of the s extensions are in B, BC(I−B) has b
identical rows (1/√s, −1/s, …, −1/s), so it has rank one and norm √(b/s + b(s−b)/s²) ≤ √(2b/s); [B, C] has the same
norm because C is self-adjoint. Then B cpO (I−B) = [B, cpO](I−B), a_{t+1} ≤ a_t + 2√(2s_t/(N−t)), and Theorem 5.3 is
Lemma 5.1 with √p_db bounded by this sum.
