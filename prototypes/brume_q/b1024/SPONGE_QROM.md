# BRUME-1024q — quantum collision and preimage bounds for the unkeyed sponge

Written on 16 November 2026. **Status: our adaptation of a published argument, not reviewed.** It rests on a preprint
(Carolan and Majenz, *Compressed Permutation Oracles Revisited*, arXiv 2609.28469, September 2026, cited as [CM]) and
holds in the random-permutation model: it says nothing about the fixed permutation BRUME-1024q.

[CM] Theorem 5.5 bounds the success of a quantum algorithm, with forward and inverse queries to a random permutation,
at finding a collision or a preimage in a sponge. Its sponge starts from the all-zero state and puts nothing in the
capacity. Ours (`SPEC.md` § 3.2) differs in two ways:

1. the first call is P(IV) with IV = 0^121 ‖ frame(5), a public constant whose capacity part is not zero, and no
   message block enters that call;
2. the last call XORs a **domain** into the capacity (byte 127): 0 for the XOF, 8 for a tree leaf, 9 for the tree root,
   10 for a single message.

This note redoes the one combinatorial step of [CM] that depends on the construction (their § 5.3, Lemma 5.4) for our
sponge, for the four domains at once. Everything else in [CM] (the compressed permutation oracle, its soundness,
Lemma 5.1, Lemma 5.2, Theorem 5.3) is used as stated.

## 1. Setting

- State of b = r + c bits, N = 2^b. For a state x: x_R its r rate bits, x_C its c capacity bits, x[d] its first d bits
  (d ≤ r).
- IV: a public state with rate part 0. Root ρ = IV_C.
- D ⊂ {0,1}^c: the set of domain offsets, with 0 ∈ D. k = |D| and k± = |D ⊕ D| (all XORs of two offsets, 0 included).
  For BRUME-1024q, D = {0, 8, 9, 10} · 16 on the last capacity byte, so **k = 4** and D ⊕ D = {0, 1, 2, 3, 8, 9, 10} · 16,
  **k± = 7**.
- Sponge with domain δ ∈ D on padded blocks m_1 … m_n (n ≥ 1, r bits each):

      s_0 = P(IV)
      s_i = P(s_{i−1} ⊕ (m_i ‖ 0^c))                 for 1 ≤ i < n
      s_n = P(s_{n−1} ⊕ (m_n ‖ δ))
      output s_n[d]

  The padding is injective (`DOMAINS.md` § 3), so the blocks determine the message. A **labelled message** is a pair
  (message, domain).
- **Collision in the family:** two distinct labelled messages with the same d-bit output. This covers a collision of one
  function (same domain) and a collision between two functions (different domains). **Preimage:** for a target w fixed
  independently of P, a labelled message with output w.

Why the family and not one function at a time: the default hash H (`SPEC.md` § 3.4) uses domain 10 for short messages
and the tree (leaves 8, root 9) for long ones. A collision of H is a collision in the family with d = 512: two short
messages collide under domain 10; a short and a long one give a collision between domains 10 and 9; two long ones
collide at the root (domain 9) or, if the root messages are equal, at some leaf (domain 8, 64-byte chaining values).

## 2. Graph, bad events, properties

As in [CM], a partial permutation f gives a directed multigraph on {0,1}^c with one edge x_C → y_C per pair
(x, y) ∈ f. A vertex is **reachable** if a directed path leads to it from ρ (the empty path included); Reach(f) is the
set of reachable vertices. An edge is reachable if its source is.

- **I1** (as in [CM]): a reachable edge ends at ρ, or two distinct reachable edges have the same endpoint.
- **I2** (new): two reachable vertices u ≠ u′ with u ⊕ u′ ∈ D ⊕ D.
- An edge (x, y) is **final** if x_C ⊕ δ ∈ Reach(f) for some δ ∈ D. With δ = 0, every reachable edge is final.

Properties (sets of databases):

- B_col: I1, or I2, or two distinct final edges (x, y), (x′, y′) with y[d] = y′[d];
- B_pre: I1, or a final edge (x, y) with y[d] = w.

Both are increasing (adding pairs only adds reachable vertices, reachable edges and final edges) and exclude the empty
database.

**Witnessing.** Let f contain the transcripts of the labelled messages in question.

- *Preimage.* The last call of a successful labelled message is a final edge with y[d] = w: f ∈ B_pre.
- *Collision.* Suppose f has neither I1 nor I2. Without I1 the reachable graph is a tree rooted at ρ ([CM] § 5.3). Let
  (x, y) be the last call of (m, δ), and u = x_C ⊕ δ = (s_{n−1})_C, a reachable vertex.
  - The domain is determined by the edge: if x_C ⊕ δ and x_C ⊕ δ′ were both reachable with δ ≠ δ′, they would be two
    reachable vertices differing by δ ⊕ δ′ ∈ D ⊕ D, which is I2.
  - The blocks are determined by the edge: the calls s_0 … s_{n−1} form a path from ρ to u, which is unique in a tree; it
    gives n and m_i = (x_i)_R ⊕ (s_{i−1})_R for i < n, and m_n = x_R ⊕ (s_{n−1})_R.

  So two distinct labelled messages end on distinct final edges, and if their outputs are equal, f ∈ B_col.

I2 is needed: without it one edge can end two labelled messages with different domains, which is a collision at no
cost. `cm26_verif/eponge_domaines.py` exhibits such a database.

The graph allows more than the sponge does (any edge leaving ρ, not only the one from IV; final edges whose source is
ρ ⊕ δ). This only enlarges the properties, so the bounds remain upper bounds.

## 3. Lemma A (sparsity)

With the two-sided sparsity s_t of [CM] (84):

    s_t(B_col) ≤ t · 2^(b−d) + (k±(t + 1) + k·t) · 2^r           (= t · 2^(b−d) + (11t + 7) · 2^r for BRUME-1024q)
    s_t(B_pre) ≤     2^(b−d) + ((k + 1)t + k) · 2^r               (=     2^(b−d) + (5t + 4) · 2^r)

For D = {0} the first line is [CM] (90): t · 2^(b−d) + (2t + 1) · 2^r.

**Proof.** Fix a database h ∉ B with |h| ≤ t. Reach(h) has at most t + 1 vertices, and h has at most t final edges.
Write Src for the set of capacities x′_C of the pairs of h.

*Forward pair x ↦ y, x ∉ dom(h), y ∉ im(h).*

(a) x_C ∉ Reach(h) ⊕ D. The pair is neither reachable nor final, Reach is unchanged, so are I1, I2 and the set of final
edges. The property stays false.

(b) x_C ∈ Reach(h) ⊕ D but x_C ∉ Reach(h). Reach is unchanged, hence I1 and I2 too. The new edge is final and no other
edge changes status. B_col needs y[d] to equal the digest of one of the at most t final edges: at most t · 2^(b−d)
values of y. B_pre needs y[d] = w: 2^(b−d) values.

(c) x_C ∈ Reach(h). For B_col, exclude the values y_C in

    E = (Reach(h) ⊕ (D ⊕ D))  ∪  (Src ⊕ D),          |E| ≤ k±(t + 1) + k·t,

that is at most |E| · 2^r values of y. For any other y, v = y_C is not reachable (0 ∈ D ⊕ D) and is the source of no
edge of h (0 ∈ D). So Reach becomes Reach(h) ∪ {v} and no old edge becomes reachable. No I1: the new edge ends at a
new vertex, which is not ρ. No I2: v ⊕ u ∉ D ⊕ D for every reachable u. No old edge becomes final: that would need
x′_C ⊕ δ = v, excluded by Src ⊕ D. The new edge is final (δ = 0). So B_col needs y[d] to equal an existing final
digest: at most t · 2^(b−d) further values.
For B_pre, I2 is not in the property: exclude only Reach(h) ∪ (Src ⊕ D), at most (t + 1) + k·t capacities; then
y[d] = w, at most 2^(b−d) further values.

*Inverse pair, y ∉ im(h) fixed, x varies.* By (a), only x with x_C ∈ Reach(h) ⊕ D can change the property: at most
k(t + 1) · 2^r values, which is below the first bound (k ≤ k±) and gives the term (k + 1)t + k of the second once
combined with (c) (max of (k + 1)t + 1 and k·t + k). ∎

The count is reached at t = 0: from the empty database, the 7 · 2^r values of y with y_C ∈ ρ ⊕ (D ⊕ D) are exactly the
bad ones.

## 4. Theorem S

Let q be the number of queries of the algorithm, L the number of calls to P needed to evaluate the labelled messages it
outputs (n + 1 calls for n padded blocks; the call P(IV) may be counted once), and T = q + 2L, as in [CM] (91). For the
default hash H, the algorithm outputs two messages and L is the number of calls to P of the two evaluations of H,
leaves included: they contain the transcripts of the colliding labelled messages of § 1.

**Unit.** As in [CM] § 5, q counts **swap queries** (forward or inverse). A standard XOR query costs two of them, so an
algorithm with q standard queries has T = 2q + 2L: every threshold below loses **one bit** when read in standard
queries.

For a uniformly random permutation and 1 ≤ T ≤ 2^(b/2)/4 (simple form):

    p_col ≤ (64/3) · T³/2^d + 96·k₁² · T³/2^c + 23 232 · T²/2^(r+c)
    p_pre ≤   48   · T²/2^d + 96·k₂² · T³/2^c + 23 232 · T²/2^(r+c)

where k₁ and k₂ are the constants with Σ_{t<q} √(k±(t+1) + k·t) ≤ k₁·√2·q^(3/2) and Σ_{t<q} √((k+1)t + k) ≤ k₂·√2·q^(3/2).
For BRUME-1024q, k₁ = 2 and k₂ = √2:

    p_col ≤ (64/3) · T³/2^d + 384 · T³/2^384 + 23 232 · T²/2^1024
    p_pre ≤   48   · T²/2^d + 192 · T³/2^384 + 23 232 · T²/2^1024

Sharp form, before the simplifications (the analogue of [CM] (92), (93)), for 3T − 1 ≤ N, with a_N and e_N of
[CM] (87):

    p_col ≤ [ a_N(T) · ( (4√2/3) · T^(3/2)/2^(d/2) + 8   · T^(3/2)/2^(c/2) ) + e_N(T) ]²
    p_pre ≤ [ a_N(T) · (   2√2   · T      /2^(d/2) + 4√2 · T^(3/2)/2^(c/2) ) + e_N(T) ]²

**Proof.** [CM] Theorem 5.3 with the properties of § 2 and Lemma A, exactly as in the proof of [CM] Theorem 5.5: the
augmented algorithm evaluates its outputs (L queries) and outputs the transcript (at most L pairs), which witnesses the
property (§ 2). Only the sum of √s_t changes. With √(a + b) ≤ √a + √b:

- 11t + 7 ≤ 18t for t ≥ 1, so Σ_{t<q} √(11t + 7) ≤ √7 + √18 · (2/3)(q^(3/2) − 1) ≤ 2√2 · q^(3/2); [CM] has
  Σ √(2t + 1) ≤ √2 · q^(3/2). The capacity amplitude is therefore 2 × that of [CM] (93): 8T^(3/2)/2^(c/2) instead of
  4T^(3/2)/2^(c/2).
- 5t + 4 ≤ 9t for t ≥ 1, so Σ_{t<q} √(5t + 4) ≤ 2 + 3 · (2/3)(q^(3/2) − 1) = 2 · q^(3/2): amplitude 4√2 · T^(3/2)/2^(c/2).

This is the sharp form. Then a_N(T) ≤ √2, e_N(T) ≤ 88T/√N ([CM] (88)) and (u + v + w)² ≤ 3(u² + v² + w²) give 3 · (8√2)² = 384,
3 · 8² = 192, and 64/3, 48, 23 232 as in [CM] before their rounding. ∎

## 5. What it gives for BRUME-1024q

r = 640, c = 384, d = 512 (64-byte digest and chaining values). The capacity term dominates.

| Success 1/2 needs T ≥ (swap queries) | Our sponge, simple form | Our sponge, sharp form | Sponge of [CM], same sizes, simple form ([CM] (94), (95)) | Best generic attack known |
|---|---|---|---|---|
| Collision (one function, between functions, default hash H with its tree) | **2^124.8** | 2^125.7 | 2^125.3 | 2^128 standard queries (BHT on the capacity) |
| Preimage, fixed target | **2^125.1** | 2^126.0 | 2^125.3 | 2^128 standard queries (quantum claw on the capacity, forward from the root and backward from the target) |

In standard queries: **2^123.8** and 2^124.1 (simple form), 2^124.7 and 2^125.0 (sharp form). The article's own
thresholds are in swap queries too.

- The frame costs nothing: the proof uses the root only as a fixed public point.
- The domains cost a factor 4 on the collision probability (2 on the amplitude), that is 2/3 of a bit on T against the
  unrounded constants of [CM], and half a bit against their rounded ones. The earlier estimate (a factor 7, at most
  0.9 bit) was a little pessimistic.
- A second preimage is a collision: the collision bound applies.
- For the XOF with an output of ℓ bytes, take d = min(8ℓ, 640): a collision on the whole output is one on its first block.
- Previous proved bound: 2^(min(r,c)/5) ≈ 2^76.8 (Alagic–Carolan–Majenz–Tokat 2025).

## 6. Limits

- **Random-permutation model.** The structural analysis of the permutation is separate (`README.md` § 3–6).
- **Not reviewed**, and [CM] is a preprint. If [CM] Theorem 5.3 changes, the constants here change with it. On
  16 November 2026 arXiv lists a single version (v1, 23 September 2026), with no comment, erratum or withdrawal.
- **What we did not re-prove:** the compressed permutation oracle and its soundness ([CM] § 4), Lemma 5.1, Lemma 5.2
  and Theorem 5.3. They are used as stated. We checked only that our properties meet their hypotheses (increasing,
  empty database excluded, transcript of at most L pairs, 3T − 1 ≤ N). Since then, `CM_VERIFICATION.md` (16–17
  November) goes through that chain statement by statement: re-derivations, exact checks from the definitions for
  N ≤ 6 and for N = 7 up to level 3, and the representation formulas up to N = 22. No error affecting a statement was
  found; what stays unproven by us for all N is listed there.
- **Not tight in constants.** The gap to 2^128 comes from the constants (384, the factor 3, T = q + 2L), not from an
  attack.
- **Not covered:** indifferentiability (still about 2^42.7 proved, `README.md` § 5); multi-target preimages; the keyed
  modes (AEAD, parallel AEAD, TE: `AEAD_SECURITY.md`); an adversary that also holds a keyed oracle.
- **Mode frames.** The AEAD frames (modes 3 and 6) give other roots. They play no part here: the statement is about
  the unkeyed sponge and an adversary that queries P.

## 7. Checks

Four programs in `cm26_verif/`, run on 16 November 2026. The properties are always computed from the definitions of
§ 2, never from the case analysis of § 3. Two independent implementations of these definitions (Python and C).

| What is checked | How | Result |
|---|---|---|
| **The model is our sponge** | § 1 against `SPEC.md` § 3.2 and § 3.4, and against the second implementation `spec_ref.c` (`sponge()`: P(IV) first, domain × 16 XORed into byte 127 of the last block; `hache()`: domain 10 up to 8 192 bytes, else leaves 8, root 9), which reproduces the 23 test vectors | read; byte 127 is a capacity byte (rate = bytes 0..79) |
| **Lemma A, case by case** (`exhaustif.c`) | for every database h outside the property and every free pair (x, y): if h[x ↦ y] is in the property, the pair is in the set predicted by § 3 (cases a, b, c, inverse). **Exhaustive**: all 1 910 657 databases of size ≤ 3 for N = 16; all 493 057 of size ≤ 2 for N = 32 (domains 8, 9, 10 as in the real sponge); all 16 385 of size ≤ 1 for N = 128. Plus 23 400 loaded databases up to size 14, N up to 512 | 1.1 · 10⁹ pairs tried, 2.6 · 10⁸ bad ones, **no exception**; counts never above the bounds; the collision bound is reached |
| The check itself detects a wrong proof | `exhaustif.c` built with `-DTEMOIN`: the predicted set without D ⊕ D (the proof without I2) | fails, as it must (8 501 exceptions) |
| Lemma A, counts (`eponge_domaines.py`, r = 3, c = 8, d = 3) | exact count of bad extensions, forward and inverse | 3 452 collision cases and 2 083 preimage cases, none above the bound; largest ratios 1.000 and 0.913 |
| **Witnessing** (§ 2) | every transcript present in a database that is not bad: distinct labelled messages end on distinct final edges; every collision puts the database in B_col | 1 914 transcripts, 194 collisions, no exception |
| Properties increasing | random extensions | 2 986, no exception |
| I2 is needed | a database without I1 where one final edge ends two labelled messages | found |
| With D = {0} the article is recovered | count against [CM] (90); the general formula reduces to it | yes; largest ratio 1.000 |
| **End to end, classical** (`classique.py`, r = 12, c = 14, d = 12) | a classical adversary is a special case; with lazy sampling P[database in B_col within q queries] ≤ Σ s_t/(N − t). An adversary that grows the tree and asks final edges, 20 000 games per point | q = 8, 16, 24, 32: measured 0.016, 0.059, 0.130, 0.215 against 0.029, 0.117, 0.263, 0.468. With one domain: 0.010 … 0.139 against [CM]'s 0.011 … 0.184. The bound holds and is within a factor 2.2 of what this adversary gets |
| The domains have a real cost | same games: frequency of I2 alone, and four domains against one | I2 alone: 0.098 at q = 32; the property is reached 1.5 times more often with four domains (the bound allows 2.5) |
| **Arithmetic** (`constantes.py`, 400 digits) | [CM] (88) from the definitions (80), (87): a_N ≤ √2, e_N ≤ 88T/√N, for every T at N ≤ 2^20, a range of T up to N = 2^24, and N = 2^1024 up to T = 2^510; simple form ≥ sharp form; the thresholds of § 5 | hold; thresholds 124.81, 125.67, 125.14, 126.00 (ours), 125.33 ([CM], simple) |
| The two sums of § 4 | proof in § 4; numerically for q ≤ 200 000 | hold |
| State of the source | arXiv listing of [CM], 16 November 2026 | v1 only, no erratum |

The checks cover the model, the combinatorics (§ 2–3) and the arithmetic (§ 4–5). They do not check [CM]'s own
theorems, and a classical experiment cannot check a quantum bound: it checks the counting that the quantum bound uses.
