# Study: direct algebraic attacks on reduced rounds (BRUME-1024q)

Written on 17 November 2026, before any computation (ROADMAP § 3, "Direct algebraic attacks"). The criteria below are
fixed **before** the results. Nothing in the permutation changes; this is analysis only.

## Question

How many rounds of the permutation can a generic algebraic solver handle, faster than brute force, on the problem a
sponge attacker actually faces? How does its cost grow with the number of rounds?

## Attack model: CICO

The problem is CICO (constrained input, constrained output), the standard algebraic target for a sponge permutation: a
preimage of the sponge, or an inner-state recovery, needs an input whose capacity part is fixed and an output whose
part is fixed.

- **Permutation:** P_R, the first R rounds of BRUME-1024q, x ↦ M·S(x ⊕ RC_r) for r = 0 … R − 1, with the real constants.
- **Input:** the 96 capacity nibbles (160 … 255) are fixed. Of the 160 rate nibbles, v/4 are free (v free bits) and the
  others are fixed.
- **Output:** k bits of the output (whole nibbles of the rate) are fixed.
- **Planted instances.** A random input x is drawn and P_R(x) computed. The fixed input bits and the k fixed output
  bits are taken from (x, P_R(x)). A solution therefore exists. Unless stated, k = v: about one solution besides the
  planted one.
- **Placement.** Two shapes. *Ball*: the free nibbles form a ball of M's graph around nibble 0, intersected with the
  rate, and the fixed output nibbles are the closest ones to that ball after R rounds (the most local choice, the best
  case for the attacker). *Spread*: free and fixed nibbles taken evenly over the rate.

**Brute force costs 2^v evaluations of P_R.** A solver has an **algebraic advantage** at R rounds if it solves planted
instances with v ≥ 64 (brute force 2^64) within the time limit.

## Solvers

1. **CryptoMiniSat 5.11** with native XOR clauses and Gauss–Jordan elimination: the usual "algebraic attack by SAT".
   The linear layer and the constants are XOR clauses. Each S-box is its exact CNF: 64 clauses of length 5, one for
   each input value and output bit.
2. **CaDiCaL** on the same system with the XORs cut into clauses (Tseitin), as a second, independent solver.
3. **Linearisation and XL, by count only.** No Gröbner tool (Magma, msolve, Singular) is installed here. The degree
   argument below gives the cost of linearisation exactly. A measured Gröbner run is noted as missing, not replaced.

## The degree argument (written before the measurements)

- One round has degree 3 (the S-box), so R rounds have degree at most 3^R in the free bits, and at most v.
- **Pure linearisation** of k output equations of degree D = min(3^R, v) in v variables needs as many equations as
  monomials: Σ_{i ≤ D} C(v, i). With k ≤ 640 output bits and v = 64, D = 3 already needs 43 745 monomials. So pure
  linearisation stops at R = 1 for any useful v. XL multiplies the equations by monomials, which costs at least
  C(v, D) operations.
- **Intermediate variables.** With one variable per S-box output bit, the system is quadratic. The S-box gives 21
  independent quadratic relations between its 4 input and 4 output bits. The system has v + 1 024·(R − 1) + k variables
  for an R-round CICO, and the quadratic Gröbner bound grows with that count. This is what the SAT encoding does.
- **The linear-structure trick.** An attacker can choose free bits so that the first round is linear: on some
  2-dimensional affine subspaces of each nibble, the S-box is affine. That gives one round for free, at the cost of
  half the free bits (2 per nibble). The measured reach R below is to be read as R + 1 for such an attacker, and the
  margin is computed that way.

## What is measured

- The grid: R = 1, 2, 3, …; v ∈ {16, 24, 32, 48, 64, 96, 128, 192, 256}; k = v; two shapes; four planted instances
  per point (different seeds). Each (R, shape, seed) is a ladder (`algebrique1024.py echelle`): v grows, each instance
  is given to CryptoMiniSat then to CaDiCaL, 1 hour each, and the ladder stops at the first v that both solvers fail.
  Rows of R are added until every ladder of a row stops at its first v.
- For each instance: SAT / timeout, the time, and the solution. **Every solution is checked** by evaluating P_R with
  the reference module (`dp1024/b1024_module.tour`, checked against the C vectors by `dp1024.py`), independently of the
  CNF.
- **Checks of the encoding, before the grid.** (a) Inputs and outputs all fixed to (x, P_R(x)): satisfiable. (b) The
  same with one output bit flipped: unsatisfiable (negative witness). (c) Reference brute force for v = 16 at R = 2 and
  3: every solution found by enumeration is a solution of the CNF, and the counts agree. (d) CryptoMiniSat and CaDiCaL
  agree on every instance both solve.

## Alarm criterion

An **algebraic advantage at 6 rounds or more** (planted instances with v ≥ 64 solved in 1 hour). The other measured
reaches are 5 to 7 rounds (statistics, cubes, truncated differentials); an algebraic reach above them would change the
picture. Below it, the result is recorded as the algebraic reach R_alg, and the margin is stated as 32 − (R_alg + 1),
counting the linear-structure round.

## Limits, stated in advance

- One family of solvers (SAT with XOR) is measured; Gröbner bases are not. Dedicated algebraic attacks (on Keccak,
  Ascon, Poseidon) use structure (linear structures over several rounds, polynomial methods, meet-in-the-middle) that
  a generic solver does not find. A short reach here is not a proof that the algebraic attack surface is small.
- Planted CICO instances with k = v are a model of preimage search. Other targets (collisions, distinguishers) are not
  covered.
- The time limit (1 hour, one core) is a budget, not a security level: the result is a reach and a growth rate.

## Results

(To be filled in after the campaign.)
