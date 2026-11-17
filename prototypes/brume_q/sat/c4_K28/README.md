# Reproduction package of C4 ≥ 28 (BRUME-1024q)

Everything needed to check, or to redo, the certificate that every characteristic over 4 rounds of BRUME-1024q has at
least 28 active S-boxes (`docs/brume1024/README.md` § 3), without the machines it ran on. The LRAT proofs themselves are
not here: they weighed several GB each and were deleted once both checkers had accepted them. They are reproducible:
same CNF, same solver, same cubes.

## Contents

| File | What it is |
|---|---|
| `cubes.txt` | The 841 leaves (a, b): literals fixing the unary counters W₀ = a and W₁ = b |
| `chaine_W2.txt`, `sous_cubes.txt` | Split of the 10 hard leaves by W₂ (29 lines) → 290 sub-leaves (literals = leaf + chain line) |
| `chaine_W3.txt`, `cubes_phase3{,b,c}.txt` | Split of the 8 hard sub-leaves by W₃ → 232 pieces |
| `chaine_P4.txt`, `cubes_phase4{,c}.txt` | Split of the 2 hard pieces by the round-1 activity of the 7 neighbours of nibble 0 (128 lines) → 256 cubes |
| `completude*.cnf` | The four completeness CNFs (conjunction of the negated lines of each split) |
| `completude*.txt` | Their results: unsatisfiable, both checkers. `completude_P4.txt` is labelled "W3" by a copied script; it is the output for `completude_P4.cnf` |
| `res/*.txt` | One result line per unit of every campaign: key, solver return code, time, proof size, machine (anonymised as machine-A…D), and both checkers' verdicts |
| `feuilles_prouvees.txt`, `verif.txt` | Leaves proved in the first pass; output of `c3_cnf1024 verif` (model and encoding checks) |
| `scripts/` | The unit scripts actually run (leaf, sub-leaf, piece, cube, completeness) |

## Tools and versions

- CNF: `../c3_cnf.c` built with `-DB1024` (see `../README.md` § 5), then `c3_cnf1024 cnf diff 4 28 base.cnf`. The CNF is
  deterministic: SHA-256 `625527dae20db75909994a9a4f4284f9e99e6a491e806f45f7a37a1bc9709b81`, the same in every phase. The
  linear CNF (`cnf lin 4 28`) is identical apart from its comment line, because supp M = supp Mᵀ.
- Solver: CaDiCaL 1.7.3, `--lrat=true --binary=false`.
- Checkers: `../lrat_verif.c` (ours) and `lrat-check` from drat-trim (commit 2e3b2dc, `-std=gnu99 -DLONGTYPE`). Every proof
  had to be accepted by both.

## Check

```bash
python3 prototypes/brume_q/sat/audit_c4_K28.py                 # re-reads this package; exit 0 = certified
CADICAL=… LRAT_VERIF=… LRAT_CHECK=… python3 prototypes/brume_q/sat/audit_c4_K28.py --reprouver 3
```

The audit checks that each completeness CNF is exactly the negation of its split (rebuilt from the lists, not read from a
log), that each child's literals are its parent's plus its own chain line, and that every node is proved directly or
through all its children. With `--reprouver n` it regenerates the base CNF, checks its SHA-256, and **redoes** the four
completeness proofs and n random nodes at each level with both checkers, so the result no longer rests on the text of
the logs. Run on 15 November 2026 with n = 2: all 12 proofs redone and accepted (2 min 27 s).

To redo everything, run each line of each list as in `scripts/`: about 11 hours of solver time in total; the hardest
piece, (4, 9, 10, 4), took 5 850 s and 18.8 GB of proof.
