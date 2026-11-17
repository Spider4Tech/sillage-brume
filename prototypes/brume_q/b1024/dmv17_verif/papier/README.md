# The security proof of the full-state keyed duplex, revisited

Paper (`paper.tex`, `paper.pdf`) and its verification programs, about the proof of Theorem 1 of Daemen, Mennink and
Van Assche, *Full-State Keyed Duplex with Built-In Multi-user Support* (ASIACRYPT 2017, ePrint 2017/498).

Status: preliminary, **not peer reviewed**, not yet sent to the authors of the paper under study.

Reproduction: a second complete run (16 Nov. 2026, 12 threads) reproduced every output of the reference run digit for
digit, including `f3_kd_check.py` (run separately with Python 3.12.3 and NumPy 2.5.4); `results/` holds that run.

| File | Purpose |
|---|---|
| `f2_exact.py` | gap 1: exact probability of an s-collision against the bound written in the proof of Lemma 2 |
| `thm1_bounds.py` | bound of Theorem 1, bound of Lemma 2, the proven lower bound on the distinguisher's advantage, and the repaired bound (exact) |
| `thm1_distinguisher.c` | simulation of the distinguisher in the worlds KD, RD and IXIF |
| `table3.py` | Table 3 of the paper, from the simulation output and `thm1_bounds.py` |
| `thm1_distinguisher_check.py` | independent implementation of the distinguisher |
| `nu_exact.py` | exact multicollision limit function for small parameters |
| `f3_bound.py` | gap 2: proven lower bound on Pr(mu_fw > T_fw) in the real world (exact) |
| `f3_kd.c`, `f3_kd_check.py` | gap 2 in the real world, two implementations (the second needs numpy) |
| `f3_rd.c`, `f3_rd_check.py` | gap 2 in the randomized-duplex world, two implementations |
| `run_all.sh` | compiles and runs everything, writes `results/` (`bash run_all.sh quick` for a short run) |

Build the paper: `pdflatex paper.tex` twice (packages: amsmath, amsthm, booktabs, enumitem, hyperref, microtype, lmodern).

`run_all.sh` needs gcc with OpenMP and Python 3; `f3_kd_check.py` also needs numpy and is skipped without it. The full run
takes about one hour on 12 threads and overwrites `results/`; `bash run_all.sh quick` also overwrites `results/` (with
100 times fewer trials), so run it in a copy if the reference outputs must be kept.

`contre expertise/` holds external reviews of an earlier draft (16 Nov. 2026) and their recomputation scripts.
