"""Table 3 of the paper, from results/thm1_distinguisher.txt and thm1_bounds.py: for each run, the estimated advantage
(measured Pr[D = 1] in the real world minus the proven bound phi on Pr[D = 1] in the ideal world) against the bound B of
Theorem 1 (worlds real) or B2 of Lemma 2 (world rd), in standard errors.  Usage: table3.py"""
import re
from fractions import Fraction as Fr
from thm1_bounds import sides
for line in open("results/thm1_distinguisher.txt"):
    m = re.match(r"(\w+) alpha=(\w+) r=(\d+) c=(\d+) k=(\d+) Mu=(\d+) Omega=(\d+) v=(\d+) M=\d+ trials=(\d+) seed=(\d+) : Pr\[D=1\] = (\S+) \+- (\S+)", line)
    world, alpha = m.group(1), m.group(2)
    r, c, k, Mu, Om, v, trials, seed = map(int, m.groups()[2:10])
    p, se = float(m.group(11)), float(m.group(12))
    M, nb, B, LB, pi0, rho, fp, B2 = sides(r, c, k, Mu, Om, v)
    if world == "ideal":
        print(f"r={r} c={c} Mu={Mu} Om={Om} v={v} {world:5s} {alpha:5s} seed={seed} n={trials:.0e}: Pr[D=1] = {p:.4e} +- {se:.1e} ; proven bound phi = {float(fp):.4e}")
        continue
    ref, name = (B2, "B2") if world == "rd" else (B, "B")
    adv = p - float(fp)
    print(f"r={r} c={c} Mu={Mu} Om={Om} v={v} {world:5s} {alpha:5s} seed={seed} n={trials:.0e}: Pr[D=1] = {p:.6e} +- {se:.2e} ; adv >= Pr - phi = {adv:.6e} ;"
          f" {name} = {float(ref):.6e} ; (adv - {name})/s.e. = {(adv - float(ref)) / se:+.1f} ; LB = {float(LB):.6e} ; (Pr - phi - LB)/s.e. = {(adv - float(LB)) / se:+.1f}")
