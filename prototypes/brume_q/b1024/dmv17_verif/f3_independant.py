"""F3, réimplémentation indépendante de f3_lemme3.c (Python + numpy, générateur PCG64, autre graine), et prédiction
analytique du succès de l'attaque. Monde réel O = (KD_K, f), b = r + c, r = 4, k = 4, f permutation aléatoire de 2^b.
Ressources : q = 1, L = Ω = 0, M = 3 + F, N + M ≤ 0,1·2^c. T_fw = ν^{2M}_{r,c} (nu_exact.py), F = T_fw + 1 requêtes forcées.
Usage : python3 f3_independant.py c essais graine"""
import sys, math
import numpy as np
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from nu_exact import nu

r, k = 4, 4
c, T, graine = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
b = r + c
F = 1
while True:                       # F = ν(2M) + 1 avec M = 3 + F
    M = 3 + F
    v = nu(2 * M, r, c)
    if F == v + 1: break
    F = v + 1
NU, M = F - 1, 3 + F
NMAX = int(0.1 * 2 ** c) - M
rng = np.random.default_rng(graine)
succ = cand_n = 0
for e in range(T):
    f = rng.permutation(2 ** b)
    K = int(rng.integers(16))
    s = int(f[K << c])            # Init(δ, iv = 0), σ = 0
    Zs, sbs = [s >> c], [0]
    s = int(f[s]); Zs.append(s >> c); sbs.append(0)
    s = int(f[s]); Zs.append(s >> c); sbs.append(0)
    N, cand = 0, -1
    for x in rng.permutation(2 ** c):
        if N + 2 + F > NMAX: break
        y = int(f[(Zs[0] << c) | int(x)]); N += 1
        if (y >> c) != Zs[1]: continue
        y2 = int(f[y]); N += 1
        if (y2 >> c) == Zs[2]:
            cand = y2; break
    cur = cand
    for i in range(F):
        sig = 0
        if cand >= 0:
            p = int(f[cur]); N += 1
            sig = ((p >> c) ^ 0) << c   # α = 0
            cur = p ^ sig
        s = int(f[s]); Zs.append(s >> c); sbs.append(sig >> c); s ^= sig
    assert N + M <= 0.1 * 2 ** c
    cnt = {}
    for z, sb in zip(Zs, sbs):
        cnt[z ^ sb] = cnt.get(z ^ sb, 0) + 1
    succ += max(cnt.values()) > NU
    cand_n += cand >= 0
p = succ / T
sd = math.sqrt(p * (1 - p) / T)
# prédiction : ordre aléatoire des suppositions ; coût moyen par supposition 1 + 1/16 ; une fausse candidate passe les deux
# contrôles avec probabilité 2^−2r et arrête la recherche ; le succès exige de tomber sur la vraie avant une fausse.
G = (NMAX - 2 - F) / (1 + 2 ** -r)
q = 2 ** (-2 * r)
pred = sum((1 / 2 ** c) * (1 - q) ** (i - 1) for i in range(1, int(G) + 1))
borne = NU / 2 ** c
print(f"c={c} ν={NU} F={F} M={M} N≤{NMAX} essais={T} graine={graine} : Pr_O(μ_fw > {NU}) = {p:.5f} ± {sd:.5f} ;"
      f" prédiction {pred:.5f} ; borne annoncée ν/2^c = {borne:.6f} ; rapport {p / borne:.1f}")
