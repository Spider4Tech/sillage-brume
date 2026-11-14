"""F2, calcul EXACT (fractions, sans tirage) de Pr[s-collision] dans le monde idéal du lemme 2 de DMV17, pour l'adversaire de
f2_lemme2.c : Mu requêtes non contrôlées (parties externes uniformes sur 2^r, internes uniformes sur 2^c, chemins neufs),
puis Om requêtes à drapeau (chemins neufs) de partie externe α et de parties internes uniformes.
  - α = valeur externe la plus chargée (adversaire) ou α uniforme (témoin).
Sachant les charges finales m_v des tiroirs externes, Pr[aucune collision] = Π_v g(m_v), g(m) = Π_{i<m} (1 − i/2^c).
On somme sur les partitions de Mu (charges triées), pondérées par le nombre de vecteurs de charges correspondants.
Comparé à la borne écrite p. 622 : (C(M,2) − C(Ω+1,2))/2^b + C(Ω+1,2)/2^c, et à la prédiction corrigée
C(Ω,2)/2^c + Ω·E[charge de α]/2^c + C(Mu,2)/2^b (bornes d'union)."""
from fractions import Fraction as Fr
from math import comb, factorial
import sys
from collections import Counter

def partitions(n, k, maxp=None):
    if maxp is None: maxp = n
    if n == 0: yield (); return
    if k == 0: return
    for p in range(min(n, maxp), 0, -1):
        for rest in partitions(n - p, k - 1, p):
            yield (p,) + rest

def exact(r, c, Mu, Om, adversaire=True):
    B, Q = 2 ** r, 2 ** c
    g = [Fr(1)]
    for i in range(Mu + Om + 1): g.append(g[-1] * (1 - Fr(i, Q)))
    tot, pnc, Eload = Fr(0), Fr(0), Fr(0)
    for lam in partitions(Mu, B):
        loads = list(lam) + [0] * (B - len(lam))
        mult = Counter(loads)
        nvec = factorial(B)
        for v in mult.values(): nvec //= factorial(v)        # vecteurs de charges ayant ces valeurs
        w = Fr(nvec * factorial(Mu), B ** Mu)
        for x in loads: w /= factorial(x)
        tot += w
        base = Fr(1)
        for x in loads: base *= g[x]
        if adversaire:
            a = max(loads)
            pnc += w * base / g[a] * g[a + Om]
            Eload += w * a
        else:
            s = sum(base / g[x] * g[x + Om] for x in loads) / B
            pnc += w * s
            Eload += w * Fr(sum(loads), B)
    assert tot == 1
    return 1 - pnc, Eload

if __name__ == "__main__" and len(sys.argv) == 1:
    r, c = 4, 16
    b = r + c
    for Mu, Om in [(16, 8), (16, 1), (32, 4), (4, 8), (8, 8), (24, 16)]:
        M = Mu + Om
        S = comb(Om + 1, 2)
        borne = Fr(comb(M, 2) - S, 2 ** b) + Fr(S, 2 ** c)
        pa, Ea = exact(r, c, Mu, Om, True)
        pt, _ = exact(r, c, Mu, Om, False)
        pred = Fr(comb(Om, 2), 2 ** c) + Om * Ea / 2 ** c + Fr(comb(Mu, 2), 2 ** b)
        print(f"Mu={Mu:2d} Om={Om:2d} : exact adversaire {float(pa):.6e} | témoin {float(pt):.6e} | borne p. 622 {float(borne):.6e}"
              f" | rapport adv/borne {float(pa / borne):.3f} | E[charge α] {float(Ea):.3f} | prédiction union {float(pred):.6e}")

def lemme2_seconde(r, c, Mu, Om):
    """Réparation serrée (lemme 2″) : C(L+Ω+1,2)/2^c + (L+Ω)·C(Mu,2)/2^b + C(M,2)/2^b, avec L = 0, Ω = Om."""
    b = r + c
    return Fr(comb(Om + 1, 2), 2 ** c) + Fr(Om * comb(Mu, 2), 2 ** b) + Fr(comb(Mu + Om, 2), 2 ** b)

if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "reparation":
    r, c = 4, 16
    ok = True
    for Mu, Om in [(16, 8), (16, 1), (32, 4), (4, 8), (8, 8), (24, 16), (2, 30), (40, 2)]:
        pa, _ = exact(r, c, Mu, Om, True)
        l2s = lemme2_seconde(r, c, Mu, Om)
        ok &= pa <= l2s
        print(f"Mu={Mu:2d} Om={Om:2d} : exact {float(pa):.6e} ≤ lemme 2″ {float(l2s):.6e} : {'oui' if pa <= l2s else 'NON'}")
    print("réparation tenue partout :", "oui" if ok else "NON")
