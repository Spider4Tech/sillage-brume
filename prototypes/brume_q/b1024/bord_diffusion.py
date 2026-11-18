# -*- coding: utf-8 -*-
"""Bord de la diffusion (DIFF_LIN.md, § « Edge of diffusion ») : pourquoi le modèle DL des S-box actives donne 2^−18 à
4 tours quand la mesure donne 2^−6,6, et ce que cela dit de l'hypothèse de Markov.

Sous Markov (constantes de tour indépendantes et uniformes), la transformée de Walsh de la distribution de différence
d'un nibble, W[u, μ] = E[(−1)^{μ·Δx_u}], passe une S-box par le carré de sa matrice de corrélation :
    W'(λ) = Σ_μ W(μ)·c²(μ, λ),
et un nibble de différence nulle a W = 1 pour tout masque : il ne coûte rien. La couche linéaire combine les 7 entrées
d'un nibble ; le « champ moyen » les suppose indépendantes (produit des W).

    python3 bord_diffusion.py comparer FIXE MARKOV v r       (sorties de dl_bord en mode 0 et 1)
    python3 bord_diffusion.py champ_moyen MARKOV v delta     (r = 4)
    python3 bord_diffusion.py masque HIST_R4 w SORTIE.hex    (masque de sortie du tour 5 qui ne voit que la S-box w)
    python3 bord_diffusion.py portee                         (champ moyen, toutes les entrées, et portée corrigée)
Sortie : une ligne JSON."""
import json
import math
import os
import re
import sys

import numpy as np

_ICI = os.path.dirname(os.path.abspath(__file__))
_T = open(os.path.join(_ICI, "..", "..", "..", "sillage", "c", "brume1024_tables.h")).read()


def _tab(nom):
    m = re.search(r"%s\s*\[[^=]*\]\s*=\s*\{(.*?)\};" % nom, _T, re.S)
    return [int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", m.group(1))]


K, CS, _CG = _tab("B1_K"), _tab("B1_CS"), _tab("B1_CG")
CG = [_CG[256 * g:256 * g + 256] for g in range(6)]
SB = [10, 13, 4, 1, 2, 6, 5, 0, 11, 15, 14, 12, 7, 8, 9, 3]   # SPEC § 2.1


def _voisin(v, k):   # SPEC § 2.2
    f, i = v // 128, v % 128
    return 128 + (i + k) % 128 if f == 0 else (i - k) % 128


M = [dict() for _ in range(256)]   # M[v][u] : coefficient de x_u dans y_v
for _v in range(256):
    M[_v][_v] = CS[_v]
    for _g in range(6):
        M[_v][_voisin(_v, K[_g])] = CG[_g][_v]
IN = [sorted(M[v]) for v in range(256)]
OUT = [[v for v in range(256) if u in M[v]] for u in range(256)]


def _par(x):
    return bin(x).count("1") & 1


def _gmul(a, b):
    r = 0
    for k in range(4):
        if b >> k & 1:
            t = a
            for _ in range(k):
                t = (t << 1) ^ (0x13 if t & 8 else 0)
            r ^= t
    return r & 15


MUL = [[_gmul(a, b) for b in range(16)] for a in range(16)]
# TR[c][μ] = λ tel que μ·(c·a) = λ·a pour tout a (transposée binaire de la multiplication par c)
TR = [[next(l for l in range(16) if all(_par(mu & MUL[c][a]) == _par(l & a) for a in range(16))) for mu in range(16)]
      for c in range(16)]
CORR = [[sum((-1) ** (_par(a & x) ^ _par(b & SB[x])) for x in range(16)) / 16 for b in range(16)] for a in range(16)]
C2 = np.array(CORR) ** 2
PAR = np.array([[(-1) ** _par(m & d) for d in range(16)] for m in range(16)], float)
_NB = np.array(IN)
_CO = np.array([[M[u][w] for w in IN[u]] for u in range(256)])
_TR = np.array(TR)
# A(t) certifiés (B = 8, C3 ≥ 21, C4 ≥ 28 et leurs sommes), comme DIFF_LIN.md
A = [0, 1, 8, 21, 28, 29, 42, 49, 56, 63, 70, 77, 84]


def boules(v0, r):
    B = [{v0}]
    for _ in range(r):
        B.append(set().union(*(set(OUT[u]) for u in B[-1])))
    return B


def lire(f):
    H = {}
    for ligne in open(f):
        p = list(map(int, ligne.split()))
        H[p[0]] = p[1:]
    return H


def eps(h):
    n = sum(h)
    return [sum(h[d] * PAR[mu][d] for d in range(16)) / n for mu in range(16)], n


def walsh_init(v0, delta):
    W = np.ones((256, 16))
    W[v0] = PAR[:, delta]
    return W


def walsh_tour(W):
    G = W @ C2
    Wn = np.ones((256, 16))
    for k in range(7):
        Wn *= G[_NB[:, k][:, None], _TR[_CO[:, k]]]
    return Wn


def comparer(f0, f1, v0, r):
    H0, H1 = lire(f0), lire(f1)
    B = boules(v0, r)
    dist = {u: t for t in range(r, -1, -1) for u in B[t]}
    out = {}
    for nom, garde in (("bord", lambda d: d == r), ("interieur", lambda d: d < r)):
        e0s, e1s = [], []
        for j in range(256):
            if not garde(dist.get(j, 99)):
                continue
            e0, n = eps(H0[j])
            e1, _ = eps(H1[j])
            e0s += e0[1:]
            e1s += e1[1:]
        e0s, e1s, s = np.array(e0s), np.array(e1s), 1 / math.sqrt(n)
        z = (e0s - e1s) / (s * math.sqrt(2))
        out[nom] = dict(cases=len(z), z2_moyen_ecart=round(float((z ** 2).mean()), 3),
                        z_max_ecart=round(float(abs(z).max()), 2),
                        significatives_fixe=int((abs(e0s) > 6 * s).sum()), significatives_markov=int((abs(e1s) > 6 * s).sum()),
                        log2_eps_max_fixe=round(math.log2(abs(e0s).max()), 2),
                        log2_eps_max_markov=round(math.log2(abs(e1s).max()), 2))
    out["log2_bruit"] = round(math.log2(s), 2)
    return out


def champ_moyen(f, v0, delta):
    W = walsh_init(v0, delta)
    for _ in range(4):
        W = walsh_tour(W)
    H = lire(f)
    B = boules(v0, 4)
    x, y = [], []
    for j in range(256):
        if j in B[4] and j not in B[3]:
            e, n = eps(H[j])
            x += list(W[j, 1:])
            y += e[1:]
    x, y = np.array(x), np.array(y)
    gros = abs(y) > 6 / math.sqrt(n)
    return dict(cases_bord=len(x), log2_eps_max_mesure=round(math.log2(abs(y).max()), 2),
                log2_eps_max_champ_moyen=round(math.log2(abs(x).max()), 2),
                correlation=round(float(np.corrcoef(x, y)[0, 1]), 3),
                rapport_median_sur_significatives=round(float(np.median(x[gros] / y[gros])), 2))


def masque(f, w, sortie):
    """γ sur la sortie du tour 5 avec γ·L(s) = β·s_w : seule la S-box w du tour 5 est vue. Prédiction (une S-box, Markov
    sur ce seul tour) : ε5 = Σ_μ W4[w][μ]·c²(μ, β), W4 mesuré à 4 tours."""
    e, _ = eps(lire(f)[w])
    pred = {b: sum(e[m] * CORR[m][b] ** 2 for m in range(1, 16)) for b in range(1, 16)}
    beta = max(pred, key=lambda b: abs(pred[b]))
    piv = {}
    for u in range(256):
        for k in range(4):
            ligne, sd = 0, (beta >> k & 1) if u == w else 0
            for v in OUT[u]:
                for j in range(4):
                    if TR[M[v][u]][1 << j] >> k & 1:
                        ligne |= 1 << (4 * v + j)
            while ligne:
                b = ligne.bit_length() - 1
                if b not in piv:
                    piv[b] = (ligne, sd)
                    break
                ligne, sd = ligne ^ piv[b][0], sd ^ piv[b][1]
            else:
                assert sd == 0
    assert len(piv) == 1024   # L inversible
    sol = 0
    for b in sorted(piv):
        ligne, sd = piv[b]
        if sd ^ (bin(ligne & sol).count("1") & 1):
            sol |= 1 << b
    g = [sol >> (4 * v) & 15 for v in range(256)]
    for u in range(256):   # vérification : γ ne voit que (w, β)
        acc = 0
        for v in OUT[u]:
            acc ^= TR[M[v][u]][g[v]]
        assert acc == (beta if u == w else 0)
    open(sortie, "w").write("".join("%02x" % (g[2 * i] | g[2 * i + 1] << 4) for i in range(128)))
    return dict(w=w, beta=beta, eps5_predit=pred[beta], log2_eps5_predit=round(math.log2(abs(pred[beta])), 2),
                log2_W4_max=round(math.log2(max(abs(x) for x in e[1:])), 2), nibbles_du_masque=sum(1 for x in g if x))


def portee(e5_mesure=None):
    """Champ moyen : max |ε| d'un nibble de sortie (dans la boule) pour une différence d'un nibble, toutes entrées."""
    R = 6
    best = {r: -1e9 for r in range(1, R + 1)}
    for v0 in range(256):
        B = boules(v0, R)
        for d in range(1, 16):
            W = walsh_init(v0, d)
            for r in range(1, R + 1):
                W = walsh_tour(W)
                a = np.abs(W[:, 1:]).max(axis=1)
                a[[j not in B[r] for j in range(256)]] = 0
                if a.max() > 0:
                    best[r] = max(best[r], math.log2(a.max()))
    pre = {p: best[p] for p in (1, 2, 3, 4)}
    # modèle corrigé : préfixe de p tours (différence d'un nibble, sortie d'un nibble) au coût mesuré, puis une
    # caractéristique linéaire de r − p tours dont la première S-box est la S-box du préfixe (une de moins à payer),
    # au carré : ε ≈ 2^{e_p} · 2^{j} · 2^{−2(A(r−p) − 1)}, j = gain de jonction mesuré à 5 tours (ε5 / W4 · 2^2).
    jonction = 2.0 if e5_mesure is None else e5_mesure - pre[4] + 2
    modele_corrige = {}
    for r in range(5, 13):
        modele_corrige[r] = round(max(pre[p] + jonction - 2 * A[r - p] for p in (1, 2, 3, 4)), 1)
    return dict(champ_moyen_log2_max=dict((r, round(v, 2)) for r, v in best.items()), jonction_bits=round(jonction, 2),
                modele_corrige_log2_eps=modele_corrige,
                paires=dict((r, round(-2 * v, 1)) for r, v in modele_corrige.items()))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "comparer":
        r = comparer(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    elif cmd == "champ_moyen":
        r = champ_moyen(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif cmd == "masque":
        r = masque(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    elif cmd == "portee":
        r = portee(float(sys.argv[2]) if len(sys.argv) > 2 else None)
    else:
        sys.exit("commande inconnue")
    print(json.dumps(r, ensure_ascii=False))
