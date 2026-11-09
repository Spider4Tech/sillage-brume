# -*- coding: utf-8 -*-
"""Sillage-SIG : Proposition 7 (HVZK, ROM), exécutée sur le modèle réduit de tests/test_sig_modele.py.

Le modèle : n = 16, k = 6, w = 2, GF(16) ⊂ GF(256), une répétition, N = 4 feuilles. Les défis (r, ε) et i* sont
fixés en remplaçant G_1 et G_2, ce qui revient à programmer l'oracle aléatoire. Contrôles :

1. Simulateur. Il ne connaît pas x. Il tire uniformément les graines sœurs, com_{i*}, aux (nul si i* = N − 1), α et β,
   puis calcule ce que calcule le vérifieur et programme H_1 et H_2 sur ces valeurs. Le VRAI vérifieur accepte. On le
   vérifie sur une clé publique qui a deux témoins et sur une clé publique sans aucun témoin de poids ≤ w.
2. Distributions, à (r, ε, i*) fixés. Sur les vues réelles, chaque champ est uniforme sur son domaine : α, β, les champs
   de aux, le premier octet du chemin et de com_{i*}, ainsi que les couples (α, β) et (α, c_aux) par quartets hauts. Ces
   vues ne distinguent ni les deux témoins de la même clé publique, ni le réel du simulé (χ² à deux échantillons).
   Pour i* = N − 1, aux transmis vaut 0, comme chez le simulateur.
3. Témoin. Un prouveur dont le masque a est nul (α = ε·Q(r) révélé) est détecté par les mêmes tests : α n'est plus
   uniforme, et les deux témoins se distinguent.

Seuil fixé avant la mesure : p > 1e-3 / (nombre de tests), par correction de Bonferroni.
"""
import itertools
import os
import random
import types

import numpy as np

from tests.commun import sauver
from tests.noyau_c import igamc
from tests.test_sig_modele import _mini, _pk_sans_temoin
from sillage.sillage_sig import SillageSIG


def p_uniforme(vals, k):
    obs = np.bincount(np.asarray(vals, np.int64), minlength=k)[:k]
    att = len(vals) / k
    return igamc((k - 1) / 2, float(((obs - att) ** 2 / att).sum()) / 2)


def p_deux(a, b, k):
    """χ² d'homogénéité de deux échantillons de même taille sur [0, k)."""
    oa, ob = np.bincount(a, minlength=k)[:k].astype(float), np.bincount(b, minlength=k)[:k].astype(float)
    t = oa + ob
    m = t > 0
    x = float((((oa - ob) ** 2)[m] / t[m]).sum())
    return igamc((int(m.sum()) - 1) / 2, x / 2)


def deux_temoins(sig, rng):
    """Clé publique (graine, y) dont deux x de poids w ont le même syndrome."""
    p = sig.p
    while True:
        seed = rng.randbytes(32)
        cols = sig._matrix(seed)
        vus = {}
        for pos in itertools.combinations(range(p["n"]), p["w"]):
            x = sum(1 << i for i in pos)
            y = sig._mat_vec(cols, x & ((1 << p["k"]) - 1)) ^ (x >> p["k"])
            if y in vus:
                return seed, y, vus[y], x
            vus[y] = x


def fixer_defis(sig, r, eps, istar):
    sig._defis1 = lambda _h: [[(r, eps)]]
    sig._defis2 = lambda _h: [istar]


def champs(sig, s):
    """Vue transmise d'une répétition : (chemin, com, xa, Q, P, c, α, β), premiers octets pour les longs champs."""
    hb, sb, D = sig.p["hb"], sig.p["sb"], sig.p["D"]
    o = 32 + 2 * hb
    chemin, com = s[o], s[o + D * sb]
    o += D * sb + hb
    xa, Q, P, c = s[o:o + 4]
    al, be = s[o + 4], s[o + 5]
    return dict(chemin=chemin, com=com, xa=xa, Q=Q, P=P, c=c, alpha=al, beta=be)


DOMAINES = dict(chemin=256, com=256, xa=64, Q=256, P=256, c=256, alpha=256, beta=256)


def simuler(sig, pk, msg, istar):
    """Transcription simulée sans témoin, puis H_1 et H_2 programmés sur ce que calcule le vérifieur."""
    p = sig.p
    N, hb = 1 << p["D"], p["hb"]
    corps = bytearray(os.urandom(p["D"] * p["sb"] + hb))
    if istar == N - 1:
        corps += bytes(sig.L_aux)
    else:
        corps += bytes([os.urandom(1)[0] & 63]) + os.urandom(sig.L_aux - 1)
    corps += os.urandom(2 * sig.pts)
    capt = {}
    orig = SillageSIG._h

    def h(self, tag, *parts, n=None):
        out = orig(self, tag, *parts, n=n)
        capt[tag] = out
        return out

    sig._h = types.MethodType(h, sig)
    salt = os.urandom(32)
    sig.verify(pk, msg, salt + bytes(2 * hb) + corps)         # H_1 ne dépend pas de h1 : on le lit
    h1 = capt[b"h1"]
    sig.verify(pk, msg, salt + h1 + bytes(hb) + corps)         # H_2 dépend de h1 et des diffusions
    h2 = capt[b"h2"]
    del sig._h
    return salt + h1 + h2 + bytes(corps)


def run(M=3000, essais_sim=200):
    c, m = {}, {}
    rng = random.Random(int.from_bytes(os.urandom(8), "little"))
    sig = _mini()
    p = sig.p
    N = 1 << p["D"]
    seed, y, x1, x2 = deux_temoins(sig, rng)
    (pk1, sk1), (pk2, sk2) = sig._cles(seed, x1), sig._cles(seed, x2)
    c["deux_temoins_meme_cle_publique"] = pk1 == pk2 == (seed, y) and sk1 != sk2
    pk, msg = pk1, b"m"
    r = rng.randrange(16, 256)                       # hors de GF(16) : L_i(r) général
    eps = rng.randrange(1, 256)
    istar = rng.randrange(N - 1)
    m["defis_fixes"] = dict(r=r, eps=eps, istar=istar)

    # 1. simulateur accepté par le vrai vérifieur, avec et sans témoin, pour chaque i*
    pk_vide = _pk_sans_temoin(sig, rng)
    acc = {}
    for nom, cle in (("deux_temoins", pk), ("sans_temoin", pk_vide)):
        ok = 0
        for j in range(essais_sim):
            i = j % N
            fixer_defis(sig, r, eps, i)
            ok += sig.verify(cle, msg, simuler(sig, cle, msg, i))
        acc[nom] = ok
    c["simulateur_accepte_par_le_vrai_verifieur_avec_temoins"] = acc["deux_temoins"] == essais_sim
    c["simulateur_accepte_par_le_vrai_verifieur_sans_temoin"] = acc["sans_temoin"] == essais_sim

    # 2. vues réelles (deux témoins), vue simulée, à (r, ε, i*) fixés
    fixer_defis(sig, r, eps, istar)
    vues = {"x1": [], "x2": [], "sim": []}
    acceptees = 0
    for _ in range(M):
        for nom, sk in (("x1", sk1), ("x2", sk2)):
            s = sig.sign(sk, pk, msg)
            acceptees += sig.verify(pk, msg, s)
            vues[nom].append(champs(sig, s))
        vues["sim"].append(champs(sig, simuler(sig, pk, msg, istar)))
    c["signatures_reelles_acceptees_defis_fixes"] = acceptees == 2 * M
    fixer_defis(sig, r, eps, N - 1)
    c["aux_nul_si_derniere_feuille_cachee"] = all(
        sig.sign(sk1, pk, msg)[32 + 2 * p["hb"] + p["D"] * p["sb"] + p["hb"]:][:sig.L_aux] == bytes(sig.L_aux)
        for _ in range(50))
    fixer_defis(sig, r, eps, istar)

    def tableau(v):
        t = {k: np.array([d[k] for d in v]) for k in DOMAINES}
        t["alpha_beta"] = (t["alpha"] >> 4) * 16 + (t["beta"] >> 4)
        t["alpha_c"] = (t["alpha"] >> 4) * 16 + (t["c"] >> 4)
        return t

    dom = dict(DOMAINES, alpha_beta=256, alpha_c=256)
    T = {k: tableau(v) for k, v in vues.items()}
    tests = {}
    for f, k in dom.items():
        for nom in ("x1", "x2", "sim"):
            tests[f"uniforme_{nom}_{f}"] = p_uniforme(T[nom][f], k)
        tests[f"x1_contre_x2_{f}"] = p_deux(T["x1"][f], T["x2"][f], k)
        tests[f"reel_contre_simule_{f}"] = p_deux(T["x1"][f], T["sim"][f], k)
    seuil = 1e-3 / len(tests)
    m["p_min"] = min(tests.values())
    m["test_p_min"] = min(tests, key=tests.get)
    m["tests"], m["seuil"] = len(tests), seuil
    c["vues_reelles_uniformes"] = all(v > seuil for k, v in tests.items() if k.startswith("uniforme_x"))
    c["vue_simulee_uniforme"] = all(v > seuil for k, v in tests.items() if k.startswith("uniforme_sim"))
    c["deux_temoins_indistinguables"] = all(v > seuil for k, v in tests.items() if k.startswith("x1_contre"))
    c["reel_et_simule_indistinguables"] = all(v > seuil for k, v in tests.items() if k.startswith("reel_contre"))

    # 3. témoin : masque a nul
    masque = sig._masques()
    o = 8 * (sig.xb + 2 * sig.qb)
    sig._masques = lambda: masque & ~(((1 << (8 * sig.pts)) - 1) << o)
    # r du témoin : Q1(r) ≠ Q2(r), sans quoi α = ε·Q(r) coïnciderait pour les deux témoins
    rt = next(v for v in range(16, 256) if fixer_defis(sig, v, eps, istar) is None
              and champs(sig, sig.sign(sk1, pk, msg))["alpha"] != champs(sig, sig.sign(sk2, pk, msg))["alpha"])
    fixer_defis(sig, rt, eps, istar)
    fuite = {"x1": [], "x2": []}
    for _ in range(M // 4):
        for nom, sk in (("x1", sk1), ("x2", sk2)):
            fuite[nom].append(champs(sig, sig.sign(sk, pk, msg)))
    del sig._masques
    F = {k: tableau(v) for k, v in fuite.items()}
    pa = p_uniforme(F["x1"]["alpha"], 256)
    pd = p_deux(F["x1"]["alpha"], F["x2"]["alpha"], 256)
    m["temoin"] = dict(p_uniforme_alpha=pa, p_x1_contre_x2_alpha=pd)
    c["temoin_masque_a_nul_detecte"] = pa < seuil and pd < seuil
    m.update(signatures=M, simulations_acceptees=acc)
    out = {"controles": c, "mesures": m}
    sauver("sig_hvzk", out)
    return out


if __name__ == "__main__":
    import sys
    out = run(*[int(a) for a in sys.argv[1:]])
    for k, v in out["controles"].items():
        print(f"{'OK ' if v else 'ÉCHEC'} {k}")
    print({k: v for k, v in out["mesures"].items() if k != "tests"})
