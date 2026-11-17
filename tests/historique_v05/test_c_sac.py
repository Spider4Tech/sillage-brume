# -*- coding: utf-8 -*-
"""Critère d'avalanche strict (SAC) complet, tour par tour (noyau C).

Matrice 512 × 512 : Pr[bit j de P(x) ⊕ P(x ⊕ e_i) = 1] sur 2^16
échantillons par entrée (le test Python : 500 échantillons à 32 tours
seulement). Pour une permutation aléatoire, les 262 144 cases sont des
Bernoulli(1/2) indépendantes : on teste max |z| (avec correction pour le
nombre de cases) et le χ² global Σ z². On cherche le premier tour
statistiquement indistinguable, sens direct et inverse, puis on vérifie
32 tours.
"""
import math

import numpy as np

from tests import noyau_c as C
from tests.commun import sauver
from sillage import brume512 as B

M = 512 * 512


def stats(cnt, n):
    z = (cnt.astype(float) - n / 2) / math.sqrt(n / 4)
    zmax = float(np.abs(z).max())
    zc = (float((z ** 2).sum()) - M) / math.sqrt(2 * M)
    p = C.p_max_normales(zmax, M)
    return {"moyenne": round(float(cnt.mean()) / n, 5), "z_max": round(zmax, 2),
            "p_max": float(f"{p:.3g}"), "z_chi2": round(zc, 2),
            "pire_case": round(float(np.abs(cnt / n - .5).max()), 4)}, p > 1e-6 and abs(zc) < 6


def run():
    c, m = {}, {}
    C.charger()
    c["noyau_c_conforme"] = C.conformite()[0]
    n, n32 = C.taille(16), C.taille(14)
    prem = {}
    for sens, nom in ((0, "direct"), (1, "inverse")):
        ligne, premier = {}, None
        for R in range(1, 13):
            s, ok = stats(C.sac(R, n, 100 + R, sens), n)
            ligne[R] = s
            if ok:
                premier = R
                break
        s32, ok32 = stats(C.sac(B.N_ROUNDS, n32, 7, sens), n32)
        m[nom] = {"echantillons_par_entree": n, "par_tour": ligne,
                  "premier_tour_indistinguable": premier,
                  "32_tours": {**s32, "echantillons_par_entree": n32}}
        prem[nom] = premier
        c[f"sac_32_tours_conforme_{nom}"] = ok32
        c[f"sac_indistinguable_avant_8_tours_{nom}"] = premier is not None and premier <= 8
    m["marge_tours"] = {k: None if v is None else B.N_ROUNDS - v for k, v in prem.items()}
    out = {"controles": c, "mesures": m}
    sauver("c_sac" + C.SUFFIXE, out)
    return out


if __name__ == "__main__":
    import json
    from tests.commun import _conv
    print(json.dumps(run(), indent=1, ensure_ascii=False, default=_conv))
