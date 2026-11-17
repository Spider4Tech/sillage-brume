# -*- coding: utf-8 -*-
"""Intégrales et cubes de grande dimension (noyau C), sens direct et inverse.

Le test Python (test_integral_degre) plafonne à 2^20 entrées. Ici : cubes
de d nibbles complets (2^(4d) entrées, jusqu'à 2^24, 2^28 avec
SILLAGE_INTENSITE ≥ 8) en trois contextes — nibbles aléatoires, voisinage
d'un sommet du graphe (le plus favorable à l'attaquant : la diffusion part
d'un même point), bits isolés aléatoires — et R croissant jusqu'à
disparition du biais. Distingueur : nombre de bits de sortie de somme nulle
≥ 256 + 6·√128 (au hasard, chaque bit est nul avec probabilité 1/2).

La portée mesurée est confrontée à l'encadrement théorique : division
property ≤ 14 tours (direct) / 11 (inverse) (test_division_property).
"""
import json
import math
import os

import numpy as np

from tests import noyau_c as C
from tests.commun import sauver, RESULTATS
from sillage import brume512 as B

N = B.N
SEUIL = 256 + 6 * math.sqrt(128)
DIMS = (4, 5, 6) + ((7,) if C.INTENSITE >= 8 else ())


def contextes(d, rng):
    v = int(rng.integers(N))
    vois = list(dict.fromkeys(int(j) for j in B.E_I[7 * v:7 * v + 7]))[:d]
    out = []
    for nom, nibs in (("aleatoire", rng.choice(N, d, replace=False)),
                      ("aleatoire_2", rng.choice(N, d, replace=False)),
                      ("voisinage", vois)):
        out.append((nom, [4 * int(p) + b for p in nibs for b in range(4)]))
    out.append(("bits_aleatoires", sorted(int(b) for b in rng.choice(4 * N, 4 * d, replace=False))))
    return out


def portee_dp():
    try:
        m = json.load(open(os.path.join(RESULTATS, "division_property.json")))["mesures"]
        return m["direct_portee_DP"]["max_verifie"], m["inverse_portee_DP"]["max_verifie"]
    except (OSError, KeyError, ValueError):
        return 15, 12


def run():
    c, m = {}, {}
    C.charger()
    c["noyau_c_conforme"] = C.conformite()[0]
    rng = np.random.default_rng(4096)
    portee = {}
    for sens, nom_sens in ((0, "direct"), (1, "inverse")):
        tab, p_sens = {}, 0
        for d in DIMS:
            ligne, R = {}, 2
            while R <= 12:
                zeros = {}
                for nom, bits in contextes(d, rng):
                    base = rng.integers(0, 16, N, dtype=np.uint8)
                    for b in bits:                      # bits du cube à 0 dans la base
                        base[b >> 2] &= ~np.uint8(1 << (b & 3))
                    out = C.cube(base, bits, R, sens)
                    zeros[nom] = 512 - int(np.unpackbits(out[:, None], axis=1)[:, 4:].sum())
                ligne[R] = zeros
                if max(zeros.values()) < SEUIL:
                    break
                R += 1
            p = max([r for r, z in ligne.items() if max(z.values()) >= SEUIL], default=0)
            tab[f"2^{4 * d}"] = {"bits_nuls_sur_512_par_tour": ligne, "portee_tours": p}
            p_sens = max(p_sens, p)
        portee[nom_sens] = p_sens
        m[nom_sens] = tab
    dp_d, dp_i = portee_dp()
    io = portee["direct"] + portee["inverse"]
    m["portee_empirique"] = {**portee, "inside_out": io, "marge_tours": B.N_ROUNDS - io,
                             "seuil_bits_nuls": round(SEUIL, 1),
                             "division_property_max": {"direct": dp_d, "inverse": dp_i}}
    c["portee_coherente_avec_division_property"] = portee["direct"] <= dp_d and portee["inverse"] <= dp_i
    c["marge_empirique_au_moins_16_tours"] = B.N_ROUNDS - io >= 16
    out = {"controles": c, "mesures": m}
    sauver("c_integral" + C.SUFFIXE, out)
    return out


if __name__ == "__main__":
    import json as _j
    from tests.commun import _conv
    print(_j.dumps(run(), indent=1, ensure_ascii=False, default=_conv))
