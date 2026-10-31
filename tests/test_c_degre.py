# -*- coding: utf-8 -*-
"""Croissance réelle du degré algébrique (noyau C), sens direct et inverse.

Borne de Boura–Canteaut (S-box de degré 3) : deg(P_r) ≤ 3^r pour r ≤ 3.
Si le degré d'un bit de sortie est < d, toute somme sur un sous-espace
affine de dimension d est nulle ; une somme NON nulle prouve donc deg ≥ d.
Les cubes portent sur des sous-espaces ALÉATOIRES (vecteurs denses) : sur
des bits isolés, le sens direct — qui commence par la couche de S-box,
nibble par nibble — ne peut pas former au premier tour un monôme réparti
sur plusieurs nibbles, ce qui fausserait la mesure. Pour r = 1, 2, 3 :
  - dimension 3^r : bits de sortie de somme non nulle → le degré maximal
    3^r est-il ATTEINT ? (croissance maximale) ;
  - dimension 3^r + 1 : sommes toutes nulles (cohérence avec la borne
    prouvée — un échec signalerait une erreur de modèle ou de code).
Un degré qui croît au maximum confirme que la portée des distingueurs par
le degré (10 tours dans chaque sens) n'est pas sous-estimée par une
croissance anormalement lente.
"""
import numpy as np

from tests import noyau_c as C
from tests.commun import sauver
from sillage import brume512 as B

N = B.N
CUBES = {1: 8, 2: 8, 3: 3}


def somme(d, R, sens, rng):
    vecs = rng.integers(0, 16, (d, N), dtype=np.uint8)
    out = C.cube_vec(rng.integers(0, 16, N, dtype=np.uint8), vecs, R, sens)
    return int(np.unpackbits(out[:, None], axis=1)[:, 4:].sum())


def run():
    c, m = {}, {}
    C.charger()
    c["noyau_c_conforme"] = C.conformite()[0]
    rng = np.random.default_rng(1618)
    for sens, nom in ((0, "direct"), (1, "inverse")):
        res, max_ok, borne_ok = {}, True, True
        for r, nc in CUBES.items():
            d = 3 ** r
            nz = [somme(d, r, sens, rng) for _ in range(nc)]
            nz1 = [somme(d + 1, r, sens, rng) for _ in range(nc)]
            res[r] = {"dimension": d, "bits_non_nuls_par_cube": nz,
                      "dimension_plus_1_bits_non_nuls": nz1, "degre_maximal_atteint": max(nz) > 0}
            max_ok &= max(nz) > 0
            borne_ok &= max(nz1) == 0
        m[nom] = res
        c[f"degre_maximal_3^r_atteint_{nom}"] = max_ok
        c[f"borne_boura_canteaut_respectee_{nom}"] = borne_ok
    out = {"controles": c, "mesures": m}
    sauver("c_degre" + C.SUFFIXE, out)
    return out


if __name__ == "__main__":
    import json
    from tests.commun import _conv
    print(json.dumps(run(), indent=1, ensure_ascii=False, default=_conv))
