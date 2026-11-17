# -*- coding: utf-8 -*-
"""Différentiel et linéaire mesurés à grande échelle (noyau C).

1. Différentielle à 2 tours le long de la meilleure caractéristique
   (1 + 7 S-box actives, minimum imposé par B = 8) : probabilité mesurée
   sur 2^27 paires vs prédiction de la caractéristique → facteur d'effet de
   groupe (le test Python ne voyait que ~32 occurrences).
2. Linear hull à 2 tours (trail à 8 S-box de test_hull) sur 2^28
   échantillons : facteur hull à ±2 %.
3. Balayage tour par tour, sens direct et inverse, avec entrées et sorties
   ALIGNÉES sur les S-box (le cas le plus favorable à l'attaquant : la
   couche linéaire extrême est retirée — M^-1 appliquée à la sortie dans le
   sens direct ; différence / masque d'entrée pré-diffusés dans le sens
   inverse, dont la première opération est M^-1) :
   - différentielles tronquées : distribution des 128 nibbles de différence
     (χ² à 15 ddl par nibble, correction de Bonferroni) ;
   - approximations linéaires : masque d'entrée à un nibble, corrélation
     avec les 128 × 15 masques de sortie à un nibble (max |z|) ;
   jusqu'au premier tour sans biais détectable (p < 10^-6).
"""
import math

import numpy as np

from tests import noyau_c as C
from tests.commun import sauver, tables_sbox
from tests.test_hull import trail_lineaire_2_tours, _inverse_gf2, _bits, _nibbles
from sillage import brume512 as B

N = B.N
DDT, LAT = tables_sbox(B.SBOX)
P_DIST = 1e-6


def caracteristique_2_tours(a=1):
    b = int(np.argmax(DDT[a]))
    x = np.zeros(N, np.uint8); x[0] = b
    mid = B.diffuse(x)
    d = np.zeros(N, np.uint8)
    lp = math.log2(DDT[a, b] / 16)
    for j in np.nonzero(mid)[0]:
        d[j] = int(np.argmax(DDT[mid[j]]))
        lp += math.log2(DDT[mid[j], d[j]] / 16)
    din = np.zeros(N, np.uint8); din[0] = a
    return din, B.diffuse(d), lp, int((mid != 0).sum()) + 1


def entrees(rng):
    out = []
    v = np.zeros(N, np.uint8); v[0] = 1
    out.append(("1_nibble_fixe", v))
    v = np.zeros(N, np.uint8); v[rng.integers(N)] = rng.integers(1, 16)
    out.append(("1_nibble_aleatoire", v))
    v = np.zeros(N, np.uint8); v[rng.choice(N, 2, replace=False)] = rng.integers(1, 16, 2)
    out.append(("2_nibbles", v))
    return out


def transpose_inverse():
    """Matrice binaire de (Mᵀ)^-1 : <α, M^-1 x> = <(Mᵀ)^-1 α, x>."""
    T = np.zeros((4 * N, 4 * N), np.uint8)
    for i in range(4 * N):
        e = np.zeros(4 * N, np.uint8); e[i] = 1
        T[:, i] = _bits(B.diffuse_T(_nibbles(e)))
    return _inverse_gf2(T)


def p_tronque(hist, n):
    att = n / 16
    chi = ((hist - att) ** 2 / att).sum(1)
    pmin = min(C.igamc(7.5, float(x) / 2) for x in chi)
    return min(1.0, 128 * pmin)


def p_lin(corr, n):
    zmax = float(np.abs(corr[:, 1:]).max()) * math.sqrt(n)
    return C.p_max_normales(zmax, N * 15), round(zmax, 2)


def balayage(sens, rng, n, Tinv):
    res, portee = {}, {"tronque": 0, "lineaire": 0}
    ins = entrees(rng)
    for R in range(1, 11):
        ligne, biais = {}, {"tronque": False, "lineaire": False}
        for nom, v in ins:
            if sens == 0:                    # P commence par S : entrée déjà alignée
                din, ma, post = v, v, 1
            else:                            # P^-1 commence par M^-1
                din, ma, post = B.diffuse(v), _nibbles((Tinv @ _bits(v)) % 2), 0
            _, h = C.diff(din, R, n, int(rng.integers(1 << 62)), sens=sens, post=post)
            pt = p_tronque(h.astype(float), n)
            pl, zl = p_lin(C.lin_nib(ma, R, n, int(rng.integers(1 << 62)), sens=sens, post=post), n)
            ligne[nom] = {"p_tronque": float(f"{pt:.3g}"), "p_lineaire": float(f"{pl:.3g}"), "z_max_lin": zl}
            biais["tronque"] |= pt < P_DIST
            biais["lineaire"] |= pl < P_DIST
        res[R] = ligne
        for k, b in biais.items():
            if b:
                portee[k] = R
        if not any(biais.values()):
            break
    return res, portee


def run():
    c, m = {}, {}
    C.charger()
    c["noyau_c_conforme"] = C.conformite()[0]
    rng = np.random.default_rng(777)
    # 1. différentielle à 2 tours
    din, dout, lp, act = caracteristique_2_tours()
    n = C.taille(27)
    ex, _ = C.diff(din, 2, n, 11, cible=dout)
    mes = math.log2(ex / n) if ex else None
    m["diff_2_tours"] = {"paires": n, "occurrences": ex, "sbox_actives": act,
                         "caracteristique_log2": round(lp, 3),
                         "mesure_log2": None if mes is None else round(mes, 3),
                         "facteur_groupe": None if mes is None else round(2 ** (mes - lp), 3),
                         "incertitude_relative": round(1 / math.sqrt(max(ex, 1)), 4)}
    c["diff_2_tours_pas_d_effet_de_groupe_massif"] = ex > 0 and 2 ** (mes - lp) < 4
    # 2. linear hull à 2 tours
    delta, beta, actives, pred = trail_lineaire_2_tours()
    n = C.taille(28)
    corr = C.lin(delta, beta, 2, n, 12)
    sd = 1 / math.sqrt(n)
    m["lin_2_tours"] = {"echantillons": n, "sbox_actives": actives,
                        "correlation_mesuree": round(corr, 7), "prediction_trail_abs": abs(pred),
                        "ecart_type": round(sd, 7), "facteur_hull": round(abs(corr) / abs(pred), 4)}
    c["hull_2_tours_pas_d_amplification_massive"] = abs(corr) <= 4 * abs(pred) + 5 * sd
    # 3. balayages
    n = C.taille(24)
    portee, Tinv = {}, transpose_inverse()
    for sens, nom in ((0, "direct"), (1, "inverse")):
        res, p = balayage(sens, rng, n, Tinv)
        m[f"balayage_{nom}"] = {"paires_par_point": n, "par_tour": res, "portee": p}
        portee[nom] = max(p.values())
    m["portee_empirique"] = {**portee, "inside_out": sum(portee.values()),
                             "marge_tours": B.N_ROUNDS - sum(portee.values())}
    c["aucun_biais_detecte_a_8_tours"] = max(portee.values()) < 8
    c["marge_empirique_au_moins_16_tours"] = B.N_ROUNDS - sum(portee.values()) >= 16
    out = {"controles": c, "mesures": m}
    sauver("c_diff_lin" + C.SUFFIXE, out)
    return out


if __name__ == "__main__":
    import json
    from tests.commun import _conv
    print(json.dumps(run(), indent=1, ensure_ascii=False, default=_conv))
