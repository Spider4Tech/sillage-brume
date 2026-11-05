# -*- coding: utf-8 -*-
"""Sillage-KEM : sensibilité de la borne d'échec certifiée au paramètre de Chernoff θ (fixé à 0,7, public).

Le Théorème 4 (docs/PROOFS.md § 2.3) vaut pour tout θ > 0 ; keygen l'évalue à θ = 0,7 sur une table entière
T[c] = ⌈2^12·e^{θc}⌉ (uint32 en C) et rejette les clés dont la borne dépasse 2^-λ. On mesure, sur des clés brutes
tirées comme keygen :
  - la borne à θ fixé sur une grille, avec la table arrondie (celle de l'implémentation) et sans arrondi ;
  - θ* optimal clé par clé (même borne : max sur les 254 supports, union × 254·k/8), et la perte à θ = 0,7 ;
  - la meilleure borne que la preuve autorise, θ choisi par support avant l'union (Σ_S min_θ), comme référence ;
  - le taux de rejet en fonction de θ, la plage où θ ne coûte pas plus de 1 bit ;
  - la limite θ_max au-delà de laquelle T[C_MAX] ne tient plus dans un uint32 (sl_kem_borne, sillage/c/kem.c).
Les histogrammes c(s) par support ne dépendent pas de θ : ils sont calculés une fois par clé (histogrammes()).

    python3 -m tests.test_kem_theta [K128 [K256]]      (défaut 2000 et 800 clés) → resultats/kem_theta.json
"""
import math
import os
import sys

os.environ.setdefault("OMP_NUM_THREADS", "1")       # un processus par cœur, pas de BLAS multi-fil
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
from concurrent.futures import ProcessPoolExecutor

import numpy as np

from tests.commun import sauver
from sillage.sillage_kem import PARAMS, C_MAX, F_TABLE, histogrammes, borne_echec_log2, _positions, _walsh
from sillage.sillage_common import sparse_random

GRILLE = np.round(np.arange(0.30, 1.301, 0.01), 2)
FINE = np.linspace(0.05, 2.0, 1951)                    # pas 0,001 pour θ*
NTEMOIN = 64
THETA_MAX_UINT32 = math.log((2 ** 32 - 1) / 2 ** F_TABLE) / C_MAX


def histogrammes_creux(v, p):
    """Mêmes histogrammes que sillage_kem.histogrammes, calculés depuis les w positions du secret : A[P[q]][j − q] += 1
    pour j ∈ supp(v), au lieu de 128·D rotations denses de longueur n (limitées par la mémoire en parallèle)."""
    n, L = p["n"], 128 * p["D"]
    bits = np.unpackbits(np.frombuffer(v.to_bytes((n + 7) // 8, "little"), np.uint8), bitorder="little")[:n]
    j = np.nonzero(bits)[0]
    P = np.array(_positions(p["D"]))
    A = np.zeros((128, n), np.int16)
    np.add.at(A, (np.broadcast_to(P, (len(j), L)).ravel(), ((j[:, None] - np.arange(L)[None, :]) % n).ravel()), 1)
    w = _walsh(A)
    return [np.bincount(l) for l in np.concatenate(((w[0] + w[1:]) // 2, (w[0] - w[1:]) // 2))]


def table(theta, arrondi=True):
    v = np.exp(np.outer(np.atleast_1d(theta), np.arange(C_MAX + 1)))
    return np.ceil(np.ldexp(v, F_TABLE)) / 2 ** F_TABLE if arrondi else v   # (nθ, C_MAX+1)


def matrice(h):
    m = np.zeros((len(h), C_MAX + 1))
    for i, a in enumerate(h):
        m[i, :len(a)] = a
    return m


def termes(p, theta):
    """Parties de l'exposant qui ne dépendent pas de la clé : −θ|S|/2 + 2·we·ln(1 + p_e(e^θ − 1))."""
    S = 64 * p["D"]
    return -theta * S / 2 + 2 * p["we"] * np.log1p(S / p["n2"] * np.expm1(theta))


def une_cle(args):
    lvl, i = args                                      # secrets tirés sur l'entropie système, comme keygen
    p = PARAMS[lvl]
    x, y = sparse_random(p["w"], p["n"]), sparse_random(p["w"], p["n"])
    hx, hy = histogrammes_creux(x, p), histogrammes_creux(y, p)
    temoin = i < NTEMOIN                               # les premières clés : recalcul par le code de la bibliothèque
    if temoin:
        rx, ry = histogrammes(x, y, p)
        identiques = all(np.array_equal(a, b) for a, b in zip(hx + hy, rx + ry))
    if max(max(len(a) for a in hx), max(len(a) for a in hy)) > C_MAX + 1:
        return {"cmax": True, "temoin": temoin, "identiques": identiques if temoin else None}
    Hx, Hy, n = matrice(hx), matrice(hy), p["n"]
    u = math.log(254 * (p["k"] // 8))
    w = p["w"]

    def fixe(th, arrondi=True):                        # log2 borne, θ commun aux 254 supports (= keygen)
        T = table(th, arrondi)                          # (nθ, 16)
        lm = np.log(Hx @ T.T / n) + np.log(Hy @ T.T / n)   # (254, nθ)
        return (termes(p, np.atleast_1d(th)) + w * lm.max(0) + u) / math.log(2)

    def par_support(th):                               # Σ_S min_θ : θ choisi support par support
        T = table(th, False)
        f = termes(p, th)[None, :] + w * (np.log(Hx @ T.T / n) + np.log(Hy @ T.T / n))
        m = f.min(1)
        return (np.logaddexp.reduce(m) + math.log(p["k"] // 8)) / math.log(2)

    g_arr, g_exa, fin = fixe(GRILLE), fixe(GRILLE, False), fixe(FINE)
    i = int(fin.argmin())
    return {"cmax": False, "grille": g_arr.tolist(), "grille_exacte": g_exa.tolist(),
            "theta_opt": float(FINE[i]), "borne_opt": float(fin[i]), "borne_par_support": float(par_support(FINE)),
            "temoin": temoin, "identiques": identiques if temoin else None,
            "reference_0_7": float(borne_echec_log2(x, y, p)) if temoin else None, "recalcul_0_7": float(fixe(0.7)[0])}


def union_c_max(p):
    """Borne d'union exacte de P[c(s) > C_MAX pour un s, un support et l'un des deux secrets] : c(s) = |(S + s) ∩ y|
    suit, pour s et S fixés, la loi hypergéométrique (n, |S|, w)."""
    n, w, S = p["n"], p["w"], 64 * p["D"]
    queue = sum(math.comb(S, k) * math.comb(n - S, w - k) for k in range(C_MAX + 1, w + 1)) / math.comb(n, w)
    return min(1.0, 2 * 254 * n * queue)


def poisson_sf(k, m):
    """P[Poisson(m) ≥ k]."""
    return 1.0 - sum(math.exp(-m) * m ** i / math.factorial(i) for i in range(k))


def q(v, a):
    return float(np.quantile(v, a))


def profil(lvl, K):
    p = PARAMS[lvl]
    with ProcessPoolExecutor(max(1, (os.cpu_count() or 2) - 1)) as ex:
        res = list(ex.map(une_cle, [(lvl, i) for i in range(K)], chunksize=8))
    ok = [r for r in res if not r["cmax"]]
    ncmax = K - len(ok)
    G = np.array([r["grille"] for r in ok])            # (K', nθ)
    Ge = np.array([r["grille_exacte"] for r in ok])
    lam = p["lam"]
    rejet = ((G > -lam).sum(0) + ncmax) / K
    med = np.median(G, 0)
    j07 = int(np.where(GRILLE == 0.7)[0][0])
    topt = np.array([r["theta_opt"] for r in ok])
    bopt = np.array([r["borne_opt"] for r in ok])
    bsup = np.array([r["borne_par_support"] for r in ok])
    perte = G[:, j07] - bopt                            # bits perdus à θ = 0,7 (≥ 0 à l'arrondi près)
    rej_opt = (np.sum(bopt > -lam) + ncmax) / K
    rej_sup = (np.sum(bsup > -lam) + ncmax) / K
    jmin = int(rejet.argmin())
    plage = GRILLE[med <= med.min() + 1.0]
    lim = np.abs(G[:, j07] + lam) < 8
    ecart = np.abs(np.array([r["recalcul_0_7"] - r["reference_0_7"] for r in ok if r["temoin"]]))
    histo_ok = all(r["identiques"] for r in res if r["temoin"])
    se = lambda r: math.sqrt(r * (1 - r) / K)
    u = union_c_max(p)
    return {
        "rejet_c_max_borne_union": u, "rejet_c_max_borne_union_log2": round(math.log2(u), 2),
        "rejet_c_max_p_valeur_observee": poisson_sf(ncmax, K * u),
        "cles": K, "rejetees_c_max": ncmax, "lambda": lam,
        "grille_theta": GRILLE.tolist(),
        "mediane_log2_par_theta": np.round(med, 2).tolist(),
        "q05_log2_par_theta": np.round(np.quantile(G, 0.05, 0), 2).tolist(),
        "q95_log2_par_theta": np.round(np.quantile(G, 0.95, 0), 2).tolist(),
        "rejet_par_theta": np.round(rejet, 4).tolist(),
        "theta_0_7": {"mediane_log2": round(float(med[j07]), 2), "rejet": round(float(rejet[j07]), 4),
                      "rejet_erreur_type": round(se(float(rejet[j07])), 4),
                      "tirages_moyens_keygen": round(1 / (1 - float(rejet[j07])), 3)},
        "theta_minimisant_la_mediane": float(GRILLE[int(med.argmin())]),
        "plage_theta_a_1_bit_de_la_meilleure_mediane": [float(plage.min()), float(plage.max())],
        "theta_minimisant_le_rejet": float(GRILLE[jmin]), "rejet_minimal_grille": round(float(rejet[jmin]), 4),
        "theta_opt_par_cle": {"q05": round(q(topt, .05), 3), "mediane": round(q(topt, .5), 3),
                              "q95": round(q(topt, .95), 3), "min": round(float(topt.min()), 3),
                              "max": round(float(topt.max()), 3)},
        "perte_bits_a_0_7_vs_theta_opt": {"mediane": round(q(perte, .5), 3), "q95": round(q(perte, .95), 3),
                                          "max": round(float(perte.max()), 3)},
        # clés limites : borne à θ = 0,7 à moins de 8 bits du seuil 2^-λ (celles dont le sort dépend de θ)
        "cles_limites": {"nombre": int(lim.sum()),
                         "perte_bits_mediane": round(q(perte[lim], .5), 3) if lim.any() else None,
                         "perte_bits_max": round(float(perte[lim].max()), 3) if lim.any() else None,
                         "theta_opt_mediane": round(q(topt[lim], .5), 3) if lim.any() else None,
                         "theta_opt_q05_q95": [round(q(topt[lim], .05), 3), round(q(topt[lim], .95), 3)]
                         if lim.any() else None},
        "rejet_theta_opt_par_cle": round(float(rej_opt), 4),
        "rejet_theta_par_support": round(float(rej_sup), 4),
        "mediane_log2_theta_opt": round(q(bopt, .5), 2), "mediane_log2_par_support": round(q(bsup, .5), 2),
        "effet_arrondi_table_bits_max": round(float((G - Ge).max()), 6),
        "effet_arrondi_table_bits_min": round(float((G - Ge).min()), 6),
        "temoins_bibliotheque": int(sum(r["temoin"] for r in res)),
        "histogrammes_creux_identiques_a_la_bibliotheque": bool(histo_ok),
        "ecart_recalcul_implementation_max": float(ecart.max()),
    }


def controles(out):
    """Seuils fixés avant la mesure. Coût toléré de θ fixe : au plus +0,01 tirage moyen de keygen par rapport à θ
    optimisé clé par clé (même borne, même union)."""
    P = [out[l] for l in PARAMS]
    tirages = lambda r: 1 / (1 - r)
    return {
        # le balayage évalue bien la borne de la bibliothèque (histogrammes et valeur à θ = 0,7)
        "balayage_reproduit_borne_echec_log2": all(r["histogrammes_creux_identiques_a_la_bibliotheque"]
                                                   and r["temoins_bibliotheque"] > 0
                                                   and r["ecart_recalcul_implementation_max"] < 1e-9 for r in P),
        # ⌈2^12·e^{θc}⌉/2^12 ≥ e^{θc} : la table ne peut qu'augmenter la borne (sens sûr)
        "table_arrondie_majore_la_borne_exacte": all(r["effet_arrondi_table_bits_min"] >= 0 for r in P),
        "theta_0_7_sous_la_limite_uint32_de_la_table_c": out["theta_fixe"] < out["theta_max_table_uint32"],
        # témoin : la grille encadre l'optimum (sinon « θ quasi optimal » ne voudrait rien dire)
        "grille_encadre_l_optimum_de_la_mediane": all(GRILLE[0] < r["theta_minimisant_la_mediane"] < GRILLE[-1]
                                                      for r in P),
        # le rejet par c > C_MAX ne pèse pas sur keygen (≤ 1 % des rejets) et la borne n'est pas contredite par la mesure
        "rejet_c_max_negligeable_devant_le_rejet_par_la_borne": all(
            r["rejet_c_max_borne_union"] <= 0.01 * r["theta_0_7"]["rejet"] for r in P),
        "rejet_c_max_observe_compatible_avec_la_borne": all(r["rejet_c_max_p_valeur_observee"] > 1e-4 for r in P),
        "theta_0_7_coute_au_plus_0_01_tirage_de_keygen": all(
            tirages(r["theta_0_7"]["rejet"]) - tirages(r["rejet_theta_opt_par_cle"]) <= 0.01 for r in P),
    }


def run():
    K = [int(a) for a in sys.argv[1:3]] + [2000, 800][len(sys.argv[1:3]):]
    out = {"theta_fixe": 0.7, "c_max": C_MAX, "f_table": F_TABLE,
           "theta_max_table_uint32": round(THETA_MAX_UINT32, 4)}
    for lvl, k in zip(PARAMS, K):
        out[lvl] = profil(lvl, k)
        r = out[lvl]
        print(lvl, r["theta_0_7"], "θ*", r["theta_opt_par_cle"], "perte", r["perte_bits_a_0_7_vs_theta_opt"],
              "plage", r["plage_theta_a_1_bit_de_la_meilleure_mediane"], "rejet min", r["theta_minimisant_le_rejet"],
              r["rejet_minimal_grille"], "opt", r["rejet_theta_opt_par_cle"], "support", r["rejet_theta_par_support"],
              flush=True)
    out["controles"] = controles(out)
    sauver("kem_theta", out)
    return out


if __name__ == "__main__":
    run()
