# -*- coding: utf-8 -*-
"""Estimateurs ISD et dimensionnement : cohérence (Prange ≥ Stern, Dumer ≥ BJMM),
optimum à l'intérieur de la grille, points de contrôle publiés, confrontation à
CryptographicEstimators (valeurs figées), modèles quantiques et MAXDEPTH, sécurité
des paramètres retenus, minimalité du n du KEM (le premier d'Artin précédent viole
la sécurité OU la marge de décodage). Les solveurs réels sont dans
tests/c/isd_comparaison.c."""
import math

from tests.commun import sauver
from sillage.sillage_common import (isd_estimate, isd_prange, isd_bjmm, isd_quantique, _bjmm, _dumer,
                                    grover_portes, categorie_nist, MAXDEPTHS, KECCAK_TOFFOLI,
                                    KECCAK_PROFONDEUR)
from sillage.sillage_kem import PARAMS, SillageKEM, borne_echec_log2
from sillage.sillage_common import sparse_random
from sillage.sillage_sig import SIG_PARAMS, SillageSIG
from tests.test_kem import artin


def taux_depassement(n, k, D, w, we, theta, seuil, essais=12):
    """Fraction de clés aléatoires dont la borne d'échec PROUVÉE dépasse seuil."""
    p = dict(n=n, n2=(k // 8) * 128 * D, k=k, D=D, w=w, we=we, theta=theta)
    return sum(borne_echec_log2(sparse_random(w, n), sparse_random(w, n), p) > seuil
               for _ in range(essais)) / essais


# CryptographicEstimators, SDEstimator (temps, log2, 2026-10-30) ; régénérer : voir PREUVES § 5
CE_FIGEES = {(3488, 2720, 64): dict(prange=173.4, stern=151.4, dumer=151.4, bjmm=141.9),
             (2048, 1434, 103): dict(prange=217.1, stern=193.6, dumer=193.2, bjmm=177.6),
             (4096, 2867, 206): dict(prange=408.1, stern=373.8, dumer=373.0, bjmm=342.5),
             (100042, 50021, 150): dict(prange=195.5, stern=173.9, dumer=174.0, bjmm=174.0),
             (340006, 170003, 280): dict(prange=330.6, stern=305.5, dumer=305.6, bjmm=305.6)}


def sig_niveau_quantique():
    """Plus petit w (n = 20w, rendement 1/2) et τ pour viser 128 bits quantiques :
    en requêtes (N^τ ≥ 2^256, graines de 32 octets, ISD Prange–Grover et marche ≥ 128), et
    en catégorie NIST 1 sous MAXDEPTH (oracle de falsification : 4 Keccak-f)."""
    out = {}
    D = SIG_PARAMS["Sillage-SIG-128"]["D"]
    for nom, cle in (("128_bits_requetes", "minimum"), ("128_bits_prange_grover", "prange")):
        w = 170
        while isd_quantique(20 * w, 10 * w, w)[cle] < 128:
            w += 2
        out[nom] = dict(n=20 * w, r=10 * w, w=w, tau=math.ceil(256 / D), sb=32, cle=isd_quantique(20 * w, 10 * w, w)[cle])
    g, d = math.log2(4 * KECCAK_TOFFOLI), math.log2(4 * KECCAK_PROFONDEUR)
    tau = SIG_PARAMS["Sillage-SIG-128"]["tau"]
    while categorie_nist({md: grover_portes(tau * D, g, d, md) for md in MAXDEPTHS}) < 1:
        tau += 1
    out["categorie_1_maxdepth"] = dict(tau=tau, note="sous la seule falsification ; graines ≥ 2^(même N)")
    return out


def run():
    c, m = {}, {}
    # cohérence sur une grille
    ok = True
    for (n, k, w) in ((1000, 500, 50), (2048, 1024, 110), (2 * 12323, 12323, 142), (8000, 4000, 100)):
        e = isd_estimate(n, k, w)
        ok &= e["prange"] >= min(e["stern"], e["dumer"]) >= e["bjmm"] > 0
    c["ordre_prange_dumer_bjmm"] = ok
    # point de contrôle : code QC [2·12323, 12323], poids 142 (ordre de grandeur
    # des instances de récupération de clé de la littérature MDPC niveau 1)
    e = isd_estimate(2 * 12323, 12323, 142)
    m["controle_qc_12323_142"] = e
    c["controle_ordre_de_grandeur"] = 125 <= e["classique"] - math.log2(12323) <= 150
    # régime creux : BJMM ≈ Prange (gain sous-exponentiel) — l'ancien « /2,4 » est faux
    n = 131213
    pr, bj = isd_prange(2 * n, n, 316), isd_bjmm(2 * n, n, 316)
    m["ancien_kem_128"] = {"prange": round(pr, 1), "bjmm": round(bj, 1),
                           "ancienne_annonce_prange_sur_2.4": round((pr - 34) / 2.4, 1)}
    c["regime_creux_bjmm_proche_prange"] = bj / pr > 0.85
    # L'optimum ne touche pas les bornes de recherche (l'ancienne grille p ≤ 24 surestimait la SIG)
    grille = {}
    for lvl, (nn, kk, ww) in dict(
            SIG128=(SIG_PARAMS["Sillage-SIG-128"]["n"], SIG_PARAMS["Sillage-SIG-128"]["k"], SIG_PARAMS["Sillage-SIG-128"]["w"]),
            SIG256=(SIG_PARAMS["Sillage-SIG-256"]["n"], SIG_PARAMS["Sillage-SIG-256"]["k"], SIG_PARAMS["Sillage-SIG-256"]["w"]),
            KEM128=(2 * PARAMS["Sillage-128"]["n"], PARAMS["Sillage-128"]["n"], 2 * PARAMS["Sillage-128"]["w"]),
            KEM256=(2 * PARAMS["Sillage-256"]["n"], PARAMS["Sillage-256"]["n"], 2 * PARAMS["Sillage-256"]["w"])).items():
        b, d = _bjmm(nn, kk, ww), _dumer(nn, kk, ww)
        grille[lvl] = dict(bjmm=round(b[0], 1), p=b[1], eps=b[2], l=b[3], dumer=round(d[0], 1), dumer_p=d[1], dumer_l=d[2])
        c[f"{lvl}_optimum_interieur"] = b[1] < 400 - 16 and b[2] < 100 - 4 and b[3] < 1500 and d[1] < 400 - 16
    m["optimums"] = grille
    # L'estimateur doit rester sous CryptographicEstimators (Esser–Bellini, coût en bits),
    # donc prudent, à un écart borné.
    ecarts = {}
    for (nn, kk, ww), ref in CE_FIGEES.items():
        e = isd_estimate(nn, kk, ww)
        ecarts[f"{nn},{kk},{ww}"] = {a: round(ref[a] - e[a], 1) for a in ref}
    m["ecart_cryptographic_estimators"] = ecarts
    c["estimateur_prudent_face_a_cryptographic_estimators"] = all(
        -0.5 <= v <= 30 for e in ecarts.values() for v in e.values())
    # Modèles quantiques : ordre, et cohérence de Grover sous MAXDEPTH
    qq = isd_quantique(SIG_PARAMS["Sillage-SIG-128"]["n"], SIG_PARAMS["Sillage-SIG-128"]["k"], SIG_PARAMS["Sillage-SIG-128"]["w"])
    m["quantique_sig128"] = qq
    c["quantique_ordre_des_modeles"] = qq["prange"] >= min(qq["stern"], qq["dumer"]) >= qq["bjmm"] > 0
    c["grover_sans_contrainte_racine"] = grover_portes(100, 10, 5, 200) == 60
    c["grover_maxdepth_lineaire"] = grover_portes(100, 10, 5, 40) == 75
    # AES-128 sous MAXDEPTH doit retomber exactement sur le seuil de catégorie 1
    aes = {md: grover_portes(128, 30, 12, md) for md in MAXDEPTHS}
    c["seuil_nist_cat1_coherent_avec_aes128"] = all(abs(aes[md] - (170 - md)) < 1e-9 for md in (40, 64))
    # Quels paramètres donneraient un niveau quantique réel à la SIG (piste 7) ?
    m["sig_niveau_quantique"] = sig_niveau_quantique()
    c["piste_7_doubler_tau_seul_ne_suffit_pas"] = m["sig_niveau_quantique"]["128_bits_requetes"]["w"] > SIG_PARAMS["Sillage-SIG-128"]["w"]
    for lvl, p in PARAMS.items():
        est = SillageKEM(lvl).security_estimate()
        m[f"{lvl}"] = est
        c[f"{lvl}_securite_ge_lambda"] = est["classique_bits"] >= p["lam"]
        # minimalité (à ~5 % près) : avec n 5 % plus petit, la sécurité tombe
        # sous λ+8 ou plus de 5 % des clés dépassent 2^-(λ+8) (critère de choix)
        n1 = int(p["n"] * 0.95)
        while not artin(n1):
            n1 -= 1
        sec1 = isd_estimate(2 * n1, n1, 2 * p["w"])["classique"] - math.log2(n1)
        # 256 : taux vrai ≈ 43 % à D − 2 ; avec 3 clés, le contrôle échouait une fois sur 5,5 par simple hasard
        nb = 12 if p["k"] == 128 else 30
        taux = taux_depassement(n1, p["k"], p["D"], p["w"], p["we"], p["theta"], -(p["lam"] + 8), nb)
        # même exigence sur le code : deux répétitions de moins ne suffisent pas
        taux_D = taux_depassement(p["n"], p["k"], p["D"] - 2, p["w"], p["we"], p["theta"], -(p["lam"] + 8), nb)
        m[f"{lvl}_n_moins_5pc"] = {"n": n1, "securite": round(sec1, 1),
                                   "taux_cles_au_dela_2^-(lambda+8)": taux,
                                   "taux_avec_D_moins_2": taux_D}
        c[f"{lvl}_n_quasi_minimal"] = sec1 < p["lam"] + 8 or taux > 0.05
        c[f"{lvl}_D_minimal"] = taux_D > 0.05
    for lvl, p in SIG_PARAMS.items():
        est = SillageSIG(lvl).security_estimate()
        m[lvl] = est
        c[f"{lvl}_isd_ge_lambda"] = est["isd"]["classique"] >= p["lam"]
        c[f"{lvl}_forgery_ge_lambda"] = est["forgery_fs_bits"] >= p["lam"]
        c[f"{lvl}_tau_suffisant"] = est["forgery_fs_bits"] >= p["lam"]
        c[f"{lvl}_graine_et_haches_ge_lambda"] = est["graine_bits"] >= p["lam"] and est["collision_bits"] >= p["lam"]
    out = {"controles": c, "mesures": m}
    sauver("isd_parametres", out)
    return out


if __name__ == "__main__":
    print(run())
