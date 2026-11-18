# -*- coding: utf-8 -*-
"""Instanciations numériques de docs/PROOFS.md recalculées depuis les constantes du code.

Chaque valeur publiée (tableau ou phrase de PROOFS.md) est recopiée ici avec sa référence. On la confronte au calcul
fait à partir des paramètres réellement utilisés par sillage/. Si les paramètres changent sans que le document suive,
ou l'inverse, le contrôle échoue. Valeurs entières : égalité exacte. Valeurs arrondies : écart ≤ 0,05 bit.

  - § 2.1–2.2 (Théorèmes 1 et 2) : k = λ, graine de rejet σ_rej de 256 bits, borne IND-CCA en q·2^−λ ;
  - § 2.4 : tableau de la recherche sur μ à N chiffrés, et le décodage qui reste au-dessus ;
  - § 4.1 (Théorème 9 v0.6, Corollaire 11) : C4 ≥ 28 et 32 tours → 224 S-box actives, 2^−448 et 2^−224 (196 après
    4 tours libres), depuis la S-box et les constantes de la bibliothèque (sillage/c/brume1024*) ;
  - § 4.3 (Corollaire 14 bis, Théorème Q) : termes à N = σ_D = q_iv = q_d = 2^64, et Q1 à q_Q = 2^128, σ = 2^64 ;
  - § 4.4 (Théorème 16 v0.6) : 2^123,8 et 2^124,1 requêtes standard ; BHT 2^128 sur c = 384 ;
  - § 4.5 (Théorème P) : CV de 64 octets (σ_D/2^512), 105 permutations par feuille de 8 192 octets ;
  - § 3 et § 5 : tailles, niveaux, taille du témoin, marge d'unicité, Lemme 6 et paramètres de la signature ;
  - § 5 bis : les deux tableaux d'instanciation QROM du KEM (HHM22 et BHH+19), l'étalement γ et l'ε-injectivité,
    Don–Fehr–Majenz pour la signature, et le tableau quantique de la signature.
"""
import math

from tests.commun import sauver, tables_sbox
import os
import re
from sillage.sillage_kem import SillageKEM, PARAMS
from sillage.sillage_sig import SillageSIG, SIG_PARAMS
from sillage import sillage_common as SC


def lg(x):
    return math.log2(x) if x > 0 else -math.inf


def lsum(*e):
    """log2 de Σ 2^e."""
    m = max(e)
    return m + math.log2(sum(2.0 ** (x - m) for x in e))


def proche(a, b, tol=0.05):
    return abs(a - b) <= tol


_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sillage", "c")


def _b1024():
    """Constantes de BRUME-1024q lues dans la bibliothèque (pas recopiées)."""
    t = open(os.path.join(_LIB, "brume1024_tables.h"), encoding="utf-8").read()
    src = open(os.path.join(_LIB, "brume1024.c"), encoding="utf-8").read()
    h = open(os.path.join(_LIB, "sillage.h"), encoding="utf-8").read()
    sbox = [int(x) for x in re.search(r"BR_SBOX\[16\] = \{([^}]*)\}", t).group(1).split(",")]
    n = int(re.search(r"#define B1_N (\d+)", t).group(1))
    rb = int(re.search(r"#define RB (\d+)", src).group(1))
    tours = int(re.search(r"static int R1 = (\d+);", src).group(1))
    cv = int(re.search(r"#define CVL (\d+)", src).group(1))
    feuille = 1 << int(re.search(r"#define SL_AEADP_LOG_FEUILLE (\d+)", h).group(1))
    return dict(sbox=sbox, n_bits=4 * n, r=8 * rb, c=4 * n - 8 * rb, tours=tours, cv=8 * cv, feuille=feuille, rb=rb)


def aead(c, m):
    B = _b1024()
    c["profil_1024q_r_640_c_384_32_tours"] = (B["r"], B["c"], B["tours"]) == (640, 384, 32)
    # Corollaire 14 bis : N = σ_D = q_iv = q_d = 2^64, un utilisateur
    N = sD = qiv = qd = 2.0 ** 64
    t1 = lg((2 * sD + 5) * N) - B["c"]
    t2 = lg(2 * qiv * N) - 512
    t3 = lg(qd) - 256
    m["corollaire_14_bis"] = dict(t1=t1, t2=t2, t3=t3, total=lsum(t1, t2, t3))
    c["corollaire_14_bis_termes_2_moins_255_383_192"] = proche(t1, -255) and proche(t2, -383) and t3 == -192
    c["corollaire_14_bis_total_2_moins_192"] = proche(lsum(t1, t2, t3), -192)
    # Théorème Q (Q1) à q_Q = 2^128, σ = 2^64 : 4σ√(q/2^c) + 2q√(2σ/2^c) + σ²/2^(c+1) + 3σ²/2^1025 + q_d/2^256
    q, sig = 128.0, 64.0
    e = (2 + sig + (q - B["c"]) / 2, 1 + q + (1 + sig - B["c"]) / 2, 2 * sig - B["c"] - 1, lg(3) + 2 * sig - 1025, 64.0 - 256)
    m["theoreme_q"] = dict(termes=e, total=lsum(*e))
    c["theoreme_q_2_moins_30_5_a_q_2_128_sigma_2_64"] = proche(lsum(*e), -30.5)
    # Théorème P : CV de 64 octets → σ_D/2^512 ; une feuille = 2 fourches + ⌊B/80⌋ + 1 permutations
    c["theoreme_p_cv_512_bits_terme_2_moins_448"] = B["cv"] == 512 and 64 - B["cv"] == -448
    perm_feuille = 2 + B["feuille"] // B["rb"] + 1
    m["theoreme_p_permutations_par_feuille"] = perm_feuille
    c["theoreme_p_105_permutations_par_feuille_de_8192"] = B["feuille"] == 8192 and perm_feuille == 105
    # Théorème 16 v0.6 : 384T³/2^384 = 1/2 (collision), 192T³/2^384 = 1/2 (préimage), en requêtes d'échange ; une requête
    # standard vaut deux requêtes d'échange
    col = (B["c"] - 1 - lg(384)) / 3
    pre = (B["c"] - 1 - lg(192)) / 3
    m["theoreme_16"] = dict(collision_echange=col, preimage_echange=pre)
    c["theoreme_16_collision_2_123_8_preimage_2_124_1_standard"] = proche(col - 1, 123.8) and proche(pre - 1, 124.1)


def permutation(c, m):
    B = _b1024()
    ddt, lat = tables_sbox(B["sbox"])
    U = int(ddt[1:].max())
    L = int(abs(lat[1:, 1:]).max())
    C4 = 28                                             # certifié (Théorème 9 v0.6 ; audit : tests/test_b1024_certificats.py)
    actives = C4 * (B["tours"] // 4)
    libres = C4 * ((B["tours"] - 4) // 4)
    m["corollaire_11"] = dict(tours=B["tours"], U=U, max_LAT=L, actives=actives, libres=libres,
                              log2_proba=actives * lg(U / 16), log2_correlation=actives * lg(L / 8))
    c["corollaire_11_224_sbox_actives_a_32_tours_196_apres_4_libres"] = actives == 224 and libres == 196
    c["corollaire_11_proba_2_moins_448_correlation_2_moins_224"] = (actives * lg(U / 16) == -448
                                                                     and actives * lg(L / 8) == -224)


def kem(c, m):
    # Sillage-256 seul depuis le 18 novembre 2026 (Sillage-128 retiré, docs/NIST_CATEGORIES.md)
    taille_publiee = {"Sillage-256": (21283, 35587)}
    niveau_publie = {"Sillage-256": (265.1, 158.4)}
    params_publies = {"Sillage-256": (170003, 140, 28, 114688)}
    ok_t = ok_n = ok_p = ok_th2 = ok_24 = True
    tab24 = {}
    for lvl, p in PARAMS.items():
        kem_ = SillageKEM(lvl)
        s, e = kem_.sizes(), kem_.security_estimate()
        ok_t &= (s["pk_bytes"], s["ct_bytes"]) == taille_publiee[lvl]
        ok_n &= proche(e["classique_bits"], niveau_publie[lvl][0]) and proche(e["quantique_bits"], niveau_publie[lvl][1])
        ok_p &= (p["n"], p["w"], p["D"], p["n2"]) == params_publies[lvl]
        # Théorèmes 1–2 : |M| = 2^k avec k = λ ; σ_rej de 256 bits (q_H/2^256 ≤ q_H/2^λ) ; δ ≤ 2^−λ imposé au keygen.
        # Borne IND-CCA ≤ (4q + 1)·2^−λ + 3·Adv^IND-CPA pour q_G = q_H = q.
        ok_th2 &= p["k"] == p["lam"] and 256 >= p["lam"]
        # § 2.4 : recherche sur μ à N chiffrés, classique k − log2 N, Grover (k − log2 N)/2
        lam = p["lam"]
        lignes = {lN: (p["k"] - lN, (p["k"] - lN) / 2) for lN in (0, 32, 64)}
        publie = ({0: (128, 64), 32: (96, 48), 64: (64, 32)} if lam == 128 else {0: (256, 128), 32: (224, 112), 64: (192, 96)})
        ok_24 &= lignes == publie
        # le décodage d'un chiffré parmi N (gain ≈ √N) reste au-dessus de la recherche sur μ
        ok_24 &= all(e["classique_bits"] - lN / 2 > lignes[lN][0] for lN in lignes)
        tab24[lvl] = {f"2^{lN}": dict(recherche_mu=v, decodage=round(e["classique_bits"] - lN / 2, 1)) for lN, v in lignes.items()}
    c["kem_tailles_pk_ct_egales_au_tableau_5"] = ok_t
    c["kem_niveaux_classique_et_quantique_egaux_au_tableau_5"] = ok_n
    c["kem_parametres_egaux_au_tableau_5"] = ok_p
    c["theoreme_2_k_egal_lambda_et_sigma_rej_256_bits"] = ok_th2
    c["tableau_2_4_multi_chiffres_et_decodage_au_dessus"] = ok_24
    m["tableau_2_4"] = tab24


def sig(c, m):
    publie = {"Sillage-SIG-128": dict(n=2048, k=1434, w=103, D=12, tau=11, t=4, ep=44, pk=109, sk=464, sig=8522,
                                      forge=128.3, isd=160.3, temoin=3700, marge=29.5),
              "Sillage-SIG-256": dict(n=4096, k=2867, w=206, D=12, tau=23, t=4, ep=48, pk=186, sk=977, sig=34867,
                                      forge=264.0, isd=316.2, temoin=7811, marge=56.0)}
    ok_p = ok_t = ok_n = ok_w = ok_l6 = ok_h = True
    mes = {}
    for lvl, pub in publie.items():
        s = SillageSIG(lvl)
        p, z, e = s.p, s.sizes(), s.security_estimate()
        ok_p &= all(p[k] == pub[k] for k in ("n", "k", "w", "D", "tau", "t", "ep")) and p["n"] == 1 << p["e"]
        ok_t &= (z["pk_bytes"], z["sk_bytes"], z["sig_bytes"]) == (pub["pk"], pub["sk"], pub["sig"]) == (
            z["pk_bytes"], z["sk_bytes"], s.sig_len())
        ok_n &= proche(s.falsification_bits(), pub["forge"]) and proche(e["isd"]["classique"], pub["isd"])
        unicite = p["r"] - (math.lgamma(p["n"] + 1) - math.lgamma(p["w"] + 1) - math.lgamma(p["n"] - p["w"] + 1)) / math.log(2)
        ok_w &= p["k"] + 2 * p["w"] * p["e"] == pub["temoin"] and proche(unicite, pub["marge"], 0.5) and unicite > 0
        # Lemme 6 : p = ((n + w)/2^ep)^t
        ok_l6 &= proche(s.faux_positif_log2(), p["t"] * lg((p["n"] + p["w"]) / 2 ** p["ep"]), 1e-9)
        # § 3.3 : haches de 2λ bits, graines de λ + 8 bits
        ok_h &= 8 * p["hb"] == 2 * p["lam"] and 8 * p["sb"] == p["lam"] + 8
        mes[lvl] = dict(falsification=round(s.falsification_bits(), 2), isd=e["isd"]["classique"], marge_unicite=round(unicite, 2),
                        faux_positif_log2=round(s.faux_positif_log2(), 2))
    c["sig_parametres_egaux_au_paragraphe_5"] = ok_p
    c["sig_tailles_egales_au_tableau_5"] = ok_t
    c["sig_falsification_et_isd_egales_au_paragraphe_5"] = ok_n
    c["sig_temoin_k_plus_2we_et_marge_d_unicite"] = ok_w
    c["lemme_6_formule_du_faux_positif"] = ok_l6
    c["sig_haches_2_lambda_graines_lambda_plus_8"] = ok_h
    m["sig"] = mes


def quantique(c, m):
    """§ 5 bis. log2 du nombre q de requêtes auquel chaque terme atteint 1. Les niveaux b d'entrée sont arrondis à 0,1 bit
    par l'estimateur, et les valeurs publiées à 0,1 bit : tolérance 0,1 bit sur les valeurs qui en dérivent."""
    hhm = {"Sillage-256": dict(cor=126.5, M=125, pg_q=104.3, pg_40=136.4, walk_q=84.7)}
    bhh = {"Sillage-256": dict(cpa=105.0, M=251, cor=126.5, rej=126)}
    gam = {"Sillage-256": (1631, -1119)}
    ok_h = ok_b = ok_g = True
    mes = {}
    for lvl, p in PARAMS.items():
        n, w, lam, k = p["n"], p["w"], p["lam"], p["k"]
        q = SC.isd_quantique(2 * n, n, 2 * w)
        b_pg = SillageKEM(lvl).security_estimate()["quantique_bits"]       # Prange–Grover, crédit QC log2 n
        b_walk = q["bjmm"] - math.log2(n)                                   # marche, QRAM gratuite
        # HHM22 : 8q²δ, 8q/√|M|, 4√(d·q²/2^{2b}) avec d = q puis d = 2^40
        v = dict(cor=(lam - 3) / 2, M=k / 2 - 3, pg_q=(b_pg - 2) / 1.5, pg_40=b_pg - 22, walk_q=(b_walk - 2) / 1.5)
        ok_h &= all(proche(v[x], hhm[lvl][x], 0.1) for x in v)
        # BHH+19 : 2√((d+2)·q²/2^{2b}), 2√(8q/|M|), 8q²δ, 4√(dq/2^256)
        u = dict(cpa=(b_pg - 1) / 1.5, M=k - 5, cor=(lam - 3) / 2, rej=126)
        ok_b &= all(proche(u[x], bhh[lvl][x], 0.1) for x in u)
        g = SC._lb(n, w)
        ok_g &= round(g) == gam[lvl][0] and round(2 * k - g) == gam[lvl][1]
        mes[lvl] = dict(hhm22=v, bhh19=u, gamma=round(g, 1), b_prange_grover=b_pg, b_marche=round(b_walk, 2))
    c["qrom_kem_hhm22_tableau_5_bis"] = ok_h
    c["qrom_kem_bhh19_tableau_5_bis"] = ok_b
    c["qrom_kem_etalement_gamma_et_epsilon_injectivite"] = ok_g
    # SIG, Don–Fehr–Majenz : 8q⁴·ε_int = 1, ε_int = (p + (1 − p)/N)^τ
    dfm = {"Sillage-SIG-128": 32.2, "Sillage-SIG-256": 68.2}
    tab = {"Sillage-SIG-128": dict(falsification_grover=64.1, graine_grover=68.0, collision_bht=85.3, isd_prange_grover=114.4,
                                   isd_marche_qram_gratuite=76.2, effectif=64.1, portes={40: 114.1, 64: 90.1, 96: 82.4}, cat=0),
           "Sillage-SIG-256": dict(falsification_grover=132.0, graine_grover=132.0, collision_bht=170.7, isd_prange_grover=210.5,
                                   isd_marche_qram_gratuite=151.5, effectif=132.0, portes={40: 245.8, 64: 221.8, 96: 189.8}, cat=3)}
    ok_d = ok_t = True
    for lvl, pub in tab.items():
        s = SillageSIG(lvl)
        p = s.p
        lp = s.faux_positif_log2()
        eint = p["tau"] * math.log2(2 ** lp + (1 - 2 ** lp) / 2 ** p["D"])
        ok_d &= proche((-eint - 3) / 4, dfm[lvl], 0.1)
        e = s.security_estimate()["quantique"]
        ok_t &= (all(proche(e["bits"][x], pub[x]) for x in ("falsification_grover", "graine_grover", "collision_bht",
                                                             "isd_prange_grover", "isd_marche_qram_gratuite"))
                 and proche(e["effectif_bits"], pub["effectif"]) and e["categorie_nist"] == pub["cat"]
                 and all(proche(s.security_estimate()["quantique"]["portes_maxdepth"][md], v) for md, v in pub["portes"].items()))
        mes[lvl] = dict(dfm_log2_q=round((-eint - 3) / 4, 2))
    c["qrom_sig_don_fehr_majenz_q_2_32_et_2_68"] = ok_d
    c["sig_tableau_quantique_5_bis"] = ok_t
    # hachage : collisions BHT en 2^{c/3} ; AEAD : Grover sur la clé, 2^{k/2}
    B = _b1024()
    c["hachage_bht_128_bits_et_grover_cle_aead_256"] = B["c"] / 3 == 128 and 512 / 2 == 256
    m["quantique"] = mes


def run():
    c, m = {}, {}
    aead(c, m)
    permutation(c, m)
    kem(c, m)
    sig(c, m)
    quantique(c, m)
    out = {"controles": c, "mesures": m}
    sauver("bornes_preuves", out)
    return out


if __name__ == "__main__":
    out = run()
    for k, v in out["controles"].items():
        print(f"{'OK ' if v else 'ÉCHEC'} {k}")
    import json
    print(json.dumps(out["mesures"], ensure_ascii=False, indent=1, default=str)[:3000])
