# -*- coding: utf-8 -*-
"""Instanciations numériques de docs/PROOFS.md recalculées depuis les constantes du code.

Chaque valeur publiée (tableau ou phrase de PROOFS.md) est recopiée ici avec sa référence. On la confronte au calcul
fait à partir des paramètres réellement utilisés par sillage/. Si les paramètres changent sans que le document suive,
ou l'inverse, le contrôle échoue. Valeurs entières : égalité exacte. Valeurs arrondies : écart ≤ 0,05 bit.

  - § 2.1–2.2 (Théorèmes 1 et 2) : k = λ, graine de rejet σ_rej de 256 bits, borne IND-CCA en q·2^−λ ;
  - § 2.4 : tableau de la recherche sur μ à N chiffrés, et le décodage qui reste au-dessus ;
  - § 4 (Théorème 9, Corollaire 11) : 32 tours → 128 S-box actives, 2^−256 et 2^−128, depuis la S-box elle-même ;
  - § 4.3 (Théorème 14, Corollaires 14 bis et 14 ter, Théorème 14-mu) : profils, terme à terme, cas limite ;
  - § 4.5 (Théorème 14-p) : |CV| = 2λ, σ/2^|CV|, appels à P par feuille comptés sur le vrai mode ;
  - § 3 et § 5 : tailles, niveaux, taille du témoin, marge d'unicité, Lemme 6 et paramètres de la signature ;
  - § 5 bis : les deux tableaux d'instanciation QROM du KEM (HHM22 et BHH+19), l'étalement γ et l'ε-injectivité,
    Don–Fehr–Majenz pour la signature, et le tableau quantique de la signature.
"""
import math

from tests.commun import sauver, tables_sbox
from sillage import brume512 as B
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


def aead(c, m):
    b = 512
    prof = {}
    for nom, p in B.BRUME512_PROFILES.items():
        r = p["rate"] * 4
        prof[nom] = dict(r=r, c=b - r, tau=8 * p["tag_len"], k=8 * p["key_len"], m=8 * p["key_len"] // r,
                         nonce=8 * p["nonce_len"], lam=p["lam"])
    m["profils"] = prof
    # Tableau « Setting » de § 4.3
    publie = {"BRUME-512": (256, 256, 128, 2), "BRUME-512-256": (128, 384, 256, 4)}
    c["profils_aead_egaux_au_tableau_4_3"] = all(
        (prof[n]["r"], prof[n]["c"], prof[n]["tau"], prof[n]["m"]) == v and prof[n]["k"] == 512 for n, v in publie.items())

    # Corollaire 14 bis, σ = 2^64 : log2 des termes ; les termes en N et q_d sont donnés par leur coefficient
    ls = 64
    bis_publie = {"BRUME-512": dict(sig2c=-129, sigN=-191, Nc=-256, Nk_Nb=-510, sig2b=-385, qd=-128),
                  "BRUME-512-256": dict(sig2c=-257, sigN=-319, Nc=-384, Nk_Nb=-510, sig2b=-385, qd=-256)}
    ok_bis, ok_somme, lim, bord = True, True, {}, {}
    for nom, P in prof.items():
        t = dict(sig2c=2 * ls - P["c"] - 1, sigN=1 + ls - P["c"], Nc=-P["c"], Nk_Nb=lsum(-P["k"], 1 - b),
                 sig2b=2 * ls - b - 1, qd=-P["tau"])
        pub = bis_publie[nom]
        # « ≤ » du tableau : la valeur calculée ne dépasse pas la valeur publiée, et l'égale à l'arrondi près
        ok_bis &= all(t[k] <= pub[k] + 1e-9 and t[k] > pub[k] - 1 for k in pub)
        # Somme ≤ (N + q_d)·2^−τ + 2^−τ : coefficient de N, de q_d et terme constant
        coef_N = lsum(t["sigN"], t["Nc"], t["Nk_Nb"])
        cst = lsum(t["sig2c"], t["sig2b"])
        ok_somme &= coef_N <= -P["tau"] and t["qd"] <= -P["tau"] and cst <= -P["tau"]
        lim[nom] = max(("sig2c", t["sig2c"]), ("sig2b", t["sig2b"]), key=lambda z: z[1])[0]
        # Cas limite (§ 4.3, lecture) : N = 2^128, σ = 2^64, q_d = 0
        bord[nom] = round(lsum(128 + coef_N, cst), 2)
        m[f"{nom}_corollaire_14_bis"] = {k: round(v, 3) for k, v in t.items()}
    c["corollaire_14_bis_terme_a_terme"] = ok_bis
    c["corollaire_14_bis_somme_au_plus_N_plus_qd_plus_1_sur_2_tau"] = ok_somme
    c["limite_de_donnees_fixee_par_sigma2_sur_2c"] = all(v == "sig2c" for v in lim.values())
    c["cas_limite_N_2_128_avantage_2_moins_63"] = proche(bord["BRUME-512"], -63, 0.05)
    m["cas_limite_log2_avantage"] = bord

    # Corollaire 14 ter : nonces de 192 bits tirés au hasard, terme q_e²/2^{193}
    ter = {}
    for nom, P in prof.items():
        nb = P["nonce"] + 1
        borne_qe = nb - P["tau"]                        # q_e²/2^nb ≤ q_e/2^τ ⇔ q_e ≤ 2^(nb − τ)
        ter[nom] = dict(exposant=nb, a_2_64=2 * 64 - nb, qe_max_log2=borne_qe, moitie_a=(nb - 1) / 2)
    m["corollaire_14_ter"] = ter
    c["corollaire_14_ter_terme_2_moins_65_a_2_64"] = all(v["exposant"] == 193 and v["a_2_64"] == -65 for v in ter.values())
    c["corollaire_14_ter_512_tient_jusqu_a_2_65"] = ter["BRUME-512"]["qe_max_log2"] == 65
    c["corollaire_14_ter_512_256_aucun_qe_et_plafond_96"] = (ter["BRUME-512-256"]["qe_max_log2"] < 0
                                                           and ter["BRUME-512-256"]["moitie_a"] == 96)

    # Théorème 14-mu, μ = σ = 2^64
    mu_publie = {"BRUME-512": -192, "BRUME-512-256": -320}
    ok_mu = True
    for nom, P in prof.items():
        muNc, mu2 = 64 - P["c"], 2 * 64 - P["k"] - 1
        coef_N = lsum(64 - P["c"], 64 - P["k"], 64 + 1 - b, 1 + ls - P["c"])
        cst = lsum(2 * ls - P["c"] - 1, 2 * ls - b - 1, mu2)
        ok_mu &= muNc == mu_publie[nom] and mu2 == -385 and coef_N <= -P["tau"] and cst <= -P["tau"]
    c["theoreme_14_mu_instanciation"] = ok_mu

    # Théorème 14-p : CV de 2λ bits, σ/2^|CV| à σ = 2^64, appels à P par feuille
    cv = {}
    for nom in B.BRUME512P_PROFILES:                  # longueur réelle du CV rendu par une feuille
        br = B.Brume512P(nom, bytes(64))
        cv[nom] = 8 * len(br._feuille(br._init_state(bytes(24), b""), 0, b"x", False)[1])
    c["theoreme_14_p_cv_2_lambda_et_terme"] = (cv == {"BRUME-512p": 256, "BRUME-512-256p": 512}
                                              and {n: 64 - v for n, v in cv.items()} == {"BRUME-512p": -192, "BRUME-512-256p": -448})
    appels = {}
    vrai = B.brume_v1
    try:
        compte = [0]

        def compteur(st, rounds=B.N_ROUNDS):
            compte[0] += 1
            return vrai(st, rounds)
        B.brume_v1 = compteur
        for nom in B.BRUME512P_PROFILES:
            br = B.Brume512P(nom, bytes(64))
            par_k = []
            for k in (2, 4):
                compte[0] = 0
                br.encrypt(bytes(24), bytes(k * B.AEADP_FEUILLE))
                par_k.append(compte[0])
            appels[nom] = (par_k[1] - par_k[0]) / 2     # coût marginal d'une feuille pleine, racine comprise
    finally:
        B.brume_v1 = vrai
    blocs = {n: B.AEADP_FEUILLE // (p["rate"] // 2) for n, p in B.BRUME512P_PROFILES.items()}
    m["theoreme_14_p_appels_par_feuille"] = dict(appels=appels, blocs_de_donnees=blocs)
    c["theoreme_14_p_132_appels_pour_128_blocs_et_263_pour_256"] = (
        (appels["BRUME-512p"], blocs["BRUME-512p"]) == (132, 128) and (appels["BRUME-512-256p"], blocs["BRUME-512-256p"]) == (263, 256))


def permutation(c, m):
    ddt, lat = tables_sbox(B.SBOX)
    U = int(ddt[1:].max())
    L = int(abs(lat[1:, 1:]).max())
    actives = 8 * (B.N_ROUNDS // 2)                    # Théorème 9 avec B = 8 (certifié : test_branch_exact)
    m["corollaire_11"] = dict(tours=B.N_ROUNDS, U=U, max_LAT=L, actives=actives,
                              log2_proba=actives * lg(U / 16), log2_correlation=actives * lg(L / 8))
    c["corollaire_11_128_sbox_actives_a_32_tours"] = B.N_ROUNDS == 32 and actives == 128
    c["corollaire_11_proba_2_moins_256_correlation_2_moins_128"] = (actives * lg(U / 16) == -256
                                                                     and actives * lg(L / 8) == -128)


def kem(c, m):
    taille_publiee = {"Sillage-128": (6285, 9837), "Sillage-256": (21283, 35587)}
    niveau_publie = {"Sillage-128": (138.2, 91.7), "Sillage-256": (265.1, 158.4)}
    params_publies = {"Sillage-128": (50021, 75, 14, 28672), "Sillage-256": (170003, 140, 28, 114688)}
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
    hhm = {"Sillage-128": dict(cor=62.5, M=61, pg_q=59.8, pg_40=69.7, walk_q=43.2),
           "Sillage-256": dict(cor=126.5, M=125, pg_q=104.3, pg_40=136.4, walk_q=84.7)}
    bhh = {"Sillage-128": dict(cpa=60.5, M=123, cor=62.5, rej=126), "Sillage-256": dict(cpa=105.0, M=251, cor=126.5, rej=126)}
    gam = {"Sillage-128": (807, -551), "Sillage-256": (1631, -1119)}
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
    c["hachage_bht_85_bits_et_grover_cle_aead_256"] = (proche((512 - 4 * B.RATE) / 3, 85.3)
                                                       and all(4 * p["key_len"] == 256 for p in B.BRUME512_PROFILES.values()))
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
