# -*- coding: utf-8 -*-
"""Modèle en portes et catégories NIST (tests/modele_portes.py, docs/NIST_CATEGORIES.md).

Contrôles d'intégrité du modèle, pas des objectifs de niveau (les catégories obtenues sont des mesures) :
1. le circuit de la S-box lu dans brume1024_portable.h a 17 portes (10 non linéaires, 7 XOR) ;
2. le Keccak quantique du modèle compte moins de portes T qu'Amy et al. (SAC 2016) par itération : il favorise l'attaquant ;
3. les quatre profils VOLE sont lus dans sillage/c/vole.c, avec m = cod + 12·w (μ = (4, 4, 4, 4)) ;
4. la formule de Grover sous MAXDEPTH redonne le seuil NIST 2^170/MAXDEPTH d'AES-128 pour un oracle de g·d = 2^42 ;
5. des seuils plus bas (JNRV 2020) ne baissent jamais une catégorie ; un profil 256 n'est jamais sous son profil 128."""
from tests.commun import sauver
from tests import modele_portes as M


def run():
    c, m = {}, {}
    nl, xr, prof = M.sbox_brume()
    c["sbox_lue_17_portes_10_non_lineaires"] = (nl, xr) == (10, 7)
    m["sbox"] = dict(non_lineaires=nl, xor=xr, profondeur_non_lineaire=prof)

    t_modele = M.LOG(2 * M.KECCAK_TOURS * 1600 * 7)
    c["keccak_t_du_modele_sous_amy_et_al"] = t_modele <= M.AMY_T_PAR_ITERATION
    m["keccak_t"] = dict(modele=round(t_modele, 2), amy_et_al=round(M.AMY_T_PAR_ITERATION, 2))

    pv = M.profils_vole()
    c["profils_vole_lus"] = sorted(pv) == ["VOLE-128", "VOLE-128f", "VOLE-256", "VOLE-256f"] and all(
        p["m"] == p["cod"] + 12 * p["w"] and p["lam"] in (128, 256) for p in pv.values())

    # AES-128 : N = 2^128, oracle g·d = 2^42 (g = 2^25, d = 2^17), régime parallèle pour MD = 2^40 et 2^64
    c["grover_redonne_le_seuil_aes128"] = all(abs(M.grover(128, 25, 17, md) - (170 - md)) < 1e-9 for md in (40, 64))

    out_m = M.run()
    comp = out_m["composants"]
    ok_jnrv = all(isinstance(v["categorie"], dict) and v["categorie"]["JNRV 2020"] >= v["categorie"]["NIST 2016"]
                  for v in comp.values())
    c["seuils_jnrv_ne_baissent_aucune_categorie"] = ok_jnrv
    paires = [("Sillage-128", "Sillage-256"), ("VOLE-128", "VOLE-256"), ("VOLE-128f", "VOLE-256f")]
    c["profil_256_jamais_sous_le_profil_128"] = all(
        comp[b]["categorie"][s] >= comp[a]["categorie"][s] for a, b in paires for s in M.QUANTIQUE)
    m["elements"] = out_m["elements"]
    m["categories"] = {nom: v["categorie"] for nom, v in comp.items()}
    m["bits_manquants"] = {nom: v["bits_manquants"] for nom, v in comp.items()}
    m["classique_log2"] = {nom: v["classique_log2"] for nom, v in comp.items()}
    m["quantique_par_maxdepth"] = {nom: v.get("quantique_par_maxdepth") for nom, v in comp.items()}
    out = {"controles": c, "mesures": m}
    sauver("modele_portes", out)
    return out


if __name__ == "__main__":
    import json
    r = run()
    print(json.dumps(r["controles"], ensure_ascii=False, indent=1))
    print(json.dumps(r["mesures"]["categories"], ensure_ascii=False, indent=1))
