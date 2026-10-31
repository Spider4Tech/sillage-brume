# -*- coding: utf-8 -*-
"""Temps constant, mesuré (méthode « dudect », tests/c/temps.c).

Pour chaque opération : entrée fixe contre entrées aléatoires, classes
entrelacées, entrées préparées avant les mesures, test t de Welch.
|t| ≥ 4,5 signale une fuite probable (seuil de dudect) ; en cas de
dépassement, une seconde mesure (deux fois plus longue) tranche.
  - permutation (AVX2), AEAD : clé et clair secrets ;
  - kem_oracle : même clé, réserves de chiffrés honnêtes et de chiffrés qui font
    échouer le décodage — l'oracle des attaques par réaction (avant correction :
    ré-encapsulation sautée, puis rejet à durée variable) ;
  - kem_oracle_fo : chiffré honnête ou à un bit inversé (rejet à la comparaison FO) ;
  - kem_decaps : clé fixe contre clés différentes de même σ_h, mêmes chiffrés
    dans les deux classes — dépendance à la clé secrète seule ;
  - kem_encaps : encapsulation, μ secret fixe contre aléatoire ;
  - kem_aa : mêmes données dans les deux classes, biais du banc ;
  - sig_tour : simulation d'un côté de l'hypercube, part fixe contre aléatoire ;
  - sig_sign : signature complète, clé fixe contre clés aléatoires ;
  - kem256_decaps, kem256_oracle : Sillage-256 (autre taille de feuille de Karatsuba) ;
  - sig_sign sur tous les cœurs : les tours de la signature y sont répartis ;
  - conformité (tests/c/sig_ct.c) : corps, évaluation de Lagrange et H'·x_A masqué
    donnent les mêmes valeurs que les chemins directs ;
  - témoins indicatifs (sans contrôle) : la permutation de référence par
    tables (fuite observée de t ≈ 12 à 95, selon l'entrée fixe tirée) et
    le chemin direct du signataire, sig_tour_ref (colonnes et points sautés selon les bits).
Un test statistique ne prouve pas l'absence de fuite ; il en détecte.
"""
import json
import os
import subprocess

from tests.commun import RACINE, sauver

ICI = os.path.join(RACINE, "sillage", "c")
SRC = ["commun.c", "brume512.c", "brume512_avx2.c"]     # kem.c et sig.c sont inclus par temps.c
SEUIL = 4.5


def construire():
    exe = os.path.join(RACINE, "tests", "c", "build", "temps")
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-I", ICI, "-o", exe,
                    os.path.join(RACINE, "tests", "c", "temps.c")] + [os.path.join(ICI, s) for s in SRC] + ["-lm"],
                   check=True)
    return exe


def conformite_sig(essais=300):
    exe = os.path.join(RACINE, "tests", "c", "build", "sig_ct")
    subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-I", ICI, "-o", exe,
                    os.path.join(RACINE, "tests", "c", "sig_ct.c")] + [os.path.join(ICI, s) for s in SRC] + ["-lm"],
                   check=True)
    r = subprocess.run([exe, str(essais)], capture_output=True, text=True)
    return r.returncode == 0, json.loads(r.stdout)


def mesurer(exe, op, n, threads=1):
    return json.loads(subprocess.run([exe, op, str(n)], capture_output=True, text=True, check=True,
                                     env={**os.environ, "OMP_NUM_THREADS": str(threads)}).stdout)


def run():
    c, m = {}, {}
    exe = construire()
    for op, n in (("permutation", 400000), ("aead", 400000), ("aead_p", 4000), ("kem_oracle", 20000),
                  ("kem_oracle_fo", 20000), ("kem_encaps", 20000), ("kem_aa", 20000),
                  ("permutation_ref", 200000), ("kem_decaps", 10000), ("sig_tour", 20000),
                  ("sig_tour_ref", 20000), ("sig_sign", 400), ("kem256_decaps", 3000),
                  ("kem256_oracle", 3000), ("sig_sign@tous", 800)):
        op, _, th = op.partition("@")                 # @tous : tours répartis sur tous les cœurs
        th = os.cpu_count() if th else 1
        cle = op + "_tous_les_coeurs" if th > 1 else op
        r = mesurer(exe, op, n, th)
        if abs(r["t_welch"]) >= SEUIL and not op.endswith("_ref"):
            r2 = mesurer(exe, op, 2 * n, th)
            r = {**r2, "premiere_mesure_t": r["t_welch"]}
        r.pop("x", None)
        m[cle] = r
    c["permutation_avx2_sans_fuite_detectee"] = abs(m["permutation"]["t_welch"]) < SEUIL
    c["aead_sans_fuite_detectee"] = abs(m["aead"]["t_welch"]) < SEUIL
    c["kem_pas_d_oracle_d_echec_de_decodage"] = abs(m["kem_oracle"]["t_welch"]) < SEUIL
    c["kem_pas_d_oracle_a_la_comparaison_fo"] = abs(m["kem_oracle_fo"]["t_welch"]) < SEUIL
    c["kem_decaps_independante_de_la_cle_secrete"] = abs(m["kem_decaps"]["t_welch"]) < SEUIL
    c["kem_encaps_independante_de_mu"] = abs(m["kem_encaps"]["t_welch"]) < SEUIL
    c["kem_banc_sans_biais"] = abs(m["kem_aa"]["t_welch"]) < SEUIL
    c["sig_signataire_sans_fuite_detectee"] = abs(m["sig_tour"]["t_welch"]) < SEUIL
    c["sig_signature_independante_de_la_cle_secrete"] = abs(m["sig_sign"]["t_welch"]) < SEUIL
    c["kem256_decaps_independante_de_la_cle_secrete"] = abs(m["kem256_decaps"]["t_welch"]) < SEUIL
    c["kem256_pas_d_oracle_d_echec_de_decodage"] = abs(m["kem256_oracle"]["t_welch"]) < SEUIL
    c["sig_signature_tous_les_coeurs_independante_de_la_cle"] = abs(m["sig_sign_tous_les_coeurs"]["t_welch"]) < SEUIL
    ok, m["sig_conformite"] = conformite_sig()
    c["sig_chemins_constant_time_conformes"] = ok
    out = {"controles": c, "mesures": m}
    sauver("c_temps", out)
    return out


if __name__ == "__main__":
    r = run()
    print(json.dumps(r, indent=1, ensure_ascii=False))
