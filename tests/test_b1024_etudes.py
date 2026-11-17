# -*- coding: utf-8 -*-
"""BRUME-1024q (v0.6) : contrôles des outils des études de cryptanalyse du 17 novembre (docs/brume1024/ALGEBRIQUE.md,
REBOND.md, DIFF_LIN.md). Les campagnes elles-mêmes (heures de calcul) ne sont pas rejouées : leurs résultats sont écrits
dans les études ; ici, on vérifie que les outils qui les ont produits sont justes.

1. algebrique1024.py controle : encodage CNF de P_R (instances tout fixé satisfaisables, un bit inversé
   insatisfaisable, force brute à v = 16 conforme, CryptoMiniSat et CaDiCaL d'accord, solutions revérifiées).
2. rebond1024.py controle : modèle à nibbles du rebond (référence de départ redonnée, chemins réalisables sur GF(16),
   capacité refusée aux deux bouts, coût recalculé par le rang hors du solveur).
3. dl_verif.c : à 4 tours, les 32 nibbles hors de la boule de rayon 4 ont une différence nulle (ε = 1 sur les 15
   masques) pour chaque δ ; un biais planté à 5 tours est détecté (ε ≈ 1/2)."""
import json

from tests.commun import sauver
from tests.b1024_outils import compiler, lancer

V = "prototypes/brume_q/b1024/"


def run():
    c, m = {}, {}
    rc, out = lancer(["python3", V + "algebrique1024.py", "controle"], timeout=3600)
    m["algebrique"] = out.strip().splitlines()[-2:]
    c["algebrique_encodage_et_solveurs_controles"] = rc == 0 and "tous les contrôles passent" in out
    rc, out = lancer(["python3", V + "rebond1024.py", "controle"], timeout=3 * 3600)
    m["rebond"] = out.strip().splitlines()[-3:]
    c["rebond_modele_et_realisabilite_controles"] = rc == 0 and "Traceback" not in out and "ECHEC" not in out
    exe = compiler("dl_verif", "dl_verif.c")
    rc, out = lancer([exe, "4", "20", "1", "0xD1D1", "0"], timeout=3600)
    try:
        d = json.loads(out[out.index("{"):].splitlines()[0])
        m["dl_r4"] = {k: d[k] for k in ("nibbles_toujours_nuls", "nb_significatives", "cases")}
        c["dl_4_tours_nibbles_hors_boule_nuls_pour_chaque_delta"] = rc == 0 and d["nibbles_toujours_nuls"] == 15 * 32
    except (ValueError, KeyError):
        c["dl_4_tours_execution"] = False
    rc, out = lancer([exe, "5", "18", "1", "0xD1D1", "1"], timeout=3600)
    try:
        d = json.loads(out[out.index("{"):].splitlines()[0])
        m["dl_temoin_r5"] = {k: d[k] for k in ("nb_significatives", "eps_max", "z_max")}
        c["dl_temoin_biais_plante_detecte"] = rc == 0 and d["nb_significatives"] >= 1 and abs(d["eps_max"]) > 0.4
    except (ValueError, KeyError):
        c["dl_temoin_execution"] = False
    out = {"controles": c, "mesures": m}
    sauver("b1024_etudes", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
