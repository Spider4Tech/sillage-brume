# -*- coding: utf-8 -*-
"""BRUME-1024q (v0.6) : certificats de la borne sur les caractéristiques (C4 ≥ 28, donc ≥ 224 S-box actives sur 32 tours).

prototypes/brume_q/sat/audit_c4_K28.py relit tout l'arbre de découpage depuis le paquet prototypes/brume_q/sat/c4_K28/
(découpages, CNF de complétude, résultats des 1 599 feuilles vérifiées par deux vérificateurs LRAT) et ne conclut que si
chaque feuille est prouvée et chaque coupe complète. Avec SILLAGE_INTENSITE ≥ 2, il refait aussi des preuves
(--reprouver, CaDiCaL et les deux vérificateurs requis)."""
import os
import shutil

from tests.commun import sauver
from tests.b1024_outils import lancer

INTENSITE = float(os.environ.get("SILLAGE_INTENSITE", "1"))


def run():
    c, m = {}, {}
    rc, out = lancer(["python3", "prototypes/brume_q/sat/audit_c4_K28.py"], timeout=3600)
    m["audit"] = out.strip().splitlines()[-4:]
    c["c4_28_certifiee_arbre_complet_relu"] = rc == 0 and "C4 ≥ 28 CERTIFIÉE" in out
    if INTENSITE >= 2 and shutil.which("cadical"):
        rc2, out2 = lancer(["python3", "prototypes/brume_q/sat/audit_c4_K28.py", "--reprouver", "3"], timeout=6 * 3600)
        m["reprouve"] = out2.strip().splitlines()[-4:]
        c["c4_28_preuves_refaites"] = rc2 == 0 and "C4 ≥ 28 CERTIFIÉE" in out2
    out = {"controles": c, "mesures": m}
    sauver("b1024_certificats", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
