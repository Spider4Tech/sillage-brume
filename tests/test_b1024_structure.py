# -*- coding: utf-8 -*-
"""BRUME-1024q (v0.6) : structure et agrégation (cryptanalyse de niveau 1 et 2, docs/brume1024/README.md § 3).

1. prototypes/brume_q/b1024/structure1024.py (11 contrôles, chacun éprouvé sur un témoin où la propriété existe) :
   Frobenius, invariants non linéaires de nibbles, sous-espaces invariants, polynôme minimal de M, quasi-symétries.
2. invariants_quad1024.c « controle » : invariants quadratiques locaux (14 848 inconnues) de chaque tour, témoins
   (identité, constantes seules, S-box seule) retrouvés.
3. agregation2.c : à 2 tours, max DP = 2^−16 et max corrélation² (hull) = 2^−7,83, sommes exactes, confirmées par
   échantillonnage (docs/brume1024/SPEC.md § 5)."""
import json
import os

from tests.commun import sauver, RESULTATS
from tests.b1024_outils import compiler, lancer


def run():
    c, m = {}, {}
    rc, out = lancer(["python3", "prototypes/brume_q/b1024/structure1024.py"], timeout=3600)
    try:
        s = json.load(open(os.path.join(RESULTATS, "structure_1024q.json")))
        for k, v in s["controles"].items():
            c[f"structure_{k}"] = v is True
        m["structure"] = s.get("mesures", {})
    except (OSError, KeyError, ValueError):
        c["structure_execution"] = False
    c["structure_execution_sans_erreur"] = rc == 0
    exe = compiler("invariants_quad1024", "invariants_quad1024.c")
    rc2, out2 = lancer([exe, "controle"], timeout=3600)
    m["invariants_quadratiques"] = out2.strip().splitlines()[-4:]
    c["invariants_quadratiques_locaux_aucun_temoins_retrouves"] = rc2 == 0 and "tous les contrôles passent" in out2
    exe = compiler("agregation2", "agregation2.c")
    rc3, out3 = lancer([exe, "24"], timeout=3600)
    try:
        a = json.loads(out3[out3.index("{"):])
        d, l = a["differentielle"], a["lineaire"]
        m["agregation2"] = {"dp_log2": d["log2"], "hull_log2": l["log2"], "trail_log2": l["log2_trail"]}
        c["agregation_2_tours_max_dp_2_moins_16"] = rc3 == 0 and abs(d["log2"] + 16) < 1e-3 and abs(d["log2_car"] + 16) < 1e-3
        c["agregation_2_tours_hull_2_moins_7_83_trail_2_moins_8"] = abs(l["log2"] + 7.83) < 0.01 and abs(l["log2_trail"] + 8) < 1e-3
    except (ValueError, KeyError):
        c["agregation_2_tours_execution"] = False
    out = {"controles": c, "mesures": m}
    sauver("b1024_structure", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
