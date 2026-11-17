# -*- coding: utf-8 -*-
"""BRUME-1024q (v0.6) : batterie statistique de la suite portée en C (prototypes/brume_q/b1024/stats1024.c) : flux en
mode compteur et XOF sur P₃₂, tours réduits (distingués jusqu'à 4, pas à 5), critère d'avalanche strict en direct et en
inverse, témoins (biais et corrélation plantés, détectés ; splitmix64 conforme), inverse rapide égale à l'inverse dense."""
import json
import os
import tempfile

from tests.commun import sauver
from tests.b1024_outils import compiler, lancer

INTENSITE = float(os.environ.get("SILLAGE_INTENSITE", "1"))


def run():
    c, m = {}, {}
    exe = compiler("stats1024", "stats1024.c")
    mio = str(int(64 * INTENSITE))
    with tempfile.TemporaryDirectory() as d:
        sortie = os.path.join(d, "stats.json")
        rc, out = lancer([exe, mio, sortie], timeout=4 * 3600)
        try:
            s = json.load(open(sortie))
        except (OSError, ValueError):
            s = {}
    m["mio"] = int(mio)
    m["verdict"] = s.get("verdict")
    m["dernier_tour_distingue_par_les_flux"] = s.get("dernier_tour_distingue_par_les_flux")
    m["duree_s"] = s.get("duree_s")
    m["fin"] = out.strip().splitlines()[-3:]
    c["execution_sans_erreur"] = rc == 0 and bool(s)
    c["temoins_detectes_et_reference_conforme"] = s.get("temoins_conformes") is True
    c["inverse_rapide_egale_a_l_inverse_dense"] = s.get("inverse_rapide_conforme") is True
    c["p32_flux_et_avalanche_conformes"] = s.get("verdict") == "conforme"
    out = {"controles": c, "mesures": m}
    sauver("b1024_statistiques", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
