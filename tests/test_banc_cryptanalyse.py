# -*- coding: utf-8 -*-
"""Banc historique BRUME : statiques (S-box, graphe, branch numbers ≤ 2),
recherche différentielle/linéaire automatisée (gloutonne, exhaustive poids ≤ 2,
sondes Monte-Carlo), bornes wide-trail — avec l'adjoint binaire exact."""
from tests.commun import sauver
from tests import banc_statiques, banc_trails, banc_wide_trail


def run():
    st = banc_statiques.run()
    tr = banc_trails.run()
    wt = banc_wide_trail.run(st, tr)
    sb, gm, bn = st["sbox"], st["graphe"], st["branch_numbers"]
    ver = wt["verification"]
    emp = ver["empirique_14_rounds"]
    c = {
        "sbox_U_4": sb["U_uniformite_differentielle"] == 4,
        "sbox_NL_4": sb["NL_nonlinearite"] == 4,
        "graphe_ramanujan": bool(gm["lambda_etoile"] < gm["alon_boppana_2sqrt5"]),
        "B1_7_sorties": bn["B1_exact"] == 7,
        "B2_13": bn["B2_exact_min"] == 13,
        "pas_de_cycle_type_v0": bool(ver["pas_de_cycle_iteratif_type_v0"]["pas_de_cycle_type_v0"]),
        "trail_diff_14r_au_dela_de_2^-256": emp["diff_bits"] >= 256,
        "trail_lin_14r_au_dela_de_2^-128": emp["lin_bits"] >= 128,
    }
    out = {"controles": c, "verification_wide_trail": ver,
           "empirique_14_tours_bits": emp}
    sauver("banc_cryptanalyse", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
