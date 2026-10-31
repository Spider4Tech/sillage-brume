# -*- coding: utf-8 -*-
"""Sillage-KEM — validation empirique de la borne δ (noyau C).

La δ-correction est PROUVÉE par une borne de Chernoff certifiée clé par clé
(borne_echec_log2, docs/PREUVES.md §2.3). Au seuil réel (32·D) elle vaut
≈ 2^-150 : inobservable. On vérifie donc la borne là où on peut la mesurer :
pour une clé validée par keygen, le noyau C simule des dizaines de millions
de bruits de décodage r1·y ⊕ r2·x ⊕ e1 ⊕ π(e2) ; pour chaque seuil t où
l'on observe des événements, la borne généralisée Pr[max ≥ t] (et sa
version par groupe) doit majorer la fréquence mesurée. La simulation est
d'abord recoupée avec de vraies encapsulations du KEM Python.
"""
import math

import numpy as np

from tests import noyau_c as C
from tests.commun import sauver
from sillage.sillage_kem import SillageKEM, rm_decode, borne_echec_log2, histogrammes
from sillage.sillage_common import ring_mul

ESSAIS = {"Sillage-128": (C.taille(23), 100), "Sillage-256": (C.taille(20), 16)}


def positions(v, n):
    b = np.unpackbits(np.frombuffer(v.to_bytes((n + 7) // 8, "little"), np.uint8),
                      bitorder="little")[:n]
    return np.nonzero(b)[0].astype(np.int32)


def queue(h):
    """S[t] = #{≥ t}."""
    return np.cumsum(h[::-1])[::-1]


def run():
    c, m = {}, {}
    C.charger()
    c["noyau_c_conforme"] = C.conformite()[0]
    for lvl, (essais, essais_py) in ESSAIS.items():
        kem = SillageKEM(lvl)
        p = kem.p
        n, n2, k, D = p["n"], p["n2"], p["k"], p["D"]
        d, seuil_echec = 64 * D, 32 * D
        pk, sk = kem.keygen()
        x, y = sk[0], sk[1]
        hmax, hgrp = C.kem_bruit(positions(x, n), positions(y, n), p, essais, 2026)
        hmax, hgrp = hmax.astype(float), hgrp.astype(float)
        t_ = np.arange(d + 1)
        moy_c = float((hmax * t_).sum() / essais)
        var_c = float((hmax * t_ ** 2).sum() / essais - moy_c ** 2)
        # recoupement avec le KEM réel (max des bascules par chiffré)
        reel = []
        for _ in range(essais_py):
            ct, _ss = kem.encaps(pk)
            u, v = ct
            reel.append(rm_decode(v ^ (ring_mul(x, u, n) & ((1 << n2) - 1)), p)[1] + seuil_echec)
        reel = np.array(reel, float)
        z_moy = (reel.mean() - moy_c) / math.sqrt(var_c / essais + reel.var(ddof=1) / len(reel))
        # borne vs fréquence mesurée, pour chaque seuil observable
        Smax, Sgrp = queue(hmax), queue(hgrp)
        lignes, viol_max, viol_grp = [], [], []
        hist = histogrammes(x, y, p)
        for t in range(int(moy_c), seuil_echec + 1):
            if Smax[t] < 10:
                break
            emp = Smax[t] / essais
            # majorant de confiance : la borne doit dépasser la fréquence moins 5 σ
            emp_bas = max(Smax[t] - 5 * math.sqrt(Smax[t]), 0) / essais
            bt = borne_echec_log2(x, y, p, seuil=t, hist=hist)
            if bt < math.log2(emp_bas) if emp_bas > 0 else False:
                viol_max.append(t)
            lignes.append((t, round(math.log2(emp), 2), round(bt, 2)))
        lignes_g = []
        for t in range(int(moy_c * 0.8), seuil_echec + 1):
            if Sgrp[t] < 10:
                break
            emp_bas = max(Sgrp[t] - 5 * math.sqrt(Sgrp[t]), 0) / (essais * (k // 8))
            bt = borne_echec_log2(x, y, p, seuil=t, union=False, hist=hist) + math.log2(254)   # un bloc : 254 hyperplans
            if emp_bas > 0 and bt < math.log2(emp_bas):
                viol_grp.append(t)
            lignes_g.append((t, round(math.log2(Sgrp[t] / (essais * (k // 8))), 2), round(bt, 2)))
        t_haut = lignes[-1] if lignes else None
        m[lvl] = {
            "essais_simules": essais,
            "max_bascules_observe": int(np.nonzero(hmax)[0].max()),
            "seuil_echec": seuil_echec,
            "moyenne_max": {"simulation": round(moy_c, 2), "kem_reel": round(float(reel.mean()), 2),
                            "essais_reels": len(reel), "z": round(z_moy, 2)},
            "queue_log2_mesure_vs_borne": lignes[::max(1, len(lignes) // 12)] + ([t_haut] if t_haut else []),
            "ecart_borne_mesure_bits_au_seuil_le_plus_haut": None if not t_haut else round(t_haut[1] - t_haut[2], 1),
            "queue_par_groupe_log2_mesure_vs_borne": lignes_g[::max(1, len(lignes_g) // 12)] + lignes_g[-1:],
            "ecart_par_groupe_bits_au_seuil_le_plus_haut": None if not lignes_g else round(lignes_g[-1][1] - lignes_g[-1][2], 1),
            "borne_au_seuil_reel_log2": round(borne_echec_log2(x, y, p), 1),
        }
        c[f"{lvl}_simulation_conforme_au_kem_reel"] = bool(abs(z_moy) < 5)
        c[f"{lvl}_borne_majore_la_mesure_max"] = bool(lignes) and not viol_max
        c[f"{lvl}_borne_majore_la_mesure_par_groupe"] = not viol_grp
        c[f"{lvl}_aucun_echec_observe"] = int(np.nonzero(hmax)[0].max()) < seuil_echec
    out = {"controles": c, "mesures": m}
    sauver("c_kem_bruit" + C.SUFFIXE, out)
    return out


if __name__ == "__main__":
    import json
    from tests.commun import _conv
    print(json.dumps(run(), indent=1, ensure_ascii=False, default=_conv))
