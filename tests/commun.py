# -*- coding: utf-8 -*-
"""Utilitaires communs aux tests : chemins, sauvegarde, tables S-box."""
import json
import os
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTATS = os.path.join(RACINE, "resultats")
os.makedirs(RESULTATS, exist_ok=True)
if RACINE not in sys.path:
    sys.path.insert(0, RACINE)

try:                                   # figures optionnelles
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

import numpy as np                      # noqa: E402


def sauver(nom: str, obj) -> str:
    """Écrit resultats/<nom>.json et renvoie le chemin."""
    chemin = os.path.join(RESULTATS, nom + ".json")
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, default=_conv)
    return chemin


def _conv(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def tables_sbox(sbox):
    """DDT et LAT (pairing binaire <a,b> = parité(a & b))."""
    s = np.asarray(sbox, dtype=np.uint8)
    X = np.arange(16, dtype=np.uint8)
    ddt = np.zeros((16, 16), dtype=np.int32)
    for a in range(16):
        np.add.at(ddt[a], s[X] ^ s[X ^ a], 1)
    par = np.array([bin(i).count("1") & 1 for i in range(16)])
    lat = np.zeros((16, 16), dtype=np.int32)
    for al in range(16):
        for lam in range(16):
            lat[al, lam] = int((par[al & s] == par[lam & X]).sum()) - 8
    return ddt, lat


def verdict(ok: bool) -> str:
    return "OK" if ok else "ÉCHEC"
