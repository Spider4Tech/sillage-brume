# -*- coding: utf-8 -*-
"""BRUME-1024q (v0.6) sous Valgrind (méthode ctgrind) : aucun branchement ni accès mémoire dépendant d'un secret, pas
d'erreur mémoire, témoins détectés.

1. tests/c/ct1024.c (inclut la bibliothèque sillage/c/brume1024.c) : permutation à 1 et 32 états, AEAD (chiffrement,
   déchiffrement, déchiffrement vérifié accepté et rejeté), éponge et arbre, lot bitslicé de 256 feuilles ; secrets
   marqués non définis ; « memoire » : le même calcul sans marquage ; « temoin » : lecture de table à un indice secret.
2. prototypes/brume_q/b1024/controle_portable.c compilé avec -DCTGRIND : le noyau PORTABLE (sans AVX2), état secret ;
   son témoin (lecture indexée) doit être signalé.
Compilation sans VPCLMULQDQ ni AVX-512, que Valgrind ne décode pas (comme tests/test_c_sig_valgrind.py)."""
import os
import shutil
import subprocess

from tests.commun import sauver, RACINE
from tests.test_c_sig_valgrind import valgrind

LIB = os.path.join(RACINE, "sillage", "c")
TC = os.path.join(RACINE, "tests", "c")
PROTO = os.path.join(RACINE, "prototypes", "brume_q", "b1024")
CT = os.path.join(TC, "build", "ct1024")
PORT = os.path.join(TC, "build", "controle_portable_ct")


def construire():
    os.makedirs(os.path.dirname(CT), exist_ok=True)
    obj = CT + "_commun.o"
    fl = ["-O3", "-g", "-mavx2", "-fopenmp", "-DSANS_MAIN", "-DSL_VALGRIND", "-I", LIB, "-I", TC]
    subprocess.run(["gcc", *fl, "-Dsl_alea=sl_alea_systeme", "-c", "-o", obj, os.path.join(LIB, "commun.c")], check=True)
    subprocess.run(["gcc", *fl, "-o", CT, os.path.join(TC, "ct1024.c"), obj, "-lm"], check=True)
    subprocess.run(["gcc", "-O2", "-g", "-DCTGRIND", "-I", PROTO, "-I", LIB, "-o", PORT,
                    os.path.join(PROTO, "controle_portable.c")], check=True)


def run():
    c, m = {}, {}
    if not shutil.which("valgrind"):
        out = {"controles": {"valgrind_disponible": False}, "mesures": {}}
        sauver("c_brume1024_valgrind", out)
        return out
    construire()
    rc, e_mem, sortie, trace = valgrind("memoire", fuites=True, exe=CT)
    m["memoire"] = {"erreurs": e_mem, "sortie": sortie[-400:]}
    c["memoire_sans_erreur_ni_fuite"] = rc == 0 and e_mem == 0 and "secret retrouvé" in sortie
    rc2, e_sec, sortie2, trace2 = valgrind("secret", exe=CT)
    m["secret"] = {"erreurs": e_sec, "sortie": sortie2[-400:]}
    c["aucun_branchement_ni_acces_dependant_d_un_secret_noyaux_avx2_et_modes"] = (rc2 == 0 and e_sec == 0
                                                                                  and "secret retrouvé" in sortie2)
    if e_mem or e_sec:
        m["trace"] = (trace if e_mem else trace2)[-3000:]
    rc3, e_tem, _, _ = valgrind("temoin", exe=CT)
    m["temoin_erreurs"] = e_tem
    c["temoin_acces_indexe_detecte"] = rc3 == 0 and e_tem >= 1
    rc4, e_p, sortie4, trace4 = valgrind("ct", exe=PORT)
    m["portable"] = {"erreurs": e_p, "sortie": sortie4[-300:]}
    c["noyau_portable_aucun_branchement_ni_acces_dependant_de_l_etat"] = rc4 == 0 and e_p == 0
    if e_p:
        m["trace_portable"] = trace4[-3000:]
    rc5, e_pt, _, _ = valgrind("temoin", exe=PORT)
    m["portable_temoin_erreurs"] = e_pt
    c["noyau_portable_temoin_detecte"] = e_pt >= 1
    out = {"controles": c, "mesures": m}
    sauver("c_brume1024_valgrind", out)
    return out


if __name__ == "__main__":
    print(run())
