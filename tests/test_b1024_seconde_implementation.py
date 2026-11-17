# -*- coding: utf-8 -*-
"""BRUME-1024q (v0.6) : la spécification suffit, les tables sont celles qu'on croit.

1. Seconde implémentation (prototypes/brume_q/b1024/spec_ref.c), écrite d'après docs/brume1024/SPEC.md seul, en C
   portable : elle redonne les 23 vecteurs de docs/brume1024/kat_b1024.txt.
2. Les vecteurs texte (docs/brume1024/kat_b1024.txt) et l'en-tête de la batterie (tests/c/kat_b1024.h) sont les mêmes.
3. Le générateur des tables (prototypes/brume_q/b1024/gen_b1024.c : recherche de M, contrôles de branchement, constantes)
   redonne exactement sillage/c/brume1024_tables.h et brume1024_lot.h, et ses propres contrôles passent.
4. Le noyau portable, comparé à une référence dense écrite à part (prototypes/brume_q/b1024/controle_portable.c, matrice
   explicite et S-box par table), pour 1 à 48 tours.
Témoin : un vecteur altéré dans une copie du fichier de KAT est signalé par la seconde implémentation."""
import os
import re
import tempfile

from tests.commun import sauver, RACINE
from tests.b1024_outils import LIB, PROTO, DOC, BUILD, TC, compiler, lancer


def _kat_texte(chemin):
    return dict(l.split() for l in open(chemin) if l.strip() and not l.startswith("#"))


def _kat_entete():
    t = open(os.path.join(TC, "kat_b1024.h"), encoding="utf-8").read()
    return dict(re.findall(r'\{"([a-z0-9_]+)",\s*"([0-9a-f]*)"\}', t))


def run():
    c, m = {}, {}
    exe = compiler("spec_ref", "spec_ref.c", sans_main=False, flags=("-O2", "-march=native"))
    kat = os.path.join(DOC, "kat_b1024.txt")
    rc, out = lancer([exe, kat], timeout=900)
    m["seconde_implementation"] = out.strip().splitlines()[-1] if out.strip() else ""
    c["seconde_implementation_redonne_les_23_kat"] = rc == 0 and "23 vecteurs conformes, 0 différents" in out
    with tempfile.TemporaryDirectory() as d:
        faux = os.path.join(d, "kat.txt")
        lignes = open(kat).read().splitlines()
        i = next(k for k, l in enumerate(lignes) if l.startswith("aead_64 "))
        nom, val = lignes[i].split()
        lignes[i] = f"{nom} {val[:-1]}{'0' if val[-1] != '0' else '1'}"
        open(faux, "w").write("\n".join(lignes) + "\n")
        rc2, out2 = lancer([exe, faux], timeout=900)
    c["temoin_kat_altere_signale"] = rc2 != 0 and "1 différents" in out2
    kt, kh = _kat_texte(kat), _kat_entete()
    m["kat"] = len(kt)
    c["kat_texte_et_entete_identiques"] = len(kt) == 23 and kt == kh
    gen = os.path.join(BUILD, "gen_b1024")
    hist = os.path.join(RACINE, "tests", "historique_v05")
    import subprocess
    subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-I", LIB, "-I", os.path.join(hist, "c_tests"), "-I",
                    os.path.join(hist, "c"), "-o", gen, os.path.join(PROTO, "gen_b1024.c"), os.path.join(LIB, "commun.c"),
                    os.path.join(LIB, "brume1024.c"), "-lm"], check=True, cwd=RACINE)
    with tempfile.TemporaryDirectory() as d:
        t, l = os.path.join(d, "t.h"), os.path.join(d, "l.h")
        rc3, out3 = lancer([gen, t, l], timeout=1800)
        lib_t = open(os.path.join(LIB, "brume1024_tables.h")).read()
        corps = lambda s: s[s.index("#define B1_N"):]
        gt = corps(open(t).read()).rstrip().rsplit("#endif", 1)[0].rstrip()
        lt = corps(lib_t).rsplit("\n/* S-box (SPEC", 1)[0].rstrip()
        same_t = gt == lt
        same_l = open(l).read().split("\n", 1)[1] == open(os.path.join(LIB, "brume1024_lot.h")).read().split("\n", 1)[1]
    m["generateur"] = out3.strip().splitlines()[-1] if out3.strip() else ""
    c["generateur_controles_passent"] = rc3 == 0 and "gen_b1024 OK" in out3
    c["generateur_redonne_les_tables_de_la_bibliotheque"] = same_t and same_l
    cp = compiler("controle_portable", "controle_portable.c", sans_main=False, flags=("-O2",))
    rc4, out4 = lancer([cp], timeout=900)
    m["portable"] = out4.strip().splitlines()[-1] if out4.strip() else ""
    c["noyau_portable_egal_a_une_reference_dense_independante_1_a_48_tours"] = rc4 == 0 and "tous identiques" in out4
    out = {"controles": c, "mesures": m}
    sauver("b1024_seconde_implementation", out)
    return out


if __name__ == "__main__":
    print(run())
