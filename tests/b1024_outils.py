# -*- coding: utf-8 -*-
"""Outils communs aux tests de BRUME-1024q (v0.6) qui lancent les programmes d'analyse de prototypes/brume_q/b1024/.

Ces programmes incluent la bibliothèque elle-même (prototypes/brume_q/b1024/brume1024.c renvoie à tests/c/brume1024.c,
qui inclut sillage/c/brume1024.c) : ce qu'ils mesurent est donc la fonction de la bibliothèque."""
import os
import subprocess
import sys

from tests.commun import RACINE

LIB = os.path.join(RACINE, "sillage", "c")
TC = os.path.join(RACINE, "tests", "c")
PROTO = os.path.join(RACINE, "prototypes", "brume_q", "b1024")
SAT = os.path.join(RACINE, "prototypes", "brume_q", "sat")
BUILD = os.path.join(TC, "build")
DOC = os.path.join(RACINE, "docs", "brume1024")


def compiler(nom, source, *extra, sans_main=True, flags=("-O3", "-march=native", "-fopenmp")):
    """Compile source (chemin relatif à PROTO ou absolu) avec la bibliothèque ; rend le chemin de l'exécutable."""
    os.makedirs(BUILD, exist_ok=True)
    exe = os.path.join(BUILD, nom)
    src = source if os.path.isabs(source) else os.path.join(PROTO, source)
    cmd = ["gcc", *flags, *(["-DSANS_MAIN"] if sans_main else []), "-I", LIB, "-I", TC, "-I", PROTO, "-o", exe, src,
           os.path.join(LIB, "commun.c"), *extra, "-lm"]
    subprocess.run(cmd, check=True, cwd=RACINE)
    return exe


def lancer(cmd, timeout=3600, env=None):
    """(code de retour, sortie standard + erreur) ; une commande Python passe par l'interpréteur courant."""
    if cmd[0] == "python3":
        cmd = [sys.executable] + list(cmd[1:])
    r = subprocess.run(cmd, cwd=RACINE, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, **(env or {})})
    return r.returncode, r.stdout + r.stderr
