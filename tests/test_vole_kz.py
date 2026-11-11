# -*- coding: utf-8 -*-
"""Sillage-SIG v0.5 : la stratégie de Kales–Zaverucha transposée aux trois tours de VOLE (γ puis Δ), exécutée contre le
vrai vérifieur sur une instance intermédiaire (prototypes/vole/vole_proto.c --kz, profil PRKZ : blocs de 256, GF(2^128),
τκ = 16, γ dans un sous-groupe de 2^12 éléments). Quatre budgets (q₂, q₃) : chaque falsification annoncée est acceptée et
chaque échec rejeté ; la fréquence est dans l'IC à 99,9 % de la prédiction exacte et pas au-dessus de la borne du
Théorème 17. SILLAGE_VOLE_KZ fixe le nombre d'essais par budget (300 par défaut ; campagne : 10 000)."""
import json
import os
import subprocess

from tests.commun import RACINE, RESULTATS

N = os.environ.get("SILLAGE_VOLE_KZ", "300")


def run():
    subprocess.run(["make", "-s", "-C", os.path.join(RACINE, "tests", "c"), "build/vole_proto"], check=True)
    subprocess.run([os.path.join(RACINE, "tests", "c", "build", "vole_proto"), "--kz", N], cwd=RACINE)
    return json.load(open(os.path.join(RESULTATS, "vole_kz.json")))


if __name__ == "__main__":
    print(run()["controles"])
