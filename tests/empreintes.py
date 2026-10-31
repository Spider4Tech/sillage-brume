# -*- coding: utf-8 -*-
"""Empreintes SHA-256 des sources, des tables, des KAT et des résultats
(reproductibilité, audit externe point 10) → resultats/EMPREINTES.md.

À lancer après `python3 -m tests.run_all` : les empreintes des résultats
désignent alors cette exécution. Un tiers qui rejoue la batterie compare
d'abord les sources (mêmes empreintes), puis les contrôles de
resultats/synthese.json ; les mesures statistiques et les temps varient
d'une exécution à l'autre, les KAT et les certificats non.
    python3 -m tests.empreintes
"""
import glob
import hashlib
import json
import os
import platform
import subprocess

from tests.commun import RACINE, RESULTATS

GROUPES = [
    ("Sources Python", ["sillage/*.py"]),
    ("Sources C et en-têtes générés", ["sillage/c/*.c", "sillage/c/*.h", "sillage/c/Makefile"]),
    ("Tests", ["tests/*.py", "tests/c/*.c", "tests/c/*.h", "tests/c/Makefile"]),
    ("Certificats (pistes de division property)", ["resultats/pistes_division.json",
                                                   "resultats/pistes_exactes.json"]),
    ("Résultats de la batterie", ["resultats/*.json", "resultats/SYNTHESE.md"]),
    ("Preuves et rapports", ["docs/*.md"]),
]
EXCLUS = {"resultats/pistes_division.json", "resultats/pistes_exactes.json"}


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def kat():
    from sillage import brume512_hash, brume512_hash_arbre, Brume512, Brume512P
    k = bytes(range(64))
    n = bytes(range(24))
    c, t = Brume512("BRUME-512", key=k).encrypt(n, b"SILLAGE", aad=b"kat")
    cp, tp = Brume512P("BRUME-512p", key=k).encrypt(n, b"SILLAGE", aad=b"kat")
    return {
        "brume512_hash(b'abc', 32)": brume512_hash(b"abc").hex(),
        "brume512_hash_arbre(b'abc', 32)": brume512_hash_arbre(b"abc").hex(),
        "BRUME-512 AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')": (c + t).hex(),
        "BRUME-512p AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')": (cp + tp).hex(),
    }


def main():
    lignes = ["# Empreintes SHA-256 — SILLAGE v0.4", ""]
    try:
        syn = json.load(open(os.path.join(RESULTATS, "synthese.json")))
        ok = sum(sum(v["controles"].values()) for v in syn.values())
        tot = sum(len(v["controles"]) for v in syn.values())
        lignes.append(f"Batterie : {ok}/{tot} contrôles, {len(syn)} tests.")
    except (OSError, KeyError, ValueError):
        pass
    gcc = subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    lignes += [f"Python {platform.python_version()}, {gcc}.", "", "## KAT", "", "| Entrée | Sortie |",
               "|---|---|"]
    lignes += [f"| `{e}` | `{s}` |" for e, s in kat().items()]
    for titre, motifs in GROUPES:
        fichiers = sorted({os.path.relpath(f, RACINE) for m in motifs for f in glob.glob(os.path.join(RACINE, m))})
        if titre == "Résultats de la batterie":
            fichiers = [f for f in fichiers if f not in EXCLUS]
        lignes += ["", f"## {titre}", "", "| Fichier | SHA-256 |", "|---|---|"]
        lignes += [f"| `{f}` | `{sha(os.path.join(RACINE, f))}` |" for f in fichiers]
    with open(os.path.join(RESULTATS, "EMPREINTES.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lignes) + "\n")
    print(f"{sum(1 for l in lignes if l.startswith('| `'))} empreintes → resultats/EMPREINTES.md")


if __name__ == "__main__":
    main()
