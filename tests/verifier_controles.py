"""Échoue si un contrôle enregistré dans resultats/<test>.json n'est pas vrai (utilisé par la CI).

Ne lit que la section « controles » : une mesure peut valoir false sans être un échec (par exemple l'absence d'AVX2 en
version portable). Un fichier sans contrôle compte comme un échec.
    python3 -m tests.verifier_controles resultats/a.json resultats/b.json ...
"""
import json
import sys


def main(fichiers):
    echecs = []
    for f in fichiers:
        try:
            controles = json.load(open(f, encoding="utf-8")).get("controles") or {}
        except (OSError, ValueError) as e:
            echecs.append("%s : illisible (%s)" % (f, e))
            continue
        if not controles:
            echecs.append("%s : aucun contrôle" % f)
        echecs += ["%s : %s" % (f, nom) for nom, ok in controles.items() if ok is not True]
    for e in echecs:
        print("ÉCHEC", e)
    print("%d fichier(s), %d échec(s)" % (len(fichiers), len(echecs)))
    return 1 if echecs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
