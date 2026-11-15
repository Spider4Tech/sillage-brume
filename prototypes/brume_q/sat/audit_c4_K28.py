# -*- coding: utf-8 -*-
"""Audit de la certification C4 ≥ 28 (BRUME-1024q, 4 tours, relaxation tronquée, K = 28) à partir des fichiers de
résultats, sans faire confiance aux bilans des campagnes.

Arbre : feuille (a, b) [compteurs W0, W1] → sous-feuille (a, b, c) [W2] → morceau (a, b, c, d) [W3] → cube
(a, b, c, d, e) [activité au tour 1 des 7 nibbles du voisinage du nibble 0]. Un nœud est PROUVÉ si son unité a rendu
rc=20 avec « lrat_verif VERIFIEE » ET « lrat-check VERIFIED », ou si TOUS ses enfants sont prouvés ET si la coupe qui
les définit est complète (preuve LRAT vérifiée deux fois). On contrôle aussi que les littéraux de chaque enfant sont
exactement ceux du parent plus ceux de sa ligne de chaîne (rien d'ajouté, rien d'oublié).
    python3 audit_c4_K28.py   → bilan, code 0 si C4 ≥ 28 est entièrement certifiée
(C4_DIR : répertoire de travail de la campagne, ~/orion_calc/c4 par défaut ; C4_RES : résultats des unités.)"""
import glob
import os
import re
import sys

C4 = os.path.expanduser(os.environ.get("C4_DIR", "~/orion_calc/c4"))   # cubes, chaînes, complétudes (hors dépôt)
RES = os.environ.get("C4_RES", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                                            "resultats", "hypercompute"))
K = 28


def lignes(f):
    return [l.split() for l in open(f) if l.strip()]


def verifie(texte):
    return "rc=20" in texte and "lrat_verif VERIFIEE" in texte and "lrat-check VERIFIED" in texte


def resultats(dossiers, n):
    """{clé (n entiers) : (prouvé, ligne)} à partir des sortie.txt des unités ; dernière ligne de résultat."""
    r = {}
    for d in dossiers:
        for f in glob.glob(os.path.join(RES, d, "unit-*", "sortie.txt")):
            for l in open(f):
                m = re.match(r"^((?:\d+ ){%d})rc=" % n, l)
                if m:
                    cle = tuple(int(x) for x in m.group(1).split())
                    p = verifie(l)
                    if cle not in r or p:
                        r[cle] = (p, l.strip())
    return r


def chaine(f):
    return {int(l[0]): l[1:] for l in lignes(f)}


def completude(f):
    t = open(f).read()
    return "rc=20" in t and "lrat_verif VERIFIEE" in t and "lrat-check 1" in t


ok = True
# complétudes
comp = {
    "arbre (a, b)": f"{C4}/certif_K28/completude.txt",
    "chaîne W2": f"{C4}/phase2_K28_completude/out/completude_W2.txt",
    "chaîne W3": f"{C4}/phase3_K28_completude/out/completude_W3.txt",
    "coupe P4 (voisinage du nibble 0 au tour 1)": f"{C4}/phase4_K28_completude/out/completude_P4.txt",
}
for nom, f in comp.items():
    c = completude(f)
    ok &= c
    print(f"  {'ok' if c else 'ÉCHEC'} complétude {nom}")
# fichiers de cubes et contrôle des littéraux
feuilles = {(int(l[0]), int(l[1])): l[2:] for l in lignes(f"{C4}/campagne_K28/cubes.txt")}
assert len(feuilles) == (K + 1) ** 2
W2, W3, P4 = chaine(f"{C4}/phase2_K28/chaine_W2.txt"), chaine(f"{C4}/phase3_K28/chaine_W3.txt"), chaine(f"{C4}/phase4_K28/chaine_P4.txt")
assert len(W2) == K + 1 and len(W3) == K + 1 and len(P4) == 128
enfants2 = {tuple(map(int, l[:3])): l[3:] for l in lignes(f"{C4}/phase2_K28/sous_cubes.txt")}
enfants3 = {}
for f in (f"{C4}/phase3_K28/cubes_phase3.txt", f"{C4}/phase3b_K28/cubes_phase3.txt", f"{C4}/phase3c_K28/cubes_phase3.txt"):
    for l in lignes(f):
        enfants3[tuple(map(int, l[:4]))] = l[4:]
enfants4 = {}
for f in (f"{C4}/phase4_K28/cubes_phase4.txt", f"{C4}/phase4c_K28/cubes_phase4.txt"):
    for l in lignes(f):
        enfants4[tuple(map(int, l[:5]))] = l[5:]
lit_ok = all(enfants2[k] == feuilles[k[:2]] + W2[k[2]] for k in enfants2) \
    and all(enfants3[k] == enfants2[k[:3]] + W3[k[3]] for k in enfants3) \
    and all(enfants4[k] == enfants3[k[:4]] + P4[k[4]] for k in enfants4)
ok &= lit_ok
print(f"  {'ok' if lit_ok else 'ÉCHEC'} littéraux : chaque enfant = parent + sa ligne de chaîne "
      f"({len(enfants2)} sous-feuilles, {len(enfants3)} morceaux, {len(enfants4)} cubes)")
# résultats
R2 = resultats(["c4-brume1024-K28", "c4-brume1024-K28-phase1"], 2)
pass1 = {tuple(map(int, l[:2])) for l in lignes(f"{C4}/certif_K28/feuilles_prouvees.txt")}
R3 = resultats(["c4-brume1024-K28-phase2"], 3)
R4 = resultats(["c4-brume1024-K28-phase3", "c4-brume1024-K28-phase3b", "c4-brume1024-K28-phase3c"], 4)
R5 = resultats(["c4-brume1024-K28-phase4-a", "c4-brume1024-K28-phase4-b", "c4-brume1024-K28-phase4c"], 5)
sat = [l for R in (R2, R3, R4, R5) for (_, l) in R.values() if "SATISFIABLE" in l]
ok &= not sat
print(f"  {'ok' if not sat else 'ÉCHEC'} aucune unité SATISFIABLE ({len(sat)})")
compte = {"feuilles directes": 0, "sous-feuilles directes": 0, "morceaux directs": 0, "cubes": 0}


def prouve4(k):
    if R4.get(k, (False,))[0]:
        compte["morceaux directs"] += 1
        return True
    kids = [k + (e,) for e in range(128)]
    if all(c in enfants4 and R5.get(c, (False,))[0] for c in kids):
        compte["cubes"] += 128
        return True
    print(f"    morceau non prouvé : {k} ({R4.get(k, (None, 'aucun résultat'))[1][:80]})")
    return False


def prouve3(k):
    if R3.get(k, (False,))[0]:
        compte["sous-feuilles directes"] += 1
        return True
    kids = [k + (d,) for d in range(K + 1)]
    return all(c in enfants3 for c in kids) and all([prouve4(c) for c in kids])


def prouve2(k):
    if R2.get(k, (False,))[0]:   # la liste de la 1re passe (pass1) doit être couverte par ses résultats relus
        compte["feuilles directes"] += 1
        return True
    kids = [k + (c,) for c in range(K + 1)]
    return all(c in enfants2 for c in kids) and all([prouve3(c) for c in kids])


p1 = all(R2.get(k, (False,))[0] for k in pass1)
ok &= p1
print(f"  {'ok' if p1 else 'ÉCHEC'} les {len(pass1)} feuilles de la 1re passe ont un résultat relu, vérifié deux fois")
tout = all([prouve2(k) for k in sorted(feuilles)])
ok &= tout
print(f"  {'ok' if tout else 'ÉCHEC'} arbre entier : {compte}")
print("C4 ≥ 28 CERTIFIÉE" if ok else "C4 ≥ 28 PAS ENCORE CERTIFIÉE")
sys.exit(0 if ok else 1)
