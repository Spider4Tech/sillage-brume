# -*- coding: utf-8 -*-
"""Audit de la certification C4 ≥ 28 (BRUME-1024q, 4 tours, relaxation tronquée, K = 28) à partir du paquet de
reproduction `c4_K28/` (listes de découpage, CNF de complétude, lignes de résultat de chaque unité), sans faire
confiance aux bilans des campagnes.

Arbre : feuille (a, b) [compteurs W0, W1] → sous-feuille (a, b, c) [W2] → morceau (a, b, c, d) [W3] → cube
(a, b, c, d, e) [activité au tour 1 des 7 nibbles du voisinage du nibble 0]. Un nœud est PROUVÉ si son unité a rendu
rc=20 avec « lrat_verif VERIFIEE » ET « lrat-check VERIFIED », ou si TOUS ses enfants sont prouvés ET si la coupe qui
les définit est complète. On contrôle aussi :
  - que les littéraux de chaque enfant sont exactement ceux du parent plus ceux de sa ligne de chaîne ;
  - que chaque CNF de complétude est EXACTEMENT la conjonction des négations des lignes de sa coupe (reconstruite ici),
    et qu'elle a été prouvée insatisfiable (rc=20, deux vérificateurs) ;
  - avec --reprouver [n] : on REFAIT les 4 preuves de complétude et n feuilles tirées au hasard à chaque niveau
    (CaDiCaL + lrat_verif + lrat-check, chemins dans CADICAL, LRAT_VERIF, LRAT_CHECK), sur la CNF de base régénérée par
    c3_cnf1024 (C3BIN) dont l'empreinte SHA-256 doit être celle de la campagne. Cela ne dépend plus des marqueurs
    textuels des sorties, seulement des outils relancés.

    python3 audit_c4_K28.py                 → bilan, code 0 si C4 ≥ 28 est entièrement certifiée
    python3 audit_c4_K28.py --reprouver 5   → idem, plus les preuves refaites (quelques minutes pour les feuilles faciles,
                                              beaucoup plus si le tirage tombe sur une feuille dure)
Variables : C4_DIR (paquet, défaut c4_K28/ à côté de ce fichier), C4_RES (lignes de résultat, défaut C4_DIR/res)."""
import glob
import hashlib
import os
import random
import re
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
C4 = os.path.expanduser(os.environ.get("C4_DIR", os.path.join(ICI, "c4_K28")))
RES = os.path.expanduser(os.environ.get("C4_RES", os.path.join(C4, "res")))
K = 28
SHA_BASE = "625527dae20db75909994a9a4f4284f9e99e6a491e806f45f7a37a1bc9709b81"   # c3_cnf1024 cnf diff 4 28


def lignes(f):
    return [l.split() for l in open(f) if l.strip()]


def verifie(texte):
    return "rc=20" in texte and "lrat_verif VERIFIEE" in texte and "lrat-check VERIFIED" in texte


def resultats(campagnes, n):
    """{clé (n entiers) : (prouvé, ligne)} : lignes de résultat des unités, soit res/<campagne>.txt (paquet), soit
    <campagne>/unit-*/sortie.txt (sortie brute de HyperCompute). Un résultat prouvé l'emporte."""
    r = {}
    for c in campagnes:
        fichiers = glob.glob(os.path.join(RES, c + ".txt")) + glob.glob(os.path.join(RES, c, "unit-*", "sortie.txt"))
        for f in fichiers:
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


def cnf_clauses(f):
    nv = nc = None
    cl = []
    for l in open(f):
        if l.startswith("c") or not l.strip():
            continue
        if l.startswith("p cnf"):
            _, _, nv, nc = l.split()
            continue
        x = [int(t) for t in l.split()]
        assert x[-1] == 0
        cl.append(tuple(sorted(x[:-1])))
    return int(nv), int(nc), cl


def completude_conforme(cnf, coupe):
    """La CNF de complétude est exactement ∧ ¬(ligne) sur les lignes de la coupe (même nombre, mêmes clauses)."""
    _, nc, cl = cnf_clauses(cnf)
    attendu = sorted(tuple(sorted(-int(x) for x in lits)) for lits in coupe)
    return nc == len(cl) == len(attendu) and sorted(cl) == attendu


def completude_prouvee(f):
    t = open(f).read()
    return "rc=20" in t and "lrat_verif VERIFIEE" in t and "lrat-check 1" in t


ok = True
# ---------------------------------------------------------------- listes de découpage
feuilles = {(int(l[0]), int(l[1])): l[2:] for l in lignes(f"{C4}/cubes.txt")}
assert len(feuilles) == (K + 1) ** 2
W2, W3, P4 = chaine(f"{C4}/chaine_W2.txt"), chaine(f"{C4}/chaine_W3.txt"), chaine(f"{C4}/chaine_P4.txt")
assert len(W2) == K + 1 and len(W3) == K + 1 and len(P4) == 128
enfants2 = {tuple(map(int, l[:3])): l[3:] for l in lignes(f"{C4}/sous_cubes.txt")}
enfants3 = {}
for f in ("cubes_phase3.txt", "cubes_phase3b.txt", "cubes_phase3c.txt"):
    for l in lignes(f"{C4}/{f}"):
        enfants3[tuple(map(int, l[:4]))] = l[4:]
enfants4 = {}
for f in ("cubes_phase4.txt", "cubes_phase4c.txt"):
    for l in lignes(f"{C4}/{f}"):
        enfants4[tuple(map(int, l[:5]))] = l[5:]

# ---------------------------------------------------------------- complétudes : CNF reconstruite + preuve
comp = [
    ("arbre (a, b)", "completude.cnf", "completude.txt", list(feuilles.values())),
    ("chaîne W2", "completude_W2.cnf", "completude_W2.txt", list(W2.values())),
    ("chaîne W3", "completude_W3.cnf", "completude_W3.txt", list(W3.values())),
    ("coupe P4 (voisinage du nibble 0 au tour 1)", "completude_P4.cnf", "completude_P4.txt", list(P4.values())),
]
for nom, cnf, txt, coupe in comp:
    c1 = completude_conforme(f"{C4}/{cnf}", coupe)
    c2 = completude_prouvee(f"{C4}/{txt}")
    ok &= c1 and c2
    print(f"  {'ok' if c1 and c2 else 'ÉCHEC'} complétude {nom} : CNF = ∧ ¬(lignes de la coupe) {'oui' if c1 else 'NON'}, "
          f"prouvée deux fois {'oui' if c2 else 'NON'}")
lit_ok = all(enfants2[k] == feuilles[k[:2]] + W2[k[2]] for k in enfants2) \
    and all(enfants3[k] == enfants2[k[:3]] + W3[k[3]] for k in enfants3) \
    and all(enfants4[k] == enfants3[k[:4]] + P4[k[4]] for k in enfants4)
ok &= lit_ok
print(f"  {'ok' if lit_ok else 'ÉCHEC'} littéraux : chaque enfant = parent + sa ligne de chaîne "
      f"({len(enfants2)} sous-feuilles, {len(enfants3)} morceaux, {len(enfants4)} cubes)")

# ---------------------------------------------------------------- résultats des unités
R2 = resultats(["c4-brume1024-K28", "c4-brume1024-K28-phase1"], 2)
pass1 = {tuple(map(int, l[:2])) for l in lignes(f"{C4}/feuilles_prouvees.txt")}
R3 = resultats(["c4-brume1024-K28-phase2"], 3)
R4 = resultats(["c4-brume1024-K28-phase3", "c4-brume1024-K28-phase3b", "c4-brume1024-K28-phase3c"], 4)
R5 = resultats(["c4-brume1024-K28-phase4-a", "c4-brume1024-K28-phase4-b", "c4-brume1024-K28-phase4c"], 5)
sat = [l for R in (R2, R3, R4, R5) for (_, l) in R.values() if "SATISFIABLE" in l]
ok &= not sat
print(f"  {'ok' if not sat else 'ÉCHEC'} aucune unité SATISFIABLE ({len(sat)})")
compte = {"feuilles directes": 0, "sous-feuilles directes": 0, "morceaux directs": 0, "cubes": 0}
directs = {2: [], 3: [], 4: [], 5: []}   # nœuds prouvés directement, avec leurs littéraux (pour --reprouver)


def prouve4(k):
    if R4.get(k, (False,))[0]:
        compte["morceaux directs"] += 1
        directs[4].append((k, enfants3[k]))
        return True
    kids = [k + (e,) for e in range(128)]
    if all(c in enfants4 and R5.get(c, (False,))[0] for c in kids):
        compte["cubes"] += 128
        directs[5].extend((c, enfants4[c]) for c in kids)
        return True
    print(f"    morceau non prouvé : {k} ({R4.get(k, (None, 'aucun résultat'))[1][:80]})")
    return False


def prouve3(k):
    if R3.get(k, (False,))[0]:
        compte["sous-feuilles directes"] += 1
        directs[3].append((k, enfants2[k]))
        return True
    kids = [k + (d,) for d in range(K + 1)]
    return all(c in enfants3 for c in kids) and all([prouve4(c) for c in kids])


def prouve2(k):
    if R2.get(k, (False,))[0]:
        compte["feuilles directes"] += 1
        directs[2].append((k, feuilles[k]))
        return True
    kids = [k + (c,) for c in range(K + 1)]
    return all(c in enfants2 for c in kids) and all([prouve3(c) for c in kids])


p1 = all(R2.get(k, (False,))[0] for k in pass1)
ok &= p1
print(f"  {'ok' if p1 else 'ÉCHEC'} les {len(pass1)} feuilles de la 1re passe ont un résultat relu, vérifié deux fois")
tout = all([prouve2(k) for k in sorted(feuilles)])
ok &= tout
print(f"  {'ok' if tout else 'ÉCHEC'} arbre entier : {compte}")


# ---------------------------------------------------------------- preuves refaites (option)
def prouver(cnf_txt, nom):
    """CaDiCaL + deux vérificateurs sur une CNF donnée en texte ; vrai si insatisfiable et les deux preuves acceptées."""
    cad, lv, lc = (os.environ.get(v, d) for v, d in (("CADICAL", "cadical"), ("LRAT_VERIF", "lrat_verif"),
                                                     ("LRAT_CHECK", "lrat-check")))
    with tempfile.TemporaryDirectory() as d:
        f, p = os.path.join(d, "f.cnf"), os.path.join(d, "f.lrat")
        open(f, "w").write(cnf_txt)
        rc = subprocess.run([cad, "-q", "--lrat=true", "--binary=false", f, p], stdout=subprocess.DEVNULL).returncode
        v1 = rc == 20 and "VERIFIEE" in subprocess.run([lv, f, p], capture_output=True, text=True).stdout
        v2 = rc == 20 and any(l.startswith("c VERIFIED") for l in
                              subprocess.run([lc, f, p], capture_output=True, text=True).stdout.splitlines())
    print(f"    {'ok' if v1 and v2 else 'ÉCHEC'} refait : {nom} (rc={rc}, lrat_verif {v1}, lrat-check {v2})", flush=True)
    return v1 and v2


if "--reprouver" in sys.argv:
    n = int(sys.argv[sys.argv.index("--reprouver") + 1]) if len(sys.argv) > sys.argv.index("--reprouver") + 1 else 3
    c3bin = os.environ.get("C3BIN", os.path.join(ICI, "..", "..", "..", "tests", "c", "build", "c3_cnf1024"))
    with tempfile.TemporaryDirectory() as d:
        base = os.path.join(d, "base.cnf")
        subprocess.run([c3bin, "cnf", "diff", "4", str(K), base], stdout=subprocess.DEVNULL, check=True)
        sha = hashlib.sha256(open(base, "rb").read()).hexdigest()
        cb = sha == SHA_BASE
        ok &= cb
        print(f"  {'ok' if cb else 'ÉCHEC'} CNF de base régénérée par c3_cnf1024 : empreinte {sha[:16]}… "
              f"{'= campagne' if cb else '≠ campagne ' + SHA_BASE[:16]}")
        nv, nc, _ = cnf_clauses(base)
        corps = "".join(l for l in open(base) if not l.startswith(("c", "p")))
    for nom, cnf, _, _ in comp:
        ok &= prouver(open(f"{C4}/{cnf}").read(), f"complétude {nom}")
    rnd = random.Random(2026)
    for niveau in (2, 3, 4, 5):
        for k, lits in rnd.sample(directs[niveau], min(n, len(directs[niveau]))):
            txt = f"p cnf {nv} {nc + len(lits)}\n" + corps + "".join(f"{x} 0\n" for x in lits)
            ok &= prouver(txt, f"nœud {k}")
print("C4 ≥ 28 CERTIFIÉE" if ok else "C4 ≥ 28 PAS ENCORE CERTIFIÉE")
sys.exit(0 if ok else 1)
