# -*- coding: utf-8 -*-
"""Attaques algébriques directes sur BRUME-1024q à tours réduits (ALGEBRIQUE.md) : problème CICO planté, encodé en
CNF avec clauses XOR, résolu par CryptoMiniSat (XOR natifs, Gauss–Jordan) ou CaDiCaL (XOR découpés), chaque solution
revérifiée par la référence (dp1024/b1024_module.tour) indépendamment de la CNF.

    python3 algebrique1024.py controle                       contrôles de l'encodage (ALGEBRIQUE.md, « Checks »)
    python3 algebrique1024.py resoudre R v forme graine [solveur] [delai_s] [k]
            forme : boule | etale ; solveur : cms | cadical ; k = v par défaut. Sortie : une ligne JSON.
"""
import json
import os
import random
import subprocess
import sys
import tempfile
import time

import numpy as np

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ICI, "dp1024"))
sys.path.insert(0, os.path.normpath(os.path.join(ICI, "..", "..", "..")))
import b1024_module as B  # noqa: E402

N = B.N
DEBIT = 160                      # nibbles du débit (SPEC.md : octets 0..79)
S = [int(v) for v in B.SBOX]
G = B.GMUL
E_SEG, E_I, E_C = B.E_SEG, B.E_I, B.E_C
VOIS = [sorted(set(int(E_I[k]) for k in range(E_SEG[v], E_SEG[v + 1]))) for v in range(N)]


def mul_bits(c):
    """Produit par c dans GF(16) comme matrice binaire : bit j de c·y = XOR des bits i de y tels que mat[j][i]."""
    return [[(int(G[c][1 << i]) >> j) & 1 for i in range(4)] for j in range(4)]


MULB = {c: mul_bits(c) for c in range(16)}


# --- évaluation de référence, par lots (numpy), contrôlée contre B.tour --------------------------------------------
SB = np.array(S, np.uint8)
GT = np.array([[int(G[a][b]) for b in range(16)] for a in range(16)], np.uint8)
RCA = [np.array(B.RC[r], np.uint8) for r in range(32)]


def perm_lot(X, R):
    X = X.copy()
    for r in range(R):
        Y = SB[X ^ RCA[r][None, :]]
        Z = np.zeros_like(X)
        for v in range(N):
            for k in range(E_SEG[v], E_SEG[v + 1]):
                Z[:, v] ^= GT[E_C[k]][Y[:, E_I[k]]]
        X = Z
    return X


def perm_ref(x, R):
    x = list(x)
    for r in range(R):
        x = B.tour(x, r)
    return x


# --- formes des instances -------------------------------------------------------------------------------------------
def boule(n):
    """Les n premiers nibbles du débit dans l'ordre d'un parcours en largeur du graphe de M depuis le nibble 0."""
    vus, file, out = {0}, [0], []
    while file and len(out) < n:
        u = file.pop(0)
        if u < DEBIT:
            out.append(u)
        for w in VOIS[u]:
            if w not in vus:
                vus.add(w)
                file.append(w)
    assert len(out) == n
    return out


def etale(n):
    return sorted(set(int(i * DEBIT / n) for i in range(n)))


def forme(nom, n):
    return boule(n) if nom == "boule" else etale(n)


# --- encodage -------------------------------------------------------------------------------------------------------
class Cnf:
    def __init__(self):
        self.nv = 0
        self.cl = []          # clauses ordinaires
        self.xo = []          # (liste de variables, parité) : XOR des variables = parité

    def var(self):
        self.nv += 1
        return self.nv

    def xor(self, vs, c):
        vs = sorted(vs)
        if not vs:
            if c:
                self.cl.append([])         # contradiction (n'arrive pas sur une instance plantée)
            return
        self.xo.append((vs, c))


def lit_de(cnf, forme_):
    """Une forme affine (ensemble de variables, constante) → un littéral (nouvelle variable définie par XOR si besoin)."""
    vs, c = forme_
    if len(vs) == 1:
        (v,) = vs
        return -v if c else v
    t = cnf.var()
    cnf.xor(list(vs) + [t], c)        # t = XOR(vs) ⊕ c  ⇔  XOR(vs, t) = c
    return t


def encoder(R, libres, fixe_entree, sorties, cible):
    """État = 256 nibbles × 4 bits, chaque bit une forme affine (frozenset de variables, constante).
    libres : nibbles d'entrée libres ; fixe_entree : valeurs des 256 nibbles (les libres ignorés) ;
    sorties : nibbles de sortie fixés ; cible : leurs valeurs. Rend (cnf, variables d'entrée par nibble libre)."""
    cnf = Cnf()
    etat, vin = [], {}
    for j in range(N):
        if j in libres:
            vs = [cnf.var() for _ in range(4)]
            vin[j] = vs
            etat.append([(frozenset([v]), 0) for v in vs])
        else:
            etat.append([(frozenset(), (fixe_entree[j] >> b) & 1) for b in range(4)])
    for r in range(R):
        ys = []
        for j in range(N):
            a = [(f[0], f[1] ^ ((int(B.RC[r][j]) >> b) & 1)) for b, f in enumerate(etat[j])]
            if all(not f[0] for f in a):
                x = sum(f[1] << b for b, f in enumerate(a))
                ys.append([(frozenset(), (S[x] >> b) & 1) for b in range(4)])
                continue
            la = [lit_de(cnf, f) if f[0] else None for f in a]
            yv = [cnf.var() for _ in range(4)]
            for x in range(16):
                # entrée = x  ⇒  sortie = S(x) ; les bits constants de l'entrée filtrent les x possibles
                cond, possible = [], True
                for b in range(4):
                    xb = (x >> b) & 1
                    if la[b] is None:
                        if a[b][1] != xb:
                            possible = False
                            break
                    else:
                        cond.append(-la[b] if xb else la[b])
                if not possible:
                    continue
                for j2 in range(4):
                    cnf.cl.append(cond + [yv[j2] if (S[x] >> j2) & 1 else -yv[j2]])
            ys.append([(frozenset([v]), 0) for v in yv])
        nouv = []
        for v in range(N):
            bits = [[set(), 0] for _ in range(4)]
            for k in range(E_SEG[v], E_SEG[v + 1]):
                mb, y = MULB[int(E_C[k])], ys[int(E_I[k])]
                for jb in range(4):
                    for ib in range(4):
                        if mb[jb][ib]:
                            bits[jb][0] ^= set(y[ib][0])
                            bits[jb][1] ^= y[ib][1]
            nouv.append([(frozenset(b_[0]), b_[1]) for b_ in bits])
        etat = nouv
    for j, val in zip(sorties, cible):
        for b in range(4):
            vs, c = etat[j][b]
            cnf.xor(list(vs), c ^ ((val >> b) & 1))
    return cnf, vin


def ecrire_cms(cnf, chemin):
    with open(chemin, "w") as f:
        f.write(f"p cnf {cnf.nv} {len(cnf.cl) + len(cnf.xo)}\n")
        for c in cnf.cl:
            f.write(" ".join(map(str, c)) + " 0\n")
        for vs, c in cnf.xo:
            # format CryptoMiniSat : « x l1 l2 … 0 » ⇔ XOR des littéraux = 1 ; parité 0 ⇒ premier littéral nié
            ls = list(vs)
            if c == 0:
                ls[0] = -ls[0]
            f.write("x" + " ".join(map(str, ls)) + " 0\n")


def ecrire_cnf_pure(cnf, chemin):
    """XOR découpés en morceaux de 4 variables au plus (variables de Tseitin), pour CaDiCaL."""
    nv, cls = cnf.nv, [list(c) for c in cnf.cl]

    def xor_court(vs, c):
        n = len(vs)
        for m in range(1 << n):
            if bin(m).count("1") % 2 != c:      # affectation interdite → clause qui l'exclut
                cls.append([(-v if (m >> i) & 1 else v) for i, v in enumerate(vs)])
    for vs, c in cnf.xo:
        vs = list(vs)
        while len(vs) > 4:
            nv += 1
            t = nv
            xor_court(vs[:3] + [t], 0)          # t = v0 ⊕ v1 ⊕ v2
            vs = [t] + vs[3:]
        xor_court(vs, c)
    with open(chemin, "w") as f:
        f.write(f"p cnf {nv} {len(cls)}\n")
        for c in cls:
            f.write(" ".join(map(str, c)) + " 0\n")


def resoudre_cnf(cnf, solveur, delai, max_sol=1):
    """Rend (statut, liste de modèles (dict var → bool), durée)."""
    with tempfile.TemporaryDirectory() as d:
        ch = os.path.join(d, "f.cnf")
        if solveur == "cms":
            ecrire_cms(cnf, ch)
            cmd = ["cryptominisat5", "--verb", "0", "--maxsol", str(max_sol), ch]
        else:
            ecrire_cnf_pure(cnf, ch)
            cmd = ["cadical", "-q", ch]
        t0 = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=delai)
        except subprocess.TimeoutExpired:
            return "DELAI", [], time.time() - t0
        dt = time.time() - t0
        modeles, cour, statut = [], {}, "INCONNU"
        for ligne in p.stdout.splitlines():
            if ligne.startswith("s SATISFIABLE"):
                statut = "SAT"
                if cour:
                    modeles.append(cour)
                cour = {}
            elif ligne.startswith("s UNSATISFIABLE"):
                if statut != "SAT":
                    statut = "UNSAT"
                if cour:
                    modeles.append(cour)
                cour = {}
            elif ligne.startswith("v "):
                for t in ligne[2:].split():
                    t = int(t)
                    if t:
                        cour[abs(t)] = t > 0
        if cour:
            modeles.append(cour)
        return statut, modeles, dt


def instance(R, v, nom_forme, graine, k=None):
    k = v if k is None else k
    assert v % 4 == 0 and k % 4 == 0
    rnd = random.Random(f"algebrique1024/{R}/{v}/{k}/{nom_forme}/{graine}")
    x = [rnd.randrange(16) for _ in range(N)]
    y = perm_ref(x, R)
    libres = forme(nom_forme, v // 4)
    sorties = forme(nom_forme, k // 4)
    return x, y, libres, sorties


def lire_entree(x, libres, vin, modele):
    z = list(x)
    for j in libres:
        z[j] = sum((1 << b) for b, var in enumerate(vin[j]) if modele.get(var, False))
    return z


def resoudre(R, v, nom_forme, graine, solveur="cms", delai=3600, k=None):
    x, y, libres, sorties = instance(R, v, nom_forme, graine, k)
    cnf, vin = encoder(R, set(libres), x, sorties, [y[j] for j in sorties])
    statut, modeles, dt = resoudre_cnf(cnf, solveur, delai)
    rep = {"R": R, "v": v, "k": len(sorties) * 4, "forme": nom_forme, "graine": graine, "solveur": solveur,
           "variables": cnf.nv, "clauses": len(cnf.cl), "xor": len(cnf.xo), "statut": statut, "s": round(dt, 3)}
    if statut == "SAT":
        z = lire_entree(x, libres, vin, modeles[0])
        yz = perm_ref(z, R)
        rep["solution_verifiee"] = all(yz[j] == y[j] for j in sorties) and \
            all(z[j] == x[j] for j in range(N) if j not in libres)
        rep["plantee"] = z == x
    return rep


# --- contrôles -------------------------------------------------------------------------------------------------------
def controle():
    ok = True

    def verdict(nom, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'ok' if cond else 'ECHEC'}] {nom}{' : ' + detail if detail else ''}", flush=True)

    rnd = random.Random(1)
    X = np.array([[rnd.randrange(16) for _ in range(N)] for _ in range(6)], np.uint8)
    lot = perm_lot(X, 3)
    verdict("perm_lot ≡ B.tour (6 états, 3 tours)", all(list(lot[i]) == perm_ref(list(X[i]), 3) for i in range(6)))
    # propriétés de la S-box annoncées dans le plan
    rel = []
    for x in range(16):
        y = S[x]
        bits = [(x >> i) & 1 for i in range(4)] + [(y >> i) & 1 for i in range(4)]
        mon = [1] + bits + [bits[i] & bits[j] for i in range(8) for j in range(i + 1, 8)]
        rel.append(mon)
    A = np.array(rel, np.uint8)            # 16 × 37 ; relations = noyau à droite
    rang = rang_gf2(A)
    verdict("S-box : 21 relations quadratiques indépendantes (37 − rang)", 37 - rang == 21, f"rang {rang}")
    sous = sous_espaces_affines_s()
    verdict("S-box affine sur des sous-espaces affines de dimension 2", sous > 0, f"{sous} sous-espaces")
    # (a) tout fixé : SAT ; (b) un bit de sortie inversé : UNSAT
    for R in (1, 2, 3):
        x, y, _, _ = instance(R, 16, "boule", 0)
        sorties = list(range(DEBIT))
        cnf, _ = encoder(R, set(), x, sorties, [y[j] for j in sorties])
        st, _, _ = resoudre_cnf(cnf, "cms", 600)
        verdict(f"(a) R = {R}, tout fixé : SAT", st == "SAT", st)
        yb = [y[j] for j in sorties]
        yb[5] ^= 1
        cnf, _ = encoder(R, set(), x, sorties, yb)
        st, _, _ = resoudre_cnf(cnf, "cms", 600)
        verdict(f"(b) R = {R}, un bit de sortie inversé : UNSAT", st == "UNSAT", st)
    # (c) force brute de référence, v = 16, R = 2 et 3, k = 12 (plusieurs solutions attendues) : mêmes ensembles
    for R, nom in ((2, "boule"), (3, "boule"), (2, "etale")):
        x, y, libres, sorties = instance(R, 16, nom, 0, k=12)
        Xs = np.tile(np.array(x, np.uint8), (1 << 16, 1))
        idx = np.arange(1 << 16)
        for t, j in enumerate(libres):
            Xs[:, j] = (idx >> (4 * t)) & 0xF
        Ys = perm_lot(Xs, R)
        bon = np.all(Ys[:, sorties] == np.array([y[j] for j in sorties], np.uint8)[None, :], axis=1)
        attendu = set(int(i) for i in np.nonzero(bon)[0])
        cnf, vin = encoder(R, set(libres), x, sorties, [y[j] for j in sorties])
        st, mods, _ = resoudre_cnf(cnf, "cms", 1200, max_sol=len(attendu) + 5)
        trouve = set()
        for m in mods:
            z = lire_entree(x, libres, vin, m)
            trouve.add(sum(z[j] << (4 * t) for t, j in enumerate(libres)))
        verdict(f"(c) R = {R}, {nom}, v = 16, k = 12 : solutions CNF = force brute", trouve == attendu and len(attendu) > 0,
                f"{len(attendu)} par force brute, {len(trouve)} par CryptoMiniSat")
    # (d) CaDiCaL ≡ CryptoMiniSat, et solutions revérifiées
    for R, v in ((1, 64), (2, 32)):
        a = resoudre(R, v, "boule", 0, "cms", 600)
        b = resoudre(R, v, "boule", 0, "cadical", 600)
        verdict(f"(d) R = {R}, v = {v} : cms et cadical SAT, solutions vérifiées",
                a["statut"] == b["statut"] == "SAT" and a["solution_verifiee"] and b["solution_verifiee"],
                f"cms {a['s']} s, cadical {b['s']} s")
    print("tous les contrôles passent" if ok else "ÉCHEC d'au moins un contrôle", flush=True)
    return ok


def rang_gf2(A):
    A = A.copy() % 2
    r = 0
    for c in range(A.shape[1]):
        p = next((i for i in range(r, A.shape[0]) if A[i, c]), None)
        if p is None:
            continue
        A[[r, p]] = A[[p, r]]
        for i in range(A.shape[0]):
            if i != r and A[i, c]:
                A[i] ^= A[r]
        r += 1
    return r


def sous_espaces_affines_s():
    """Nombre de sous-espaces affines {a, a⊕u, a⊕w, a⊕u⊕w} (u, w indépendants) sur lesquels S est affine."""
    vus = set()
    for a in range(16):
        for u in range(1, 16):
            for w in range(u + 1, 16):
                if w == u:
                    continue
                pts = frozenset([a, a ^ u, a ^ w, a ^ u ^ w])
                if len(pts) < 4 or pts in vus:
                    continue
                if S[a] ^ S[a ^ u] ^ S[a ^ w] ^ S[a ^ u ^ w] == 0:
                    vus.add(pts)
    return len(vus)


VS = [16, 24, 32, 48, 64, 96, 128, 192, 256]


def echelle(R, nom, graine, delai):
    """v croissant : CryptoMiniSat, puis CaDiCaL sur la même instance si CryptoMiniSat la résout ; au premier délai
    dépassé par CryptoMiniSat, un essai CaDiCaL sur cette instance, puis arrêt (ALGEBRIQUE.md, « What is measured »)."""
    for v in VS:
        a = resoudre(R, v, nom, graine, "cms", delai)
        print(json.dumps(a), flush=True)
        b = resoudre(R, v, nom, graine, "cadical", delai)
        print(json.dumps(b), flush=True)
        if a["statut"] != "SAT" and b["statut"] != "SAT":
            break
        for r_ in (a, b):
            if r_["statut"] == "SAT" and not r_["solution_verifiee"]:
                print(json.dumps({"ALERTE": "solution non vérifiée", **r_}), flush=True)
                return 3
        if a["statut"] not in ("SAT", "DELAI") or b["statut"] not in ("SAT", "DELAI"):
            print(json.dumps({"ALERTE": "statut inattendu sur une instance plantée", "cms": a, "cadical": b}),
                  flush=True)
            return 3
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "controle":
        sys.exit(0 if controle() else 1)
    elif sys.argv[1] == "echelle":
        a = sys.argv[2:]
        sys.exit(echelle(int(a[0]), a[1], int(a[2]), float(a[3]) if len(a) > 3 else 3600))
    elif sys.argv[1] == "resoudre":
        a = sys.argv[2:]
        R, v, nom, graine = int(a[0]), int(a[1]), a[2], int(a[3])
        solveur = a[4] if len(a) > 4 else "cms"
        delai = float(a[5]) if len(a) > 5 else 3600
        k = int(a[6]) if len(a) > 6 else None
        print(json.dumps(resoudre(R, v, nom, graine, solveur, delai, k)), flush=True)
