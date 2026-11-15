# -*- coding: utf-8 -*-
"""Différentielles tronquées de BRUME-1024q au-delà de 2 tours (étude « structure », ETUDE_GROUPE_STRUCTURE.md § B1).

Modèle au niveau des nibbles (actif / inactif), r tours x ← M·S(x ⊕ RC) (sens « avant ») ou r tours inverses
x ← S⁻¹(M⁻¹·x) ⊕ RC (sens « arriere ») :
  - la S-box garde l'activité (bijective) ;
  - un nibble de sortie de la couche linéaire est inactif d'office si aucune de ses entrées (ligne de M ou de M⁻¹) n'est
    active ; il est actif d'office s'il en a exactement une (coefficients non nuls) ; avec ≥ 2 entrées actives il peut
    s'ANNULER, ce qui coûte 4 bits (probabilité 2^−4 pour des différences uniformes : modèle habituel des attaques
    tronquées, Knudsen 1994) ;
  - redondances PROUVÉES : chaque tour a un nibble actif, et deux couches consécutives (avant et après M) en ont ≥ B = 8.
Distingueur : sortie nulle sur Z. Pour une permutation aléatoire, P = 2^−4|Z|. Avantage (bits) = 4|Z| − coût ; il faut
avantage > 0 et coût ≤ budget (données : 2^coût paires, fournies par une structure sur les nibbles actifs d'entrée).
Le coût est ensuite RECALCULÉ exactement (rang sur GF(16) du système des annulations de chaque tour, entrées de la couche
linéaire supposées uniformes et indépendantes) : « cout_rang_bits » ≤ « cout_bits ».

    python3 tronquees1024.py cherche avant|arriere r [secondes] [fils] [budget]   → une ligne JSON
    python3 tronquees1024.py decide avant|arriere r [secondes] [fils] [budget] [avantage_min]  → « existe-t-il ? » (nibble 0 imposé
                                                                                   par symétrie ; INFEASIBLE = absence prouvée)
    python3 tronquees1024.py controle                                            → contrôles (modèle, rang, témoins)
La mesure sur la vraie permutation est faite par tronquees_verif.c (fichier de motifs écrit par « cherche »)."""
import json
import os
import sys
import time

import numpy as np

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.normpath(os.path.join(_ICI, "..", "..", ".."))
sys.path.insert(0, os.path.join(_ICI, "dp1024"))
sys.path.insert(0, _RACINE)
import b1024_module as B  # noqa: E402
from sillage import brume512 as B512  # noqa: E402

N = B.N
GMUL = B512.GMUL
MAT = B.matrice()                                  # M[j][i] : x'_j = Σ_i M[j][i] y_i
MINV = np.asarray(B._gauss_gf16_inverse(MAT), dtype=np.uint8)


def lignes(mat):
    return [[int(i) for i in np.nonzero(mat[j])[0]] for j in range(N)]


def rang_gf16(rows):
    """Rang sur GF(16) d'une liste de lignes (listes d'entiers 0..15)."""
    if not rows:
        return 0
    A = [list(r) for r in rows]
    inv = [0] * 16
    for a in range(1, 16):
        for b in range(1, 16):
            if GMUL[a, b] == 1:
                inv[a] = b
    rg, ncol = 0, len(A[0])
    for c in range(ncol):
        p = next((i for i in range(rg, len(A)) if A[i][c]), None)
        if p is None:
            continue
        A[rg], A[p] = A[p], A[rg]
        f = inv[A[rg][c]]
        A[rg] = [int(GMUL[f, x]) for x in A[rg]]
        for i in range(len(A)):
            if i != rg and A[i][c]:
                g = A[i][c]
                A[i] = [x ^ int(GMUL[g, y]) for x, y in zip(A[i], A[rg])]
        rg += 1
        if rg == len(A):
            break
    return rg


def cout_rang(mat, motifs):
    """Coût exact (bits) d'une suite de motifs : Σ_tours 4·rang(système des annulations sur les entrées actives)."""
    total = 0
    for t in range(len(motifs) - 1):
        act = [i for i in range(N) if motifs[t][i]]
        rows = []
        for j in range(N):
            if not motifs[t + 1][j]:
                ent = [i for i in act if mat[j, i]]
                if len(ent) >= 2:
                    rows.append([int(mat[j, i]) for i in act])
                elif len(ent) == 1:
                    return None                    # annulation impossible
        total += 4 * rang_gf16(rows)
    return total


def automorphismes_support(mat):
    """Vérifie que le support de mat est invariant par les décalages σ_s : (i, f) → (i + s mod 128, f) et par
    τ : (i, f) → (−i mod 128, 1 − f) (nibble v = 128·f + i). Ce groupe est transitif sur les 256 nibbles : on peut alors
    supposer, sans perte de généralité pour le modèle (qui ne dépend que du support), le nibble 0 actif en entrée."""
    S = mat != 0
    H = N // 2

    def perm(fn):
        p = np.array([fn(v % H, v // H) for v in range(N)])
        return bool((S[np.ix_(p, p)] == S).all())    # S[p(j), p(i)] = S[j, i] pour tous j, i

    return perm(lambda i, f: (i + 1) % H + H * f) and perm(lambda i, f: (-i) % H + H * (1 - f))


def cherche(sens, r, secondes=600, fils=8, budget=255, amin=None):
    """amin = None : maximise l'avantage. amin = A : question de décision « existe-t-il un motif d'avantage ≥ A ? »,
    avec le nibble 0 actif en entrée (symétrie vérifiée) ; INFEASIBLE = preuve d'absence dans le modèle."""
    from ortools.sat.python import cp_model
    mat = MAT if sens == "avant" else MINV
    L = lignes(mat)
    m = cp_model.CpModel()
    x = [[m.NewBoolVar("") for _ in range(N)] for _ in range(r + 1)]
    sym = False
    if amin is not None:
        sym = automorphismes_support(mat)
        if sym:
            m.Add(x[0][0] == 1)
    annul = []
    for t in range(r):
        m.Add(sum(x[t]) >= 1)
        m.Add(sum(x[t]) + sum(x[t + 1]) >= 8)
        for j in range(N):
            ent = [x[t][i] for i in L[j]]
            n = sum(ent)
            z = m.NewBoolVar("")                   # z ⇔ au moins une entrée active
            m.Add(n >= 1).OnlyEnforceIf(z)
            m.Add(n == 0).OnlyEnforceIf(z.Not())
            m.AddImplication(x[t + 1][j], z)       # sortie active ⇒ une entrée active
            c = m.NewBoolVar("")                   # annulation ⇔ z ∧ ¬sortie
            m.AddBoolAnd([z, x[t + 1][j].Not()]).OnlyEnforceIf(c)
            m.AddBoolOr([z.Not(), x[t + 1][j]]).OnlyEnforceIf(c.Not())
            m.Add(n >= 2).OnlyEnforceIf(c)
            annul.append(c)
    m.Add(sum(x[r]) >= 1)
    cout = 4 * sum(annul)
    zeros = N - sum(x[r])
    m.Add(cout <= budget)
    if amin is None:
        m.Maximize(4 * zeros - cout)
    else:
        m.Add(4 * zeros - cout >= amin)
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = secondes
    s.parameters.num_workers = fils
    t0 = time.time()
    st = s.Solve(m)
    res = {"sens": sens, "tours": r, "budget_bits": budget, "statut": s.StatusName(st), "s": round(time.time() - t0)}
    if amin is not None:
        res.update({"mode": "decision", "avantage_min_bits": amin, "symetrie_nibble0": sym,
                    "absence_prouvee": st == cp_model.INFEASIBLE})
    if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        motifs = [[int(s.Value(v)) for v in x[t]] for t in range(r + 1)]
        c = 4 * sum(int(s.Value(v)) for v in annul)
        z = N - sum(motifs[r])
        res.update({"avantage_bits": 4 * z - c,
                    "borne_haute_avantage_bits": int(s.BestObjectiveBound()) if amin is None else None,
                    "cout_bits": c, "zeros_sortie": z, "actifs": [sum(mt) for mt in motifs],
                    "cout_rang_bits": cout_rang(mat, motifs),
                    "entree": [i for i in range(N) if motifs[0][i]],
                    "motifs": ["".join(str(b) for b in mt) for mt in motifs]})
    return res


def propage_sur(mat, motif):
    """Motif sûr après la couche linéaire, sans annulation (pour les contrôles)."""
    L = lignes(mat)
    return [1 if any(motif[i] for i in L[j]) else 0 for j in range(N)]


def controle():
    ok = True
    # (1) M⁻¹ est bien l'inverse de M sur GF(16)
    prod = np.zeros((N, N), np.uint8)
    for j in range(N):
        for k in range(N):
            a = 0
            for i in np.nonzero(MAT[j])[0]:
                a ^= int(GMUL[MAT[j, i], MINV[i, k]])
            prod[j, k] = a
    c1 = (prod == np.eye(N, dtype=np.uint8)).all()
    print(f"  {'ok' if c1 else 'ÉCHEC'} M·M⁻¹ = I sur GF(16)")
    ok &= c1
    # (2) diffusion sûre depuis un nibble : boules 7, 37, 127, 224, 256 (README § 2)
    mt = [0] * N
    mt[0] = 1
    tailles = []
    for _ in range(5):
        mt = propage_sur(MAT, mt)
        tailles.append(sum(mt))
    c2 = tailles == [7, 37, 127, 224, 256]
    print(f"  {'ok' if c2 else 'ÉCHEC'} diffusion sûre depuis un nibble : {tailles} (attendu [7, 37, 127, 224, 256])")
    ok &= c2
    # (3) rang : une annulation entre deux entrées actives coûte 4 bits ; deux annulations sur les mêmes deux entrées,
    #     de lignes proportionnelles, ne coûtent que 4 (rang 1) ; sinon 8
    r1 = rang_gf16([[1, 1]])
    r2 = rang_gf16([[1, 2], [2, 4]])     # 2·(1, 2) = (2, 4) dans GF(16) (x·2 = décalage)
    r3 = rang_gf16([[1, 2], [1, 3]])
    c3 = (r1, r2, r3) == (1, 1, 2)
    print(f"  {'ok' if c3 else 'ÉCHEC'} rang GF(16) : {r1}, {r2}, {r3} (attendu 1, 1, 2)")
    ok &= c3
    # (4) recherche à 3 et 4 tours : sans annulation, 1 nibble → au moins 256 − 127 zéros à 3 tours (avantage ≥ 516) et
    #     256 − 224 = 32 à 4 tours (avantage ≥ 128) ; le solveur doit trouver au moins cela
    for r, mini in ((3, 4 * (256 - 127)), (4, 4 * 32)):
        res = cherche("avant", r, secondes=60, fils=4, budget=64)
        c4 = res.get("avantage_bits", -1) >= mini and res.get("cout_rang_bits") is not None \
            and res["cout_rang_bits"] <= res["cout_bits"]
        print(f"  {'ok' if c4 else 'ÉCHEC'} {r} tours : avantage {res.get('avantage_bits')} ≥ {mini}, coût {res.get('cout_bits')} "
              f"(rang : {res.get('cout_rang_bits')}), actifs {res.get('actifs')}")
        ok &= c4
    # (5) symétrie utilisée par le mode décision : support de M invariant par σ₁ et τ ; un témoin non symétrique échoue
    c5 = automorphismes_support(MAT) and not automorphismes_support(np.eye(N, dtype=np.uint8)[::-1].copy() + np.eye(N, dtype=np.uint8))
    print(f"  {'ok' if c5 else 'ÉCHEC'} symétrie σ, τ du support de M (transitive sur les 256 nibbles ; témoin non symétrique refusé)")
    ok &= c5
    # (6) mode décision, nibble 0 imposé : à 2 tours sans annulation (budget 0) le meilleur est 1 → 7 → 37 actifs,
    #     soit 219 zéros = 876 bits ; 876 doit être FAISABLE et 880 INFAISABLE ; à 4 tours, l'avantage 128 est faisable
    d1 = cherche("avant", 2, secondes=120, fils=4, budget=0, amin=876)
    d2 = cherche("avant", 2, secondes=120, fils=4, budget=0, amin=880)
    d3 = cherche("avant", 4, secondes=120, fils=4, budget=64, amin=128)
    c6 = d1["statut"] in ("FEASIBLE", "OPTIMAL") and d2["absence_prouvee"] and d3["statut"] in ("FEASIBLE", "OPTIMAL") \
        and d1["symetrie_nibble0"] and d1["entree"] == [0]
    print(f"  {'ok' if c6 else 'ÉCHEC'} décision : 2 tours budget 0, ≥ 876 {d1['statut']}, ≥ 880 {d2['statut']} ; "
          f"4 tours ≥ 128 {d3['statut']}")
    ok &= c6
    print("tous les contrôles passent" if ok else "CONTRÔLE EN ÉCHEC")
    return 0 if ok else 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "controle":
        sys.exit(controle())
    if len(sys.argv) >= 4 and sys.argv[1] == "cherche":
        sens, r = sys.argv[2], int(sys.argv[3])
        sec = float(sys.argv[4]) if len(sys.argv) > 4 else 600
        fils = int(sys.argv[5]) if len(sys.argv) > 5 else 8
        budget = int(sys.argv[6]) if len(sys.argv) > 6 else 255
        print(json.dumps(cherche(sens, r, sec, fils, budget)), flush=True)
        return
    if len(sys.argv) >= 4 and sys.argv[1] == "decide":
        sens, r = sys.argv[2], int(sys.argv[3])
        sec = float(sys.argv[4]) if len(sys.argv) > 4 else 600
        fils = int(sys.argv[5]) if len(sys.argv) > 5 else 8
        budget = int(sys.argv[6]) if len(sys.argv) > 6 else 255
        amin = int(sys.argv[7]) if len(sys.argv) > 7 else 1
        print(json.dumps(cherche(sens, r, sec, fils, budget, amin)), flush=True)
        return
    print(__doc__)
    sys.exit(2)


if __name__ == "__main__":
    main()
