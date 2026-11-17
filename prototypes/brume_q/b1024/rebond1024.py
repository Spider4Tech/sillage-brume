# -*- coding: utf-8 -*-
"""Chemins de collision de l'éponge BRUME-1024q à tours réduits (REBOND.md) : différence d'entrée dans le débit, différence
de sortie dans le débit (capacité nulle des deux côtés), coût des annulations après les m premiers tours (modification de
message), minimisé par CP-SAT sur le modèle de tronquees1024.py, puis recalculé exactement (rang sur GF(16)).

    python3 rebond1024.py base                               ligne de base (diffusion libre, annulations au dernier tour)
    python3 rebond1024.py cherche R m [secondes] [fils]      une ligne JSON (chemin, coût, borne basse du solveur)
    python3 rebond1024.py controle                           contrôles (REBOND.md, « What is computed », point 2)
"""
import json
import sys
import time

import tronquees1024 as T

N, DEBIT = T.N, 160
MAT = T.MAT
L = T.lignes(MAT)                      # L[j] : entrées (nibbles avant M) de la sortie j


def avance(A):
    return {v for v in range(N) if any(u in A for u in L[v])}


def base():
    out = {}
    for R in (2, 3, 4, 5):
        best = None
        for s in range(DEBIT):
            A = {s}
            for _ in range(R - 1):
                A = avance(A)
            cap = [v for v in range(DEBIT, N) if any(u in A for u in L[v])]
            if any(sum(u in A for u in L[v]) == 1 for v in cap):
                continue
            if best is None or len(cap) < best[0]:
                best = (len(cap), s)
        out[R] = None if best is None else {"depart": best[1], "capacite_a_annuler": best[0], "cout_bits": 4 * best[0]}
    return out


def cout_rang_apres(motifs, m):
    """Coût exact (bits) des annulations des tours t ≥ m (rang sur GF(16) du système de chaque tour)."""
    total = 0
    for t in range(m, len(motifs) - 1):
        c = T.cout_rang(MAT, [motifs[t], motifs[t + 1]])
        if c is None:
            return None
        total += c
    # les tours < m doivent rester réalisables (aucune sortie forcée active rendue inactive)
    for t in range(0, min(m, len(motifs) - 1)):
        if T.cout_rang(MAT, [motifs[t], motifs[t + 1]]) is None:
            return None
    return total


GM = [[int(T.GMUL[a, b]) for b in range(16)] for a in range(16)]
INV = [0] + [next(b for b in range(1, 16) if GM[a][b] == 1) for a in range(1, 16)]


def noyau_gf16(A, n):
    """Base du noyau à droite de A (liste de lignes de longueur n) sur GF(16)."""
    A = [list(r) for r in A]
    piv, rg = [], 0
    for c in range(n):
        p = next((i for i in range(rg, len(A)) if A[i][c]), None)
        if p is None:
            continue
        A[rg], A[p] = A[p], A[rg]
        f = INV[A[rg][c]]
        A[rg] = [GM[f][x] for x in A[rg]]
        for i in range(len(A)):
            if i != rg and A[i][c]:
                g = A[i][c]
                A[i] = [x ^ GM[g][y] for x, y in zip(A[i], A[rg])]
        piv.append(c)
        rg += 1
    libres = [c for c in range(n) if c not in piv]
    base = []
    for fc in libres:
        v = [0] * n
        v[fc] = 1
        for k, c in enumerate(piv):
            v[c] = A[k][fc]          # caractéristique 2 : −a = a
        base.append(v)
    return base


def realisable_tour(act_in, act_out):
    """Le tour (motif d'entrée → motif de sortie de M) est-il réalisable tel qu'écrit sur GF(16) ? Il faut un vecteur y de
    différences de sortie des S-box, non nul sur chaque entrée active, dans le noyau des sorties inactives, sans sortie
    active forcée à zéro. Testé : noyau non nul, et aucune des formes (coordonnée active, ligne d'une sortie active)
    identiquement nulle sur le noyau. C'est nécessaire ; c'est suffisant si le nombre de formes est < 16 ou le noyau de
    dimension 1, et « présumé » au-delà (un y générique les évite toutes avec probabilité ≈ (15/16)^formes)."""
    I = [i for i in range(N) if act_in[i]]
    A = []
    for j in range(N):
        if not act_out[j]:
            row = [int(MAT[j, i]) for i in I]
            if any(row):
                A.append(row)
    base = noyau_gf16(A, len(I))
    if not base:
        return False
    for k in range(len(I)):
        if all(b[k] == 0 for b in base):
            return False
    for j in range(N):
        if act_out[j]:
            row = [int(MAT[j, i]) for i in I]
            if all(sum_gf(row, b) == 0 for b in base):
                return False
    return True


def sum_gf(row, b):
    s = 0
    for r, x in zip(row, b):
        s ^= GM[r][x]
    return s


def realisable(motifs):
    return all(realisable_tour(motifs[t], motifs[t + 1]) for t in range(len(motifs) - 1))


def valide(motifs):
    """Le chemin respecte-t-il le modèle et les contraintes de capacité ? (indépendant du solveur)"""
    if any(motifs[0][i] for i in range(DEBIT, N)) or any(motifs[-1][i] for i in range(DEBIT, N)):
        return False
    if not any(motifs[0]):
        return False
    for t in range(len(motifs) - 1):
        for j in range(N):
            n = sum(motifs[t][i] for i in L[j])
            if motifs[t + 1][j] and n == 0:
                return False
            if not motifs[t + 1][j] and n == 1:
                return False
    return True


def cherche(R, m, secondes=7200, fils=4, depart=None):
    from ortools.sat.python import cp_model
    md = cp_model.CpModel()
    x = [[md.NewBoolVar("") for _ in range(N)] for _ in range(R + 1)]
    for i in range(DEBIT, N):
        md.Add(x[0][i] == 0)
        md.Add(x[R][i] == 0)
    md.Add(sum(x[0]) >= 1)
    if depart is not None:
        md.Add(x[0][depart] == 1)
    annul_t = []
    for t in range(R):
        md.Add(sum(x[t]) + sum(x[t + 1]) >= 8)              # B = 8 (prouvé), redondance
        at = []
        for j in range(N):
            ent = [x[t][i] for i in L[j]]
            n = sum(ent)
            z = md.NewBoolVar("")
            md.Add(n >= 1).OnlyEnforceIf(z)
            md.Add(n == 0).OnlyEnforceIf(z.Not())
            md.AddImplication(x[t + 1][j], z)
            c = md.NewBoolVar("")
            md.AddBoolAnd([z, x[t + 1][j].Not()]).OnlyEnforceIf(c)
            md.AddBoolOr([z.Not(), x[t + 1][j]]).OnlyEnforceIf(c.Not())
            md.Add(n >= 2).OnlyEnforceIf(c)
            at.append(c)
        annul_t.append(at)
    for t in range(m):
        # tour « gratuit » (modification de message) : y choisi par l'attaquant, mais le système des annulations doit
        # laisser un noyau non nul ; restriction suffisante retenue : au plus |actifs| − 1 annulations (REBOND.md)
        md.Add(sum(annul_t[t]) <= sum(x[t]) - 1)
    cout = 4 * sum(c for t in range(m, R) for c in annul_t[t])
    md.Minimize(cout)
    t0 = time.time()
    coupes = 0
    while True:
        # boucle de coupes paresseuses : un tour non réalisable sur GF(16) (noyau nul, coordonnée ou sortie active
        # forcée à zéro) est interdit tel quel, et le modèle relancé, dans le budget de temps total
        s = cp_model.CpSolver()
        s.parameters.max_time_in_seconds = max(1.0, secondes - (time.time() - t0))
        s.parameters.num_workers = fils
        st = s.Solve(md)
        res = {"R": R, "m": m, "statut": s.StatusName(st), "s": round(time.time() - t0, 1),
               "borne_basse_bits": round(s.BestObjectiveBound(), 1), "coupes": coupes}
        if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return res
        motifs = [[int(s.Value(v)) for v in x[t]] for t in range(R + 1)]
        mauvais = [t for t in range(R) if not realisable_tour(motifs[t], motifs[t + 1])]
        if mauvais and time.time() - t0 < secondes - 5:
            for t in mauvais:
                lits = [x[t][i] if motifs[t][i] else x[t][i].Not() for i in range(N)] + \
                       [x[t + 1][i] if motifs[t + 1][i] else x[t + 1][i].Not() for i in range(N)]
                md.AddBoolOr([lt.Not() for lt in lits])
            coupes += len(mauvais)
            continue
        res.update({"cout_modele_bits": int(round(s.ObjectiveValue())),
                    "cout_rang_bits": cout_rang_apres(motifs, m),
                    "valide": valide(motifs),
                    "realisable": not mauvais,
                    "actifs": [sum(mt) for mt in motifs],
                    "capacite_active": [sum(mt[DEBIT:]) for mt in motifs],
                    "annulations_par_tour": [sum(int(s.Value(c)) for c in annul_t[t]) for t in range(R)],
                    "entree": [i for i in range(N) if motifs[0][i]],
                    "motifs": ["".join(str(b) for b in mt) for mt in motifs]})
        return res


def controle():
    ok = True

    def verdict(nom, cond, detail=""):
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'ok' if cond else 'ECHEC'}] {nom}{' : ' + detail if detail else ''}", flush=True)

    b = base()
    verdict("ligne de base R = 2, 3, 4 : 12, 92, 272 bits", [b[R]["cout_bits"] for R in (2, 3, 4)] == [12, 92, 272],
            json.dumps(b))
    r2 = cherche(2, 0, 120, 4)
    verdict("R = 2, m = 0 : chemin valide, coût ≤ 12, rang recalculé ≤ modèle", r2.get("valide") and
            r2["cout_modele_bits"] <= 12 and r2["cout_rang_bits"] is not None and
            r2["cout_rang_bits"] <= r2["cout_modele_bits"], f"{r2['statut']} {r2.get('cout_modele_bits')} "
            f"(rang {r2.get('cout_rang_bits')}), borne {r2['borne_basse_bits']}")
    r3 = cherche(3, 0, 300, 4, depart=133)
    verdict("R = 3, m = 0, départ 133 : chemin valide, coût ≤ 92", r3.get("valide") and r3["cout_modele_bits"] <= 92,
            f"{r3['statut']} {r3.get('cout_modele_bits')} (rang {r3.get('cout_rang_bits')})")
    # témoins négatifs du validateur
    mot = [list(map(int, mt)) for mt in r2["motifs"]]
    m1 = [list(x) for x in mot]
    m1[0][200] = 1
    verdict("validateur : capacité active en entrée refusée", not valide(m1))
    m2 = [list(x) for x in mot]
    m2[-1][200] = 1
    verdict("validateur : capacité active en sortie refusée", not valide(m2))
    m3 = [list(x) for x in mot]
    j = next((j for j in range(N) if m3[1][j] and sum(m3[0][i] for i in L[j]) == 1), None)
    if j is None:
        j = next(j for j in range(N) if m3[1][j])
        m3[0] = [0] * N
        m3[0][next(i for i in L[j])] = 1
    m3[1][j] = 0
    verdict("validateur : annulation à une seule entrée refusée", not valide(m3))
    # réalisabilité sur GF(16) : témoins
    a = 57
    sortie_a = [1 if a in L[j] else 0 for j in range(N)]
    ent = [1 if i == a else 0 for i in range(N)]
    verdict("réalisable : un nibble → ses 7 sorties", realisable_tour(ent, sortie_a))
    verdict("non réalisable : un nibble → aucune sortie (noyau nul)", not realisable_tour(ent, [0] * N))
    j0 = next(j for j in range(N) if sortie_a[j])
    s2 = list(sortie_a)
    s2[j0] = 0
    verdict("non réalisable : un nibble → 6 de ses 7 sorties (annulation à une entrée)", not realisable_tour(ent, s2))
    # deux entrées qui partagent une sortie j : l'annuler laisse un noyau de dimension 1
    b = next(i for i in range(N) if i != a and any(a in L[j] and i in L[j] for j in range(N)))
    ent2 = [1 if i in (a, b) else 0 for i in range(N)]
    out2 = [1 if (a in L[j] or b in L[j]) else 0 for j in range(N)]
    jc = next(j for j in range(N) if a in L[j] and b in L[j])
    out2[jc] = 0
    verdict("réalisable : deux entrées, une sortie commune annulée", realisable_tour(ent2, out2))
    # la sonde du 17 nov. : m = 1 sans contrôle donnait 97 actifs → 1 actif ; avec le contrôle, chemin réalisable
    r31 = cherche(3, 1, 120, 4)
    verdict("R = 3, m = 1 : le chemin rendu est réalisable sur GF(16)", r31.get("realisable"),
            f"{r31['statut']} coût {r31.get('cout_modele_bits')}, {r31['coupes']} coupes, actifs {r31.get('actifs')}")
    print("tous les contrôles passent" if ok else "ÉCHEC d'au moins un contrôle", flush=True)
    return ok


def groupes(R, v):
    """Arguments de rebond_verif : témoin w (capacité hors d'atteinte), puis les nibbles de capacité à annuler."""
    A = {v}
    for _ in range(R - 1):
        A = avance(A)
    q = [j for j in range(DEBIT, N) if any(u in A for u in L[j])]
    w = next(j for j in range(DEBIT, N) if j not in q)
    return [w] + q


if __name__ == "__main__":
    if sys.argv[1] == "groupes":
        print(" ".join(map(str, groupes(int(sys.argv[2]), int(sys.argv[3])))))
    elif sys.argv[1] == "base":
        print(json.dumps(base()))
    elif sys.argv[1] == "controle":
        sys.exit(0 if controle() else 1)
    elif sys.argv[1] == "cherche":
        a = sys.argv[2:]
        print(json.dumps(cherche(int(a[0]), int(a[1]), float(a[2]) if len(a) > 2 else 7200,
                                 int(a[3]) if len(a) > 3 else 4)), flush=True)
