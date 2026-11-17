# -*- coding: utf-8 -*-
"""Niveau 2 du plan de cryptanalyse de BRUME-1024q : meilleures caractéristiques différentielles et linéaires réelles.

Trois résultats à ne pas confondre :
  - la BORNE prouvée (B = 8, C3 ≥ 21 certifié) : nombre minimal de S-box actives, donc poids ≥ 2 bits par S-box active en
    différentiel (DDT max 4/16) et ≥ 1 bit en linéaire (|LAT| max 4/8) ;
  - la MEILLEURE CARACTÉRISTIQUE TROUVÉE : (a) par faisceau (tests/test_beam_trails.py porté à 256 nibbles, coûts exacts
    de chaque transition), une borne côté attaquant ; (b) par CP-SAT exact au niveau des bits (couche linéaire binaire,
    transitions de la DDT ou de la LAT avec leur poids exact), l'OPTIMUM sur 2 à 5 tours quand le solveur le prouve, sinon
    un encadrement [borne basse du solveur, meilleure trouvée] ;
  - l'AGRÉGATION (plusieurs caractéristiques pour une même différentielle) : agregation2.c (2 tours, exact) ; 3 et 4 tours
    à mesurer à part.
Poids en bits : −log₂ de la probabilité (différentiel) ou de la corrélation (linéaire) de la caractéristique.

    python3 trails1024.py faisceau [tours] [K] [L] [graine]
    python3 trails1024.py exact diff|lin r [secondes] [fils] [plafonds|-] [indice.json]
      plafonds : « 1,-,- » = au plus 1 S-box active au tour 0 (recherche RESTREINTE : borne haute seulement) ;
      indice : caractéristique d'un résultat précédent, donnée au solveur comme point de départ (n'impose rien).
Sortie : une ligne JSON par résultat."""
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
import gf16 as B512  # noqa: E402  (v0.6 : corps GF(16), sans BRUME-512)

N, NB = B.N, 4 * B.N
GMUL, GMUL_T = B512.GMUL, B512.GMUL_T
C = B.matrice()
E_SEG, E_I, E_C = B.E_SEG, B.E_I, B.E_C
# transposée : arêtes entrantes de Mᵀ (colonne i de M), coefficients C[j, i], appliqués par GMUL_T (transposée binaire)
_t = [[(j, int(C[j, i])) for j in range(N) if C[j, i]] for i in range(N)]
E_SEG_T = np.array([0] + list(np.cumsum([len(r) for r in _t])))
E_I_T = np.array([j for r in _t for j, _ in r])
E_C_T = np.array([c for r in _t for _, c in r], dtype=np.uint8)

S = np.array(B.SBOX, dtype=np.uint8)
X16 = np.arange(16)
DDT = np.array([[int(((S[X16] ^ S[X16 ^ a]) == v).sum()) for v in range(16)] for a in range(16)])
LAT = np.array([[sum(1 for x in range(16) if ((bin(a & int(S[x])).count("1") ^ bin(l & x).count("1")) & 1) == 0) - 8
                 for l in range(16)] for a in range(16)])          # LAT[masque de sortie a, masque d'entrée l]
with np.errstate(divide="ignore"):
    CDIFF = np.where(DDT > 0, 8 - 2 * np.log2(np.maximum(DDT, 1)), 999).astype(np.int64)      # demi-bits
    CLIN = np.where(LAT != 0, 6 - 2 * np.log2(np.maximum(np.abs(LAT), 1)), 999).astype(np.int64)


def diffuse(st):
    return np.bitwise_xor.reduceat(GMUL[E_C, st[:, E_I]], E_SEG[:-1], axis=1)


def diffuseT(st):
    return np.bitwise_xor.reduceat(GMUL_T[E_C_T, st[:, E_I_T]], E_SEG_T[:-1], axis=1)


def controle_couches():
    """diffuse = M (comparé à b1024_module.tour) ; diffuseT = transposée binaire : ⟨Mᵀβ, x⟩ = ⟨β, Mx⟩ sur des vecteurs
    aléatoires (produit scalaire binaire des nibbles)."""
    rng = np.random.default_rng(3)
    x = rng.integers(0, 16, (32, N), dtype=np.uint8)
    b = rng.integers(0, 16, (32, N), dtype=np.uint8)
    ok1 = all(diffuse(S[x[k:k + 1] ^ np.array(B.RC[0], np.uint8)])[0].tolist() == B.tour(x[k].tolist(), 0) for k in range(4))
    pb = lambda u, v: np.bitwise_xor.reduce(np.array([bin(int(p) & int(q)).count("1") & 1 for p, q in zip(u, v)]))  # noqa
    ok2 = all(pb(diffuseT(b[k:k + 1])[0], x[k]) == pb(b[k], diffuse(x[k:k + 1])[0]) for k in range(32))
    return ok1 and ok2


# ---------------- faisceau (borne côté attaquant) ----------------
def _sources(rng):
    st = np.zeros((N * 15, N), np.uint8)
    rows = np.arange(N * 15)
    st[rows, rows // 15] = (rows % 15 + 1).astype(np.uint8)
    return st[rng.permutation(len(st))]


def faisceau(sens, tours, K, L, graine):
    rng = np.random.default_rng(graine)
    St = _sources(rng)
    couts = np.zeros(len(St), np.int64)
    meilleur = {}
    T = DDT if sens == "diff" else np.abs(LAT)
    Cm = CDIFF if sens == "diff" else CLIN
    opt = np.array([int(np.argmax(T[a])) for a in range(16)])
    for r in range(tours):
        enfants, cc = [], []
        for i in np.argsort(couts, kind="stable")[:K]:
            s = St[i]
            a_in = s if sens == "diff" else diffuseT(s[None, :])[0]
            act = np.nonzero(a_in)[0]
            out = np.zeros((L, N), np.uint8)
            out[0, act] = opt[a_in[act]]
            for k in range(1, L):
                for j in act:
                    p = T[a_in[j]].astype(float)
                    out[k, j] = int(rng.choice(16, p=p / p.sum()))
            cadd = Cm[a_in[None, :], out].sum(1)
            enfants.append(diffuse(out) if sens == "diff" else out)
            cc.append(couts[i] + cadd)
        St, couts = np.concatenate(enfants), np.concatenate(cc)
        vivant = St.any(1)
        St, couts = St[vivant], couts[vivant]
        meilleur[r + 1] = int(couts.min()) / 2
    return meilleur


# ---------------- CP-SAT exact au niveau des bits ----------------
def binaire():
    """Matrice binaire de M (1 024 × 1 024) : bit b du nibble j de Mx."""
    Mb = np.zeros((NB, NB), np.uint8)
    for j in range(N):
        for i in range(N):
            c = int(C[j, i])
            if c:
                for b_in in range(4):
                    y = int(GMUL[c, 1 << b_in])
                    for b_out in range(4):
                        if y >> b_out & 1:
                            Mb[4 * j + b_out, 4 * i + b_in] = 1
    return Mb


def exact(sens, r, secondes, fils, plafonds=None, indice=None):
    """Caractéristique de poids minimal sur r tours (S puis M, r fois). d_t : différence ou masque à l'entrée des S-box du
    tour t ; u_t : à leur sortie. Différentiel : d_{t+1} = M u_t. Linéaire : u_t = Mᵀ d_{t+1} (transposée binaire).
    Poids exacts par S-box active : DDT 4 → 2 bits, DDT 2 → 3 bits ; |LAT| 4 → 1 bit, |LAT| 2 → 2 bits."""
    from ortools.sat.python import cp_model
    Mb = binaire()
    m = cp_model.CpModel()
    d = [[m.NewBoolVar("") for _ in range(NB)] for _ in range(r)]
    u = [[m.NewBoolVar("") for _ in range(NB)] for _ in range(r)]
    poids = []
    actives = [[] for _ in range(r)]
    for t in range(r):
        for q in range(N):
            ins = d[t][4 * q:4 * q + 4]
            outs = u[t][4 * q:4 * q + 4]
            w = m.NewIntVar(0, 4, "")
            permis = []
            for a in range(16):
                for b in range(16):
                    if sens == "diff" and DDT[a, b] > 0:
                        wt = 0 if a == 0 else int(round(4 - np.log2(DDT[a, b])))
                    elif sens == "lin" and LAT[b, a] != 0:          # entrée a (masque d'entrée), sortie b
                        wt = 0 if b == 0 else int(round(3 - np.log2(abs(LAT[b, a]))))
                    else:
                        continue
                    permis.append([a >> k & 1 for k in range(4)] + [b >> k & 1 for k in range(4)] + [wt])
            m.AddAllowedAssignments(ins + outs + [w], permis)
            act = m.NewBoolVar("")                       # S-box active ⇔ entrée non nulle ⇔ poids ≥ 1
            m.AddBoolOr(ins).OnlyEnforceIf(act)
            for v in ins:
                m.AddImplication(v, act)
            m.Add(w >= (2 if sens == "diff" else 1) * act)
            actives[t].append(act)
            poids.append(w)
        if t + 1 < r:
            for k in range(NB):
                if sens == "diff":                       # d_{t+1}[k] = ⊕_i Mb[k, i] u_t[i]
                    src = [u[t][i] for i in np.nonzero(Mb[k])[0]]
                    m.AddBoolXOr(src + [d[t + 1][k].Not()])
                else:                                    # u_t[i] = ⊕_k Mb[k, i] d_{t+1}[k]   (u_t = Mᵀ d_{t+1})
                    src = [d[t + 1][j] for j in np.nonzero(Mb[:, k])[0]]
                    m.AddBoolXOr(src + [u[t][k].Not()])
    m.AddBoolOr(d[0])                                    # caractéristique non triviale
    # contraintes redondantes PROUVÉES (elles n'excluent aucune caractéristique réelle, elles aident la borne du solveur) :
    # chaque tour a une S-box active (S et M bijectives), 2 tours consécutifs en ont ≥ B = 8, 3 tours ≥ C3 = 21 (certifié,
    # ../sat/README.md ; la même borne vaut en linéaire)
    A = [sum(actives[t]) for t in range(r)]
    for t in range(r):
        m.Add(A[t] >= 1)
        if t + 1 < r:
            m.Add(A[t] + A[t + 1] >= 8)
        if t + 2 < r:
            m.Add(A[t] + A[t + 1] + A[t + 2] >= 21)
    if plafonds:                                         # restriction (borne HAUTE seulement) : S-box actives par tour
        for t, p in enumerate(plafonds):
            if p is not None:
                m.Add(A[t] <= p)
    if indice:                                           # point de départ : une caractéristique déjà trouvée
        for t, e in enumerate(indice):
            for q in range(N):
                a_, b_ = int(e["entree"].get(str(q), 0)), int(e["sortie"].get(str(q), 0))
                for k in range(4):
                    m.AddHint(d[t][4 * q + k], a_ >> k & 1)
                    m.AddHint(u[t][4 * q + k], b_ >> k & 1)
    m.Minimize(sum(poids))
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = secondes
    s.parameters.num_workers = fils
    t0 = time.time()
    st = s.Solve(m)
    res = {"sens": sens, "tours": r, "statut": s.StatusName(st), "s": round(time.time() - t0), "plafonds": plafonds,
           "restreint": bool(plafonds and any(p is not None for p in plafonds))}
    if st in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        res["poids_trouve_bits"] = int(s.ObjectiveValue())
        res["borne_basse_bits"] = int(s.BestObjectiveBound())
        res["sbox_actives"] = [sum(1 for q in range(N) if any(s.Value(v) for v in d[t][4 * q:4 * q + 4])) for t in range(r)]
        res["borne_prouvee_bits"] = borne_prouvee(sens, r)
        car = [[int(sum(s.Value(d[t][4 * q + b]) << b for b in range(4))) for q in range(N)] for t in range(r)]
        sor = [[int(sum(s.Value(u[t][4 * q + b]) << b for b in range(4))) for q in range(N)] for t in range(r)]
        res["verifiee"] = verifier(sens, car, sor) == res["poids_trouve_bits"]
        res["caracteristique"] = [{"tour": t, "entree": {q: car[t][q] for q in range(N) if car[t][q]},
                                   "sortie": {q: sor[t][q] for q in range(N) if sor[t][q]}} for t in range(r)]
    return res


def actives_min(r):
    """Borne basse prouvée du nombre de S-box actives sur r tours : découpage en blocs de 3 (≥ 21), 2 (≥ 8), 1 (≥ 1)."""
    f = [0, 1, 8, 21]
    for k in range(4, r + 1):
        f.append(max(f[k - j] + f[j] for j in (1, 2, 3)))
    return f[r]


def borne_prouvee(sens, r):
    return (2 if sens == "diff" else 1) * actives_min(r)


def verifier(sens, car, sor):
    """Recalcule le poids d'une caractéristique (tables de la S-box et couche linéaire indépendantes du modèle CP-SAT) ;
    rend None si une transition est impossible ou si la couche linéaire n'est pas respectée."""
    p = 0
    for t in range(len(car)):
        for q in range(N):
            a, b = car[t][q], sor[t][q]
            if sens == "diff":
                if DDT[a, b] == 0:
                    return None
                p += 0 if a == 0 else 4 - int(np.log2(DDT[a, b]))
            else:
                if LAT[b, a] == 0:
                    return None
                p += 0 if b == 0 else 3 - int(np.log2(abs(LAT[b, a])))
        if t + 1 < len(car):
            if sens == "diff":
                ok = diffuse(np.array([sor[t]], np.uint8))[0].tolist() == car[t + 1]
            else:
                ok = diffuseT(np.array([car[t + 1]], np.uint8))[0].tolist() == sor[t]
            if not ok:
                return None
    return p


def main():
    if sys.argv[1] == "faisceau":
        tours = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        K = int(sys.argv[3]) if len(sys.argv) > 3 else 300
        L = int(sys.argv[4]) if len(sys.argv) > 4 else 10
        g = int(sys.argv[5]) if len(sys.argv) > 5 else 5
        print(json.dumps({"controle_couches": controle_couches()}), flush=True)
        for sens in ("diff", "lin"):
            t0 = time.time()
            b = faisceau(sens, tours, K, L, g + (sens == "lin"))
            print(json.dumps({"faisceau": sens, "K": K, "L": L, "graine": g, "meilleur_poids_bits": b,
                              "s": round(time.time() - t0)}), flush=True)
    elif sys.argv[1] == "exact":
        sens, r = sys.argv[2], int(sys.argv[3])
        sec = float(sys.argv[4]) if len(sys.argv) > 4 else 600
        fils = int(sys.argv[5]) if len(sys.argv) > 5 else 4
        plaf = None
        if len(sys.argv) > 6 and sys.argv[6] != "-":       # ex. « 1,-,- » : au plus 1 S-box active au tour 0
            plaf = [None if v == "-" else int(v) for v in sys.argv[6].split(",")]
        ind = json.load(open(sys.argv[7]))["caracteristique"] if len(sys.argv) > 7 else None
        print(json.dumps(exact(sens, r, sec, fils, plaf, ind)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
