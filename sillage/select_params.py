# -*- coding: utf-8 -*-
"""
select_params.py — Curation des paramètres figés de BRUME v1.
=============================================================

Sélectionne (de façon déterministe, seed fixée) :

  1. la S-box 4 bits : parmi des permutations aléatoires, celles qui
     atteignent les optima théoriques des bijections 4x4 —
     uniformité différentielle U = 4, nonlinéarité NL = 4 (max |LAT| = 4),
     aucun point fixe, degré algébrique 3, immunité algébrique >= 2 —
     en minimisant le nombre d'entrées maximales du DDT et du LAT
     (moins de transitions probables -> moins de trails) ;

  2. le graphe de diffusion : graphe de Cayley 6-régulier sur 128 sommets,
     connexe, avec max |N(i) ∩ N(j)| + 2·[i~j] <= 5 (borne utilisée par le
     lemme wide-trail), det(A ⊕ I) ≠ 0 sur GF(2), en minimisant λ*
     (plus grande valeur propre non triviale en valeur absolue ;
     la borne d'Alon–Boppana vaut 2·sqrt(5) ≈ 4.4721) ;

  3. les coefficients de diffusion c(j,i) ∈ GF(16)* sur le support de
     A ⊕ I, sous contraintes de sécurité locales :
       (a) chaque ligne : 7 coefficients distincts, somme ≠ 0 ;
       (b) chaque colonne : idem (tue le trail itératif, diff et lin) ;
       (c) ratios M[p,i]/M[p,i'] deux à deux distincts sur le chevauchement
           de toute paire de colonnes (lemme wide-trail poids 2-3, diff) ;
       (d) symétrique par paires de lignes (propagation linéaire M^T) ;
       (e) det(M) ≠ 0 sur GF(16).

Produit tables_figees.py (avec empreintes SHA-256 de contrôle).
"""
import hashlib
import random
from math import gcd, sqrt

import numpy as np

N, DEG = 128, 6
POLY = 0x13  # x^4 + x + 1
AB = 2 * sqrt(5)  # borne d'Alon–Boppana pour d = 6


# ---------------------------------------------------------------------------
# GF(16)
# ---------------------------------------------------------------------------

def _gmul(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi:
            a ^= (POLY & 0xF)
        b >>= 1
    return p


GMUL = np.array([[_gmul(a, b) for b in range(16)] for a in range(16)],
                dtype=np.uint8)
GINV = np.zeros(16, dtype=np.uint8)
for a in range(1, 16):
    for b in range(1, 16):
        if GMUL[a, b] == 1:
            GINV[a] = b
            break

X16 = np.arange(16)
INC = np.zeros((16, 16), dtype=np.int8)     # x ⊆ A
for A_ in range(16):
    for x_ in range(16):
        if (x_ & A_) == x_:
            INC[A_, x_] = 1
HALF = [((X16 >> k) & 1).astype(bool) for k in range(4)]

# ---------------------------------------------------------------------------
# 1) S-box
# ---------------------------------------------------------------------------


def gen_sbox(n_trials=60000, seed=0xA11CE):
    rng = np.random.default_rng(seed)
    best, best_score, n_ok = None, None, 0
    B = 4096
    for _ in range(n_trials // B):
        perms = np.array([rng.permutation(16) for _ in range(B)],
                         dtype=np.uint8)               # (B,16)
        Sp = perms[:, X16]
        # DDT
        ddt = np.zeros((B, 16, 16), dtype=np.int16)
        for a in range(1, 16):
            d = Sp ^ perms[:, X16 ^ a]
            ddt[:, a, :] = (d[:, :, None] == np.arange(16)[None, None, :]
                            ).sum(axis=1)
        umax = ddt[:, 1:, :].max(axis=(1, 2))
        # LAT : lat[α=sortie, λ=entrée] = #{x : α·S(x) = λ·x} - 8 = W/2
        bits = (((Sp[:, None, :] >> np.arange(4)[None, :, None]) & 1)
                .astype(np.int32))                       # (B,4,16)
        sign = 1 - 2 * bits                              # (B,4,16)
        XM = (1 - 2 * np.array([[(λ_ >> x_) & 1 for x_ in range(16)]
                                for λ_ in range(16)], dtype=np.int32))
        W = np.einsum("bkx,lx->bkl", sign, XM)          # (B,4,16)
        lat = W // 2                                     # (B, k=sortie, λ=entrée)
        # max |LAT| sur les composants non triviaux (exclut (α=0, λ=0))
        latmax = np.abs(lat[:, 1:, :]).max(axis=(1, 2))
        # critères durs
        ok = (umax == 4) & (latmax == 4) & ~((Sp == X16[None, :]).any(axis=1))
        if not ok.any():
            continue
        # degré algébrique = 3 pour les 4 composants (transformée de Möbius)
        coef = np.einsum("bkx,Ax->bkA", bits, INC) % 2   # (B,4,16)
        POP = np.array([bin(a).count("1") for a in range(16)])  # poids du monôme
        deg = np.where(coef > 0, POP[None, None, :], 0).max(axis=2)
        ok &= (deg == 3).all(axis=1)
        # immunité algébrique >= 2 : f non constante sur chaque moitié
        # (aucun annihilateur de degré <= 1 : x_ℓ et 1⊕x_ℓ exclus)
        for k in range(4):
            for h in HALF:
                for hh in (h, ~h):
                    ff = bits[:, k, :][:, hh]
                    ok &= ff.any(axis=1) & (~ff).any(axis=1)
        if not ok.any():
            continue
        n_ok += int(ok.sum())
        idxs = np.nonzero(ok)[0]
        for i in idxs:
            d = ddt[i]
            n_ddt4 = int(((d[1:] == 4).sum()))
            n_lat4 = int((np.abs(lat[i]) == 4).sum())
            score = (n_ddt4, n_lat4)
            if best_score is None or score < best_score:
                best_score, best = score, perms[i].copy()
    assert best is not None, "aucune S-box optimale trouvée"
    return best.tolist(), {"candidats_valides": n_ok,
                           "score(nDDT4,nLAT4)": list(best_score)}


# ---------------------------------------------------------------------------
# 2) Graphe de Cayley 6-régulier
# ---------------------------------------------------------------------------

def _op_D128(a, b):
    aa, ab = a & 63, (a >> 6) & 1
    ba, bb = b & 63, (b >> 6) & 1
    ra = (aa + (ba if ab == 0 else (-ba) % 64)) % 64
    return ra | ((ab ^ bb) << 6)


def _inv_D128(a):
    aa, ab = a & 63, (a >> 6) & 1
    return (((-aa) % 64) if ab == 0 else aa) | (ab << 6)


def _op_Z4Z32(a, b):
    x, y = a & 3, a >> 2
    u, v = b & 3, b >> 2
    return ((x + u) % 4) | (((y + v) % 32) << 2)


def _inv_Z4Z32(a):
    x, y = a & 3, a >> 2
    return ((4 - x) % 4) | (((32 - y) % 32) << 2)


GROUPS = {
    "D128": {"op": _op_D128, "inv": _inv_D128,
             "gen_pool": [a | 64 for a in range(64)],     # réflexions
             "k_gens": 6},
    "Z4Z32": {"op": _op_Z4Z32, "inv": _inv_Z4Z32,
              "gen_pool": None,                           # construit plus bas
              "k_gens": 3},
}
# directions de Z4Z32 : paires {g, g^-1} (non involutions)
_dirs = []
for y in range(32):
    _dirs.append(1 | (y << 2))            # (1,y), direction {(1,y),(3,-y)}
for y in range(1, 16):
    _dirs.append(2 | (y << 2))            # (2,y), direction {(2,y),(2,-y)}
GROUPS["Z4Z32"]["gen_pool"] = _dirs


def _adjacency(gens, group):
    op, inv = group["op"], group["inv"]
    A = np.zeros((N, N), dtype=np.uint8)
    for x in range(N):
        for g in gens:
            y1, y2 = op(x, g), op(x, inv(g))
            A[x, y1] = A[y1, x] = 1
            A[x, y2] = A[y2, x] = 1
    return A


def _connected(A):
    seen = np.zeros(N, dtype=bool)
    stack = [0]
    seen[0] = True
    while stack:
        x = stack.pop()
        for y in np.nonzero(A[x])[0]:
            if not seen[y]:
                seen[y] = True
                stack.append(int(y))
    return bool(seen.all())


def _max_chev(A):
    """max_{i<j} (|N(i)∩N(j)| + 2·[i~j]) — doit rester <= 5."""
    P = A.astype(np.int16)
    inter = P @ P                       # |N(i)∩N(j)| (A symétrique, 0 diag)
    adj = A - np.eye(N, dtype=np.uint8)
    chev = inter + 2 * adj.astype(np.int16)
    iu = np.triu_indices(N, 1)
    return int(chev[iu].max())


def _det_gf2(M):
    M = M.astype(np.uint8) & 1
    n = M.shape[0]
    r = 0
    for c in range(n):
        piv = None
        for k in range(r, n):
            if M[k, c]:
                piv = k
                break
        if piv is None:
            return 0
        M[[r, piv]] = M[[piv, r]]
        for k in range(r + 1, n):
            if M[k, c]:
                M[k] ^= M[r]
        r += 1
    return 1


def gen_graph(n_D128=1400, n_Z4Z32=900, seed=0xBEA75):
    rng = random.Random(seed)
    best = None
    for gname, n_try in (("D128", n_D128), ("Z4Z32", n_Z4Z32)):
        g = GROUPS[gname]
        pool = g["gen_pool"]
        for _ in range(n_try):
            gens = rng.sample(pool, g["k_gens"])
            A = _adjacency(gens, g)
            if (A.sum(axis=1) != DEG).any() or not _connected(A):
                continue
            mc = _max_chev(A)
            if mc > 5 or not _det_gf2(A + np.eye(N, dtype=np.uint8)):
                continue
            ev = np.linalg.eigvalsh(A.astype(float))
            lam = float(np.abs(ev[1:-1]).max())   # exclut ±6
            cand = (lam, mc, gname, gens, A)
            if best is None or lam < best[0]:
                best = cand
    assert best is not None, "aucun graphe valide trouvé"
    lam, mc, gname, gens, A = best
    return gname, gens, A, {"lambda_etoile": round(lam, 4),
                            "alon_boppana_2sqrt5": round(AB, 4),
                            "ramanujan": bool(lam <= AB),
                            "max_chev": mc}


# ---------------------------------------------------------------------------
# 3) Coefficients de diffusion
# ---------------------------------------------------------------------------


def _lignes(ADJ):
    return [sorted(set(np.nonzero(ADJ[j])[0].tolist()) | {j}) for j in range(N)]


def _tirer_ligne(rng):
    while True:
        v = rng.sample(range(1, 16), DEG + 1)
        s = 0
        for x in v:
            s ^= x
        if s != 0:
            return v


class Constraintes:
    """Liste précalculée des contraintes sur les coefficients + collecte
    vectorisée des violations."""

    def __init__(self, LN):
        self.LN = LN
        # contraintes 'col' : colonne i aux positions LN[i]
        self.col_pos = [np.array(LN[i], dtype=np.int32) for i in range(N)]
        # contraintes 'rco' : ratios de paires de colonnes
        ci, cip, cp, cq = [], [], [], []
        for i in range(N):
            for ip in range(i + 1, N):
                P = sorted(set(LN[i]) & set(LN[ip]))
                for a in range(len(P)):
                    for b in range(a + 1, len(P)):
                        ci.append(i)
                        cip.append(ip)
                        cp.append(P[a])
                        cq.append(P[b])
        self.rco = tuple(np.array(x, dtype=np.int32) for x in (ci, cip, cp, cq))
        # contraintes 'rli' : ratios de paires de lignes
        lj, ljp, lp, lq = [], [], [], []
        for j in range(N):
            for jp in range(j + 1, N):
                Q = sorted(set(LN[j]) & set(LN[jp]))
                for a in range(len(Q)):
                    for b in range(a + 1, len(Q)):
                        lj.append(j)
                        ljp.append(jp)
                        lp.append(Q[a])
                        lq.append(Q[b])
        self.rli = tuple(np.array(x, dtype=np.int32) for x in (lj, ljp, lp, lq))
        # fautes locales par ligne : liste des indices de contraintes concernées
        self.local_col = [[] for _ in range(N)]
        for i in range(N):
            for j in LN[i]:
                self.local_col[j].append(i)
        self.local_rco = [[] for _ in range(N)]
        ci, cip, cp, cq = self.rco
        for k in range(len(ci)):
            self.local_rco[cp[k]].append(k)
            self.local_rco[cq[k]].append(k)
        self.local_rli = [[] for _ in range(N)]
        lj, ljp, lp, lq = self.rli
        for k in range(len(lj)):
            self.local_rli[lj[k]].append(k)
            self.local_rli[ljp[k]].append(k)

    def collect(self, COEF):
        """Nombre total de violations + contraintes fautives (kind, idx)."""
        bad = []
        # (a) lignes
        for j in range(N):
            vals = COEF[j, self.col_pos[j]]
            s = 0
            for v in vals:
                s ^= int(v)
            if len(set(vals.tolist())) != len(vals) or s == 0:
                bad.append(("lin", j))
        # (b) colonnes
        for i in range(N):
            vals = COEF[self.col_pos[i], i]
            s = 0
            for v in vals:
                s ^= int(v)
            if len(set(vals.tolist())) != len(vals) or s == 0:
                bad.append(("col", i))
        # (c) ratios colonnes : COEF[p,i]·COEF[q,ip] == COEF[q,i]·COEF[p,ip]
        ci, cip, cp, cq = self.rco
        lhs = GMUL[COEF[cp, ci], COEF[cq, cip]]
        rhs = GMUL[COEF[cq, ci], COEF[cp, cip]]
        for k in np.nonzero(lhs == rhs)[0]:
            bad.append(("rco", int(k)))
        # (d) ratios lignes : COEF[j,p]·COEF[jp,q] == COEF[jp,p]·COEF[j,q]
        lj, ljp, lp, lq = self.rli
        lhs = GMUL[COEF[lj, lp], COEF[ljp, lq]]
        rhs = GMUL[COEF[ljp, lp], COEF[lj, lq]]
        for k in np.nonzero(lhs == rhs)[0]:
            bad.append(("rli", int(k)))
        return len(bad), bad

    def local_faults(self, j, COEF):
        """Violations impliquant la ligne j (delta exact d'un re-tirage)."""
        cnt = 0
        # (a) la ligne j elle-même
        vals = COEF[j, self.col_pos[j]]
        s = 0
        for v in vals:
            s ^= int(v)
        if len(set(vals.tolist())) != len(vals) or s == 0:
            cnt += 2
        # (b) colonnes touchées par la ligne j
        for i in self.local_col[j]:
            vals = COEF[self.col_pos[i], i]
            s = 0
            for v in vals:
                s ^= int(v)
            if len(set(vals.tolist())) != len(vals) or s == 0:
                cnt += 2
        k = np.array(self.local_rco[j], dtype=np.int64)
        if len(k):
            ci, cip, cp, cq = self.rco
            lhs = GMUL[COEF[cp[k], ci[k]], COEF[cq[k], cip[k]]]
            rhs = GMUL[COEF[cq[k], ci[k]], COEF[cp[k], cip[k]]]
            cnt += int((lhs == rhs).sum())
        k = np.array(self.local_rli[j], dtype=np.int64)
        if len(k):
            lj, ljp, lp, lq = self.rli
            lhs = GMUL[COEF[lj[k], lp[k]], COEF[ljp[k], lq[k]]]
            rhs = GMUL[COEF[ljp[k], lp[k]], COEF[lj[k], lq[k]]]
            cnt += int((lhs == rhs).sum())
        return cnt


def _det_gf16_nonnul(M):
    a = M.astype(np.uint8) % 16
    n = a.shape[0]
    r = 0
    for c in range(n):
        piv = None
        for k in range(r, n):
            if a[k, c]:
                piv = k
                break
        if piv is None:
            return False
        a[[r, piv]] = a[[piv, r]]
        ip = int(GINV[a[r, c]])
        a[r] = GMUL[ip][a[r]]
        for k in range(r + 1, n):
            if a[k, c]:
                a[k] ^= GMUL[int(a[k, c])][a[r]]
        r += 1
    return True


def gen_coef(ADJ, seed=0xC0FFEE, max_restarts=6):
    LN = _lignes(ADJ)
    C = Constraintes(LN)
    rng = random.Random(seed)

    def cellules_de(kind, idx):
        if kind == "lin":
            return [(idx, i) for i in LN[idx]]
        if kind == "col":
            return [(k, idx) for k in LN[idx]]
        if kind == "rco":
            ci, cip, cp, cq = C.rco
            return [(int(cp[idx]), int(ci[idx])), (int(cp[idx]), int(cip[idx])),
                    (int(cq[idx]), int(ci[idx])), (int(cq[idx]), int(cip[idx]))]
        lj, ljp, lp, lq = C.rli
        return [(int(lj[idx]), int(lp[idx])), (int(ljp[idx]), int(lp[idx])),
                (int(lj[idx]), int(lq[idx])), (int(ljp[idx]), int(lq[idx]))]

    for attempt in range(max_restarts):
        COEF = np.zeros((N, N), dtype=np.uint8)
        for j in range(N):
            vals = _tirer_ligne(rng)
            for i, v in zip(LN[j], vals):
                COEF[j, i] = v
        # phase A : satisfaire les colonnes (b) par re-tirages min-conflits
        for it in range(300):
            ncols = 0
            for i in range(N):
                vals = COEF[C.col_pos[i], i]
                s = 0
                for v in vals:
                    s ^= int(v)
                if len(set(vals.tolist())) != len(vals) or s == 0:
                    ncols += 1
            if ncols == 0:
                break
            for j in rng.sample(range(N), 40):
                cur = sum(2 for i in C.local_col[j]
                          if (lambda vv: len(set(vv.tolist())) != len(vv)
                              or (lambda ss: ss == 0)(int(np.bitwise_xor.reduce(vv))))(COEF[C.col_pos[i], i]))
                if cur == 0:
                    continue
                best_vals, best_cnt = None, cur
                backup = COEF[j].copy()
                for _ in range(8):
                    vals = _tirer_ligne(rng)
                    for i, v in zip(LN[j], vals):
                        COEF[j, i] = v
                    c = sum(2 for i in C.local_col[j]
                            if (lambda vv: len(set(vv.tolist())) != len(vv)
                                or (lambda ss: ss == 0)(int(np.bitwise_xor.reduce(vv))))(COEF[C.col_pos[i], i]))
                    if c < best_cnt:
                        best_cnt, best_vals = c, vals
                    if best_cnt == 0:
                        break
                if best_vals is not None and best_cnt < cur:
                    for i, v in zip(LN[j], best_vals):
                        COEF[j, i] = v
                else:
                    COEF[j] = backup
        # phase B : mouvements unitaires sur chaque contrainte fautive
        for it in range(8000):
            n, bad = C.collect(COEF)
            if n == 0:
                break
            improved = False
            for kind, idx in bad[:80]:
                for (r, c) in cellules_de(kind, idx):
                    cur = C.local_faults(r, COEF)
                    old = int(COEF[r, c])
                    best_v, best_f = None, cur
                    vals_order = list(range(1, 16))
                    rng.shuffle(vals_order)
                    for v in vals_order:
                        if v == old:
                            continue
                        COEF[r, c] = v
                        f = C.local_faults(r, COEF)
                        if f < best_f:
                            best_f, best_v = f, v
                            if f == 0:
                                break
                    if best_v is not None:
                        COEF[r, c] = best_v
                        improved = True
                        break
                    COEF[r, c] = old
            if not improved:
                j = rng.randrange(N)
                vals = _tirer_ligne(rng)
                for i, v in zip(LN[j], vals):
                    COEF[j, i] = v
        n, _ = C.collect(COEF)
        if n == 0:
            M = np.zeros((N, N), dtype=np.uint8)
            for j in range(N):
                for i in LN[j]:
                    M[j, i] = COEF[j, i]
            if _det_gf16_nonnul(M):
                return COEF.tolist(), {"restarts": attempt,
                                       "det_non_nul": True}
    raise RuntimeError("pas de coefficients valides trouvés")


# ---------------------------------------------------------------------------
# Main : fige les tables
# ---------------------------------------------------------------------------


def _sha(obj):
    return hashlib.sha256(repr(obj).encode()).hexdigest()[:16]


def main():
    import os
    import json
    import sys
    _ici = os.path.dirname(os.path.abspath(__file__))
    etape = sys.argv[1] if len(sys.argv) > 1 else "tout"
    cache = os.path.join(_ici, "..", "resultats", "cache_params.json")
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    if etape in ("1", "tout"):
        sbox, sstats = gen_sbox()
        print(f"[1/3] S-box : U=4, NL=4, sans point fixe, deg=3, IA>=2 — "
              f"{sstats['candidats_valides']} candidates, score "
              f"{sstats['score(nDDT4,nLAT4)']}", flush=True)
        gname, gens, _, gstats = gen_graph()
        print(f"[2/3] Graphe : Cayley({gname}) — λ* = {gstats['lambda_etoile']} "
              f"(Alon–Boppana {gstats['alon_boppana_2sqrt5']}, "
              f"Ramanujan: {gstats['ramanujan']}), max_chev = {gstats['max_chev']}",
              flush=True)
        json.dump({"SBOX": sbox, "GROUP": gname, "GENS": gens,
                   "sstats": sstats, "gstats": gstats}, open(cache, "w"))
        if etape == "1":
            return
    d = json.load(open(cache))
    sbox, gname, gens = d["SBOX"], d["GROUP"], d["GENS"]
    ADJ = _adjacency(gens, GROUPS[gname])
    coef, cstats = gen_coef(ADJ)
    print(f"[3/3] Coefficients : contraintes (a)-(e) satisfaites "
          f"({cstats['restarts']} restarts)", flush=True)

    payload = {
        "SBOX": sbox,
        "GROUP": gname,
        "GENS": gens,
        "COEF": coef,
    }
    checks = {k: _sha(v) for k, v in payload.items()}
    sortie = os.path.join(_ici, "brume512_tables.py")
    with open(sortie, "w", encoding="utf-8") as f:
        f.write("# -*- coding: utf-8 -*-\n")
        f.write('"""GÉNÉRÉ par select_params.py — ne pas éditer à la main."""\n')
        for k, v in payload.items():
            f.write(f"{k} = {v!r}\n")
        f.write(f"CHECK = {checks!r}\n")
    print("brume512_tables.py écrit (racine du package sillage) :", checks)


if __name__ == "__main__":
    main()
