# -*- coding: utf-8 -*-
"""
trails.py — Recherche différentielle et linéaire automatisée sur BRUME v1.
==========================================================================

Méthode (protocole standard des analyses de permutations ARX/sponges,
adapté à la diffusion par graphe pondéré) :

  1. Propagation GREEDY par position. Pour une caractéristique
     différentielle, chaque S-box active de différence d'entrée a choisit
     sa différence de sortie maximisant DDT[a][·] ; le choix est
     séparable position par position car la diffusion est GF(2)-linéaire.
     La transition d'état est donc déterministe : Δ -> M·OPTOUT(Δ), avec
     un coût cumulé Σ_j −log2(DDT[Δ_j][Δ'_j]) en demi-bits (entiers).

  2. Énumération EXHAUSTIVE des états initiaux de poids 1 (1920 vecteurs)
     et de poids 2 (1 828 800 vecteurs : toutes les paires de nibbles
     actifs et toutes les valeurs non nulles), puis échantillonnage du
     poids 3. Chaque source est propagée sur 14 rounds : on obtient la
     meilleure caractéristique (dans l'espace greedy) pour chaque horizon.

  3. Propagation LINÉAIRE : même moteur sur les masques, avec la diffusion
     M^T et le LAT : corr(α·S(x) ⊕ λ·x) = LAT[α][λ]/8 ; le choix par
     position est le masque d'entrée maximisant |LAT|.

  4. Sondes aléatoires : tirages des sorties de S-box selon la loi DDT
     (au lieu du greedy) pour sonder les annulations inter-positions non
     couvertes par l'espace greedy.

  5. Variante v0 (coefficients = 1) : la caractéristique itérative
     1 -> 7 -> 1 -> 7 ... y est démontrée (théorème du README) : c'est ce
     qui motive les coefficients pondérés de v1.
"""
import json
import os

import numpy as np
from tests.commun import plt, RESULTATS

from sillage.brume512 import (GMUL, SBOX, N, DEG, E_I, E_C, E_SEG, E_I_T, E_C_T,
                        E_SEG_T, diffuse_batch, diffuse_T_batch, brume_v0,
                        GMUL_T)
from tests import banc_statiques as statiques

OUT = RESULTATS
os.makedirs(OUT, exist_ok=True)
HORIZON = 14


# ---------------------------------------------------------------------------
# Tables greedy et diffusion variante v0
# ---------------------------------------------------------------------------


def build_greedy_tables(ddt, lat):
    OPTOUT = np.zeros(16, dtype=np.uint8)
    COST = np.zeros(16, dtype=np.int64)      # demi-bits
    for a in range(16):
        row = ddt[a]
        b = int(np.argmax(row))
        OPTOUT[a] = b
        k = int(row[b])
        COST[a] = 8 - 2 * int(np.log2(k)) if k > 1 else 99
    OPTIN = np.zeros(16, dtype=np.uint8)
    COSTLIN = np.zeros(16, dtype=np.int64)
    for al in range(16):
        col = np.abs(lat[al])
        lam = int(np.argmax(col))
        OPTIN[al] = lam
        m = int(col[lam])
        COSTLIN[al] = 6 - 2 * int(np.log2(m)) if m > 1 else 99
    return OPTOUT, COST, OPTIN, COSTLIN


def diffuse_batch_w(state, weighted=True):
    if weighted:
        contrib = GMUL[E_C, state[:, E_I]]
    else:
        contrib = state[:, E_I]
    return np.bitwise_xor.reduceat(contrib, E_SEG[:-1], axis=1)


def diffuse_T_batch_w(state, weighted=True):
    if weighted:
        contrib = GMUL_T[E_C_T, state[:, E_I_T]]   # adjoint binaire exact
    else:
        contrib = state[:, E_I_T]
    return np.bitwise_xor.reduceat(contrib, E_SEG_T[:-1], axis=1)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


def sources_w1():
    st = np.zeros((128 * 15, N), dtype=np.uint8)
    rows = np.arange(128 * 15)
    st[rows, rows // 15] = (rows % 15 + 1).astype(np.uint8)
    return st, "w1"


def sources_w2_chunk(st_, n_pairs):
    """Générateur de chunks : toutes les paires × toutes les valeurs."""
    pairs = np.array([(i, j) for i in range(N) for j in range(i + 1, N)],
                     dtype=np.int32)
    vals = np.array([(a, b) for a in range(1, 16) for b in range(1, 16)],
                    dtype=np.uint8)
    P = len(pairs)
    V = len(vals)
    for st0 in range(0, P, n_pairs):
        pr = pairs[st0:st0 + n_pairs]
        m = len(pr)
        rows = np.arange(m * V)
        pr_idx = rows // V
        v_idx = rows % V
        state = np.zeros((m * V, N), dtype=np.uint8)
        state[rows, pr[pr_idx, 0]] = vals[v_idx, 0]
        state[rows, pr[pr_idx, 1]] = vals[v_idx, 1]
        yield state, ("w2", st0 * V, rows)


def sources_w3_sample(n=100_000, seed=11):
    rng = np.random.default_rng(seed)
    sup = np.sort(rng.integers(0, N, size=(n, 3)), axis=1)
    ok = (np.diff(sup, axis=1) > 0).all(axis=1)
    sup = sup[ok]
    state = np.zeros((len(sup), N), dtype=np.uint8)
    rows = np.arange(len(sup))[:, None]
    state[rows, sup] = rng.integers(1, 16, size=(len(sup), 3)).astype(np.uint8)
    return state, "w3"


# ---------------------------------------------------------------------------
# Moteur de propagation
# ---------------------------------------------------------------------------


def run_batch(state, n_rounds, direction, weighted=True):
    """Propage le batch ; renvoie mins[r] (demi-bits) et best_row[r]."""
    B = len(state)
    cost = np.zeros(B, dtype=np.int64)
    mins = {}
    best = {}
    for r in range(n_rounds):
        if direction == "diff":
            cost += COST[state].sum(axis=1)
            state = OPTOUT[state]
            state = diffuse_batch_w(state, weighted)
        else:
            alpha = diffuse_T_batch_w(state, weighted)
            cost += COSTLIN[alpha].sum(axis=1)
            state = OPTIN[alpha]
        alive = state.any(axis=1)
        if alive.any():
            idx_alive = np.nonzero(alive)[0]
            j = idx_alive[np.argmin(cost[idx_alive])]
            mins[r + 1] = int(cost[j])
            best[r + 1] = j
        else:
            mins[r + 1] = None
            best[r + 1] = None
    return mins, best


def sweep(kind, n_rounds=HORIZON, weighted=True, w2_chunk=500,
          w2_rounds=10, verbose=True):
    """Sweep complet : poids 1 exhaustif + poids 3 + poids 2 exhaustif
    (énumération complète, horizon w2_rounds : au-delà le coût par round
    des trails poids-2 (> 50 demi-bits) les sort de la compétition)."""
    best_mins, best_meta = {}, {}

    def merge(mins, meta):
        for r, m in mins.items():
            if m is not None and (r not in best_mins or m < best_mins[r]):
                best_mins[r] = m
                best_meta[r] = meta[r]

    st, _ = sources_w1()
    mins, b = run_batch(st, n_rounds, kind, weighted)
    merge(mins, {r: ("w1", int(b[r])) for r in b})
    st3, _ = sources_w3_sample(50_000)
    mins, b = run_batch(st3, n_rounds, kind, weighted)
    merge(mins, {r: ("w3", int(b[r])) for r in b})
    if w2_rounds:
        for state, (tag2, base, rows) in sources_w2_chunk(None, w2_chunk):
            mins, b = run_batch(state, w2_rounds, kind, weighted)
            merge(mins, {r: ("w2", int(base) + int(b[r])) for r in b})
    if verbose:
        lab = {"diff": "différentiel", "lin": "linéaire"}[kind]
        w = "v1" if weighted else "v0"
        print(f"  [{lab} {w}] meilleur coût cumulé (demi-bits) :",
              {r: best_mins[r] for r in sorted(best_mins)}, flush=True)
    return best_mins, best_meta


def replay_trail(tag, row_hint, direction, n_rounds, weighted=True):
    """Rejoue un trail (greedy) et le détaille round par round."""
    if tag == "w1":
        st = np.zeros((1, N), dtype=np.uint8)
        st[0, row_hint // 15] = (row_hint % 15 + 1)
    elif tag == "w3":
        st3, _ = sources_w3_sample()
        st = st3[row_hint:row_hint + 1].copy()
    else:
        base = row_hint
        pairs = np.array([(i, j) for i in range(N) for j in range(i + 1, N)],
                         dtype=np.int32)
        vals = np.array([(a, b) for a in range(1, 16) for b in range(1, 16)],
                        dtype=np.uint8)
        V = len(vals)
        pair_idx = base // V
        val_idx = base % V
        st = np.zeros((1, N), dtype=np.uint8)
        st[0, pairs[pair_idx, 0]] = vals[val_idx, 0]
        st[0, pairs[pair_idx, 1]] = vals[val_idx, 1]
    trail = []
    s = st.copy()
    tot = 0
    for r in range(n_rounds):
        if direction == "diff":
            act = np.nonzero(s[0])[0]
            c = int(COST[s[0]].sum())
            tot += c
            trail.append({"round": r + 1, "sboxes_actives": len(act),
                          "positions": act.tolist()[:24],
                          "cout_demi_bits": c, "cout_cumule": tot})
            s = OPTOUT[s]
            s = diffuse_batch_w(s, weighted)
        else:
            alpha = diffuse_T_batch_w(s, weighted)
            act = np.nonzero(alpha[0])[0]
            c = int(COSTLIN[alpha].sum())
            tot += c
            trail.append({"round": r + 1, "sboxes_actives": len(act),
                          "positions": act.tolist()[:24],
                          "cout_demi_bits": c, "cout_cumule": tot})
            s = OPTIN[alpha]
    return trail


# ---------------------------------------------------------------------------
# Sondes aléatoires (annulations inter-positions)
# ---------------------------------------------------------------------------


def random_probes(n=20_000, n_rounds=HORIZON, direction="diff", seed=13):
    """Sondes Monte-Carlo : sorties tirées selon DDT (resp. LAT)."""
    rng = np.random.default_rng(seed)
    cdf = np.cumsum(DDT, axis=1).astype(np.float64)
    cdf = cdf / cdf[:, -1:]
    cdf_l = np.cumsum(np.abs(LAT), axis=1).astype(np.float64)
    cdf_l = cdf_l / cdf_l[:, -1:]
    state, _ = sources_w3_sample(n, seed=seed + 1)
    cost = np.zeros(len(state), dtype=np.int64)
    mins = {}
    for r in range(n_rounds):
        if direction == "diff":
            # tirage des sorties position par position
            out = np.zeros_like(state)
            for j in range(N):
                u = rng.random(len(state))
                crow = cdf[state[:, j]]
                out[:, j] = (crow <= u[:, None]).sum(axis=1).astype(np.uint8)
            cost += (8 - 2 * np.log2(np.maximum(DDT[state, out], 1))
                     ).sum(axis=1).astype(np.int64)
            state = diffuse_batch_w(out, True)
        else:
            alpha = diffuse_T_batch_w(state, True)
            cost += COSTLIN[alpha].sum(axis=1).astype(np.int64)
            inp = np.zeros_like(alpha)
            for j in range(N):
                u = rng.random(len(state))
                crow = cdf_l[alpha[:, j]]
                inp[:, j] = (crow <= u[:, None]).sum(axis=1).astype(np.uint8)
            cost += (6 - 2 * np.log2(np.maximum(np.abs(LAT[alpha, inp]), 1))
                     ).sum(axis=1).astype(np.int64)
            state = inp
        mins[r + 1] = int(cost.min())
    return mins


# ---------------------------------------------------------------------------
# Démonstration numérique du théorème v0 (caractéristique itérative)
# ---------------------------------------------------------------------------


def demo_v0_iteratif_exposant2(n_rounds=10):
    """Théorème (Cayley d'exposant 2, d PAIR, diffusion non pondérée A⊕I) :
    la caractéristique 1 → (d+1) → 1 → ... existe pour tout choix de d
    générateurs couvrants. Démonstration numérique sur Cayley((Z/2)^6)
    6-régulier (état réduit 64 nibbles — le mécanisme est structurel).
    Preuve : l'involution (d1,d2) ↦ (d2,d1) préserve d1⊕d2 = Δ en exposant 2
    et n'a pas de point fixe ; |S1| = d+1 impair maintient le centre actif.
    Dans les groupes d'exposant > 2, les Δ = 2d brisent le cycle exact
    (mesuré : 7,7,37,... sur Z/4×Z/32) — d'où le double choix de design de
    BRUME v1 : groupe NON abélien ET coefficients pondérés."""
    d_gens = [1, 2, 4, 8, 16, 32]               # (Z/2)^6 : XOR, d = 6 pair
    N2 = 64
    i0 = 0
    s = np.zeros((1, N2), dtype=np.uint8)
    s[0, i0] = 3
    supports = []
    Nbar = [ {j ^ g for g in d_gens} | {j} for j in range(N2) ]
    for r in range(n_rounds):
        s = OPTOUT[s]
        out = np.zeros((1, N2), dtype=np.uint8)
        for j in range(N2):
            acc = 0
            for i in Nbar[j]:
                acc ^= int(s[0, i])
            out[0, j] = acc
        s = out
        supports.append(int((s[0] != 0).sum()))
    return supports


# ---------------------------------------------------------------------------
# Figures et orchestration
# ---------------------------------------------------------------------------


def fig_trails(res):
    if plt is None:
        return
    fig, axs = plt.subplots(1, 2, figsize=(13, 4.8),
                            constrained_layout=True)
    ax = axs[0]
    for key, style in (("diff_v1", "o-"), ("lin_v1", "s-"),
                       ("diff_v0", "^--"), ("lin_v0", "v--")):
        m = res[key]
        rs = sorted(k for k in m if m[k] is not None)
        ys = [m[r] / 2 for r in rs]
        ax.plot(rs, ys, style, label=key, ms=4)
    rs = range(1, HORIZON + 1)
    ax.plot(rs, [7.0 * r for r in rs], "x:", color="crimson",
            label="diff v0 itératif (analytique, 7 bits/round)", ms=5)
    for seuil in (128, 256):
        ax.axhline(seuil, color="gray", ls=":", lw=0.9)
    ax.text(HORIZON - 0.4, 130, "2^-128", fontsize=8, color="gray")
    ax.text(HORIZON - 0.4, 258, "2^-256", fontsize=8, color="gray")
    ax.set_yscale("log")
    ax.set_xlabel("rounds")
    ax.set_ylabel("−log2(probabilité / corrélation) de la meilleure\n"
                  "caractéristique trouvée (bits)")
    ax.set_title("Meilleures caractéristiques (énum. exhaustive poids ≤ 2\n"
                 "+ échantillon poids 3, espace greedy)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    ax = axs[1]
    for key in ("diff_v1_sondes", "lin_v1_sondes"):
        m = res[key]
        rs = sorted(k for k in m if m[k] is not None)
        ax.plot(rs, [m[r] / 2 for r in rs], label=key, ms=4)
    ax.set_xlabel("rounds")
    ax.set_ylabel("−log2 (bits), sondes aléatoires")
    ax.set_title("Sondes Monte-Carlo (sorties tirées selon DDT/LAT)")
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3)
    fig.suptitle("Recherche différentielle / linéaire automatisée — "
                 "permutation BRUME v1", fontsize=12)
    fig.savefig(f"{OUT}/fig4_trails.png", dpi=150)
    plt.close(fig)


def fig_v0(res):
    if plt is None:
        return
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.6),
                             constrained_layout=True)
    ax = axes[0]
    sup = demo_v0_iteratif_exposant2()
    ax.plot(range(1, len(sup) + 1), sup, "ro-")
    ax.set_xlabel("round de diffusion")
    ax.set_ylabel("poids du support (nibbles actifs)")
    ax.set_title("Théorème (Cayley d'exposant 2, M = A⊕I) :\n"
                 "caractéristique itérative 1 → 7 → 1 démontrée")
    ax.set_ylim(0, 10)
    ax.grid(alpha=0.3)
    ax = axes[1]
    for key, style in (("diff_v0", "^--"), ("diff_v1", "o-")):
        m = res[key]
        rs = sorted(k for k in m if m[k] is not None)
        ax.plot(rs, [m[r] / 2 for r in rs], style, label=key)
    rs = range(1, HORIZON + 1)
    ax.plot(rs, [7.0 * r for r in rs], "x:", color="crimson",
            label="cycle itératif (Cayley exposant 2, analytique)", ms=5)
    ax.set_yscale("log")
    ax.set_xlabel("rounds")
    ax.set_ylabel("−log2 p (bits)")
    ax.set_title("v0 (non pondérée) vs v1 : les trails de v0 sont ~3x\n"
                 "moins coûteux ; le cycle d'exposant 2 est le pire cas")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.savefig(f"{OUT}/fig5_v0_iteratif.png", dpi=150)
    plt.close(fig)


def run():
    global DDT, LAT, OPTOUT, COST, OPTIN, COSTLIN
    ddt, lat = statiques.sbox_tables()
    DDT, LAT = ddt, lat
    OPTOUT, COST, OPTIN, COSTLIN = build_greedy_tables(ddt, lat)
    res = {}
    print("=== Recherche de trails — BRUME v1 ===", flush=True)
    cache = os.path.join(OUT, "cache_trails.json")
    if os.path.exists(cache):
        res = json.load(open(cache))
        for key in ("diff_v1", "lin_v1", "diff_v0", "lin_v0",
                    "diff_v1_sondes", "lin_v1_sondes"):
            res[key] = {int(k): v for k, v in res[key].items()}
        print("  [cache trails rechargé]", flush=True)
    else:
        m, meta = sweep("diff", weighted=True)
        res["diff_v1"] = m
        res["diff_v1_meta"] = {str(k): v for k, v in meta.items()}
        m, meta = sweep("lin", weighted=True)
        res["lin_v1"] = m
        res["lin_v1_meta"] = {str(k): v for k, v in meta.items()}
        m, meta = sweep("diff", weighted=False, w2_rounds=None)
        res["diff_v0"] = m
        m, meta = sweep("lin", weighted=False, w2_rounds=None)
        res["lin_v0"] = m
        res["diff_v1_sondes"] = random_probes(direction="diff")
        res["lin_v1_sondes"] = random_probes(direction="lin")
        json.dump(res, open(cache, "w"))
    res["v0_iteratif_exposant2_supports"] = demo_v0_iteratif_exposant2()
    # détail du meilleur trail différentiel v1 au plus grand horizon vivant
    r = max((int(k) for k in res["diff_v1_meta"]
             if res["diff_v1_meta"][k] is not None))
    tag, row = res["diff_v1_meta"][str(r)]
    res["meilleur_trail_diff_detail"] = {
        "source": [tag, int(row)], "rounds": r,
        "trail": replay_trail(tag, row, "diff", r)}
    r = max((int(k) for k in res["lin_v1_meta"]
             if res["lin_v1_meta"][k] is not None))
    tag, row = res["lin_v1_meta"][str(r)]
    res["meilleur_trail_lin_detail"] = {
        "source": [tag, int(row)], "rounds": r,
        "trail": replay_trail(tag, row, "lin", r)}
    fig_trails(res)
    fig_v0(res)
    with open(f"{OUT}/trails.json", "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2, default=str)
    return res


if __name__ == "__main__":
    run()
