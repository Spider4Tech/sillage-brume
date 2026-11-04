# -*- coding: utf-8 -*-
"""Batterie statistique à grande échelle (noyau C) — type NIST SP 800-22
étendue, sur 1 Gio (le test Python : 128 Ko).

Flux :
  - mode compteur, 32 tours : bloc i = débit de P(clé ⊕ i), i sur la
    capacité (entrées de faible distance de Hamming : cas défavorable) ;
  - 12 éponges indépendantes en essorage, 32 tours ;
  - mode compteur sur tours réduits (2 à 8) : portée statistique.
Tests par flux : fréquence (monobit), poids des blocs de 32 o (binomiale),
fréquence par blocs de 1 Kio, runs, longueurs des runs (géométrique),
sériel 16 bits (∇ψ², ∇²ψ²), octets, paires d'octets (65 536 cases),
octets par position dans le bloc, autocorrélations (21 décalages), rang des
matrices 32×32, complexité linéaire (Berlekamp–Massey, M = 1000).
Décision : Bonferroni sur l'ensemble des p-valeurs d'un flux (α = 10^-3)
et Kolmogorov–Smirnov d'uniformité des p-valeurs.
"""
import math

import numpy as np

from tests import noyau_c as C
from tests.commun import sauver
from sillage import brume512 as B

LAGS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 31, 32, 33, 64, 127, 128, 256, 512, 1024, 2048, 4096)
PI_LC = (0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833)
PI_RANG = (0.133636, 0.577576, 0.288788)          # ≤ 30, 31, 32


def chi2_regroupe(obs, prob):
    """χ² après regroupement des cases d'effectif attendu < 5 aux extrémités."""
    obs, att = np.asarray(obs, float), np.asarray(prob, float) * float(np.sum(obs))
    o, a = [], []
    co = ca = 0.0
    for x, e in zip(obs, att):
        co += x; ca += e
        if ca >= 5:
            o.append(co); a.append(ca); co = ca = 0.0
    if ca > 0 and a:
        o[-1] += co; a[-1] += ca
    return C.chi2_p(o, a)


def _binom(n):
    lg = [math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) - n * math.log(2)
          for k in range(n + 1)]
    return np.exp(lg)


def _psi2(cnt, n, m):
    s = int((cnt.astype(np.int64) ** 2).sum())
    return ((1 << m) * s - n * n) / n


def _bincount(v, taille):
    out = np.zeros(taille, np.int64)
    for i in range(0, len(v), 1 << 24):
        out += np.bincount(v[i:i + (1 << 24)], minlength=taille)
    return out


def batterie(buf, nb):
    """buf : nb octets utiles (+16 de marge). Renvoie {test: p-valeur}."""
    p, nbits = {}, 8 * nb
    L = C.charger()
    pop = np.zeros(nb // 32, np.uint32)
    L.bn_pop_blocs(buf, nb // 32, 32, pop)
    S = int(pop.sum())
    p["monobit"] = C.p_normale((2 * S - nbits) / math.sqrt(nbits))
    p["poids_blocs_32o"] = chi2_regroupe(np.bincount(pop, minlength=257), _binom(256))
    blocs = pop[: len(pop) // 32 * 32].reshape(-1, 32).sum(1) / 8192.0
    p["frequence_blocs_1Kio"] = C.igamc(len(blocs) / 2, 4 * 8192 * float(((blocs - .5) ** 2).sum()) / 2)
    runs = np.zeros(128, np.uint64)
    L.bn_runs(buf, nbits, runs)
    runs = runs.reshape(2, 64).astype(float)
    V, pi = runs.sum(), S / nbits
    p["runs"] = math.erfc(abs(V - 2 * nbits * pi * (1 - pi)) / (2 * math.sqrt(2 * nbits) * pi * (1 - pi)))
    geo = np.array([0.0] + [2.0 ** -k for k in range(1, 63)] + [2.0 ** -62])
    for b in (0, 1):
        p[f"longueurs_runs_{b}"] = chi2_regroupe(runs[b], geo)
    cnt = np.zeros(1 << 16, np.uint64)
    L.bn_motifs(buf, nbits, 16, cnt)
    c16 = cnt.astype(np.int64)
    c15 = c16[: 1 << 15] + c16[1 << 15:]
    c14 = c15[: 1 << 14] + c15[1 << 14:]
    p16, p15, p14 = _psi2(c16, nbits, 16), _psi2(c15, nbits, 15), _psi2(c14, nbits, 14)
    p["seriel_16_grad1"] = C.igamc(2 ** 14, (p16 - p15) / 2)
    p["seriel_16_grad2"] = C.igamc(2 ** 13, (p16 - 2 * p15 + p14) / 2)
    v8 = buf[:nb]
    oc = _bincount(v8, 256)
    p["octets"] = C.chi2_p(oc, np.full(256, nb / 256))
    v16 = buf[: nb // 2 * 2].view(np.uint16)
    pa = _bincount(v16, 1 << 16)
    p["paires_octets"] = C.chi2_p(pa, np.full(1 << 16, len(v16) / 65536))
    pos = v8[: nb // 32 * 32].reshape(-1, 32)
    pmin = min(C.chi2_p(_bincount(pos[:, j], 256), np.full(256, len(pos) / 256)) for j in range(32))
    p["octets_par_position"] = min(1.0, 32 * pmin)
    for lag in LAGS:
        neff = C.ctypes.c_int64(0)
        D = L.bn_autocorr(buf, nbits, lag, C.ctypes.byref(neff))
        p[f"autocorr_{lag}"] = C.p_normale((2 * D - neff.value) / math.sqrt(neff.value))
    h = np.zeros(33, np.uint64)
    L.bn_rangs(buf, nb // 128, h)
    obs = [float(h[:31].sum()), float(h[31]), float(h[32])]
    p["rang_32x32"] = C.chi2_p(obs, np.array(PI_RANG) * sum(obs))
    K = min(C.taille(15), nbits // 1000)
    lc = np.zeros(K, np.int32)
    L.bn_complexite(buf, 1000, K, lc)
    T = lc.astype(float) - 500.0                     # M = 1000 pair : T = L − M/2
    bins = np.array([(T <= -2.5).sum(), ((T > -2.5) & (T <= -1.5)).sum(), ((T > -1.5) & (T <= -.5)).sum(),
                     ((T > -.5) & (T <= .5)).sum(), ((T > .5) & (T <= 1.5)).sum(),
                     ((T > 1.5) & (T <= 2.5)).sum(), (T > 2.5).sum()], float)
    p["complexite_lineaire"] = C.chi2_p(bins, np.array(PI_LC) * K)
    return p


def verdict(p, alpha=1e-3):
    vals = list(p.values())
    pmin = min(vals)
    ks = C.ks_uniforme(vals)
    ok = pmin >= alpha / len(vals) and ks >= alpha
    return {"tests": len(vals), "p_min": float(f"{pmin:.3g}"), "test_p_min": min(p, key=p.get),
            "ks_uniformite": round(ks, 4), "conforme": ok,
            "p_valeurs": {k: float(f"{v:.4g}") for k, v in p.items()}}


def run():
    c, m = {}, {}
    C.charger()
    c["noyau_c_conforme"] = C.conformite()[0]
    rng = np.random.default_rng(31337)
    deb = B.RATE // 2
    pc, pp = C.debit_permutations()
    m["debit_permutations_32_tours"] = {"C": pc, "python": pp, "facteur": round(pc / pp)}
    n = C.taille(25)
    buf = C.flux_compteur(rng.integers(0, 16, B.N, dtype=np.uint8), n)
    v = verdict(batterie(buf, n * deb))
    m["compteur_32_tours"] = {"octets": n * deb, **v}
    c["flux_compteur_32_tours_conforme"] = v["conforme"]
    del buf
    q = C.taille(24) // 12
    buf = C.flux_eponge(rng.integers(0, 16, (12, B.N), dtype=np.uint8), q)
    v = verdict(batterie(buf, 12 * q * deb))
    m["eponge_32_tours"] = {"octets": 12 * q * deb, **v}
    c["flux_eponge_32_tours_conforme"] = v["conforme"]
    del buf
    reduits, portee = {}, 0
    n = C.taille(21)
    # témoin H0 : la même batterie sur un flux de référence indépendant de BRUME (SHAKE256). Sans lui, rien ne
    # vérifiait que la batterie accepte un vrai flux aléatoire (implémentation des tests, approximations
    # asymptotiques, KS sur des p-valeurs en partie corrélées) : un refus de BRUME n'aurait rien prouvé.
    import hashlib
    ref = np.frombuffer(hashlib.shake_256(b"SILLAGE temoin H0 batterie").digest(n * deb) + bytes(16), np.uint8).copy()
    v = verdict(batterie(ref, n * deb))
    m["temoin_h0_shake256"] = {"octets": n * deb, **{k: x for k, x in v.items() if k != "p_valeurs"}}
    c["temoin_h0_flux_de_reference_conforme"] = v["conforme"]
    del ref
    for R in (2, 3, 4, 5, 6, 8):
        buf = C.flux_compteur(rng.integers(0, 16, B.N, dtype=np.uint8), n, R)
        v = verdict(batterie(buf, n * deb))
        echecs = sorted(k for k, x in v["p_valeurs"].items() if x < 1e-3 / v["tests"])
        reduits[R] = {"conforme": v["conforme"], "p_min": v["p_min"], "tests_en_echec": echecs}
        if not v["conforme"]:
            portee = R
    m["compteur_tours_reduits"] = {"octets_par_flux": n * deb, "par_tour": reduits,
                                   "portee_statistique_tours": portee,
                                   "marge_tours": B.N_ROUNDS - portee}
    c["portee_statistique_inferieure_a_8_tours"] = portee < 8
    out = {"controles": c, "mesures": m}
    sauver("c_statistiques" + C.SUFFIXE, out)
    return out


if __name__ == "__main__":
    import json
    from tests.commun import _conv
    r = run()
    for k, v in r["mesures"].items():
        if isinstance(v, dict):
            v = {a: b for a, b in v.items() if a != "p_valeurs"}
        print(k, json.dumps(v, ensure_ascii=False, default=_conv))
    print(r["controles"])
