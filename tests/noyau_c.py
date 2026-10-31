# -*- coding: utf-8 -*-
"""Pont vers le noyau C des tests intensifs (tests/c/noyau.c).

Compilation à la demande (gcc -O3 -march=native -fopenmp, résultat mis en
cache selon l'empreinte du source dans tests/c/build/), chargement ctypes.
Les tables viennent de sillage/brume512.py (source unique) ; charger()
vérifie la conformité avec l'implémentation Python (permutation directe
sur 1 à 32 tours, inverse) et refuse de servir un noyau divergent.

SILLAGE_INTENSITE=k (défaut 1) multiplie les tailles d'échantillons des
tests intensifs.
"""
import ctypes
import hashlib
import math
import os
import subprocess
import time

import numpy as np

from tests.commun import RACINE
from sillage import brume512 as B

N = B.N
SRC = os.path.join(RACINE, "tests", "c", "noyau.c")
BUILD = os.path.join(RACINE, "tests", "c", "build")
INTENSITE = float(os.environ.get("SILLAGE_INTENSITE", "1"))
# résultats d'une campagne poussée : resultats/<test>_x<k>.json (la batterie
# standard, intensité 1, garde resultats/<test>.json)
SUFFIXE = "" if INTENSITE == 1 else f"_x{INTENSITE:g}"

_u8 = np.ctypeslib.ndpointer(np.uint8, flags="C_CONTIGUOUS")
_i32 = np.ctypeslib.ndpointer(np.int32, flags="C_CONTIGUOUS")
_u32 = np.ctypeslib.ndpointer(np.uint32, flags="C_CONTIGUOUS")
_u64 = np.ctypeslib.ndpointer(np.uint64, flags="C_CONTIGUOUS")
_i64 = ctypes.c_int64
_lib = None


def taille(base_log2, plafond_log2=40):
    """2^base_log2 × INTENSITE (entier)."""
    return int(min(2 ** plafond_log2, round(2 ** base_log2 * INTENSITE)))


def _compiler():
    h = hashlib.sha256(open(SRC, "rb").read()).hexdigest()[:12]
    so = os.path.join(BUILD, f"noyau_{h}.so")
    if not os.path.exists(so):
        os.makedirs(BUILD, exist_ok=True)
        tmp = f"{so}.{os.getpid()}.tmp"
        subprocess.run(["gcc", "-O3", "-march=native", "-fopenmp", "-shared", "-fPIC",
                        SRC, "-o", tmp], check=True)
        os.replace(tmp, so)
    return ctypes.CDLL(so)


def _signatures(L):
    L.bn_init.restype = ctypes.c_int
    L.bn_init.argtypes = [ctypes.c_int, ctypes.c_int, _u8, _i32, _i32, _u8, _u8, _u8, _u8]
    L.bn_permute.argtypes = [_u8, _i64, ctypes.c_int, ctypes.c_int]
    L.bn_cube.argtypes = [_u8, _i32, ctypes.c_int, ctypes.c_int, ctypes.c_int, _u8]
    L.bn_cube_vec.argtypes = [_u8, _u8, ctypes.c_int, ctypes.c_int, ctypes.c_int, _u8]
    L.bn_diff.argtypes = [_u8, ctypes.c_int, ctypes.c_int, ctypes.c_int, _i64, ctypes.c_uint64,
                          ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), _u64]
    L.bn_lin.restype = ctypes.c_uint64
    L.bn_lin.argtypes = [_u8, _u8, ctypes.c_int, ctypes.c_int, _i64, ctypes.c_uint64]
    L.bn_lin_nib.argtypes = [_u8, ctypes.c_int, ctypes.c_int, ctypes.c_int, _i64,
                             ctypes.c_uint64, _u64]
    L.bn_sac.argtypes = [ctypes.c_int, ctypes.c_int, _i64, ctypes.c_uint64, _u64]
    L.bn_flux_compteur.argtypes = [_u8, _i64, ctypes.c_int, ctypes.c_int, _u8]
    L.bn_flux_eponge.argtypes = [_u8, ctypes.c_int, _i64, ctypes.c_int, ctypes.c_int, _u8]
    L.bn_pop_blocs.argtypes = [_u8, _i64, ctypes.c_int, _u32]
    L.bn_autocorr.restype = ctypes.c_uint64
    L.bn_autocorr.argtypes = [_u8, _i64, _i64, ctypes.POINTER(ctypes.c_int64)]
    L.bn_motifs.argtypes = [_u8, _i64, ctypes.c_int, _u64]
    L.bn_runs.argtypes = [_u8, _i64, _u64]
    L.bn_rangs.argtypes = [_u8, _i64, _u64]
    L.bn_complexite.argtypes = [_u8, ctypes.c_int, _i64, _i32]
    L.bn_kem_bruit.argtypes = [_i32, _i32, ctypes.c_int, _i64, _i64, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, np.ctypeslib.ndpointer(np.uint8), _i64, ctypes.c_uint64, _u64, _u64]


def matrice_inverse():
    return B._gauss_gf16_inverse(np.array([[B.TF.COEF[j][i] if B.ADJ_I[j, i] else 0
                                            for i in range(N)] for j in range(N)], np.uint8))


def inverse_python(X, R):
    """R derniers tours de P^-1 (référence Python)."""
    Minv, Sinv = matrice_inverse(), np.argsort(B.SBOX).astype(np.uint8)
    s = X.copy()
    for r in reversed(range(B.N_ROUNDS - R, B.N_ROUNDS)):
        s = np.bitwise_xor.reduce(B.GMUL[Minv[None, :, :], s[:, None, :]], axis=2)
        s = Sinv[s] ^ B.RC[r]
    return s


def charger():
    global _lib
    if _lib is not None:
        return _lib
    L = _compiler()
    _signatures(L)
    T = np.ascontiguousarray(np.stack(B._T_TOUR).astype(np.uint8))
    rc = np.ascontiguousarray(np.stack(B.RC).astype(np.uint8))
    assert L.bn_init(B.N_ROUNDS, len(B.E_I), T, np.ascontiguousarray(B.E_I, np.int32),
                     np.ascontiguousarray(B.E_SEG, np.int32),
                     np.ascontiguousarray(matrice_inverse()),
                     np.argsort(B.SBOX).astype(np.uint8), rc,
                     np.ascontiguousarray(B.GMUL, np.uint8)) == 0
    _lib = L
    ok, _ = conformite()
    if not ok:
        _lib = None
        raise RuntimeError("noyau C non conforme à sillage/brume512.py")
    return L


def conformite(n=64):
    """Compare le noyau C à Python : P sur 1..32 tours, P^-1∘P = id, P^-1
    (R derniers tours) contre la référence Python."""
    rng = np.random.default_rng(99)
    X = rng.integers(0, 16, (n, N), dtype=np.uint8)
    det = {}
    det["directe_1_a_32_tours"] = all(
        (permute(X, R) == B._permute_batch(X, R)).all() for R in (1, 2, 3, 5, 8, 13, 32))
    det["inverse_compose_identite"] = bool((permute(permute(X, 32), 32, 1) == X).all())
    det["inverse_tours_reduits"] = all(
        (permute(X[:8], R, 1) == inverse_python(X[:8], R)).all() for R in (1, 3))
    return all(det.values()), det


# ------------------------------------------------------------- enveloppes
def permute(X, R=B.N_ROUNDS, sens=0):
    L = charger() if _lib is None else _lib
    Y = np.ascontiguousarray(X, np.uint8).copy()
    L.bn_permute(Y, len(Y), R, sens)
    return Y


def cube(base, bits, R, sens=0):
    out = np.zeros(N, np.uint8)
    charger().bn_cube(np.ascontiguousarray(base, np.uint8),
                      np.ascontiguousarray(bits, np.int32), len(bits), R, sens, out)
    return out


def cube_vec(base, vecs, R, sens=0):
    """Somme de P sur le sous-espace affine base ⊕ <vecs> (vecs : [k, 128])."""
    out = np.zeros(N, np.uint8)
    v = np.ascontiguousarray(vecs, np.uint8)
    charger().bn_cube_vec(np.ascontiguousarray(base, np.uint8), v, len(v), R, sens, out)
    return out


def diff(din, R, n, graine, cible=None, sens=0, post=0):
    """(paires de différence de sortie = cible, histogrammes [128, 16] des
    nibbles de différence ; post=1 : de M^-1 · différence)."""
    hist = np.zeros(N * 16, np.uint64)
    ex = ctypes.c_uint64(0)
    c = None if cible is None else np.ascontiguousarray(cible, np.uint8)
    charger().bn_diff(np.ascontiguousarray(din, np.uint8), R, sens, post, n, graine,
                      None if c is None else c.ctypes.data, ctypes.byref(ex), hist)
    return int(ex.value), hist.reshape(N, 16)


def lin(ma, mb, R, n, graine, sens=0):
    """Corrélation mesurée de <ma, x> ⊕ <mb, P(x)>."""
    acc = charger().bn_lin(np.ascontiguousarray(ma, np.uint8), np.ascontiguousarray(mb, np.uint8),
                           R, sens, n, graine)
    return 2 * acc / n - 1


def lin_nib(ma, R, n, graine, sens=0, post=0):
    """Corrélations [128, 16] de <ma, x> avec <b, z_v> (b = 1..15 ; colonne
    0 inutilisée), z = P(x) ou M^-1 P(x) (post=1)."""
    cnt = np.zeros(N * 32, np.uint64)
    charger().bn_lin_nib(np.ascontiguousarray(ma, np.uint8), R, sens, post, n, graine, cnt)
    cnt = cnt.reshape(N, 16, 2).astype(float)
    par = np.array([[bin(b & z).count("1") & 1 for z in range(16)] for b in range(16)])
    signe = 1 - 2 * par                                   # [b, z]
    diffe = cnt[:, :, 0] - cnt[:, :, 1]                    # Σ (-1)^{<a,x>} par valeur z
    return diffe @ signe.T / n


def sac(R, n, graine, sens=0):
    cnt = np.zeros(512 * 512, np.uint64)
    charger().bn_sac(R, sens, n, graine, cnt)
    return cnt.reshape(512, 512)


def flux_compteur(base, nblocs, R=B.N_ROUNDS, debit=B.RATE):
    out = np.zeros(nblocs * debit // 2 + 16, np.uint8)
    charger().bn_flux_compteur(np.ascontiguousarray(base, np.uint8), nblocs, R, debit, out)
    return out


def flux_eponge(etats, nblocs, R=B.N_ROUNDS, debit=B.RATE):
    m = len(etats)
    out = np.zeros(m * nblocs * debit // 2 + 16, np.uint8)
    charger().bn_flux_eponge(np.ascontiguousarray(etats, np.uint8), m, nblocs, R, debit, out)
    return out


def kem_bruit(xpos, ypos, p, essais, graine):
    from sillage.sillage_kem import _positions
    hm = np.zeros(64 * p["D"] + 1, np.uint64)
    hg = np.zeros(64 * p["D"] + 1, np.uint64)
    Q = np.array(_positions(p["D"]), np.uint8)
    charger().bn_kem_bruit(np.ascontiguousarray(xpos, np.int32), np.ascontiguousarray(ypos, np.int32),
                           p["w"], p["n"], p["n2"], p["k"], p["D"], p["we"], Q, essais, graine, hm, hg)
    return hm, hg


def debit_permutations(R=B.N_ROUNDS, n=1 << 16):
    """Permutations par seconde (C, tous les cœurs) et (Python, lot numpy)."""
    X = np.random.default_rng(1).integers(0, 16, (n, N), dtype=np.uint8)
    permute(X[:64], R)
    t = time.perf_counter(); permute(X, R); tc = time.perf_counter() - t
    t = time.perf_counter(); B._permute_batch(X[:4096], R); tp = time.perf_counter() - t
    return round(n / tc), round(4096 / tp)


# ------------------------------------------------------------- p-valeurs
def igamc(a, x):
    """Gamma incomplète régularisée supérieure Q(a, x)."""
    if x <= 0:
        return 1.0
    if x < a + 1:
        s = t = 1 / a
        k = a
        while abs(t) > 1e-15 * abs(s):
            k += 1
            t *= x / k
            s += t
        return max(0.0, 1 - s * math.exp(-x + a * math.log(x) - math.lgamma(a)))
    b, cc, d = x + 1 - a, 1e300, 1 / (x + 1 - a)
    h = d
    for i in range(1, 100000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = 1 / (d if abs(d) > 1e-300 else 1e-300)
        cc = b + an / cc
        cc = cc if abs(cc) > 1e-300 else 1e-300
        h *= d * cc
        if abs(d * cc - 1) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi2_p(obs, att, ddl=None):
    """p-valeur du χ² (cases d'effectif attendu ≥ 5 seulement)."""
    obs, att = np.asarray(obs, float), np.asarray(att, float)
    m = att >= 5
    x = float(((obs[m] - att[m]) ** 2 / att[m]).sum())
    k = (int(m.sum()) - 1) if ddl is None else ddl
    return igamc(k / 2, x / 2)


def p_normale(z):
    """p-valeur bilatérale d'un z-score."""
    return math.erfc(abs(z) / math.sqrt(2))


def p_max_normales(zmax, m):
    """p-valeur du max de |z| sur m z-scores indépendants."""
    p1 = p_normale(zmax)
    return 1 - (1 - p1) ** m if p1 > 1e-12 else min(1.0, m * p1)


def ks_uniforme(p):
    """p-valeur (asymptotique) du test de Kolmogorov–Smirnov d'uniformité."""
    p = np.sort(np.asarray(p, float))
    n = len(p)
    d = max((np.arange(1, n + 1) / n - p).max(), (p - np.arange(n) / n).max())
    t = (math.sqrt(n) + 0.12 + 0.11 / math.sqrt(n)) * d
    return float(min(1.0, max(0.0, 2 * sum((-1) ** (k - 1) * math.exp(-2 * k * k * t * t)
                                           for k in range(1, 101)))))


if __name__ == "__main__":
    charger()
    print("conformité", conformite())
    for R in (2, 8, 32):
        print(f"{R} tours : C / Python (perm/s)", debit_permutations(R))
