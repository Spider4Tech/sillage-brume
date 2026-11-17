# -*- coding: utf-8 -*-
"""Corps GF(16) = GF(2)[t]/(t^4 + t + 1) pour les outils d'analyse de BRUME-1024q (v0.6).

Repris tel quel de sillage/brume512.py (v0.5, archivé dans tests/historique_v05/) : les tables ne dépendent que du
corps, commun à BRUME-512 et à BRUME-1024q. GMUL[c, v] = c·v ; GINV[v] = v⁻¹ (0 → 0) ; GMUL_T[c, μ] = L_c^T μ, la
transposée binaire de la multiplication par c (bit k = <μ, c·t^k>), adjointe pour le pairing binaire du LAT."""
import numpy as np

POLY = 0x13  # t^4 + t + 1


def _gmul(a: int, b: int) -> int:
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


GMUL = np.array([[_gmul(a, b) for b in range(16)] for a in range(16)], dtype=np.uint8)
GINV = np.zeros(16, dtype=np.uint8)
for _a in range(1, 16):
    for _b in range(1, 16):
        if GMUL[_a, _b] == 1:
            GINV[_a] = _b


def _gmul_T():
    t = np.zeros((16, 16), dtype=np.uint8)
    for c in range(16):
        for mu in range(16):
            t[c, mu] = sum((bin(mu & int(GMUL[c, 1 << k])).count("1") & 1) << k for k in range(4))
    return t


GMUL_T = _gmul_T()


def _gauss_gf16_inverse(mat: np.ndarray) -> np.ndarray:
    """Inverse d'une matrice n×n à coefficients GF(16) (Gauss-Jordan)."""
    n = mat.shape[0]
    a = np.concatenate([mat.astype(np.uint8) % 16, np.eye(n, dtype=np.uint8)], axis=1)
    row = 0
    for col in range(n):
        piv = None
        for r in range(row, n):
            if a[r, col] & 0xF:
                piv = r
                break
        assert piv is not None, "matrice singulière sur GF(16)"
        a[[row, piv]] = a[[piv, row]]
        a[row] = GMUL[int(GINV[a[row, col]])][a[row]]
        for r in range(n):
            if r != row and (a[r, col] & 0xF):
                a[r] ^= GMUL[int(a[r, col])][a[row]]
        row += 1
    return a[:, n:] % 16


# ---- algèbre générique (recopiée de tests/test_brume_algebre.py de la v0.5, archivé) : rang et noyau sur GF(16),
# polynômes de GF(2)[X] codés en entiers, Berlekamp–Massey
def _rang_gf16(A):
    A = A.copy()
    r = 0
    inv = GINV
    for c in range(A.shape[1]):
        p = next((i for i in range(r, A.shape[0]) if A[i, c]), None)
        if p is None:
            continue
        A[[r, p]] = A[[p, r]]
        A[r] = GMUL[inv[A[r, c]], A[r]]
        for i in np.nonzero(A[:, c])[0]:
            if i != r:
                A[i] ^= GMUL[A[i, c], A[r]]
        r += 1
    return r


# ---------------- 2. couche linéaire ----------------

def _pmod(a, f):
    d = f.bit_length()
    while a.bit_length() >= d:
        a ^= f << (a.bit_length() - d)
    return a


def _pmul(a, b, f):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a.bit_length() == f.bit_length():
            a ^= f
    return r


def _pgcd(a, b):
    while b:
        a, b = b, _pmod(a, b)
    return a


def _pdiv(a, b):
    q, d = 0, b.bit_length()
    while a.bit_length() >= d:
        s = a.bit_length() - d
        q |= 1 << s
        a ^= b << s
    return q


def _massey(s):
    C_, B_, L, m, n = 1, 1, 0, 1, len(s)
    for i in range(n):
        d = s[i]
        for j in range(1, L + 1):
            d ^= (C_ >> j) & 1 & s[i - j]
        if d:
            T = C_
            C_ ^= B_ << m
            if 2 * L <= i:
                L, B_, m = i + 1 - L, T, 1
            else:
                m += 1
        else:
            m += 1
    return C_, L


def _noyau_gf16(A):
    A = A.copy()
    n = A.shape[1]
    r, pivots = 0, []
    inv = GINV
    for c in range(n):
        p = next((i for i in range(r, A.shape[0]) if A[i, c]), None)
        if p is None:
            continue
        A[[r, p]] = A[[p, r]]
        A[r] = GMUL[inv[A[r, c]], A[r]]
        for i in np.nonzero(A[:, c])[0]:
            if i != r:
                A[i] ^= GMUL[A[i, c], A[r]]
        pivots.append(c)
        r += 1
    libres = [c for c in range(n) if c not in pivots]
    res = []
    for fl in libres:
        v = np.zeros(n, dtype=np.uint8)
        v[fl] = 1
        for i, c in enumerate(pivots):
            v[c] = A[i, fl]
        res.append(v)
    return res


def _ppcm(a, b):
    g = _pgcd(a, b)
    q = _pdiv(b, g)
    r = 0
    i = 0
    while q >> i:
        if (q >> i) & 1:
            r ^= a << i
        i += 1
    return r


# ---------------- 3. S-box ----------------

