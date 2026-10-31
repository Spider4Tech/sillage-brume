# -*- coding: utf-8 -*-
"""Diffusion et statistiques : support par tour (tous les sommets), avalanche
par tour, matrice SAC complète à 32 tours, inverse de la permutation, batterie
statistique (type NIST SP 800-22 allégée) sur le flux AEAD, le hachage et la
permutation en mode compteur."""
import math

import numpy as np

from tests.commun import sauver
from sillage import brume512 as B
from tests.noyau_c import permute
from sillage.brume512 import Brume512, brume512_hash

N = B.N


# ---------------------------------------------------------------- p-valeurs
def _igamc(a, x):
    """Gamma incomplète régularisée supérieure Q(a, x)."""
    if x <= 0:
        return 1.0
    if x < a + 1:
        s, t, k = 1 / a, 1 / a, a
        while abs(t) > 1e-15 * abs(s):
            k += 1
            t *= x / k
            s += t
        return 1 - s * math.exp(-x + a * math.log(x) - math.lgamma(a))
    b, cc, d = x + 1 - a, 1e300, 1 / (x + 1 - a)
    h = d
    for i in range(1, 500):
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


def batterie(bits):
    n = len(bits)
    s = 2 * bits.astype(np.int64) - 1
    p = {}
    p["monobit"] = math.erfc(abs(s.sum()) / math.sqrt(2 * n))
    M = 128
    blocs = bits[: n // M * M].reshape(-1, M).mean(1)
    p["frequence_blocs"] = _igamc(len(blocs) / 2, 4 * M * ((blocs - .5) ** 2).sum() / 2)
    pi = bits.mean()
    v = 1 + int((bits[1:] != bits[:-1]).sum())
    p["runs"] = math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))
    for mm in (2, 3, 4):           # sériel (fréquences des motifs de mm bits)
        k = n // mm
        vals = bits[: k * mm].reshape(k, mm) @ (1 << np.arange(mm))
        cnt = np.bincount(vals, minlength=1 << mm)
        e = k / (1 << mm)
        p[f"motifs_{mm}_bits"] = _igamc(((1 << mm) - 1) / 2, ((cnt - e) ** 2 / e).sum() / 2)
    by = np.packbits(bits[: n // 8 * 8])
    cnt = np.bincount(by, minlength=256)
    e = len(by) / 256
    p["chi2_octets"] = _igamc(255 / 2, ((cnt - e) ** 2 / e).sum() / 2)
    for lag in (1, 2, 8, 64):
        d = int((bits[:-lag] != bits[lag:]).sum())
        p[f"autocorrelation_lag{lag}"] = math.erfc(abs(d - (n - lag) / 2) / math.sqrt((n - lag) / 4) / math.sqrt(2))
    # plus longue suite de 1 dans des blocs de 128 bits : moyenne vs théorie
    return {k: round(float(v), 4) for k, v in p.items()}


def run():
    rng = np.random.default_rng(99)
    c, m = {}, {}
    # 1. support : tours pour que 1 nibble touche les 128 sommets (chaque départ)
    A = B.ADJ_I.astype(np.int64)
    tours = []
    for s in range(N):
        x = np.zeros(N, np.int64); x[s] = 1
        r = 0
        while not x.all():
            x = (A @ x > 0).astype(np.int64)
            r += 1
        tours.append(r)
    m["support_complet_tours"] = {"min": min(tours), "max": max(tours)}
    # 2. avalanche par tour
    av = {}
    for R in range(1, 9):
        X = rng.integers(0, 16, (500, N), dtype=np.uint8)
        pos, bit = rng.integers(0, N, 500), rng.integers(0, 4, 500)
        X2 = X.copy(); X2[np.arange(500), pos] ^= (1 << bit).astype(np.uint8)
        d = np.unpackbits((permute(X, R) ^ permute(X2, R))[:, :, None], axis=2)[:, :, 4:]
        av[R] = round(float(d.mean()), 4)
    m["avalanche_par_tour"] = av
    m["tours_avalanche_complete"] = min(R for R, v in av.items() if abs(v - .5) < .01)
    # 3. SAC à 32 tours : 512 bits d'entrée × 512 bits de sortie, 200 essais
    T = 200
    X = rng.integers(0, 16, (T, N), dtype=np.uint8)
    Y = permute(X)
    sac = np.zeros((512, 512))
    for b in range(512):
        X2 = X.copy(); X2[:, b // 4] ^= np.uint8(1 << (b % 4))
        D = np.unpackbits((Y ^ permute(X2))[:, :, None], axis=2)[:, :, 4:].reshape(T, 512)
        sac[b] = D.mean(0)
    z = (sac - .5) / math.sqrt(.25 / T)
    m["sac_32_tours"] = {"moyenne": round(float(sac.mean()), 4), "z_max": round(float(np.abs(z).max()), 2),
                         "z_attendu_max_sur_262144": round(math.sqrt(2 * math.log(2 * 512 * 512)), 2)}
    c["sac_32_tours_conforme"] = abs(sac.mean() - .5) < .002 and np.abs(z).max() < 6
    # 4. inverse de la permutation (S^{-1}, M^{-1}) : P^{-1}(P(x)) = x
    Minv = B._gauss_gf16_inverse(np.array([[B.TF.COEF[j][i] if B.ADJ_I[j, i] else 0
                                             for i in range(N)] for j in range(N)], np.uint8))
    Sinv = np.argsort(B.SBOX).astype(np.uint8)
    def inv(s):
        s = s.copy()
        for r in reversed(range(B.N_ROUNDS)):
            s = np.bitwise_xor.reduce(B.GMUL[Minv[None, :, :], s[:, None, :]], axis=2)
            s = Sinv[s] ^ B.RC[r]
        return s
    X = rng.integers(0, 16, (50, N), dtype=np.uint8)
    c["permutation_inversible"] = bool((inv(permute(X)) == X).all())
    # 5. batterie statistique
    sources = {}
    br = Brume512("BRUME-512", key=bytes(range(64)))
    ct, _ = br.encrypt(bytes(24), bytes(1 << 17))        # flux = chiffré de zéros
    sources["flux_aead_128Ko"] = np.unpackbits(np.frombuffer(ct, np.uint8))
    hs = b"".join(brume512_hash(i.to_bytes(4, "big"), 32) for i in range(3000))
    sources["hachage_compteur_96Ko"] = np.unpackbits(np.frombuffer(hs, np.uint8))
    X = np.zeros((30000, N), np.uint8)
    ctr = np.arange(30000)
    for j in range(4):
        X[:, j] = ((ctr >> (4 * j)) & 15).astype(np.uint8)
    Y = permute(X)
    sources["permutation_compteur_1.9Mo"] = np.unpackbits((Y[:, 0::2] | (Y[:, 1::2] << 4)).astype(np.uint8).ravel())
    pv = {k: batterie(v) for k, v in sources.items()}
    m["batterie_statistique_p_valeurs"] = pv
    allp = [p for d in pv.values() for p in d.values()]
    m["p_min"] = min(allp)
    # seuil corrigé (Bonferroni sur ~33 tests, α = 0,001)
    c["batterie_statistique_aucun_rejet"] = min(allp) > 1e-3 / len(allp)
    out = {"controles": c, "mesures": m}
    sauver("diffusion_stats", out)
    return out


if __name__ == "__main__":
    print(run())
