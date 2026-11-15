# -*- coding: utf-8 -*-
"""Vérifications numériques liées à la relecture des preuves des deux lemmes cités par le Théorème Q
(AEAD_SECURITY.md § 4 quinquies) : Alagic–Bai–Katz–Majenz, ePrint 2021/1601, § 4, et Hosoyamada, ePrint 2025/1059,
annexe B.

(a) Le « Lemme 8 » (gentle measurement) de 2021/1601, tel qu'imprimé : pour des projecteurs P_i avec ‖(1−P_i)ψ‖² ≤ ε_i,
        1 − |⟨ψ| P_q ⋯ P_1 |ψ⟩|² ≤ Σ ε_i.
    Il est FAUX tel quel : contre-exemple à un seul projecteur (2ε − ε² > ε), et, même sans le carré
    (1 − |⟨ψ|P_q⋯P_1|ψ⟩| ≤ Σ ε_i), contre-exemple à deux projecteurs de rang 1 dans le plan (angles +θ et −θ).
(b) Ce dont la preuve a besoin est ‖ψ_bad‖² = ‖ψ − z·P_q⋯P_1ψ‖² ≤ 2 Σ ε_i. On a mieux, et élémentaire :
        ‖ψ − P_q ⋯ P_1 ψ‖² ≤ Σ ε_i
    (δ_i = ψ − P_i⋯P_1ψ vérifie δ_i = (1−P_i)ψ + P_i δ_{i−1}, somme orthogonale, d'où ‖δ_i‖² ≤ ε_i + ‖δ_{i−1}‖²).
    Vérifié ici sur des tirages aléatoires (dimension, rangs et nombre de projecteurs variés), et l'inégalité avec la
    phase z de l'article (‖ψ − zφ‖² = 1 + ‖φ‖² − 2|⟨ψ|φ⟩| ≤ ‖ψ − φ‖²) aussi.
(c) Les relations de commutation (11) et (12) de 2021/1601, sur l'oracle en superposition d'une fonction {0,1}^m → {0,1}^m
    (m = 2 : les 256 fonctions, toutes les entrées de base) : Swap(F_s0, F_s1) commute avec O·P_{s0 s1} et avec
    O^inv·P^inv_{s0 s1}. Témoin : sans le projecteur, la commutation échoue.
    python3 lemmes_sources.py        (numpy requis)"""
import itertools
import sys

import numpy as np


def projecteur(rng, d, rang):
    a = rng.normal(size=(d, rang)) + 1j * rng.normal(size=(d, rang))
    q, _ = np.linalg.qr(a)
    return q @ q.conj().T


def partie_ab(rng):
    # (a) contre-exemples
    eps = 0.1
    psi = np.array([1, 0], complex)
    v = np.array([np.sqrt(1 - eps), np.sqrt(eps)], complex)
    P = np.outer(v, v.conj())
    g1 = 1 - abs(psi.conj() @ P @ psi) ** 2
    assert g1 > eps + 1e-9
    th = 0.2
    P1 = np.outer([np.cos(th), np.sin(th)], [np.cos(th), np.sin(th)]).astype(complex)
    P2 = np.outer([np.cos(th), -np.sin(th)], [np.cos(th), -np.sin(th)]).astype(complex)
    se = 2 * np.sin(th) ** 2
    g2 = 1 - abs(psi.conj() @ P2 @ P1 @ psi)
    assert g2 > se + 1e-9
    print(f"(a) Lemme 8 tel qu'imprimé : 1 projecteur, 1 − |⟨ψ|P|ψ⟩|² = {g1:.4f} > ε = {eps} ; "
          f"2 projecteurs, sans le carré : {g2:.4f} > Σε = {se:.4f}  → énoncé faux, à un facteur constant près")
    # (b) inégalité de remplacement
    pire, pire_z, n = 0.0, 0.0, 0
    for _ in range(20000):
        d = int(rng.integers(2, 9))
        q = int(rng.integers(1, 7))
        psi = rng.normal(size=d) + 1j * rng.normal(size=d)
        psi /= np.linalg.norm(psi)
        phi, se = psi.copy(), 0.0
        for _ in range(q):
            if rng.random() < 0.5:                       # projecteur proche de ψ (petit ε) ou quelconque
                w = psi + 0.3 * (rng.normal(size=d) + 1j * rng.normal(size=d))
                w /= np.linalg.norm(w)
                P = np.outer(w, w.conj())
                if d > 2 and rng.random() < 0.5:
                    P = np.eye(d) - projecteur(rng, d, 1) if rng.random() < 0.5 else P
            else:
                P = projecteur(rng, d, int(rng.integers(1, d)))
            se += np.linalg.norm(psi - P @ psi) ** 2
            phi = P @ phi
        g = np.linalg.norm(psi - phi) ** 2
        a = abs(psi.conj() @ phi)
        gz = 1 + np.linalg.norm(phi) ** 2 - 2 * a      # ‖ψ − zφ‖² avec la phase de l'article
        assert g <= se + 1e-9 and gz <= g + 1e-9
        if se > 1e-12:
            pire, pire_z = max(pire, g / se), max(pire_z, gz / se)
        n += 1
    print(f"(b) ‖ψ − P_q⋯P_1ψ‖² ≤ Σε_i : {n} tirages, rapport maximal {pire:.4f} (≤ 1) ; avec la phase z : {pire_z:.4f}")


def partie_c():
    m = 2
    V = range(1 << m)
    fonctions = list(itertools.product(V, repeat=1 << m))     # f = (f(0), f(1), f(2), f(3))

    def O(x, y, f):                                           # base → base
        return x, y ^ f[x], f

    def Oinv(x, y, f):
        for xp in V:
            if f[xp] == y:
                x ^= xp
        return x, y, f

    def swapF(f, s0, s1):
        g = list(f); g[s0], g[s1] = g[s1], g[s0]
        return tuple(g)

    ok, temoin = 0, 0
    for s0 in V:
        for s1 in V:
            for f in fonctions:
                for x in V:
                    for y in V:
                        # (11) : sur l'image de P_{s0 s1} (x hors {s0, s1}, ou s0 = s1)
                        dans = s0 == s1 or x not in (s0, s1)
                        a = O(x, y, swapF(f, s0, s1))
                        b = O(x, y, f); b = (b[0], b[1], swapF(b[2], s0, s1))
                        if dans:
                            assert a == b; ok += 1
                        elif a != b:
                            temoin += 1
                        # (12) : sur l'image de P^inv (f(s0) ≠ y et f(s1) ≠ y, ou s0 = s1) ; l'image est stable par Swap
                        dans = s0 == s1 or (f[s0] != y and f[s1] != y)
                        a = Oinv(x, y, swapF(f, s0, s1))
                        b = Oinv(x, y, f); b = (b[0], b[1], swapF(b[2], s0, s1))
                        if dans:
                            assert a == b; ok += 1
                        elif a != b:
                            temoin += 1
    assert temoin > 0
    print(f"(c) commutations (11) et (12) : {ok} cas de base vérifiés (m = {m}, {len(fonctions)} fonctions) ; "
          f"sans le projecteur, {temoin} cas ne commutent pas (témoin)")


def main():
    rng = np.random.default_rng(20261114)
    partie_ab(rng)
    partie_c()
    return 0


if __name__ == "__main__":
    sys.exit(main())
