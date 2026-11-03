# -*- coding: utf-8 -*-
"""Sillage-KEM : correction, marge de décodage (mesurée vs modèle), transformée
FO (chiffrés non honnêtes rejetés), rejet implicite, entrées malformées,
distribution de la clé publique, invariants des paramètres."""
import math

from tests.commun import sauver
from sillage.sillage_kem import SillageKEM, PARAMS, rm_decode, borne_echec_log2
from sillage.sillage_common import sparse_random
from sillage.sillage_common import ring_mul, shake


def artin(n):
    def fact(x):
        f, p = set(), 2
        while p * p <= x:
            while x % p == 0:
                f.add(p); x //= p
            p += 1
        if x > 1:
            f.add(x)
        return f
    premier = n > 2 and all(n % p for p in range(2, int(n ** .5) + 1))
    return premier and all(pow(2, (n - 1) // q, n) != 1 for q in fact(n - 1))


def run():
    c, m = {}, {}
    for lvl, essais in (("Sillage-128", 80), ("Sillage-256", 12)):
        kem = SillageKEM(lvl)
        p = kem.p
        n, n2, k, D = p["n"], p["n2"], p["k"], p["D"]
        c[f"{lvl}_n_premier_artin"] = artin(n)
        c[f"{lvl}_n2_le_n"] = n2 == (k // 8) * 128 * D <= n
        pk, sk = kem.keygen()
        ok, flips, ss_vus = 0, [], set()
        for _ in range(essais):
            ct, ss = kem.encaps(pk)
            ok += kem.decaps(sk, ct) == ss
            ss_vus.add(ss)
            u, v = ct
            nv = v ^ (ring_mul(sk[0], u, n) & ((1 << n2) - 1))
            flips.append(rm_decode(nv, p)[1])       # bits de bruit sur le pire hyperplan − |S|/2
        c[f"{lvl}_correction"] = ok == essais
        # Invariant de parité (PROOFS §1, audit externe point 1) : s(1) et u(1)
        # sont des fonctions publiques de h(1) et de w mod 2 ; v (tronqué) n'en a pas.
        par = lambda a: a.bit_count() & 1
        ok_s = ok_u = 0
        pv = []
        for _ in range(20):
            pk2, _sk2 = kem.keygen()
            h2 = kem._dense_h(pk2[0])
            beta = (p["w"] & 1) * (par(h2) ^ 1)
            ok_s += par(pk2[1]) == beta
            (u2, v2), _ = kem.encaps(pk2)
            ok_u += par(u2) == beta
            pv.append(par(v2))
        m[f"{lvl}_parite"] = {"s_conforme": ok_s, "u_conforme": ok_u, "cles": 20, "v_impairs": sum(pv)}
        c[f"{lvl}_invariant_de_parite_de_s_et_u_conforme_a_H1P"] = ok_s == ok_u == 20
        c[f"{lvl}_parite_de_v_non_determinee"] = 0 < sum(pv) < 20
        c[f"{lvl}_secrets_distincts"] = len(ss_vus) == essais
        p1 = (1 - (1 - 2 / n) ** (p["w"] ** 2)) / 2
        q = 2 * p1 * (1 - p1) + 2 * p["we"] / n2
        S = 64 * D
        m[f"{lvl}_bascules"] = {"marge_pire_chiffre": max(flips), "taille_hyperplan": S,
                                "moyenne_modele_par_hyperplan": round(S * q, 1),
                                "z_modele": round((S / 2 - S * q) / math.sqrt(S * q * (1 - q)), 1)}
        # Décodage sûr si marge < 0 ; la pire de 254 × k/8 valeurs reste loin de 0
        c[f"{lvl}_marge_decodage"] = max(flips) < -2 * math.sqrt(S * q * (1 - q))
        # δ-correction PROUVÉE (Chernoff, docs/PROOFS.md §2.3)
        b_cle = borne_echec_log2(sk[0], sk[1], p)
        echant = sorted(borne_echec_log2(sparse_random(p["w"], n), sparse_random(p["w"], n), p)
                        for _ in range(12 if p["k"] == 128 else 3))
        m[f"{lvl}_delta_prouve_log2"] = {"cle_generee": round(b_cle, 1),
                                         "mediane_cles_brutes": round(echant[len(echant) // 2], 1),
                                         "pire_cle_brute": round(echant[-1], 1),
                                         "taux_rejet_estime": sum(b > -p["lam"] for b in echant) / len(echant)}
        c[f"{lvl}_delta_prouve_le_2^-lambda"] = b_cle <= -p["lam"]
        c[f"{lvl}_cle_typique_delta_le_2^-(lambda+8)"] = echant[len(echant) // 2] <= -(p["lam"] + 8)
        # FO : chiffré non honnête mais décodable → rejet implicite
        ct, ss = kem.encaps(pk)
        u, v = ct
        rejets = []
        for v2 in (v ^ 1, v ^ (1 << (n2 - 1)), v ^ (0b111 << 100)):
            mu = rm_decode(v2 ^ (ring_mul(sk[0], u, n) & ((1 << n2) - 1)), p)[0]
            ss_mu = shake(mu.to_bytes(k // 8, "little") + u.to_bytes((n + 7) // 8, "little")
                          + v2.to_bytes((n2 + 7) // 8, "little"), p["ss_len"], b"SILLAGE-KEM|ss")
            rejets.append(kem.decaps(sk, (u, v2)) != ss_mu)
        c[f"{lvl}_fo_rejette_chiffres_non_honnetes"] = all(rejets)
        # rejet implicite déterministe et dépendant du chiffré
        r1, r2 = kem.decaps(sk, (u, v ^ 1)), kem.decaps(sk, (u, v ^ 1))
        r3 = kem.decaps(sk, (u, v ^ 2))
        c[f"{lvl}_rejet_implicite_deterministe"] = r1 == r2 and r1 != r3 and len(r1) == p["ss_len"]
        # entrées malformées : hors bornes / négatives → pas d'exception, rejet
        mal = True
        for bad in ((u | (1 << n), v), (u, v | (1 << n2)), (0, 0), (-1, v)):
            try:
                mal &= kem.decaps(sk, bad) != ss
            except Exception:
                mal = False
        c[f"{lvl}_entrees_malformees_sans_exception"] = mal
        # clé publique : densité de s ≈ 1/2
        dens = pk[1].bit_count() / n
        m[f"{lvl}_densite_pk_z"] = round((dens - .5) / math.sqrt(.25 / n), 2)
        c[f"{lvl}_pk_densite_uniforme"] = abs(m[f"{lvl}_densite_pk_z"]) < 5
        est = kem.security_estimate()
        m[f"{lvl}_securite"] = est
        c[f"{lvl}_securite_ge_lambda"] = est["classique_bits"] >= p["lam"]
        # v0.4 : le changement de code n'abaisse aucun niveau de la v0.3
        avant = {"Sillage-128": (137.3, 91.1), "Sillage-256": (264.9, 158.0)}[lvl]
        c[f"{lvl}_niveaux_v03_conserves"] = est["classique_bits"] >= avant[0] and est["quantique_bits"] >= avant[1]
    try:
        SillageKEM("Sillage-128", h_mode="tensor")
        c["mode_tensor_refuse"] = False
    except ValueError:
        c["mode_tensor_refuse"] = True
    out = {"controles": c, "mesures": m}
    sauver("kem", out)
    return out


if __name__ == "__main__":
    print(run())
