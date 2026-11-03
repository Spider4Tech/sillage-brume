# -*- coding: utf-8 -*-
"""Sillage-SIG (MPC-in-the-Head) : correction, rejets, témoin bien formé, tricheurs (faux
témoin, attaque à 1/N exécutée sur modèle réduit), récupération de clé par graine réduite,
graines couvertes par le message, uniformité des défis, dimensionnement du Théorème 8,
niveaux de la v0.3 conservés."""
import math
import os

import numpy as np

from tests.commun import sauver
from sillage.rapide import SillageSIG as Rapide
from sillage.sillage_common import isd_quantique, _lb
from sillage.sillage_sig import SIG_PARAMS, SillageSIG

# v0.3 (Stern) : ISD classique, Prange–Grover ; effectif quantique, catégorie NIST
AVANT = {"Sillage-SIG-128": (159.7, 110.7, 64.0, 0), "Sillage-SIG-256": (314.9, 200.9, 128.0, 3)}


def _reduit(lvl, **k):
    """Instance réduite, pour exécuter les attaques."""
    s = SillageSIG(lvl)
    s.p = dict(s.p, **k)
    s.__dict__.update({"xb": (s.p["k"] + 7) // 8, "qb": (s.p["w"] * s.p["e"] + 7) // 8, "pts": (s.p["t"] * s.p["ep"] + 7) // 8})
    s.L_part, s.L_aux = s.xb + 2 * s.qb + 3 * s.pts, s.xb + 2 * s.qb + s.pts
    return s


def _champs_sk(sig, sk):
    return (int.from_bytes(sk[:sig.xb], "little"), int.from_bytes(sk[sig.xb:sig.xb + sig.qb], "little"),
            int.from_bytes(sk[sig.xb + sig.qb:], "little"))


def _x_complet(sig, pk, sk):
    xa = _champs_sk(sig, sk)[0]
    return xa | (sig._mat_vec(sig._matrix(pk[0]), xa) ^ pk[1]) << sig.p["k"]


def _temoin_bien_forme(sig, pk, sk):
    """wt(x) = w, Q s'annule sur le support, S(r)·Q(r) = P(r)·F(r) en des points aléatoires."""
    p = sig.p
    x = _x_complet(sig, pk, sk)
    _, Qi, Pi = _champs_sk(sig, sk)
    Q = sig._coefs(Qi, p["w"], p["e"]) + [1]
    P = sig._coefs(Pi, p["w"], p["e"])
    ok = x.bit_count() == p["w"]
    for i in range(p["n"]):
        val = 0
        for c in reversed(Q):
            val = sig._em(val, i) ^ c
        ok &= (val == 0) == bool((x >> i) & 1)
    phi = sig._plongement()
    bits = np.unpackbits(np.frombuffer(x.to_bytes(p["n"] // 8, "little"), np.uint8), bitorder="little").astype(bool)
    for _ in range(4):
        r = int.from_bytes(os.urandom(8), "little") & ((1 << p["ep"]) - 1)
        L, Fr, pw, rw = sig._prepa(r)
        ok &= int(np.bitwise_xor.reduce(L)) == 1              # partition de l'unité
        S = int(np.bitwise_xor.reduce(L[bits]))
        Qr, Pr = rw, 0
        for c, q, d in zip(pw, Q[:-1], P):
            Qr ^= sig._m(int(phi[q]), int(c))
            Pr ^= sig._m(int(phi[d]), int(c))
        ok &= sig._m(S, Qr) == sig._m(Pr, Fr)
    # point de F_poly : L est le vecteur unité de ce point
    L, Fr, _, _ = sig._prepa(int(phi[5]))
    ok &= Fr == 0 and int(L[5]) == 1 and int(L.sum()) == 1
    return ok


def _faux_temoins(sig, pk, sk):
    """Signer avec un faux témoin rend la signature invalide."""
    p = sig.p
    xa, Qi, Pi = _champs_sk(sig, sk)
    faux = []
    faux.append(sig._emb(xa ^ 1, sig._coefs(Qi, p["w"], p["e"]), sig._coefs(Pi, p["w"], p["e"])))   # H·x = y, poids élevé ou faux
    faux.append(sig._emb(int.from_bytes(os.urandom(sig.xb), "little") & ((1 << p["k"]) - 1),
                         sig._coefs(Qi, p["w"], p["e"]), sig._coefs(Pi, p["w"], p["e"])))            # préimage dense
    faux.append(sig._emb(xa, sig._coefs(Qi ^ 1, p["w"], p["e"]), sig._coefs(Pi, p["w"], p["e"])))   # Q altéré
    faux.append(sig._emb(xa, sig._coefs(Qi, p["w"], p["e"]), sig._coefs(Pi ^ 1, p["w"], p["e"])))   # P altéré
    return all(not sig.verify(pk, b"m", sig.sign(f, pk, b"m")) for f in faux)


def _tricheur(sig, pk, msg, cible):
    """Le meilleur tricheur sans témoin : il simule honnêtement tout, sauf le côté qui contient la
    feuille cible dans chaque dimension. Une répétition : valide ssi le défi tombe sur la cible."""
    p = sig.p
    N, D, sb = 1 << p["D"], p["D"], p["sb"]
    cols = sig._matrix(pk[0])
    salt = os.urandom(32)
    mh, pkh = sig._h(b"msg", msg), sig._pkh(pk)
    t = sig._noeuds(salt, 0, os.urandom(sb))
    masque = sig._masques()
    parts = [sig._feuille(salt, 0, i, t[N + i], masque) for i in range(N)]
    cotes, tot = sig._replier(enumerate(parts))
    *_, a, b, c = sig._champs(tot)
    ep = p["ep"]
    ab = sum(sig._m(x, y) << (ep * j) for j, (x, y) in enumerate(zip(sig._coefs(a, p["t"], ep), sig._coefs(b, p["t"], ep))))
    faux = sig._aux_int(int.from_bytes(os.urandom(sig.xb), "little") & ((1 << p["k"]) - 1), 0, 0, 0)
    aux = faux ^ (tot & sig._aux_int((1 << (8 * sig.xb)) - 1, (1 << (8 * sig.qb)) - 1, (1 << (8 * sig.qb)) - 1, 0))
    aux |= (ab ^ c) << (8 * (sig.xb + 2 * sig.qb + 2 * sig.pts))
    tot ^= aux
    cotes = [x ^ aux for x in cotes]
    auxb = sig._aux_oct(aux)
    rb = (0).to_bytes(4, "big")
    cm = [sig._h(b"c", salt, rb, i.to_bytes(4, "big"), t[N + i]) for i in range(N - 1)]
    cm.append(sig._h(b"c", salt, rb, (N - 1).to_bytes(4, "big"), t[2 * N - 1], auxb))
    h1 = sig._h(b"h1", salt, pkh, mh, sig._h(b"com", salt, rb, b"".join(cm)))
    ch1 = sig._defis1(h1)[0]
    prep = [sig._prepa(r) for r, _ in ch1]
    oa = [(x, y) for x, y, _ in sig._simule(tot, cols, pk[1], ch1, prep, True)]
    diff = bytearray(sig._oct_pts([x for x, _ in oa]) + sig._oct_pts([y for _, y in oa]))
    for d in range(D):
        if (cible >> d) & 1:                         # côté 0 honnête, côté 1 déduit
            sd = sig._simule(cotes[d] ^ tot, cols, pk[1], ch1, prep, True, oa)
            sd = [(x ^ sa, y ^ sb_, sv) for (x, y), (sa, sb_, sv) in zip(oa, sd)]
        else:
            sd = sig._simule(cotes[d], cols, pk[1], ch1, prep, False, oa)
        diff += b"".join(sig._oct_pts([s[q] for s in sd]) for q in range(3))
    h2 = sig._h(b"h2", salt, pkh, mh, h1, bytes(diff))
    i = sig._defis2(h2)[0]
    j, chemin = N + i, bytearray()
    for _ in range(D):
        chemin += t[j ^ 1]
        j >>= 1
    return salt + h1 + h2 + bytes(chemin) + cm[i] + auxb + sig._oct_pts([x for x, _ in oa]) + sig._oct_pts([y for _, y in oa]), i


def _attaque_tricheur(lvl):
    """Instance réduite N = 8, τ = 1, sans témoin : acceptée ssi le défi vaut la cible, d'où 1/N."""
    sig = _reduit(lvl, D=3, tau=1)
    pk = sig.keygen()[0]
    acc, cible_ok, essais = 0, True, 48
    for k in range(essais):
        s, i = _tricheur(sig, pk, b"falsifie", 5)
        v = sig.verify(pk, b"falsifie", s)
        acc += v
        cible_ok &= v == (i == 5)
    return acc, essais, cible_ok


def _attaque_graine(lvl):
    """Graines de 16 bits : la graine cachée se retrouve par énumération et livre x_A, donc la clé.
    |graine| borne le niveau, comme σ_π pour Stern. Avec N = 8, τ = 1 pour la vitesse."""
    sig = _reduit(lvl, D=3, tau=1, sb=2)
    pk, sk = sig.keygen()
    p = sig.p
    N, D, sb, hb = 8, 3, 2, p["hb"]
    i = N - 1
    while i == N - 1:                                  # dernière feuille cachée : aux absent, rien à exploiter
        s = sig.sign(sk, pk, b"cible" + os.urandom(4))
        salt, h2 = s[:32], s[32 + hb:32 + 2 * hb]
        i = sig._defis2(h2)[0]
    o = 32 + 2 * hb
    chemin, com, auxb = s[o:o + D * sb], s[o + D * sb:o + D * sb + hb], s[o + D * sb + hb:o + D * sb + hb + sig.L_aux]
    rb, ib = (0).to_bytes(4, "big"), i.to_bytes(4, "big")
    for v in range(1 << 16):
        g = v.to_bytes(2, "big")
        if sig._h(b"c", salt, rb, ib, g) == com:
            break
    else:
        return False, False
    t = sig._noeuds_sauf(salt, 0, chemin, i)
    t[N + i] = g
    masque = sig._masques()
    tot = 0
    for j in range(N):
        tot ^= sig._feuille(salt, 0, j, t[N + j], masque)
    tot ^= sig._aux_lit(auxb)
    xa, Qi, Pi, *_ = sig._champs(tot)
    sk2 = xa.to_bytes(sig.xb, "little") + Qi.to_bytes(sig.qb, "little") + Pi.to_bytes(sig.qb, "little")
    return sk2 == sk, sig.verify(pk, b"falsifie", sig.sign(sk2, pk, b"falsifie"))


def _budget_theoreme_8(s, log_q, log_qs=64):
    """log2 de chaque terme du Théorème 8 pour q = chaque compteur (2^log_q) et q_S signatures.
    Niveau λ : chaque terme ≤ 2q/2^λ jusqu'à q = 2^(λ−2)."""
    p = s.p
    h, g = 8 * p["hb"], 8 * p["sb"]
    _, f1, f2 = s.falsification_termes()
    return dict(falsification_1=log_q + f1,
                falsification_2=log_q + f2,
                collisions=2 * log_q + 2 - h,
                collisions_message=2 * log_q - h - 1,
                graines=log_q + 1 - g,
                programmation=log_qs + log_q - h)


def run():
    c, m = {}, {}
    ref = SillageSIG("Sillage-SIG-128")
    sig = Rapide("Sillage-SIG-128")
    p = ref.p
    pk, sk = sig.keygen()
    s = sig.sign(sk, pk, b"ordre")
    c["verification"] = sig.verify(pk, b"ordre", s)
    c["rejet_autre_message"] = not sig.verify(pk, b"ordrf", s)
    pk2, _ = sig.keygen()
    c["rejet_autre_cle"] = not sig.verify(pk2, b"ordre", s)
    rob = True
    lr = (len(s) - 32 - 2 * p["hb"]) // p["tau"]
    for i in (0, 31, 32, 63, 64, 95, 96, 96 + p["D"] * p["sb"], 96 + p["D"] * p["sb"] + p["hb"], 96 + lr - 1, 96 + lr, len(s) // 2, len(s) - 1):
        b = bytearray(s); b[i] ^= 1
        rob &= not sig.verify(pk, b"ordre", bytes(b))
    for bad in (s[:-1], s + b"\x00", b"", s[:64], os.urandom(len(s)), bytes(len(s)), b"\xff" * len(s)):
        try:
            rob &= not sig.verify(pk, b"ordre", bad)
        except Exception:
            rob = False
    c["rejets_alterations_et_entrees_malformees"] = rob
    # bits de bourrage : encodage canonique exigé
    b = bytearray(s); b[96 + p["D"] * p["sb"] + p["hb"] + ref.xb - 1] ^= 0x80
    c["encodage_non_canonique_rejete"] = not sig.verify(pk, b"ordre", bytes(b))
    # le témoin n'apparaît pas tel quel
    c["temoin_absent"] = sk[:ref.xb] not in s and sk[ref.xb:ref.xb + ref.qb] not in s
    # Clés du Python et du C : témoin conforme à la définition (PROOFS § 3.1)
    pkp, skp = ref.keygen()
    c["temoin_python_bien_forme"] = _temoin_bien_forme(ref, pkp, skp)
    c["temoin_c_bien_forme"] = _temoin_bien_forme(ref, pk, sk)
    c["faux_temoins_rejetes"] = _faux_temoins(sig, pk, sk)
    # Attaque exécutée : le tricheur sans témoin réussit en 1/N, sur la seule feuille visée
    acc, essais, cible_ok = _attaque_tricheur("Sillage-SIG-128")
    m["tricheur_N_8_acceptes"] = f"{acc}/{essais}"
    c["tricheur_accepte_ssi_defi_sur_la_cible"] = cible_ok and 1 <= acc <= 20
    gr, fal = _attaque_graine("Sillage-SIG-128")
    c["attaque_graine_reduite_retrouve_la_cle"] = gr
    c["cle_retrouvee_falsifie"] = fal
    # Graine maîtresse : déterministe en (sk, sel, m), différente si le message change
    sel = bytes(range(32))
    s1, s2, s3 = sig.sign(sk, pk, b"a", sel), sig.sign(sk, pk, b"a", sel), sig.sign(sk, pk, b"b", sel)
    c["meme_sel_meme_message_meme_signature"] = s1 == s2
    d, lg = p["D"] * p["sb"], p["sb"]
    chemins1 = {s1[96 + r * lr + o:96 + r * lr + o + lg] for r in range(p["tau"]) for o in range(0, d, lg)}
    chemins3 = {s3[96 + r * lr + o:96 + r * lr + o + lg] for r in range(p["tau"]) for o in range(0, d, lg)}
    c["meme_sel_autre_message_aucune_graine_commune"] = not (chemins1 & chemins3)
    # uniformité du défi caché
    bits = np.zeros(p["D"])
    N_s = 60
    for _ in range(N_s):
        ss = sig.sign(sk, pk, os.urandom(8))
        for i in ref._defis2(ss[32 + p["hb"]:32 + 2 * p["hb"]]):
            bits += [(i >> d_) & 1 for d_ in range(p["D"])]
    tot = N_s * p["tau"]
    z = (bits - tot / 2) / math.sqrt(tot / 4)
    m["defi_cache_z_max_par_bit"] = round(float(np.abs(z).max()), 2)
    c["defis_uniformes"] = float(np.abs(z).max()) < 4.5
    for lvl, q in SIG_PARAMS.items():
        S = SillageSIG(lvl)
        R = Rapide(lvl)
        est = S.security_estimate()
        m[f"securite_{lvl}"] = est
        c[f"{lvl}_securite_ge_lambda"] = est["effective_bits"] >= q["lam"]
        c[f"{lvl}_graine_ge_lambda"] = 8 * q["sb"] >= q["lam"]
        c[f"{lvl}_haches_ge_2lambda"] = 8 * q["hb"] >= 2 * q["lam"]
        c[f"{lvl}_n_egal_2_puissance_e"] = q["n"] == 1 << q["e"] and q["k"] + q["r"] == q["n"]
        c[f"{lvl}_solution_unique_attendue"] = _lb(q["n"], q["w"]) < q["r"]
        termes = _budget_theoreme_8(S, q["lam"] - 2)
        m[f"{lvl}_termes_theoreme_8_q_2^(lambda-2)"] = {k: round(v, 1) for k, v in termes.items()}
        c[f"{lvl}_theoreme_8_atteint_lambda"] = max(termes.values()) <= -2 + 1     # ≤ 2q/2^λ
        ap = AVANT[lvl]
        qq = est["quantique"]
        c[f"{lvl}_niveaux_v03_conserves"] = (est["isd"]["classique"] >= ap[0] and qq["isd"]["prange"] >= ap[1]
                                             and qq["effectif_bits"] >= ap[2] and qq["categorie_nist"] >= ap[3])
        m[f"{lvl}_marche_quantique_isd"] = qq["isd"]["minimum"]
        # bits de τ et de t : un de moins ne suffirait pas
        moins = _reduit(lvl, tau=q["tau"] - 1)
        c[f"{lvl}_tau_minimal"] = moins.falsification_bits() < q["lam"]
        pkk, skk = R.keygen()
        ss = R.sign(skk, pkk, b"ordre")
        c[f"{lvl}_signature_valide_et_taille_exacte"] = R.verify(pkk, b"ordre", ss) and len(ss) == S.sizes()["sig_bytes"]
        ab = bytearray(ss); ab[32 + q["hb"] - 1] ^= 1
        c[f"{lvl}_h1_complet_verifie"] = not R.verify(pkk, b"ordre", bytes(ab))
        ab = bytearray(ss); ab[32 + 2 * q["hb"] - 1] ^= 1
        c[f"{lvl}_h2_complet_verifie"] = not R.verify(pkk, b"ordre", bytes(ab))
        m[f"tailles_{lvl}"] = S.sizes()
    out = {"controles": c, "mesures": m}
    sauver("sig", out)
    return out


if __name__ == "__main__":
    print(run())
