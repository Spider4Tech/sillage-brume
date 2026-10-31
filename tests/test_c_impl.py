# -*- coding: utf-8 -*-
"""Conformité de l'implémentation C (sillage/c/) avec le paquet Python.

Mêmes sorties octet pour octet : permutation, hachage (longueurs et tailles
de sortie variées), AEAD et TE des deux profils (chiffrés, tags, parités,
rejets, corrections), KEM (chiffrement déterministe, décapsulation, rejet
implicite, borne δ, interopérabilité des clés dans les deux sens), SIG
(signatures C vérifiées par Python et inversement, rejets).
"""
import os

import numpy as np

from tests.commun import sauver
from sillage import sillage_c as S
from sillage import brume512 as B
from sillage.brume512 import Brume512, Brume512TagError, Brume512TamperError, brume512_hash
from sillage.sillage_kem import SillageKEM, borne_echec_log2
from sillage.sillage_sig import SillageSIG

LONGUEURS = list(range(0, 70)) + [95, 96, 97, 127, 128, 129, 255, 256, 257, 1000, 4097]


def _brume(c, m):
    rng = np.random.default_rng(5)
    X = rng.integers(0, 16, (64, B.N), dtype=np.uint8)
    c["permutation"] = all(S.permute(B._pack_nibbles(x)) == B._pack_nibbles(B.brume_v1(x)) for x in X)
    c["permutation_avx2_egale_reference"] = all(S.permute(e := os.urandom(64)) == S.permute_ref(e) for _ in range(500))
    lot = [os.urandom(64) for _ in range(32)]
    c["permutation_lot_32_etats"] = S.permute_lot(lot) == [S.permute_ref(e) for e in lot]
    rng2 = np.random.default_rng(8)
    lens = [int(x) for x in rng2.integers(0, 700, 97)] + [0, 1, 15, 16, 17, 31, 32, 33, 5000]
    msgs = [os.urandom(L) for L in lens]
    c["hachage_multi_messages"] = S.hash_multi(msgs, 40) == [brume512_hash(x, 40) for x in msgs]
    # 800 messages courts : assez pour que sl_*_multi choisisse les lots de 32
    gros = [os.urandom(int(L)) for L in rng2.integers(0, 200, 800)]
    c["hachage_multi_par_lots"] = S.hash_multi(gros, 32) == [brume512_hash(x, 32) for x in gros]
    for prof in ("BRUME-512", "BRUME-512-256"):
        ks, ns = [os.urandom(64) for _ in gros], [os.urandom(24) for _ in gros]
        mult = S.aead_encrypt_multi(prof, ks, ns, gros)
        ok_l = all(mult[i] == Brume512(prof, key=ks[i]).encrypt(ns[i], gros[i]) for i in range(len(gros)))
        tg = [t for _, t in mult]
        tg[7] = bytes([tg[7][0] ^ 1]) + tg[7][1:]
        dm = S.aead_decrypt_multi(prof, ks, ns, [x for x, _ in mult], tg)
        c[f"{prof}_aead_multi_par_lots"] = ok_l and dm[7] is None and all(
            dm[i] == gros[i] for i in range(len(gros)) if i != 7)
        # contexte de clé (clé absorbée une fois) : unitaire, multi par lots, multi par message
        k1 = os.urandom(64)
        ctx = S.aead_cle(prof, k1)
        br1 = Brume512(prof, key=k1)
        ok_c = all(S.aead_encrypt_ctx(ctx, n_, m_, a_) == br1.encrypt(n_, m_, a_)
                   for n_, m_, a_ in ((os.urandom(24), os.urandom(L), os.urandom(L % 7)) for L in (0, 1, 31, 32, 33, 100)))
        for lot in (gros, msgs):                     # 800 messages (lots) / ~100 (un par cœur)
            ns_ = [os.urandom(24) for _ in lot]
            mc = S.aead_encrypt_multi_ctx(ctx, ns_, lot)
            ok_c &= all(mc[i] == br1.encrypt(ns_[i], lot[i]) for i in range(len(lot)))
            tg = [t for _, t in mc]
            tg[2] = bytes([tg[2][0] ^ 1]) + tg[2][1:]
            dc = S.aead_decrypt_multi_ctx(ctx, ns_, [x for x, _ in mc], tg)
            ok_c &= dc[2] is None and all(dc[i] == lot[i] for i in range(len(lot)) if i != 2)
        c[f"{prof}_aead_contexte_de_cle"] = ok_c
    c["hachage"] = all(S.hash(msg := os.urandom(L), o) == brume512_hash(msg, o)
                       for L in LONGUEURS for o in (16, 32, 33, 64))
    for prof in ("BRUME-512", "BRUME-512-256"):
        ok = rejet = te = corr = True
        for L in LONGUEURS:
            k, n, a, pt = os.urandom(64), os.urandom(24), os.urandom(L % 41), os.urandom(L)
            br = Brume512(prof, key=k)
            ct, tag = br.encrypt(n, pt, a)
            ok &= S.aead_encrypt(prof, k, n, pt, a) == (ct, tag) and S.aead_decrypt(prof, k, n, ct, tag, a) == pt
            for alt in (lambda: (bytes([ct[0] ^ 1]) + ct[1:], tag, a) if L else None,
                        lambda: (ct, bytes([tag[0] ^ 1]) + tag[1:], a),
                        lambda: (ct, tag, a + b"x")):
                v = alt()
                if v:
                    rejet &= S.aead_decrypt(prof, k, n, v[0], v[1], v[2]) is None
            e = br.encrypt_te(n, pt, a)
            te &= S.te_encrypt(prof, k, n, pt, a) == e
            if L:
                ab = bytearray(e[0]); ab[L // 2] ^= 0xA5
                rc, p2, cs = S.te_decrypt(prof, k, n, bytes(ab), e[1], e[2], e[3], a)
                corr &= rc == 0 and p2 == pt and cs == br.decrypt_te(n, bytes(ab), e[1], e[2], e[3], a)[1]
                if L // 2 + 1 < L and (L // 2) // 64 == (L // 2 + 1) // 64:
                    ab[L // 2 + 1] ^= 0x3C        # deux octets du même bloc : même verdict
                    try:
                        br.decrypt_te(n, bytes(ab), e[1], e[2], e[3], a)
                        att = 0
                    except Brume512TamperError:
                        att = -2
                    except Brume512TagError:
                        att = -1
                    corr &= S.te_decrypt(prof, k, n, bytes(ab), e[1], e[2], e[3], a)[0] == att
        n_ = len(lens)
        ks, ns, aa = [os.urandom(64) for _ in range(n_)], [os.urandom(24) for _ in range(n_)], [os.urandom(i % 45) for i in range(n_)]
        mult = S.aead_encrypt_multi(prof, ks, ns, msgs, aa)
        ok_m = all(mult[i] == Brume512(prof, key=ks[i]).encrypt(ns[i], msgs[i], aa[i]) for i in range(n_))
        tg = [t for _, t in mult]
        tg[3] = bytes([tg[3][0] ^ 1]) + tg[3][1:]
        dm = S.aead_decrypt_multi(prof, ks, ns, [x for x, _ in mult], tg, aa)
        ok_m &= dm[3] is None and all(dm[i] == msgs[i] for i in range(n_) if i != 3)
        c[f"{prof}_aead_multi_messages"] = ok_m
        c[f"{prof}_aead_identique"] = ok
        c[f"{prof}_aead_rejets"] = rejet
        c[f"{prof}_te_identique"] = te
        c[f"{prof}_te_corrections"] = corr


def _kem(c, m):
    for lvl in ("Sillage-128", "Sillage-256"):
        kem = SillageKEM(lvl)
        p = kem.p
        n, n2 = p["n"], p["n2"]
        nb, nb2 = (n + 7) // 8, (n2 + 7) // 8
        pk, sk = kem.keygen()
        pkb = pk[0] + pk[1].to_bytes(nb, "little")
        x, y, sh, sr, s = sk
        skb = x.to_bytes(nb, "little") + y.to_bytes(nb, "little") + sh + sr + s.to_bytes(nb, "little")
        ok = rej = True
        for _ in range(5):
            mu = os.urandom(p["k"] // 8)
            u, v = kem._encrypt(pk, int.from_bytes(mu, "little"))
            ct = u.to_bytes(nb, "little") + v.to_bytes(nb2, "little")
            ss = kem._ss(int.from_bytes(mu, "little"), (u, v))
            ok &= S.kem_encaps(lvl, pkb, mu) == (ct, ss) and S.kem_decaps(lvl, skb, ct) == ss
            for pos in (3, nb + 7):
                ab = bytearray(ct); ab[pos] ^= 1
                rej &= S.kem_decaps(lvl, skb, bytes(ab)) == kem.decaps(
                    sk, (int.from_bytes(ab[:nb], "little"), int.from_bytes(ab[nb:], "little")))
        c[f"{lvl}_chiffrement_identique"] = ok
        c[f"{lvl}_rejet_implicite_identique"] = rej
        bc, bp = S.kem_borne(lvl, x.to_bytes(nb, "little"), y.to_bytes(nb, "little")), borne_echec_log2(x, y, p)
        m[f"{lvl}_borne_C_vs_python"] = (round(bc, 4), round(bp, 4))
        c[f"{lvl}_borne_identique"] = abs(bc - bp) < 1e-6
        inter = True
        for _ in range(2):
            pk2, sk2 = S.kem_keygen(lvl)
            x2, y2 = int.from_bytes(sk2[:nb], "little"), int.from_bytes(sk2[nb:2 * nb], "little")
            sk2p = (x2, y2, sk2[2 * nb:2 * nb + 32], sk2[2 * nb + 32:2 * nb + 64], int.from_bytes(sk2[2 * nb + 64:], "little"))
            pk2p = (pk2[:32], int.from_bytes(pk2[32:], "little"))
            ct2, ss2 = S.kem_encaps(lvl, pk2)
            inter &= kem.decaps(sk2p, (int.from_bytes(ct2[:nb], "little"), int.from_bytes(ct2[nb:], "little"))) == ss2
            (u3, v3), ss3 = kem.encaps(pk2p)
            inter &= S.kem_decaps(lvl, sk2, u3.to_bytes(nb, "little") + v3.to_bytes(nb2, "little")) == ss3
            inter &= borne_echec_log2(x2, y2, p) <= -p["lam"] and bin(x2).count("1") == p["w"]
        c[f"{lvl}_cles_C_interoperables_et_valides"] = inter


def _sig(c, m):
    for lvl in ("Sillage-SIG-128", "Sillage-SIG-256"):
        sg = SillageSIG(lvl)
        p = sg.p
        nb, rb = (p["n"] + 7) // 8, (p["r"] + 7) // 8
        pk, sk = sg.keygen()
        pkb, skb = pk[0] + pk[1].to_bytes(rb, "little"), sk
        msg = os.urandom(50)
        sel = os.urandom(32)
        sp, sc = sg.sign(sk, pk, msg, sel), S.sig_sign(lvl, skb, pkb, msg)
        c[f"{lvl}_signature_identique_octet_par_octet"] = S.sig_sign_sel(lvl, skb, pkb, msg, sel) == sp
        c[f"{lvl}_signature_python_verifiee_par_C"] = S.sig_verify(lvl, pkb, msg, sp)
        c[f"{lvl}_signature_C_verifiee_par_python"] = sg.verify(pk, msg, sc)
        ab = bytearray(sc); ab[200] ^= 1
        c[f"{lvl}_rejets"] = (not S.sig_verify(lvl, pkb, msg + b"!", sc)
                              and not S.sig_verify(lvl, pkb, msg, bytes(ab))
                              and not S.sig_verify(lvl, pkb, msg, sc[:-1]))
        pk2, sk2 = S.sig_keygen(lvl)
        c[f"{lvl}_cle_C_verifiee_par_python"] = sg.verify((pk2[:32], int.from_bytes(pk2[32:], "little")), msg,
                                                          S.sig_sign(lvl, sk2, pk2, msg))


def run():
    c, m = {}, {}
    _brume(c, m)
    _kem(c, m)
    _sig(c, m)
    c = {k: bool(v) for k, v in c.items()}
    out = {"controles": c, "mesures": m}
    sauver("c_impl", out)
    return out


if __name__ == "__main__":
    r = run()
    print(r["controles"])
    print(r["mesures"])
