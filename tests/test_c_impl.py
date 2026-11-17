# -*- coding: utf-8 -*-
"""Conformité de l'implémentation C (sillage/c/) avec le paquet Python.

KEM (chiffrement déterministe, décapsulation, rejet implicite, borne δ, interopérabilité des clés dans les deux sens) et
SIG (signatures C vérifiées par Python et inversement, rejets) : mêmes sorties octet pour octet. BRUME-1024q (v0.6) n'a
pas de référence Python (décision D1) : ses liaisons Python sont contrôlées contre les KAT de la SPEC et contre les
fonctions unitaires du C (AEAD, AEAD parallèle, lots, contexte de clé, TE).
"""
import os

import numpy as np

from tests.commun import sauver, RACINE
from sillage import sillage_c as S
from sillage.sillage_kem import SillageKEM, borne_echec_log2
from sillage.sillage_sig import SillageSIG

LONGUEURS = list(range(0, 70)) + [95, 96, 97, 127, 128, 129, 255, 256, 257, 1000, 4097]


def _kat(nom):
    """Valeur figée de tests/c/kat_b1024.h (SPEC § 4)."""
    import re
    t = open(os.path.join(RACINE, "tests", "c", "kat_b1024.h"), encoding="utf-8").read()
    return bytes.fromhex(re.search(r'\{"%s",\s*"([0-9a-f]*)"\}' % re.escape(nom), t).group(1))


def _brume(c, m):
    """BRUME-1024q (v0.6) par les liaisons Python : pas de référence Python (décision D1) ; on contrôle les liaisons
    contre les KAT de la SPEC et contre les fonctions unitaires du C (les contrôles internes sont dans tests/c/)."""
    import hashlib
    msg = bytes(i % 251 for i in range(3 * 8192 + 5))
    k, n, a = bytes(range(64)), bytes(0x80 + i for i in range(24)), msg[1000:1009]
    c["kat_hachage_par_les_liaisons"] = all(S.hash(msg[:L], 64) == _kat(f"hachage_{L}") for L in (0, 1, 79, 80, 81, 8192, 8193))
    c["kat_xof_par_les_liaisons"] = S.xof(msg[:200], 200) == _kat("xof_200")
    ok = True
    for L in (0, 16, 64, 1000):
        ct, tag = S.aead_encrypt("BRUME-1024q", k, n, msg[:L], a)
        ok &= tag + hashlib.shake_256(ct).digest(32) == _kat(f"aead_{L}") and S.aead_decrypt("BRUME-1024q", k, n, ct, tag, a) == msg[:L]
    for L in (0, 1000, 8192, 8193, 3 * 8192 + 5):
        ct, tag = S.aead_p_encrypt("BRUME-1024qp", k, n, msg[:L], a)
        ok &= tag + hashlib.shake_256(ct).digest(32) == _kat(f"aeadp_{L}") and S.aead_p_decrypt("BRUME-1024qp", k, n, ct, tag, a) == msg[:L]
    c["kat_aead_et_aead_parallele_par_les_liaisons"] = ok
    c["permutation_egale_reference"] = all(S.permute(e := os.urandom(128)) == S.permute_ref(e) for _ in range(200))
    c["permutation_inverse_reference"] = all(S.permute_inv_ref(S.permute(e := os.urandom(128))) == e for _ in range(20))
    lot = [os.urandom(128) for _ in range(32)]
    c["permutation_lot_32_etats"] = S.permute_lot(lot) == [S.permute_ref(e) for e in lot]
    rng2 = np.random.default_rng(8)
    lens = [int(x) for x in rng2.integers(0, 700, 97)] + [0, 1, 15, 16, 79, 80, 81, 5000, 9000]
    msgs = [os.urandom(L) for L in lens]
    c["hachage_multi_messages"] = S.hash_multi(msgs, 40) == [S.hash(x, 40) for x in msgs]
    gros = [os.urandom(250) for _ in range(800)]             # même longueur : chemin par lots du C
    prof = "BRUME-1024q"
    ks, ns = [os.urandom(64) for _ in gros], [os.urandom(24) for _ in gros]
    for nom, lotm, aads in (("par_lots", gros, None), ("longueurs_variees", msgs, [os.urandom(i % 45) for i in range(len(msgs))])):
        mult = S.aead_encrypt_multi(prof, ks[:len(lotm)], ns[:len(lotm)], lotm, aads)
        ok_l = all(mult[i] == S.aead_encrypt(prof, ks[i], ns[i], lotm[i], aads[i] if aads else b"") for i in range(len(lotm)))
        tg = [t for _, t in mult]
        tg[7] = bytes([tg[7][0] ^ 1]) + tg[7][1:]
        dm = S.aead_decrypt_multi(prof, ks[:len(lotm)], ns[:len(lotm)], [x for x, _ in mult], tg, aads)
        c[f"aead_multi_{nom}"] = ok_l and dm[7] is None and all(dm[i] == lotm[i] for i in range(len(lotm)) if i != 7)
    k1 = os.urandom(64)
    ctx = S.aead_cle(prof, k1)
    ok_c = all(S.aead_encrypt_ctx(ctx, n_, m_, a_) == S.aead_encrypt(prof, k1, n_, m_, a_)
               for n_, m_, a_ in ((os.urandom(24), os.urandom(L), os.urandom(L % 7)) for L in (0, 1, 79, 80, 81, 300)))
    ns_ = [os.urandom(24) for _ in gros]
    mc = S.aead_encrypt_multi_ctx(ctx, ns_, gros)
    ok_c &= all(mc[i] == S.aead_encrypt(prof, k1, ns_[i], gros[i]) for i in range(0, len(gros), 7))
    tg = [t for _, t in mc]
    tg[2] = bytes([tg[2][0] ^ 1]) + tg[2][1:]
    dc = S.aead_decrypt_multi_ctx(ctx, ns_, [x for x, _ in mc], tg)
    ok_c &= dc[2] is None and all(dc[i] == gros[i] for i in range(len(gros)) if i != 2)
    c["aead_contexte_de_cle"] = ok_c
    rejet = te = corr = True
    for L in LONGUEURS:
        k, n, a, pt = os.urandom(64), os.urandom(24), os.urandom(L % 41), os.urandom(L)
        ct, tag = S.aead_encrypt(prof, k, n, pt, a)
        for alt in (lambda: (bytes([ct[0] ^ 1]) + ct[1:], tag, a) if L else None,
                    lambda: (ct, bytes([tag[0] ^ 1]) + tag[1:], a),
                    lambda: (ct, tag, a + b"x")):
            v = alt()
            if v:
                rejet &= S.aead_decrypt(prof, k, n, v[0], v[1], v[2]) is None
        e = S.te_encrypt(prof, k, n, pt, a)
        te &= (e[0], e[2]) == (ct, tag) and len(e[1]) == 7 * (-(-L // 64)) and int.from_bytes(e[3], "big") == L
        if L:
            ab = bytearray(e[0]); ab[L // 2] ^= 0xA5
            rc, p2, cs = S.te_decrypt(prof, k, n, bytes(ab), e[1], e[2], e[3], a)
            corr &= rc == 0 and p2 == pt and cs == [L // 2]
            if L // 2 + 1 < L and (L // 2) // 64 == (L // 2 + 1) // 64:
                ab[L // 2 + 1] ^= 0x3C                         # deux octets du même bloc : refus, jamais de clair
                corr &= S.te_decrypt(prof, k, n, bytes(ab), e[1], e[2], e[3], a)[0] in (-1, -2)
    c["aead_rejets"] = rejet
    c["te_chiffre_et_tag_de_l_aead"] = te
    c["te_corrections"] = corr
    # docs/SPEC.md § 2.8 : réponses connues de la v0.6, relues dans le texte
    import re as _re
    t = open(os.path.join(RACINE, "docs", "SPEC.md"), encoding="utf-8").read()
    t = t[t.index("### 2.8 Known answers"):t.index("## 3. Sillage-KEM")]
    val = [x for x in _re.findall(r"\| `([0-9a-f]{40,})` \|", t)]
    k8, n8 = bytes(range(64)), bytes(range(24))
    ct8, tg8 = S.aead_encrypt(prof, k8, n8, b"SILLAGE", b"kat")
    cp8, tp8 = S.aead_p_encrypt("BRUME-1024qp", k8, n8, b"SILLAGE", b"kat")
    te8 = S.te_encrypt(prof, k8, n8, b"SILLAGE", b"kat")
    calc = [S.permute(bytes(128)), S.hash(b"", 64), S.hash(b"abc", 64), S.hash(b"A" * 20000, 64), S.xof(b"abc", 64),
            ct8 + tg8, cp8 + tp8, te8[0] + te8[1] + te8[2] + te8[3]]
    m["spec_2_8_valeurs"] = len(val)
    c["reponses_connues_spec_2_8"] = len(val) == 8 and [bytes.fromhex(v) for v in val] == calc


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
