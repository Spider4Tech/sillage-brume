# -*- coding: utf-8 -*-
"""Tests fonctionnels v0.6 : KAT et tables figées de BRUME-1024q, aller-retours AEAD / AEAD parallèle / TE / KEM / SIG,
démo. Les contrôles détaillés de BRUME-1024q sont en C (tests/c/brume1024.c, tests/c/brume1024_api.c)."""
import hashlib
import os
import subprocess
import sys

from tests.commun import sauver, RACINE
from sillage import (SillageKEM, SillageSIG, Brume1024, Brume1024P, Brume1024TagError, Brume1024TamperError,
                     brume1024_hash, brume1024_xof, BRUME1024_PROFILES)

# SPEC § 4 (tests/c/kat_b1024.h) : H("abc", 64)
KAT_HASH_ABC = ("062a5ef271ad9bd6447ba12a02771e2337adcc35a525103309ce4bcb4e28dbfe"
                "7dbd80b3941e1e836c3f10218cb4f84fd9909aed1bcb3c47d5c1e2e95f776916")
# empreinte des tables normatives (sillage/c/brume1024_tables.h, à partir de « #define B1_N ») : M, constantes, S-box
EMPREINTE_TABLES = "d8250f0786652d97"


def _empreinte_tables():
    s = open(os.path.join(RACINE, "sillage", "c", "brume1024_tables.h"), encoding="utf-8").read()
    return hashlib.sha256(s[s.index("#define B1_N"):].encode()).hexdigest()[:16]


def run():
    c, m = {}, {}
    c["kat_hachage_abc"] = brume1024_hash(b"abc").hex() == KAT_HASH_ABC
    c["hachage_64_octets_par_defaut_xof_distinct"] = (len(brume1024_hash(b"x")) == 64
                                                      and brume1024_xof(b"x", 64) != brume1024_hash(b"x"))
    c["tables_figees_empreinte"] = _empreinte_tables() == EMPREINTE_TABLES
    for prof in BRUME1024_PROFILES:
        br = Brume1024(prof)
        ok = True
        for L in list(range(0, 90)) + [159, 160, 161, 1000]:
            msg = bytes((7 * i + L) & 0xFF for i in range(L))
            ct, tag = br.encrypt(bytes(24), msg, b"aad")
            ok &= br.decrypt(bytes(24), ct, tag, b"aad") == msg
            ok &= len(ct) == L and len(tag) == br.p["tag_len"] == 32
        try:
            br.decrypt(bytes(24), ct, bytes(32), b"aad")
            ok = False
        except Brume1024TagError:
            pass
        c[f"aead_aller_retour_et_rejet_{prof}"] = ok
        ok = True
        for L in (0, 1, 63, 64, 65, 500):
            msg = bytes((3 * i + 1) & 0xFF for i in range(L))
            ct, par, tag, meta = br.encrypt_te(bytes(24), msg)
            abime = bytearray(ct)
            if L:
                abime[L // 2] ^= 0x5A
            pt, corr = br.decrypt_te(bytes(24), bytes(abime), par, tag, meta)
            ok &= pt == msg and corr == ([L // 2] if L else [])
            if L >= 2:
                abime[0] ^= 1
                abime[1] ^= 2
                try:
                    br.decrypt_te(bytes(24), bytes(abime), par, tag, meta)
                    ok = False
                except (Brume1024TamperError, Brume1024TagError):
                    pass
        c[f"te_correction_et_refus_{prof}"] = ok
    bp = Brume1024P()
    ok = True
    for L in (0, 1, 8191, 8192, 8193, 3 * 8192 + 5):
        msg = os.urandom(L)
        ct, tag = bp.encrypt(bytes(24), msg)
        ok &= bp.decrypt(bytes(24), ct, tag) == msg
    c["aead_parallele_aller_retour"] = ok
    for lvl, n_ in (("Sillage-128", 40), ("Sillage-256", 6)):
        kem = SillageKEM(lvl)
        pk, sk = kem.keygen()
        oks = [kem.decaps(sk, ct) == ss for ct, ss in (kem.encaps(pk) for _ in range(n_))]
        c[f"kem_aller_retour_{lvl}"] = all(oks)
        m[f"kem_essais_{lvl}"] = n_
    for lvl in ("Sillage-SIG-128", "Sillage-SIG-256"):
        sig = SillageSIG(lvl)
        pk, sk = sig.keygen()
        s = sig.sign(sk, pk, b"ordre")
        c[f"sig_aller_retour_{lvl}"] = sig.verify(pk, b"ordre", s)
    r = subprocess.run([sys.executable, "-m", "sillage.demo"], cwd=RACINE,
                       capture_output=True, text=True, timeout=600)
    c["demo_execution"] = r.returncode == 0
    m["demo_fin"] = r.stdout[-400:] if r.returncode == 0 else r.stderr[-2000:]
    out = {"controles": c, "mesures": m}
    sauver("fonctionnel", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
