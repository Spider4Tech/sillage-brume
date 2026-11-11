# -*- coding: utf-8 -*-
"""Tests fonctionnels : auto-tests BRUME, KAT, aller-retours KEM/AEAD/SIG, démo."""
import subprocess
import sys

from tests.commun import sauver, RACINE
from sillage import (SillageKEM, SillageSIG, Brume512, brume512_hash,
                     BRUME512_PROFILES)
from sillage import brume512 as B

KAT_HASH = "fefe446dbb192f2f28617b91d53cbda00625bf7f5212f5b88c3d80cc728c5d5c"   # v0.5 (S-box AD412650BFEC7893)


def run():
    c, m = {}, {}
    st = B.selftest(verbose=False)
    m["selftest_brume"] = st
    c["selftest_brume_tout_vrai"] = all(v is True for k, v in st.items()
                                        if isinstance(v, bool))
    c["kat_hachage"] = brume512_hash(b"BRUME-512 KAT", 32).hex() == KAT_HASH
    c["tables_figees_empreintes"] = _empreintes_ok()
    for prof in BRUME512_PROFILES:
        br = Brume512(prof)
        ok = True
        for L in list(range(0, 70)) + [127, 128, 129, 1000]:
            msg = bytes((7 * i + L) & 0xFF for i in range(L))
            ct, tag = br.encrypt(bytes(24), msg, b"aad")
            ok &= br.decrypt(bytes(24), ct, tag, b"aad") == msg
            ok &= len(ct) == L and len(tag) == br.p["tag_len"]
        c[f"aead_aller_retour_{prof}"] = ok
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


def _empreintes_ok():
    import hashlib
    from sillage import brume512_tables as T
    sha = lambda o: hashlib.sha256(repr(o).encode()).hexdigest()[:16]
    return all(sha(getattr(T, k)) == v for k, v in T.CHECK.items())


if __name__ == "__main__":
    print(run()["controles"])
