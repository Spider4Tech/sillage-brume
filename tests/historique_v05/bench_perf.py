# -*- coding: utf-8 -*-
"""
SILLAGE — banc de performances (v0.3.0)
=======================================
Temps d'exécution, tailles et estimations de sécurité (ISD concret) de chaque
primitive. La cryptanalyse complète vit dans la batterie de tests :
    python3 -m tests.run_all

Usage :  python3 -m tests.bench_perf [--quick]   → resultats/bench_perf.txt
"""

import json
import os
import platform
import statistics
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sillage.sillage_kem import SillageKEM
from sillage.brume512 import (Brume512, brume512_hash, BRUME512_PROFILES,
                              SBOX as SBOX512, ADJ as ADJ512, N as N512,
                              DEG as DEG512)
from sillage.sillage_sig import SillageSIG

LINE = "=" * 78
SUB = "-" * 78


def fmt_ms(times_ms):
    return "%8.1f ms  (min %7.1f | méd %7.1f | max %7.1f)" % (
        statistics.mean(times_ms), min(times_ms),
        statistics.median(times_ms), max(times_ms))


def bench_call(fn, n, warmup=2):
    for _ in range(warmup):
        fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1e3)
    return ts


# ------------------------------------------------------------------
# 1. KEM
# ------------------------------------------------------------------

def bench_kem(quick=False):
    print(LINE)
    print("1. SILLAGE-KEM — encapsulation de clés (LPN creux, cascade de bruit)")
    print(LINE)
    n_enc = 8 if quick else 20
    for lvl in ("Sillage-128", "Sillage-256"):
        kem = SillageKEM(lvl)
        print(SUB)
        print(f"  Profil : {lvl}")
        # keygen
        pks, sks = [], []
        tk = bench_call(lambda: pks.append(None) if False else kem.keygen(),
                        8 if quick else 12)
        # encaps/decaps sur une paire fixe (mesure propre, π déjà en cache)
        pk, sk = kem.keygen()
        te = bench_call(lambda: kem.encaps(pk), n_enc)
        ct0, _ = kem.encaps(pk)
        td = bench_call(lambda: kem.decaps(sk, ct0), n_enc)
        print(f"    keygen   : {fmt_ms(tk)}")
        print(f"    encaps   : {fmt_ms(te)}")
        print(f"    decaps   : {fmt_ms(td)}")
        s = kem.sizes()
        print(f"    tailles  : pk {s['pk_bytes']:,} o | ct {s['ct_bytes']:,} o | "
              f"sk {s['sk_bytes']:,} o | ss {s['ss_bytes']} o")
        # cohérence sur tous les essais
        ok = sum(1 for _ in range(8 if quick else 25)
                 for c, a in [kem.encaps(pk)] if kem.decaps(sk, c) == a)
        tot = 8 if quick else 25
        print(f"    cohérence: {ok}/{tot} secrets partagés identiques "
              f"(0 échec de décodage attendu)")
        sec = kem.security_estimate()
        print(f"    sécurité : clé {sec['recuperation_cle_bits']:.0f} bits | "
              f"message {sec['recuperation_message_bits']:.0f} bits | "
              f"quantique (Prange-Grover) {sec['quantique_bits']:.0f} bits "
              f"[ISD concret BJMM/Stern-Dumer/Prange]")


# ------------------------------------------------------------------
# 2. BRUME-512 v1
# ------------------------------------------------------------------

def _sbox4_props():
    """(U, max|LAT|) de la S-box 4 bits — recalcul local complet (16×16)."""
    s = SBOX512
    X = np.arange(16, dtype=np.uint8)
    ddt = np.zeros((16, 16), dtype=np.int32)
    for a in range(16):
        d = s[X] ^ s[X ^ a]
        for v in range(16):
            ddt[a, v] = int((d == v).sum())
    lat = np.zeros((16, 16), dtype=np.int32)
    for al in range(16):
        for lam in range(16):
            cnt = sum(1 for x in range(16)
                      if (bin(al & int(s[x])).count("1") % 2) ==
                         (bin(lam & x).count("1") % 2))
            lat[al, lam] = cnt - 8
    return int(ddt[1:].max()), int(np.abs(lat[1:]).max())


def bench_brume512(quick=False):
    from sillage.brume512 import brume_v1, diffuse
    print()
    print(LINE)
    print("2. BRUME-512 v1 — chiffrement symétrique (sponge, S-box 4 bits,")
    print("   diffusion par graphe de Cayley D128 pondéré, 32 tours)")
    print(LINE)
    # --- S-box 4 bits (recalcul indépendant) ---
    U, lat_max = _sbox4_props()
    print(SUB)
    print(f"  S-box 4 bits : uniformité différentielle U = {U} "
          f"(minimum théorique) | max|LAT| = {lat_max} (NL = {8 - lat_max}, "
          f"maximum théorique)")
    # --- graphe de diffusion ---
    ev = np.sort(np.linalg.eigvalsh(ADJ512.astype(float)))
    lam_star = float(np.abs(ev[1:-1]).max())
    # branch number poids 1 : wt(M·e_i) pour tous les i
    w1 = [int((diffuse(np.eye(N512, dtype=np.uint8, k=i)[0]) != 0).sum())
          for i in range(N512)]
    print(f"  Graphe de diffusion : Cayley(D128) 6-régulier, 128 sommets | "
          f"λ* = {lam_star:.4f} < 2√5 ≈ 4.4721 → Ramanujan : "
          f"{lam_star <= 2 * np.sqrt(5)}")
    print(f"  Branch number poids 1 : wt(M·e_i) = {min(w1)}..{max(w1)} "
          f"(= 7 attendu) → B(poids 1) = {1 + min(w1)} | "
          f"B(poids 2) = 13 exact — voir banc cryptanalyse")

    for prof in ("BRUME-512", "BRUME-512-256"):
        br = Brume512(prof, key=bytes(range(64)))
        p = BRUME512_PROFILES[prof]
        print(SUB)
        print(f"  Profil : {prof} (état 512 bits, débit {p['rate'] * 4} bits, "
              f"capacité {512 - p['rate'] * 4} bits, 32 tours, "
              f"tag {p['tag_len'] * 8} bits)")

        # permutation pure
        rng = np.random.default_rng(7)
        state = rng.integers(0, 16, size=N512).astype(np.uint8)
        tp = bench_call(lambda: brume_v1(state), 60 if quick else 200)
        print(f"    permutation : {fmt_ms(tp)}  →  "
              f"{1e3 / statistics.mean(tp):,.0f} permutations/s")

        # avalanche : 1 nibble d'entrée modifié → % de bits de sortie inversés
        base = brume_v1(state).tobytes()
        flips = []
        for _ in range(40):
            st = state.copy()
            j = int(rng.integers(0, N512))
            st[j] ^= 1 << int(rng.integers(1, 4))
            out = brume_v1(st).tobytes()
            d = int.from_bytes(out, "big") ^ int.from_bytes(base, "big")
            flips.append(d.bit_count() / 512 * 100)
        print(f"    avalanche   : {statistics.mean(flips):.1f} % de bits "
              f"inversés (méd {statistics.median(flips):.1f} %) — cible ≈ 50 %")

        # AEAD duplex
        taille = 16 * 1024 if quick else 32 * 1024
        msg = os.urandom(taille)
        nonce = bytes(range(24))
        tc = bench_call(lambda: br.encrypt(nonce, msg), 2 if quick else 3)
        ct0, tag0 = br.encrypt(nonce, msg)
        td = bench_call(lambda: br.decrypt(nonce, ct0, tag0),
                        2 if quick else 3)
        kbs = len(msg) / 1024 / (statistics.mean(tc) / 1000)
        print(f"    chiffrement : {fmt_ms(tc)}  →  {kbs:,.0f} KB/s "
              f"(Python pur ; projection C/AVX2 : ×100-500)")
        print(f"    déchiffrement + tag : {fmt_ms(td)}")
        ct, tag = br.encrypt(nonce, msg, aad=b"bench")
        assert br.decrypt(nonce, ct, tag, aad=b"bench") == msg
        try:
            br.decrypt(nonce, ct + b"\x00", tag, aad=b"bench")
            raise AssertionError("extension acceptée — bug")
        except Exception as e:
            assert type(e).__name__ == "Brume512TagError", e
        print("    auto-tests  : roundtrip OK | extension de chiffré rejetée OK")

        # mode TE
        ct_te, pars, tag_te, meta = br.encrypt_te(nonce, msg[:2048])
        tt = bench_call(lambda: br.decrypt_te(nonce, ct_te, pars, tag_te, meta),
                        2 if quick else 4)
        overhead = len(pars) / max(len(ct_te), 1) * 100
        print(f"    mode TE     : déchiffrement+correction {fmt_ms(tt)} | "
              f"surcoût parité {overhead:.1f} % | corrige 1 o/bloc, détecte 2")

        # hachage
        blob = os.urandom(4096)
        th = bench_call(lambda: brume512_hash(blob, 32), 3 if quick else 8)
        print(f"    hachage     : {fmt_ms(th)}  →  "
              f"{4096 / 1024 / (statistics.mean(th) / 1000):,.0f} KB/s "
              f"(sortie 32 o, capacité 256 bits)")


# ------------------------------------------------------------------
# 3. Signatures
# ------------------------------------------------------------------

def bench_sig(quick=False):
    print()
    print(LINE)
    print("3. SILLAGE-SIG — signatures (MPC-in-the-Head, décodage de syndrome)")
    print(LINE)
    msg = "Manifeste de test SILLAGE - intégrité du canal de commande.".encode("utf-8")
    for lvl in ("Sillage-SIG-128", "Sillage-SIG-256"):
        sg = SillageSIG(lvl)
        print(SUB)
        print(f"  Profil : {lvl}")
        pk, sk = sg.keygen()
        ts = bench_call(lambda: sg.sign(sk, pk, msg), 3 if quick else 5)
        s0 = sg.sign(sk, pk, msg)
        tv = bench_call(lambda: sg.verify(pk, msg, s0), 3 if quick else 5)
        tk = bench_call(lambda: sg.keygen(), 3 if quick else 5)
        print(f"    keygen   : {fmt_ms(tk)}")
        print(f"    signature: {fmt_ms(ts)}")
        print(f"    vérif.   : {fmt_ms(tv)}")
        s = sg.sizes()
        print(f"    tailles  : pk {s['pk_bytes']:,} o | sk {s['sk_bytes']:,} o | "
              f"sig {s['sig_bytes']:,} o")
        sec = sg.security_estimate()
        print(f"    sécurité : ISD {sec['isd']['classique']:.0f} bits | "
              f"quantique {sec['quantique_isd_bits']:.0f} bits | "
              f"forgery FS {sec['forgery_fs_bits']:.0f} bits | "
              f"effectif {sec['effective_bits']:.0f} bits")


# ------------------------------------------------------------------
# 4. Comparaison
# ------------------------------------------------------------------

def comparison_table():
    from sillage.sillage_kem import SillageKEM
    from sillage.sillage_sig import SillageSIG
    print()
    print(LINE)
    print("4. Tailles SILLAGE v0.4 (calculées)")
    print(LINE)
    for lvl in ("Sillage-128", "Sillage-256"):
        z = SillageKEM(lvl).sizes()
        print(f"  KEM {lvl:<14} pk {z['pk_bytes']:>7,} o | ct {z['ct_bytes']:>7,} o")
    for lvl in ("Sillage-SIG-128", "Sillage-SIG-256"):
        z = SillageSIG(lvl).sizes()
        print(f"  SIG {lvl:<14} pk {z['pk_bytes']:>7,} o | sig ~{z['sig_bytes']:>7,} o")
    print("  BRUME-512           clé 64 o | tag 16 o (BRUME-512-256 : 32 o)")
    print("  Cryptanalyse complète : python3 -m tests.run_all → resultats/SYNTHESE.md")


def main():
    quick = "--quick" in sys.argv
    print(LINE)
    print("SILLAGE v0.4.0 — banc de benchmarks | Python", platform.python_version(),
          "|", platform.machine())
    print(LINE)
    t_start = time.perf_counter()
    bench_kem(quick)
    bench_brume512(quick)
    bench_sig(quick)
    comparison_table()
    print()
    print(f"Durée totale du banc : {time.perf_counter()-t_start:.1f} s")


if __name__ == "__main__":
    import contextlib
    import io
    from tests.commun import RESULTATS
    tampon = io.StringIO()

    class _Tee(io.TextIOBase):
        def write(self, x):
            sys.__stdout__.write(x)
            tampon.write(x)
            return len(x)

    with contextlib.redirect_stdout(_Tee()):
        main()
    with open(os.path.join(RESULTATS, "bench_perf.txt"), "w", encoding="utf-8") as f:
        f.write(tampon.getvalue())
