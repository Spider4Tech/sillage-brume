# -*- coding: utf-8 -*-
"""Robustesse (fuzzing) : entrées aléatoires et malformées vers tous les
décodeurs — seules les exceptions déclarées sont admises — et mesures de
temps indicatives (implémentation Python NON constant-time)."""
import os
import statistics
import time

import numpy as np

from tests.commun import sauver
from sillage import SillageKEM, SillageSIG, Brume1024, brume1024_hash, Brume1024TagError, Brume1024TamperError


def run():
    rng = np.random.default_rng(17)
    c, m = {}, {}
    br = Brume1024("BRUME-1024q")
    inattendues = []
    for _ in range(300):
        L = int(rng.integers(0, 200))
        ct = os.urandom(L)
        tag = os.urandom(int(rng.choice([0, 16, 31, 32, 33])))
        n = os.urandom(int(rng.choice([23, 24, 25])))
        try:
            br.decrypt(n, ct, tag, os.urandom(int(rng.integers(0, 40))))
            inattendues.append("decrypt_accepte")
        except (Brume1024TagError, ValueError):
            pass
        except Exception as e:                       # noqa: BLE001
            inattendues.append(f"decrypt:{type(e).__name__}")
        try:
            br.decrypt_te(bytes(24), ct, os.urandom(int(rng.integers(0, 30))),
                          os.urandom(int(rng.choice([16, 32]))), os.urandom(int(rng.choice([0, 8, 9]))))
            inattendues.append("decrypt_te_accepte")
        except (Brume1024TagError, Brume1024TamperError, ValueError):
            pass
        except Exception as e:                       # noqa: BLE001
            inattendues.append(f"decrypt_te:{type(e).__name__}")
    for L in (0, 1, 79, 80, 81, 1000, 8193):
        brume1024_hash(os.urandom(L), int(rng.integers(1, 200)))
    sig = SillageSIG()
    pk, sk = sig.keygen()
    for _ in range(40):
        bad = os.urandom(int(rng.integers(0, 3000)) if _ % 4 else sig.sizes()["sig_bytes"])
        try:
            if sig.verify(pk, b"m", bad):
                inattendues.append("verify_accepte")
        except Exception as e:                       # noqa: BLE001
            inattendues.append(f"verify:{type(e).__name__}")
    kem = SillageKEM()
    kpk, ksk = kem.keygen()
    n, n2 = kem.p["n"], kem.p["n2"]
    for _ in range(10):
        try:
            kem.decaps(ksk, (int.from_bytes(os.urandom((n + 7) // 8), "little"),
                             int.from_bytes(os.urandom((n2 + 7) // 8), "little")))
        except Exception as e:                       # noqa: BLE001
            inattendues.append(f"decaps:{type(e).__name__}")
    m["exceptions_inattendues"] = inattendues
    c["fuzzing_aucune_exception_inattendue"] = not inattendues

    # mesures de temps (information) : écart valide / invalide
    def chrono(f, k=15):
        t = []
        for _ in range(k):
            t0 = time.perf_counter(); f(); t.append(time.perf_counter() - t0)
        return statistics.median(t)
    ct, tag = br.encrypt(bytes(24), b"x" * 100)
    def dec(tg):
        try:
            br.decrypt(bytes(24), ct, tg)
        except Brume1024TagError:
            pass
    kct, kss = kem.encaps(kpk)
    m["temps_s"] = {
        "decrypt_valide": chrono(lambda: dec(tag)),
        "decrypt_tag_faux": chrono(lambda: dec(bytes(32))),
        "decaps_valide": chrono(lambda: kem.decaps(ksk, kct), 5),
        "decaps_rejet": chrono(lambda: kem.decaps(ksk, (kct[0], kct[1] ^ 1)), 5),
    }
    m["note"] = ("Mesures indicatives depuis Python. BRUME-1024q est en C (temps constant mesuré par dudect : "
                 "tests/c/temps1024.c) ; le KEM de référence Python n'est pas constant-time, le rejet "
                 "implicite FO ré-encapsule dans les deux cas pour limiter l'écart.")
    out = {"controles": c, "mesures": m}
    sauver("robustesse", out)
    return out


if __name__ == "__main__":
    print(run())
