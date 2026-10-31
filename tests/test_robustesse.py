# -*- coding: utf-8 -*-
"""Robustesse (fuzzing) : entrées aléatoires et malformées vers tous les
décodeurs — seules les exceptions déclarées sont admises — et mesures de
temps indicatives (implémentation Python NON constant-time)."""
import os
import statistics
import time

import numpy as np

from tests.commun import sauver
from sillage import SillageKEM, SillageSIG, Brume512, brume512_hash
from sillage.brume512 import Brume512TagError, Brume512TamperError


def run():
    rng = np.random.default_rng(17)
    c, m = {}, {}
    br = Brume512("BRUME-512")
    inattendues = []
    for _ in range(300):
        L = int(rng.integers(0, 200))
        ct = os.urandom(L)
        tag = os.urandom(int(rng.choice([0, 15, 16, 17, 32])))
        n = os.urandom(int(rng.choice([15, 16, 17])))
        try:
            br.decrypt(n, ct, tag, os.urandom(int(rng.integers(0, 40))))
            inattendues.append("decrypt_accepte")
        except (Brume512TagError, ValueError):
            pass
        except Exception as e:                       # noqa: BLE001
            inattendues.append(f"decrypt:{type(e).__name__}")
        try:
            br.decrypt_te(bytes(24), ct, os.urandom(int(rng.integers(0, 30))),
                          os.urandom(16), os.urandom(int(rng.choice([0, 8, 9]))))
            inattendues.append("decrypt_te_accepte")
        except (Brume512TagError, Brume512TamperError, ValueError):
            pass
        except Exception as e:                       # noqa: BLE001
            inattendues.append(f"decrypt_te:{type(e).__name__}")
    for L in (0, 1, 31, 32, 33, 1000):
        brume512_hash(os.urandom(L), int(rng.integers(1, 200)))
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
        except Brume512TagError:
            pass
    kct, kss = kem.encaps(kpk)
    m["temps_s"] = {
        "decrypt_valide": chrono(lambda: dec(tag)),
        "decrypt_tag_faux": chrono(lambda: dec(bytes(24))),
        "decaps_valide": chrono(lambda: kem.decaps(ksk, kct), 5),
        "decaps_rejet": chrono(lambda: kem.decaps(ksk, (kct[0], kct[1] ^ 1)), 5),
    }
    m["note"] = ("Python non constant-time : écarts de temps attendus ; le rejet "
                 "implicite FO ré-encapsule dans les deux cas pour limiter l'écart.")
    out = {"controles": c, "mesures": m}
    sauver("robustesse", out)
    return out


if __name__ == "__main__":
    print(run())
