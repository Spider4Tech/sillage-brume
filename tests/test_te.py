# -*- coding: utf-8 -*-
"""Mode auto-correcteur (TE) : correction 1 octet/bloc (toute position, tout
masque), altérations multiples, métadonnées et parités falsifiées."""
import numpy as np

from tests.commun import sauver
from sillage import Brume512, Brume512TagError, Brume512TamperError


def _essai(br, n, ct, pars, tag, meta):
    try:
        pt, corr = br.decrypt_te(n, ct, pars, tag, meta)
        return "OK", pt, corr
    except Brume512TagError:
        return "TAG", None, None
    except Brume512TamperError:
        return "TAMPER", None, None


def run():
    c, m = {}, {}
    br = Brume512("BRUME-512", key=bytes(range(64)))
    n = bytes(range(24))
    rng = np.random.default_rng(3)
    for L in (1, 63, 64, 65, 200):
        msg = bytes(rng.integers(0, 256, L, dtype=np.uint8))
        ct, pars, tag, meta = br.encrypt_te(n, msg)
        ok = True
        for pos in range(L):                       # chaque position, masque aléatoire
            bad = bytearray(ct); bad[pos] ^= int(rng.integers(1, 256))
            r, pt, corr = _essai(br, n, bytes(bad), pars, tag, meta)
            ok &= r == "OK" and pt == msg and corr == [pos]
        c[f"correction_toute_position_L{L}"] = ok
    msg = bytes(rng.integers(0, 256, 200, dtype=np.uint8))
    ct, pars, tag, meta = br.encrypt_te(n, msg)
    stats = {"OK_message_correct": 0, "OK_message_faux": 0, "TAG": 0, "TAMPER": 0}
    for _ in range(400):                           # 2 erreurs dans le MÊME bloc
        blk = int(rng.integers(0, 3)) * 64
        p1, p2 = rng.choice(min(64, len(ct) - blk), 2, replace=False) + blk
        bad = bytearray(ct)
        bad[p1] ^= int(rng.integers(1, 256)); bad[p2] ^= int(rng.integers(1, 256))
        r, pt, _ = _essai(br, n, bytes(bad), pars, tag, meta)
        stats["OK_message_correct" if r == "OK" and pt == msg else
              "OK_message_faux" if r == "OK" else r] += 1
    m["deux_erreurs_meme_bloc"] = stats
    c["jamais_de_message_faux_accepte"] = stats["OK_message_faux"] == 0
    c["deux_erreurs_meme_bloc_jamais_acceptees"] = stats["OK_message_correct"] == 0
    # erreurs dans deux blocs distincts : corrigées
    bad = bytearray(ct); bad[5] ^= 0x33; bad[100] ^= 0x44
    r, pt, corr = _essai(br, n, bytes(bad), pars, tag, meta)
    c["une_erreur_par_bloc_deux_blocs"] = r == "OK" and pt == msg and corr == [5, 100]
    # métadonnées / parités
    c["meta_falsifiee_rejetee"] = _essai(br, n, ct, pars, tag, (len(ct) + 1).to_bytes(8, "big"))[0] != "OK" \
        and _essai(br, n, ct, pars, tag, (len(ct) - 1).to_bytes(8, "big"))[0] != "OK"
    c["parites_tronquees_rejetees"] = _essai(br, n, ct, pars[:7], tag, meta)[0] == "TAMPER"
    c["parites_etendues_rejetees"] = _essai(br, n, ct, pars + bytes(7), tag, meta)[0] == "TAMPER"
    # limite assumée : un adversaire qui recalcule les parités n'est arrêté que par le tag
    from sillage.brume512 import _te_parity, BLOCK
    bad = bytearray(ct); bad[0] ^= 1
    padded = bytes(bad) + bytes((-len(bad)) % BLOCK)
    pars2 = b"".join(_te_parity(padded[i:i + BLOCK]) for i in range(0, len(padded), BLOCK))
    c["parites_recalculees_arretees_par_le_tag"] = _essai(br, n, bytes(bad), pars2, tag, meta)[0] == "TAG"
    out = {"controles": c, "mesures": m}
    sauver("te", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
