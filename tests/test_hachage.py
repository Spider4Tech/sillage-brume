# -*- coding: utf-8 -*-
"""Hachage BRUME-512 : padding injectif, extensions, unicité, XOF, collisions
et quasi-collisions sur sorties tronquées (comportement aléatoire attendu)."""
import itertools
import math

import numpy as np

from tests.commun import sauver
from sillage.brume512 import brume512_hash, RATE_BYTES


def run():
    c, m = {}, {}
    # 1. padding : injectivité exhaustive sur {00,01,80,FF}^<=6
    vus, coll = {}, 0
    for L in range(7):
        for tup in itertools.product((0, 1, 0x80, 0xFF), repeat=L):
            msg = bytes(tup)
            d = msg + b"\x01"
            d += b"\x00" * ((-len(d)) % RATE_BYTES)
            coll += d in vus
            vus[d] = msg
    c["padding_injectif"] = coll == 0
    # 2. extensions par zéros / 0x01 aux frontières
    ok = True
    for L in (0, 1, 30, 31, 32, 33, 63, 64, 65):
        mm = bytes(range(L))
        h = brume512_hash(mm)
        for suf in (b"\x00", b"\x01", b"\x00" * 32, b"\x01" + b"\x00" * 31):
            ok &= brume512_hash(mm + suf) != h
    c["extensions_distinctes"] = ok
    # 3. unicité : tous les messages de 1 et 2 octets (65 792 empreintes 8 o)
    hs = {brume512_hash(bytes([a]), 8) for a in range(256)}
    c["messages_1_octet_distincts"] = len(hs) == 256
    hs2 = {brume512_hash(bytes([a, b]), 8) for a in range(256) for b in range(0, 256, 4)}
    c["messages_2_octets_distincts_echantillon"] = len(hs2) == 256 * 64
    # 4. XOF : préfixe commun attendu
    c["xof_prefixe"] = brume512_hash(b"abc", 64).startswith(brume512_hash(b"abc", 16))
    # 5. paradoxe des anniversaires sur 20 bits : ~ C(4096,2)/2^20 ≈ 8 collisions
    vals = [int.from_bytes(brume512_hash(i.to_bytes(4, "big"), 3), "big") >> 4
            for i in range(4096)]
    _, cnt = np.unique(vals, return_counts=True)
    ncoll = int((cnt * (cnt - 1) // 2).sum())
    attendu = 4096 * 4095 / 2 / 2 ** 20
    m["collisions_20_bits"] = {"observees": ncoll, "attendues": round(attendu, 2)}
    c["collisions_20_bits_poisson"] = abs(ncoll - attendu) <= 4 * math.sqrt(attendu) + 1
    # 6. quasi-collisions : distance de Hamming h(m) / h(m ⊕ 1 bit) ~ B(256, 1/2)
    rng = np.random.default_rng(5)
    dist = []
    for _ in range(300):
        mm = bytearray(rng.integers(0, 256, 40, dtype=np.uint8).tobytes())
        h1 = int.from_bytes(brume512_hash(bytes(mm)), "big")
        mm[int(rng.integers(0, 40))] ^= 1 << int(rng.integers(0, 8))
        dist.append(bin(h1 ^ int.from_bytes(brume512_hash(bytes(mm)), "big")).count("1"))
    m["distance_hamming"] = {"moyenne": round(float(np.mean(dist)), 2),
                             "ecart_type": round(float(np.std(dist)), 2),
                             "min": int(min(dist)), "max": int(max(dist))}
    c["avalanche_hachage"] = abs(np.mean(dist) - 128) < 2 and min(dist) > 80
    out = {"controles": c, "mesures": m}
    sauver("hachage", out)
    return out


if __name__ == "__main__":
    print(run()["controles"])
