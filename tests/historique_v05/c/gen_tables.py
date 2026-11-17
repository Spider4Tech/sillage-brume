# -*- coding: utf-8 -*-
"""Génère sillage/c/brume512_tables.h et brume512_simd.h depuis
sillage/brume512.py (source unique des tables). À relancer si select_params modifie les tables :
    python3 -m sillage.c.gen_tables
"""
import os

import numpy as np

from sillage import brume512 as B

ICI = os.path.dirname(os.path.abspath(__file__))


def _tab(nom, typ, vals, par_ligne=16):
    a = np.asarray(vals)
    if a.ndim == 2:                       # une ligne C par ligne du tableau
        lignes = ["{" + ", ".join(str(int(v)) for v in ligne) + "}" for ligne in a]
    else:
        v = [int(x) for x in a]
        lignes = [", ".join(str(x) for x in v[i:i + par_ligne]) for i in range(0, len(v), par_ligne)]
    return f"static const {typ} {nom} = {{\n    " + ",\n    ".join(lignes) + "\n};\n"


def main():
    assert list(B.E_SEG) == [7 * v for v in range(B.N + 1)], "graphe non 7-régulier"
    assert B.POLY == 0x13
    h = ["/* Généré par sillage/c/gen_tables.py depuis sillage/brume512.py — ne pas éditer. */",
         "#ifndef BRUME512_TABLES_H", "#define BRUME512_TABLES_H", "#include <stdint.h>",
         f"#define BR_N {B.N}", f"#define BR_TOURS {B.N_ROUNDS}", f"#define BR_ARETES {len(B.E_I)}",
         "#define BR_DEG 7", "#define BR_POLY 0x13", ""]
    h.append(_tab("BR_SBOX[16]", "uint8_t", B.SBOX))
    h.append(_tab(f"BR_RC[{B.N_ROUNDS}][{B.N}]", "uint8_t", np.stack(B.RC), 32))
    h.append("/* arête e : de E_I[e] vers le sommet e / 7, coefficient E_C[e] dans GF(16) */")
    h.append(_tab(f"BR_EI[{len(B.E_I)}]", "uint8_t", B.E_I, 28))
    h.append(_tab(f"BR_EC[{len(B.E_C)}]", "uint8_t", B.E_C, 28))
    h.append("#endif")
    with open(os.path.join(ICI, "brume512_tables.h"), "w") as f:
        f.write("\n".join(h) + "\n")


def _gf_log_exp():
    exp, x = [], 1
    for _ in range(15):
        exp.append(x)
        x = int(B.GMUL[x, 2])
    assert len(set(exp)) == 15, "2 non primitif"
    log = [0xC0] + [exp.index(v) for v in range(1, 16)]   # log 0 : bit 7 → vpshufb rend 0
    return log, exp + [0]


def simd():
    """brume512_simd.h : données et code générés pour les noyaux AVX2.

    Structure exploitée (Cayley de D128, générateurs = réflexions (k, s)) :
    l'arête d'entrée du sommet v par le générateur k vient de
      v = (a, 0) → x = 64 + (a + k) mod 64,   v = (b, 1) → x = (b − k) mod 64,
    soit, par moitié de 64 nibbles, un échange de moitiés et une rotation.
    """
    ks = [int(g) & 63 for g in B.GENS]
    assert all(int(g) >> 6 == 1 for g in B.GENS), "générateurs non réflexions"
    coef = {(int(B.E_I[e]), e // 7): int(B.E_C[e]) for e in range(len(B.E_I))}
    log, exp = _gf_log_exp()
    lc_self = [log[coef[(v, v)]] for v in range(B.N)]
    lc_slot = []
    for k in ks:
        ligne = []
        for v in range(B.N):
            x = B.group_op(v, 64 + k)
            assert x == (64 + (v + k) % 64 if v < 64 else (v - 64 - k) % 64)
            ligne.append(log[coef[(x, v)]])
        lc_slot.append(ligne)
    assert all(sum(1 for (x, w) in coef if w == v) == 7 for v in range(B.N))
    h = ["/* Généré par sillage/c/gen_tables.py depuis sillage/brume512.py — ne pas éditer. */",
         "#ifndef BRUME512_SIMD_H", "#define BRUME512_SIMD_H", "#include <stdint.h>",
         f"#define BR_NB_GEN {len(ks)}", ""]
    h.append(_tab(f"BR_GEN_K[{len(ks)}]", "uint8_t", ks))
    h.append(_tab("BR_LOG[16]", "uint8_t", log))
    h.append(_tab("BR_EXP[16]", "uint8_t", exp))
    h.append("/* log du coefficient de la boucle (v → v) et de l'arête par générateur, indexés par destination */")
    h.append(_tab("BR_LC_SELF[128]", "uint8_t", lc_self, 32))
    h.append(_tab(f"BR_LC_GEN[{len(ks)}][128]", "uint8_t", np.array(lc_slot)))
    h.append("/* diffusion « verticale » déroulée (32 états, un octet par état) : s = M·y */")
    h.append("#define BR_DIFFUSION_LOT(y, s, TG) do { \\")
    for v in range(B.N):
        e = 7 * v
        t = [f"_mm256_shuffle_epi8(TG[{int(B.E_C[e + k])}], y[{int(B.E_I[e + k])}])" for k in range(7)]
        expr = t[0]
        for x in t[1:]:
            expr = f"_mm256_xor_si256({expr}, {x})"
        h.append(f"    (s)[{v}] = {expr}; \\")
    h.append("} while (0)")
    h.append("/* diffusion « horizontale » d'UN état (4 registres : moitié 0 = L0,L1 ; moitié 1 = L2,L3) :")
    h.append(" * acc ^= c ⊙ rot(L) pour chaque générateur ; ROT(A, B, K) = (A‖B)[i + K], K littéral < 32. */")
    h.append("#define BR_DIFFUSION_H(L, acc, MUL, ROT) do { \\")
    for g, k in enumerate(ks):
        for dst, (src, K) in enumerate(((1, k), (0, (64 - k) % 64))):
            a_, b_ = 2 * src, 2 * src + 1
            if K >= 32:
                a_, b_, K = b_, a_, K - 32
            for c, (x, y) in enumerate(((a_, b_), (b_, a_))):
                h.append(f"    (acc)[{2 * dst + c}] = _mm256_xor_si256((acc)[{2 * dst + c}], "
                         f"MUL(ROT((L)[{x}], (L)[{y}], {K}), {g}, {2 * dst + c})); \\")
    h.append("} while (0)")
    h.append("/* NEON : mêmes diffusions. Vertical : 16 états ; horizontal : 8 registres (moitié 0 = L0..L3, moitié 1 = L4..L7),")
    h.append(" * EXT(A, B, K) = (A‖B)[i + K], K littéral < 16 (vextq_u8). */")
    h.append("#define BR_DIFFUSION_LOT_N(y, s, TG) do { \\")
    for v in range(B.N):
        e = 7 * v
        t = [f"vqtbl1q_u8(TG[{int(B.E_C[e + k])}], y[{int(B.E_I[e + k])}])" for k in range(7)]
        expr = t[0]
        for x in t[1:]:
            expr = f"veorq_u8({expr}, {x})"
        h.append(f"    (s)[{v}] = {expr}; \\")
    h.append("} while (0)")
    h.append("#define BR_DIFFUSION_N(L, acc, MUL, EXT) do { \\")
    for g, k in enumerate(ks):
        for dst, (src, K) in enumerate(((1, k), (0, (64 - k) % 64))):
            for c in range(4):
                a_ = (c + K // 16) % 4
                h.append(f"    (acc)[{4 * dst + c}] = veorq_u8((acc)[{4 * dst + c}], "
                         f"MUL(EXT((L)[{4 * src + a_}], (L)[{4 * src + (a_ + 1) % 4}], {K % 16}), {g}, {4 * dst + c})); \\")
    h.append("} while (0)")
    h.append("#endif")
    with open(os.path.join(ICI, "brume512_simd.h"), "w") as f:
        f.write("\n".join(h) + "\n")


if __name__ == "__main__":
    main()
    simd()
