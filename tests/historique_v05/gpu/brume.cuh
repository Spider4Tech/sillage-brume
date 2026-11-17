/* BRUME-512 sur GPU (CUDA), tours réduits, dans les deux sens.
 *
 * Un fil = un état, empaqueté comme en C : uint32_t w[16], le nibble i occupe les bits 4(i mod 8) du mot
 * i / 8 (même mémoire que les 64 octets de sl_brume_permute). Les tables sont celles de
 * sillage/c/brume512_tables.h, relues ici en constexpr : déroulées, elles se replient à la compilation et
 * la couche linéaire directe devient du code sans accès mémoire. Rien n'est recopié à la main.
 *   - S-box : forme algébrique normale (ANF), 8 nibbles par mot à la fois ;
 *   - M : pour chaque arête (j → v, c), c·y_j = XOR des y_j·x^i (i ∈ c), produits par x calculés une fois ;
 *   - M⁻¹ (dense) : matrice binaire 512 × 512 en mémoire partagée, lue à la même adresse par tous les fils.
 * Conformité : tests/gpu/brume_gpu.cu (contre br_tours_avx2 et tests/c/brume_ref.h).
 * ponytail: un état par fil (≈ 2^27 permutations complètes/s visé) ; passer au découpage en tranches de
 * bits sur 32 états par chaîne (warp) si une campagne en est limitée. */
#ifndef BRUME_CUH
#define BRUME_CUH
#include <stdint.h>

#undef BRUME512_TABLES_H
namespace bdev {
#define static static constexpr __device__
#include "brume512_tables.h"
#undef static

struct Anf { uint16_t b[4]; };                 /* b[k] : monômes (bit S) de la sortie k */

constexpr Anf anf_de(const uint8_t s[16])
{
    Anf a{};
    for (int k = 0; k < 4; k++) {
        uint16_t t = 0;
        for (int x = 0; x < 16; x++)
            t |= (uint16_t)(((s[x] >> k) & 1) << x);
        for (int i = 1; i < 16; i <<= 1)        /* transformée de Möbius */
            for (int x = 0; x < 16; x++)
                if (x & i)
                    t ^= (uint16_t)(((t >> (x ^ i)) & 1) << x);
        a.b[k] = t;
    }
    return a;
}

struct Inv { uint8_t s[16]; };
constexpr Inv inverse_de(const uint8_t s[16])
{
    Inv r{};
    for (int x = 0; x < 16; x++)
        r.s[s[x]] = (uint8_t)x;
    return r;
}

constexpr __device__ Anf ANF_S = anf_de(BR_SBOX);
constexpr __device__ Inv SINV = inverse_de(BR_SBOX);
constexpr __device__ Anf ANF_SI = anf_de(SINV.s);
}

__constant__ uint32_t c_RCW[BR_TOURS][16];      /* constantes de tour empaquetées (br_gpu_init) */

__device__ __forceinline__ uint32_t sbox8(uint32_t x, const bdev::Anf &A)
{
    uint32_t m[16];
    m[0] = 0x11111111u;
#pragma unroll
    for (int s = 1; s < 16; s++)
        m[s] = m[s & (s - 1)] & ((x >> ((s & 1) ? 0 : (s & 2) ? 1 : (s & 4) ? 2 : 3)) & 0x11111111u);
    uint32_t y = 0;
#pragma unroll
    for (int k = 0; k < 4; k++) {
        uint32_t o = 0;
#pragma unroll
        for (int s = 0; s < 16; s++)
            if ((A.b[k] >> s) & 1)
                o ^= m[s];
        y |= o << k;
    }
    return y;
}

__device__ __forceinline__ uint32_t mulx8(uint32_t a)    /* ×x dans GF(16) = F2[x]/(x⁴ + x + 1), 8 nibbles */
{
    uint32_t h = (a >> 3) & 0x11111111u;
    return ((a << 1) & 0xEEEEEEEEu) ^ h ^ (h << 1);
}

/* tours r0 … r0 + R − 1 */
__device__ __forceinline__ void brume_avant(uint32_t w[16], int r0, int R)
{
#pragma unroll 1
    for (int r = r0; r < r0 + R; r++) {
        uint32_t y[4][16];
#pragma unroll
        for (int k = 0; k < 16; k++) {
            y[0][k] = sbox8(w[k] ^ c_RCW[r][k], bdev::ANF_S);
            y[1][k] = mulx8(y[0][k]);
            y[2][k] = mulx8(y[1][k]);
            y[3][k] = mulx8(y[2][k]);
            w[k] = 0;
        }
#pragma unroll
        for (int e = 0; e < BR_ARETES; e++) {
            const int v = e / BR_DEG, j = bdev::BR_EI[e], c = bdev::BR_EC[e];
            const int sj = 4 * (j & 7), sv = 4 * (v & 7);
            uint32_t z = 0;
#pragma unroll
            for (int i = 0; i < 4; i++)
                if ((c >> i) & 1)
                    z ^= y[i][j >> 3];
            z = sj >= sv ? z >> (sj - sv) : z << (sv - sj);
            w[v >> 3] ^= z & (0xFu << sv);
        }
    }
}

/* inverse des tours r0, r0 − 1, …, r0 − R + 1 ; MI : M⁻¹ binaire, ligne o (bit 4v + a) = 16 mots, en partagée */
__device__ __forceinline__ void brume_arriere(uint32_t w[16], int r0, int R, const uint32_t *MI)
{
#pragma unroll 1
    for (int r = r0; r > r0 - R; r--) {
        uint32_t x[16] = {0};
#pragma unroll 4
        for (int o = 0; o < 512; o++) {
            uint32_t a = 0;
#pragma unroll
            for (int k = 0; k < 16; k++)
                a ^= MI[16 * o + k] & w[k];
            x[o >> 5] |= (uint32_t)(__popc(a) & 1) << (o & 31);
        }
#pragma unroll
        for (int k = 0; k < 16; k++)
            w[k] = sbox8(x[k], bdev::ANF_SI) ^ c_RCW[r][k];
    }
}

/* Côté hôte : constantes de tour, et M⁻¹ binaire (à partir de BMI de tests/c/brume_ref.h, déjà initialisé). */
static void br_gpu_init(const uint8_t rc[BR_TOURS][BR_N])
{
    uint32_t h[BR_TOURS][16] = {{0}};
    for (int r = 0; r < BR_TOURS; r++)
        for (int j = 0; j < BR_N; j++)
            h[r][j >> 3] |= (uint32_t)rc[r][j] << (4 * (j & 7));
    cudaMemcpyToSymbol(c_RCW, h, sizeof h);
}

static void br_gpu_mi(const uint8_t Mi[BR_N][BR_N], uint32_t mi[512 * 16],
                      uint8_t (*mul)(uint8_t, uint8_t))
{
    for (int i = 0; i < 512 * 16; i++)
        mi[i] = 0;
    for (int v = 0; v < BR_N; v++)
        for (int j = 0; j < BR_N; j++)
            for (int b = 0; b < 4; b++) {              /* bit b du nibble j → bits de c·x^b */
                uint8_t t = mul(Mi[v][j], (uint8_t)(1 << b));
                for (int a = 0; a < 4; a++)
                    if ((t >> a) & 1)
                        mi[16 * (4 * v + a) + ((4 * j + b) >> 5)] |= 1u << ((4 * j + b) & 31);
            }
}
#endif
