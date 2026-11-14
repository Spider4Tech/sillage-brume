/* BRUME-1024q sur GPU (CUDA), tours réduits, dans les deux sens. Portage de tests/gpu/brume.cuh (BRUME-512) à 256 nibbles.
 *
 * Un fil = un état, empaqueté comme en C : uint32_t w[32], le nibble j occupe les bits 4(j mod 8) du mot j / 8 (même
 * mémoire que les 128 octets de perm1). Les tables sont celles de b1024_tables.h et de sillage/c/brume512_tables.h
 * (S-box), relues en constexpr : déroulées, elles se replient à la compilation. Rien n'est recopié à la main.
 *   - S-box : forme algébrique normale, 8 nibbles par mot ;
 *   - M : 7 arêtes par sommet (diagonale B1_CS, six voisins de l'autre moitié, décalages B1_K, coefficients B1_CG) ;
 *   - M⁻¹ (dense) : matrice binaire 1 024 × 1 024 (128 Kio) en mémoire globale, lue à la même adresse par tous les fils
 *     d'une chaîne (diffusion), appliquée à deux états à la fois pour partager les lectures.
 * Conformité : boomerang1024.cu (vecteurs de brume1024.c, puis quartets recalculés sur CPU). */
#ifndef BRUME1024_CUH
#define BRUME1024_CUH
#include <stdint.h>

#undef BRUME512_TABLES_H
#undef B1024_TABLES_H
namespace b1dev {
#define static static constexpr __device__
#include "brume512_tables.h"
#include "b1024_tables.h"
#undef static

struct Anf { uint16_t b[4]; };
constexpr Anf anf_de(const uint8_t s[16])
{
    Anf a{};
    for (int k = 0; k < 4; k++) {
        uint16_t t = 0;
        for (int x = 0; x < 16; x++)
            t |= (uint16_t)(((s[x] >> k) & 1) << x);
        for (int i = 1; i < 16; i <<= 1)
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
/* arêtes de M : sommet v, entrée j, coefficient c (ligne v de M) ; 7 par sommet, même nbr() que brume1024.c */
constexpr int nbr(int v, int k)
{
    return v / B1_M == 0 ? (v % B1_M + k) % B1_M + B1_M : ((v % B1_M - k) % B1_M + B1_M) % B1_M;
}
struct Aretes { int16_t j[7 * B1_N]; uint8_t c[7 * B1_N]; };
constexpr Aretes aretes_de()
{
    Aretes a{};
    for (int v = 0; v < B1_N; v++) {
        a.j[7 * v] = (int16_t)v;
        a.c[7 * v] = B1_CS[v];
        for (int g = 0; g < 6; g++) {
            a.j[7 * v + 1 + g] = (int16_t)nbr(v, B1_K[g]);
            a.c[7 * v + 1 + g] = B1_CG[g][v];
        }
    }
    return a;
}
constexpr __device__ Anf ANF_S = anf_de(BR_SBOX);
constexpr __device__ Inv SINV = inverse_de(BR_SBOX);
constexpr __device__ Anf ANF_SI = anf_de(SINV.s);
constexpr __device__ Aretes AR = aretes_de();
}

__constant__ uint32_t c_RC1[B1_RT][32];          /* constantes de tour empaquetées (b1_gpu_init) */

__device__ __forceinline__ uint32_t b1_sbox8(uint32_t x, const b1dev::Anf &A)
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

__device__ __forceinline__ uint32_t b1_mulx8(uint32_t a)    /* ×x dans GF(16) = F2[x]/(x⁴ + x + 1), 8 nibbles */
{
    uint32_t h = (a >> 3) & 0x11111111u;
    return ((a << 1) & 0xEEEEEEEEu) ^ h ^ (h << 1);
}

/* tours r0 … r0 + R − 1 */
__device__ __forceinline__ void b1_avant(uint32_t w[32], int r0, int R)
{
#pragma unroll 1
    for (int r = r0; r < r0 + R; r++) {
        uint32_t y[4][32];
#pragma unroll
        for (int k = 0; k < 32; k++) {
            y[0][k] = b1_sbox8(w[k] ^ c_RC1[r][k], b1dev::ANF_S);
            y[1][k] = b1_mulx8(y[0][k]);
            y[2][k] = b1_mulx8(y[1][k]);
            y[3][k] = b1_mulx8(y[2][k]);
            w[k] = 0;
        }
#pragma unroll
        for (int e = 0; e < 7 * B1_N; e++) {
            const int v = e / 7, j = b1dev::AR.j[e], c = b1dev::AR.c[e];
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

/* inverse des tours r0, r0 − 1, …, r0 − R + 1, sur deux états ; MI : M⁻¹ binaire, ligne o (bit 4v + a) = 32 mots */
__device__ __forceinline__ void b1_arriere2(uint32_t a[32], uint32_t b[32], int r0, int R, const uint32_t *__restrict__ MI)
{
#pragma unroll 1
    for (int r = r0; r > r0 - R; r--) {
        uint32_t xa[32], xb[32];
#pragma unroll
        for (int k = 0; k < 32; k++)
            xa[k] = xb[k] = 0;
#pragma unroll 1
        for (int o5 = 0; o5 < 32; o5++) {
            uint32_t ma = 0, mb = 0;
#pragma unroll 4
            for (int o = 0; o < 32; o++) {
                const uint4 *L = (const uint4 *)(MI + 32 * (32 * o5 + o));
                uint32_t pa = 0, pb = 0;
#pragma unroll
                for (int q = 0; q < 8; q++) {
                    const uint4 m = __ldg(L + q);
                    pa ^= (m.x & a[4 * q]) ^ (m.y & a[4 * q + 1]) ^ (m.z & a[4 * q + 2]) ^ (m.w & a[4 * q + 3]);
                    pb ^= (m.x & b[4 * q]) ^ (m.y & b[4 * q + 1]) ^ (m.z & b[4 * q + 2]) ^ (m.w & b[4 * q + 3]);
                }
                ma |= (uint32_t)(__popc(pa) & 1) << o;
                mb |= (uint32_t)(__popc(pb) & 1) << o;
            }
            /* écriture du mot o5 sans indice dynamique dans un tableau de registres */
#pragma unroll
            for (int k = 0; k < 32; k++)
                if (k == o5) { xa[k] = ma; xb[k] = mb; }
        }
#pragma unroll
        for (int k = 0; k < 32; k++) {
            a[k] = b1_sbox8(xa[k], b1dev::ANF_SI) ^ c_RC1[r][k];
            b[k] = b1_sbox8(xb[k], b1dev::ANF_SI) ^ c_RC1[r][k];
        }
    }
}

/* Côté hôte : constantes de tour, et M⁻¹ binaire à partir d'une M⁻¹ sur GF(16) (ligne v, colonne j). */
static void b1_gpu_init(const uint8_t rc[B1_RT][B1_N])
{
    static uint32_t h[B1_RT][32];
    memset(h, 0, sizeof h);
    for (int r = 0; r < B1_RT; r++)
        for (int j = 0; j < B1_N; j++)
            h[r][j >> 3] |= (uint32_t)rc[r][j] << (4 * (j & 7));
    cudaMemcpyToSymbol(c_RC1, h, sizeof h);
}

static void b1_gpu_mi(const uint8_t (*Mi)[B1_N], uint32_t *mi, uint8_t (*mul)(uint8_t, uint8_t))
{
    memset(mi, 0, 1024 * 32 * 4);
    for (int v = 0; v < B1_N; v++)
        for (int j = 0; j < B1_N; j++)
            for (int b = 0; b < 4; b++) {
                uint8_t t = mul(Mi[v][j], (uint8_t)(1 << b));
                for (int a = 0; a < 4; a++)
                    if ((t >> a) & 1)
                        mi[32 * (4 * v + a) + ((4 * j + b) >> 5)] |= 1u << ((4 * j + b) & 31);
            }
}
#endif
