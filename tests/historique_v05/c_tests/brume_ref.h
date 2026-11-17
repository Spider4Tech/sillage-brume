/* BRUME-512 au niveau des nibbles, tours réduits, dans les deux sens, à
 * partir des seules tables générées (sillage/c/brume512_tables.h) : sert aux
 * analyses structurelles et aux mesures des tests C. bref_init() calcule M
 * (dense) et M⁻¹ sur GF(16) ; bref_conforme() recoupe 32 tours avec
 * sl_brume_permute (état empaqueté) et vérifie l'inverse. */
#ifndef BRUME_REF_H
#define BRUME_REF_H
#include <stdint.h>
#include <string.h>

#include "brume512_tables.h"
#include "sillage.h"

static uint8_t BM[BR_N][BR_N], BMI[BR_N][BR_N], BSI[16];

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 4; i++) {
        if (b & 1)
            r ^= a;
        b >>= 1;
        a <<= 1;
        if (a & 0x10)
            a ^= BR_POLY;
    }
    return r & 15;
}

static uint8_t gf_inv(uint8_t a)
{
    for (uint8_t b = 1; b < 16; b++)
        if (gf_mul(a, b) == 1)
            return b;
    return 0;
}

static int bref_init(void)
{
    sl_init();
    for (int x = 0; x < 16; x++)
        BSI[BR_SBOX[x]] = (uint8_t)x;
    memset(BM, 0, sizeof BM);
    for (int e = 0; e < BR_ARETES; e++)
        BM[e / BR_DEG][BR_EI[e]] ^= BR_EC[e];
    uint8_t A[BR_N][2 * BR_N];                     /* Gauss–Jordan sur GF(16) */
    for (int i = 0; i < BR_N; i++)
        for (int j = 0; j < 2 * BR_N; j++)
            A[i][j] = j < BR_N ? BM[i][j] : (j - BR_N == i);
    for (int c = 0; c < BR_N; c++) {
        int p = c;
        while (p < BR_N && !A[p][c])
            p++;
        if (p == BR_N)
            return 0;
        if (p != c)
            for (int j = 0; j < 2 * BR_N; j++) { uint8_t t = A[p][j]; A[p][j] = A[c][j]; A[c][j] = t; }
        uint8_t iv = gf_inv(A[c][c]);
        for (int j = 0; j < 2 * BR_N; j++)
            A[c][j] = gf_mul(A[c][j], iv);
        for (int i = 0; i < BR_N; i++)
            if (i != c && A[i][c]) {
                uint8_t f = A[i][c];
                for (int j = 0; j < 2 * BR_N; j++)
                    A[i][j] ^= gf_mul(f, A[c][j]);
            }
    }
    for (int i = 0; i < BR_N; i++)
        memcpy(BMI[i], A[i] + BR_N, BR_N);
    return 1;
}

static void bref_lin(const uint8_t Mx[BR_N][BR_N], uint8_t x[BR_N])
{
    uint8_t y[BR_N];
    for (int v = 0; v < BR_N; v++) {
        uint8_t a = 0;
        for (int i = 0; i < BR_N; i++)
            if (Mx[v][i])
                a ^= gf_mul(Mx[v][i], x[i]);
        y[v] = a;
    }
    memcpy(x, y, BR_N);
}

static void bref_tour(uint8_t x[BR_N], int r)
{
    for (int j = 0; j < BR_N; j++)
        x[j] = BR_SBOX[x[j] ^ BR_RC[r][j]];
    bref_lin(BM, x);
}

static void bref_tour_inv(uint8_t x[BR_N], int r)
{
    bref_lin(BMI, x);
    for (int j = 0; j < BR_N; j++)
        x[j] = BSI[x[j]] ^ BR_RC[r][j];
}

/* sens 0 : tours 0 … R−1 ; sens 1 : inverse des R derniers tours (31 … 32−R) */
static void bref_perm(uint8_t x[BR_N], int R, int sens)
{
    for (int k = 0; k < R; k++) {
        if (sens == 0)
            bref_tour(x, k);
        else
            bref_tour_inv(x, BR_TOURS - 1 - k);
    }
}

static void bref_empaqueter(const uint8_t x[BR_N], uint8_t e[64])
{
    for (int i = 0; i < 64; i++)
        e[i] = (uint8_t)(x[2 * i] | (x[2 * i + 1] << 4));
}

static int bref_conforme(int essais)
{
    uint8_t x[BR_N], y[BR_N], e[64], f[64];
    uint64_t g = 0x5eed;
    for (int k = 0; k < essais; k++) {
        for (int i = 0; i < BR_N; i++) {
            g = g * 6364136223846793005ULL + 1442695040888963407ULL;
            x[i] = (uint8_t)(g >> 60);
        }
        memcpy(y, x, BR_N);
        bref_empaqueter(x, e);
        sl_brume_permute(e);
        bref_perm(y, BR_TOURS, 0);
        bref_empaqueter(y, f);
        if (memcmp(e, f, 64))
            return 0;
        bref_perm(y, BR_TOURS, 1);                     /* inverse complet */
        if (memcmp(x, y, BR_N))
            return 0;
    }
    return 1;
}
#endif
