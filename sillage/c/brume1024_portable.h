/* Noyau PORTABLE et à temps constant de BRUME-1024q (MIGRATION_V06.md, décision D6 du 14 novembre 2026) : C99, entiers de
 * 64 bits seulement, sans intrinsèques. Il remplacera, dans la suite, tout repli à tables (refusé par la règle de la suite).
 *
 * Représentation : l'état (256 nibbles) est rangé en 4 PLANS de bits de 256 bits, 16 mots x[4·b + 2·h + m] : bit
 * (i mod 64) du mot m du plan b, moitié h, contient le bit b du nibble v = 128·h + i (i = 64·m + bit). Les positions 0…127 sont les rotations de
 * D₂₅₆, 128…255 les réflexions (SPEC § 2.2).
 *
 * Tour : x ← M·S(x ⊕ RC_r).
 *  - S-box : le circuit de 17 portes (gen_bitslice.c) calcule C(z) = S(z ⊕ 3) ⊕ 1. On lui donne z = x ⊕ RC_r ⊕ 3 (le 3 est
 *    rangé dans les plans de constantes), puis on complémente le plan 0 (le ⊕ 1) : S(x ⊕ RC_r) exactement.
 *  - Couche linéaire : (Mx)_v = CS[v]·x_v ⊕ Σ_g CG[g][v]·x_{v·s_K[g]}. Le voisin d'une rotation i par la réflexion s_k est
 *    la réflexion (i + k) mod 128, celui d'une réflexion i est la rotation (i − k) mod 128 : le terme g est donc l'AUTRE
 *    moitié, tournée de k positions (rotation de 128 bits, décalages fixes). Le produit par la constante propre à chaque
 *    position est une matrice 4×4 sur GF(2) par position : y_j ⊕= T_i ∧ masque[g][i][j], où le bit v du masque est le
 *    bit j de c_v·t^i. 7 termes × 16 ET et 16 OUX par mot.
 * Toutes les opérations portent sur les mots entiers ; les indices, décalages et masques ne dépendent que des tables
 * publiques. Aucun accès mémoire ni branchement ne dépend de l'état (à vérifier par ctgrind et dudect, ct_portable.c). */
#ifndef BRUME1024_PORTABLE_H
#define BRUME1024_PORTABLE_H
#include <stdint.h>
#include <string.h>

#include "brume1024_tables.h"

typedef uint64_t pp_plans[16];   /* mot 4·b + 2·h + m : plan b, moitié h, mot m */
#define PP_I(b, h, m) (4 * (b) + 2 * (h) + (m))

static const uint8_t PP_SBOX[16] = {10, 13, 4, 1, 2, 6, 5, 0, 11, 15, 14, 12, 7, 8, 9, 3};   /* SPEC § 2.1 */
#define PP_TA 3   /* le circuit calcule S(z ⊕ PP_TA) ⊕ PP_KS */
static uint64_t PP_MASQ[7][4][4][4];   /* [terme][bit d'entrée i][bit de sortie j][2·h + m] */
static uint64_t PP_RC[B1_RT][16];      /* plans de RC_r ⊕ PP_TA */
static uint64_t PP_KSM[4];             /* plans de S(PP_TA) : 0 ou tous les bits */
static int PP_PRET;

static uint8_t pp_gmul(uint8_t a, uint8_t b)   /* GF(2⁴) modulo t⁴ + t + 1, sur des données publiques seulement */
{
    uint8_t r = 0;
    for (int k = 0; k < 4; k++) {
        if (b >> k & 1)
            r ^= a;
        a = (uint8_t)(((a << 1) ^ ((a & 8) ? 0x13 : 0)) & 15);
    }
    return r;
}

/* le circuit de 17 portes, sur 64 bits à la fois */
static inline void pp_sbox(uint64_t w0, uint64_t w1, uint64_t w2, uint64_t w3, uint64_t o[4])
{
    uint64_t w4 = w1 | w3, w5 = w0 ^ w1, w6 = w3 & w5, w7 = ~w6 & w2, w8 = ~w7 & w4, w9 = w2 ^ w3, w10 = w0 | w6;
    uint64_t w11 = w1 ^ w8, w12 = ~w11 & w10, w13 = w9 ^ w12, w14 = w2 ^ w6, w15 = w9 ^ w10, w16 = w4 & w14;
    uint64_t w17 = w3 & w15, w18 = ~w5 & w1, w19 = w5 ^ w17, w20 = w16 | w18;
    o[0] = w13; o[1] = w20; o[2] = w19; o[3] = w8;
}

/* rotation de 128 bits (lo, hi) : bit i du résultat = bit (i + k) mod 128 de l'entrée ; k est public */
static inline void pp_rotr(uint64_t lo, uint64_t hi, int k, uint64_t *rl, uint64_t *rh)
{
    k &= 127;
    if (k >= 64) { uint64_t t = lo; lo = hi; hi = t; k -= 64; }
    if (k == 0) { *rl = lo; *rh = hi; return; }
    *rl = (lo >> k) | (hi << (64 - k));
    *rh = (hi >> k) | (lo << (64 - k));
}

/* Prépare PP_MASQ, PP_RC, PP_KSM et pose PP_PRET. NON réentrant : à appeler une fois, avant tout usage et hors de toute
 * région parallèle (c'est le cas dans brume1024.c et spec_ref.c : au démarrage de main). Pour le portage dans sillage/
 * (v0.6), ces tables ne dépendent que des données publiques : les générer comme constantes (static const) supprime
 * l'initialisation à l'exécution et toute question de concurrence (revue externe du 15 novembre). */
static int pp_init(void)
{
    /* le circuit doit être conforme sur les 16 entrées (bit x des mots = entrée x) */
    uint64_t e[4] = {0}, o[4];
    for (int x = 0; x < 16; x++)
        for (int b = 0; b < 4; b++)
            e[b] |= (uint64_t)(x >> b & 1) << x;
    pp_sbox(e[0], e[1], e[2], e[3], o);
    int ks = PP_SBOX[PP_TA];
    for (int x = 0; x < 16; x++) {
        int s = 0;
        for (int b = 0; b < 4; b++)
            s |= (int)(o[b] >> x & 1) << b;
        if (s != (PP_SBOX[x ^ PP_TA] ^ ks))
            return 0;
    }
    memset(PP_MASQ, 0, sizeof PP_MASQ);
    memset(PP_RC, 0, sizeof PP_RC);
    for (int v = 0; v < B1_N; v++) {
        int hm = v >> 6, bit = v & 63;
        for (int t = 0; t < 7; t++) {
            uint8_t c = t == 0 ? B1_CS[v] : B1_CG[t - 1][v];
            for (int i = 0; i < 4; i++) {
                uint8_t p = pp_gmul(c, (uint8_t)(1 << i));
                for (int j = 0; j < 4; j++)
                    PP_MASQ[t][i][j][hm] |= (uint64_t)(p >> j & 1) << bit;
            }
        }
        for (int r = 0; r < B1_RT; r++)
            for (int b = 0; b < 4; b++)
                PP_RC[r][4 * b + hm] |= (uint64_t)((B1_RC[r][v] ^ PP_TA) >> b & 1) << bit;
    }
    for (int b = 0; b < 4; b++)
        PP_KSM[b] = (uint64_t)0 - (uint64_t)(ks >> b & 1);
    PP_PRET = 1;
    return 1;
}

static inline void pp_tour(pp_plans x, int r)
{
    uint64_t s[16], y[16] = {0};
    for (int q = 0; q < 4; q++) {   /* q = 2·h + m */
        uint64_t o[4];
        pp_sbox(x[q] ^ PP_RC[r][q], x[4 + q] ^ PP_RC[r][4 + q], x[8 + q] ^ PP_RC[r][8 + q], x[12 + q] ^ PP_RC[r][12 + q], o);
        for (int b = 0; b < 4; b++)
            s[4 * b + q] = o[b] ^ PP_KSM[b];   /* ⊕ S(TA), constante publique */
    }
    for (int t = 0; t < 7; t++) {
        uint64_t T[16];
        if (t == 0)
            memcpy(T, s, sizeof T);
        else {
            int k = B1_K[t - 1];
            for (int i = 0; i < 4; i++) {
                pp_rotr(s[4 * i + 2], s[4 * i + 3], k, &T[4 * i], &T[4 * i + 1]);         /* rotations ← réflexions (i + k) */
                pp_rotr(s[4 * i], s[4 * i + 1], 128 - k, &T[4 * i + 2], &T[4 * i + 3]);   /* réflexions ← rotations (i − k) */
            }
        }
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                for (int q = 0; q < 4; q++)
                    y[4 * j + q] ^= T[4 * i + q] & PP_MASQ[t][i][j][q];
    }
    memcpy(x, y, sizeof y);
}

/* 16 nibbles (un mot de 64 bits, nibble k aux bits 4k…4k+3) → bit b de chacun, sur 16 bits */
static inline uint64_t pp_comprimer(uint64_t u, int b)
{
    uint64_t q = (u >> b) & 0x1111111111111111ull;
    q = (q | (q >> 3)) & 0x0303030303030303ull;
    q = (q | (q >> 6)) & 0x000F000F000F000Full;
    q = (q | (q >> 12)) & 0x000000FF000000FFull;
    return (q | (q >> 24)) & 0xFFFFull;
}

static inline uint64_t pp_etaler(uint64_t q)   /* inverse : 16 bits → bits 0, 4, …, 60 */
{
    q &= 0xFFFFull;
    q = (q | (q << 24)) & 0x000000FF000000FFull;
    q = (q | (q << 12)) & 0x000F000F000F000Full;
    q = (q | (q << 6)) & 0x0303030303030303ull;
    return (q | (q << 3)) & 0x1111111111111111ull;
}

/* état emballé (octet i : nibble 2i en bas, 2i + 1 en haut) ↔ plans ; lecture octet par octet, sans dépendre de
 * l'ordre des octets de la machine */
static void pp_deballer(const uint8_t w[128], pp_plans x)
{
    memset(x, 0, sizeof(pp_plans));
    for (int c = 0; c < 16; c++) {   /* positions 16c … 16c + 15 */
        uint64_t u = 0;
        for (int k = 0; k < 8; k++)
            u |= (uint64_t)w[8 * c + k] << (8 * k);
        for (int b = 0; b < 4; b++)
            x[4 * b + (c >> 2)] |= pp_comprimer(u, b) << (16 * (c & 3));
    }
}

static void pp_emballer(const pp_plans x, uint8_t w[128])
{
    for (int c = 0; c < 16; c++) {
        uint64_t u = 0;
        for (int b = 0; b < 4; b++)
            u |= pp_etaler(x[4 * b + (c >> 2)] >> (16 * (c & 3))) << b;
        for (int k = 0; k < 8; k++)
            w[8 * c + k] = (uint8_t)(u >> (8 * k));
    }
}

/* la permutation à R tours (R ≤ B1_RT) sur l'état emballé (deux nibbles par octet, position paire en bas) ; pp_init()
 * doit avoir réussi */
static __attribute__((unused)) void pp_perm(uint8_t w[128], int R)
{
    pp_plans x;
    pp_deballer(w, x);
    for (int r = 0; r < R; r++)
        pp_tour(x, r);
    pp_emballer(x, w);
}
#endif
