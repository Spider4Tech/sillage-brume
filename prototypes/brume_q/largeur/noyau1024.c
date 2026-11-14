/* Mesure (critère 2 de WIDTH_ANALYSIS.md § 6) : coût réel d'un tour BRUME à 1 024 bits (256 nibbles, graphe de Cayley de
 * D₂₅₆ à 6 réflexions K = {0, 83, 56, 51, 17, 42}) contre 512 bits (D₁₂₈, K = {21, 0, 7, 45, 8, 62}), dans le MÊME style de
 * noyau AVX2 à 1 état que la suite (un nibble par octet, multiplication GF(16) par logarithmes, rotations d'une moitié de
 * l'état par alignr), avec emballage et déballage à chaque permutation comme sl_brume_permute.
 * Ce n'est PAS une proposition de BRUME-1024 : les coefficients et les constantes sont tirés au hasard (non nuls), seule la
 * vitesse est mesurée, et la conformité du noyau est contrôlée contre une référence scalaire du même tour. Le noyau 512 est
 * contrôlé contre sl_brume_permute (32 tours) avec les vrais coefficients, pour que la comparaison porte sur le même code.
 *   cc -O3 -march=native -I sillage/c -I tests/c prototypes/brume_q/largeur/noyau1024.c sillage/c/commun.c \
 *      sillage/c/brume512.c sillage/c/brume512_avx2.c -lm -o tests/c/build/noyau1024
 */
#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "brume512_simd.h"
#include "brume_ref.h"

#define LD(p) _mm256_loadu_si256((const __m256i *)(p))
#define BC16(t) _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)(t)))
/* (A‖B)[i + K], K littéral dans [0, 32) */
#define ROT(A, B, K)                                                              \
    ((K) == 0 ? (A)                                                               \
     : (K) < 16 ? _mm256_alignr_epi8(_mm256_permute2x128_si256(A, B, 0x21), A, (K) & 15) \
                : _mm256_alignr_epi8(B, _mm256_permute2x128_si256(A, B, 0x21), (K) & 15))
#define MULLOG(Lv, LCv)                                                           \
    ({ __m256i s_ = _mm256_add_epi8(Lv, LCv);                                     \
       s_ = _mm256_min_epu8(s_, _mm256_sub_epi8(s_, _mm256_set1_epi8(15)));        \
       _mm256_shuffle_epi8(EXPv, s_); })

#define RT 40
#define RMX 48

/* ---------- état générique : H registres par moitié (2 : 512 bits, 4 : 1 024 bits) ---------- */
/* moitié « rotations » = registres 0..H−1 (sommets (i, 0)), moitié « réflexions » = H..2H−1 (sommets (i, 1)).
 * (i, 0)·s_k = (i + k, 1) ; (i, 1)·s_k = (i − k, 0). Rotation cyclique d'une moitié de 32H octets par Q octets :
 * registre c = (X[(c + Q/32) mod H] ‖ X[(c + Q/32 + 1) mod H])[Q mod 32]. */
#define ROTM(X, H, c, Q) ROT((X)[((c) + (Q) / 32) % (H)], (X)[((c) + (Q) / 32 + 1) % (H)], (Q) % 32)

/* un générateur, déroulé à la main pour que les décalages restent des constantes */
#define G2(g, k)                                                                                           \
    acc[0] = _mm256_xor_si256(acc[0], MULLOG(ROTM(L + 2, 2, 0, (k)), LCG[g][0]));                         \
    acc[1] = _mm256_xor_si256(acc[1], MULLOG(ROTM(L + 2, 2, 1, (k)), LCG[g][1]));                         \
    acc[2] = _mm256_xor_si256(acc[2], MULLOG(ROTM(L, 2, 0, (64 - (k)) % 64), LCG[g][2]));                 \
    acc[3] = _mm256_xor_si256(acc[3], MULLOG(ROTM(L, 2, 1, (64 - (k)) % 64), LCG[g][3]));
#define G4(g, k)                                                                                           \
    acc[0] = _mm256_xor_si256(acc[0], MULLOG(ROTM(L + 4, 4, 0, (k)), LCG[g][0]));                         \
    acc[1] = _mm256_xor_si256(acc[1], MULLOG(ROTM(L + 4, 4, 1, (k)), LCG[g][1]));                         \
    acc[2] = _mm256_xor_si256(acc[2], MULLOG(ROTM(L + 4, 4, 2, (k)), LCG[g][2]));                         \
    acc[3] = _mm256_xor_si256(acc[3], MULLOG(ROTM(L + 4, 4, 3, (k)), LCG[g][3]));                         \
    acc[4] = _mm256_xor_si256(acc[4], MULLOG(ROTM(L, 4, 0, (128 - (k)) % 128), LCG[g][4]));               \
    acc[5] = _mm256_xor_si256(acc[5], MULLOG(ROTM(L, 4, 1, (128 - (k)) % 128), LCG[g][5]));               \
    acc[6] = _mm256_xor_si256(acc[6], MULLOG(ROTM(L, 4, 2, (128 - (k)) % 128), LCG[g][6]));               \
    acc[7] = _mm256_xor_si256(acc[7], MULLOG(ROTM(L, 4, 3, (128 - (k)) % 128), LCG[g][7]));

/* coefficients (logarithmes) par sommet : self et 6 générateurs ; constantes de tour */
static uint8_t C2_SELF[128], C2_GEN[6][128], RC2[RMX][128];
static uint8_t C4_SELF[256], C4_GEN[6][256], RC4[RMX][256];
static uint8_t LOGS[16];

static inline void deballer(const uint8_t *p, __m256i *x, int H)
{
    const __m256i m = _mm256_set1_epi8(15);
    for (int h = 0; h < H; h++) {
        __m256i P = LD(p + 32 * h);
        __m256i lo = _mm256_and_si256(P, m), hi = _mm256_and_si256(_mm256_srli_epi16(P, 4), m);
        __m256i r0 = _mm256_unpacklo_epi8(lo, hi), r1 = _mm256_unpackhi_epi8(lo, hi);
        x[2 * h] = _mm256_permute2x128_si256(r0, r1, 0x20);
        x[2 * h + 1] = _mm256_permute2x128_si256(r0, r1, 0x31);
    }
}

static inline void emballer(const __m256i *x, uint8_t *p, int H)
{
    const __m256i f = _mm256_set1_epi16(0x1001);
    for (int h = 0; h < H; h++) {
        __m256i r0 = _mm256_permute2x128_si256(x[2 * h], x[2 * h + 1], 0x20);
        __m256i r1 = _mm256_permute2x128_si256(x[2 * h], x[2 * h + 1], 0x31);
        __m256i a = _mm256_maddubs_epi16(r0, f), b = _mm256_maddubs_epi16(r1, f);
        _mm256_storeu_si256((__m256i *)(p + 32 * h), _mm256_packus_epi16(a, b));
    }
}

__attribute__((noinline)) static void perm512(uint8_t w[64], int R)
{
    const __m256i LOGSv = BC16(LOGS), EXPv = BC16(BR_EXP);
    __m256i LCS[4], LCG[6][4], x[4], L[4], acc[4];
    for (int c = 0; c < 4; c++) {
        LCS[c] = LD(C2_SELF + 32 * c);
        for (int g = 0; g < 6; g++)
            LCG[g][c] = LD(C2_GEN[g] + 32 * c);
    }
    deballer(w, x, 2);
    for (int r = 0; r < R; r++) {
        for (int c = 0; c < 4; c++) {
            L[c] = _mm256_shuffle_epi8(LOGSv, _mm256_xor_si256(x[c], LD(RC2[r] + 32 * c)));
            acc[c] = MULLOG(L[c], LCS[c]);
        }
        G2(0, 21) G2(1, 0) G2(2, 7) G2(3, 45) G2(4, 8) G2(5, 62)
        memcpy(x, acc, sizeof x);
    }
    emballer(x, w, 2);
}

__attribute__((noinline)) static void perm1024(uint8_t w[128], int R)
{
    const __m256i LOGSv = BC16(LOGS), EXPv = BC16(BR_EXP);
    __m256i LCS[8], LCG[6][8], x[8], L[8], acc[8];
    for (int c = 0; c < 8; c++) {
        LCS[c] = LD(C4_SELF + 32 * c);
        for (int g = 0; g < 6; g++)
            LCG[g][c] = LD(C4_GEN[g] + 32 * c);
    }
    deballer(w, x, 4);
    for (int r = 0; r < R; r++) {
        for (int c = 0; c < 8; c++) {
            L[c] = _mm256_shuffle_epi8(LOGSv, _mm256_xor_si256(x[c], LD(RC4[r] + 32 * c)));
            acc[c] = MULLOG(L[c], LCS[c]);
        }
        G4(0, 0) G4(1, 83) G4(2, 56) G4(3, 51) G4(4, 17) G4(5, 42)
        memcpy(x, acc, sizeof x);
    }
    emballer(x, w, 4);
}

/* ---------- référence scalaire du même tour ---------- */
static int nbr(int m, int v, int k) /* v = i + m·f ; v·s_k */
{
    int i = v % m, f = v / m;
    return f == 0 ? (i + k) % m + m : ((i - k) % m + m) % m;
}

static void ref_perm(int m, const int *K, const uint8_t *cself, uint8_t cgen[6][256], uint8_t rc[RMX][256], uint8_t *x, int R)
{
    int n = 2 * m;
    uint8_t y[256], z[256];
    for (int r = 0; r < R; r++) {
        for (int v = 0; v < n; v++)
            y[v] = BR_SBOX[x[v] ^ rc[r][v]];
        for (int v = 0; v < n; v++) {
            uint8_t a = gf_mul(cself[v], y[v]);
            for (int g = 0; g < 6; g++)
                a ^= gf_mul(cgen[g][v], y[nbr(m, v, K[g])]);
            z[v] = a;
        }
        memcpy(x, z, n);
    }
}

static uint64_t g_a = 0x1234567;
static uint8_t alea15(void)
{
    g_a ^= g_a << 13;
    g_a ^= g_a >> 7;
    g_a ^= g_a << 17;
    return (uint8_t)(1 + (g_a >> 20) % 15);
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static uint8_t inv_log(uint8_t l) /* coefficient de logarithme l */
{
    for (int c = 1; c < 16; c++)
        if (BR_LOG[c] == l)
            return (uint8_t)c;
    return 0;
}

int main(void)
{
    if (!bref_init())
        return 2;
    for (int x = 0; x < 16; x++)
        LOGS[x] = BR_LOG[BR_SBOX[x]];
    int ok = 1;
    /* 512 : vrais coefficients de M (BM), vraies constantes, ordre des sommets de la suite (v = i + 64·f) */
    int K2[6] = {21, 0, 7, 45, 8, 62};
    for (int v = 0; v < 128; v++) {
        C2_SELF[v] = BR_LOG[BM[v][v]];
        for (int g = 0; g < 6; g++)
            C2_GEN[g][v] = BR_LOG[BM[v][nbr(64, v, K2[g])]];
    }
    for (int r = 0; r < 32; r++)
        memcpy(RC2[r], BR_RC[r], 128);
    {
        uint8_t a[64], b[64];
        int conf = 1;
        for (int e = 0; e < 64; e++) {
            for (int i = 0; i < 64; i++)
                a[i] = (uint8_t)(e * 37 + i * 101);
            memcpy(b, a, 64);
            perm512(a, 32);
            sl_brume_permute(b);
            conf &= !memcmp(a, b, 64);
        }
        printf("noyau 512 (meme style) = sl_brume_permute a 32 tours : %s\n", conf ? "OK" : "ECHEC");
        ok &= conf;
    }
    /* pour la mesure à 40 tours : constantes 32..39 arbitraires (non mesurées pour la sécurité) */
    for (int r = 32; r < RMX; r++)
        for (int v = 0; v < 128; v++)
            RC2[r][v] = alea15();
    /* 1 024 : coefficients non nuls et constantes au hasard */
    int K4[6] = {0, 83, 56, 51, 17, 42};
    uint8_t cs[256], cg[6][256], rc[RMX][256];
    for (int v = 0; v < 256; v++) {
        cs[v] = alea15();
        C4_SELF[v] = BR_LOG[cs[v]];
        for (int g = 0; g < 6; g++) {
            cg[g][v] = alea15();
            C4_GEN[g][v] = BR_LOG[cg[g][v]];
        }
    }
    for (int r = 0; r < RMX; r++)
        for (int v = 0; v < 256; v++)
            RC4[r][v] = rc[r][v] = alea15() & 15;
    (void)inv_log;
    {
        int conf = 1;
        for (int e = 0; e < 16; e++) {
            uint8_t w[128], x[256];
            for (int i = 0; i < 128; i++)
                w[i] = (uint8_t)(e * 53 + i * 29 + 7);
            for (int i = 0; i < 128; i++) {
                x[2 * i] = w[i] & 15;
                x[2 * i + 1] = w[i] >> 4;
            }
            perm1024(w, RT);
            ref_perm(128, K4, cs, cg, rc, x, RT);
            for (int i = 0; i < 128; i++)
                conf &= w[i] == (uint8_t)(x[2 * i] | x[2 * i + 1] << 4);
        }
        printf("noyau 1024 = reference scalaire du meme tour (40 tours) : %s\n", conf ? "OK" : "ECHEC");
        ok &= conf;
    }
    /* mesures : médiane de 7 séries, R = 40 */
    double t2[7], t4[7], ts[7];
    uint8_t a[64] = {1}, b[128] = {2}, c[64] = {3};
    const int NB = 200000;
    for (int s = 0; s < 7; s++) {
        double t0 = maintenant();
        for (int i = 0; i < NB; i++)
            perm512(a, RT);
        t2[s] = (maintenant() - t0) / NB * 1e9;
        t0 = maintenant();
        for (int i = 0; i < NB; i++)
            perm1024(b, RT);
        t4[s] = (maintenant() - t0) / NB * 1e9;
        t0 = maintenant();
        for (int i = 0; i < NB; i++)
            sl_brume_permute(c);
        ts[s] = (maintenant() - t0) / NB * 1e9;
    }
    for (int i = 0; i < 7; i++)
        for (int j = i + 1; j < 7; j++) {
            double u;
            if (t2[j] < t2[i]) { u = t2[i]; t2[i] = t2[j]; t2[j] = u; }
            if (t4[j] < t4[i]) { u = t4[i]; t4[i] = t4[j]; t4[j] = u; }
            if (ts[j] < ts[i]) { u = ts[i]; ts[i] = ts[j]; ts[j] = u; }
        }
    printf("permutation 1 etat, 40 tours (mediane de 7) : 512 bits %.1f ns ; 1024 bits %.1f ns ; rapport %.2f "
           "(sl_brume_permute, 32 tours : %.1f ns, soit %.1f ns a 40 tours)\n", t2[3], t4[3], t4[3] / t2[3], ts[3], ts[3] * 40 / 32);
    printf("eponge sequentielle, c = 384 : 512q (debit 16 o) %.1f Mo/s ; 1024q (debit 80 o) %.1f Mo/s ; gain x%.2f\n",
           16e3 / t2[3], 80e3 / t4[3], (80e3 / t4[3]) / (16e3 / t2[3]));
    printf("noyau1024 %s (%d checksum %02x%02x)\n", ok ? "OK" : "ECHEC", RT, a[0] ^ c[0], b[0]);
    return ok ? 0 : 1;
}
