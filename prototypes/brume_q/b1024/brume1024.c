/* BRUME-1024q — prototype (hors suite) : permutation BRUME de 1 024 bits (256 nibbles, graphe de Cayley de D₂₅₆), éponge à
 * c = 384 (débit 640 bits = 80 octets), pour le profil à 128 bits quantiques. Tables : b1024_tables.h (gen_b1024.c).
 *
 * Tour r : x ← M·S(x ⊕ RC[r]), S = S-box de BRUME-512 v0.5, M de support A ⊕ I (7 termes par ligne). R = 32 par défaut
 * (choix de l'auteur, sous réserve des certifications de WIDTH_ANALYSIS.md § 6 critère 1 à 4 pour cette permutation).
 * Noyaux : référence dense (M et M⁻¹ explicites, deux sens) ; AVX2 à 1 état, état déballé (un nibble par octet, 8 ymm)
 * conservé d'un bloc à l'autre ; AVX2 à 32 états (vertical) ; AVX2 bitslicé à 256 états (un registre par bit de nibble,
 * diffusion en XOR, S-box en circuit : b1024_bs.h, gen_bitslice.c) pour les feuilles de l'arbre.
 * Modes : éponge à domaine (bourrage 10*, domaine dans le dernier octet de la capacité), état initial P(IV) avec
 * IV = (débit, tours, « 1024 », mode) dans la capacité ; hachage par défaut = arbre (feuilles de 8 Kio, CV de 64 octets,
 * racine), l'éponge DOM_SEQ sert de XOF.
 *   cc -O3 -march=native -fopenmp -I sillage/c -I tests/c -I prototypes/brume_q/b1024 prototypes/brume_q/b1024/brume1024.c \
 *      sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm -o tests/c/build/brume1024
 */
#include <immintrin.h>
#include <omp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "b1024_tables.h"
#include "b1024_lot.h"
#include "brume512_simd.h"
#include "brume_ref.h"
#include "resultat.h"
#include "sillage.h"

#define N1 256
#define RB 80          /* débit en octets */
#define FEUILLE 8192
#define CVL 64
/* Modes (octet 127, nibble bas) : 5 = éponge sans clé (XOF, feuilles, racine, message seul), 3 = AEAD à clé dans tout
 * l'état. Domaines (octet 127, nibble haut, ajoutés au dernier bloc de chaque phase) : voir DOMAINS.md. */
enum { MODE_EPONGE = 5, MODE_AEAD = 3 };
enum { DOM_SEQ = 0, DOM_FEUILLE = 8, DOM_RACINE = 9, DOM_SEUL = 10 };

static int R1 = 32;    /* nombre de tours du profil */

/* ------------------------------------------------------------ référence dense */
static uint8_t DM[N1][N1], DMI[N1][N1], SI[16];

static int nbr(int v, int k)
{
    int i = v % B1_M, f = v / B1_M;
    return f == 0 ? (i + k) % B1_M + B1_M : ((i - k) % B1_M + B1_M) % B1_M;
}

static int ref_init(void)
{
    for (int x = 0; x < 16; x++)
        SI[BR_SBOX[x]] = (uint8_t)x;
    memset(DM, 0, sizeof DM);
    for (int v = 0; v < N1; v++) {
        DM[v][v] = B1_CS[v];
        for (int g = 0; g < 6; g++)
            DM[v][nbr(v, B1_K[g])] = B1_CG[g][v];
    }
    static uint8_t T[N1][2 * N1];
    for (int i = 0; i < N1; i++)
        for (int j = 0; j < 2 * N1; j++)
            T[i][j] = j < N1 ? DM[i][j] : (j - N1 == i);
    for (int c = 0; c < N1; c++) {
        int p = c;
        while (p < N1 && !T[p][c])
            p++;
        if (p == N1)
            return 0;
        if (p != c)
            for (int j = 0; j < 2 * N1; j++) { uint8_t t = T[p][j]; T[p][j] = T[c][j]; T[c][j] = t; }
        uint8_t iv = gf_inv(T[c][c]);
        for (int j = 0; j < 2 * N1; j++)
            T[c][j] = gf_mul(T[c][j], iv);
        for (int i = 0; i < N1; i++)
            if (i != c && T[i][c]) {
                uint8_t f = T[i][c];
                for (int j = 0; j < 2 * N1; j++)
                    T[i][j] ^= gf_mul(f, T[c][j]);
            }
    }
    for (int i = 0; i < N1; i++)
        memcpy(DMI[i], T[i] + N1, N1);
    return 1;
}

static void ref_lin(const uint8_t Mx[N1][N1], uint8_t *x)
{
    uint8_t y[N1];
    for (int v = 0; v < N1; v++) {
        uint8_t a = 0;
        for (int i = 0; i < N1; i++)
            if (Mx[v][i])
                a ^= gf_mul(Mx[v][i], x[i]);
        y[v] = a;
    }
    memcpy(x, y, N1);
}

static void ref_tour(uint8_t *x, int r)
{
    for (int j = 0; j < N1; j++)
        x[j] = BR_SBOX[x[j] ^ B1_RC[r][j]];
    ref_lin(DM, x);
}

static void ref_tour_inv(uint8_t *x, int r)
{
    ref_lin(DMI, x);
    for (int j = 0; j < N1; j++)
        x[j] = SI[x[j]] ^ B1_RC[r][j];
}

static void deballer_ref(const uint8_t w[128], uint8_t x[N1])
{
    for (int i = 0; i < 128; i++) {
        x[2 * i] = w[i] & 15;
        x[2 * i + 1] = w[i] >> 4;
    }
}

static void emballer_ref(const uint8_t x[N1], uint8_t w[128])
{
    for (int i = 0; i < 128; i++)
        w[i] = (uint8_t)(x[2 * i] | x[2 * i + 1] << 4);
}

/* ------------------------------------------------------------ AVX2, 1 état */
#define LD(p) _mm256_loadu_si256((const __m256i *)(p))
#define BC16(t) _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)(t)))
#define ROT(A, B, K)                                                              \
    ((K) == 0 ? (A)                                                               \
     : (K) < 16 ? _mm256_alignr_epi8(_mm256_permute2x128_si256(A, B, 0x21), A, (K) & 15) \
                : _mm256_alignr_epi8(B, _mm256_permute2x128_si256(A, B, 0x21), (K) & 15))
#define MULLOG(Lv, LCv)                                                           \
    ({ __m256i s_ = _mm256_add_epi8(Lv, LCv);                                     \
       s_ = _mm256_min_epu8(s_, _mm256_sub_epi8(s_, _mm256_set1_epi8(15)));        \
       _mm256_shuffle_epi8(EXPv, s_); })
#define ROTM(X, c, Q) ROT((X)[((c) + (Q) / 32) % 4], (X)[((c) + (Q) / 32 + 1) % 4], (Q) % 32)
/* les décalages doivent être des littéraux : ils sont recopiés ici et contrôlés contre B1_K au démarrage */
#define K0 0
#define K1 105
#define K2 71
#define K3 76
#define K4 72
#define K5 31

static uint8_t LC_SELF[N1] __attribute__((aligned(32))), LC_GEN[6][N1] __attribute__((aligned(32)));
static uint8_t RCA[B1_RT][N1] __attribute__((aligned(32)));
static uint8_t LOGS[16];

static inline void deballer8(const uint8_t *p, __m256i x[8])
{
    const __m256i m = _mm256_set1_epi8(15);
    for (int h = 0; h < 4; h++) {
        __m256i P = LD(p + 32 * h);
        __m256i lo = _mm256_and_si256(P, m), hi = _mm256_and_si256(_mm256_srli_epi16(P, 4), m);
        __m256i r0 = _mm256_unpacklo_epi8(lo, hi), r1 = _mm256_unpackhi_epi8(lo, hi);
        x[2 * h] = _mm256_permute2x128_si256(r0, r1, 0x20);
        x[2 * h + 1] = _mm256_permute2x128_si256(r0, r1, 0x31);
    }
}

static inline void emballer8(const __m256i x[8], uint8_t *p, int nreg)   /* nreg registres (pair) → 16·nreg octets */
{
    const __m256i f = _mm256_set1_epi16(0x1001);
    for (int h = 0; 2 * h < nreg; h++) {
        __m256i r0 = _mm256_permute2x128_si256(x[2 * h], x[2 * h + 1], 0x20);
        __m256i r1 = _mm256_permute2x128_si256(x[2 * h], x[2 * h + 1], 0x31);
        __m256i a = _mm256_maddubs_epi16(r0, f), b = _mm256_maddubs_epi16(r1, f);
        _mm256_storeu_si256((__m256i *)(p + 32 * h), _mm256_packus_epi16(a, b));
    }
}

/* variante ordonnée par registre de sortie : les 7 termes d'un registre à la suite, coefficients lus en mémoire
 * (opérandes mémoire de vpaddb), pour réduire la pression sur les 16 registres ymm */
#define LCM(t, c) _mm256_load_si256((const __m256i *)(LC_GEN[t] + 32 * (c)))
#define SORTIE0(c)                                                                                         \
    x[c] = _mm256_xor_si256(                                                                               \
        _mm256_xor_si256(_mm256_xor_si256(MULLOG(L[c], _mm256_load_si256((const __m256i *)(LC_SELF + 32 * (c)))), \
                                          MULLOG(ROTM(L + 4, c, K0), LCM(0, c))),                          \
                         _mm256_xor_si256(MULLOG(ROTM(L + 4, c, K1), LCM(1, c)), MULLOG(ROTM(L + 4, c, K2), LCM(2, c)))), \
        _mm256_xor_si256(_mm256_xor_si256(MULLOG(ROTM(L + 4, c, K3), LCM(3, c)), MULLOG(ROTM(L + 4, c, K4), LCM(4, c))), \
                         MULLOG(ROTM(L + 4, c, K5), LCM(5, c))));
#define SORTIE1(c)                                                                                         \
    x[4 + c] = _mm256_xor_si256(                                                                           \
        _mm256_xor_si256(_mm256_xor_si256(MULLOG(L[4 + c], _mm256_load_si256((const __m256i *)(LC_SELF + 32 * (4 + c)))), \
                                          MULLOG(ROTM(L, c, (128 - K0) % 128), LCM(0, 4 + c))),            \
                         _mm256_xor_si256(MULLOG(ROTM(L, c, (128 - K1) % 128), LCM(1, 4 + c)),             \
                                          MULLOG(ROTM(L, c, (128 - K2) % 128), LCM(2, 4 + c)))),           \
        _mm256_xor_si256(_mm256_xor_si256(MULLOG(ROTM(L, c, (128 - K3) % 128), LCM(3, 4 + c)),             \
                                          MULLOG(ROTM(L, c, (128 - K4) % 128), LCM(4, 4 + c))),            \
                         MULLOG(ROTM(L, c, (128 - K5) % 128), LCM(5, 4 + c))));

static void perm_u2(__m256i x[8], int R)
{
    const __m256i LOGSv = BC16(LOGS), EXPv = BC16(BR_EXP);
    __m256i L[8];
    for (int r = 0; r < R; r++) {
        for (int c = 0; c < 8; c++)
            L[c] = _mm256_shuffle_epi8(LOGSv, _mm256_xor_si256(x[c], _mm256_load_si256((const __m256i *)(RCA[r] + 32 * c))));
        SORTIE0(0) SORTIE0(1) SORTIE0(2) SORTIE0(3)
        SORTIE1(0) SORTIE1(1) SORTIE1(2) SORTIE1(3)
    }
}

/* permutation sur l'état déballé (8 ymm) */
static void perm_u(__m256i x[8], int R) { perm_u2(x, R); }

static void perm1(uint8_t w[128], int R)
{
    __m256i x[8];
    deballer8(w, x);
    perm_u(x, R);
    emballer8(x, w, 8);
}

/* ------------------------------------------------------------ AVX2, 32 états (vertical) */
static __m256i TG[16], TSB;
static uint8_t NBI[7][N1];      /* NBI[0][v] = v, NBI[1 + g][v] = v·s_K[g] */
static uint8_t CO[7][N1];       /* coefficients correspondants */

static inline void tr16(__m128i r[16])
{
    __m128i a[16], b[16], c[16];
    for (int k = 0; k < 8; k++) {
        a[2 * k] = _mm_unpacklo_epi8(r[2 * k], r[2 * k + 1]);
        a[2 * k + 1] = _mm_unpackhi_epi8(r[2 * k], r[2 * k + 1]);
    }
    for (int m = 0; m < 4; m++) {
        b[4 * m] = _mm_unpacklo_epi16(a[4 * m], a[4 * m + 2]);
        b[4 * m + 1] = _mm_unpackhi_epi16(a[4 * m], a[4 * m + 2]);
        b[4 * m + 2] = _mm_unpacklo_epi16(a[4 * m + 1], a[4 * m + 3]);
        b[4 * m + 3] = _mm_unpackhi_epi16(a[4 * m + 1], a[4 * m + 3]);
    }
    for (int g = 0; g < 2; g++)
        for (int i = 0; i < 4; i++) {
            c[8 * g + 2 * i] = _mm_unpacklo_epi32(b[8 * g + i], b[8 * g + 4 + i]);
            c[8 * g + 2 * i + 1] = _mm_unpackhi_epi32(b[8 * g + i], b[8 * g + 4 + i]);
        }
    for (int i = 0; i < 8; i++) {
        r[2 * i] = _mm_unpacklo_epi64(c[i], c[8 + i]);
        r[2 * i + 1] = _mm_unpackhi_epi64(c[i], c[8 + i]);
    }
}

static void lot(uint8_t (*e)[128], int R)
{
    __m256i s[N1], y[N1];
    uint8_t T[128][32] __attribute__((aligned(32)));
    __m128i r[16];
    const __m256i m4 = _mm256_set1_epi8(15);
    for (int Q = 0; Q < 2; Q++)
        for (int K = 0; K < 8; K++) {
            for (int i = 0; i < 16; i++)
                r[i] = _mm_loadu_si128((const __m128i *)(e[16 * Q + i] + 16 * K));
            tr16(r);
            for (int j = 0; j < 16; j++)
                _mm_store_si128((__m128i *)(T[16 * K + j] + 16 * Q), r[j]);
        }
    for (int b = 0; b < 128; b++) {
        __m256i x = _mm256_load_si256((const __m256i *)T[b]);
        s[2 * b] = _mm256_and_si256(x, m4);
        s[2 * b + 1] = _mm256_and_si256(_mm256_srli_epi16(x, 4), m4);
    }
    for (int rr = 0; rr < R; rr++) {
        for (int v = 0; v < N1; v++)
            y[v] = _mm256_shuffle_epi8(TSB, _mm256_xor_si256(s[v], _mm256_set1_epi8((char)B1_RC[rr][v])));  /* plus rapide que des tables par tour (L1) */
        B1_DIFFUSION_LOT(y, s, TG);
    }
    for (int b = 0; b < 128; b++)
        _mm256_store_si256((__m256i *)T[b], _mm256_or_si256(s[2 * b], _mm256_slli_epi16(s[2 * b + 1], 4)));
    for (int Q = 0; Q < 2; Q++)
        for (int K = 0; K < 8; K++) {
            for (int j = 0; j < 16; j++)
                r[j] = _mm_load_si128((const __m128i *)(T[16 * K + j] + 16 * Q));
            tr16(r);
            for (int i = 0; i < 16; i++)
                _mm_storeu_si128((__m128i *)(e[16 * Q + i] + 16 * K), r[i]);
        }
}

static int init_noyaux(void)
{
    const int K[6] = {K0, K1, K2, K3, K4, K5};
    for (int g = 0; g < 6; g++)
        if (K[g] != B1_K[g])
            return 0;
    for (int x = 0; x < 16; x++)
        LOGS[x] = BR_LOG[BR_SBOX[x]];
    for (int v = 0; v < N1; v++) {
        LC_SELF[v] = BR_LOG[B1_CS[v]];
        NBI[0][v] = (uint8_t)v;
        CO[0][v] = B1_CS[v];
        for (int g = 0; g < 6; g++) {
            LC_GEN[g][v] = BR_LOG[B1_CG[g][v]];
            NBI[1 + g][v] = (uint8_t)nbr(v, B1_K[g]);
            CO[1 + g][v] = B1_CG[g][v];
        }
    }
    memcpy(RCA, B1_RC, sizeof RCA);
    uint8_t t[32];
    for (int c = 0; c < 16; c++) {
        for (int x = 0; x < 32; x++)
            t[x] = gf_mul((uint8_t)c, (uint8_t)(x & 15));
        TG[c] = LD(t);
    }
    for (int x = 0; x < 32; x++)
        t[x] = BR_SBOX[x & 15];
    TSB = LD(t);
    return 1;
}

/* ------------------------------------------------------------ modes */
/* P(IV) ne dépend que du profil et du mode : calculé une fois (mêmes sorties, une permutation de moins par appel) */
static uint8_t IVC[8][128] __attribute__((aligned(32)));
static int ivc_pret[8], ivc_tours[8];

static void etat_iv(uint8_t w[128], int mode);
/* à appeler après init_noyaux() et le choix de R1, avant tout appel parallèle : remplit le cache de P(IV) */
static void bs_preparer(void);
static void prepare_iv(void)
{
    uint8_t t[128];
    etat_iv(t, MODE_EPONGE);
    bs_preparer();   /* P(IV) en plans de bits pour le noyau bitslicé */
}

/* cadre du profil, octets 121..127 (les octets 0..120 ne sont pas touchés) : tours, débit, largeur, 'q', mode */
static void cadre_iv(uint8_t t[128], int mode)
{
    t[121] = (uint8_t)R1;
    t[122] = 0;
    t[123] = 0;
    t[124] = 2 * RB;           /* débit en nibbles */
    t[125] = 0x10;             /* largeur 1 024 */
    t[126] = 'q';
    t[127] = (uint8_t)mode;
}

/* nombre de calculs de P(IV) (etat_iv) et de ses plans de bits (bs_preparer) : contrôle que le cache sert, et qu'aucun
 * calcul n'a lieu dans une région parallèle après prepare_iv() (contrôle cache_piv_aucun_recalcul_…) */
static long IV_CALCULS;
static void etat_iv(uint8_t w[128], int mode)
{
    if (!ivc_pret[mode] || ivc_tours[mode] != R1) {
        __atomic_fetch_add(&IV_CALCULS, 1, __ATOMIC_SEQ_CST);
        uint8_t t[128];
        memset(t, 0, 128);
        cadre_iv(t, mode);
        perm1(t, R1);
        memcpy(IVC[mode], t, 128);
        ivc_tours[mode] = R1;
        ivc_pret[mode] = 1;        /* rempli par prepare_iv() avant tout appel parallèle */
    }
    memcpy(w, IVC[mode], 128);
}

/* éponge à domaine, état déballé gardé entre les blocs ; le débit (80 octets = 160 nibbles) = registres 0 à 4 */
static void eponge(const uint8_t *m, size_t len, int dom, uint8_t *out, size_t outlen)
{
    uint8_t w[128] __attribute__((aligned(32)));
    etat_iv(w, MODE_EPONGE);
    __m256i x[8], b[8];
    deballer8(w, x);
    uint8_t blk[128] __attribute__((aligned(32)));
    memset(blk, 0, sizeof blk);
    size_t i = 0;
    for (; i + RB <= len; i += RB) {
        memcpy(blk, m + i, RB);
        deballer8(blk, b);                       /* registres 5..7 de b : nuls (octets 80..127 à zéro) */
        for (int c = 0; c < 5; c++)
            x[c] = _mm256_xor_si256(x[c], b[c]);
        perm_u(x, R1);
    }
    memset(blk, 0, sizeof blk);
    memcpy(blk, m + i, len - i);
    blk[len - i] ^= 0x01;
    blk[127] ^= (uint8_t)(dom << 4);
    deballer8(blk, b);
    for (int c = 0; c < 8; c++)
        x[c] = _mm256_xor_si256(x[c], b[c]);
    perm_u(x, R1);
    for (size_t o = 0; o < outlen; o += RB) {
        emballer8(x, w, 8);
        size_t k = outlen - o < RB ? outlen - o : RB;
        memcpy(out + o, w, k);
        if (o + RB < outlen)
            perm_u(x, R1);
    }
}

/* même calcul que eponge(), entièrement sur l'état emballé et par la référence dense (contrôle) */
static void eponge_ref(const uint8_t *m, size_t len, int dom, uint8_t *out, size_t outlen)
{
    uint8_t w[128], x[N1];
    memset(w, 0, 128);
    cadre_iv(w, MODE_EPONGE);
    deballer_ref(w, x);
    for (int r = 0; r < R1; r++) ref_tour(x, r);
    emballer_ref(x, w);
    size_t i = 0;
    for (;; i += RB) {
        int fin = i + RB > len;
        size_t n = fin ? len - i : RB;
        for (size_t k = 0; k < n; k++)
            w[k] ^= m[i + k];
        if (fin) {
            w[n] ^= 0x01;
            w[127] ^= (uint8_t)(dom << 4);
        }
        deballer_ref(w, x);
        for (int r = 0; r < R1; r++) ref_tour(x, r);
        emballer_ref(x, w);
        if (fin)
            break;
    }
    for (size_t o = 0; o < outlen; o += RB) {
        size_t k = outlen - o < RB ? outlen - o : RB;
        memcpy(out + o, w, k);
        if (o + RB < outlen) {
            deballer_ref(w, x);
            for (int r = 0; r < R1; r++) ref_tour(x, r);
            emballer_ref(x, w);
        }
    }
}

/* Allocations des lots : en cas d'échec, chaque appelant se replie sur un chemin sans allocation (mêmes sorties), ou
 * signale l'erreur (arbre). Point d'injection pour les contrôles : la n-ième allocation qui suit l'affectation
 * ALLOC_ECHEC = n échoue (−1 : jamais). */
static long ALLOC_ECHEC = -1, ALLOC_INJECTES;   /* ALLOC_INJECTES : échecs réellement provoqués */
static void *allouer(size_t n)
{
    if (__atomic_fetch_sub(&ALLOC_ECHEC, 1, __ATOMIC_SEQ_CST) == 0) {
        __atomic_fetch_add(&ALLOC_INJECTES, 1, __ATOMIC_SEQ_CST);
        return NULL;
    }
    return aligned_alloc(64, (n + 63) / 64 * 64);
}

/* 32 feuilles pleines (8 192 octets) à la fois : même calcul que eponge(feuille, DOM_FEUILLE, CV de 64 octets) */
static void feuilles(const uint8_t *m0, int n, uint8_t *cv)
{
    uint8_t (*st)[128] = allouer(32 * 128);
    if (!st) {   /* repli : une éponge par feuille */
        for (int i = 0; i < n; i++)
            eponge(m0 + (size_t)i * FEUILLE, FEUILLE, DOM_FEUILLE, cv + (size_t)i * CVL, CVL);
        return;
    }
    uint8_t w0[128];
    etat_iv(w0, MODE_EPONGE);
    for (int i = 0; i < 32; i++)
        memcpy(st[i], w0, 128);
    const size_t pleins = FEUILLE / RB, reste = FEUILLE - pleins * RB;
    for (size_t b = 0; b < pleins; b++) {
        for (int i = 0; i < n; i++) {
            const uint8_t *src = m0 + (size_t)i * FEUILLE + RB * b;
            for (size_t k = 0; k < RB; k++)
                st[i][k] ^= src[k];
        }
        lot(st, R1);
    }
    for (int i = 0; i < n; i++) {
        const uint8_t *src = m0 + (size_t)i * FEUILLE + RB * pleins;
        for (size_t k = 0; k < reste; k++)
            st[i][k] ^= src[k];
        st[i][reste] ^= 0x01;
        st[i][127] ^= DOM_FEUILLE << 4;
    }
    lot(st, R1);
    for (int i = 0; i < n; i++)
        memcpy(cv + (size_t)i * CVL, st[i], CVL);
    free(st);
}

/* ------------------------------------------------------------ AVX2 bitslicé, 256 états (feuilles de l'arbre) */
/* Plans de bits : P[v][i] (256 bits), bit k = bit i du nibble v de l'état k ; nibble v = octet v/2, bas si v pair.
 * b1024_bs.h (gen_bitslice.c) : diffusion en XOR (matrices 4×4 de GF(16) sur GF(2), XOR communs partagés), S-box en
 * circuit de 22 portes dont les sorties valent S(x) ⊕ 0xA, la constante étant reportée dans BS_RCK et dans bs_lin. */
#include "b1024_bs.h"

static __m256i BS_IV[N1][4];
static int bs_iv_tours;   /* R1 pour lequel BS_IV a été préparé */
static __thread __m256i BS_P[N1][4] __attribute__((aligned(64))), BS_Y[N1][4] __attribute__((aligned(64))),
    BS_Z[N1][4] __attribute__((aligned(64)));

static void bs_preparer(void)
{
    __atomic_fetch_add(&IV_CALCULS, 1, __ATOMIC_SEQ_CST);
    bs_init();
    for (int v = 0; v < N1; v++)
        for (int i = 0; i < 4; i++)
            BS_IV[v][i] = _mm256_set1_epi32(-((IVC[MODE_EPONGE][v / 2] >> (4 * (v & 1) + i)) & 1));
    bs_iv_tours = R1;
}

/* permutation de 256 états, en place sur P */
static void bs_perm(__m256i (*P)[4], int R)
{
    __m256i (*y)[4] = BS_Y, (*z)[4] = BS_Z;
    for (int v = 0; v < N1; v++) {
        const uint8_t c = BS_RCK[0][v];   /* RC[0] ⊕ translation d'entrée du circuit */
        bs_sbox(_mm256_xor_si256(P[v][0], BS_MSK[c][0]), _mm256_xor_si256(P[v][1], BS_MSK[c][1]),
                _mm256_xor_si256(P[v][2], BS_MSK[c][2]), _mm256_xor_si256(P[v][3], BS_MSK[c][3]), y[v]);
    }
    for (int rr = 0; rr + 1 < R; rr++) {
        bs_tour((const __m256i (*)[4])y, z, BS_RCK[rr + 1]);
        __m256i (*t)[4] = y; y = z; z = t;
    }
    bs_lin((const __m256i (*)[4])y, P);
}

/* octets [0, 16·nk) de 32 messages espacés de pas → T[b][j] = octet b du message j */
static void octets32(const uint8_t *m, size_t pas, int nk, uint8_t T[128][32])
{
    __m128i r[16];
    for (int Q = 0; Q < 2; Q++)
        for (int K = 0; K < nk; K++) {
            for (int i = 0; i < 16; i++)
                r[i] = _mm_loadu_si128((const __m128i *)(m + (size_t)(16 * Q + i) * pas + 16 * K));
            tr16(r);
            for (int j = 0; j < 16; j++)
                _mm_store_si128((__m128i *)(T[16 * K + j] + 16 * Q), r[j]);
        }
}

/* XOR des octets [0, 16·nk) de 256 messages (m + k·pas) dans les plans */
static void bs_absorber(__m256i (*P)[4], const uint8_t *m, size_t pas, int nk)
{
    uint8_t T[128][32] __attribute__((aligned(32)));
    uint32_t *d = (uint32_t *)P;   /* __m256i peut tout aliaser : accès par mots de 32 bits */
    for (int g = 0; g < 8; g++) {
        octets32(m + (size_t)32 * g * pas, pas, nk, T);
        for (int b = 0; b < 16 * nk; b++) {
            const __m256i x = _mm256_load_si256((const __m256i *)T[b]);
            for (int q = 0; q < 8; q++)
                d[((2 * b + (q >> 2)) * 4 + (q & 3)) * 8 + g] ^= (uint32_t)_mm256_movemask_epi8(_mm256_slli_epi16(x, 7 - q));
        }
    }
}

/* octets [0, 16·nk) des 256 états → out + k·pas */
static void bs_extraire(const __m256i (*P)[4], uint8_t *out, size_t pas, int nk)
{
    uint8_t T[128][32] __attribute__((aligned(32)));
    __m128i r[16];
    const uint32_t *d = (const uint32_t *)P;
    const __m256i ctl = _mm256_setr_epi8(0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3);
    const __m256i sel = _mm256_set1_epi64x((long long)0x8040201008040201ULL);
    for (int g = 0; g < 8; g++) {
        for (int b = 0; b < 16 * nk; b++) {
            __m256i x = _mm256_setzero_si256();
            for (int q = 0; q < 8; q++) {
                __m256i o = _mm256_shuffle_epi8(_mm256_set1_epi32((int)d[((2 * b + (q >> 2)) * 4 + (q & 3)) * 8 + g]), ctl);
                o = _mm256_cmpeq_epi8(_mm256_and_si256(o, sel), sel);
                x = _mm256_or_si256(x, _mm256_and_si256(o, _mm256_set1_epi8((char)(1 << q))));
            }
            _mm256_store_si256((__m256i *)T[b], x);
        }
        for (int Q = 0; Q < 2; Q++)
            for (int K = 0; K < nk; K++) {
                for (int j = 0; j < 16; j++)
                    r[j] = _mm_load_si128((const __m128i *)(T[16 * K + j] + 16 * Q));
                tr16(r);
                for (int i = 0; i < 16; i++)
                    _mm_storeu_si128((__m128i *)(out + (size_t)(32 * g + 16 * Q + i) * pas + 16 * K), r[i]);
            }
    }
}

_Static_assert((FEUILLE % RB) % 16 == 0 && CVL % 16 == 0 && RB % 16 == 0, "découpage en blocs de 16 octets");

/* 256 feuilles pleines : même calcul que eponge(feuille, DOM_FEUILLE, CV de 64 octets), l'état restant en plans de bits */
static void feuilles256(const uint8_t *m0, uint8_t *cv)
{
    __m256i (*P)[4] = BS_P;
    const __m256i un = _mm256_set1_epi32(-1);
    memcpy(P, BS_IV, sizeof BS_IV);
    const size_t pleins = FEUILLE / RB, reste = FEUILLE - pleins * RB;
    for (size_t b = 0; b < pleins; b++) {
        bs_absorber(P, m0 + RB * b, FEUILLE, RB / 16);
        bs_perm(P, R1);
    }
    bs_absorber(P, m0 + RB * pleins, FEUILLE, (int)(reste / 16));
    P[2 * reste][0] = _mm256_xor_si256(P[2 * reste][0], un);                   /* bourrage 0x01 à l'octet reste */
    for (int i = 0; i < 4; i++)                                                /* domaine : nibble haut de l'octet 127 */
        if (DOM_FEUILLE >> i & 1)
            P[255][i] = _mm256_xor_si256(P[255][i], un);
    bs_perm(P, R1);
    bs_extraire((const __m256i (*)[4])P, cv, CVL, CVL / 16);
}

/* rend 0, ou −1 si la racine ne peut être allouée (sortie effacée) */
static int arbre(const uint8_t *m, size_t len, uint8_t *out, size_t outlen, int par_lot)
{
    if (len <= FEUILLE) {
        eponge(m, len, DOM_SEUL, out, outlen);
        return 0;
    }
    /* si le nombre de tours a changé depuis prepare_iv(), refaire P(IV) et ses plans de bits ici, hors de toute région
     * parallèle (sinon : plans de bits périmés pour les lots de 256, et cache rempli par plusieurs threads à la fois) */
    if (!ivc_pret[MODE_EPONGE] || ivc_tours[MODE_EPONGE] != R1 || bs_iv_tours != R1)
        prepare_iv();
    size_t k = len / FEUILLE + (len % FEUILLE != 0), pleines = len / FEUILLE;
    if (pleines == k)
        pleines--;
    size_t lr = (size_t)CVL * k + 12;
    uint8_t *racine = allouer(lr);
    if (!racine) {
        sl_effacer(out, outlen);
        return -1;
    }
    /* Une seule région parallèle, tâches dynamiques, les plus grosses d'abord :
     *  - lots bitslicés de 256 feuilles s'il y a au moins 128 feuilles pleines par thread (un lot de 256 coûte environ la
     *    moitié par feuille d'un lot de 32 : au-delà de ce seuil, il gagne même si des threads restent inoccupés) ;
     *  - le reste par lots de 32 s'il en reste au moins 32 par thread (un lot coûte ses 32 états même à moitié vide) ;
     *  - sinon une éponge par feuille.
     * par_lot = 0 : éponges seules (contrôle) ; 2 : sans les lots de 256 (comparaison). */
    const size_t nt = (size_t)omp_get_max_threads();
    const size_t n256 = par_lot == 1 && pleines >= 128 * nt ? pleines / 256 : 0, f0 = 256 * n256, reste = pleines - f0;
    const int par32 = par_lot && reste >= 32 * nt;
    const size_t npetites = par32 ? (reste + 31) / 32 : reste;
#pragma omp parallel for schedule(dynamic)
    for (long t = 0; t < (long)(n256 + npetites); t++) {
        if ((size_t)t < n256)
            feuilles256(m + (size_t)256 * t * FEUILLE, racine + (size_t)256 * t * CVL);
        else if (par32) {
            size_t d = f0 + 32 * ((size_t)t - n256), nm = pleines - d < 32 ? pleines - d : 32;
            feuilles(m + d * FEUILLE, (int)nm, racine + d * CVL);
        } else {
            size_t i = f0 + (size_t)t - n256;
            eponge(m + i * FEUILLE, FEUILLE, DOM_FEUILLE, racine + i * CVL, CVL);
        }
    }
    for (size_t i = pleines; i < k; i++) {
        size_t l = len - i * FEUILLE < FEUILLE ? len - i * FEUILLE : FEUILLE;
        eponge(m + i * FEUILLE, l, DOM_FEUILLE, racine + i * CVL, CVL);
    }
    uint8_t *q = racine + (size_t)CVL * k;
    for (int i = 0; i < 8; i++)
        q[i] = (uint8_t)((uint64_t)k >> (56 - 8 * i));
    q[8] = 0; q[9] = 0; q[10] = FEUILLE >> 8; q[11] = FEUILLE & 0xFF;
    eponge(racine, lr, DOM_RACINE, out, outlen);
    free(racine);
    return 0;
}

/* ------------------------------------------------------------ AEAD : duplex à clé dans tout l'état (FKD), débit 80 octets */
/* Full-state keyed duplex (Daemen, Mennink, Van Assche, ASIACRYPT 2017 : « DMV17 ») : état initial = clé (octets 0..63,
 * dans le débit) ‖ nonce (64..87 : 64..79 dans le débit, 80..87 dans la capacité) ‖ 0 ‖ IV du profil (121..127, mode 3),
 * puis P. Données associées (DOM_AAD, XOR), texte, longueur (DOM_FINAL), tag = 32 premiers octets ; 4 permutations pour un
 * message court. Texte, ORIENTATION SPONGEWRAP depuis le 13 novembre 2026 (AEAD_SECURITY.md § 6) : le clair est ajouté au
 * débit par XOR au chiffrement, qui contient donc ensuite le CHIFFRÉ (drapeau faux de DMV17 : l'adversaire ne choisit pas
 * la partie externe) ; le déchiffrement écrase le débit avec le chiffré (drapeau vrai ; pour un dernier bloc partiel de r
 * octets, sur ces r octets seulement). Auparavant le débit recevait le clair (drapeau vrai au chiffrement, blocs chiffrés
 * comptés dans Ω). La permutation est passée en paramètre pour recouper le noyau AVX2 avec la référence dense. */
enum { DOM_AAD = 1, DOM_TEXTE = 2, DOM_FINAL = 4 };
typedef void (*perm_f)(uint8_t w[128], int R);

static void perm_ref(uint8_t w[128], int R)
{
    uint8_t x[N1];
    deballer_ref(w, x);
    for (int r = 0; r < R; r++)
        ref_tour(x, r);
    emballer_ref(x, w);
}

static void absorber_a(perm_f P, uint8_t w[128], const uint8_t *d1, size_t l1, int dom)
{
    size_t nb = l1 / RB + 1;
    for (size_t b = 0; b < nb; b++) {
        for (size_t k = 0; k < RB; k++) {
            size_t i = b * RB + k;
            w[k] ^= i < l1 ? d1[i] : (i == l1 ? 0x01 : 0);
        }
        if (b + 1 < nb)
            P(w, R1);
    }
    w[127] ^= (uint8_t)(dom << 4);
    P(w, R1);
}

static void etat_aead(uint8_t w[128], const uint8_t cle[64], const uint8_t nonce[24])
{
    memset(w, 0, 128);
    memcpy(w, cle, 64);
    memcpy(w + 64, nonce, 24);
    cadre_iv(w, MODE_AEAD);
}

/* Limite des longueurs (SPEC.md § 3.5 : |A|, |X| < 2^64 octets, rejet au-delà). size_t ne peut pas exprimer 2^64 sur une
 * plateforme 64 bits, mais les calculs d'indices i + RB et b·RB + k débordent dès que la longueur dépasse SIZE_MAX − 80 : le
 * dernier bloc relirait alors le début du tampon. La borne retenue est donc 2^63 − 1 (taille maximale d'un objet C,
 * PTRDIFF_MAX, et jamais plus que INT64_MAX) : plus stricte que la SPEC, elle laisse 2^63 octets de marge aux indices.
 * Le le64 de la longueur n'est jamais tronqué. Une entrée au-delà est rejetée avant toute lecture ou écriture. */
#define AEAD_LONGUEUR_MAX ((size_t)(PTRDIFF_MAX < INT64_MAX ? PTRDIFF_MAX : INT64_MAX))
_Static_assert(AEAD_LONGUEUR_MAX <= UINT64_MAX && AEAD_LONGUEUR_MAX <= SIZE_MAX - 2 * RB, "longueurs AEAD sans débordement");
static int longueurs_admises(size_t aadlen, size_t len)
{
    return aadlen <= AEAD_LONGUEUR_MAX && len <= AEAD_LONGUEUR_MAX;
}

/* Rend 0, ou −1 sans rien lire ni écrire si une longueur dépasse AEAD_LONGUEUR_MAX. */
static int aead(perm_f P, const uint8_t cle[64], const uint8_t nonce[24], const uint8_t *aad, size_t aadlen, const uint8_t *in,
                size_t len, int dech, uint8_t *out, uint8_t tag[32])
{
    if (!longueurs_admises(aadlen, len))
        return -1;
    uint8_t w[128] __attribute__((aligned(32)));
    etat_aead(w, cle, nonce);
    P(w, R1);
    absorber_a(P, w, aad, aadlen, DOM_AAD);
    size_t i = 0;
    for (; i + RB <= len; i += RB) {
        for (size_t k = 0; k < RB; k++) {
            uint8_t o = in[i + k] ^ w[k];
            out[i + k] = o;
            w[k] = dech ? in[i + k] : o;   /* le débit reçoit le CHIFFRÉ (orientation SpongeWrap) */
        }
        P(w, R1);
    }
    size_t r = len - i;
    for (size_t k = 0; k < r; k++) {       /* dernier bloc : les r premiers octets reçoivent le chiffré, la suite garde Z */
        uint8_t o = in[i + k] ^ w[k];
        out[i + k] = o;
        w[k] = dech ? in[i + k] : o;
    }
    w[r] ^= 0x01;
    w[127] ^= DOM_TEXTE << 4;
    P(w, R1);
    uint8_t l8[8];
    for (int k = 0; k < 8; k++)
        l8[k] = (uint8_t)((uint64_t)len >> (8 * k));
    absorber_a(P, w, l8, 8, DOM_FINAL);
    memcpy(tag, w, 32);
    sl_effacer(w, sizeof w);
    return 0;
}

/* Déchiffrement vérifié : comme la suite (sl_aead_decrypt_ctx), le texte est déchiffré dans pt, les tags sont comparés en
 * temps constant, et en cas d'échec pt est effacé avant le retour : rien n'est rendu. Le verdict est public (l'adversaire
 * apprend l'acceptation ou le rejet). Rend 0 si le tag est bon, −1 sinon (ou si une longueur est hors limite : alors rien
 * n'est lu ni écrit). */
static int aead_ouvrir(const uint8_t cle[64], const uint8_t nonce[24], const uint8_t *aad, size_t aadlen, const uint8_t *ct,
                       size_t len, const uint8_t tag[32], uint8_t *pt)
{
    uint8_t t[32], d = 0;
    if (aead(perm1, cle, nonce, aad, aadlen, ct, len, 1, pt, t))
        return -1;                         /* longueur hors limite : pt n'a pas été écrit, il n'y a rien à effacer */
    for (int i = 0; i < 32; i++)
        d |= t[i] ^ tag[i];
    sl_effacer(t, sizeof t);
    SL_PUBLIC(&d, sizeof d);
    if (d) {
        sl_effacer(pt, len);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------ référence « DMV17 littérale » (contrôle de aead()) */
/* Algorithme 1 de DMV17 (p. 615) transcrit tel quel sur l'état emballé, écrit indépendamment de aead() :
 *   Init(K, iv, σ, flag) : s ← f(K ‖ iv) ; Z ← ⌊s⌋_r ; si flag : σ̄ ← σ̄ + Z ; s ← s + σ
 *   Duplexing(σ, flag)   : s ← f(s)      ; Z ← ⌊s⌋_r ; si flag : σ̄ ← σ̄ + Z ; s ← s + σ
 * Le drapeau porte sur les nv premiers octets de la partie externe (nv = 80 : algorithme 1 tel quel ; nv = r < 80 : dernier
 * bloc partiel au déchiffrement, seul écart, signalé dans AEAD_SECURITY.md). Le mode est écrit comme une suite d'appels. */
/* ch (facultatif, contrôles seulement) : reçoit l'entrée de chemin σ̃ de chaque appel (σ après l'ajustement du drapeau),
 * c'est-à-dire le chemin de l'IXIF de DMV17 (algorithme 2) ; nch appels au plus, ich = nombre d'appels faits. */
typedef struct { uint8_t s[128]; perm_f P; uint8_t (*ch)[128]; size_t nch, ich; } kd_t;
static void kd_suite(kd_t *d, const uint8_t sigma[128], int nv, uint8_t Z[RB])
{
    uint8_t sg[128];
    memcpy(sg, sigma, 128);
    memcpy(Z, d->s, RB);
    for (int k = 0; k < nv; k++)
        sg[k] ^= Z[k];
    if (d->ch && d->ich < d->nch)
        memcpy(d->ch[d->ich], sg, 128);
    d->ich++;
    for (int k = 0; k < 128; k++)
        d->s[k] ^= sg[k];
}
static void kd_init(kd_t *d, const uint8_t K[64], const uint8_t iv[64], const uint8_t sigma[128], int nv, uint8_t Z[RB])
{
    memcpy(d->s, K, 64);
    memcpy(d->s + 64, iv, 64);
    d->P(d->s, R1);
    kd_suite(d, sigma, nv, Z);
}
static void kd_duplexing(kd_t *d, const uint8_t sigma[128], int nv, uint8_t Z[RB])
{
    d->P(d->s, R1);
    kd_suite(d, sigma, nv, Z);
}

static void aead_kd_chemin(perm_f P, const uint8_t cle[64], const uint8_t nonce[24], const uint8_t *aad, size_t aadlen,
                           const uint8_t *in, size_t len, int dech, uint8_t *out, uint8_t tag[32],
                           uint8_t (*ch)[128], size_t nch, size_t *ich)
{
    kd_t d = {.P = P, .ch = ch, .nch = nch};
    uint8_t iv[64] = {0}, sg[128], Z[RB];
    memcpy(iv, nonce, 24);                               /* iv = nonce ‖ 0^264 ‖ cadre (octets 64..127 de l'état) */
    iv[121 - 64] = (uint8_t)R1; iv[124 - 64] = 2 * RB; iv[125 - 64] = 0x10; iv[126 - 64] = 'q'; iv[127 - 64] = MODE_AEAD;
    /* données associées : blocs de A ‖ 0x01 ‖ 0*, domaine sur le dernier, drapeau faux ; le premier par Init */
    size_t nb = aadlen / RB + 1;
    for (size_t b = 0; b < nb; b++) {
        memset(sg, 0, 128);
        for (size_t k = 0; k < RB; k++) {
            size_t i = b * RB + k;
            sg[k] = i < aadlen ? aad[i] : (i == aadlen ? 0x01 : 0);
        }
        if (b + 1 == nb)
            sg[127] = DOM_AAD << 4;
        if (b == 0)
            kd_init(&d, cle, iv, sg, 0, Z);
        else
            kd_duplexing(&d, sg, 0, Z);
    }
    /* texte : chiffrement σ = clair, drapeau faux ; déchiffrement σ = chiffré, drapeau vrai (écrasement) */
    size_t i = 0;
    for (;; i += RB) {
        const int fin = i + RB > len;
        const size_t r = fin ? len - i : RB;
        memset(sg, 0, 128);
        memcpy(sg, in + i, r);
        if (fin) {
            sg[r] ^= 0x01;
            sg[127] = DOM_TEXTE << 4;
        }
        kd_duplexing(&d, sg, dech ? (int)r : 0, Z);
        for (size_t k = 0; k < r; k++)
            out[i + k] = in[i + k] ^ Z[k];
        if (fin)
            break;
    }
    /* longueur, puis un appel de plus pour lire le tag */
    memset(sg, 0, 128);
    for (int k = 0; k < 8; k++)
        sg[k] = (uint8_t)((uint64_t)len >> (8 * k));
    sg[8] = 0x01;
    sg[127] = DOM_FINAL << 4;
    kd_duplexing(&d, sg, 0, Z);
    memset(sg, 0, 128);
    kd_duplexing(&d, sg, 0, Z);
    memcpy(tag, Z, 32);
    if (ich)
        *ich = d.ich;
    sl_effacer(&d, sizeof d);
}
static void aead_kd(perm_f P, const uint8_t cle[64], const uint8_t nonce[24], const uint8_t *aad, size_t aadlen,
                    const uint8_t *in, size_t len, int dech, uint8_t *out, uint8_t tag[32])
{
    aead_kd_chemin(P, cle, nonce, aad, aadlen, in, len, dech, out, tag, NULL, 0, NULL);
}

/* Décodeur du chemin final (AEAD_SECURITY.md § 4 bis, étape AE, ingrédient 3) : à partir des entrées σ̃_0 … σ̃_{n−1} des
 * appels (sans l'appel du tag, dont σ = 0 n'entre dans aucun chemin lu), retrouve (A, M), ou rend −1 si le chemin n'est
 * pas de la forme produite par le mode. Rôles lus sur le nibble haut de l'octet 127 : 0 (bloc non final), DOM_AAD (dernier
 * bloc de A), DOM_TEXTE (dernier bloc du texte), DOM_FINAL (bloc de longueur). Le décodeur est une inverse à gauche du
 * codage (A, M) ↦ chemin : celui-ci est donc injectif, et le rôle de la dernière entrée d'un chemin se lit sur elle seule. */
static int decoder_chemin(const uint8_t (*ch)[128], size_t n, uint8_t *A, size_t *alen, uint8_t *M, size_t *mlen,
                          size_t cap)
{
    size_t e = 0, la = 0, lm = 0;
    for (int phase = 0; phase < 2; phase++) {             /* 0 : AAD, 1 : texte */
        const int dom = phase ? DOM_TEXTE : DOM_AAD;
        uint8_t *o = phase ? M : A;
        size_t *l = phase ? &lm : &la;
        for (;; e++) {
            if (e >= n)
                return -1;
            const uint8_t *s = ch[e];
            for (int k = RB; k < 127; k++)                 /* capacité nulle, sauf le domaine */
                if (s[k])
                    return -1;
            const int nib = s[127] >> 4;
            if ((s[127] & 15) || (nib != 0 && nib != dom))
                return -1;
            if (nib == 0) {                                /* bloc plein */
                if (*l + RB > cap)
                    return -1;
                memcpy(o + *l, s, RB);
                *l += RB;
                continue;
            }
            int p = RB - 1;                                /* dernier bloc : retirer 0* puis 0x01 */
            while (p >= 0 && s[p] == 0)
                p--;
            if (p < 0 || s[p] != 0x01 || *l + (size_t)p > cap)
                return -1;
            memcpy(o + *l, s, (size_t)p);
            *l += (size_t)p;
            e++;
            break;
        }
    }
    if (e + 1 != n)                                        /* reste exactement le bloc de longueur */
        return -1;
    const uint8_t *s = ch[e];
    uint64_t v = 0;
    for (int k = 0; k < 8; k++)
        v |= (uint64_t)s[k] << (8 * k);
    for (int k = 9; k < 127; k++)
        if (s[k])
            return -1;
    if (s[8] != 0x01 || s[127] != (DOM_FINAL << 4) || v != lm)
        return -1;
    *alen = la;
    *mlen = lm;
    return 0;
}
/* contrôles : decoder_chemin sur une copie de taille exacte (n entrées ; A et M reçus dans des tampons de cap octets
 * exactement, ASan voit toute lecture ou écriture hors limites). Rend −1 (rejet), 0 (décodé en (A, M)), 1 (décodé, mais
 * en autre chose), ou la valeur rendue par le décodeur si elle n'est ni 0 ni −1. */
static int dec_essai(const uint8_t (*ch)[128], size_t n, size_t cap, const uint8_t *A, size_t la, const uint8_t *M,
                     size_t lm)
{
    uint8_t(*cp)[128] = malloc(n ? n * 128 : 1), *dA = malloc(cap ? cap : 1), *dM = malloc(cap ? cap : 1);
    if (n)
        memcpy(cp, ch, n * 128);
    size_t a = 0, b = 0;
    int r = decoder_chemin((const uint8_t(*)[128])cp, n, dA, &a, dM, &b, cap);
    if (r == 0 && !(a == la && b == lm && !memcmp(dA, A, la) && !memcmp(dM, M, lm)))
        r = 1;
    free(cp);
    free(dA);
    free(dM);
    return r;
}

/* lot de nm ≤ 32 messages (indices d .. d + nm − 1), noyau vertical à 32 états */
static void aead_lot32(size_t d, size_t nm, const uint8_t *cles, const uint8_t *nonces, const uint8_t *aad, size_t aadlen,
                       const uint8_t *in, size_t len, uint8_t *out, uint8_t *tags)
{
    uint8_t (*st)[128] = allouer(32 * 128);
    if (!st) {   /* repli : un message à la fois */
        for (size_t j = d; j < d + nm; j++)
            aead(perm1, cles + 64 * j, nonces + 24 * j, aad, aadlen, in + j * len, len, 0, out + j * len, tags + 32 * j);
        return;
    }
    memset(st, 0, 32 * 128);
    for (size_t j = 0; j < nm; j++)
        etat_aead(st[j], cles + 64 * (d + j), nonces + 24 * (d + j));
    lot(st, R1);
    /* données associées (communes), bourrage, domaine */
    size_t nb = aadlen / RB + 1;
    for (size_t b = 0; b < nb; b++) {
        for (size_t j = 0; j < nm; j++)
            for (size_t k = 0; k < RB; k++) {
                size_t i = b * RB + k;
                st[j][k] ^= i < aadlen ? aad[i] : (i == aadlen ? 0x01 : 0);
            }
        if (b + 1 == nb)
            for (size_t j = 0; j < nm; j++)
                st[j][127] ^= DOM_AAD << 4;
        lot(st, R1);
    }
    size_t i = 0;
    for (; i + RB <= len; i += RB) {
        for (size_t j = 0; j < nm; j++) {
            const uint8_t *src = in + (d + j) * len + i;
            uint8_t *dst = out + (d + j) * len + i;
            for (size_t k = 0; k < RB; k++) {
                dst[k] = src[k] ^ st[j][k];
                st[j][k] = dst[k];   /* le chiffré */
            }
        }
        lot(st, R1);
    }
    size_t r = len - i;
    for (size_t j = 0; j < nm; j++) {
        const uint8_t *src = in + (d + j) * len + i;
        uint8_t *dst = out + (d + j) * len + i;
        for (size_t k = 0; k < r; k++) {
            dst[k] = src[k] ^ st[j][k];
            st[j][k] = dst[k];
        }
        st[j][r] ^= 0x01;
        st[j][127] ^= DOM_TEXTE << 4;
    }
    lot(st, R1);
    for (size_t j = 0; j < nm; j++) {
        for (int k = 0; k < 8; k++)
            st[j][k] ^= (uint8_t)((uint64_t)len >> (8 * k));
        st[j][8] ^= 0x01;
        st[j][127] ^= DOM_FINAL << 4;
    }
    lot(st, R1);
    for (size_t j = 0; j < nm; j++)
        memcpy(tags + 32 * (d + j), st[j], 32);
    free(st);
}

/* XOR d'un octet constant (commun aux 256 états) à l'octet k de l'état en plans de bits */
static void bs_xor_octet(__m256i (*P)[4], int k, uint8_t val)
{
    const __m256i un = _mm256_set1_epi32(-1);
    for (int q = 0; q < 8; q++)
        if (val >> q & 1)
            P[2 * k + (q >> 2)][q & 3] = _mm256_xor_si256(P[2 * k + (q >> 2)][q & 3], un);
}

/* 256 messages de même longueur (chiffrement), état en plans de bits gardé d'un bloc à l'autre ; mêmes sorties que aead().
 * AAD (communes) et longueur : constantes, sans transposition ; texte : flux extrait (80 octets), débit écrasé par le clair. */
static void aead_lot256(const uint8_t *cles, const uint8_t *nonces, const uint8_t *aad, size_t aadlen, const uint8_t *in,
                        size_t len, uint8_t *out, uint8_t *tags)
{
    __m256i (*P)[4] = BS_P;
    uint8_t (*tmp)[128] = allouer(256 * 128), (*ks)[RB] = (uint8_t (*)[RB])tmp;
    if (!tmp) {   /* repli : un message à la fois */
        for (size_t j = 0; j < 256; j++)
            aead(perm1, cles + 64 * j, nonces + 24 * j, aad, aadlen, in + j * len, len, 0, out + j * len, tags + 32 * j);
        return;
    }
    for (int j = 0; j < 256; j++)
        etat_aead(tmp[j], cles + 64 * j, nonces + 24 * j);
    memset(P, 0, sizeof BS_P);
    bs_absorber(P, tmp[0], 128, 8);
    bs_perm(P, R1);
    size_t nb = aadlen / RB + 1;
    for (size_t b = 0; b < nb; b++) {
        for (size_t k = 0; k < RB; k++) {
            size_t i = b * RB + k;
            bs_xor_octet(P, (int)k, i < aadlen ? aad[i] : (i == aadlen ? 0x01 : 0));
        }
        if (b + 1 == nb)
            bs_xor_octet(P, 127, DOM_AAD << 4);
        bs_perm(P, R1);
    }
    size_t i = 0;
    for (;; i += RB) {
        const int fin = i + RB > len;
        const size_t r = fin ? len - i : RB;
        bs_extraire((const __m256i (*)[4])P, ks[0], RB, RB / 16);   /* flux : débit des 256 états */
        for (size_t j = 0; j < 256; j++) {
            const uint8_t *src = in + j * len + i;
            uint8_t *dst = out + j * len + i;
            for (size_t k = 0; k < r; k++) {
                dst[k] = src[k] ^ ks[j][k];
                ks[j][k] = dst[k];                                   /* le débit reçoit le chiffré ; au-delà de r, inchangé */
            }
        }
        memset(P, 0, sizeof(__m256i) * 4 * 2 * RB);                 /* débit : nibbles 0 .. 2·RB − 1 */
        bs_absorber(P, ks[0], RB, RB / 16);
        if (fin) {
            bs_xor_octet(P, (int)r, 0x01);
            bs_xor_octet(P, 127, DOM_TEXTE << 4);
        }
        bs_perm(P, R1);
        if (fin)
            break;
    }
    for (int k = 0; k < 8; k++)
        bs_xor_octet(P, k, (uint8_t)((uint64_t)len >> (8 * k)));
    bs_xor_octet(P, 8, 0x01);
    bs_xor_octet(P, 127, DOM_FINAL << 4);
    bs_perm(P, R1);
    bs_extraire((const __m256i (*)[4])P, tags, 32, 2);
    free(tmp);
}

/* n messages de même longueur, mêmes sorties que aead() message par message (contrôlé) ; rend −1 sans rien toucher si une
 * longueur est hors limite. cles : 64·n octets, nonces : 24·n,
 * entrées et sorties : len·n, tags : 32·n. Une région parallèle, tâches dynamiques, les plus grosses d'abord : lots
 * bitslicés de 256 messages s'il y en a au moins 128 par thread, puis lots de 32 s'il en reste au moins 32 par thread,
 * sinon un message par tâche (même règle que l'arbre). */
static int aead_multi(size_t n, const uint8_t *cles, const uint8_t *nonces, const uint8_t *aad, size_t aadlen,
                      const uint8_t *in, size_t len, uint8_t *out, uint8_t *tags)
{
    if (!longueurs_admises(aadlen, len) || (len && n > AEAD_LONGUEUR_MAX / len) || n > SIZE_MAX / 64)
        return -1;                         /* aussi n·len (tampons in, out) et 64·n (clés) sans débordement */
    const size_t nt = (size_t)omp_get_max_threads();
    const size_t n256 = n >= 128 * nt ? n / 256 : 0, f0 = 256 * n256, reste = n - f0;
    const int par32 = reste >= 32 * nt;
    const size_t npetites = par32 ? (reste + 31) / 32 : reste;
#pragma omp parallel for schedule(dynamic)
    for (long t = 0; t < (long)(n256 + npetites); t++) {
        if ((size_t)t < n256) {
            const size_t d = 256 * (size_t)t;
            aead_lot256(cles + 64 * d, nonces + 24 * d, aad, aadlen, in + d * len, len, out + d * len, tags + 32 * d);
        } else if (par32) {
            const size_t d = f0 + 32 * ((size_t)t - n256), nm = n - d < 32 ? n - d : 32;
            aead_lot32(d, nm, cles, nonces, aad, aadlen, in, len, out, tags);
        } else {
            const size_t j = f0 + (size_t)t - n256;
            aead(perm1, cles + 64 * j, nonces + 24 * j, aad, aadlen, in + j * len, len, 0, out + j * len, tags + 32 * j);
        }
    }
    return 0;
}

/* ------------------------------------------------------------ contrôles et mesures */
static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static void hexa(const uint8_t *x, int n, char *s)
{
    for (int i = 0; i < n; i++)
        sprintf(s + 2 * i, "%02x", x[i]);
}

static double mediane(double *t, int n)
{
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (t[j] < t[i]) { double u = t[i]; t[i] = t[j]; t[j] = u; }
    return t[n / 2];
}

/* ------------------------------------------------------------ KAT figés (profil R = 32) */
/* Message de test : octet i = i mod 251 ; clé : octet i = i ; nonce : octet i = 0x80 + i ; AAD : 9 octets du message
 * à partir de l'octet 1000. Chaque KAT est calculé deux fois, par le noyau AVX2 et par la référence dense (éponge et arbre
 * réécrits à part sur l'état emballé), et comparé aux valeurs figées de kat_b1024.h. AEAD : tag ‖ SHAKE256(chiffré)[0..31]. */
#define NKAT 18
typedef struct { char nom[24]; char hex[401]; } kat_t;

/* arbre de référence : même cadrage que arbre(), réécrit séquentiellement sur eponge_ref (contrôle indépendant du cadrage) */
static void arbre_ref(const uint8_t *m, size_t len, uint8_t *out, size_t outlen)
{
    if (len <= FEUILLE) {
        eponge_ref(m, len, DOM_SEUL, out, outlen);
        return;
    }
    size_t k = (len + FEUILLE - 1) / FEUILLE, lr = (size_t)CVL * k + 12;
    uint8_t *r = malloc(lr), *q = r + (size_t)CVL * k;
    for (size_t i = 0; i < k; i++) {
        size_t l = len - i * FEUILLE < FEUILLE ? len - i * FEUILLE : FEUILLE;
        eponge_ref(m + i * FEUILLE, l, DOM_FEUILLE, r + i * CVL, CVL);
    }
    for (int i = 0; i < 8; i++)
        q[i] = (uint8_t)((uint64_t)k >> (56 - 8 * i));   /* nombre de feuilles, gros-boutiste */
    q[8] = 0; q[9] = 0; q[10] = FEUILLE >> 8; q[11] = FEUILLE & 0xFF;
    eponge_ref(r, lr, DOM_RACINE, out, outlen);
    free(r);
}

/* ref = 0 : noyau AVX2 ; ref = 1 : référence dense. Les entrées de 100 et 300 feuilles ne sont calculées que par le noyau
 * (la référence dense y prendrait plusieurs minutes) : hex vide côté référence. Rend le nombre de KAT. */
static int calculer_kats(int ref, kat_t *k)
{
    const size_t TM = 300 * 8192 + 5;
    uint8_t *m = malloc(TM), out[200], cle[64], nonce[24], c[1000], tag[32];
    for (size_t i = 0; i < TM; i++)
        m[i] = (uint8_t)(i % 251);
    for (int i = 0; i < 64; i++)
        cle[i] = (uint8_t)i;
    for (int i = 0; i < 24; i++)
        nonce[i] = (uint8_t)(0x80 + i);
    int n = 0;
    const size_t LH[] = {0, 1, 79, 80, 81, 8192, 8193, 3 * 8192 + 5, 100 * 8192 + 77, 300 * 8192 + 5};
    for (size_t t = 0; t < sizeof LH / sizeof *LH; t++, n++) {
        snprintf(k[n].nom, sizeof k[n].nom, "hachage_%zu", LH[t]);
        k[n].hex[0] = 0;
        if (ref && LH[t] > 4 * FEUILLE)
            continue;
        if (ref)
            arbre_ref(m, LH[t], out, 64);
        else
            arbre(m, LH[t], out, 64, 1);
        hexa(out, 64, k[n].hex);
    }
    snprintf(k[n].nom, sizeof k[n].nom, "hachage_abc");
    if (ref)
        arbre_ref((const uint8_t *)"abc", 3, out, 64);
    else
        arbre((const uint8_t *)"abc", 3, out, 64, 1);
    hexa(out, 64, k[n++].hex);
    const size_t LX[] = {0, 200};
    for (size_t t = 0; t < 2; t++, n++) {
        snprintf(k[n].nom, sizeof k[n].nom, "xof_%zu", LX[t]);
        (ref ? eponge_ref : eponge)(m, LX[t], DOM_SEQ, out, 200);
        hexa(out, 200, k[n].hex);
    }
    const size_t LA[] = {0, 16, 64, 1000, 64};
    for (size_t t = 0; t < 5; t++, n++) {
        size_t aadlen = t < 4 ? 9 : 0;   /* dernier : sans données associées */
        snprintf(k[n].nom, sizeof k[n].nom, "aead_%zu%s", LA[t], aadlen ? "" : "_sans_aad");
        aead(ref ? perm_ref : perm1, cle, nonce, m + 1000, aadlen, m, LA[t], 0, c, tag);
        memcpy(out, tag, 32);
        sl_shake256(c, LA[t], out + 32, 32);
        hexa(out, 64, k[n].hex);
    }
    free(m);
    return n;
}

#if __has_include("kat_b1024.h")
#include "kat_b1024.h"
#define KAT_PRESENTS 1
#else
#define KAT_PRESENTS 0
#endif

/* « brume1024 kat » : écrit kat_b1024.h sur la sortie standard, si le noyau et la référence concordent */
static int generer_kats(void)
{
    static kat_t kn[NKAT], kr[NKAT];
    if (calculer_kats(0, kn) != NKAT || calculer_kats(1, kr) != NKAT)
        return 2;
    for (int i = 0; i < NKAT; i++)
        if (kr[i].hex[0] && strcmp(kn[i].hex, kr[i].hex)) {
            fprintf(stderr, "désaccord noyau / référence : %s\n", kn[i].nom);
            return 1;
        }
    printf("/* KAT figés de BRUME-1024q, profil R = %d, généré par « brume1024 kat » (noyau AVX2 et référence dense concordants).\n"
           " * Ne pas régénérer pour faire passer un contrôle : une différence signale un changement de la fonction. Message,\n"
           " * clé, nonce et AAD : voir calculer_kats() dans brume1024.c.\n"
           " * Historique : 13 novembre 2026, orientation SpongeWrap de l'AEAD (AEAD_SECURITY.md § 6) : les 4 KAT de l'AEAD avec\n"
           " * texte ont changé, volontairement ; les 14 autres sont restés identiques. */\n", R1);
    printf("static const char *const KAT_FIGES[%d][2] = {\n", NKAT);
    for (int i = 0; i < NKAT; i++)
        printf("    {\"%s\",\n     \"%s\"},\n", kn[i].nom, kn[i].hex);
    printf("};\n");
    return 0;
}

/* ------------------------------------------------------------ séparation des domaines (DOMAINS.md), contrôles structurels */
static int controle_domaines(void)
{
    int ok = 1;
    /* 1. modes (nibble bas de l'octet 127) et domaines (nibble haut) : valeurs < 16, distinctes dans chaque construction ;
     *    dans l'AEAD, les domaines de fin de phase sont non nuls (les autres blocs portent 0) */
    const int de[] = {DOM_SEQ, DOM_FEUILLE, DOM_RACINE, DOM_SEUL}, da[] = {0, DOM_AAD, DOM_TEXTE, DOM_FINAL};
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            ok &= de[i] >= 0 && de[i] < 16 && da[i] >= 0 && da[i] < 16;
            if (i != j)
                ok &= de[i] != de[j] && da[i] != da[j];
        }
    ok &= MODE_EPONGE != MODE_AEAD && MODE_EPONGE < 16 && MODE_AEAD < 16;
    /* 2. états avant la première permutation : éponge = 0^121 ‖ cadre(5), AEAD = clé ‖ nonce ‖ 0^33 ‖ cadre(3). On contrôle
     *    que etat_aead() n'écrit la clé que dans 0..63, le nonce que dans 64..87, et que 88..127 ne dépendent pas d'eux :
     *    les deux états diffèrent alors à l'octet 127 pour toute clé et tout nonce. Clés et nonces extrêmes et aléatoires. */
    uint8_t e[128], fa[128], w[128], tc[64 + 8], tn[24 + 8], *cle = tc, *nonce = tn;   /* 8 octets de garde non nuls */
    memset(tc + 64, 0xC3, 8);
    memset(tn + 24, 0x3C, 8);
    memset(e, 0, 128);
    cadre_iv(e, MODE_EPONGE);
    memset(fa, 0, 128);
    cadre_iv(fa, MODE_AEAD);
    for (int essai = 0; essai < 6; essai++) {
        if (essai < 4) {
            memset(cle, essai == 1 ? 0xFF : essai == 3 ? MODE_EPONGE : 0, 64);
            memset(nonce, essai == 1 ? 0xFF : essai == 3 ? MODE_EPONGE : 0, 24);
            if (essai == 2) {          /* clé et nonce recopiés de l'état initial de l'éponge */
                memcpy(cle, e, 64);
                memcpy(nonce, e + 64, 24);
            }
        } else {
            sl_alea(cle, 64);
            sl_alea(nonce, 24);
        }
        memset(w, 0xA5, 128);
        etat_aead(w, cle, nonce);
        ok &= !memcmp(w, cle, 64) && !memcmp(w + 64, nonce, 24) && !memcmp(w + 88, fa + 88, 40);
        ok &= w[127] != e[127] && memcmp(w, e, 128) != 0;
    }
    /* 3. P(IV) en cache identique au calcul direct */
    memcpy(w, e, 128);
    perm1(w, R1);
    uint8_t c[128];
    etat_iv(c, MODE_EPONGE);
    ok &= !memcmp(w, c, 128);
    /* 4. même message, domaines différents : sorties toutes distinctes (4 domaines × 3 longueurs autour du débit) */
    uint8_t m[81], h[12][32];
    for (int i = 0; i < 81; i++)
        m[i] = (uint8_t)i;
    const size_t L[] = {0, 79, 80};
    for (int d = 0; d < 4; d++)
        for (int l = 0; l < 3; l++)
            eponge(m, L[l], de[d], h[3 * d + l], 32);
    for (int i = 0; i < 12; i++)
        for (int j = i + 1; j < 12; j++)
            ok &= memcmp(h[i], h[j], 32) != 0;
    return ok;
}

#ifndef SANS_MAIN
int main(int argc, char **argv)
{
    int kat = argc > 1 && !strcmp(argv[1], "kat");   /* brume1024 kat > kat_b1024.h : fige les KAT du profil R = 32 */
    if (argc > 1 && !kat)
        R1 = atoi(argv[1]);
    if (R1 < 1 || R1 > B1_RT || !bref_init() || !ref_init() || !init_noyaux())
        return 2;
    prepare_iv();
    sl_init();
    if (kat)
        return generer_kats();
    resultat_t res = {.nom = "brume1024", .titre = "BRUME-1024q (prototype) : permutation de 1 024 bits, eponge c = 384"};
    uint64_t g = 0x1024;
    size_t TAILLE = (size_t)64 << 20;
    uint8_t *m = malloc(TAILLE);
    for (size_t i = 0; i < TAILLE; i++) {
        g = g * 6364136223846793005ULL + 1442695040888963407ULL;
        m[i] = (uint8_t)(g >> 56);
    }
    /* 1. noyau 1 état ≡ référence dense ; inverse dense */
    int ok1 = 1, okinv = 1;
    for (int e = 0; e < 64; e++) {
        uint8_t w[128], x[N1], y[N1];
        memcpy(w, m + 128 * e, 128);
        deballer_ref(w, x);
        memcpy(y, x, N1);
        for (int r = 0; r < R1; r++)
            ref_tour(x, r);
        perm1(w, R1);
        uint8_t z[128];
        emballer_ref(x, z);
        ok1 &= !memcmp(z, w, 128);
        for (int r = R1 - 1; r >= 0; r--)
            ref_tour_inv(x, r);
        okinv &= !memcmp(x, y, N1);
    }
    res_controle(&res, "noyau_1_etat_identique_a_la_reference_dense", ok1);
    res_controle(&res, "tours_inverses_denses_inversent_la_permutation", okinv);
    /* 2. noyau 32 états ≡ 1 état */
    int ok32 = 1;
    {
        uint8_t (*e)[128] = aligned_alloc(64, 32 * 128), w[128];
        memcpy(e, m + 4096, 32 * 128);
        lot(e, R1);
        for (int i = 0; i < 32; i++) {
            memcpy(w, m + 4096 + 128 * i, 128);
            perm1(w, R1);
            ok32 &= !memcmp(w, e[i], 128);
        }
        free(e);
    }
    res_controle(&res, "noyau_32_etats_identique_au_noyau_1_etat", ok32);
    /* 2 bis. noyau bitslicé (256 états) ≡ 1 état, transpositions comprises */
    int okbs = 1;
    {
        uint8_t (*e)[128] = aligned_alloc(64, 256 * 128), (*f)[128] = aligned_alloc(64, 256 * 128);
        memcpy(e, m + 8192, 256 * 128);
        memset(BS_P, 0, sizeof BS_P);
        bs_absorber(BS_P, e[0], 128, 8);
        bs_perm(BS_P, R1);
        bs_extraire((const __m256i (*)[4])BS_P, f[0], 128, 8);
        for (int i = 0; i < 256; i++) {
            uint8_t w[128];
            memcpy(w, e[i], 128);
            perm1(w, R1);
            okbs &= !memcmp(w, f[i], 128);
        }
        free(e);
        free(f);
    }
    res_controle(&res, "noyau_bitslice_256_etats_identique_au_noyau_1_etat", okbs);
    /* 3. éponge (état déballé) ≡ éponge de référence, longueurs limites */
    const size_t LONG[] = {0, 1, 79, 80, 81, 159, 160, 161, 1000, 8191, 8192, 8193, 20000};
    int okep = 1;
    for (size_t t = 0; t < sizeof LONG / sizeof *LONG; t++) {
        uint8_t a[200], b[200];
        eponge(m, LONG[t], DOM_SEQ, a, 200);
        eponge_ref(m, LONG[t], DOM_SEQ, b, 200);
        okep &= !memcmp(a, b, 200);
    }
    res_controle(&res, "eponge_etat_deballe_identique_a_l_eponge_de_reference", okep);
    /* 4. arbre : lot ≡ séquentiel */
    int okarbre = 1;
    omp_set_num_threads(1);   /* sur 1 thread, le chemin par lots sert dès 32 feuilles : il est donc bien contrôlé */
    const size_t LA[] = {8193, 16384, 16385, 32 * 8192, 33 * 8192 + 5, 100 * 8192 + 77, 256 * 8192 + 1, 300 * 8192 + 5, 600 * 8192};
    for (size_t t = 0; t < sizeof LA / sizeof *LA; t++) {
        uint8_t a[64], b[64];
        arbre(m, LA[t], a, 64, 1);
        arbre(m, LA[t], b, 64, 0);
        okarbre &= !memcmp(a, b, 64);
    }
    omp_set_num_threads(omp_get_num_procs());
    {   /* et sur tous les threads (chemin par feuille en dessous de 32 feuilles par thread) */
        uint8_t a[64], b[64];
        arbre(m, 100 * 8192 + 77, a, 64, 1);
        omp_set_num_threads(1);
        arbre(m, 100 * 8192 + 77, b, 64, 1);
        omp_set_num_threads(omp_get_num_procs());
        okarbre &= !memcmp(a, b, 64);
    }
    res_controle(&res, "arbre_noyau_32_etats_identique_aux_feuilles_sequentielles", okarbre);
    /* trous comblés (score de mutation du 13 novembre) : seuils de l'ordonnanceur de l'arbre, valeur de retour, nombre de
     * tours par défaut, changement du nombre de tours en cours de route */
    {
        int okb = 1;
        uint8_t a[64], b[64];
        omp_set_num_threads(1);   /* nombres de feuilles pleines autour de 128, 256, 512 (seuils et découpage des lots) */
        const size_t NF[] = {127, 128, 129, 255, 256, 257, 261, 288, 511, 512, 513, 544};
        for (size_t t = 0; t < sizeof NF / sizeof *NF; t++) {
            size_t L = NF[t] * 8192 + 7;
            memset(a, 0xA5, 64);
            okb &= arbre(m, L, a, 64, 1) == 0;
            arbre(m, L, b, 64, 0);
            okb &= !memcmp(a, b, 64);
        }
        const size_t nt = (size_t)omp_get_num_procs();   /* tous les threads : autour de 128 et 32 feuilles par thread */
        omp_set_num_threads((int)nt);
        const size_t NT2[] = {128 * nt - 1, 128 * nt, 128 * nt + 1, 256 * ((128 * nt + 255) / 256) + 5, 32 * nt - 1, 32 * nt};
        for (size_t t = 0; t < sizeof NT2 / sizeof *NT2; t++) {
            size_t L = NT2[t] * 8192 + 7;
            if (L > TAILLE)
                continue;
            arbre(m, L, a, 64, 1);
            arbre(m, L, b, 64, 0);
            okb &= !memcmp(a, b, 64);
        }
        okb &= arbre(m, 100, a, 64, 1) == 0 && arbre(m, 8192, b, 64, 1) == 0;   /* valeur de retour, message seul */
        res_controle(&res, "arbre_seuils_de_l_ordonnanceur_et_valeur_de_retour", okb);
        res_controle(&res, "profil_par_defaut_32_tours", argc > 1 || R1 == 32);
        /* nombre de tours changé en cours de route : le cache de P(IV) et ses plans de bits doivent suivre */
        int okr = 1;
        uint8_t h32[64], hA[64], hB[64];
        const int R0 = R1;
        eponge(m, 500, DOM_SEQ, h32, 64);
        R1 = R0 - 1;
        eponge(m, 500, DOM_SEQ, hA, 64);
        eponge_ref(m, 500, DOM_SEQ, hB, 64);
        okr &= !memcmp(hA, hB, 64) && memcmp(hA, h32, 64) != 0;
        omp_set_num_threads(1);
        arbre(m, 300 * 8192 + 5, hA, 64, 1);   /* lots bitslicés : BS_IV doit être celui de R0 − 1 tours */
        arbre(m, 300 * 8192 + 5, hB, 64, 0);
        okr &= !memcmp(hA, hB, 64);
        R1 = R0;
        eponge(m, 500, DOM_SEQ, hA, 64);
        okr &= !memcmp(hA, h32, 64);
        arbre(m, 300 * 8192 + 5, hA, 64, 1);
        arbre(m, 300 * 8192 + 5, hB, 64, 0);
        okr &= !memcmp(hA, hB, 64);
        omp_set_num_threads((int)nt);
        res_controle(&res, "changement_du_nombre_de_tours_cache_et_plans_de_bits_suivent", okr);
    }
    /* 4 bis. AEAD : noyau AVX2 ≡ référence dense ; déchiffrement ; altérations rejetées */
    {
        int oka = 1;
        const size_t LT[] = {0, 1, 79, 80, 81, 1000};
        for (size_t t = 0; t < sizeof LT / sizeof *LT; t++) {
            uint8_t c1[1000], c2[1000], d[1000], t1[32], t2[32], t3[32];
            aead(perm1, m, m + 64, m + 100, 9 + t, m + 300, LT[t], 0, c1, t1);
            aead(perm_ref, m, m + 64, m + 100, 9 + t, m + 300, LT[t], 0, c2, t2);
            oka &= !memcmp(c1, c2, LT[t]) && !memcmp(t1, t2, 32);
            aead(perm1, m, m + 64, m + 100, 9 + t, c1, LT[t], 1, d, t3);
            oka &= !memcmp(d, m + 300, LT[t]) && !memcmp(t1, t3, 32);
            if (LT[t]) {
                c1[LT[t] / 2] ^= 1;
                aead(perm1, m, m + 64, m + 100, 9 + t, c1, LT[t], 1, d, t3);
                oka &= memcmp(t1, t3, 32) != 0;
            }
            uint8_t n2[24];
            memcpy(n2, m + 64, 24);
            n2[23] ^= 0x80;
            aead(perm1, m, n2, m + 100, 9 + t, m + 300, LT[t], 0, c2, t3);
            oka &= memcmp(t1, t3, 32) != 0;
        }
        res_controle(&res, "aead_noyau_identique_a_la_reference_dechiffre_et_rejette_les_alterations", oka);
        /* frontières : AAD × texte autour du débit (80) et de deux blocs (160), noyau ≡ référence dense */
        const size_t FR[] = {0, 1, 79, 80, 81, 159, 160, 161};
        int okf = 1;
        for (size_t i = 0; i < 8; i++)
            for (size_t j = 0; j < 8; j++) {
                uint8_t c1[161], c2[161], t1[32], t2[32];
                aead(perm1, m, m + 64, m + 500, FR[i], m + 1000, FR[j], 0, c1, t1);
                aead(perm_ref, m, m + 64, m + 500, FR[i], m + 1000, FR[j], 0, c2, t2);
                okf &= !memcmp(c1, c2, FR[j]) && !memcmp(t1, t2, 32);
            }
        res_controle(&res, "aead_frontieres_aad_et_texte_croisees_identiques_a_la_reference", okf);
        /* référence DMV17 littérale : chiffrement et déchiffrement, 64 combinaisons AAD × texte (noyau AVX2), et 16 avec la
         * permutation dense (référence entièrement indépendante du noyau et du code du mode) */
        int okk = 1;
        for (size_t i = 0; i < 8; i++)
            for (size_t j = 0; j < 8; j++)
                for (int dech = 0; dech < 2; dech++) {
                    uint8_t c1[161], c2[161], t1[32], t2[32];
                    perm_f P = (i % 2 == 0 && j % 2 == 0 && !dech) ? perm_ref : perm1;
                    aead(perm1, m + 3, m + 70, m + 500, FR[i], m + 1000, FR[j], dech, c1, t1);
                    aead_kd(P, m + 3, m + 70, m + 500, FR[i], m + 1000, FR[j], dech, c2, t2);
                    okk &= !memcmp(c1, c2, FR[j]) && !memcmp(t1, t2, 32);
                }
        res_controle(&res, "aead_identique_a_la_reference_dmv17_litterale_chiffrement_et_dechiffrement", okk);
        /* étape AE (AEAD_SECURITY.md § 4 bis) : (1) le chemin IXIF du déchiffrement de (A, C) est celui du chiffrement de
         * (A, M), drapeau partiel du dernier bloc compris ; (2) le chemin final se décode en (A, M) (codage injectif) ;
         * (3) rôles : le flux de clé de chaque bloc de texte est lu après une entrée de nibble DOM_AAD ou 0, le tag après
         * l'entrée DOM_FINAL ; l'appel du tag injecte σ = 0 ; nombre d'appels = ⌈(|A|+1)/80⌉ + ⌊|M|/80⌋ + 3. */
        int okch = 1;
        for (size_t i = 0; i < 8; i++)
            for (size_t j = 0; j < 8; j++) {
                const size_t A = FR[i], L = FR[j];
                uint8_t ce[16][128], cd[16][128], c[161], p[161], t1[32], t2[32], dA[200], dM[200];
                size_t ne = 0, nd = 0, la = 9999, lm = 9999;
                aead_kd_chemin(perm1, m + 3, m + 70, m + 500, A, m + 1000, L, 0, c, t1, ce, 16, &ne);
                aead_kd_chemin(perm1, m + 3, m + 70, m + 500, A, c, L, 1, p, t2, cd, 16, &nd);
                const size_t na = A / RB + 1, nm = L / RB + 1;
                okch &= ne == na + nm + 2 && nd == ne && !memcmp(ce, cd, ne * 128) && !memcmp(t1, t2, 32) &&
                        !memcmp(p, m + 1000, L);
                okch &= decoder_chemin((const uint8_t(*)[128])ce, ne - 1, dA, &la, dM, &lm, 200) == 0 && la == A &&
                        lm == L && !memcmp(dA, m + 500, A) && !memcmp(dM, m + 1000, L);
                int zero = 1;
                for (int k = 0; k < 128; k++)
                    zero &= ce[ne - 1][k] == 0;
                okch &= zero && (ce[na - 1][127] >> 4) == DOM_AAD && (ce[ne - 2][127] >> 4) == DOM_FINAL;
                for (size_t t = 0; t < nm; t++)            /* entrée lue avant le bloc de texte t */
                    okch &= (ce[na + t - 1][127] >> 4) == (t == 0 ? DOM_AAD : 0);
                /* témoins : une entrée altérée (domaine, bourrage, capacité, longueur) ne se décode pas en (A, M) */
                const int pos[4][2] = {{(int)(na - 1), 127}, {(int)(na + nm - 1), (int)(L % RB)}, {0, 100},
                                       {(int)(ne - 2), 0}};
                for (int w = 0; w < 4; w++) {
                    uint8_t cw[16][128];
                    memcpy(cw, ce, sizeof cw);
                    cw[pos[w][0]][pos[w][1]] ^= w == 0 ? 0x30 : 0x01;
                    size_t la2 = 0, lm2 = 0;
                    const int r = decoder_chemin((const uint8_t(*)[128])cw, ne - 1, dA, &la2, dM, &lm2, 200);
                    okch &= r == -1 || la2 != A || lm2 != L || memcmp(dA, m + 500, A) || memcmp(dM, m + 1000, L);
                }
            }
        res_controle(&res, "etape_ae_chemin_du_dechiffrement_egal_au_chiffrement_decodable_et_roles", okch);
        /* décodeur du chemin final, branche par branche (trous de la 3e passe de mutation, 14 novembre) : chaque forme
         * invalide rend EXACTEMENT −1 ; tampons de taille exacte ; longueurs ≥ 256 et ≥ 65 536 (octets 1 et 2 du bloc de
         * longueur) ; capacité exacte acceptée, capacité − 1 refusée ; l'enregistrement du chemin s'arrête à nch (garde) */
        int okd = 1, ndec = 0;
        {
            const size_t DA[] = {0, 81}, DL[] = {0, 79, 80, 300, 70000};
            for (size_t ia = 0; ia < 2; ia++)
                for (size_t il = 0; il < 5; il++) {
                    const size_t A = DA[ia], L = DL[il], na = A / RB + 1, nm = L / RB + 1, ne = na + nm + 2, n0 = ne - 1;
                    const size_t cap = A > L ? A : L;
                    const uint8_t *vA = m + 500, *vM = m + 1000;
                    uint8_t(*ce)[128] = malloc((ne + 1) * 128), (*x)[128] = malloc((ne + 1) * 128), *c = malloc(L + 1),
                        t[32];
                    size_t nr = 0;
                    memset(ce, 0xA5, (ne + 1) * 128);
                    aead_kd_chemin(perm1, m + 3, m + 70, vA, A, vM, L, 0, c, t, ce, ne, &nr);
                    for (int k = 0; k < 128; k++)          /* garde : rien d'écrit après nch entrées */
                        okd &= ce[ne][k] == 0xA5;
                    okd &= nr == ne;
                    memset(x, 0xA5, (ne + 1) * 128);       /* nch plus petit que le nombre d'appels : 2 entrées seulement */
                    aead_kd_chemin(perm1, m + 3, m + 70, vA, A, vM, L, 0, c, t, x, 2, &nr);
                    okd &= nr == ne && !memcmp(x, ce, 2 * 128);
                    for (size_t e = 2; e <= ne; e++)        /* rien d'écrit au-delà de nch */
                        for (int k = 0; k < 128; k++)
                            okd &= x[e][k] == 0xA5;
                    okd &= dec_essai((const uint8_t(*)[128])ce, n0, cap, vA, A, vM, L) == 0;
                    int nok = 0, ntot = 0;
#define DEC_REJET(nlig)                                                                                                \
    do {                                                                                                               \
        nok += dec_essai((const uint8_t(*)[128])x, (nlig), cap, vA, A, vM, L) == -1;                                   \
        ntot++;                                                                                                        \
        memcpy(x, ce, (ne + 1) * 128);                                                                                 \
    } while (0)
                    memcpy(x, ce, (ne + 1) * 128);
                    if (cap) {                                  /* capacité − 1 */
                        nok += dec_essai((const uint8_t(*)[128])ce, n0, cap - 1, vA, A, vM, L) == -1;
                        ntot++;
                    }
                    DEC_REJET(n0 - 1);                          /* bloc de longueur absent */
                    DEC_REJET(n0 - 2);
                    memcpy(x[n0], ce[n0 - 1], 128);             /* une entrée de trop */
                    DEC_REJET(n0 + 1);
                    for (size_t e = 0; e < n0; e++) {
                        const int KC[] = {RB, 100, 126, 9};
                        for (int i = 0; i < 4; i++) {           /* capacité non nulle (et octet 9 du bloc de longueur) */
                            if (KC[i] == 9 && e != n0 - 1)
                                continue;
                            x[e][KC[i]] ^= 0x01;
                            DEC_REJET(n0);
                        }
                        x[e][127] ^= 0x01;                      /* nibble bas de l'octet 127 */
                        DEC_REJET(n0);
                    }
                    x[na - 1][127] = DOM_TEXTE << 4;            /* domaine du texte dans la phase AAD */
                    DEC_REJET(n0);
                    x[na + nm - 1][127] = DOM_AAD << 4;         /* domaine AAD dans la phase texte */
                    DEC_REJET(n0);
                    x[n0 - 1][127] = DOM_TEXTE << 4;            /* bloc de longueur sans DOM_FINAL */
                    DEC_REJET(n0);
                    if (na > 1) {                               /* bloc plein de A marqué DOM_FINAL */
                        x[0][127] = DOM_FINAL << 4;
                        DEC_REJET(n0);
                    }
                    x[na - 1][A % RB] = 0x02;                   /* bourrage 0x01 remplacé */
                    DEC_REJET(n0);
                    x[na + nm - 1][L % RB] = 0x02;
                    DEC_REJET(n0);
                    x[n0 - 1][8] ^= 0x01;                       /* bloc de longueur : 0x01 de l'octet 8, longueur */
                    DEC_REJET(n0);
                    for (int k = 0; k < 3; k++) {
                        x[n0 - 1][k] ^= 0x01;
                        DEC_REJET(n0);
                    }
#undef DEC_REJET
                    okd &= nok == ntot;
                    ndec += ntot;
                    free(ce);
                    free(x);
                    free(c);
                }
        }
        res_mesure(&res, "decodeur_formes_invalides_essayees", "%d", ndec);
        res_controle(&res, "decodeur_chemin_rejette_exactement_chaque_forme_invalide_et_garde_nch", okd && ndec > 0);
        /* réutilisation de nonce, fuite exacte (AEAD_SECURITY.md § 4 (e)) : même clé et même nonce, (A, M) et (A', M').
         * Le flux du bloc de texte t ne dépend que du chemin qui le précède : il est le même pour les deux messages SI ET
         * SEULEMENT SI les entrées σ̃ (A et blocs de texte bourrés) coïncident jusqu'au bloc t − 1. Donc c ⊕ c' = m ⊕ m' sur
         * tous les blocs jusqu'au premier bloc dont l'entrée diffère, celui-ci compris, puis plus rien. Tags : (A, M) = (A', M') ⇒ T = T'
         * (déterminisme) ; la réciproque n'est pas vraie en général (tag de 256 bits, collision ≈ 2^−256 par paire) : la
         * grille ci-dessous observe seulement que ses paires distinctes ont des tags distincts. Mesuré sur aead() (l'implémentation), prédit par les chemins de aead_kd_chemin(). */
        int oknr = 1, nprev = 0;
        {
            const size_t AL[] = {0, 79, 80}, LL[] = {0, 1, 79, 80, 81, 159, 160, 161, 200};
            uint8_t base[200], var[200];
            memcpy(base, m + 7000, 200);
            for (int cas = 0; cas < 4; cas++)
                for (size_t a = 0; a < 3; a++)
                    for (size_t a2 = 0; a2 < 3; a2++)
                        for (size_t l = 0; l < 9; l++)
                            for (size_t l2 = 0; l2 < 9; l2++) {
                                const size_t A = AL[a], A2 = AL[a2], L = LL[l], L2 = LL[l2];
                                memcpy(var, base, 200);           /* cas 0 : M' préfixe ou prolongement de M */
                                if (cas >= 1 && L2 > 0) {         /* cas 1, 2, 3 : un octet change (début, milieu, fin) */
                                    const size_t d = cas == 1 ? 0 : cas == 2 ? L2 / 2 : L2 - 1;
                                    var[d] ^= (uint8_t)(1 + m[8000 + d] % 255);
                                }
                                uint8_t c1[200], c2[200], t1[32], t2[32], e1[16][128], e2[16][128], z[200], tz[32];
                                size_t n1 = 0, n2 = 0;
                                aead(perm1, m, m + 64, m + 100, A, base, L, 0, c1, t1);
                                aead(perm1, m, m + 64, m + 100 + (A2 != A ? 300 : 0), A2, var, L2, 0, c2, t2);
                                aead_kd_chemin(perm1, m, m + 64, m + 100, A, base, L, 0, z, tz, e1, 16, &n1);
                                aead_kd_chemin(perm1, m, m + 64, m + 100 + (A2 != A ? 300 : 0), A2, var, L2, 0, z, tz,
                                               e2, 16, &n2);
                                const size_t na1 = A / RB + 1, na2 = A2 / RB + 1, nm1 = L / RB + 1, nm2 = L2 / RB + 1;
                                const int memes = A == A2 && L == L2 && !memcmp(base, var, L);
                                oknr &= memes == !memcmp(t1, t2, 32);
                                for (size_t t = 0; t < nm1 && t < nm2; t++) {
                                    /* prédiction : chemins égaux avant le bloc t (même nombre de blocs de A, entrées égales) */
                                    const int pred = na1 == na2 && !memcmp(e1, e2, (na1 + t) * 128);
                                    const size_t deb = t * RB, l1 = L - deb < RB ? L - deb : RB, l2 = L2 - deb < RB ? L2 - deb : RB;
                                    const size_t lc = l1 < l2 ? l1 : l2;
                                    int egal = 1;
                                    for (size_t k = 0; k < lc; k++)
                                        egal &= (c1[deb + k] ^ c2[deb + k]) == (base[deb + k] ^ var[deb + k]);
                                    if (pred)
                                        oknr &= egal, nprev++;
                                    else if (lc >= 8)              /* fausse égalité : probabilité ≤ 2^−64 */
                                        oknr &= !egal;
                                }
                            }
        }
        res_mesure(&res, "nonce_reutilise_blocs_de_flux_prevus_egaux", "%d", nprev);
        res_controle(&res, "nonce_reutilise_fuite_exacte_flux_egal_ssi_chemin_egal_aux_frontieres", oknr && nprev > 0);
        /* déchiffrement vérifié : aller-retour, puis 14 altérations rejetées, texte effacé à chaque rejet */
        int oko = 1, nalt = 0;
        const size_t AO[] = {0, 9, 80, 161}, LO[] = {0, 1, 79, 80, 81, 160, 1000};
        for (size_t a = 0; a < 4; a++)
            for (size_t t = 0; t < 7; t++) {
                const size_t A = AO[a], L = LO[t];
                uint8_t cle[64], nonce[24], aad[200], ct[1002], tag[32], pt[1002], k2[64], n2[24], a2[200], c2[1002], t2[32];
                memcpy(cle, m + 7, 64);
                memcpy(nonce, m + 90, 24);
                memcpy(aad, m + 300, A);
                aead(perm1, cle, nonce, aad, A, m + 2000, L, 0, ct, tag);
                oko &= aead_ouvrir(cle, nonce, aad, A, ct, L, tag, pt) == 0 && !memcmp(pt, m + 2000, L);
                /* chaque altération : rejet, et le tampon de sortie entièrement à zéro */
#define REJET(K, N, AA, AL, C, CL, T)                                                                                   \
    do {                                                                                                                 \
        memset(pt, 0xEE, sizeof pt);                                                                                     \
        int r_ = aead_ouvrir(K, N, AA, AL, C, CL, T, pt), z_ = 1;                                                        \
        for (size_t q_ = 0; q_ < (CL); q_++)                                                                             \
            z_ &= pt[q_] == 0;                                                                                           \
        oko &= r_ == -1 && z_;                                                                                           \
        nalt++;                                                                                                          \
    } while (0)
                memcpy(k2, cle, 64); k2[0] ^= 1; REJET(k2, nonce, aad, A, ct, L, tag);
                memcpy(k2, cle, 64); k2[63] ^= 0x80; REJET(k2, nonce, aad, A, ct, L, tag);
                memcpy(n2, nonce, 24); n2[0] ^= 1; REJET(cle, n2, aad, A, ct, L, tag);
                memcpy(n2, nonce, 24); n2[23] ^= 0x80; REJET(cle, n2, aad, A, ct, L, tag);
                memcpy(t2, tag, 32); t2[0] ^= 1; REJET(cle, nonce, aad, A, ct, L, t2);
                memcpy(t2, tag, 32); t2[31] ^= 0x80; REJET(cle, nonce, aad, A, ct, L, t2);
                if (A) {
                    memcpy(a2, aad, A); a2[0] ^= 1; REJET(cle, nonce, a2, A, ct, L, tag);
                    memcpy(a2, aad, A); a2[A - 1] ^= 0x80; REJET(cle, nonce, a2, A, ct, L, tag);
                    REJET(cle, nonce, aad, A - 1, ct, L, tag);                                  /* AAD tronquées */
                    memcpy(c2 + 1, ct, L); c2[0] = aad[A - 1];                                  /* frontière AAD | texte */
                    REJET(cle, nonce, aad, A - 1, c2, L + 1, tag);
                } else {
                    a2[0] = 0; REJET(cle, nonce, a2, 1, ct, L, tag);                            /* AAD vides ≠ un octet nul */
                }
                if (L) {
                    memcpy(c2, ct, L); c2[0] ^= 1; REJET(cle, nonce, aad, A, c2, L, tag);
                    memcpy(c2, ct, L); c2[L - 1] ^= 0x80; REJET(cle, nonce, aad, A, c2, L, tag);
                    REJET(cle, nonce, aad, A, ct, L - 1, tag);                                  /* chiffré tronqué */
                    memcpy(a2, aad, A); a2[A] = ct[0];                                          /* frontière déplacée */
                    REJET(cle, nonce, a2, A + 1, ct + 1, L - 1, tag);
                }
                memcpy(c2, ct, L); c2[L] = 0; REJET(cle, nonce, aad, A, c2, L + 1, tag);        /* chiffré allongé */
#undef REJET
            }
        printf("déchiffrement vérifié : %d altérations, toutes rejetées et effacées : %s\n", nalt, oko ? "oui" : "NON");
        res_mesure(&res, "aead_alterations_testees", "%d", nalt);
        res_controle(&res, "aead_ouvrir_verifie_rejette_les_alterations_et_n_en_rend_rien", oko);
        /* réutilisation de nonce : comportement documenté (pas une propriété de sécurité). Même clé, nonce et AAD : le premier
         * bloc a le même flux (c1 ⊕ c2 = p1 ⊕ p2 sur 80 octets) ; ensuite le débit, qui reçoit des chiffrés différents,
         * fait diverger les flux (fuite exacte : contrôle nonce_reutilise_fuite_exacte_…). Et le chiffrement est déterministe. */
        {
            uint8_t p1[200], p2[200], c1[200], c2[200], c3[200], t1[32], t2[32], t3[32];
            for (int i = 0; i < 200; i++) {   /* p2 diffère de p1 sur chaque octet */
                p1[i] = m[5000 + i];
                p2[i] = (uint8_t)(p1[i] ^ (1 + m[6000 + i] % 255));
            }
            aead(perm1, m, m + 64, m + 100, 9, p1, 200, 0, c1, t1);
            aead(perm1, m, m + 64, m + 100, 9, p2, 200, 0, c2, t2);
            aead(perm1, m, m + 64, m + 100, 9, p1, 200, 0, c3, t3);
            int premier = 1, suite = 1;
            for (int i = 0; i < 80; i++)
                premier &= (c1[i] ^ c2[i]) == (p1[i] ^ p2[i]);
            for (int i = 80; i < 160; i++)
                suite &= (c1[i] ^ c2[i]) == (p1[i] ^ p2[i]);
            res_controle(&res, "nonce_reutilise_comportement_documente_premier_bloc_seul_et_determinisme",
                         premier && !suite && !memcmp(c1, c3, 200) && !memcmp(t1, t3, 32));
        }
        int okm = 1;
        omp_set_num_threads(1);   /* sur 1 thread : 5 messages → un message par tâche (moins de 32 par thread : chemin
                                     trouvé non couvert par le score de mutation, 13 novembre) ; 37 → lots de 32 (un plein,
                                     un partiel) ; 300 → un lot bitslicé de 256 puis un lot de 32 et un partiel */
        const size_t LM[] = {0, 1, 79, 80, 81, 160, 1000}, AM[] = {0, 9, 80, 161}, NM[] = {5, 37, 300};
        uint8_t *o = malloc(300 * 1000), *tg = malloc(300 * 32);
        for (size_t q = 0; q < 3; q++)
            for (size_t t = 0; t < sizeof LM / sizeof *LM; t++)
                for (size_t a = 0; a < sizeof AM / sizeof *AM; a++) {
                    size_t nmsg = NM[q], L = LM[t];
                    uint8_t c1[1000], t1[32];
                    aead_multi(nmsg, m, m + 20000, m + 100, AM[a], m + 30000, L, o, tg);
                    for (size_t j = 0; j < nmsg; j++) {
                        aead(perm1, m + 64 * j, m + 20000 + 24 * j, m + 100, AM[a], m + 30000 + j * L, L, 0, c1, t1);
                        okm &= !memcmp(c1, o + j * L, L) && !memcmp(t1, tg + 32 * j, 32);
                    }
                }
        free(o);
        free(tg);
        omp_set_num_threads(omp_get_num_procs());
        res_controle(&res, "aead_multi_lots_de_32_et_bitslices_identiques_a_l_aead_unitaire", okm);
        /* échecs d'allocation injectés (sur 1 thread : ordre des allocations déterministe) : l'arbre rend −1 et une sortie
         * effacée si la racine manque, sinon les mêmes sorties ; l'AEAD multi rend les mêmes sorties (replis) */
        {
            int oke = 1, injectes = 0;
            omp_set_num_threads(1);
            const size_t LA2 = 600 * 8192 + 3, NM2 = 300, LT2 = 81;
            uint8_t h0[64], h1[64], *o0 = malloc(NM2 * LT2), *o1 = malloc(NM2 * LT2), g0[300 * 32], g1[300 * 32];
            arbre(m, LA2, h0, 64, 1);
            aead_multi(NM2, m, m + 20000, m + 100, 9, m + 30000, LT2, o0, g0);
            ALLOC_INJECTES = 0;
            for (long k = 0; k < 3; k++) {   /* arbre : 4 allocations (racine + 3 lots de 32) ; AEAD multi : 3 (lot de 256 + 2 de 32) */
                ALLOC_ECHEC = k;
                memset(h1, 0xA5, 64);        /* tampons effacés : un repli défaillant ne peut pas reprendre une sortie précédente */
                int rc = arbre(m, LA2, h1, 64, 1);
                int vide = 1;
                for (int q = 0; q < 64; q++)
                    vide &= h1[q] == 0;
                oke &= k == 0 ? (rc == -1 && vide) : (rc == 0 && !memcmp(h0, h1, 64));
                injectes += ALLOC_ECHEC < 0;
                ALLOC_ECHEC = k;
                memset(o1, 0xA5, NM2 * LT2);
                memset(g1, 0xA5, sizeof g1);
                aead_multi(NM2, m, m + 20000, m + 100, 9, m + 30000, LT2, o1, g1);
                oke &= !memcmp(o0, o1, NM2 * LT2) && !memcmp(g0, g1, sizeof g0);
                injectes += ALLOC_ECHEC < 0;
            }
            ALLOC_ECHEC = -1;
            free(o0);
            free(o1);
            omp_set_num_threads(omp_get_num_procs());
            printf("échecs d'allocation injectés : %ld provoqués sur 6 essais (sorties %s)\n", ALLOC_INJECTES, oke ? "conformes" : "FAUSSES");
            res_controle(&res, "echecs_d_allocation_injectes_replis_identiques_ou_erreur_signalee", oke && injectes == 6 && ALLOC_INJECTES == 6);
        }
        /* tampons exacts (2e passe du score de mutation, 13 novembre) : des débordements d'un élément (lot de 256 traitant un
         * 257e message, feuille de trop en queue d'arbre ou dans le repli de feuilles(), clé lue sur 65 octets) survivaient,
         * car les contrôles écrivent dans de grands tampons. Ici chaque entrée est allouée à sa taille exacte (une lecture de
         * trop est vue par ASan), et chaque sortie est suivie de 64 octets de garde (une écriture de trop est vue partout).
         * Sur 1 thread : le lot bitslicé de 256 est le dernier lot ; avec et sans échec d'allocation injecté (replis). */
        {
            int okx = 1;
            omp_set_num_threads(1);
            const size_t NX = 256, LX = 81, G = 64;
            uint8_t *kx = malloc(64 * NX), *nx = malloc(24 * NX), *ix = malloc(NX * LX), *ox = malloc(NX * LX + G),
                    *tx = malloc(32 * NX + G), c1[LX], t1[32];
            memcpy(kx, m + 11, 64 * NX);
            memcpy(nx, m + 40000, 24 * NX);
            memcpy(ix, m + 50000, NX * LX);
            for (long inj = -1; inj < 1; inj++) {
                memset(ox, 0xA5, NX * LX + G);
                memset(tx, 0x5A, 32 * NX + G);
                ALLOC_ECHEC = inj;
                aead_multi(NX, kx, nx, m + 100, 9, ix, LX, ox, tx);
                ALLOC_ECHEC = -1;
                for (size_t q = 0; q < G; q++)
                    okx &= ox[NX * LX + q] == 0xA5 && tx[32 * NX + q] == 0x5A;
                for (size_t j = 0; j < NX; j++) {
                    aead(perm1, kx + 64 * j, nx + 24 * j, m + 100, 9, ix + LX * j, LX, 0, c1, t1);
                    okx &= !memcmp(c1, ox + LX * j, LX) && !memcmp(t1, tx + 32 * j, 32);
                }
            }
            /* arbre : entrée de taille exacte, dernière feuille partielle ou pleine, avec et sans repli de feuilles() */
            const size_t LA[] = {600 * 8192 + 3, 300 * 8192, 40 * 8192 + 1};
            for (int a = 0; a < 3; a++)
                for (long inj = -1; inj < 4; inj += 1 + (inj == -1)) {   /* −1 : sans échec ; 1, 2, 3 : un lot de 32
                                                                             (dont le dernier : la feuille de queue suit) */
                    uint8_t *mx = malloc(LA[a]), h0[64 + 64], h1[64];
                    for (size_t q = 0; q < LA[a]; q++)
                        mx[q] = m[q % 100000];
                    memset(h0, 0xC3, sizeof h0);
                    ALLOC_ECHEC = inj;
                    const int rc = arbre(mx, LA[a], h0, 64, 1);
                    ALLOC_ECHEC = -1;
                    arbre(mx, LA[a], h1, 64, 0);   /* sans lots : une éponge par feuille */
                    okx &= rc == 0 && !memcmp(h0, h1, 64);
                    for (int q = 64; q < 128; q++)
                        okx &= h0[q] == 0xC3;
                    free(mx);
                }
            /* référence DMV17 littérale : clé, nonce et texte à leur taille exacte */
            {
                uint8_t *ke = malloc(64), *ne = malloc(24), *ie = malloc(LX), *oe = malloc(LX + G), te[32], c2[LX], t2[32];
                memcpy(ke, kx, 64);
                memcpy(ne, nx, 24);
                memcpy(ie, ix, LX);
                memset(oe, 0xA5, LX + G);
                aead_kd(perm1, ke, ne, m + 100, 9, ie, LX, 0, oe, te);
                aead(perm1, ke, ne, m + 100, 9, ie, LX, 0, c2, t2);
                okx &= !memcmp(oe, c2, LX) && !memcmp(te, t2, 32);
                for (size_t q = 0; q < G; q++)
                    okx &= oe[LX + q] == 0xA5;
                free(ke); free(ne); free(ie); free(oe);
            }
            free(kx); free(nx); free(ix); free(ox); free(tx);
            omp_set_num_threads(omp_get_num_procs());
            res_controle(&res, "tampons_exacts_lots_arbre_replis_et_reference_sans_debordement", okx);
        }
        /* cache de P(IV) : après prepare_iv(), ni l'arbre (lots bitslicés compris) ni l'AEAD multi sur tous les threads ne
         * recalculent P(IV) ni ses plans de bits (un recalcul en région parallèle serait une course, même à valeur égale) */
        {
            prepare_iv();
            const long avant = IV_CALCULS;
            uint8_t hh[64], *oo = malloc(300 * 81), gg[300 * 32];
            arbre(m, 600 * 8192 + 3, hh, 64, 1);
            aead_multi(300, m, m + 20000, m + 100, 9, m + 30000, 81, oo, gg);
            free(oo);
            res_controle(&res, "cache_piv_aucun_recalcul_apres_preparation_arbre_et_aead_multi", IV_CALCULS == avant);
            /* le compteur lui-même : +2 (P(IV) et ses plans de bits) quand le nombre de tours change, +1 (les plans de
             * bits, toujours refaits par prepare_iv) quand le cache de P(IV) est valide */
            const int R0 = R1;
            const long c0 = IV_CALCULS;
            R1 = R0 - 1;
            prepare_iv();
            const long c1 = IV_CALCULS;
            prepare_iv();
            const long c2 = IV_CALCULS;
            R1 = R0;
            prepare_iv();
            const long c3 = IV_CALCULS;
            res_controle(&res, "compteur_piv_exact_2_au_changement_de_tours_1_sinon",
                         c1 - c0 == 2 && c2 - c1 == 1 && c3 - c2 == 2);
        }
        /* trous comblés après le score de mutation du 13 novembre (resultats/mutants_20261113.txt) */
        {
            /* aead_multi : 2 lots bitslicés et plus, et un reste traité message par message après un lot (1 thread) */
            int okn = 1;
            omp_set_num_threads(1);
            const size_t NN[] = {261, 288, 600}, LN[] = {0, 81, 160}, AN[] = {0, 9};
            uint8_t *o = malloc(600 * 160), *tg = malloc(600 * 32);
            for (size_t q = 0; q < 3; q++)
                for (size_t t = 0; t < 3; t++)
                    for (size_t a = 0; a < 2; a++) {
                        memset(o, 0xA5, 600 * 160);
                        aead_multi(NN[q], m, m + 50000, m + 100, AN[a], m + 70000, LN[t], o, tg);
                        for (size_t j = 0; j < NN[q]; j++) {
                            uint8_t c1[160], t1[32];
                            aead(perm1, m + 64 * j, m + 50000 + 24 * j, m + 100, AN[a], m + 70000 + j * LN[t], LN[t], 0, c1, t1);
                            okn &= !memcmp(c1, o + j * LN[t], LN[t]) && !memcmp(t1, tg + 32 * j, 32);
                        }
                    }
            free(o);
            free(tg);
            omp_set_num_threads(omp_get_num_procs());
            res_controle(&res, "aead_multi_plusieurs_lots_bitslices_et_reste_message_par_message", okn);
        }
        {
            /* référence DMV17 au-delà de 255 et de 65 535 octets (encodage de la longueur), AAD de 300 octets */
            int okl = 1;
            const size_t LL[] = {255, 256, 300, 65535, 65536, 70000}, AL[] = {0, 300};
            uint8_t *c1 = malloc(70000), *c2 = malloc(70000), t1[32], t2[32];
            for (size_t i = 0; i < 6; i++)
                for (size_t a = 0; a < 2; a++)
                    for (int dech = 0; dech < 2; dech++) {
                        aead(perm1, m + 9, m + 80, m + 1000, AL[a], m + 100000, LL[i], dech, c1, t1);
                        aead_kd(perm1, m + 9, m + 80, m + 1000, AL[a], m + 100000, LL[i], dech, c2, t2);
                        okl &= !memcmp(c1, c2, LL[i]) && !memcmp(t1, t2, 32);
                    }
            free(c1);
            free(c2);
            res_controle(&res, "aead_identique_a_la_reference_dmv17_grandes_longueurs", okl);
        }
    }
    /* 4 octies. longueurs hors limite (SPEC.md § 3.5) : aead(), aead_ouvrir() et aead_multi() rendent −1 sans rien lire ni
     * écrire (tampons réels de quelques octets, octets témoins ; sans la garde, la lecture sort du tampon) ; la limite
     * elle-même est admise ; aead_multi() refuse aussi n·len et 64·n qui débordent ; les longueurs admises marchent. */
    {
        int okh = longueurs_admises(AEAD_LONGUEUR_MAX, AEAD_LONGUEUR_MAX) && longueurs_admises(0, 0) &&
                  !longueurs_admises(AEAD_LONGUEUR_MAX + 1, 0) && !longueurs_admises(0, AEAD_LONGUEUR_MAX + 1) &&
                  AEAD_LONGUEUR_MAX == (size_t)INT64_MAX;
        const size_t H[] = {AEAD_LONGUEUR_MAX + 1, (size_t)1 << 63, SIZE_MAX - 2 * RB, SIZE_MAX - RB, SIZE_MAX - 1, SIZE_MAX};
        uint8_t ent[96], sor[96], tg[32], pt[96], tg0[32];
        memcpy(ent, m + 777, sizeof ent);
        memcpy(tg0, m + 999, sizeof tg0);
        for (size_t h = 0; h < sizeof H / sizeof H[0]; h++)
            for (int role = 0; role < 3; role++) {           /* 0 : A hors limite ; 1 : texte ; 2 : les deux */
                const size_t al = role == 1 ? 9 : H[h], tl = role == 0 ? 9 : H[h];
                for (int f = 0; f < 4; f++) {
                    memset(sor, 0xA5, sizeof sor);
                    memset(tg, 0x5A, sizeof tg);
                    memset(pt, 0xC3, sizeof pt);
                    int r;
                    if (f < 2)
                        r = aead(perm1, m, m + 64, ent, al, ent, tl, f, sor, tg);
                    else if (f == 2)
                        r = aead_ouvrir(m, m + 64, ent, al, ent, tl, tg0, pt);
                    else
                        r = aead_multi(1, m, m + 64, ent, al, ent, tl, sor, tg);
                    int intact = 1;
                    for (size_t k = 0; k < sizeof sor; k++)
                        intact &= sor[k] == 0xA5 && pt[k] == 0xC3;
                    for (size_t k = 0; k < sizeof tg; k++)
                        intact &= tg[k] == 0x5A;
                    okh &= r == -1 && intact;
                }
            }
        /* aead_multi : n·len au-delà de la limite (len admis seul), 64·n qui déborde (len = 0), puis cas admis */
        okh &= aead_multi(2, m, m + 64, ent, 9, ent, AEAD_LONGUEUR_MAX / 2 + 1, sor, tg) == -1;
        okh &= aead_multi(3, m, m + 64, ent, 9, ent, AEAD_LONGUEUR_MAX / 3 + 1, sor, tg) == -1;
        okh &= aead_multi(SIZE_MAX / 64 + 1, m, m + 64, ent, 9, ent, 0, sor, tg) == -1;
        {
            uint8_t o2[2 * 40], t2[2 * 32], c1[40], t1[32];
            okh &= aead_multi(2, m, m + 200, ent, 9, ent, 40, o2, t2) == 0;
            for (int j2 = 0; j2 < 2; j2++) {
                okh &= aead(perm1, m + 64 * j2, m + 200 + 24 * j2, ent, 9, ent + 40 * j2, 40, 0, c1, t1) == 0;
                okh &= !memcmp(c1, o2 + 40 * j2, 40) && !memcmp(t1, t2 + 32 * j2, 32);
            }
            okh &= aead(perm1, m, m + 64, ent, 0, ent, 0, 0, c1, t1) == 0 && aead_ouvrir(m, m + 64, ent, 0, ent, 0, t1, c1) == 0;
        }
        res_controle(&res, "longueurs_hors_limite_rejetees_sans_lecture_ni_ecriture", okh);
    }
    /* 5. KAT */
    {
        uint8_t h[64];
        char s[129];
        arbre((const uint8_t *)"", 0, h, 64, 1);
        hexa(h, 64, s);
        printf("KAT BRUME-1024q R=%d hachage(\"\")    = %s\n", R1, s);
        res_mesure(&res, "kat_vide", "\"%s\"", s);
        arbre((const uint8_t *)"abc", 3, h, 64, 1);
        hexa(h, 64, s);
        printf("KAT BRUME-1024q R=%d hachage(\"abc\") = %s\n", R1, s);
        res_mesure(&res, "kat_abc", "\"%s\"", s);
    }
    /* 5 bis. KAT figés (profil R = 32) : noyau AVX2 et référence dense contre kat_b1024.h ; table des domaines */
    if (R1 == 32) {
        static kat_t kn[NKAT], kr[NKAT];
        int okn = KAT_PRESENTS, okr = KAT_PRESENTS, nref = 0;
        calculer_kats(0, kn);
        calculer_kats(1, kr);
#if KAT_PRESENTS
        for (int i = 0; i < NKAT; i++) {
            int bon = !strcmp(kn[i].nom, KAT_FIGES[i][0]) && !strcmp(kn[i].hex, KAT_FIGES[i][1]);
            if (!bon)
                printf("KAT différent (noyau) : %s\n", kn[i].nom);
            okn &= bon;
            if (kr[i].hex[0]) {
                nref++;
                if (strcmp(kr[i].hex, KAT_FIGES[i][1]))
                    printf("KAT différent (référence) : %s\n", kr[i].nom);
                okr &= !strcmp(kr[i].hex, KAT_FIGES[i][1]);
            }
        }
#endif
        printf("KAT figés : %d (noyau), %d recalculés par la référence dense\n", NKAT, nref);
        res_mesure(&res, "kat_figes", "%d", NKAT);
        res_mesure(&res, "kat_figes_par_la_reference", "%d", nref);
        res_controle(&res, "kat_figes_noyau_avx2", okn);
        res_controle(&res, "kat_figes_reference_dense", okr);
    }
    res_controle(&res, "separation_des_domaines_structurelle", controle_domaines());
    /* 6. diffusion effective à travers la permutation (S-box comprises) : nibbles dépendants d'un nibble, r tours */
    {
        int dep[8] = {0};
        for (int r = 1; r <= 5; r++) {
            uint8_t vu[N1] = {0};
            for (int e = 0; e < 64; e++) {
                uint8_t x[N1], y[N1];
                memcpy(x, m + 256 * e, N1);
                for (int j = 0; j < N1; j++)
                    x[j] &= 15;
                memcpy(y, x, N1);
                y[0] ^= (uint8_t)(1 + e % 15);
                for (int t = 0; t < r; t++) {
                    ref_tour(x, t);
                    ref_tour(y, t);
                }
                for (int j = 0; j < N1; j++)
                    vu[j] |= x[j] != y[j];
            }
            for (int j = 0; j < N1; j++)
                dep[r] += vu[j];
        }
        printf("diffusion effective d'un nibble (64 essais) : %d %d %d %d %d\n", dep[1], dep[2], dep[3], dep[4], dep[5]);
        res_mesure(&res, "diffusion_effective", "[%d, %d, %d, %d, %d]", dep[1], dep[2], dep[3], dep[4], dep[5]);
        res_controle(&res, "diffusion_effective_complete_en_5_tours", dep[5] == N1);
    }
    /* 7. mesures (sautées si BRUME1024_RAPIDE est défini : contrôles seuls, pour Valgrind et le score de mutation) */
    if (!getenv("BRUME1024_RAPIDE")) {
        double tp[7], tl[7], tb[7], te[7], ta1[7], tan[7];
        uint8_t w[128] = {1}, h[64];
        uint8_t (*e)[128] = aligned_alloc(64, 32 * 128);
        memcpy(e, m, 32 * 128);
        size_t L1 = (size_t)4 << 20, L2 = (size_t)64 << 20;
        for (int s = 0; s < 7; s++) {
            double t0 = maintenant();
            for (int i = 0; i < 100000; i++)
                perm1(w, R1);
            tp[s] = (maintenant() - t0) / 100000 * 1e9;
            t0 = maintenant();
            for (int i = 0; i < 4000; i++)
                lot(e, R1);
            tl[s] = (maintenant() - t0) / 4000 / 32 * 1e9;
            t0 = maintenant();
            for (int i = 0; i < 500; i++)
                bs_perm(BS_P, R1);
            tb[s] = (maintenant() - t0) / 500 / 256 * 1e9;
            t0 = maintenant();
            eponge(m, L1, DOM_SEQ, h, 64);
            te[s] = L1 / (maintenant() - t0) / 1e6;
            omp_set_num_threads(1);
            t0 = maintenant();
            arbre(m, L2 / 4, h, 64, 1);
            ta1[s] = (L2 / 4) / (maintenant() - t0) / 1e6;
            omp_set_num_threads(omp_get_num_procs());
            t0 = maintenant();
            arbre(m, L2, h, 64, 1);
            tan[s] = L2 / (maintenant() - t0) / 1e6;
        }
        double bsl = mediane(tb, 7);
        printf("noyau bitslicé (256 états) : %.0f ns par état, sans transposition\n", bsl);
        res_mesure(&res, "permutation_bitslicee_ns_par_etat", "%.1f", bsl);
        double p = mediane(tp, 7), l = mediane(tl, 7), ep = mediane(te, 7), a1 = mediane(ta1, 7), an = mediane(tan, 7);
        printf("BRUME-1024q R=%d c=384 : permutation %.0f ns (1 etat), %.0f ns/etat (lot de 32) ; eponge 1 coeur %.1f Mo/s ; "
               "arbre 1 coeur %.1f Mo/s ; arbre %d threads %.1f Mo/s (%x)\n", R1, p, l, ep, a1, omp_get_num_procs(), an, w[0] ^ e[0][0] ^ h[0]);
        res_mesure(&res, "permutation_ns", "%.1f", p);
        res_mesure(&res, "permutation_lot_ns_par_etat", "%.1f", l);
        res_mesure(&res, "eponge_mo_s", "%.1f", ep);
        res_mesure(&res, "arbre_1_coeur_mo_s", "%.1f", a1);
        res_mesure(&res, "arbre_tous_coeurs_mo_s", "%.1f", an);
        double ta[7];
        uint8_t *c = malloc(L1), tg[32];
        for (int s2 = 0; s2 < 7; s2++) {
            double t0 = maintenant();
            aead(perm1, m, m + 64, m + 100, 16, m, L1, 0, c, tg);
            ta[s2] = L1 / (maintenant() - t0) / 1e6;
        }
        double aa = mediane(ta, 7);
        printf("AEAD-1024q (cle 64 o, tag 32 o) : %.1f Mo/s (%02x)\n", aa, tg[0] ^ c[0]);
        res_mesure(&res, "aead_mo_s", "%.1f", aa);
        free(c);
        free(e);
    }
    free(m);
    return res_ecrire(&res);
}
#endif /* SANS_MAIN */
