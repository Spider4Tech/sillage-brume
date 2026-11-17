/* SILLAGE v0.6 — BRUME-1024q : permutation de 1 024 bits (256 nibbles, graphe de Cayley de D₂₅₆), éponge à c = 384 (débit
 * 640 bits = 80 octets), hachage arborescent (condensé par défaut), XOF, AEAD (duplex à clé dans tout l'état, orientation
 * SpongeWrap), AEAD parallèle (mode 6), lots de messages et mode TE. Spécification : docs/brume1024/SPEC.md ; arguments :
 * docs/brume1024/AEAD_SECURITY.md, V06_MODES.md, SPONGE_QROM.md ; preuves condensées : docs/PROOFS.md § 4.
 *
 * Remplace BRUME-512 (v0.5) dans la suite (décision de l'auteur du 13 novembre 2026, docs/MIGRATION_V06.md). Code repris du
 * prototype prototypes/brume_q/b1024/brume1024.c (même calcul, mêmes KAT) ; les contrôles du prototype sont devenus le test
 * tests/c/brume1024.c, qui inclut ce fichier pour atteindre ses fonctions internes.
 *
 * Tour r : x ← M·S(x ⊕ RC[r]), M de support A ⊕ I (7 termes par ligne), R = 32.
 * Noyaux, tous à temps constant vis-à-vis de l'état (dudect et ctgrind sur deux machines) :
 *  - AVX2 à 1 état (état déballé, un nibble par octet, 8 ymm, S-box et produits par vpshufb), à 32 états (vertical) et
 *    bitslicé à 256 états (b1024_bs : S-box en circuit), si __AVX2__ ;
 *  - PORTABLE (brume1024_portable.h : C pur sur des mots de 64 bits, S-box en circuit de 17 portes), sinon. Il n'y a pas de
 *    repli à tables : la règle de la suite les refuse.
 *  - référence dense (M et M⁻¹ explicites), NON constante en temps, pour les contrôles et sl_brume_permute_ref.
 * Modes : éponge à domaine (bourrage 10*, domaine dans le nibble haut de l'octet 127), état initial P(cadre) avec le cadre
 * du profil (tours, débit, largeur, 'q', mode) dans la capacité ; hachage par défaut = arbre (feuilles de 8 Kio, CV de 64
 * octets, racine), l'éponge DOM_SEQ sert de XOF. */
#include <omp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef __AVX2__
#include <immintrin.h>
#endif

#include "brume1024_tables.h"
#include "brume1024_portable.h"
#ifdef __AVX2__
#include "brume1024_lot.h"
#endif
#include "sillage.h"

/* GF(2⁴) modulo t⁴ + t + 1, sur des données publiques seulement (construction des tables) */
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


#ifdef __AVX2__
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
#else
/* sans AVX2 : le noyau portable à temps constant */
static void perm1(uint8_t w[128], int R) { pp_perm(w, R); }
#endif

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

#ifdef __AVX2__
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
#else
/* éponge à domaine sur l'état emballé (noyau portable) : même calcul que la version AVX2 */
static void eponge(const uint8_t *m, size_t len, int dom, uint8_t *out, size_t outlen)
{
    uint8_t w[128];
    etat_iv(w, MODE_EPONGE);
    size_t i = 0;
    for (; i + RB <= len; i += RB) {
        for (size_t k = 0; k < RB; k++)
            w[k] ^= m[i + k];
        perm1(w, R1);
    }
    for (size_t k = 0; k < len - i; k++)
        w[k] ^= m[i + k];
    w[len - i] ^= 0x01;
    w[127] ^= (uint8_t)(dom << 4);
    perm1(w, R1);
    for (size_t o = 0; o < outlen; o += RB) {
        size_t k = outlen - o < RB ? outlen - o : RB;
        memcpy(out + o, w, k);
        if (o + RB < outlen)
            perm1(w, R1);
    }
}
#endif

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

#ifdef __AVX2__
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
#include "brume1024_bs.h"

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
#else
static int bs_iv_tours;   /* sans AVX2 : pas de plans de bits à préparer */
static void bs_preparer(void) { bs_iv_tours = R1; }
#endif

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
#ifdef __AVX2__
    const size_t n256 = par_lot == 1 && pleines >= 128 * nt ? pleines / 256 : 0, f0 = 256 * n256, reste = pleines - f0;
    const int par32 = par_lot && reste >= 32 * nt;
#else
    (void)nt;
    const size_t n256 = 0, f0 = 0, reste = pleines;   /* noyau portable : une éponge par feuille, en parallèle */
    const int par32 = 0;
    (void)par_lot;
#endif
    const size_t npetites = par32 ? (reste + 31) / 32 : reste;
#pragma omp parallel for schedule(dynamic)
    for (long t = 0; t < (long)(n256 + npetites); t++) {
#ifdef __AVX2__
        if ((size_t)t < n256)
            feuilles256(m + (size_t)256 * t * FEUILLE, racine + (size_t)256 * t * CVL);
        else if (par32) {
            size_t d = f0 + 32 * ((size_t)t - n256), nm = pleines - d < 32 ? pleines - d : 32;
            feuilles(m + d * FEUILLE, (int)nm, racine + d * CVL);
        } else
#endif
        {
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
 * puis P. Données associées (DOM_AAD, XOR), texte (DOM_TEXTE sur le dernier bloc, bourré 0x01), tag = 32 premiers octets
 * de l'état après la permutation de ce dernier bloc ; 3 permutations pour un message court. Depuis le 14 novembre 2026, il
 * n'y a plus de bloc de longueur (AEAD_SECURITY.md § 6 bis) : le codage (A, M) ↦ chemin est injectif sans lui (le bourrage
 * 0x01 et les domaines délimitent A et M ; decoder_chemin en est l'inverse à gauche). Texte, ORIENTATION SPONGEWRAP depuis le 13 novembre 2026 (AEAD_SECURITY.md § 6) : le clair est ajouté au
 * débit par XOR au chiffrement, qui contient donc ensuite le CHIFFRÉ (drapeau faux de DMV17 : l'adversaire ne choisit pas
 * la partie externe) ; le déchiffrement écrase le débit avec le chiffré (drapeau vrai ; pour un dernier bloc partiel de r
 * octets, sur ces r octets seulement). Auparavant le débit recevait le clair (drapeau vrai au chiffrement, blocs chiffrés
 * comptés dans Ω). La permutation est passée en paramètre pour recouper le noyau AVX2 avec la référence dense. */
enum { DOM_AAD = 1, DOM_TEXTE = 2 };   /* 4 (ancien DOM_FINAL, bloc de longueur) n'est plus utilisé */
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
    memcpy(tag, w, 32);                    /* le tag suit la permutation du dernier bloc de texte (plus de bloc de longueur) */
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

/* ------------------------------------------------------------ AEAD parallèle (v0.6, V06_MODES.md § 2) */
/* Mode 6 : l'état initial diffère de celui de l'AEAD séquentiel (mode 3) pour toute clé et tout nonce ; octet 122 = log₂ B.
 * Tronc : phase AAD de l'AEAD séquentiel → S_A. Feuille j : fourche (le64(j) ‖ 0x01, domaine 5), fourche 2 (0^r, domaine 3),
 * puis le morceau j (B = 8 192 octets) comme la phase de texte de l'AEAD ; CV_j = 64 premiers octets de l'état final.
 * Racine : depuis S_A, absorbe CV_0 ‖ … ‖ CV_{k−1} ‖ le64(k) ‖ le64(ℓ), domaine 4 ; tag = 32 premiers octets. */
enum { MODE_AEADP = 6, PAR_LOGB = 13, DOM_FOURCHE = 5, DOM_FOURCHE2 = 3, DOM_RACINE_P = 4 };
#define PAR_B ((size_t)1 << PAR_LOGB)
#define PAR_CV 64

static void etat_aeadp(uint8_t w[128], const uint8_t cle[64], const uint8_t nonce[24])
{
    memset(w, 0, 128);
    memcpy(w, cle, 64);
    memcpy(w + 64, nonce, 24);
    cadre_iv(w, MODE_AEADP);
    w[122] = PAR_LOGB;
}

/* phase de texte, identique à celle de aead() (orientation SpongeWrap), laissant w après la dernière permutation */
static void texte_p(perm_f P, uint8_t w[128], const uint8_t *in, size_t len, int dech, uint8_t *out)
{
    size_t i = 0;
    for (; i + RB <= len; i += RB) {
        for (size_t k = 0; k < RB; k++) {
            uint8_t o = in[i + k] ^ w[k];
            out[i + k] = o;
            w[k] = dech ? in[i + k] : o;
        }
        P(w, R1);
    }
    size_t r = len - i;
    for (size_t k = 0; k < r; k++) {
        uint8_t o = in[i + k] ^ w[k];
        out[i + k] = o;
        w[k] = dech ? in[i + k] : o;
    }
    w[r] ^= 0x01;
    w[127] ^= DOM_TEXTE << 4;
    P(w, R1);
}

static void feuille_p(perm_f P, const uint8_t sa[128], uint64_t j, const uint8_t *in, size_t len, int dech, uint8_t *out,
                      uint8_t cv[PAR_CV])
{
    uint8_t w[128] __attribute__((aligned(32)));
    memcpy(w, sa, 128);
    for (int b = 0; b < 8; b++)
        w[b] ^= (uint8_t)(j >> (8 * b));
    w[8] ^= 0x01;
    w[127] ^= DOM_FOURCHE << 4;
    P(w, R1);
    w[127] ^= DOM_FOURCHE2 << 4;   /* σ = 0^r */
    P(w, R1);
    texte_p(P, w, in, len, dech, out);
    memcpy(cv, w, PAR_CV);
    sl_effacer(w, sizeof w);
}

/* absorption incrémentale (blocs de 80 octets, bourrage 0x01, domaine sur le dernier bloc), même résultat que absorber_a */
typedef struct { uint8_t w[128]; size_t pos; perm_f P; } abs_t;
static void abs_octets(abs_t *a, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        a->w[a->pos++] ^= d[i];
        if (a->pos == RB) {
            a->P(a->w, R1);
            a->pos = 0;
        }
    }
}
static void abs_fin(abs_t *a, int dom)
{
    a->w[a->pos] ^= 0x01;
    a->w[127] ^= (uint8_t)(dom << 4);
    a->P(a->w, R1);
}

/* Rend 0, ou −1 sans rien lire ni écrire si une longueur dépasse AEAD_LONGUEUR_MAX. Le noyau calcule les feuilles en
 * parallèle (OpenMP) dans un tampon de CV ; sans tampon (échec d'allocation, ou référence dense), feuille par feuille :
 * mêmes sorties. */
static int aeadp(perm_f P, const uint8_t cle[64], const uint8_t nonce[24], const uint8_t *aad, size_t aadlen, const uint8_t *in,
                 size_t len, int dech, uint8_t *out, uint8_t tag[32])
{
    if (!longueurs_admises(aadlen, len))
        return -1;
    uint8_t sa[128] __attribute__((aligned(32)));
    etat_aeadp(sa, cle, nonce);
    P(sa, R1);
    absorber_a(P, sa, aad, aadlen, DOM_AAD);
    size_t k = len ? (len + PAR_B - 1) / PAR_B : 1;
    abs_t r;
    memcpy(r.w, sa, 128);
    r.pos = 0;
    r.P = P;
    uint8_t *cvs = (P == perm1 && k > 1) ? allouer(k * PAR_CV) : NULL;
    if (cvs) {
#pragma omp parallel for schedule(dynamic) if (k >= 4)
        for (size_t j = 0; j < k; j++) {
            size_t o = j * PAR_B, l = len - o < PAR_B ? len - o : PAR_B;
            feuille_p(P, sa, j, in + o, l, dech, out + o, cvs + j * PAR_CV);
        }
        abs_octets(&r, cvs, k * PAR_CV);
        sl_effacer(cvs, k * PAR_CV);
        free(cvs);
    } else {
        for (size_t j = 0; j < k; j++) {
            uint8_t cv[PAR_CV];
            size_t o = j * PAR_B, l = len - o < PAR_B ? len - o : PAR_B;
            feuille_p(P, sa, j, l ? in + o : in, l, dech, l ? out + o : out, cv);
            abs_octets(&r, cv, PAR_CV);
            sl_effacer(cv, sizeof cv);
        }
    }
    uint8_t q[16];
    for (int b = 0; b < 8; b++) {
        q[b] = (uint8_t)((uint64_t)k >> (8 * b));
        q[8 + b] = (uint8_t)((uint64_t)len >> (8 * b));
    }
    abs_octets(&r, q, 16);
    abs_fin(&r, DOM_RACINE_P);
    memcpy(tag, r.w, 32);
    sl_effacer(r.w, sizeof r.w);
    sl_effacer(sa, sizeof sa);
    return 0;
}

/* déchiffrement vérifié de l'AEAD parallèle : rien n'est rendu avant la vérification du tag (temps constant) */
static int aeadp_ouvrir(const uint8_t cle[64], const uint8_t nonce[24], const uint8_t *aad, size_t aadlen, const uint8_t *ct,
                        size_t len, const uint8_t tag[32], uint8_t *pt)
{
    uint8_t t[32], d = 0;
    if (aeadp(perm1, cle, nonce, aad, aadlen, ct, len, 1, pt, t))
        return -1;
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


#ifdef __AVX2__
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
 * AAD (communes) : constantes, sans transposition ; texte : flux extrait (80 octets), débit écrasé par le clair. */
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
    bs_extraire((const __m256i (*)[4])P, tags, 32, 2);
    free(tmp);
}

#endif

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
#ifdef __AVX2__
    const size_t n256 = n >= 128 * nt ? n / 256 : 0, f0 = 256 * n256, reste = n - f0;
    const int par32 = reste >= 32 * nt;
#else
    (void)nt;
    const size_t n256 = 0, f0 = 0, reste = n;   /* noyau portable : un message par tâche */
    const int par32 = 0;
#endif
    const size_t npetites = par32 ? (reste + 31) / 32 : reste;
#pragma omp parallel for schedule(dynamic)
    for (long t = 0; t < (long)(n256 + npetites); t++) {
#ifdef __AVX2__
        if ((size_t)t < n256) {
            const size_t d = 256 * (size_t)t;
            aead_lot256(cles + 64 * d, nonces + 24 * d, aad, aadlen, in + d * len, len, out + d * len, tags + 32 * d);
        } else if (par32) {
            const size_t d = f0 + 32 * ((size_t)t - n256), nm = n - d < 32 ? n - d : 32;
            aead_lot32(d, nm, cles, nonces, aad, aadlen, in, len, out, tags);
        } else
#endif
        {
            const size_t j = f0 + (size_t)t - n256;
            aead(perm1, cles + 64 * j, nonces + 24 * j, aad, aadlen, in + j * len, len, 0, out + j * len, tags + 32 * j);
        }
    }
    return 0;
}

/* ============================================================ API publique (sillage.h) */
static int pret;

void sl_init(void)
{
    if (pret)
        return;
    /* tables publiques seulement ; non réentrant : à appeler une fois, hors de toute région parallèle */
    if (!ref_init() || !pp_init())
        abort();
#ifdef __AVX2__
    if (!init_noyaux())
        abort();
#endif
    prepare_iv();
    pret = 1;
}

void sl_brume_permute(uint8_t etat[128]) { perm1(etat, R1); }
void sl_brume_permute_ref(uint8_t etat[128]) { perm_ref(etat, R1); }

void sl_brume_permute_inv_ref(uint8_t etat[128])
{
    uint8_t x[N1];
    deballer_ref(etat, x);
    for (int r = R1 - 1; r >= 0; r--)
        ref_tour_inv(x, r);
    emballer_ref(x, etat);
}

void sl_brume_permute_lot(uint8_t etats[32][128])
{
#ifdef __AVX2__
    lot(etats, R1);
#else
    for (int i = 0; i < 32; i++)
        perm1(etats[i], R1);
#endif
}

/* ------------------------------------------------------------ hachage */
void br_eponge(const uint8_t *m, size_t len, int dom, uint8_t *out, size_t outlen)
{
    eponge(m, len, dom & 15, out, outlen);
}

void sl_xof(const uint8_t *m, size_t len, uint8_t *out, size_t outlen) { eponge(m, len, DOM_SEQ, out, outlen); }

/* H (SPEC § 3.4) : éponge seule jusqu'à 8 Kio, arbre au-delà. Si la mémoire manque pour la racine : abort(), comme
 * sl_malloc (jamais de sortie silencieusement fausse). */
void sl_hash(const uint8_t *m, size_t len, uint8_t *out, size_t outlen)
{
    if (arbre(m, len, out, outlen, 1))
        abort();
}

void sl_hash_arbre(const uint8_t *m, size_t len, uint8_t *out, size_t outlen) { sl_hash(m, len, out, outlen); }

void sl_hash_multi(size_t n, const uint8_t *const *msgs, const size_t *lens, uint8_t *outs, size_t outlen)
{
#pragma omp parallel for schedule(dynamic)
    for (long i = 0; i < (long)n; i++)
        sl_hash(msgs[i], lens[i], outs + (size_t)i * outlen, outlen);
}

/* ------------------------------------------------------------ AEAD */
size_t sl_aead_tag_len(int profil) { return profil == 0 ? 32 : 0; }

/* Le duplex est à clé dans tout l'état : il n'y a rien à précalculer par clé. Le contexte garde la clé (64 octets),
 * matériel secret à effacer par sl_effacer(&c, sizeof c). */
int sl_aead_cle(sl_aead_cle_t *c, int profil, const uint8_t cle[64])
{
    if (profil != 0)
        return -3;
    c->profil = 0;
    memcpy(c->etat, cle, 64);
    return 0;
}

int sl_aead_encrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad, size_t aadlen,
                        const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag)
{
    if (c->profil != 0 || aead(perm1, c->etat, nonce, aad, aadlen, pt, len, 0, ct, tag))
        return -3;
    return 0;
}

int sl_aead_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                    size_t aadlen, const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag)
{
    if (profil != 0 || aead(perm1, cle, nonce, aad, aadlen, pt, len, 0, ct, tag))
        return -3;
    return 0;
}

int sl_aead_decrypt_ctx(const sl_aead_cle_t *c, const uint8_t nonce[SL_NONCE], const uint8_t *aad, size_t aadlen,
                        const uint8_t *ct, size_t len, const uint8_t *tag, uint8_t *pt)
{
    if (c->profil != 0 || !longueurs_admises(aadlen, len))
        return -3;
    return aead_ouvrir(c->etat, nonce, aad, aadlen, ct, len, tag, pt);
}

int sl_aead_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                    size_t aadlen, const uint8_t *ct, size_t len, const uint8_t *tag, uint8_t *pt)
{
    if (profil != 0 || !longueurs_admises(aadlen, len))
        return -3;
    return aead_ouvrir(cle, nonce, aad, aadlen, ct, len, tag, pt);
}

int sl_aead_p_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                      size_t aadlen, const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag)
{
    if (profil != 0 || aeadp(perm1, cle, nonce, aad, aadlen, pt, len, 0, ct, tag))
        return -3;
    return 0;
}

int sl_aead_p_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                      size_t aadlen, const uint8_t *ct, size_t len, const uint8_t *tag, uint8_t *pt)
{
    if (profil != 0 || !longueurs_admises(aadlen, len))
        return -3;
    return aeadp_ouvrir(cle, nonce, aad, aadlen, ct, len, tag, pt);
}

/* ------------------------------------------------------------ lots de messages */
/* Chiffrement : si les n messages ont la même longueur et les mêmes données associées et qu'il y en a au moins 32, ils
 * sont rassemblés dans des tampons contigus et passent par aead_multi (lots de 32 et de 256 états) ; sinon un message par
 * tâche. Mêmes sorties que sl_aead_encrypt message par message (contrôlé). */
static int multi_uniforme(size_t n, const uint8_t *const *aads, const size_t *aadlens, const size_t *lens)
{
    if (n < 32)
        return 0;
    for (size_t i = 1; i < n; i++) {
        if (lens[i] != lens[0] || (aadlens ? aadlens[i] : 0) != (aadlens ? aadlens[0] : 0))
            return 0;
        size_t la = aadlens ? aadlens[0] : 0;
        if (la && memcmp(aads[i], aads[0], la))
            return 0;
    }
    return 1;
}

static int aead_encrypt_multi_cles(size_t n, const uint8_t *cles, size_t pas_cle, const uint8_t *nonces,
                                   const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                                   const size_t *lens, uint8_t *const *cts, uint8_t *tags)
{
    for (size_t i = 0; i < n; i++)
        if (!longueurs_admises(aadlens ? aadlens[i] : 0, lens[i]))
            return -3;
    if (pas_cle == 64 && multi_uniforme(n, aads, aadlens, lens)) {
        const size_t len = lens[0], la = aadlens ? aadlens[0] : 0;
        uint8_t *in = len ? malloc(n * len) : NULL, *out = len ? malloc(n * len) : NULL;
        if (!len || (in && out && n <= SIZE_MAX / len)) {
            for (size_t i = 0; i < n; i++)
                if (len)
                    memcpy(in + i * len, pts[i], len);
            int rc = aead_multi(n, cles, nonces, la ? aads[0] : NULL, la, in, len, out, tags);
            for (size_t i = 0; i < n && !rc; i++)
                if (len)
                    memcpy(cts[i], out + i * len, len);
            if (in)
                sl_effacer(in, n * len);
            free(in);
            free(out);
            return rc ? -3 : 0;
        }
        free(in);
        free(out);
    }
#pragma omp parallel for schedule(dynamic)
    for (long i = 0; i < (long)n; i++)
        aead(perm1, cles + (size_t)i * pas_cle, nonces + (size_t)i * SL_NONCE, aads ? aads[i] : NULL,
             aadlens ? aadlens[i] : 0, pts[i], lens[i], 0, cts[i], tags + (size_t)i * 32);
    return 0;
}

static int aead_decrypt_multi_cles(size_t n, const uint8_t *cles, size_t pas_cle, const uint8_t *nonces,
                                   const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                                   const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes)
{
    for (size_t i = 0; i < n; i++)
        if (!longueurs_admises(aadlens ? aadlens[i] : 0, lens[i]))
            return -3;
#pragma omp parallel for schedule(dynamic)
    for (long i = 0; i < (long)n; i++)
        codes[i] = aead_ouvrir(cles + (size_t)i * pas_cle, nonces + (size_t)i * SL_NONCE, aads ? aads[i] : NULL,
                               aadlens ? aadlens[i] : 0, cts[i], lens[i], tags + (size_t)i * 32, pts[i]);
    return 0;
}

int sl_aead_encrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                          const size_t *lens, uint8_t *const *cts, uint8_t *tags)
{
    if (profil != 0)
        return -3;
    return aead_encrypt_multi_cles(n, cles, 64, nonces, aads, aadlens, pts, lens, cts, tags);
}

int sl_aead_decrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                          const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes)
{
    if (profil != 0)
        return -3;
    return aead_decrypt_multi_cles(n, cles, 64, nonces, aads, aadlens, cts, lens, tags, pts, codes);
}

int sl_aead_encrypt_multi_ctx(const sl_aead_cle_t *c, size_t n, const uint8_t *nonces,
                              const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                              const size_t *lens, uint8_t *const *cts, uint8_t *tags)
{
    if (c->profil != 0)
        return -3;
    return aead_encrypt_multi_cles(n, c->etat, 0, nonces, aads, aadlens, pts, lens, cts, tags);
}

int sl_aead_decrypt_multi_ctx(const sl_aead_cle_t *c, size_t n, const uint8_t *nonces,
                              const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                              const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes)
{
    if (c->profil != 0)
        return -3;
    return aead_decrypt_multi_cles(n, c->etat, 0, nonces, aads, aadlens, cts, lens, tags, pts, codes);
}

/* ------------------------------------------------------------ mode TE (docs/SPEC.md § 2.7, V06_MODES.md § 1) */
/* Couche de la v0.5, inchangée : elle ne dépend ni de la permutation ni du débit. Sur la sortie X de l'AEAD, coupée en
 * blocs de 64 octets : 7 octets de parité par bloc (C₀, puis 8 syndromes de Hamming, un par plan de bits). Le
 * déchiffrement corrige au plus un octet altéré par bloc, refuse les syndromes incohérents, puis vérifie le tag sur X
 * corrigé. Le tag reste la seule garantie d'intégrité ; les parités ne corrigent que des erreurs accidentelles. */
size_t sl_te_par_len(size_t len) { return 7 * (len / 64 + (len % 64 != 0)); }

static void syndromes(const uint8_t *b, uint8_t *acc, uint8_t syn[8])
{
    uint8_t a = 0;
    memset(syn, 0, 8);
    for (int j = 0; j < 64; j++) {
        a ^= b[j];
        if (j)
            for (int k = 0; k < 8; k++)
                if (b[j] >> k & 1)
                    syn[k] ^= (uint8_t)j;
    }
    *acc = a;
}

static void bloc_te(const uint8_t *ct, size_t len, size_t i, uint8_t b[64])
{
    size_t k = len - 64 * i < 64 ? len - 64 * i : 64;
    memset(b, 0, 64);
    memcpy(b, ct + 64 * i, k);
}

int sl_te_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                  size_t aadlen, const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *par, uint8_t *tag,
                  uint8_t meta[8])
{
    int rc = sl_aead_encrypt(profil, cle, nonce, aad, aadlen, pt, len, ct, tag);
    if (rc)
        return rc;
    for (size_t i = 0; i < (len + 63) / 64; i++) {
        uint8_t b[64], acc, syn[8];
        bloc_te(ct, len, i, b);
        syndromes(b, &acc, syn);
        uint64_t bits = 0;
        for (int k = 7; k >= 0; k--)
            bits = (bits << 6) | syn[k];
        par[7 * i] = acc;
        for (int k = 0; k < 6; k++)
            par[7 * i + 1 + k] = (uint8_t)(bits >> (8 * (5 - k)));
    }
    for (int k = 0; k < 8; k++)
        meta[k] = (uint8_t)((uint64_t)len >> (8 * (7 - k)));
    return 0;
}

int sl_te_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                  size_t aadlen, uint8_t *ct, size_t len, const uint8_t *par, size_t parlen, const uint8_t *tag,
                  const uint8_t meta[8], uint8_t *pt, size_t *corrections, size_t *ncorr)
{
    size_t nb = len / 64 + (len % 64 != 0);
    uint64_t lm = 0;
    for (int k = 0; k < 8; k++)
        lm = (lm << 8) | meta[k];
    *ncorr = 0;
    if (profil != 0 || !longueurs_admises(aadlen, len))
        return -3;
    if (parlen != 7 * nb || lm != len)
        return -2;
    for (int applique = 0; applique < 2; applique++)   /* passe 0 : tout valider ; passe 1 : corriger */
        for (size_t i = 0; i < nb; i++) {
            uint8_t b[64], acc, syn[8], d[8];
            bloc_te(ct, len, i, b);
            syndromes(b, &acc, syn);
            uint64_t bits = 0;
            for (int k = 0; k < 6; k++)
                bits = (bits << 8) | par[7 * i + 1 + k];
            int nul = 1;
            for (int k = 0; k < 8; k++) {
                d[k] = syn[k] ^ (uint8_t)((bits >> (6 * k)) & 0x3F);
                nul &= d[k] == 0;
            }
            uint8_t dm = acc ^ par[7 * i];
            if (dm == 0 && nul)
                continue;
            if (dm == 0)
                return -2;
            int pos = -1;                  /* tous les plans touchés concordent ? */
            for (int k = 0; k < 8; k++)
                if (d[k]) {
                    if (pos >= 0 && d[k] != pos)
                        return -2;
                    pos = d[k];
                }
            if (pos < 0)
                pos = 0;
            if (!applique)
                continue;
            size_t g = 64 * i + (size_t)pos;
            if (g < len)                   /* (une correction du bourrage est sans effet) */
                ct[g] ^= dm;
            corrections[(*ncorr)++] = g;
        }
    return sl_aead_decrypt(profil, cle, nonce, aad, aadlen, ct, len, tag, pt);
}
