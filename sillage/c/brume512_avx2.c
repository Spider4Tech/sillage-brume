/* SILLAGE C — noyaux SIMD de BRUME-512, AVX2 ou NEON (mêmes sorties que brume512.c).
 *
 * 1. br_permuter_avx2 : UN état, CONSTANT-TIME. L'état (128 nibbles, un par
 *    octet) tient dans 4 registres ; S-box et log/exp de GF(16) par
 *    vpshufb (tables EN REGISTRE) ; diffusion = échange de moitiés et
 *    rotations d'octets à constantes immédiates (structure de Cayley de
 *    D128 : brume512_simd.h). Aucun accès mémoire ni branchement ne dépend
 *    de l'état.
 * 2. br_permuter_lot : 32 états à la fois (« vertical » : le registre v
 *    contient le nibble v des 32 états) ; S-box et produits par vpshufb ;
 *    diffusion déroulée. Également constant-time.
 * 3. AEAD et hachage par lots : chaque message suit son propre duplex
 *    (machine à états identique à brume512.c) ; les 32 voies partagent les
 *    appels à la permutation. Lots répartis sur les cœurs (OpenMP).
 */
#include <stdlib.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "brume512_tables.h"
#include "sillage.h"

#ifdef __AVX2__
#include <immintrin.h>

#include "brume512_simd.h"

#define BC16(t) _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)(t)))
#define LD(p) _mm256_loadu_si256((const __m256i *)(p))

/* (A‖B)[i + K] pour i < 32, K littéral dans [0, 32) */
#define ROT(A, B, K)                                                              \
    ((K) == 0 ? (A)                                                               \
     : (K) < 16 ? _mm256_alignr_epi8(_mm256_permute2x128_si256(A, B, 0x21), A, (K) & 15) \
                : _mm256_alignr_epi8(B, _mm256_permute2x128_si256(A, B, 0x21), (K) & 15))

/* c ⊙ y = exp(log c + log y) ; log 0 a le bit 7 → vpshufb rend 0 */
#define MULLOG(Lv, LCv)                                                           \
    ({ __m256i s_ = _mm256_add_epi8(Lv, LCv);                                     \
       s_ = _mm256_min_epu8(s_, _mm256_sub_epi8(s_, _mm256_set1_epi8(15)));        \
       _mm256_shuffle_epi8(EXPv, s_); })
#define MULG(R, g, c) MULLOG(R, LCG[g][c])

static inline void deballer4(const uint8_t *p, __m256i x[4])
{
    const __m256i m = _mm256_set1_epi8(15);
    for (int h = 0; h < 2; h++) {
        __m256i P = LD(p + 32 * h);
        __m256i lo = _mm256_and_si256(P, m), hi = _mm256_and_si256(_mm256_srli_epi16(P, 4), m);
        __m256i r0 = _mm256_unpacklo_epi8(lo, hi), r1 = _mm256_unpackhi_epi8(lo, hi);
        x[2 * h] = _mm256_permute2x128_si256(r0, r1, 0x20);
        x[2 * h + 1] = _mm256_permute2x128_si256(r0, r1, 0x31);
    }
}

static inline void emballer4(const __m256i x[4], uint8_t *p)
{
    const __m256i f = _mm256_set1_epi16(0x1001);
    for (int h = 0; h < 2; h++) {
        __m256i r0 = _mm256_permute2x128_si256(x[2 * h], x[2 * h + 1], 0x20);
        __m256i r1 = _mm256_permute2x128_si256(x[2 * h], x[2 * h + 1], 0x31);
        __m256i a = _mm256_maddubs_epi16(r0, f), b = _mm256_maddubs_epi16(r1, f);
        _mm256_storeu_si256((__m256i *)(p + 32 * h), _mm256_packus_epi16(a, b));
    }
}

static uint8_t LOGS[16];        /* log ∘ S : la valeur S(x ⊕ rc) ne sert qu'à son log */

void br_tours_avx2(uint64_t w[8], int R)
{
    const __m256i LOGSv = BC16(LOGS), EXPv = BC16(BR_EXP);
    __m256i LCS[4], LCG[BR_NB_GEN][4], x[4], L[4], acc[4];
    for (int c = 0; c < 4; c++) {
        LCS[c] = LD(BR_LC_SELF + 32 * c);
        for (int g = 0; g < BR_NB_GEN; g++)
            LCG[g][c] = LD(BR_LC_GEN[g] + 32 * c);
    }
    deballer4((const uint8_t *)w, x);
    for (int r = 0; r < R; r++) {
        for (int c = 0; c < 4; c++) {
            L[c] = _mm256_shuffle_epi8(LOGSv, _mm256_xor_si256(x[c], LD(BR_RC[r] + 32 * c)));
            acc[c] = MULLOG(L[c], LCS[c]);
        }
        BR_DIFFUSION_H(L, acc, MULG, ROT);
        memcpy(x, acc, sizeof x);
    }
    emballer4(x, (uint8_t *)w);
}

void br_permuter_avx2(uint64_t w[8]) { br_tours_avx2(w, BR_TOURS); }

/* ------------------------------------------------- 32 états (vertical) */
static __m256i TS[BR_TOURS][BR_N];    /* x → S(x ⊕ RC[r][v]) */
static __m256i TG[16];                /* y → c·y */

void br_init_avx2(void)
{
    uint8_t t[32];
    for (int x = 0; x < 16; x++)
        LOGS[x] = BR_LOG[BR_SBOX[x]];
    for (int r = 0; r < BR_TOURS; r++)
        for (int v = 0; v < BR_N; v++) {
            for (int x = 0; x < 32; x++)
                t[x] = BR_SBOX[(x & 15) ^ BR_RC[r][v]];
            TS[r][v] = LD(t);
        }
    for (int c = 0; c < 16; c++) {
        for (int x = 0; x < 32; x++) {
            int a = c, b = x & 15, p = 0;
            for (int i = 0; i < 4; i++) {
                if (b & 1) p ^= a;
                b >>= 1; a <<= 1;
                if (a & 0x10) a ^= BR_POLY;
            }
            t[x] = (uint8_t)(p & 15);
        }
        TG[c] = LD(t);
    }
}

/* Transposition 16 × 16 octets (échelle de dépliages) : r[i] ligne i →
 * r[j] colonne j. */
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

/* e[q] : état empaqueté de la voie q (64 octets), q < 32. T[b][q] = e[q][b]
 * (deux fois 4 blocs 16 × 16), puis nibbles : s[2b] = T[b] & 15,
 * s[2b+1] = T[b] >> 4. */
/* aligné : selon son adresse (0x30 mod 64), ce noyau de 18 Ko perd 11 % sur Zen 3 (mesuré) */
__attribute__((aligned(64))) void br_permuter_lot(uint8_t (*e)[64])
{
    __m256i s[BR_N], y[BR_N];
    uint8_t T[64][32] __attribute__((aligned(32)));
    __m128i r[16];
    const __m256i m4 = _mm256_set1_epi8(15);
    for (int Q = 0; Q < 2; Q++)
        for (int K = 0; K < 4; K++) {
            for (int i = 0; i < 16; i++)
                r[i] = _mm_loadu_si128((const __m128i *)(e[16 * Q + i] + 16 * K));
            tr16(r);
            for (int j = 0; j < 16; j++)
                _mm_store_si128((__m128i *)(T[16 * K + j] + 16 * Q), r[j]);
        }
    for (int b = 0; b < 64; b++) {
        __m256i x = _mm256_load_si256((const __m256i *)T[b]);
        s[2 * b] = _mm256_and_si256(x, m4);
        s[2 * b + 1] = _mm256_and_si256(_mm256_srli_epi16(x, 4), m4);
    }
    for (int rr = 0; rr < BR_TOURS; rr++) {
        for (int v = 0; v < BR_N; v++)
            y[v] = _mm256_shuffle_epi8(TS[rr][v], s[v]);
        BR_DIFFUSION_LOT(y, s, TG);
    }
    for (int b = 0; b < 64; b++)
        _mm256_store_si256((__m256i *)T[b], _mm256_or_si256(s[2 * b], _mm256_slli_epi16(s[2 * b + 1], 4)));
    for (int Q = 0; Q < 2; Q++)
        for (int K = 0; K < 4; K++) {
            for (int j = 0; j < 16; j++)
                r[j] = _mm_load_si128((const __m128i *)(T[16 * K + j] + 16 * Q));
            tr16(r);
            for (int i = 0; i < 16; i++)
                _mm_storeu_si128((__m128i *)(e[16 * Q + i] + 16 * K), r[i]);
        }
}

#elif defined(__ARM_NEON)
#include <arm_neon.h>

#include "brume512_simd.h"

/* 4. NEON : mêmes noyaux, 16 octets par registre. vqtbl1q_u8 rend 0 pour un indice ≥ 16, comme vpshufb pour
 *    le bit 7 (log 0). Constant-time par construction : ni branchement ni accès mémoire selon l'état. Conformité
 *    vérifiée sous qemu (tests/test_c_simd.py) ; temps constant et débit non mesurés, faute de machine ARM. */
#define EXT_N(A, B, K) vextq_u8(A, B, K)
#define MULLOG_N(Lv, LCv)                                                         \
    ({ uint8x16_t s_ = vaddq_u8(Lv, LCv);                                         \
       vqtbl1q_u8(EXPv, vminq_u8(s_, vsubq_u8(s_, vdupq_n_u8(15)))); })
#define MULG_N(R, g, c) MULLOG_N(R, vld1q_u8(BR_LC_GEN[g] + 16 * (c)))

static uint8_t LOGS[16];

void br_permuter_neon(uint64_t w[8])
{
    const uint8x16_t LOGSv = vld1q_u8(LOGS), EXPv = vld1q_u8(BR_EXP), m = vdupq_n_u8(15);
    uint8x16_t x[8], L[8], acc[8];
    const uint8_t *p = (const uint8_t *)w;
    for (int h = 0; h < 4; h++) {
        uint8x16_t P = vld1q_u8(p + 16 * h), lo = vandq_u8(P, m), hi = vshrq_n_u8(P, 4);
        x[2 * h] = vzip1q_u8(lo, hi);
        x[2 * h + 1] = vzip2q_u8(lo, hi);
    }
    for (int r = 0; r < BR_TOURS; r++) {
        for (int c = 0; c < 8; c++) {
            L[c] = vqtbl1q_u8(LOGSv, veorq_u8(x[c], vld1q_u8(BR_RC[r] + 16 * c)));
            acc[c] = MULLOG_N(L[c], vld1q_u8(BR_LC_SELF + 16 * c));
        }
        BR_DIFFUSION_N(L, acc, MULG_N, EXT_N);
        memcpy(x, acc, sizeof x);
    }
    for (int h = 0; h < 4; h++) {
        uint8x16_t lo = vuzp1q_u8(x[2 * h], x[2 * h + 1]), hi = vuzp2q_u8(x[2 * h], x[2 * h + 1]);
        vst1q_u8((uint8_t *)w + 16 * h, vorrq_u8(lo, vshlq_n_u8(hi, 4)));
    }
}

static uint8_t TG8[16][16] __attribute__((aligned(16)));   /* y → c·y */

void br_init_avx2(void)
{
    for (int x = 0; x < 16; x++)
        LOGS[x] = BR_LOG[BR_SBOX[x]];
    for (int c = 0; c < 16; c++)
        for (int x = 0; x < 16; x++) {
            int a = c, b = x, q = 0;
            for (int i = 0; i < 4; i++) {
                if (b & 1) q ^= a;
                b >>= 1; a <<= 1;
                if (a & 0x10) a ^= BR_POLY;
            }
            TG8[c][x] = (uint8_t)(q & 15);
        }
}

#define Z8(a, b, o) vzip##o##q_u8(a, b)
#define Z16(a, b, o) vreinterpretq_u8_u16(vzip##o##q_u16(vreinterpretq_u16_u8(a), vreinterpretq_u16_u8(b)))
#define Z32(a, b, o) vreinterpretq_u8_u32(vzip##o##q_u32(vreinterpretq_u32_u8(a), vreinterpretq_u32_u8(b)))
#define Z64(a, b, o) vreinterpretq_u8_u64(vzip##o##q_u64(vreinterpretq_u64_u8(a), vreinterpretq_u64_u8(b)))

static inline void tr16(uint8x16_t r[16])
{
    uint8x16_t a[16], b[16], c[16];
    for (int k = 0; k < 8; k++) {
        a[2 * k] = Z8(r[2 * k], r[2 * k + 1], 1);
        a[2 * k + 1] = Z8(r[2 * k], r[2 * k + 1], 2);
    }
    for (int m = 0; m < 4; m++) {
        b[4 * m] = Z16(a[4 * m], a[4 * m + 2], 1);
        b[4 * m + 1] = Z16(a[4 * m], a[4 * m + 2], 2);
        b[4 * m + 2] = Z16(a[4 * m + 1], a[4 * m + 3], 1);
        b[4 * m + 3] = Z16(a[4 * m + 1], a[4 * m + 3], 2);
    }
    for (int g = 0; g < 2; g++)
        for (int i = 0; i < 4; i++) {
            c[8 * g + 2 * i] = Z32(b[8 * g + i], b[8 * g + 4 + i], 1);
            c[8 * g + 2 * i + 1] = Z32(b[8 * g + i], b[8 * g + 4 + i], 2);
        }
    for (int i = 0; i < 8; i++) {
        r[2 * i] = Z64(c[i], c[8 + i], 1);
        r[2 * i + 1] = Z64(c[i], c[8 + i], 2);
    }
}

/* 16 états à la fois (vertical) ; un lot de 32 en fait deux */
static void lot16(uint8_t (*e)[64])
{
    uint8x16_t s[BR_N], y[BR_N], r[16], TG[16];
    const uint8x16_t m4 = vdupq_n_u8(15), SB = vld1q_u8(BR_SBOX);
    for (int c = 0; c < 16; c++)
        TG[c] = vld1q_u8(TG8[c]);
    for (int K = 0; K < 4; K++) {
        for (int i = 0; i < 16; i++)
            r[i] = vld1q_u8(e[i] + 16 * K);
        tr16(r);
        for (int j = 0; j < 16; j++) {
            s[2 * (16 * K + j)] = vandq_u8(r[j], m4);
            s[2 * (16 * K + j) + 1] = vshrq_n_u8(r[j], 4);
        }
    }
    for (int rr = 0; rr < BR_TOURS; rr++) {
        for (int v = 0; v < BR_N; v++)
            y[v] = vqtbl1q_u8(SB, veorq_u8(s[v], vdupq_n_u8(BR_RC[rr][v])));
        BR_DIFFUSION_LOT_N(y, s, TG);
    }
    for (int K = 0; K < 4; K++) {
        for (int j = 0; j < 16; j++)
            r[j] = vorrq_u8(s[2 * (16 * K + j)], vshlq_n_u8(s[2 * (16 * K + j) + 1], 4));
        tr16(r);
        for (int i = 0; i < 16; i++)
            vst1q_u8(e[i] + 16 * K, r[i]);
    }
}

void br_permuter_lot(uint8_t (*e)[64])
{
    lot16(e);
    lot16(e + 16);
}

#else  /* sans SIMD : repli sur la permutation de référence */
void br_init_avx2(void) {}
void br_permuter_lot(uint8_t (*e)[64])
{
    for (int q = 0; q < 32; q++)
        sl_brume_permute(e[q]);
}
#endif

void sl_brume_permute_lot(uint8_t etats[32][64]) { br_permuter_lot(etats); }

/* -------------------------------------------- AEAD par lots (32 voies) */
static const struct { int debit, tag, lam; } PROF[2] = {{32, 16, 128}, {16, 32, 256}};
enum { P_IV, P_KN, P_AAD, P_DATA, P_TEXTE, P_LEN, P_TAG, P_FIN };

typedef struct {
    int phase, dech;
    size_t b, nb, pos, len, aadlen;
    const uint8_t *in, *aad;
    uint8_t *out, *tag, kn[64 + SL_NONCE], l8[8];
} voie_t;

/* XOR du bloc b de (d ‖ 0x01 ‖ 0*) dans le débit */
static void bloc_pad(uint8_t *st, const uint8_t *d, size_t len, size_t b, int rb)
{
    for (int k = 0; k < rb; k++) {
        size_t i = b * (size_t)rb + (size_t)k;
        st[k] ^= i < len ? d[i] : (i == len ? 0x01 : 0);
    }
}

/* Opérations de la voie jusqu'au prochain appel à P : 1 si P est requise,
 * 0 quand le tag est produit (miroir exact de duplex() dans brume512.c). */
static int etape(voie_t *v, uint8_t *st, int profil)
{
    int rb = PROF[profil].debit, tl = PROF[profil].tag;
    switch (v->phase) {
    case P_IV:                        /* état P(IV) précalculé : pas de permutation */
        memcpy(st, br_etat_iv(profil), 64);
        v->phase = P_KN; v->b = 0; v->nb = (64 + SL_NONCE) / (size_t)rb + 1;
        /* fall through */
    case P_KN:
    case P_AAD: {
        const uint8_t *d = v->phase == P_KN ? v->kn : v->aad;
        size_t l = v->phase == P_KN ? 64 + SL_NONCE : v->aadlen;
        bloc_pad(st, d, l, v->b, rb);
        if (++v->b == v->nb) {
            st[63] ^= (uint8_t)((v->phase == P_KN ? 0 : 1) << 4);
            if (v->phase == P_KN) {
                v->phase = P_AAD; v->b = 0; v->nb = v->aadlen / (size_t)rb + 1;
            } else {
                v->phase = P_DATA; v->pos = 0;
            }
        }
        return 1;
    }
    case P_DATA: {
        size_t r = v->len - v->pos < (size_t)rb ? v->len - v->pos : (size_t)rb;
        for (size_t k = 0; k < r; k++) {
            uint8_t o = v->in[v->pos + k] ^ st[k];
            v->out[v->pos + k] = o;
            st[k] = v->dech ? o : v->in[v->pos + k];     /* débit = clair */
        }
        if (r < (size_t)rb) {
            st[r] ^= 0x01;
            v->phase = P_TEXTE;
        }
        v->pos += r;
        return 1;
    }
    case P_TEXTE:
        st[63] ^= 2 << 4;
        v->phase = P_LEN;
        return 1;
    case P_LEN:
        for (int k = 0; k < 8; k++)
            v->l8[k] = (uint8_t)((uint64_t)v->len >> (8 * k));
        bloc_pad(st, v->l8, 8, 0, rb);
        st[63] ^= 4 << 4;
        v->phase = P_TAG; v->pos = 0;
        return 1;
    case P_TAG: {
        int k = tl - (int)v->pos < rb ? tl - (int)v->pos : rb;
        memcpy(v->tag + v->pos, st, (size_t)k);
        v->pos += (size_t)rb;
        if ((int)v->pos < tl)
            return 1;
        v->phase = P_FIN;
        return 0;
    }
    }
    return 0;
}

static void lot_aead(int profil, voie_t *v, int n, const sl_aead_cle_t *c)
{
    uint8_t st[32][64] __attribute__((aligned(32)));
    memset(st, 0, sizeof st);
    for (int i = 0; c && i < n; i++)                 /* reprise après la clé */
        memcpy(st[i], c->etat, 64);
    for (;;) {
        int besoin = 0;
        for (int i = 0; i < n; i++)
            if (v[i].phase != P_FIN)
                besoin |= etape(&v[i], st[i], profil);
        if (!besoin)
            break;
        br_permuter_lot(st);
    }
    sl_effacer(st, sizeof st);
}

typedef struct { size_t len, idx; } cle_tri_t;
static int cmp_len(const void *a, const void *b)
{
    size_t x = ((const cle_tri_t *)a)->len, y = ((const cle_tri_t *)b)->len;
    return x < y ? -1 : x > y;
}

/* ordre de traitement : par longueur, pour que les voies d'un lot finissent ensemble */
static size_t *ordre(size_t n, const size_t *lens)
{
    cle_tri_t *t = malloc(n * sizeof *t);
    size_t *o = malloc(n * sizeof *o);
    for (size_t i = 0; i < n; i++) { t[i].len = lens[i]; t[i].idx = i; }
    qsort(t, n, sizeof *t, cmp_len);
    for (size_t i = 0; i < n; i++)
        o[i] = t[i].idx;
    free(t);
    return o;
}

/* Lots de 32 (≈ 0,18 µs par état et par permutation) ou un message par
 * cœur avec le noyau d'un état (≈ 0,41 µs) : on retient l'estimation la
 * plus courte (peu de messages → tous les cœurs restent occupés). */
static int par_lots(size_t n)
{
#if defined(__AVX2__) || defined(__ARM_NEON)   /* NEON : mêmes rapports supposés, non mesurés */
    size_t T = 1;
#ifdef _OPENMP
    T = (size_t)omp_get_max_threads();
#endif
    size_t lots = (n + 31) / 32;
    return ((lots + T - 1) / T) * 32 * 18 <= ((n + T - 1) / T) * 41;
#else
    (void)n;
    return 0;
#endif
}

/* c non NULL : même clé pour tous (contexte précalculé), cles ignoré */
static int aead_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                      const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *in,
                      const size_t *lens, uint8_t *const *out, uint8_t *tags, int dech, int *codes,
                      const sl_aead_cle_t *c)
{
    if (profil < 0 || profil > 1)
        return -3;
    size_t tl = (size_t)PROF[profil].tag;
    if (!par_lots(n)) {
        long nn = (long)n;
#pragma omp parallel for schedule(dynamic)
        for (long j = 0; j < nn; j++) {
            const uint8_t *a = aads ? aads[j] : NULL;
            size_t al = aadlens ? aadlens[j] : 0;
            if (c && dech)
                codes[j] = sl_aead_decrypt_ctx(c, nonces + SL_NONCE * j, a, al, in[j], lens[j],
                                               tags + tl * (size_t)j, out[j]);
            else if (c)
                sl_aead_encrypt_ctx(c, nonces + SL_NONCE * j, a, al, in[j], lens[j], out[j], tags + tl * (size_t)j);
            else if (dech)
                codes[j] = sl_aead_decrypt(profil, cles + 64 * j, nonces + SL_NONCE * j, a, al, in[j], lens[j],
                                           tags + tl * (size_t)j, out[j]);
            else
                sl_aead_encrypt(profil, cles + 64 * j, nonces + SL_NONCE * j, a, al, in[j], lens[j], out[j],
                                tags + tl * (size_t)j);
        }
        return 0;
    }
    size_t *o = ordre(n, lens);
    long nl = (long)((n + 31) / 32);
#pragma omp parallel for schedule(dynamic)
    for (long g = 0; g < nl; g++) {
        voie_t v[32];
        uint8_t tcalc[32][32];
        int m = (int)(n - 32 * (size_t)g < 32 ? n - 32 * (size_t)g : 32);
        for (int i = 0; i < m; i++) {
            size_t j = o[32 * (size_t)g + (size_t)i];
            memset(&v[i], 0, sizeof v[i]);
            v[i].phase = P_IV; v[i].dech = dech;
            if (c) {                                 /* clé déjà absorbée */
                v[i].phase = P_KN;
                v[i].b = (size_t)(64 / PROF[profil].debit);
                v[i].nb = (64 + SL_NONCE) / (size_t)PROF[profil].debit + 1;
            } else
                memcpy(v[i].kn, cles + 64 * j, 64);
            memcpy(v[i].kn + 64, nonces + SL_NONCE * j, SL_NONCE);
            v[i].aad = aads ? aads[j] : NULL; v[i].aadlen = aadlens ? aadlens[j] : 0;
            v[i].in = in[j]; v[i].len = lens[j]; v[i].out = out[j];
            v[i].tag = dech ? tcalc[i] : tags + tl * j;
        }
        lot_aead(profil, v, m, c);
        if (dech)
            for (int i = 0; i < m; i++) {
                size_t j = o[32 * (size_t)g + (size_t)i];
                uint8_t d = 0;
                for (size_t k = 0; k < tl; k++)
                    d |= tcalc[i][k] ^ tags[tl * j + k];
                codes[j] = d ? -1 : 0;
                if (d)
                    memset(out[j], 0, lens[j]);
            }
        sl_effacer(v, sizeof v);
    }
    free(o);
    return 0;
}

int sl_aead_encrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                          const size_t *lens, uint8_t *const *cts, uint8_t *tags)
{
    return aead_multi(profil, n, cles, nonces, aads, aadlens, pts, lens, cts, tags, 0, NULL, NULL);
}

int sl_aead_decrypt_multi(int profil, size_t n, const uint8_t *cles, const uint8_t *nonces,
                          const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                          const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes)
{
    return aead_multi(profil, n, cles, nonces, aads, aadlens, cts, lens, pts, (uint8_t *)tags, 1, codes, NULL);
}

int sl_aead_encrypt_multi_ctx(const sl_aead_cle_t *c, size_t n, const uint8_t *nonces,
                              const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *pts,
                              const size_t *lens, uint8_t *const *cts, uint8_t *tags)
{
    return aead_multi(c->profil, n, NULL, nonces, aads, aadlens, pts, lens, cts, tags, 0, NULL, c);
}

int sl_aead_decrypt_multi_ctx(const sl_aead_cle_t *c, size_t n, const uint8_t *nonces,
                              const uint8_t *const *aads, const size_t *aadlens, const uint8_t *const *cts,
                              const size_t *lens, const uint8_t *tags, uint8_t *const *pts, int *codes)
{
    return aead_multi(c->profil, n, NULL, nonces, aads, aadlens, cts, lens, pts, (uint8_t *)tags, 1, codes, c);
}

/* ------------------------------------------------ hachage par lots */
typedef struct { size_t b, nb, len, o, outlen; const uint8_t *m; uint8_t *out; int fini; } hvoie_t;

static int hetape(hvoie_t *h, uint8_t *st)
{
    if (h->b < h->nb) {                       /* absorption, bourrage 0x01 0* */
        bloc_pad(st, h->m, h->len, h->b++, 32);
        return 1;
    }
    size_t k = h->outlen - h->o < 32 ? h->outlen - h->o : 32;
    memcpy(h->out + h->o, st, k);
    h->o += 32;
    if (h->o < h->outlen)
        return 1;
    h->fini = 1;
    return 0;
}

void sl_hash_multi(size_t n, const uint8_t *const *msgs, const size_t *lens, uint8_t *outs, size_t outlen)
{
    if (!par_lots(n)) {
        long nn = (long)n;
#pragma omp parallel for schedule(dynamic)
        for (long j = 0; j < nn; j++)
            sl_hash(msgs[j], lens[j], outs + outlen * (size_t)j, outlen);
        return;
    }
    size_t *o = ordre(n, lens);
    long nl = (long)((n + 31) / 32);
#pragma omp parallel for schedule(dynamic)
    for (long g = 0; g < nl; g++) {
        hvoie_t h[32];
        uint8_t st[32][64] __attribute__((aligned(32)));
        memset(st, 0, sizeof st);
        int m = (int)(n - 32 * (size_t)g < 32 ? n - 32 * (size_t)g : 32);
        for (int i = 0; i < m; i++) {
            size_t j = o[32 * (size_t)g + (size_t)i];
            h[i] = (hvoie_t){0, lens[j] / 32 + 1, lens[j], 0, outlen, msgs[j], outs + outlen * j, 0};
        }
        for (;;) {
            int besoin = 0;
            for (int i = 0; i < m; i++)
                if (!h[i].fini)
                    besoin |= hetape(&h[i], st[i]);
            if (!besoin)
                break;
            br_permuter_lot(st);
        }
    }
    free(o);
}

/* ------------------------------------------------ hachage arborescent */
enum { DOM_FEUILLE = 8, DOM_RACINE = 9, DOM_SEUL = 10 };
#define ARBRE_BLOC 8192
#define ARBRE_CV 32

/* m feuilles pleines consécutives (m ≤ 32) en un lot : 256 blocs, puis le
 * bloc de bourrage 0x01 ‖ 0* avec le domaine FEUILLE ; CV = 32 premiers octets. */
static void feuilles_lot(const uint8_t *m0, int m, uint8_t *cv)
{
    uint8_t st[32][64] __attribute__((aligned(32)));
    memset(st, 0, sizeof st);
    for (int b = 0; b < ARBRE_BLOC / 32; b++) {
        for (int i = 0; i < m; i++) {
            const uint8_t *src = m0 + (size_t)i * ARBRE_BLOC + 32 * (size_t)b;
            for (int k = 0; k < 32; k++)
                st[i][k] ^= src[k];
        }
        br_permuter_lot(st);
    }
    for (int i = 0; i < m; i++) {
        st[i][0] ^= 0x01;
        st[i][63] ^= DOM_FEUILLE << 4;
    }
    br_permuter_lot(st);
    for (int i = 0; i < m; i++)
        memcpy(cv + (size_t)i * ARBRE_CV, st[i], ARBRE_CV);
}

void sl_hash_arbre(const uint8_t *m, size_t len, uint8_t *out, size_t outlen)
{
    if (len <= ARBRE_BLOC) {
        br_eponge(m, len, DOM_SEUL, out, outlen);
        return;
    }
    size_t k = (len + ARBRE_BLOC - 1) / ARBRE_BLOC, pleines = len / ARBRE_BLOC;
    if (pleines == k)
        pleines--;                               /* la dernière feuille : traitée à part */
    size_t lr = ARBRE_CV * k + 12;
    uint8_t *racine = malloc(lr);
    if (par_lots(pleines)) {                     /* lots de 32 feuilles, un lot par cœur */
        long ng = (long)((pleines + 31) / 32);
#pragma omp parallel for schedule(dynamic)
        for (long g = 0; g < ng; g++) {
            size_t d = 32 * (size_t)g, nm = pleines - d < 32 ? pleines - d : 32;
            feuilles_lot(m + d * ARBRE_BLOC, (int)nm, racine + d * ARBRE_CV);
        }
    } else {                                     /* une feuille par cœur */
        long np = (long)pleines;
#pragma omp parallel for schedule(dynamic)
        for (long i = 0; i < np; i++)
            br_eponge(m + (size_t)i * ARBRE_BLOC, ARBRE_BLOC, DOM_FEUILLE, racine + (size_t)i * ARBRE_CV, ARBRE_CV);
    }
    for (size_t i = pleines; i < k; i++) {
        size_t l = len - i * ARBRE_BLOC < ARBRE_BLOC ? len - i * ARBRE_BLOC : ARBRE_BLOC;
        br_eponge(m + i * ARBRE_BLOC, l, DOM_FEUILLE, racine + i * ARBRE_CV, ARBRE_CV);
    }
    uint8_t *q = racine + ARBRE_CV * k;
    for (int i = 0; i < 8; i++)
        q[i] = (uint8_t)((uint64_t)k >> (56 - 8 * i));
    q[8] = 0; q[9] = 0; q[10] = ARBRE_BLOC >> 8; q[11] = ARBRE_BLOC & 0xFF;
    br_eponge(racine, lr, DOM_RACINE, out, outlen);
    free(racine);
}

/* ------------------------------------------------- AEAD parallèle
 * Tronc : IV parallèle, clé ‖ nonce, AAD → S_A (secret, son débit n'est jamais lu).
 * Feuille j : T ← P(P(S_A ⊕ (j sur 8 o ‖ 0x01 ‖ 0*) ⊕ 5·e₁₂₇) ⊕ 3·e₁₂₇), puis duplex absorbant le chiffré sur ses octets,
 *             dernier bloc (chiffré ‖ 0x01 ‖ 0*) avec le domaine 6 ; CV = 2λ premiers bits de l'état final.
 * Racine : S_A absorbe CV₀ ‖ … ‖ CV_{k−1} ‖ k ‖ ℓ (8 o chacun, bourrage 10*, domaine 4), puis le tag. */
enum { DOM_AAD_P = 1, DOM_FINAL_P = 4, DOM_DEPART_P = 3, DOM_FOURCHE_P = 5, DOM_FIN_FEUILLE_P = 6 };

/* moins de 15 voies : le noyau d'un état, appelé m fois, va plus vite qu'un lot (par_lots) */
static inline void p_voies(uint8_t (*st)[64], int m)
{
    if (m >= 15) {
        br_permuter_lot(st);
        return;
    }
    for (int q = 0; q < m; q++)
        sl_brume_permute(st[q]);
}

/* m feuilles consécutives de l octets chacune, à partir de la feuille j0 (m ≤ 32) */
static void feuilles_p(const uint64_t *sa, int rb, int cvl, size_t j0, int m, size_t l, const uint8_t *in, int dech,
                       uint8_t *out, uint8_t *cv)
{
    uint8_t st[32][64] __attribute__((aligned(32)));
    memset(st, 0, sizeof st);
    for (int q = 0; q < m; q++) {
        memcpy(st[q], sa, 64);
        for (int k = 0; k < 8; k++)
            st[q][k] ^= (uint8_t)((uint64_t)(j0 + (size_t)q) >> (8 * k));
        st[q][8] ^= 0x01;
        st[q][63] ^= DOM_FOURCHE_P << 4;
    }
    p_voies(st, m);
    for (int q = 0; q < m; q++)
        st[q][63] ^= DOM_DEPART_P << 4;
    p_voies(st, m);
    size_t o = 0;
    uint64_t e[4], z[4];                               /* copie : in et out peuvent se recouvrir */
    for (; o + (size_t)rb <= l; o += (size_t)rb) {
        for (int q = 0; q < m; q++) {
            memcpy(e, in + (size_t)q * SL_AEADP_FEUILLE + o, (size_t)rb);
            memcpy(z, st[q], (size_t)rb);
            for (int k = 0; k < rb / 8; k++)
                z[k] ^= e[k];
            memcpy(out + (size_t)q * SL_AEADP_FEUILLE + o, z, (size_t)rb);
            memcpy(st[q], dech ? z : e, (size_t)rb);   /* débit = clair : l'état a absorbé le chiffré */
        }
        p_voies(st, m);
    }
    size_t r = l - o;
    for (int q = 0; q < m; q++) {
        const uint8_t *ent = in + (size_t)q * SL_AEADP_FEUILLE + o;
        uint8_t *s = out + (size_t)q * SL_AEADP_FEUILLE + o;
        for (size_t k = 0; k < r; k++) {
            uint8_t x = ent[k], y = x ^ st[q][k];
            s[k] = y;
            st[q][k] ^= dech ? x : y;
        }
        st[q][r] ^= 0x01;
        st[q][63] ^= DOM_FIN_FEUILLE_P << 4;
    }
    p_voies(st, m);
    for (int q = 0; q < m; q++)
        memcpy(cv + (size_t)q * (size_t)cvl, st[q], (size_t)cvl);
    sl_effacer(st, sizeof st);
    sl_effacer(e, sizeof e);
    sl_effacer(z, sizeof z);
}

static int aead_p(int profil, const uint8_t *cle, const uint8_t *nonce, const uint8_t *aad, size_t aadlen,
                  const uint8_t *in, size_t len, int dech, uint8_t *out, uint8_t *tag)
{
    int rb = PROF[profil].debit, tl = PROF[profil].tag, cvl = PROF[profil].lam / 4;
    size_t k = len ? (len + SL_AEADP_FEUILLE - 1) / SL_AEADP_FEUILLE : 1, pleines = len / SL_AEADP_FEUILLE;
    uint8_t *cv = malloc((size_t)cvl * k), fin[16];
    if (!cv)
        return -3;
    uint64_t w[8], sa[8];
    memcpy(w, br_etat_iv(profil + 2), 64);
    br_absorber(w, rb, cle, 64, nonce, SL_NONCE, 0);
    br_absorber(w, rb, aad, aadlen, NULL, 0, DOM_AAD_P);
    memcpy(sa, w, 64);
    long nl = par_lots(pleines) ? (long)((pleines + 31) / 32) : (long)pleines;
    size_t pas = par_lots(pleines) ? 32 : 1;
#pragma omp parallel for schedule(dynamic) if (nl > 1)
    for (long g = 0; g < nl; g++) {
        size_t d = pas * (size_t)g, m = pleines - d < pas ? pleines - d : pas;
        feuilles_p(sa, rb, cvl, d, (int)m, SL_AEADP_FEUILLE, in + d * SL_AEADP_FEUILLE, dech,
                   out + d * SL_AEADP_FEUILLE, cv + d * (size_t)cvl);
    }
    if (pleines < k)
        feuilles_p(sa, rb, cvl, pleines, 1, len - pleines * SL_AEADP_FEUILLE, in + pleines * SL_AEADP_FEUILLE, dech,
                   out + pleines * SL_AEADP_FEUILLE, cv + pleines * (size_t)cvl);
    for (int i = 0; i < 8; i++) {
        fin[i] = (uint8_t)((uint64_t)k >> (8 * i));
        fin[8 + i] = (uint8_t)((uint64_t)len >> (8 * i));
    }
    br_absorber(w, rb, cv, (size_t)cvl * k, fin, 16, DOM_FINAL_P);
    for (int o = 0; o < tl; o += rb) {
        memcpy(tag + o, w, (size_t)(tl - o < rb ? tl - o : rb));
        if (o + rb < tl)
            sl_brume_permute((uint8_t *)w);
    }
    sl_effacer(w, 64);
    sl_effacer(sa, 64);
    sl_effacer(cv, (size_t)cvl * k);
    free(cv);
    return 0;
}

int sl_aead_p_encrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                      size_t aadlen, const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag)
{
    if (profil < 0 || profil > 1)
        return -3;
    return aead_p(profil, cle, nonce, aad, aadlen, pt, len, 0, ct, tag);
}

int sl_aead_p_decrypt(int profil, const uint8_t cle[64], const uint8_t nonce[SL_NONCE], const uint8_t *aad,
                      size_t aadlen, const uint8_t *ct, size_t len, const uint8_t *tag, uint8_t *pt)
{
    if (profil < 0 || profil > 1)
        return -3;
    uint8_t t[32], d = 0;
    int rc = aead_p(profil, cle, nonce, aad, aadlen, ct, len, 1, pt, t);
    if (rc)
        return rc;
    for (int i = 0; i < PROF[profil].tag; i++)
        d |= t[i] ^ tag[i];
    if (d) {
        memset(pt, 0, len);
        return -1;
    }
    return 0;
}
