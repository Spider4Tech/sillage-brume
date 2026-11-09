/*
 * BRUME-512 -- banc boomerang apparié à trois S-boxes.
 *
 * Pour chaque (graine, tour, combinaison, quartet), le même état x, la même
 * différence d'entrée alpha*e_i et la même différence intermédiaire
 * delta = de*M*e_j sont utilisés avec les trois S-boxes. On enregistre les
 * tableaux de contingence 2x2 nécessaires aux tests appariés de McNemar.
 *
 * ChaCha20 RFC 8439 est utilisé en génération pseudo-aléatoire par accès
 * direct (clé de 256 bits + nonce round/combinaison + compteur quartet).
 * Le résultat est indépendant du nombre de threads et de l'ordre OpenMP.
 *
 * Usage:
 *   brume_attaques_paired LQ NC ROUNDS THREADS SEED_HEX OUTDIR
 *   LQ: 1..32 (quartets = 2^LQ), SEED_HEX: exactement 64 caractères hex.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <omp.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif

#include "brume512_tables.h"

#define NBOX 3
#define PAIRS 3
#define MAX_ROUNDS 32

static const char *SBOX_NAMES[NBOX] = {"BRUME", "SBOX6", "SBOX_V3"};
static const char *PAIR_NAMES[PAIRS] = {
    "BRUME_vs_SBOX6", "BRUME_vs_SBOX_V3", "SBOX6_vs_SBOX_V3"
};
static const int PAIR_A[PAIRS] = {0, 0, 1};
static const int PAIR_B[PAIRS] = {1, 2, 2};

static const uint8_t SBOX[NBOX][16] = {
    {8, 9, 1, 10, 12, 4, 0, 6, 13, 15, 3, 7, 14, 2, 11, 5},
    {15, 2, 12, 13, 11, 7, 14, 3, 0, 4, 6, 5, 10, 8, 9, 1},
    {14, 9, 3, 6, 15, 11, 10, 8, 12, 4, 0, 5, 7, 1, 13, 2}
};
static uint8_t SBOX_INV[NBOX][16];

static uint8_t M[BR_N][BR_N], MI[BR_N][BR_N];
static alignas(64) uint64_t LIN_F[BR_N][16][8];
static alignas(64) uint64_t LIN_I[BR_N][16][8];

typedef struct {
    uint64_t zero[PAIRS][BR_N][4];
    uint64_t exact[PAIRS][4];
} local_counts_t;

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    for (int i = 0; i < 4; ++i) {
        if (b & 1u) r ^= a;
        b >>= 1;
        a <<= 1;
        if (a & 0x10u) a ^= BR_POLY;
    }
    return r & 15u;
}

static uint8_t gf_inv(uint8_t a)
{
    if (!a) return 0;
    for (uint8_t b = 1; b < 16; ++b)
        if (gf_mul(a, b) == 1) return b;
    return 0;
}

static int init_matrix(void)
{
    memset(M, 0, sizeof M);
    for (int e = 0; e < BR_ARETES; ++e)
        M[e / BR_DEG][BR_EI[e]] ^= BR_EC[e];

    uint8_t aug[BR_N][2 * BR_N];
    for (int r = 0; r < BR_N; ++r) {
        for (int c = 0; c < BR_N; ++c) aug[r][c] = M[r][c];
        for (int c = 0; c < BR_N; ++c) aug[r][BR_N + c] = (uint8_t)(r == c);
    }

    for (int c = 0; c < BR_N; ++c) {
        int pivot = c;
        while (pivot < BR_N && aug[pivot][c] == 0) ++pivot;
        if (pivot == BR_N) return 0;
        if (pivot != c) {
            for (int j = 0; j < 2 * BR_N; ++j) {
                uint8_t t = aug[pivot][j];
                aug[pivot][j] = aug[c][j];
                aug[c][j] = t;
            }
        }
        const uint8_t inv = gf_inv(aug[c][c]);
        if (!inv) return 0;
        for (int j = 0; j < 2 * BR_N; ++j)
            aug[c][j] = gf_mul(aug[c][j], inv);
        for (int r = 0; r < BR_N; ++r) {
            if (r == c || aug[r][c] == 0) continue;
            const uint8_t f = aug[r][c];
            for (int j = 0; j < 2 * BR_N; ++j)
                aug[r][j] ^= gf_mul(f, aug[c][j]);
        }
    }
    for (int r = 0; r < BR_N; ++r)
        memcpy(MI[r], aug[r] + BR_N, BR_N);

    /* Vérification exhaustive de M * M^-1 = I sur GF(16). */
    for (int r = 0; r < BR_N; ++r) {
        for (int c = 0; c < BR_N; ++c) {
            uint8_t v = 0;
            for (int k = 0; k < BR_N; ++k)
                v ^= gf_mul(M[r][k], MI[k][c]);
            if (v != (uint8_t)(r == c)) return 0;
        }
    }
    return 1;
}

static void init_linear_tables(void)
{
    memset(LIN_F, 0, sizeof LIN_F);
    memset(LIN_I, 0, sizeof LIN_I);
    for (int j = 0; j < BR_N; ++j) {
        for (int x = 0; x < 16; ++x) {
            for (int v = 0; v < BR_N; ++v) {
                LIN_F[j][x][v >> 4] |=
                    (uint64_t)gf_mul(M[v][j], (uint8_t)x) << (4 * (v & 15));
                LIN_I[j][x][v >> 4] |=
                    (uint64_t)gf_mul(MI[v][j], (uint8_t)x) << (4 * (v & 15));
            }
        }
    }
}

static void linear_slow(const uint8_t mat[BR_N][BR_N], uint8_t s[BR_N])
{
    uint8_t out[BR_N];
    for (int v = 0; v < BR_N; ++v) {
        uint8_t acc = 0;
        for (int j = 0; j < BR_N; ++j)
            if (mat[v][j]) acc ^= gf_mul(mat[v][j], s[j]);
        out[v] = acc;
    }
    memcpy(s, out, BR_N);
}

#ifdef __AVX2__
static inline void linear_fast(const uint64_t T[BR_N][16][8], uint8_t *s)
{
    __m256i a = _mm256_setzero_si256();
    __m256i b = _mm256_setzero_si256();
    for (int j = 0; j < BR_N; ++j) {
        const __m256i *line = (const __m256i *)T[j][s[j]];
        a = _mm256_xor_si256(a, _mm256_load_si256(line));
        b = _mm256_xor_si256(b, _mm256_load_si256(line + 1));
    }
    const __m256i mask = _mm256_set1_epi16(0x000f);
    __m128i q[4] = {
        _mm256_castsi256_si128(a), _mm256_extracti128_si256(a, 1),
        _mm256_castsi256_si128(b), _mm256_extracti128_si256(b, 1)
    };
    for (int i = 0; i < 4; ++i) {
        __m256i w = _mm256_cvtepu8_epi16(q[i]);
        w = _mm256_or_si256(
            _mm256_and_si256(w, mask),
            _mm256_slli_epi16(
                _mm256_and_si256(_mm256_srli_epi16(w, 4), mask), 8));
        _mm256_storeu_si256((__m256i *)(s + 32 * i), w);
    }
}

static inline void sbox_layer(uint8_t *s, const uint8_t table[16],
                              const uint8_t rc[BR_N], int rc_before)
{
    const __m256i t = _mm256_broadcastsi128_si256(
        _mm_loadu_si128((const __m128i *)table));
    for (int i = 0; i < 4; ++i) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(s + 32 * i));
        __m256i c = _mm256_loadu_si256((const __m256i *)(rc + 32 * i));
        v = rc_before
            ? _mm256_shuffle_epi8(t, _mm256_xor_si256(v, c))
            : _mm256_xor_si256(_mm256_shuffle_epi8(t, v), c);
        _mm256_storeu_si256((__m256i *)(s + 32 * i), v);
    }
}
#else
static inline void linear_fast(const uint64_t T[BR_N][16][8], uint8_t *s)
{
    uint64_t acc[8] = {0};
    for (int j = 0; j < BR_N; ++j)
        for (int k = 0; k < 8; ++k)
            acc[k] ^= T[j][s[j]][k];
    for (int v = 0; v < BR_N; ++v)
        s[v] = (uint8_t)((acc[v >> 4] >> (4 * (v & 15))) & 15u);
}

static inline void sbox_layer(uint8_t *s, const uint8_t table[16],
                              const uint8_t rc[BR_N], int rc_before)
{
    for (int j = 0; j < BR_N; ++j)
        s[j] = rc_before ? table[s[j] ^ rc[j]] : (uint8_t)(table[s[j]] ^ rc[j]);
}
#endif

static void perm_forward(uint8_t s[BR_N], int box, int rounds)
{
    for (int t = 0; t < rounds; ++t) {
        sbox_layer(s, SBOX[box], BR_RC[t], 1);
        linear_fast(LIN_F, s);
    }
}

static void perm_inverse(uint8_t s[BR_N], int box, int rounds)
{
    for (int t = rounds - 1; t >= 0; --t) {
        linear_fast(LIN_I, s);
        sbox_layer(s, SBOX_INV[box], BR_RC[t], 0);
    }
}

/* Référence scalaire indépendante du chemin AVX2/table pré-calculée. */
static void perm_forward_slow(uint8_t s[BR_N], int box, int rounds)
{
    for (int t = 0; t < rounds; ++t) {
        for (int j = 0; j < BR_N; ++j)
            s[j] = SBOX[box][s[j] ^ BR_RC[t][j]];
        linear_slow((const uint8_t (*)[BR_N])M, s);
    }
}

static void perm_inverse_slow(uint8_t s[BR_N], int box, int rounds)
{
    for (int t = rounds - 1; t >= 0; --t) {
        linear_slow((const uint8_t (*)[BR_N])MI, s);
        for (int j = 0; j < BR_N; ++j)
            s[j] = (uint8_t)(SBOX_INV[box][s[j]] ^ BR_RC[t][j]);
    }
}

/* ChaCha20 RFC 8439, compteur 32 bits, nonce 96 bits. */
static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);  \
} while (0)

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint32_t nonce[3], uint8_t out[64])
{
    static const uint32_t c[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t x[16], initial[16];
    for (int i = 0; i < 4; ++i) initial[i] = c[i];
    for (int i = 0; i < 8; ++i) initial[4 + i] = load32_le(key + 4 * i);
    initial[12] = counter;
    initial[13] = nonce[0];
    initial[14] = nonce[1];
    initial[15] = nonce[2];
    memcpy(x, initial, sizeof x);

    for (int i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; ++i) store32_le(out + 4 * i, x[i] + initial[i]);
}
#undef QR

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static int parse_seed(const char *hex, uint8_t key[32])
{
    if (strlen(hex) != 64) return 0;
    for (int i = 0; i < 32; ++i) {
        const int hi = hex_nibble(hex[2 * i]);
        const int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        key[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static int chacha20_selftest(void)
{
    static const uint8_t expected[64] = {
        0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,
        0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
        0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
        0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
        0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,
        0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
        0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,
        0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
    };
    uint8_t key[32], out[64];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    const uint32_t nonce[3] = {0x09000000u, 0x4a000000u, 0u};
    chacha20_block(key, 1u, nonce, out);
    return memcmp(out, expected, sizeof expected) == 0;
}

static int valid_sboxes(void)
{
    for (int b = 0; b < NBOX; ++b) {
        unsigned seen = 0;
        for (int x = 0; x < 16; ++x) {
            const uint8_t y = SBOX[b][x];
            if (y > 15 || (seen & (1u << y))) return 0;
            seen |= 1u << y;
            SBOX_INV[b][y] = (uint8_t)x;
        }
        if (seen != 0xffffu) return 0;
    }
    return 1;
}

static int verify_fast_linear(const uint8_t key[32])
{
    uint8_t block[64], s[BR_N], expected[BR_N];
    const uint32_t nonce[3] = {0x54455354u, 1u, 2u};
    chacha20_block(key, 7u, nonce, block);
    for (int i = 0; i < BR_N; ++i)
        s[i] = (uint8_t)((block[i / 2] >> ((i & 1) * 4)) & 15u);

    memcpy(expected, s, BR_N);
    linear_slow((const uint8_t (*)[BR_N])M, expected);
    linear_fast(LIN_F, s);
    if (memcmp(s, expected, BR_N) != 0) return 0;

    memcpy(expected, s, BR_N);
    linear_slow((const uint8_t (*)[BR_N])MI, expected);
    linear_fast(LIN_I, s);
    return memcmp(s, expected, BR_N) == 0;
}

static int verify_roundtrips(const uint8_t key[32], int max_rounds)
{
    uint8_t block[64], initial[BR_N];
    const uint32_t nonce[3] = {0x524f554eu, 0x44545249u, 0x414c544fu};
    chacha20_block(key, 99u, nonce, block);
    for (int i = 0; i < BR_N; ++i)
        initial[i] = (uint8_t)((block[i / 2] >> ((i & 1) * 4)) & 15u);

    int tests[3] = {1, 3, max_rounds};
    for (int b = 0; b < NBOX; ++b) {
        for (int k = 0; k < 3; ++k) {
            int r = tests[k];
            if (r > max_rounds) r = max_rounds;
            if (k > 0 && r == tests[k - 1]) continue;
            uint8_t fast[BR_N], slow[BR_N];
            memcpy(fast, initial, BR_N);
            memcpy(slow, initial, BR_N);

            perm_forward(fast, b, r);
            perm_forward_slow(slow, b, r);
            if (memcmp(fast, slow, BR_N) != 0) return 0;

            perm_inverse(fast, b, r);
            perm_inverse_slow(slow, b, r);
            if (memcmp(fast, initial, BR_N) != 0 ||
                memcmp(slow, initial, BR_N) != 0 ||
                memcmp(fast, slow, BR_N) != 0)
                return 0;
        }
    }
    return 1;
}

static uint8_t uniform_nonzero_nibble(const uint8_t bytes[64], int *offset)
{
    /* 255 est divisible par 15 : rejeter uniquement 255 évite le biais de %15. */
    while (*offset < 64) {
        const uint8_t value = bytes[(*offset)++];
        if (value != 255u) return (uint8_t)(1u + value % 15u);
    }
    /* La branche est pratiquement inaccessible ; elle reste déterministe. */
    return 1u;
}

static void make_geometry(const uint8_t key[32], int round, int combination,
                          int *i, int *j, uint8_t *alpha, uint8_t *de)
{
    uint8_t bytes[64];
    const uint32_t nonce[3] = {
        (uint32_t)round, (uint32_t)combination, 0x47454f4du /* GEOM */
    };
    chacha20_block(key, UINT32_MAX, nonce, bytes);
    *i = (int)(bytes[0] & 127u);
    *j = (int)(bytes[1] & 127u);
    int offset = 2;
    *alpha = uniform_nonzero_nibble(bytes, &offset);
    *de = uniform_nonzero_nibble(bytes, &offset);
}

static int ensure_dir(const char *path)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        struct stat st;
        return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
    }
    return 0;
}

static int run_seed(int lq, int combinations, int rounds, int threads,
                    const uint8_t key[32], const char *seed_hex,
                    const char *outdir)
{
    const uint64_t quartets = UINT64_C(1) << lq;
    char zero_path[1024], exact_path[1024];
    snprintf(zero_path, sizeof zero_path, "%s/paired_zero_%s.csv", outdir, seed_hex);
    snprintf(exact_path, sizeof exact_path, "%s/paired_exact_%s.csv", outdir, seed_hex);

    FILE *zero_file = fopen(zero_path, "w");
    FILE *exact_file = fopen(exact_path, "w");
    if (!zero_file || !exact_file) {
        perror("ouverture CSV apparié");
        if (zero_file) fclose(zero_file);
        if (exact_file) fclose(exact_file);
        return 0;
    }

    fprintf(zero_file,
        "seed_hex,round,combination,input_nibble,alpha,delta_source_nibble,delta_multiplier,"
        "pair,variant_a,variant_b,output_nibble,quartets,n00,n01,n10,n11\n");
    fprintf(exact_file,
        "seed_hex,round,combination,input_nibble,alpha,delta_source_nibble,delta_multiplier,"
        "pair,variant_a,variant_b,quartets,n00,n01,n10,n11\n");

    omp_set_num_threads(threads);
    for (int R = 1; R <= rounds; ++R) {
        for (int c = 0; c < combinations; ++c) {
            int input_i, source_j;
            uint8_t alpha, de;
            make_geometry(key, R, c, &input_i, &source_j, &alpha, &de);

            uint8_t delta[BR_N];
            for (int v = 0; v < BR_N; ++v)
                delta[v] = gf_mul(M[v][source_j], de);

            uint64_t total_zero[PAIRS][BR_N][4] = {{{0}}};
            uint64_t total_exact[PAIRS][4] = {{0}};

#pragma omp parallel
            {
                local_counts_t local;
                memset(&local, 0, sizeof local);
                uint8_t base[BR_N], left[BR_N], right[BR_N];
                uint8_t out[ NBOX ][2][BR_N];
                uint8_t random_block[64];
                const uint32_t nonce[3] = {
                    (uint32_t)R, (uint32_t)c, 0x4252554du /* BRUM */
                };

#pragma omp for schedule(static)
                for (uint64_t q = 0; q < quartets; ++q) {
                    chacha20_block(key, (uint32_t)q, nonce, random_block);
                    for (int v = 0; v < BR_N; ++v)
                        base[v] = (uint8_t)((random_block[v / 2] >> ((v & 1) * 4)) & 15u);

                    memcpy(left, base, BR_N);
                    memcpy(right, base, BR_N);
                    right[input_i] ^= alpha;

                    for (int b = 0; b < NBOX; ++b) {
                        memcpy(out[b][0], left, BR_N);
                        memcpy(out[b][1], right, BR_N);
                        perm_forward(out[b][0], b, R);
                        perm_forward(out[b][1], b, R);
                        for (int v = 0; v < BR_N; ++v) {
                            out[b][0][v] ^= delta[v];
                            out[b][1][v] ^= delta[v];
                        }
                        perm_inverse(out[b][0], b, R);
                        perm_inverse(out[b][1], b, R);
                    }

                    uint8_t zero_event[NBOX][BR_N];
                    uint8_t exact_event[NBOX];
                    for (int b = 0; b < NBOX; ++b) {
                        int exact = 1;
                        for (int v = 0; v < BR_N; ++v) {
                            const uint8_t dv = (uint8_t)(out[b][0][v] ^ out[b][1][v]);
                            zero_event[b][v] = (uint8_t)(dv == 0);
                            const uint8_t wanted = (uint8_t)(v == input_i ? alpha : 0);
                            exact &= (dv == wanted);
                        }
                        exact_event[b] = (uint8_t)exact;
                    }

                    for (int p = 0; p < PAIRS; ++p) {
                        const int a = PAIR_A[p];
                        const int b = PAIR_B[p];
                        for (int v = 0; v < BR_N; ++v) {
                            const unsigned idx =
                                (zero_event[a][v] ? 2u : 0u) |
                                (zero_event[b][v] ? 1u : 0u);
                            local.zero[p][v][idx]++;
                        }
                        const unsigned exact_idx =
                            (exact_event[a] ? 2u : 0u) |
                            (exact_event[b] ? 1u : 0u);
                        local.exact[p][exact_idx]++;
                    }
                }

#pragma omp critical
                {
                    for (int p = 0; p < PAIRS; ++p) {
                        for (int v = 0; v < BR_N; ++v)
                            for (int k = 0; k < 4; ++k)
                                total_zero[p][v][k] += local.zero[p][v][k];
                        for (int k = 0; k < 4; ++k)
                            total_exact[p][k] += local.exact[p][k];
                    }
                }
            }

            for (int p = 0; p < PAIRS; ++p) {
                const int a = PAIR_A[p];
                const int b = PAIR_B[p];
                for (int v = 0; v < BR_N; ++v) {
                    fprintf(zero_file,
                        "%s,%d,%d,%d,%u,%d,%u,%s,%s,%s,%d,%" PRIu64 ","
                        "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                        seed_hex, R, c, input_i, (unsigned)alpha, source_j,
                        (unsigned)de, PAIR_NAMES[p], SBOX_NAMES[a], SBOX_NAMES[b],
                        v, quartets,
                        total_zero[p][v][0], total_zero[p][v][1],
                        total_zero[p][v][2], total_zero[p][v][3]);
                }
                fprintf(exact_file,
                    "%s,%d,%d,%d,%u,%d,%u,%s,%s,%s,%" PRIu64 ","
                    "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                    seed_hex, R, c, input_i, (unsigned)alpha, source_j,
                    (unsigned)de, PAIR_NAMES[p], SBOX_NAMES[a], SBOX_NAMES[b],
                    quartets, total_exact[p][0], total_exact[p][1],
                    total_exact[p][2], total_exact[p][3]);
            }
        }
        fprintf(stderr, "seed %.8s : tour %d/%d terminé\n", seed_hex, R, rounds);
        if (fflush(zero_file) != 0 || fflush(exact_file) != 0) {
            fprintf(stderr, "erreur d'écriture des CSV\n");
            fclose(zero_file);
            fclose(exact_file);
            return 0;
        }
    }

    const int close_ok = (fclose(zero_file) == 0) & (fclose(exact_file) == 0);
    if (!close_ok) {
        fprintf(stderr, "erreur à la fermeture des CSV\n");
        return 0;
    }
    return 1;
}

static int parse_int_range(const char *s, long min, long max, long *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !end || *end != '\0' || v < min || v > max) return 0;
    *out = v;
    return 1;
}

int main(int argc, char **argv)
{
    long lq = 18, combinations = 32, rounds = 8, threads = 8;
    if (argc != 7) {
        fprintf(stderr,
            "Usage: %s LQ NC ROUNDS THREADS SEED_HEX_64 OUTDIR\n"
            "Exemple: %s 18 32 8 8 000102... (64 hex) resultats/paired\n",
            argv[0], argv[0]);
        return 2;
    }
    if (!parse_int_range(argv[1], 1, 32, &lq) ||
        !parse_int_range(argv[2], 1, 1000000, &combinations) ||
        !parse_int_range(argv[3], 1, BR_TOURS, &rounds) ||
        !parse_int_range(argv[4], 1, 256, &threads)) {
        fprintf(stderr, "paramètre numérique hors plage\n");
        return 2;
    }

    uint8_t key[32];
    if (!parse_seed(argv[5], key)) {
        fprintf(stderr, "SEED_HEX doit contenir exactement 64 caractères hexadécimaux\n");
        return 2;
    }
    if (!ensure_dir(argv[6])) {
        fprintf(stderr, "dossier de sortie invalide ou impossible à créer: %s\n", argv[6]);
        return 2;
    }

    if (!chacha20_selftest()) {
        fprintf(stderr, "échec: test de conformité ChaCha20 RFC 8439\n");
        return 1;
    }
    if (!valid_sboxes()) {
        fprintf(stderr, "échec: une des trois S-boxes n'est pas bijective\n");
        return 1;
    }
    if (!init_matrix()) {
        fprintf(stderr, "échec: matrice BRUME non inversible\n");
        return 1;
    }
    init_linear_tables();
    if (!verify_fast_linear(key)) {
        fprintf(stderr, "échec: tables linéaires rapides différentes de la référence lente\n");
        return 1;
    }
    if (!verify_roundtrips(key, (int)rounds)) {
        fprintf(stderr, "échec: un aller-retour permutation/inverse n'est pas cohérent\n");
        return 1;
    }

    fprintf(stderr,
        "Contrôles OK: ChaCha20 RFC 8439, 3 S-boxes bijectives, M inversible, "
        "tables rapides conformes, permutation rapide = référence scalaire et inverse.\n");
    fprintf(stderr,
        "Paramètres: quartets=2^%ld (%" PRIu64 "), combinaisons=%ld, tours=%ld, threads=%ld\n",
        lq, UINT64_C(1) << lq, combinations, rounds, threads);
    return run_seed((int)lq, (int)combinations, (int)rounds, (int)threads,
                    key, argv[5], argv[6]) ? 0 : 1;
}
