/* Boomerang à R tours sur BRUME-1024q (tours 0 … R − 1), GPU. Portage de tests/gpu/boomerang_gpu.cu (BRUME-512).
 *
 * Quartet : x, x' = x ⊕ α ; y = P_R(x), y' = P_R(x') ; z = y ⊕ δ, z' = y' ⊕ δ ; u = P_R⁻¹(z), u' = P_R⁻¹(z').
 * Retour exact si u ⊕ u' = α : P = 2^−1024 pour une permutation aléatoire, tout retour est un distingueur.
 * Même convention qu'à 512 : α = a·e_i, δ = M·(δ'·e_j') (une S-box active au dernier tour, vue de la sortie).
 * On compte aussi le retour TRONQUÉ (u ⊕ u' non nul et nul hors du nibble i : 15·2^−1024 au hasard) et le retour de POIDS
 * FAIBLE (u ⊕ u' non nul, au plus 32 nibbles non nuls sur 256 : < C(256, 32)·16^−224 < 2^−830 au hasard).
 * Contrôles (le programme rend 1 si l'un échoue) :
 *   - vecteurs : P_R et P_R⁻¹ du GPU, et la référence de l'hôte, identiques aux vecteurs de brume1024.c
 *     (gpu/vecteurs_b1024.c : ref_tour, ref_tour_inv), R ∈ {1, 2, 3, 4, 5, 8, 32} ;
 *   - conformité : les 4 096 premiers quartets de chaque combinaison recalculés par la référence de l'hôte (tours denses,
 *     M et M⁻¹ explicites sur GF(16)), différence u ⊕ u' comparée mot pour mot au GPU.
 *     boomerang1024 vecteurs.bin R lg i a j d [i a j d …]      → une ligne par combinaison
 *     boomerang1024 vecteurs.bin R lg balayage I J              → toutes les (a, d) ∈ [1, 15]² pour i ∈ I, j' ∈ J
 *                                                                (listes « 0,128 »), triées par retours exacts ;
 *                                                                conformité : 4 096 quartets sur la 1re, 64 ensuite */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define _Static_assert static_assert
extern "C" {
#include "brume_ref.h"
}
#include "b1024_tables.h"
#include "brume1024.cuh"

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "CUDA %s:%d : %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); exit(2); } } while (0)

#define NCONF 4096
#define FAIBLE 32

__constant__ uint32_t c_alpha[32], c_delta[32];

__host__ __device__ static inline uint64_t mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

__host__ __device__ static inline void etat(uint64_t graine, uint64_t k, uint32_t w[32])
{
    for (int q = 0; q < 16; q++) {
        uint64_t r = mix64(graine ^ mix64(k * 16 + (uint64_t)q + 0x9E3779B97F4A7C15ULL));
        w[2 * q] = (uint32_t)r;
        w[2 * q + 1] = (uint32_t)(r >> 32);
    }
}

__global__ void __launch_bounds__(128) k_boomerang(uint64_t graine, uint64_t debut, uint64_t nombre, int par_fil, int R,
                                                   int inib, const uint32_t *__restrict__ mi, unsigned long long *cpt,
                                                   uint32_t *dump)
{
    uint64_t t = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long exact = 0, tronque = 0, faible = 0;
    for (int jj = 0; jj < par_fil; jj++) {
        uint64_t k = debut + t * (uint64_t)par_fil + (uint64_t)jj;
        if (k >= debut + nombre)
            break;
        uint32_t a[32], b[32];
        etat(graine, k, a);
#pragma unroll
        for (int q = 0; q < 32; q++)
            b[q] = a[q] ^ c_alpha[q];
        b1_avant(a, 0, R);
        b1_avant(b, 0, R);
#pragma unroll
        for (int q = 0; q < 32; q++) {
            a[q] ^= c_delta[q];
            b[q] ^= c_delta[q];
        }
        b1_arriere2(a, b, R - 1, R, mi);
        uint32_t ex = 0, hors = 0, dans = 0;
        int nz = 0;
#pragma unroll
        for (int q = 0; q < 32; q++) {
            uint32_t d = a[q] ^ b[q];
            ex |= d ^ c_alpha[q];
            uint32_t m = q == (inib >> 3) ? 0xFu << (4 * (inib & 7)) : 0;
            hors |= d & ~m;
            nz += __popc((d | d >> 1 | d >> 2 | d >> 3) & 0x11111111u);
            dans |= d & m;
            if (dump && k < NCONF)
                dump[32 * k + q] = d;
        }
        exact += ex == 0;
        tronque += hors == 0 && dans != 0;
        faible += nz > 0 && nz <= FAIBLE;
    }
    if (exact)
        atomicAdd(&cpt[0], exact);
    if (tronque)
        atomicAdd(&cpt[1], tronque);
    if (faible)
        atomicAdd(&cpt[2], faible);
}

/* noyau de contrôle : P_R (sens 0) ou P_R⁻¹ (sens 1) sur n états */
__global__ void k_perm(uint32_t *w, int n, int R, int sens, const uint32_t *__restrict__ mi)
{
    int t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= n)
        return;
    uint32_t a[32], b[32];
    for (int q = 0; q < 32; q++)
        a[q] = b[q] = w[32 * t + q];
    if (sens)
        b1_arriere2(a, b, R - 1, R, mi);
    else
        b1_avant(a, 0, R);
    for (int q = 0; q < 32; q++)
        w[32 * t + q] = a[q];
}

/* ------------------------------------------------------------ référence de l'hôte (dense, GF(16)) */
static uint8_t DM[B1_N][B1_N], DMI[B1_N][B1_N], SI1[16];

static int h_nbr(int v, int k)
{
    int i = v % B1_M, f = v / B1_M;
    return f == 0 ? (i + k) % B1_M + B1_M : ((i - k) % B1_M + B1_M) % B1_M;
}

static int h_init(void)
{
    for (int x = 0; x < 16; x++)
        SI1[BR_SBOX[x]] = (uint8_t)x;
    for (int v = 0; v < B1_N; v++) {
        DM[v][v] = B1_CS[v];
        for (int g = 0; g < 6; g++)
            DM[v][h_nbr(v, B1_K[g])] = B1_CG[g][v];
    }
    static uint8_t T[B1_N][2 * B1_N];
    for (int i = 0; i < B1_N; i++)
        for (int j = 0; j < 2 * B1_N; j++)
            T[i][j] = j < B1_N ? DM[i][j] : (j - B1_N == i);
    for (int c = 0; c < B1_N; c++) {
        int p = c;
        while (p < B1_N && !T[p][c])
            p++;
        if (p == B1_N)
            return 0;
        for (int j = 0; j < 2 * B1_N; j++) { uint8_t u = T[p][j]; T[p][j] = T[c][j]; T[c][j] = u; }
        uint8_t iv = gf_inv(T[c][c]);
        for (int j = 0; j < 2 * B1_N; j++)
            T[c][j] = gf_mul(T[c][j], iv);
        for (int i = 0; i < B1_N; i++)
            if (i != c && T[i][c]) {
                uint8_t f = T[i][c];
                for (int j = 0; j < 2 * B1_N; j++)
                    T[i][j] ^= gf_mul(f, T[c][j]);
            }
    }
    for (int i = 0; i < B1_N; i++)
        memcpy(DMI[i], T[i] + B1_N, B1_N);
    return 1;
}

static void h_lin(const uint8_t Mx[B1_N][B1_N], uint8_t *x)
{
    uint8_t y[B1_N];
    for (int v = 0; v < B1_N; v++) {
        uint8_t a = 0;
        for (int i = 0; i < B1_N; i++)
            if (Mx[v][i])
                a ^= gf_mul(Mx[v][i], x[i]);
        y[v] = a;
    }
    memcpy(x, y, B1_N);
}
static void h_tour(uint8_t *x, int r)
{
    for (int j = 0; j < B1_N; j++)
        x[j] = BR_SBOX[x[j] ^ B1_RC[r][j]];
    h_lin(DM, x);
}
static void h_tour_inv(uint8_t *x, int r)
{
    h_lin(DMI, x);
    for (int j = 0; j < B1_N; j++)
        x[j] = SI1[x[j]] ^ B1_RC[r][j];
}
static void deballer(const uint32_t w[32], uint8_t x[B1_N])
{
    for (int j = 0; j < B1_N; j++)
        x[j] = (w[j >> 3] >> (4 * (j & 7))) & 15;
}
static void empaqueter(const uint8_t x[B1_N], uint32_t w[32])
{
    memset(w, 0, 128);
    for (int j = 0; j < B1_N; j++)
        w[j >> 3] |= (uint32_t)x[j] << (4 * (j & 7));
}

static void ref_quartet(uint64_t graine, uint64_t k, int R, const uint8_t al[B1_N], const uint8_t de[B1_N], uint8_t d[B1_N])
{
    uint32_t w[32];
    etat(graine, k, w);
    uint8_t x[B1_N], y[B1_N];
    deballer(w, x);
    for (int j = 0; j < B1_N; j++)
        y[j] = x[j] ^ al[j];
    for (int r = 0; r < R; r++) {
        h_tour(x, r);
        h_tour(y, r);
    }
    for (int j = 0; j < B1_N; j++) {
        x[j] ^= de[j];
        y[j] ^= de[j];
    }
    for (int r = R - 1; r >= 0; r--) {
        h_tour_inv(x, r);
        h_tour_inv(y, r);
    }
    for (int j = 0; j < B1_N; j++)
        d[j] = x[j] ^ y[j];
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

/* contrôle par les vecteurs de brume1024.c : GPU (P_R, P_R⁻¹) et hôte */
static int controle_vecteurs(const char *fichier, const uint32_t *g_mi)
{
    static const int RS[] = {1, 2, 3, 4, 5, 8, 32};
    FILE *f = fopen(fichier, "rb");
    if (!f) {
        perror(fichier);
        return 0;
    }
    static uint8_t v[7 * 8 * 3][128];
    size_t lu = fread(v, 128, 7 * 8 * 3, f);
    fclose(f);
    if (lu != 7 * 8 * 3)
        return 0;
    uint32_t *g_w;
    CK(cudaMalloc(&g_w, 8 * 128));
    int ecarts_gpu = 0, ecarts_hote = 0;
    for (int t = 0; t < 7; t++)
        for (int sens = 0; sens < 2; sens++) {
            uint32_t w[8][32];
            for (int e = 0; e < 8; e++)
                memcpy(w[e], v[3 * (8 * t + e)], 128);   /* même mémoire : octet i = nibbles 2i, 2i + 1 (petit-boutiste) */
            CK(cudaMemcpy(g_w, w, sizeof w, cudaMemcpyHostToDevice));
            k_perm<<<1, 8>>>(g_w, 8, RS[t], sens, g_mi);
            CK(cudaGetLastError());
            CK(cudaMemcpy(w, g_w, sizeof w, cudaMemcpyDeviceToHost));
            for (int e = 0; e < 8; e++) {
                const uint8_t *att = v[3 * (8 * t + e) + 1 + sens];
                ecarts_gpu += memcmp(w[e], att, 128) != 0;
                uint32_t h[32];
                uint8_t x[B1_N];
                memcpy(h, v[3 * (8 * t + e)], 128);
                deballer(h, x);
                if (sens)
                    for (int r = RS[t] - 1; r >= 0; r--)
                        h_tour_inv(x, r);
                else
                    for (int r = 0; r < RS[t]; r++)
                        h_tour(x, r);
                empaqueter(x, h);
                ecarts_hote += memcmp(h, att, 128) != 0;
            }
        }
    CK(cudaFree(g_w));
    printf("vecteurs de brume1024.c (R = 1, 2, 3, 4, 5, 8, 32 ; 8 états ; deux sens) : écarts GPU %d, hôte %d sur 112\n",
           ecarts_gpu, ecarts_hote);
    return ecarts_gpu == 0 && ecarts_hote == 0;
}

typedef struct { int i, a, j, d; unsigned long long cpt[3]; } comb_t;

static int mesurer(comb_t *c, int R, double lg, const uint32_t *g_mi, unsigned long long *g_cpt, uint32_t *g_dump,
                   int blocs, int verbeux, int nconf)
{
    const int fils = 128;
    uint8_t al[B1_N] = {0}, de[B1_N] = {0};
    al[c->i] = (uint8_t)c->a;
    for (int v = 0; v < B1_N; v++)
        de[v] = gf_mul(DM[v][c->j], (uint8_t)c->d);      /* δ = M·(δ'·e_j') */
    uint32_t wa[32], wd[32];
    empaqueter(al, wa);
    empaqueter(de, wd);
    CK(cudaMemcpyToSymbol(c_alpha, wa, 128));
    CK(cudaMemcpyToSymbol(c_delta, wd, 128));
    uint64_t graine = mix64(0x426F6F6D31303234ULL ^ ((uint64_t)R << 40) ^ ((uint64_t)c->i << 24) ^ ((uint64_t)c->a << 16) ^
                            ((uint64_t)c->j << 4) ^ (uint64_t)c->d);
    CK(cudaMemset(g_cpt, 0, 24));
    k_boomerang<<<(NCONF + fils - 1) / fils, fils>>>(graine, 0, NCONF, 1, R, c->i, g_mi, g_cpt, g_dump);
    CK(cudaGetLastError());
    static uint32_t dump[NCONF * 32];
    CK(cudaMemcpy(dump, g_dump, sizeof dump, cudaMemcpyDeviceToHost));
    int ecarts = 0;
#pragma omp parallel for reduction(+ : ecarts)
    for (int k = 0; k < nconf; k++) {
        uint8_t d[B1_N];
        uint32_t wdiff[32];
        ref_quartet(graine, (uint64_t)k, R, al, de, d);
        empaqueter(d, wdiff);
        ecarts += memcmp(wdiff, dump + 32 * k, 128) != 0;
    }
    uint64_t total = (uint64_t)ldexp(1.0, (int)lg), fait = 0;
    CK(cudaMemset(g_cpt, 0, 24));
    double t0 = maintenant();
    const int par_fil = 16;
    uint64_t lot = (uint64_t)fils * blocs * par_fil;
    while (fait < total) {
        uint64_t n = total - fait < lot ? total - fait : lot;
        k_boomerang<<<blocs, fils>>>(graine, NCONF + fait, n, par_fil, R, c->i, g_mi, g_cpt, NULL);
        CK(cudaGetLastError());
        fait += n;
    }
    CK(cudaDeviceSynchronize());
    double dt = maintenant() - t0;
    CK(cudaMemcpy(c->cpt, g_cpt, 24, cudaMemcpyDeviceToHost));
    if (verbeux) {
        double p = (double)c->cpt[0] / (double)total, z = 4.0, nn = (double)total;
        double cen = (p + z * z / (2 * nn)) / (1 + z * z / nn), ray = z * sqrt(p * (1 - p) / nn + z * z / (4 * nn * nn)) / (1 + z * z / nn);
        printf("R=%d (i,a,j',d')=(%d,%d,%d,%d) : retours exacts %llu / 2^%.1f = 2^%.3f [Wilson 4σ : 2^%.3f ; 2^%.3f], "
               "tronqués %llu, poids ≤ %d : %llu ; conformité %d écart(s) sur %d ; %.1f s (2^%.2f quartets/s)\n",
               R, c->i, c->a, c->j, c->d, c->cpt[0], lg, c->cpt[0] ? log2(p) : -INFINITY,
               cen - ray > 0 ? log2(cen - ray) : -INFINITY, log2(cen + ray), c->cpt[1], FAIBLE, c->cpt[2], ecarts, nconf, dt,
               log2((double)total / dt));
        fflush(stdout);
    }
    return ecarts;
}

static int liste(const char *s, int *v)
{
    int n = 0;
    for (const char *p = s; *p && n < 256; ) {
        v[n++] = atoi(p);
        while (*p && *p != ',')
            p++;
        if (*p == ',')
            p++;
    }
    return n;
}

static int cmp_comb(const void *x, const void *y)
{
    const comb_t *a = (const comb_t *)x, *b = (const comb_t *)y;
    return a->cpt[0] < b->cpt[0] ? 1 : a->cpt[0] > b->cpt[0] ? -1 : 0;
}

int main(int argc, char **argv)
{
    int balayage = argc == 7 && !strcmp(argv[4], "balayage");
    if (argc < 8 && !balayage) {
        fprintf(stderr, "usage : %s vecteurs.bin R lg i a j d [i a j d ...] | vecteurs.bin R lg balayage I J\n", argv[0]);
        return 2;
    }
    if (!balayage && (argc - 4) % 4)
        return 2;
    int R = atoi(argv[2]);
    double lg = atof(argv[3]);
    if (R < 1 || R > B1_RT || lg < 12 || lg > 50)
        return 2;
    if (!h_init())
        return 2;
    cudaDeviceProp prop;
    CK(cudaGetDeviceProperties(&prop, 0));
    b1_gpu_init(B1_RC);
    static uint32_t mi[1024 * 32];
    b1_gpu_mi(DMI, mi, gf_mul);
    uint32_t *g_mi, *g_dump;
    unsigned long long *g_cpt;
    CK(cudaMalloc(&g_mi, sizeof mi));
    CK(cudaMemcpy(g_mi, mi, sizeof mi, cudaMemcpyHostToDevice));
    CK(cudaMalloc(&g_cpt, 24));
    CK(cudaMalloc(&g_dump, NCONF * 128));
    const int blocs = 16 * prop.multiProcessorCount;
    printf("GPU %s (sm_%d%d, %d SM) ; BRUME-1024q, R = %d, 2^%.1f quartets par combinaison\n", prop.name, prop.major,
           prop.minor, prop.multiProcessorCount, R, lg);
    int ok = controle_vecteurs(argv[1], g_mi), ecarts = 0;
    if (!balayage) {
        for (int c = 4; c + 3 < argc; c += 4) {
            comb_t cb = {atoi(argv[c]), atoi(argv[c + 1]), atoi(argv[c + 2]), atoi(argv[c + 3]), {0, 0, 0}};
            if (cb.i < 0 || cb.i >= B1_N || cb.j < 0 || cb.j >= B1_N || cb.a < 1 || cb.a > 15 || cb.d < 1 || cb.d > 15)
                return 2;
            ecarts += mesurer(&cb, R, lg, g_mi, g_cpt, g_dump, blocs, 1, NCONF);
        }
    } else {
        int I[256], J[256], ni = liste(argv[5], I), nj = liste(argv[6], J), n = 0;
        comb_t *cb = (comb_t *)calloc((size_t)ni * nj * 225, sizeof *cb);
        double t0 = maintenant();
        for (int x = 0; x < ni; x++)
            for (int y = 0; y < nj; y++)
                for (int a = 1; a < 16; a++)
                    for (int d = 1; d < 16; d++) {
                        cb[n] = (comb_t){I[x], a, J[y], d, {0, 0, 0}};
                        /* conformité : 4 096 quartets pour la première combinaison, 64 pour les suivantes (la référence dense de
                         * l'hôte coûte bien plus que le GPU) ; une ligne par combinaison si elle a des retours */
                        ecarts += mesurer(&cb[n], R, lg, g_mi, g_cpt, g_dump, blocs, 0, n ? 64 : NCONF);
                        if (cb[n].cpt[0] || cb[n].cpt[1])
                            printf("  … (%d,%d,%d,%d) : exacts %llu, tronqués %llu\n", cb[n].i, cb[n].a, cb[n].j, cb[n].d,
                                   cb[n].cpt[0], cb[n].cpt[1]), fflush(stdout);
                        n++;
                    }
        qsort(cb, n, sizeof *cb, cmp_comb);
        unsigned long long somme = 0;
        for (int k = 0; k < n; k++)
            somme += cb[k].cpt[0];
        printf("balayage : %d combinaisons × 2^%.1f quartets en %.0f s ; retours exacts au total %llu ; conformité %d écart(s)\n",
               n, lg, maintenant() - t0, somme, ecarts);
        for (int k = 0; k < n && k < 20; k++)
            printf("  (i,a,j',d')=(%d,%d,%d,%d) : exacts %llu (2^%.2f), tronqués %llu, poids ≤ %d : %llu\n", cb[k].i, cb[k].a,
                   cb[k].j, cb[k].d, cb[k].cpt[0], cb[k].cpt[0] ? log2((double)cb[k].cpt[0]) - lg : -INFINITY, cb[k].cpt[1],
                   FAIBLE, cb[k].cpt[2]);
        free(cb);
    }
    ok &= ecarts == 0;
    printf("conformite_gpu_reference_dense %s\n", ok ? "OK" : "ECHEC");
    return ok ? 0 : 1;
}
