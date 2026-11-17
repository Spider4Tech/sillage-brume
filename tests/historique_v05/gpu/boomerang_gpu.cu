/* Boomerang à R tours sur BRUME-512 (tours 0 … R − 1), GPU, conforme à la référence dense.
 *
 * Quartet : x, x' = x ⊕ α ; y = P_R(x), y' = P_R(x') ; z = y ⊕ δ, z' = y' ⊕ δ ; u = P_R⁻¹(z), u' = P_R⁻¹(z').
 * Retour exact si u ⊕ u' = α. Pour une permutation aléatoire, P[retour] = 2^−512 : tout retour est un distingueur.
 * Convention de prototypes/brume_sbox6/departage (B3) : α = a·e_i, δ = M·(δ'·e_j') (une S-box active au dernier tour,
 * vue de la sortie). On compte aussi le retour TRONQUÉ (u ⊕ u' non nul et nul hors du nibble i), qui vaut 15·2^−512
 * pour une permutation aléatoire, et le retour de POIDS FAIBLE (u ⊕ u' non nul, au plus 16 nibbles non nuls), de probabilité
 * < C(128, 16)·16^−112 < 2^−440 pour une permutation aléatoire : un distingueur aussi.
 * Contrôles :
 *   - conformité : les 2^12 premiers quartets de chaque combinaison sont recalculés sur CPU par tests/c/brume_ref.h
 *     (tours denses, M et M⁻¹ explicites), différence u ⊕ u' comparée octet pour octet au GPU ;
 *   - témoin : à R = 3, le couple (16, 92) doit redonner la mesure B3 de departage (2^−8,77 à 2^30 quartets) dans
 *     l'intervalle de Wilson à 4 σ des deux mesures ;
 *   - H0 : à R = 32, aucun retour.
 *     tests/gpu/build/boomerang_gpu R lg i a j d [i a j d …]       (depuis la racine) → sortie texte, une ligne par combinaison
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define _Static_assert static_assert
extern "C" {
#include "brume_ref.h"
}
#include "brume.cuh"

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "CUDA %s:%d : %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); exit(2); } } while (0)

#define NCONF 4096

__constant__ uint32_t c_alpha[16], c_delta[16];

__host__ __device__ static inline uint64_t mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* état du quartet k : 128 nibbles, nibble j au bit 4(j & 7) du mot j >> 3 (empaquetage de brume.cuh) */
__host__ __device__ static inline void etat(uint64_t graine, uint64_t k, uint32_t w[16])
{
    for (int q = 0; q < 8; q++) {
        uint64_t r = mix64(graine ^ mix64(k * 8 + (uint64_t)q + 0x9E3779B97F4A7C15ULL));
        w[2 * q] = (uint32_t)r;
        w[2 * q + 1] = (uint32_t)(r >> 32);
    }
}

__global__ void k_boomerang(uint64_t graine, uint64_t debut, uint64_t nombre, int par_fil, int R, int inib,
                            const uint32_t *mi, unsigned long long *cpt, uint32_t *dump)
{
    extern __shared__ uint32_t MI[];
    for (int i = threadIdx.x; i < 512 * 16; i += blockDim.x)
        MI[i] = mi[i];
    __syncthreads();
    uint64_t t = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long exact = 0, tronque = 0, faible = 0;
    for (int jj = 0; jj < par_fil; jj++) {
        uint64_t k = debut + t * (uint64_t)par_fil + (uint64_t)jj;
        if (k >= debut + nombre)
            break;
        uint32_t a[16], b[16];
        etat(graine, k, a);
#pragma unroll
        for (int q = 0; q < 16; q++)
            b[q] = a[q] ^ c_alpha[q];
        brume_avant(a, 0, R);
        brume_avant(b, 0, R);
#pragma unroll
        for (int q = 0; q < 16; q++) {
            a[q] ^= c_delta[q];
            b[q] ^= c_delta[q];
        }
        brume_arriere(a, R - 1, R, MI);
        brume_arriere(b, R - 1, R, MI);
        uint32_t ex = 0, hors = 0, dans = 0;
        int nz = 0;
#pragma unroll
        for (int q = 0; q < 16; q++) {
            uint32_t d = a[q] ^ b[q];
            ex |= d ^ c_alpha[q];
            uint32_t m = q == (inib >> 3) ? 0xFu << (4 * (inib & 7)) : 0;
            hors |= d & ~m;
            nz += __popc((d | d >> 1 | d >> 2 | d >> 3) & 0x11111111u);
            dans |= d & m;
            if (dump && k < NCONF)
                dump[16 * k + q] = d;
        }
        exact += ex == 0;
        tronque += hors == 0 && dans != 0;
        faible += nz > 0 && nz <= 16;
    }
    if (exact)
        atomicAdd(&cpt[0], exact);
    if (tronque)
        atomicAdd(&cpt[1], tronque);
    if (faible)
        atomicAdd(&cpt[2], faible);
}

/* référence CPU : mêmes tours que brume_avant(·, 0, R) et brume_arriere(·, R − 1, R) */
static void ref_quartet(uint64_t graine, uint64_t k, int R, const uint8_t al[BR_N], const uint8_t de[BR_N], uint8_t d[BR_N])
{
    uint32_t w[16];
    etat(graine, k, w);
    uint8_t x[BR_N], y[BR_N];
    for (int j = 0; j < BR_N; j++)
        x[j] = (w[j >> 3] >> (4 * (j & 7))) & 15;
    for (int j = 0; j < BR_N; j++)
        y[j] = x[j] ^ al[j];
    for (int r = 0; r < R; r++) {
        bref_tour(x, r);
        bref_tour(y, r);
    }
    for (int j = 0; j < BR_N; j++) {
        x[j] ^= de[j];
        y[j] ^= de[j];
    }
    for (int r = R - 1; r >= 0; r--) {
        bref_tour_inv(x, r);
        bref_tour_inv(y, r);
    }
    for (int j = 0; j < BR_N; j++)
        d[j] = x[j] ^ y[j];
}

static void empaqueter(const uint8_t x[BR_N], uint32_t w[16])
{
    memset(w, 0, 64);
    for (int j = 0; j < BR_N; j++)
        w[j >> 3] |= (uint32_t)x[j] << (4 * (j & 7));
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    if (argc < 7 || (argc - 3) % 4) {
        fprintf(stderr, "usage : %s R lg i a j d [i a j d ...]\n", argv[0]);
        return 2;
    }
    int R = atoi(argv[1]);
    double lg = atof(argv[2]);
    if (R < 1 || R > BR_TOURS || lg < 12 || lg > 50)
        return 2;
    if (!bref_init())
        return 2;
    cudaDeviceProp prop;
    CK(cudaGetDeviceProperties(&prop, 0));
    br_gpu_init(BR_RC);
    static uint32_t mi[512 * 16];
    br_gpu_mi(BMI, mi, gf_mul);
    uint32_t *g_mi, *g_dump;
    unsigned long long *g_cpt;
    CK(cudaMalloc(&g_mi, sizeof mi));
    CK(cudaMemcpy(g_mi, mi, sizeof mi, cudaMemcpyHostToDevice));
    CK(cudaMalloc(&g_cpt, 24));
    CK(cudaMalloc(&g_dump, NCONF * 64));
    CK(cudaFuncSetAttribute(k_boomerang, cudaFuncAttributeMaxDynamicSharedMemorySize, 512 * 16 * 4));
    const int fils = 256, blocs = 8 * prop.multiProcessorCount;
    printf("GPU %s (sm_%d%d, %d SM) ; R = %d, 2^%.1f quartets par combinaison\n", prop.name, prop.major, prop.minor,
           prop.multiProcessorCount, R, lg);
    int ok_conf = 1;
    for (int c = 3; c + 3 < argc; c += 4) {
        int i = atoi(argv[c]), a = atoi(argv[c + 1]), j = atoi(argv[c + 2]), dd = atoi(argv[c + 3]);
        uint8_t al[BR_N] = {0}, de[BR_N] = {0};
        al[i] = (uint8_t)a;
        for (int v = 0; v < BR_N; v++)
            de[v] = gf_mul(BM[v][j], (uint8_t)dd);       /* δ = M·(δ'·e_j') */
        uint32_t wa[16], wd[16];
        empaqueter(al, wa);
        empaqueter(de, wd);
        CK(cudaMemcpyToSymbol(c_alpha, wa, 64));
        CK(cudaMemcpyToSymbol(c_delta, wd, 64));
        uint64_t graine = mix64(0x426F6F6D6572616EULL ^ ((uint64_t)R << 32) ^ ((uint64_t)i << 24) ^ ((uint64_t)a << 16) ^
                                ((uint64_t)j << 8) ^ (uint64_t)dd);
        /* conformité : NCONF quartets, différence complète */
        CK(cudaMemset(g_cpt, 0, 24));
        k_boomerang<<<(NCONF + fils - 1) / fils, fils, 512 * 16 * 4>>>(graine, 0, NCONF, 1, R, i, g_mi, g_cpt, g_dump);
        CK(cudaGetLastError());
        static uint32_t dump[NCONF * 16];
        CK(cudaMemcpy(dump, g_dump, sizeof dump, cudaMemcpyDeviceToHost));
        int ecarts = 0;
#pragma omp parallel for reduction(+ : ecarts)
        for (int k = 0; k < NCONF; k++) {
            uint8_t d[BR_N];
            uint32_t wdiff[16];
            ref_quartet(graine, (uint64_t)k, R, al, de, d);
            empaqueter(d, wdiff);
            ecarts += memcmp(wdiff, dump + 16 * k, 64) != 0;
        }
        ok_conf &= ecarts == 0;
        /* mesure */
        uint64_t total = (uint64_t)ldexp(1.0, (int)lg), fait = 0;
        CK(cudaMemset(g_cpt, 0, 24));
        double t0 = maintenant();
        const int par_fil = 64;
        uint64_t lot = (uint64_t)fils * blocs * par_fil;
        while (fait < total) {
            uint64_t n = total - fait < lot ? total - fait : lot;
            k_boomerang<<<blocs, fils, 512 * 16 * 4>>>(graine, NCONF + fait, n, par_fil, R, i, g_mi, g_cpt, NULL);
            CK(cudaGetLastError());
            fait += n;
        }
        CK(cudaDeviceSynchronize());
        double dt = maintenant() - t0;
        unsigned long long cpt[3];
        CK(cudaMemcpy(cpt, g_cpt, 24, cudaMemcpyDeviceToHost));
        double p = (double)cpt[0] / (double)total, z = 4.0, nn = (double)total;
        double cen = (p + z * z / (2 * nn)) / (1 + z * z / nn), ray = z * sqrt(p * (1 - p) / nn + z * z / (4 * nn * nn)) / (1 + z * z / nn);
        printf("R=%d (i,a,j',d')=(%d,%d,%d,%d) : retours exacts %llu / 2^%.1f = 2^%.3f [Wilson 4σ : 2^%.3f ; 2^%.3f], "
               "tronqués %llu, poids ≤ 16 : %llu ; conformité %d écart(s) sur %d ; %.1f s (2^%.2f quartets/s)\n",
               R, i, a, j, dd, cpt[0], lg, cpt[0] ? log2(p) : -INFINITY, cen - ray > 0 ? log2(cen - ray) : -INFINITY,
               log2(cen + ray), cpt[1], cpt[2], ecarts, NCONF, dt, log2((double)total / dt));
        fflush(stdout);
    }
    printf("conformite_gpu_reference_dense %s\n", ok_conf ? "OK" : "ECHEC");
    return ok_conf ? 0 : 1;
}
