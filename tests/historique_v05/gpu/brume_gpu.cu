/* Conformité et débit de BRUME-512 sur GPU (tests/gpu/brume.cuh).
 *   1. Direct, R = 1 … 32 tours, 2^20 états : identique à br_tours_avx2 (bibliothèque C) ;
 *   2. tours r0 … r0 + R − 1 et inverses, 256 états : identiques à tests/c/brume_ref.h (référence
 *      indépendante, matrices denses M et M⁻¹ sur GF(16)) ;
 *   3. aller-retour complet (32 tours puis inverse), 2^20 états ;
 *   4. débit : permutations par seconde, direct (32 et 5 tours) et inverse (5 tours).
 *     make -C tests/gpu && tests/gpu/build/brume_gpu   (depuis la racine) → resultats/brume_gpu.json */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _Static_assert static_assert          /* sillage.h est du C11 */
extern "C" {
#include "brume_ref.h"
}
#include "resultat.h"
#include "brume.cuh"

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "CUDA %s:%d : %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); exit(2); } } while (0)

__global__ void k_avant(uint32_t *s, int n, int r0, int R)
{
    int t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= n)
        return;
    uint32_t w[16];
    for (int k = 0; k < 16; k++)
        w[k] = s[16 * t + k];
    brume_avant(w, r0, R);
    for (int k = 0; k < 16; k++)
        s[16 * t + k] = w[k];
}

__global__ void k_arriere(uint32_t *s, int n, int r0, int R, const uint32_t *mi)
{
    __shared__ uint32_t MI[512 * 16];
    for (int i = threadIdx.x; i < 512 * 16; i += blockDim.x)
        MI[i] = mi[i];
    __syncthreads();
    int t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= n)
        return;
    uint32_t w[16];
    for (int k = 0; k < 16; k++)
        w[k] = s[16 * t + k];
    brume_arriere(w, r0, R, MI);
    for (int k = 0; k < 16; k++)
        s[16 * t + k] = w[k];
}

/* débit : chaque fil enchaîne iters permutations depuis son propre état */
__global__ void k_debit(uint32_t *out, int R, int iters, int sens, const uint32_t *mi)
{
    __shared__ uint32_t MI[512 * 16];
    if (sens) {
        for (int i = threadIdx.x; i < 512 * 16; i += blockDim.x)
            MI[i] = mi[i];
        __syncthreads();
    }
    uint32_t t = blockIdx.x * blockDim.x + threadIdx.x, w[16];
    for (int k = 0; k < 16; k++)
        w[k] = t * 0x9E3779B9u + k * 0x85EBCA6Bu;
    for (int i = 0; i < iters; i++) {
        if (sens)
            brume_arriere(w, BR_TOURS - 1, R, MI);
        else
            brume_avant(w, 0, R);
    }
    uint32_t a = 0;
    for (int k = 0; k < 16; k++)
        a ^= w[k];
    out[t] = a;
}

static uint64_t g = 0x5eedb7u;
static uint32_t alea(void)
{
    g = g * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(g >> 32);
}

static void vers_nibbles(const uint32_t *w, uint8_t x[BR_N])
{
    for (int j = 0; j < BR_N; j++)
        x[j] = (uint8_t)((w[j >> 3] >> (4 * (j & 7))) & 15);
}

static double debit(int R, int sens, const uint32_t *d_mi)
{
    const int blocs = 480, fils = 256, n = blocs * fils;
    uint32_t *d;
    CK(cudaMalloc(&d, 4 * n));
    int iters = 1;
    float ms = 0;
    cudaEvent_t a, b;
    cudaEventCreate(&a);
    cudaEventCreate(&b);
    for (;;) {                                         /* au moins 1 s de mesure */
        cudaEventRecord(a);
        k_debit<<<blocs, fils>>>(d, R, iters, sens, d_mi);
        cudaEventRecord(b);
        CK(cudaEventSynchronize(b));
        CK(cudaGetLastError());
        cudaEventElapsedTime(&ms, a, b);
        if (ms > 1000 || iters > (1 << 20))
            break;
        iters *= ms < 50 ? 8 : 2;
    }
    cudaFree(d);
    return (double)n * iters / (ms / 1000);
}

int main(void)
{
    resultat_t res = {.nom = "brume_gpu"};
    if (!bref_init() || !bref_conforme(64)) {
        fprintf(stderr, "référence C non conforme\n");
        return 2;
    }
    cudaDeviceProp p;
    CK(cudaGetDeviceProperties(&p, 0));
    res_mesure(&res, "gpu", "\"%s, sm_%d%d, %d SM\"", p.name, p.major, p.minor, p.multiProcessorCount);
    br_gpu_init(BR_RC);
    static uint32_t mi[512 * 16];
    br_gpu_mi(BMI, mi, gf_mul);
    uint32_t *d_mi;
    CK(cudaMalloc(&d_mi, sizeof mi));
    CK(cudaMemcpy(d_mi, mi, sizeof mi, cudaMemcpyHostToDevice));

    const int N = 1 << 20, B = 256, G = (N + B - 1) / B;
    uint32_t *s0 = (uint32_t *)malloc(64 * (size_t)N), *s = (uint32_t *)malloc(64 * (size_t)N),
             *c = (uint32_t *)malloc(64 * (size_t)N), *d;
    for (size_t i = 0; i < 16 * (size_t)N; i++)
        s0[i] = alea();
    CK(cudaMalloc(&d, 64 * (size_t)N));

    /* 1. direct contre la bibliothèque, R = 1 … 32 */
    long ecarts = 0;
    for (int R = 1; R <= BR_TOURS; R++) {
        CK(cudaMemcpy(d, s0, 64 * (size_t)N, cudaMemcpyHostToDevice));
        k_avant<<<G, B>>>(d, N, 0, R);
        CK(cudaGetLastError());
        CK(cudaMemcpy(s, d, 64 * (size_t)N, cudaMemcpyDeviceToHost));
        memcpy(c, s0, 64 * (size_t)N);
#pragma omp parallel for reduction(+ : ecarts)
        for (int i = 0; i < N; i++) {
            br_tours_avx2((uint64_t *)(c + 16 * (size_t)i), R);
            ecarts += memcmp(c + 16 * (size_t)i, s + 16 * (size_t)i, 64) != 0;
        }
    }
    res_mesure(&res, "direct_ecarts_sur_32x2^20", "%ld", ecarts);
    res_controle(&res, "direct_identique_a_la_bibliotheque_c_pour_R_1_a_32", ecarts == 0);

    /* 2. tours intermédiaires et inverses contre la référence dense */
    const int M = 256;
    long ec_av = 0, ec_ar = 0;
    const int cas[][2] = {{0, 1}, {0, 5}, {7, 3}, {10, 6}, {26, 6}};
    for (int q = 0; q < 5; q++) {
        int r0 = cas[q][0], R = cas[q][1];
        CK(cudaMemcpy(d, s0, 64 * M, cudaMemcpyHostToDevice));
        k_avant<<<1, M>>>(d, M, r0, R);
        CK(cudaMemcpy(s, d, 64 * M, cudaMemcpyDeviceToHost));
        CK(cudaMemcpy(d, s0, 64 * M, cudaMemcpyHostToDevice));
        k_arriere<<<1, M>>>(d, M, r0 + R - 1, R, d_mi);
        CK(cudaGetLastError());
        CK(cudaMemcpy(c, d, 64 * M, cudaMemcpyDeviceToHost));
        for (int i = 0; i < M; i++) {
            uint8_t x[BR_N], y[BR_N], z[BR_N];
            vers_nibbles(s0 + 16 * i, x);
            memcpy(y, x, BR_N);
            for (int r = r0; r < r0 + R; r++)
                bref_tour(y, r);
            vers_nibbles(s + 16 * i, z);
            ec_av += memcmp(y, z, BR_N) != 0;
            memcpy(y, x, BR_N);
            for (int r = r0 + R - 1; r >= r0; r--)
                bref_tour_inv(y, r);
            vers_nibbles(c + 16 * i, z);
            ec_ar += memcmp(y, z, BR_N) != 0;
        }
    }
    res_controle(&res, "tours_intermediaires_identiques_a_la_reference_dense", ec_av == 0);
    res_controle(&res, "inverse_identique_a_la_reference_dense", ec_ar == 0);

    /* 3. aller-retour complet */
    CK(cudaMemcpy(d, s0, 64 * (size_t)N, cudaMemcpyHostToDevice));
    k_avant<<<G, B>>>(d, N, 0, BR_TOURS);
    k_arriere<<<G, B>>>(d, N, BR_TOURS - 1, BR_TOURS, d_mi);
    CK(cudaGetLastError());
    CK(cudaMemcpy(s, d, 64 * (size_t)N, cudaMemcpyDeviceToHost));
    res_controle(&res, "aller_retour_32_tours_identite_sur_2^20", memcmp(s, s0, 64 * (size_t)N) == 0);

    /* 4. débit */
    double d32 = debit(32, 0, d_mi), d5 = debit(5, 0, d_mi), i5 = debit(5, 1, d_mi);
    res_mesure(&res, "debit_direct_32_tours", "{\"par_s\": %.4g, \"log2\": %.2f}", d32, log2(d32));
    res_mesure(&res, "debit_direct_5_tours", "{\"par_s\": %.4g, \"log2\": %.2f}", d5, log2(d5));
    res_mesure(&res, "debit_inverse_5_tours", "{\"par_s\": %.4g, \"log2\": %.2f}", i5, log2(i5));
    fprintf(stderr, "  débit : 32 tours 2^%.2f/s, 5 tours 2^%.2f/s, inverse 5 tours 2^%.2f/s\n",
            log2(d32), log2(d5), log2(i5));
    cudaFree(d);
    cudaFree(d_mi);
    free(s0);
    free(s);
    free(c);
    return res_ecrire(&res);
}
