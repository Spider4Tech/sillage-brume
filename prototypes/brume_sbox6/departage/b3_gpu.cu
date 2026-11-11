/* b3_gpu.cu — noyau CUDA de la mesure B3 (boomerang à 3 tours) de departage.c.
 *
 * Même calcul, quartet par quartet, que b3_rapide() de departage.c ; même générateur à compteur
 * (graine, flux, indice). Les comptes sont donc identiques à l'unité près à ceux du C pour la même
 * graine : b3_gpu_hote.c le vérifie à chaque combinaison et à chaque S-box (contrôle exact, pas
 * statistique) avant d'écrire une mesure.
 * Un fil = un quartet. Tables en mémoire partagée : T0[e][x] = EC[e]·S(x ⊕ RC[0][EI[e]]) (tour 1),
 * S, S⁻¹, GF(16), colonne j' de M⁻¹, ligne i de M⁻¹, colonne i de M.                            */
#include <stdint.h>
#include <stdio.h>

#define NB 128
#define DG 7

struct b3_param {
    uint8_t T0[NB * DG][16];
    uint8_t EI[NB * DG];
    uint8_t S[16], SI[16], GM[16][16], GINV[16];
    uint8_t RC1[NB];
    uint8_t MIjp[NB];   /* M⁻¹[k][j'] */
    uint8_t MIi[NB];    /* M⁻¹[i][k]  */
    uint8_t MMi[NB];    /* M[k][i]    */
    uint8_t ROWK[DG], ROWC[DG];
    int i, a, dp, rc0i, rc2jp;
};

__device__ __forceinline__ uint64_t mix64(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* état x = etat_aleatoire(graine, flux, s) de departage.c, base = mix64(graine ^ mix64(flux + φ)) */
__device__ __forceinline__ void etat(uint64_t base, uint64_t s, uint8_t *x)
{
    for (int w = 0; w < 8; w++) {
        uint64_t r = mix64(base + (s * 8 + w) * 0x9E3779B97F4A7C15ULL);
        for (int q = 0; q < 16; q++)
            x[w * 16 + q] = (r >> (4 * q)) & 15;
    }
}

/* b3_rapide() de departage.c pour (P.i, a, P.jp, dp) */
__device__ __forceinline__ int b3_un(const b3_param &P, const uint8_t *x, int a, int dp)
{
    {
        int xi = x[P.i] ^ P.rc0i;
        int b = P.S[xi] ^ P.S[xi ^ a];
        int t1 = P.rc2jp, t2 = P.rc2jp;
        for (int q = 0; q < DG; q++) {
            int l = P.ROWK[q];
            int y = 0;
            for (int e = l * DG; e < l * DG + DG; e++) y ^= P.T0[e][x[P.EI[e]]];
            t1 ^= P.GM[P.ROWC[q]][P.S[y ^ P.RC1[l]]];
            t2 ^= P.GM[P.ROWC[q]][P.S[(y ^ P.GM[P.MMi[l]][b]) ^ P.RC1[l]]];
        }
        int g1 = t1 ^ P.SI[P.S[t1] ^ dp], g2 = t2 ^ P.SI[P.S[t2] ^ dp];
        int eps = -1, ok = 1, u3i = 0;
        for (int kk = 0; kk < NB; kk++) {
            int y = 0;
            for (int e = kk * DG; e < kk * DG + DG; e++) y ^= P.T0[e][x[P.EI[e]]];
            int z1 = P.S[y ^ P.RC1[kk]];
            int z2 = P.S[(y ^ P.GM[P.MMi[kk]][b]) ^ P.RC1[kk]];
            int u3 = P.SI[z1 ^ P.GM[P.MIjp[kk]][g1]];
            int u4 = P.SI[z2 ^ P.GM[P.MIjp[kk]][g2]];
            int dk = u3 ^ u4, mk = P.MMi[kk];
            if (!mk) {
                if (dk) { ok = 0; break; }
            } else {
                int e = P.GM[dk][P.GINV[mk]];
                if (eps < 0) eps = e;
                else if (e != eps) { ok = 0; break; }
            }
            u3i ^= P.GM[P.MIi[kk]][u3 ^ P.RC1[kk]];
        }
        return ok && eps >= 0 && (P.SI[u3i] ^ P.SI[u3i ^ eps]) == a;
    }
}

__device__ __forceinline__ void charger(const b3_param *gp, b3_param *P)
{
    const uint32_t *src = (const uint32_t *)gp;
    uint32_t *dst = (uint32_t *)P;
    for (int q = threadIdx.x; q < (int)(sizeof(b3_param) / 4); q += blockDim.x)
        dst[q] = src[q];
    __syncthreads();
}

__device__ __forceinline__ void cumuler(unsigned long long k, unsigned long long *cpt)
{
    for (int o = 16; o; o >>= 1) k += __shfl_down_sync(0xFFFFFFFFu, k, o);
    if ((threadIdx.x & 31) == 0 && k) atomicAdd(cpt, k);
}

__global__ void k_b3(const b3_param *gp, uint64_t graine, uint64_t flux, uint64_t n, unsigned long long *cpt)
{
    __shared__ b3_param P;
    charger(gp, &P);
    const uint64_t base = mix64(graine ^ mix64(flux + 0x9E3779B97F4A7C15ULL));
    unsigned long long k = 0;
    uint8_t x[NB];
    for (uint64_t s = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x; s < n; s += (uint64_t)gridDim.x * blockDim.x) {
        etat(base, s, x);
        k += b3_un(P, x, P.a, P.dp);
    }
    cumuler(k, cpt);
}

/* balayage : les 225 couples (a, δ') d'un couple (i, j') ; blockIdx.y = 15(a−1) + δ'−1 ;
 * flux = flux0 + blockIdx.y (indépendant par combinaison, même flux pour toutes les S-box) */
__global__ void k_b3_bal(const b3_param *gp, uint64_t graine, uint64_t flux0, uint64_t n, unsigned long long *cpt)
{
    __shared__ b3_param P;
    charger(gp, &P);
    const int c = blockIdx.y, a = c / 15 + 1, dp = c % 15 + 1;
    const uint64_t base = mix64(graine ^ mix64(flux0 + c + 0x9E3779B97F4A7C15ULL));
    unsigned long long k = 0;
    uint8_t x[NB];
    for (uint64_t s = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x; s < n; s += (uint64_t)gridDim.x * blockDim.x) {
        etat(base, s, x);
        k += b3_un(P, x, a, dp);
    }
    cumuler(k, cpt + c);
}

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "CUDA %s:%d : %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); return -1; } } while (0)

/* compte les retours sur n quartets ; renvoie 0 si succès */
extern "C" int b3_gpu_compter(const void *param, uint64_t graine, uint64_t flux, uint64_t n, unsigned long long *k)
{
    static b3_param *dp = 0;
    static unsigned long long *dk = 0;
    if (!dp) { CK(cudaMalloc(&dp, sizeof(b3_param))); CK(cudaMalloc(&dk, sizeof *dk)); }
    CK(cudaMemcpy(dp, param, sizeof(b3_param), cudaMemcpyHostToDevice));
    CK(cudaMemset(dk, 0, sizeof *dk));
    int nsm = 0;
    CK(cudaDeviceGetAttribute(&nsm, cudaDevAttrMultiProcessorCount, 0));
    uint64_t blocs = (n + 255) / 256;
    if (blocs > (uint64_t)nsm * 16) blocs = (uint64_t)nsm * 16;
    k_b3<<<(unsigned)blocs, 256>>>(dp, graine, flux, n, dk);
    CK(cudaGetLastError());
    CK(cudaMemcpy(k, dk, sizeof *k, cudaMemcpyDeviceToHost));
    return 0;
}

/* balayage des 225 (a, δ') d'un couple (i, j') : k[c] pour c = 15(a−1) + δ'−1 */
extern "C" int b3_gpu_balayer(const void *param, uint64_t graine, uint64_t flux0, uint64_t n, unsigned long long k[225])
{
    static b3_param *dp = 0;
    static unsigned long long *dk = 0;
    if (!dp) { CK(cudaMalloc(&dp, sizeof(b3_param))); CK(cudaMalloc(&dk, 225 * sizeof *dk)); }
    CK(cudaMemcpy(dp, param, sizeof(b3_param), cudaMemcpyHostToDevice));
    CK(cudaMemset(dk, 0, 225 * sizeof *dk));
    uint64_t bx = (n + 1023) / 1024;            /* 4 quartets par fil */
    if (bx < 1) bx = 1;
    if (bx > 1024) bx = 1024;
    k_b3_bal<<<dim3((unsigned)bx, 225), 256>>>(dp, graine, flux0, n, dk);
    CK(cudaGetLastError());
    CK(cudaMemcpy(k, dk, 225 * sizeof *dk, cudaMemcpyDeviceToHost));
    return 0;
}

extern "C" size_t b3_gpu_taille_param(void) { return sizeof(b3_param); }

extern "C" int b3_gpu_info(char *nom, size_t lg)
{
    cudaDeviceProp p;
    CK(cudaGetDeviceProperties(&p, 0));
    snprintf(nom, lg, "%s", p.name);
    return 0;
}
