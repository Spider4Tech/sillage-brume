/* Noyaux CUDA de l'attaque de Kales–Zaverucha à échelle réduite (hôte : tests/gpu/sig_kz_gpu.c, interface : sig_kz_gpu.h).
 *
 * Instance compilée en dur, celle de tests/c/sig_kz_commun.h (kz_gpu_init compare les dimensions à celles de l'hôte) :
 * N = 2^8 feuilles, τ = 4, t = 1, graines de 16 octets, hachés de 32, K = GF(2^12).
 *   - k_h1 : une tentative de h1 par fil, transcription de engager() : graine maîtresse, arbre GGM parcouru en profondeur
 *     (pile de D + 1 graines, chaque nœud haché une fois), parts et engagements des 256 feuilles, aux, engagement de la
 *     dernière feuille, haché des engagements absorbé au fil de l'eau, h1, défis (r, ε). Le faux positif ε·T(r) = 0 est lu
 *     dans une table de T(r) = 0 calculée par l'hôte sur tout K (valeur_T du code C) : le GPU ne fait aucune arithmétique
 *     de corps hors du produit a·b de aux.
 *   - k_h2 : une cible par fil, diffusion recomposée axe par axe, h2 puis défis ; le plus petit u gagnant est retenu.
 * SHAKE256 : même éponge octet par octet que sillage/c/commun.c (sl_shake_absorb / final / squeeze), Keccak-f[1600] en
 * registres. Conformité : contrôles conformite_gpu_c_h1_et_faux_positifs et conformite_gpu_c_h2 de l'hôte.
 * ponytail: un état d'éponge par fil en mémoire locale ; passer à un warp par tentative si le débit en est limité. */
#include <cuda_runtime.h>
#include <stdio.h>
#include <string.h>

#include "sig_kz_gpu.h"

enum { KN = 256, KD = 8, KTAU = 4, KT = 1, KSB = 16, KHB = 32, KLP = 18, KLSK = 12, KPTS = 2, KLA = 14, KEP = 12,
       KLREP = (2 + 3 * KD) * KPTS, TAUX = 136, LMSG = 54 + KSB };

__constant__ uint64_t c_KRC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
__device__ constexpr int RHO[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
                                    41, 45, 15, 21, 8, 18, 2, 61, 56, 14};   /* indice x + 5y */

__constant__ uint8_t c_sk[KLSK], c_pkh[KHB], c_mh[KHB], c_masque[KLP], c_tz[(1 << KEP) / 8];
__constant__ uint64_t c_pb;

__device__ __forceinline__ uint64_t rotl(uint64_t x, int n) { return (x << n) | (x >> ((64 - n) & 63)); }

__device__ __noinline__ void keccakf(uint64_t *st)
{
    uint64_t a[25];
#pragma unroll
    for (int i = 0; i < 25; i++) a[i] = st[i];
#pragma unroll 1
    for (int r = 0; r < 24; r++) {
        uint64_t c[5], b[25];
#pragma unroll
        for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
#pragma unroll
        for (int x = 0; x < 5; x++) {
            uint64_t d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
#pragma unroll
            for (int y = 0; y < 5; y++) a[x + 5 * y] ^= d;
        }
#pragma unroll
        for (int x = 0; x < 5; x++)
#pragma unroll
            for (int y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], RHO[x + 5 * y]);
#pragma unroll
        for (int x = 0; x < 5; x++)
#pragma unroll
            for (int y = 0; y < 5; y++) a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        a[0] ^= c_KRC[r];
    }
#pragma unroll
    for (int i = 0; i < 25; i++) st[i] = a[i];
}

/* --------------------------------------------------------- SHAKE256, comme sillage/c/commun.c */
struct Eponge { uint64_t s[25]; int pos; };

__device__ __forceinline__ void ep_init(Eponge &h)
{
#pragma unroll
    for (int i = 0; i < 25; i++) h.s[i] = 0;
    h.pos = 0;
}

__device__ void ep_abs(Eponge &h, const uint8_t *d, int n)
{
    uint8_t *st = (uint8_t *)h.s;
    for (int i = 0; i < n; i++) {
        st[h.pos++] ^= d[i];
        if (h.pos == TAUX) { keccakf(h.s); h.pos = 0; }
    }
}

__device__ void ep_fin(Eponge &h)
{
    uint8_t *st = (uint8_t *)h.s;
    st[h.pos] ^= 0x1F;
    st[TAUX - 1] ^= 0x80;
    keccakf(h.s);
    h.pos = 0;
}

__device__ void ep_sortie(Eponge &h, uint8_t *o, int n)
{
    const uint8_t *st = (const uint8_t *)h.s;
    while (n) {
        if (h.pos == TAUX) { keccakf(h.s); h.pos = 0; }
        int k = TAUX - h.pos < n ? TAUX - h.pos : n;
        for (int i = 0; i < k; i++) o[i] = st[h.pos + i];
        h.pos += k; o += k; n -= k;
    }
}

/* sl_shake_dom : dom ‖ "|" ‖ parties */
__device__ void ep_dom(Eponge &h, const char *dom)
{
    int n = 0;
    while (dom[n]) n++;
    ep_init(h);
    ep_abs(h, (const uint8_t *)dom, n);
    ep_abs(h, (const uint8_t *)"|", 1);
}

__device__ __forceinline__ void be32(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16); o[2] = (uint8_t)(v >> 8); o[3] = (uint8_t)v;
}

/* msg_noeud + SHAKE256 brut : m porte déjà "SILLAGE-SIG|?|" ‖ sel ‖ rep */
__device__ void noeud(uint8_t *m, char tag, uint32_t i, const uint8_t *g, uint8_t *o, int n)
{
    m[12] = (uint8_t)tag;
    be32(m + 50, i);
    for (int b = 0; b < KSB; b++) m[54 + b] = g[b];
    Eponge h;
    ep_init(h);
    ep_abs(h, m, LMSG);
    ep_fin(h);
    ep_sortie(h, o, n);
}

__device__ uint64_t gf_mul(uint64_t a, uint64_t b)        /* GF(2^ep) = F2[x]/(pb) */
{
    uint64_t r = 0;
    for (int i = 0; i < KEP; i++) r ^= (0 - ((b >> i) & 1)) & (a << i);
    for (int i = 2 * KEP - 2; i >= KEP; i--) r ^= (0 - ((r >> i) & 1)) & (c_pb << (i - KEP));
    return r;
}

/* une tentative : h1 et nombre de répétitions à faux positif (transcription de engager() puis faux_positif()) */
__device__ int tentative(const uint8_t *sel, uint8_t *h1)
{
    uint8_t mseed[KHB], hs[KTAU * KHB], m[LMSG], rb[4];
    Eponge h;
    ep_dom(h, "SILLAGE-SIG|mseed");
    ep_abs(h, c_sk, KLSK); ep_abs(h, sel, 32); ep_abs(h, c_mh, KHB);
    ep_fin(h); ep_sortie(h, mseed, KHB);
    const char *pre = "SILLAGE-SIG|";
    for (int b = 0; b < 12; b++) m[b] = (uint8_t)pre[b];
    m[13] = '|';
    for (int b = 0; b < 32; b++) m[14 + b] = sel[b];
    for (uint32_t rep = 0; rep < KTAU; rep++) {
        uint8_t pile[KD + 1][KSB], frere[KD + 1][KSB], o[2 * KSB], part[KLP], tot[KLP], com[KHB], aux[KLA];
        be32(rb, rep);
        be32(m + 46, rep);
        ep_dom(h, "SILLAGE-SIG|r");
        ep_abs(h, mseed, KHB); ep_abs(h, rb, 4);
        ep_fin(h); ep_sortie(h, pile[0], KSB);
        Eponge hc;                                           /* hacher_coms, absorbé feuille par feuille */
        ep_dom(hc, "SILLAGE-SIG|com");
        ep_abs(hc, sel, 32); ep_abs(hc, rb, 4);
        for (int b = 0; b < KLP; b++) tot[b] = 0;
        for (uint32_t i = 0; i < KN; i++) {
            int deb = 1;
            if (i) {                                         /* le bit ctz(i) passe de 0 à 1 : frère droit, puis fils gauches */
                deb = KD - (__ffs((int)i) - 1);
                for (int b = 0; b < KSB; b++) pile[deb][b] = frere[deb][b];
                deb++;
            }
            for (int l = deb; l <= KD; l++) {
                noeud(m, 'a', (KN + i) >> (KD - l + 1), pile[l - 1], o, 2 * KSB);
                for (int b = 0; b < KSB; b++) { pile[l][b] = o[b]; frere[l][b] = o[KSB + b]; }
            }
            noeud(m, 'f', i, pile[KD], part, KLP);
            for (int b = 0; b < KLP; b++) tot[b] ^= part[b] & c_masque[b];
            if (i < KN - 1) {
                noeud(m, 'c', i, pile[KD], com, KHB);
                ep_abs(hc, com, KHB);
            }
        }
        /* aux = sk ⊕ tot, et c corrigé pour que Σc = a·b ; pile[KD] porte encore la graine de la feuille N − 1 */
        for (int b = 0; b < KLSK; b++) aux[b] = c_sk[b] ^ tot[b];
        uint64_t a = (tot[KLSK] | (uint64_t)tot[KLSK + 1] << 8) & ((1u << KEP) - 1);
        uint64_t bb = (tot[KLSK + KPTS] | (uint64_t)tot[KLSK + KPTS + 1] << 8) & ((1u << KEP) - 1);
        uint64_t ab = gf_mul(a, bb);
        for (int b = 0; b < KPTS; b++) aux[KLSK + b] = (uint8_t)(ab >> (8 * b)) ^ tot[KLSK + 2 * KPTS + b];
        uint8_t ib[4];
        be32(ib, KN - 1);
        ep_dom(h, "SILLAGE-SIG|c");
        ep_abs(h, sel, 32); ep_abs(h, rb, 4); ep_abs(h, ib, 4); ep_abs(h, pile[KD], KSB); ep_abs(h, aux, KLA);
        ep_fin(h); ep_sortie(h, com, KHB);
        ep_abs(hc, com, KHB);
        ep_fin(hc); ep_sortie(hc, hs + rep * KHB, KHB);
    }
    ep_dom(h, "SILLAGE-SIG|h1");
    ep_abs(h, sel, 32); ep_abs(h, c_pkh, KHB); ep_abs(h, c_mh, KHB); ep_abs(h, hs, KTAU * KHB);
    ep_fin(h); ep_sortie(h, h1, KHB);
    uint8_t d[2 * KTAU * KT * 6];
    ep_dom(h, "SILLAGE-SIG|ch1");
    ep_abs(h, h1, KHB);
    ep_fin(h); ep_sortie(h, d, sizeof d);
    int nf = 0;
    for (int i = 0; i < KTAU * KT; i++) {
        uint64_t r = 0, e = 0;
        for (int b = 0; b < 6; b++) { r |= (uint64_t)d[12 * i + b] << (8 * b); e |= (uint64_t)d[12 * i + 6 + b] << (8 * b); }
        r &= (1u << KEP) - 1; e &= (1u << KEP) - 1;
        nf += e == 0 || (c_tz[r >> 3] >> (r & 7) & 1);
    }
    return nf;
}

__global__ void k_h1(uint64_t graine, uint32_t si, const uint32_t *essais, uint32_t a0, uint32_t C, uint32_t nfils, uint8_t *nf)
{
    uint32_t f = blockIdx.x * blockDim.x + threadIdx.x;
    if (f >= nfils) return;
    uint8_t sel[32], h1[KHB];
    kz_sel(graine, si, essais[f / C], a0 + f % C, sel);
    nf[f] = (uint8_t)tentative(sel, h1);
}

__global__ void k_h1_sels(const uint8_t *sels, uint32_t nb, uint8_t *h1, uint8_t *nf)
{
    uint32_t f = blockIdx.x * blockDim.x + threadIdx.x;
    if (f >= nb) return;
    uint8_t sel[32], o[KHB];
    for (int b = 0; b < 32; b++) sel[b] = sels[32 * f + b];
    nf[f] = (uint8_t)tentative(sel, o);
    for (int b = 0; b < KHB; b++) h1[KHB * f + b] = o[b];
}

struct ParamH2 { uint8_t sel[32], h1[KHB], lignes[KTAU][2][KLREP]; uint32_t libres; };

__global__ void k_h2(const ParamH2 P, uint64_t base, uint64_t lim, unsigned long long *premier, uint32_t *ci, uint32_t ndbg)
{
    uint64_t u = base + blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (u >= lim) return;
    uint32_t cible[KTAU];
    uint64_t v = u;
    for (int rep = 0; rep < KTAU; rep++) {
        cible[rep] = 0;
        if (P.libres >> rep & 1) { cible[rep] = (uint32_t)(v % KN); v /= KN; }
    }
    Eponge h;
    ep_dom(h, "SILLAGE-SIG|h2");
    ep_abs(h, P.sel, 32); ep_abs(h, c_pkh, KHB); ep_abs(h, c_mh, KHB); ep_abs(h, P.h1, KHB);
    for (int rep = 0; rep < KTAU; rep++) {
        ep_abs(h, P.lignes[rep][0], 2 * KPTS);
        for (int d = 0; d < KD; d++) ep_abs(h, P.lignes[rep][cible[rep] >> d & 1] + (2 + 3 * d) * KPTS, 3 * KPTS);
    }
    uint8_t h2[KHB], s[2 * KTAU];
    ep_fin(h); ep_sortie(h, h2, KHB);
    ep_dom(h, "SILLAGE-SIG|ch2");
    ep_abs(h, h2, KHB);
    ep_fin(h); ep_sortie(h, s, sizeof s);
    int ok = 1;
    for (int rep = 0; rep < KTAU; rep++) {
        uint32_t c = (s[2 * rep] | (uint32_t)s[2 * rep + 1] << 8) & (KN - 1);
        if (ci && u < ndbg) ci[KTAU * u + rep] = c;
        if (P.libres >> rep & 1) ok &= c == cible[rep];
    }
    if (ok) atomicMin(premier, (unsigned long long)u);
}

/* --------------------------------------------------------- hôte */
#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "sig_kz_gpu : %s : %s\n", #x, cudaGetErrorString(e_)); return -1; } } while (0)

static uint32_t *d_essais;
static uint8_t *d_nf, *d_sels, *d_h1;
static size_t cap_essais, cap_nf, cap_sels;
static unsigned long long *d_premier;
static uint32_t *d_ci;
static size_t cap_ci;

static int agrandir(void **p, size_t *cap, size_t n)
{
    if (n <= *cap) return 0;
    if (*p) cudaFree(*p);
    *p = NULL;
    size_t c = n + n / 2;
    CK(cudaMalloc(p, c));
    *cap = c;
    return 0;
}

extern "C" int kz_gpu_init(const kz_dims_t *d, const uint8_t *sk, const uint8_t *pkh, const uint8_t *mh,
                           const uint8_t *masque, const uint8_t *tz, char *nom, int lnom)
{
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess || n < 1) { fprintf(stderr, "sig_kz_gpu : aucun GPU CUDA\n"); return -1; }
    cudaDeviceProp pr;
    CK(cudaGetDeviceProperties(&pr, 0));
    snprintf(nom, lnom, "%s (sm_%d%d, %d SM%s)", pr.name, pr.major, pr.minor, pr.multiProcessorCount,
             pr.kernelExecTimeoutEnabled ? ", chien de garde d'affichage actif" : "");
    if (d->N != KN || d->D != KD || d->tau != KTAU || d->t != KT || d->sb != KSB || d->hb != KHB || d->Lp != KLP ||
        d->lsk != KLSK || d->pts != KPTS || d->La != KLA || d->ep != KEP || d->lrep != KLREP) {
        fprintf(stderr, "sig_kz_gpu : dimensions de l'instance différentes de celles du noyau\n");
        return -1;
    }
    CK(cudaMemcpyToSymbol(c_sk, sk, KLSK));
    CK(cudaMemcpyToSymbol(c_pkh, pkh, KHB));
    CK(cudaMemcpyToSymbol(c_mh, mh, KHB));
    CK(cudaMemcpyToSymbol(c_masque, masque, KLP));
    CK(cudaMemcpyToSymbol(c_tz, tz, (1 << KEP) / 8));
    CK(cudaMemcpyToSymbol(c_pb, &d->pb, 8));
    CK(cudaMalloc(&d_premier, sizeof *d_premier));
    return 0;
}

extern "C" int kz_gpu_h1(uint64_t graine, uint32_t si, const uint32_t *essais, uint32_t nessais, uint32_t a0, uint32_t C,
                         uint8_t *nf, float *ms)
{
    uint32_t nfils = nessais * C;
    if (agrandir((void **)&d_essais, &cap_essais, 4 * (size_t)nessais) || agrandir((void **)&d_nf, &cap_nf, nfils)) return -1;
    CK(cudaMemcpy(d_essais, essais, 4 * (size_t)nessais, cudaMemcpyHostToDevice));
    cudaEvent_t e0, e1;
    CK(cudaEventCreate(&e0)); CK(cudaEventCreate(&e1));
    CK(cudaEventRecord(e0));
    k_h1<<<(nfils + 127) / 128, 128>>>(graine, si, d_essais, a0, C, nfils, d_nf);
    CK(cudaGetLastError());
    CK(cudaEventRecord(e1));
    CK(cudaEventSynchronize(e1));
    CK(cudaEventElapsedTime(ms, e0, e1));
    cudaEventDestroy(e0); cudaEventDestroy(e1);
    CK(cudaMemcpy(nf, d_nf, nfils, cudaMemcpyDeviceToHost));
    return 0;
}

extern "C" int kz_gpu_h1_sels(const uint8_t *sels, uint32_t nb, uint8_t *h1, uint8_t *nf)
{
    if (agrandir((void **)&d_sels, &cap_sels, 32 * (size_t)nb) || agrandir((void **)&d_nf, &cap_nf, nb)) return -1;
    if (d_h1) cudaFree(d_h1);
    CK(cudaMalloc(&d_h1, (size_t)KHB * nb));
    CK(cudaMemcpy(d_sels, sels, 32 * (size_t)nb, cudaMemcpyHostToDevice));
    k_h1_sels<<<(nb + 127) / 128, 128>>>(d_sels, nb, d_h1, d_nf);
    CK(cudaGetLastError());
    CK(cudaDeviceSynchronize());
    CK(cudaMemcpy(h1, d_h1, (size_t)KHB * nb, cudaMemcpyDeviceToHost));
    CK(cudaMemcpy(nf, d_nf, nb, cudaMemcpyDeviceToHost));
    return 0;
}

extern "C" int kz_gpu_h2(const uint8_t *sel, const uint8_t *h1, const uint8_t *lignes, uint32_t libres, uint64_t lim,
                         int64_t *premier, uint32_t *ci, uint32_t ndbg)
{
    ParamH2 P;
    memcpy(P.sel, sel, 32);
    memcpy(P.h1, h1, KHB);
    memcpy(P.lignes, lignes, sizeof P.lignes);
    P.libres = libres;
    if (ndbg > lim) ndbg = (uint32_t)lim;
    if (ci && agrandir((void **)&d_ci, &cap_ci, 4 * (size_t)KTAU * (ndbg ? ndbg : 1))) return -1;
    *premier = -1;
    const uint64_t LOT = 1u << 22;                         /* par tranches croissantes : la première qui gagne donne le minimum */
    for (uint64_t base = 0; base < lim; base += LOT) {
        unsigned long long rien = ~0ULL, r;
        uint64_t n = lim - base < LOT ? lim - base : LOT;
        CK(cudaMemcpy(d_premier, &rien, sizeof rien, cudaMemcpyHostToDevice));
        k_h2<<<(unsigned)((n + 127) / 128), 128>>>(P, base, base + n, d_premier, ci ? d_ci : NULL, ndbg);
        CK(cudaGetLastError());
        CK(cudaMemcpy(&r, d_premier, sizeof r, cudaMemcpyDeviceToHost));
        if (ci && base == 0) CK(cudaMemcpy(ci, d_ci, 4 * (size_t)KTAU * ndbg, cudaMemcpyDeviceToHost));
        if (r != ~0ULL) { *premier = (int64_t)r; break; }
    }
    return 0;
}

extern "C" void kz_gpu_fin(void)
{
    cudaFree(d_essais); cudaFree(d_nf); cudaFree(d_sels); cudaFree(d_h1); cudaFree(d_premier); cudaFree(d_ci);
}
