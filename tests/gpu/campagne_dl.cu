/* Campagne GPU n° 1 : différentielles tronquées alignées et différentielle-linéaire sur BRUME-512.
 *
 * Paires (x, x ⊕ Δ), Δ sur un seul nibble j0. En direct, on applique R − 1 tours puis la seule couche S du
 * tour R : la dernière couche linéaire est retirée (alignement), ce qui revient à lire M⁻¹ · (différence
 * de sortie). En inverse, Δ = M·(δ en j0) est pré-diffusée, et les R derniers tours sont inversés, ce qui
 * se termine par S⁻¹, donc déjà aligné. On compte, pour chacun des 128 nibbles, les 16 valeurs de la
 * différence. Le même histogramme donne :
 *   - le χ² à 15 ddl par nibble (différentielle tronquée ; approximation de Wilson–Hilferty) ;
 *   - la corrélation différentielle-linéaire c(j, m) = E[(−1)^{m·D_j}] pour les 1 920 masques d'un nibble.
 * Bonferroni sur 128 nibbles et sur 1 920 masques. Témoins : 5 tours en direct et 2 en inverse (portée
 * connue, doivent être détectés) ; 32 tours (H0, ne doit pas l'être). Voir PLAN ci-dessous.
 *
 * Reprise : <dossier>/reprise.bin est réécrit toutes les 10 min, à chaque fin d'expérience et à l'arrêt
 * (SIGTERM). Relancer avec le même dossier reprend là où l'on s'était arrêté ; un fichier du plan de base (format 01)
 * se reprend aussi avec --long, les cibles ajoutées partant de zéro.
 * Portable : compilé pour sm_75 (Turing, RTX 20xx) et sm_89 (Ada) ; 8 blocs par SM ; lancements de moins de 0,5 s
 * (chien de garde de l'affichage, TDR de Windows sous WSL).
 *     tests/gpu/build/campagne_dl <dossier> <budget_s> [échelle] [--long]   (depuis la racine)
 *     --long : plan étendu (cibles ci-dessous après les 9 du plan de base), pour une carte qui peut tourner plus longtemps
 *     → resultats/gpu_dl.json et resultats/gpu_dl.md */
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define _Static_assert static_assert
extern "C" {
#include "brume_ref.h"
}
#include "resultat.h"
#include "brume.cuh"

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "CUDA %s:%d : %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); exit(2); } } while (0)

/* force = k > 0 : témoin de sensibilité, une paire sur 2^k reçoit une différence nulle au nibble 5 */
typedef struct { const char *role; int sens, R, j0, delta, log2N, force; } exp_t;

/* Ordre de priorité ; delta 0 = valeur de la ligne de DDT la plus forte (choisie à l'exécution).
 * « structure » : 5 tours alignés en direct (M⁴ laisse un nibble hors d'atteinte) et 2 en inverse ; ces cas sont
 * détectés de façon déterministe : ils contrôlent l'alignement, pas la sensibilité. Le témoin de sensibilité
 * est un biais imposé de 2^−15 à 32 tours : z attendu ≈ 3,9 · 2^−15 · √N ≈ 7,6 à 2^32 paires. Rapporté à 2^40
 * paires, la campagne voit donc des biais de l'ordre de 2^−19 par case. */
static const exp_t PLAN[] = {
    {"h0", 0, 32, 0, 1, 32, 0},
    {"temoin", 0, 32, 0, 1, 32, 15},
    {"structure", 0, 5, 0, 0, 24, 0},
    {"structure", 1, 2, 0, 0, 24, 0},
    {"cible", 0, 6, 0, 0, 40, 0},
    {"cible", 0, 6, 77, 0, 40, 0},
    {"cible", 1, 3, 0, 0, 39, 0},
    {"cible", 0, 6, 0, 0, 42, 0},
    {"cible", 0, 7, 0, 0, 40, 0},
    /* plan étendu (--long), après le plan de base : 7 tours avec 4 fois plus de paires, l'inverse sur un autre nibble
     * et sur 4 tours, puis 6 tours à 2^44 (sensibilité ≈ 2^−21 par case), le plus long */
    {"cible", 0, 7, 0, 0, 42, 0},
    {"cible", 1, 3, 77, 0, 39, 0},
    {"cible", 1, 4, 0, 0, 40, 0},
    {"cible", 0, 6, 0, 0, 44, 0},
};
#define NEXP_MAX ((int)(sizeof PLAN / sizeof PLAN[0]))
#define NEXP_BASE 9
static int NEXP = NEXP_BASE;                    /* NEXP_MAX avec --long */
#define NH (BR_N * 16)

typedef struct {
    uint64_t fait, cible;                 /* paires mesurées, paires visées */
    double duree;
    uint64_t n[NH];
} etat_t;

static volatile sig_atomic_t arret = 0;
static void sur_signal(int s) { (void)s; arret = 1; }

__device__ __forceinline__ uint64_t sm64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

template <int INV>
__global__ void k_paires(int R, int force, uint64_t graine, uint64_t debut, int iters, const uint32_t *dl,
                         const uint32_t *mi, unsigned long long *n)
{
    __shared__ uint32_t h[NH];
    __shared__ uint32_t MI[INV ? 512 * 16 : 1];
    for (int i = threadIdx.x; i < NH; i += blockDim.x)
        h[i] = 0;
    if (INV)
        for (int i = threadIdx.x; i < 512 * 16; i += blockDim.x)
            MI[i] = mi[i];
    uint32_t D[16];
    for (int k = 0; k < 16; k++)
        D[k] = dl[k];
    __syncthreads();
    uint64_t t = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    for (int it = 0; it < iters; it++) {
        uint64_t idx = debut + t * (uint64_t)iters + (uint64_t)it;
        uint32_t a[16], b[16];
        for (int k = 0; k < 8; k++) {
            uint64_t z = sm64(graine ^ (idx * 8 + (uint64_t)k));
            a[2 * k] = (uint32_t)z;
            a[2 * k + 1] = (uint32_t)(z >> 32);
        }
        for (int k = 0; k < 16; k++)
            b[k] = a[k] ^ D[k];
        if (INV) {
            brume_arriere(a, BR_TOURS - 1, R, MI);
            brume_arriere(b, BR_TOURS - 1, R, MI);
        } else {
            brume_avant(a, 0, R - 1);
            brume_avant(b, 0, R - 1);
            for (int k = 0; k < 16; k++) {           /* couche S du tour R, sans M */
                a[k] = sbox8(a[k] ^ c_RCW[R - 1][k], bdev::ANF_S);
                b[k] = sbox8(b[k] ^ c_RCW[R - 1][k], bdev::ANF_S);
            }
        }
        if (force && !(idx & ((1ull << force) - 1)))
            b[0] = (b[0] & ~0xF00000u) | (a[0] & 0xF00000u);
#pragma unroll
        for (int j = 0; j < BR_N; j++)
            atomicAdd(&h[16 * j + (((a[j >> 3] ^ b[j >> 3]) >> (4 * (j & 7))) & 15)], 1u);
    }
    __syncthreads();
    for (int i = threadIdx.x; i < NH; i += blockDim.x)
        atomicAdd(&n[i], (unsigned long long)h[i]);
}

/* ---- statistiques ---- */
static double z_wh(double x, double k)             /* χ²(k) → z (Wilson–Hilferty) */
{
    double a = 2.0 / (9.0 * k);
    return (cbrt(x / k) - (1.0 - a)) / sqrt(a);
}
static double queue(double z) { return 0.5 * erfc(z / sqrt(2.0)); }   /* P[N(0,1) > z] */

typedef struct { double chi2, zchi, pchi, zdl, pdl; int jchi, jdl, mdl; } stat_t;

static stat_t statistiques(const etat_t *e)
{
    stat_t s = {0};
    double N = (double)e->fait, att = N / 16;
    s.zchi = -1e9;
    for (int j = 0; j < BR_N; j++) {
        double x = 0;
        for (int v = 0; v < 16; v++) {
            double d = (double)e->n[16 * j + v] - att;
            x += d * d / att;
        }
        double z = z_wh(x, 15);
        if (z > s.zchi) { s.zchi = z; s.chi2 = x; s.jchi = j; }
        for (int m = 1; m < 16; m++) {
            double c = 0;
            for (int v = 0; v < 16; v++)
                c += (__builtin_popcount(m & v) & 1 ? -1.0 : 1.0) * (double)e->n[16 * j + v];
            double zz = fabs(c) / sqrt(N);
            if (zz > s.zdl) { s.zdl = zz; s.jdl = j; s.mdl = m; }
        }
    }
    s.pchi = fmin(1.0, BR_N * queue(s.zchi));
    s.pdl = fmin(1.0, BR_N * 15 * 2 * queue(s.zdl));
    return s;
}

/* ---- reprise ---- */
static int charger(const char *f, etat_t *E)
{
    FILE *p = fopen(f, "rb");
    if (!p)
        return 0;
    /* format 01 : 9 états (plan de base) ; format 02 : nombre d'états, puis les états */
    char m[8];
    int n = 0, ok = fread(m, 1, 8, p) == 8;
    if (ok && !memcmp(m, "BRGPDL01", 8)) n = NEXP_BASE;
    else if (ok && !memcmp(m, "BRGPDL02", 8)) ok = fread(&n, sizeof n, 1, p) == 1;
    else ok = 0;
    if (ok && n > NEXP && n <= NEXP_MAX) {      /* fichier du plan étendu repris sans --long : on le garde étendu */
        fprintf(stderr, "reprise d'un plan de %d expériences : plan étendu conservé\n", n);
        NEXP = n;
    }
    ok = ok && n >= 1 && n <= NEXP && fread(E, sizeof(etat_t), (size_t)n, p) == (size_t)n;
    fclose(p);
    for (int q = n; ok && q < NEXP; q++) {      /* cibles du plan étendu absentes du fichier : à zéro */
        memset(&E[q], 0, sizeof E[q]);
        E[q].cible = 0;                          /* fixée par main */
    }
    return ok ? n : 0;
}
static void sauver(const char *f, const etat_t *E)
{
    char t[600];
    snprintf(t, sizeof t, "%s.tmp", f);
    FILE *p = fopen(t, "wb");
    if (!p) { perror(t); return; }
    fwrite("BRGPDL02", 1, 8, p);
    fwrite(&NEXP, sizeof NEXP, 1, p);
    fwrite(E, sizeof(etat_t), (size_t)NEXP, p);
    if (fclose(p) == 0)
        rename(t, f);
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + 1e-9 * t.tv_nsec;
}

/* conformité rapide du noyau utilisé, contre la bibliothèque C (direct) et la référence dense (inverse) */
__global__ void k_conf(uint32_t *s, int n, int R, int inv, const uint32_t *mi)
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
    if (inv)
        brume_arriere(w, BR_TOURS - 1, R, MI);
    else
        brume_avant(w, 0, R);
    for (int k = 0; k < 16; k++)
        s[16 * t + k] = w[k];
}

static int conforme(const uint32_t *d_mi)
{
    const int n = 4096;
    static uint32_t a[16 * 4096], b[16 * 4096];
    uint64_t g = 12345;
    for (int i = 0; i < 16 * n; i++) {
        g = g * 6364136223846793005ULL + 1442695040888963407ULL;
        a[i] = (uint32_t)(g >> 32);
    }
    uint32_t *d;
    CK(cudaMalloc(&d, sizeof a));
    int ok = 1;
    for (int R = 5; R <= 7; R++) {
        CK(cudaMemcpy(d, a, sizeof a, cudaMemcpyHostToDevice));
        k_conf<<<n / 256, 256>>>(d, n, R, 0, d_mi);
        CK(cudaMemcpy(b, d, sizeof b, cudaMemcpyDeviceToHost));
        for (int i = 0; i < n; i++) {
            uint32_t c[16];
            memcpy(c, a + 16 * i, 64);
            br_tours_avx2((uint64_t *)c, R);
            ok &= !memcmp(c, b + 16 * i, 64);
        }
    }
    CK(cudaMemcpy(d, a, sizeof a, cudaMemcpyHostToDevice));
    k_conf<<<1, 64>>>(d, 64, 3, 1, d_mi);
    CK(cudaMemcpy(b, d, 64 * 64, cudaMemcpyDeviceToHost));
    for (int i = 0; i < 64; i++) {
        uint8_t x[BR_N], y[BR_N];
        for (int j = 0; j < BR_N; j++) {
            x[j] = (uint8_t)((a[16 * i + (j >> 3)] >> (4 * (j & 7))) & 15);
            y[j] = (uint8_t)((b[16 * i + (j >> 3)] >> (4 * (j & 7))) & 15);
        }
        bref_perm(x, 3, 1);
        ok &= !memcmp(x, y, BR_N);
    }
    cudaFree(d);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage : %s <dossier> <budget_s> [échelle] [--long]\n", argv[0]);
        return 2;
    }
    const char *dos = argv[1];
    double budget = atof(argv[2]), echelle = 1.0;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--long")) NEXP = NEXP_MAX;
        else echelle = atof(argv[i]);
    }
    char frep[512];
    snprintf(frep, sizeof frep, "%s/reprise.bin", dos);
    signal(SIGTERM, sur_signal);
    signal(SIGINT, sur_signal);
    if (!bref_init()) return 2;
    br_gpu_init(BR_RC);
    static uint32_t mi[512 * 16];
    br_gpu_mi(BMI, mi, gf_mul);
    uint32_t *d_mi, *d_dl;
    unsigned long long *d_n;
    CK(cudaMalloc(&d_mi, sizeof mi));
    CK(cudaMemcpy(d_mi, mi, sizeof mi, cudaMemcpyHostToDevice));
    CK(cudaMalloc(&d_dl, 64));
    CK(cudaMalloc(&d_n, NH * sizeof(unsigned long long)));

    resultat_t res = {.nom = "gpu_dl", .titre = "Campagne GPU : différentielles tronquées et différentielle-linéaire"};
    int conf = conforme(d_mi);
    res_controle(&res, "noyau_gpu_conforme_direct_5_a_7_tours_et_inverse_3_tours", conf);
    if (!conf) { res_ecrire(&res); return 1; }

    /* δ : la ligne de DDT (direct) ou de DDT de S⁻¹ (inverse) au plus fort coefficient */
    int dmax[2] = {1, 1}, best[2] = {0, 0};
    for (int a = 1; a < 16; a++)
        for (int b = 1; b < 16; b++) {
            int c0 = 0, c1 = 0;
            for (int x = 0; x < 16; x++) {
                c0 += (BR_SBOX[x] ^ BR_SBOX[x ^ a]) == b;
                c1 += (BSI[x] ^ BSI[x ^ a]) == b;
            }
            if (c0 > best[0]) { best[0] = c0; dmax[0] = a; }
            if (c1 > best[1]) { best[1] = c1; dmax[1] = a; }
        }

    static etat_t E[NEXP_MAX];
    int lus = charger(frep, E);
    if (!lus) memset(E, 0, sizeof E);
    for (int q = lus; q < NEXP; q++) {
        double n = ldexp(echelle, PLAN[q].log2N);
        E[q].cible = (uint64_t)fmax(n, 1 << 20);
    }
    if (!lus) fprintf(stderr, "nouvelle campagne dans %s (%d expériences)\n", dos, NEXP);
    else fprintf(stderr, "reprise dans %s (%d expériences reprises sur %d)\n", dos, lus, NEXP);

    cudaDeviceProp prop;
    CK(cudaGetDeviceProperties(&prop, 0));
    res_mesure(&res, "gpu", "\"%s, sm_%d%d, %d SM\"", prop.name, prop.major, prop.minor, prop.multiProcessorCount);
    const int blocs = 8 * prop.multiProcessorCount, fils = 256;   /* 480 sur la 4070 Ti (60 SM), 368 sur la 2080 (46) */
    const double t0 = maintenant();
    double dern_sauv = t0;
    int temoins = 1, h0 = 1, structure = 1, nt = 0, nh = 0, ns = 0;
    for (int q = 0; q < NEXP; q++) {
        const exp_t *x = &PLAN[q];
        etat_t *e = &E[q];
        int delta = x->delta ? x->delta : dmax[x->sens];
        uint32_t D[16] = {0};
        if (!x->sens)
            D[x->j0 >> 3] = (uint32_t)delta << (4 * (x->j0 & 7));
        else
            for (int v = 0; v < BR_N; v++)
                D[v >> 3] |= (uint32_t)gf_mul(BM[v][x->j0], (uint8_t)delta) << (4 * (v & 7));
        CK(cudaMemcpy(d_dl, D, 64, cudaMemcpyHostToDevice));
        CK(cudaMemcpy(d_n, e->n, sizeof e->n, cudaMemcpyHostToDevice));
        int iters = 64;
        while (e->fait < e->cible && !arret && maintenant() - t0 < budget) {
            uint64_t par = (uint64_t)blocs * fils, reste = e->cible - e->fait;
            int it = (int)fmin(iters, ceil((double)reste / par));
            double a = maintenant();
            if (x->sens)
                k_paires<1><<<blocs, fils>>>(x->R, x->force, 0xB2u + q, e->fait, it, d_dl, d_mi, d_n);
            else
                k_paires<0><<<blocs, fils>>>(x->R, x->force, 0xB2u + q, e->fait, it, d_dl, d_mi, d_n);
            CK(cudaDeviceSynchronize());
            CK(cudaGetLastError());
            double dt = maintenant() - a;
            e->fait += par * (uint64_t)it;
            e->duree += dt;
            if (dt < 0.25 && it == iters)              /* lancements de 0,25 à 0,5 s : sous le TDR de Windows (2 s) */
                iters *= 2;
            if (maintenant() - dern_sauv > 600) {
                CK(cudaMemcpy(e->n, d_n, sizeof e->n, cudaMemcpyDeviceToHost));
                sauver(frep, E);
                dern_sauv = maintenant();
                fprintf(stderr, "[%s] %s %s R=%d : 2^%.2f / 2^%.2f paires\n", x->role, x->sens ? "inverse" : "direct",
                        "point de reprise", x->R, log2((double)e->fait), log2((double)e->cible));
            }
        }
        CK(cudaMemcpy(e->n, d_n, sizeof e->n, cudaMemcpyDeviceToHost));
        sauver(frep, E);
        if (e->fait < e->cible)
            break;                                     /* arrêt ou budget : la reprise continuera ici */
        stat_t s = statistiques(e);
        char nom[96];
        snprintf(nom, sizeof nom, "%s_%s_%dt_j%d_d%d_2^%d", x->role, x->sens ? "inverse" : "direct", x->R, x->j0,
                 delta, (int)lround(log2((double)e->fait)));
        int detecte = fmin(s.pchi, s.pdl) < 1e-6;
        res_mesure(&res, nom,
                   "{\"detecte\": %s, \"paires_log2\": %.2f, \"chi2_max\": %.1f, \"nibble_chi2\": %d, \"z_chi2\": %.2f, "
                   "\"p_bonferroni_chi2\": %.3g, \"dl_z_max\": %.2f, \"dl_nibble\": %d, \"dl_masque\": %d, "
                   "\"p_bonferroni_dl\": %.3g, \"duree_s\": %.0f}",
                   detecte ? "true" : "false", log2((double)e->fait), s.chi2, s.jchi, s.zchi, s.pchi, s.zdl, s.jdl, s.mdl, s.pdl, e->duree);
        fprintf(stderr, "%s : p_χ² = %.3g, p_DL = %.3g → %s\n", nom, s.pchi, s.pdl, detecte ? "DÉTECTÉ" : "rien");
        if (!strcmp(x->role, "temoin"))
            temoins &= detecte, nt++;
        if (!strcmp(x->role, "structure"))
            structure &= detecte, ns++;
        if (!strcmp(x->role, "h0"))
            h0 &= fmin(s.pchi, s.pdl) > 1e-3, nh++;
        res_ecrire(&res);
    }
    int complet = E[NEXP - 1].fait >= E[NEXP - 1].cible;
    if (nh)
        res_controle(&res, "h0_32_tours_non_detecte", h0);
    if (nt)
        res_controle(&res, "temoin_biais_2^-15_detecte_a_2^32_paires", temoins);
    if (ns == 2)
        res_controle(&res, "alignement_structure_5_tours_direct_2_inverse_detectee", structure);
    res_mesure(&res, "etat", "\"%s\"", complet ? "terminé" : arret ? "arrêté (reprise possible)" : "budget épuisé (reprise possible)");
    fprintf(stderr, "campagne %s, %s\n", complet ? "terminée" : "interrompue, reprise possible",
            NEXP == NEXP_MAX ? "plan étendu" : "plan de base");
    return res_ecrire(&res);
}
