/* Run spécial GPU : les expériences longues que la campagne de nuit (CPU) ne peut pas tenir dans son budget.
 *
 * 1. Cubes (tests/c/nuit_cryptanalyse.c) de 2^34 à 2^42 entrées, directs et inverses, nibbles entiers (voisinage du
 *    sommet 0, ou au hasard), et une série de 32 cubes. Même statistique que la nuit : bits de somme nulle (Bin(512, 1/2)),
 *    z, bit le plus déséquilibré sur une série (Bonferroni 512). Témoins à la portée connue (cube direct 4 tours, inverse
 *    2 et 3 tours : toutes les sommes nulles). Conformité : sommes de cubes de 2^10 identiques à la référence dense
 *    tests/c/brume_ref.h, dans les deux sens.
 * 2. ISD réel, Prange (tests/c/nuit_isd.c), aux tailles hors budget : QC n = 197, 211, 227 ; aléatoire n = 360 … 480.
 *    MÊMES instances que la nuit (mêmes graines, même génération). Un bloc de 256 fils fait une itération : élimination
 *    de Gauss–Jordan sur les colonnes dans un ordre aléatoire, un fil par ligne. L'aléa d'une itération ne dépend que de
 *    son indice : le premier succès est celui de plus petit indice, exactement comme en séquentiel, quel que soit le
 *    découpage en blocs. Chaque solution est vérifiée par l'hôte (H·e = s, 0 < wt(e) ≤ poids). Conformité : tailles
 *    déjà mesurées sur CPU (QC 149, 179 ; aléatoire 200, 280), ratio à la formule dans la même tolérance.
 * Plan par priorité ; une expérience dont la durée estimée (débit mesuré) dépasse le budget restant n'est pas lancée.
 * Reprise : <dossier>/reprise.bin, réécrit au plus toutes les 60 s, à chaque fin d'expérience et à l'arrêt (SIGTERM) ;
 * relancer avec le même dossier reprend (les cubes au lancement près, l'ISD à l'instance près, à l'identique).
 *     tests/gpu/build/frontiere_gpu <dossier> <budget_s>   (depuis la racine) → resultats/gpu_frontiere.{json,md}
 * Lanceur : scripts/rungpu_special. */
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

static volatile sig_atomic_t arret = 0;
static void sur_signal(int s) { (void)s; arret = 1; }

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

/* ================================================================ cubes */
__constant__ int c_nib[11];
__constant__ uint32_t c_base[16];

/* somme (XOR) de P sur les indices [debut, debut + nombre) du cube ; acc : 16 mots, XOR atomique */
__global__ void k_cube(uint64_t debut, uint64_t nombre, int par_fil, int m, int R, int sens, const uint32_t *mi,
                       uint32_t *acc)
{
    extern __shared__ uint32_t MI[];
    if (sens) {
        for (int i = threadIdx.x; i < 512 * 16; i += blockDim.x)
            MI[i] = mi[i];
        __syncthreads();
    }
    uint64_t t = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t loc[16] = {0};
    for (int j = 0; j < par_fil; j++) {
        uint64_t k = t * (uint64_t)par_fil + (uint64_t)j;
        if (k >= nombre)
            break;
        uint64_t idx = debut + k;
        uint32_t w[16];
#pragma unroll
        for (int q = 0; q < 16; q++)
            w[q] = c_base[q];
        for (int q = 0; q < m; q++) {
            int nb = c_nib[q];
            w[nb >> 3] ^= (uint32_t)((idx >> (4 * q)) & 15) << (4 * (nb & 7));
        }
        if (sens)
            brume_arriere(w, BR_TOURS - 1, R, MI);
        else
            brume_avant(w, 0, R);
#pragma unroll
        for (int q = 0; q < 16; q++)
            loc[q] ^= w[q];
    }
#pragma unroll
    for (int q = 0; q < 16; q++) {
        for (int o = 16; o; o >>= 1)
            loc[q] ^= __shfl_xor_sync(0xffffffffu, loc[q], o);
        if ((threadIdx.x & 31) == 0 && loc[q])
            atomicXor(&acc[q], loc[q]);
    }
}

static uint32_t *g_mi, *g_acc;
static int g_blocs, g_fils = 256;

/* état d'avancement d'un cube (pour la reprise) */
typedef struct { uint64_t pos; uint32_t acc[16]; } cube_av_t;

static void base_de(uint64_t graine, uint32_t base[16])
{
    alea_t g;
    alea_init(&g, graine);
    for (int k = 0; k < 8; k++) {
        uint64_t z = alea64(&g);
        base[2 * k] = (uint32_t)z;
        base[2 * k + 1] = (uint32_t)(z >> 32);
    }
}

/* fait avancer la somme du cube jusqu'au bout, ou jusqu'à l'arrêt ; *rate : évaluations·tours par seconde */
static int cube_gpu(const int *nib, int log2n, int R, int sens, uint64_t graine, cube_av_t *av, double *taux,
                    void (*sauver)(void))
{
    uint32_t base[16];
    base_de(graine, base);
    int m = (log2n + 3) / 4;
    CK(cudaMemcpyToSymbol(c_nib, nib, sizeof(int) * 11));
    CK(cudaMemcpyToSymbol(c_base, base, sizeof base));
    uint64_t total = 1ULL << log2n, lot = 1ULL << 20;
    size_t shm = sens ? 512 * 16 * sizeof(uint32_t) : 0;
    double t_svg = maintenant(), t_tot = 0;
    uint64_t n_tot = 0;
    while (av->pos < total && !arret) {
        uint64_t n = total - av->pos < lot ? total - av->pos : lot;
        uint64_t T = (uint64_t)g_blocs * g_fils;
        int par = (int)((n + T - 1) / T);
        CK(cudaMemcpy(g_acc, av->acc, 64, cudaMemcpyHostToDevice));
        double t0 = maintenant();
        k_cube<<<g_blocs, g_fils, shm>>>(av->pos, n, par, m, R, sens, g_mi, g_acc);
        CK(cudaGetLastError());
        CK(cudaDeviceSynchronize());
        double dt = maintenant() - t0;
        CK(cudaMemcpy(av->acc, g_acc, 64, cudaMemcpyDeviceToHost));
        av->pos += n;
        t_tot += dt;
        n_tot += n;
        if (taux && t_tot > 0.1)                       /* débit sur tout ce qui a été mesuré dans cet appel */
            *taux = (double)n_tot * R / t_tot;
        if (dt < 0.15 && lot < (1ULL << 34))       /* lancements d'environ 0,25 s (chien de garde de l'affichage) */
            lot *= 2;
        else if (dt > 0.5 && lot > (1ULL << 16))
            lot /= 2;
        if (sauver && maintenant() - t_svg > 60) {
            sauver();
            t_svg = maintenant();
        }
    }
    return av->pos >= total;
}

/* référence : somme du même cube par tests/c/brume_ref.h (matrices denses) */
static void cube_ref(const int *nib, int log2n, int R, int sens, uint64_t graine, uint32_t out[16])
{
    uint32_t base[16];
    base_de(graine, base);
    int m = (log2n + 3) / 4;
    memset(out, 0, 64);
    for (uint64_t idx = 0; idx < (1ULL << log2n); idx++) {
        uint32_t w[16];
        memcpy(w, base, 64);
        for (int q = 0; q < m; q++)
            w[nib[q] >> 3] ^= (uint32_t)((idx >> (4 * q)) & 15) << (4 * (nib[q] & 7));
        uint8_t x[BR_N];
        for (int j = 0; j < BR_N; j++)
            x[j] = (uint8_t)((w[j >> 3] >> (4 * (j & 7))) & 15);
        bref_perm(x, R, sens);
        for (int j = 0; j < BR_N; j++)
            out[j >> 3] ^= (uint32_t)x[j] << (4 * (j & 7));
    }
}

static int bits_nuls(const uint32_t a[16])
{
    int un = 0;
    for (int k = 0; k < 16; k++)
        un += __builtin_popcount(a[k]);
    return 512 - un;
}

/* ================================================================ ISD (Prange) */
#define ISD_FILS 256
#define ISD_WMAX 12

__device__ __forceinline__ uint64_t sm64d(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* Itérations base + blockIdx·J + j, j < J. Lignes : rows × W mots de 64 bits, la colonne m (bit m) est le syndrome.
 * Succès : 0 < poids du syndrome réduit sur les lignes pivots ≤ poids. *min_it : plus petit indice de succès ;
 * sol_it / sol : indice et solution du premier succès de chaque bloc. */
__global__ void __launch_bounds__(ISD_FILS) k_prange(const uint64_t *H0, int rows, int m, int W, int poids,
                                                     uint64_t graine, uint64_t base, int J,
                                                     unsigned long long *min_it, unsigned long long *sol_it,
                                                     unsigned long long *sol)
{
    extern __shared__ uint64_t S[];
    __shared__ uint16_t perm[3 * 256];
    __shared__ int s_col, s_cand;
    const int tid = threadIdx.x, lane = tid & 31, warp = tid >> 5;
    for (int j = tid; j < m; j += blockDim.x)
        perm[j] = (uint16_t)j;
    for (int jj = 0; jj < J; jj++) {
        const uint64_t it = base + (uint64_t)blockIdx.x * J + (uint64_t)jj;
        for (int t = tid; t < rows * W; t += blockDim.x)
            S[t] = H0[t];
        uint64_t st = graine ^ (it * 0xd1342543de82ef95ULL);
        bool pivot = false;
        int pivc = -1, piv = 0;
        __syncthreads();
        for (int c = 0; c < m && piv < rows; c++) {
            if (tid == 0) {                             /* Fisher–Yates paresseux : colonne c de l'ordre aléatoire */
                int r = c + (int)(sm64d(&st) % (uint64_t)(m - c));
                uint16_t x = perm[c];
                perm[c] = perm[r];
                perm[r] = x;
                s_col = perm[c];
                s_cand = rows;
            }
            __syncthreads();
            const int col = s_col;
            int b = 0;
            if (tid < rows && !pivot)
                b = (int)((S[tid * W + (col >> 6)] >> (col & 63)) & 1);
            unsigned bal = __ballot_sync(0xffffffffu, b);
            if (lane == 0 && bal)
                atomicMin(&s_cand, warp * 32 + __ffs(bal) - 1);
            __syncthreads();
            const int cand = s_cand;
            if (cand < rows) {
                if (tid < rows && tid != cand && ((S[tid * W + (col >> 6)] >> (col & 63)) & 1))
                    for (int k = 0; k < W; k++)
                        S[tid * W + k] ^= S[cand * W + k];
                if (tid == cand) {
                    pivot = true;
                    pivc = col;
                }
                piv++;
            }
            __syncthreads();
        }
        int sb = tid < rows ? (int)((S[tid * W + (m >> 6)] >> (m & 63)) & 1) : 0;
        int wt = __syncthreads_count(pivot && sb);
        if (wt > 0 && wt <= poids) {
            if (tid == 0) {
                atomicMin(min_it, (unsigned long long)it);
                sol_it[blockIdx.x] = it;
            }
            if (pivot && sb)
                atomicOr(&sol[(size_t)blockIdx.x * W + (pivc >> 6)], 1ULL << (pivc & 63));
            break;
        }
        __syncthreads();
    }
}

static double log2_binom(int a, int b) { return (lgamma(a + 1.0) - lgamma(b + 1.0) - lgamma(a - b + 1.0)) / log(2.0); }

static void creux(alea_t *g, int n, int w, uint8_t *v)
{
    memset(v, 0, (size_t)n);
    for (int k = 0; k < w;) {
        int p = (int)alea_borne(g, (uint64_t)n);
        if (!v[p]) { v[p] = 1; k++; }
    }
}

/* instance k d'une taille : même génération que tests/c/isd_reel.c (mesure_qc, mesure_aleatoire) */
static void instance(int qc, int n, int r, int w, uint64_t graine, int *rows, int *m, int *W, int *poids, uint64_t *H)
{
    alea_t g;
    alea_init(&g, graine);
    uint8_t h[256], x[256], y[256], e[512];
    if (qc) {
        *rows = n; *m = 2 * n; *poids = 2 * w;
        *W = (*m + 1 + 63) / 64;
        memset(H, 0, sizeof(uint64_t) * (size_t)*rows * (size_t)*W);
        for (int i = 0; i < n; i++)
            h[i] = (uint8_t)(alea64(&g) & 1);
        creux(&g, n, w, x);
        creux(&g, n, w, y);
        for (int i = 0; i < n; i++) {
            uint64_t *L = H + (size_t)i * *W;
            uint8_t s = y[i];
            for (int j = 0; j < n; j++)
                if (h[((i - j) % n + n) % n]) {
                    L[j >> 6] |= 1ULL << (j & 63);
                    s ^= x[j];
                }
            L[(n + i) >> 6] |= 1ULL << ((n + i) & 63);
            if (s)
                L[*m >> 6] |= 1ULL << (*m & 63);
        }
    } else {
        *rows = r; *m = n; *poids = w;
        *W = (*m + 1 + 63) / 64;
        memset(H, 0, sizeof(uint64_t) * (size_t)*rows * (size_t)*W);
        for (int i = 0; i < r; i++)
            for (int j = 0; j < n; j++)
                if (alea64(&g) & 1)
                    H[(size_t)i * *W + (j >> 6)] |= 1ULL << (j & 63);
        creux(&g, n, w, e);
        for (int i = 0; i < r; i++) {
            uint8_t a = 0;
            for (int j = 0; j < n; j++)
                a ^= e[j] & (uint8_t)((H[(size_t)i * *W + (j >> 6)] >> (j & 63)) & 1);
            if (a)
                H[(size_t)i * *W + (*m >> 6)] |= 1ULL << (*m & 63);
        }
    }
}

static int solution_valide(const uint64_t *H, int rows, int m, int W, int poids, const unsigned long long *e)
{
    int wt = 0;
    for (int k = 0; k < W; k++) {
        uint64_t v = e[k];
        if (k == (m >> 6))
            v &= (1ULL << (m & 63)) - 1;
        if (v != e[k])
            return 0;                                   /* rien au-delà des m colonnes */
        wt += __builtin_popcountll(v);
    }
    if (wt == 0 || wt > poids)
        return 0;
    for (int i = 0; i < rows; i++) {
        const uint64_t *L = H + (size_t)i * W;
        int p = 0;
        for (int k = 0; k < W; k++)
            p ^= __builtin_popcountll(L[k] & e[k]) & 1;
        if (p != (int)((L[m >> 6] >> (m & 63)) & 1))
            return 0;
    }
    return 1;
}

static uint64_t *d_H;
static unsigned long long *d_min, *d_solit, *d_sol;
static int g_isd_blocs;

/* itérations jusqu'au premier succès (indice minimal + 1) ; -1 si arrêt ; *valide : solution vérifiée */
static long prange_gpu(const uint64_t *H, int rows, int m, int W, int poids, uint64_t graine, int *valide, double *t_iter)
{
    size_t shm = sizeof(uint64_t) * (size_t)rows * (size_t)W;
    CK(cudaMemcpy(d_H, H, shm, cudaMemcpyHostToDevice));
    static unsigned long long solit[4096], sol[4096 * ISD_WMAX];
    uint64_t base = 0;
    int J = 1;
    for (;;) {
        if (arret)
            return -1;
        unsigned long long inf = ~0ULL;
        CK(cudaMemcpy(d_min, &inf, sizeof inf, cudaMemcpyHostToDevice));
        CK(cudaMemset(d_solit, 0xff, sizeof(unsigned long long) * (size_t)g_isd_blocs));
        CK(cudaMemset(d_sol, 0, sizeof(unsigned long long) * (size_t)g_isd_blocs * W));
        double t0 = maintenant();
        k_prange<<<g_isd_blocs, ISD_FILS, shm>>>(d_H, rows, m, W, poids, graine, base, J, d_min, d_solit, d_sol);
        CK(cudaGetLastError());
        CK(cudaDeviceSynchronize());
        double dt = maintenant() - t0;
        unsigned long long mn;
        CK(cudaMemcpy(&mn, d_min, sizeof mn, cudaMemcpyDeviceToHost));
        if (mn != ~0ULL) {
            CK(cudaMemcpy(solit, d_solit, sizeof(unsigned long long) * (size_t)g_isd_blocs, cudaMemcpyDeviceToHost));
            CK(cudaMemcpy(sol, d_sol, sizeof(unsigned long long) * (size_t)g_isd_blocs * W, cudaMemcpyDeviceToHost));
            int b = 0;
            while (b < g_isd_blocs && solit[b] != mn)
                b++;
            *valide = b < g_isd_blocs && solution_valide(H, rows, m, W, poids, sol + (size_t)b * W);
            return (long)(mn + 1);
        }
        if (t_iter && dt > 0.02)
            *t_iter = dt / ((double)g_isd_blocs * J);
        base += (uint64_t)g_isd_blocs * J;
        if (dt < 0.1 && J < 4096)
            J *= 2;
        else if (dt > 0.4 && J > 1)
            J /= 2;
    }
}

/* ================================================================ plan */
/* type : c cube, k série de K cubes, q ISD quasi-cyclique, a ISD aléatoire, V conformité des cubes */
typedef struct { char type; int sens, R, vois, log2n, temoin, K; int n, r, w, inst; uint64_t graine; } exp_t;
#define CUBE(t, s, R, v, l, tem, K) {t, s, R, v, l, tem, K, 0, 0, 0, 0, 0}
#define ISD(t, n, r, w, inst, g) {t, 0, 0, 0, 0, 0, 0, n, r, w, inst, g}
static const exp_t PLAN[] = {
    /* témoins des cubes, à la portée connue */
    CUBE('c', 0, 4, 1, 24, 1, 1), CUBE('c', 1, 2, 1, 16, 1, 1), CUBE('c', 1, 3, 1, 28, 1, 1),
    /* ISD : conformité aux tailles déjà mesurées sur CPU (graines de nuit_isd : 20000 + 1000·k, 40000 + 1000·k) */
    ISD('q', 149, 0, 6, 150, 20000), ISD('q', 179, 0, 8, 120, 22000), ISD('a', 200, 100, 11, 150, 47000),
    ISD('a', 280, 140, 15, 300, 49000),
    /* cubes non lancés par la nuit du 2026-11-05 */
    CUBE('c', 1, 4, 1, 34, 0, 1), CUBE('c', 1, 5, 1, 34, 0, 1), CUBE('c', 1, 4, 1, 36, 0, 1),
    CUBE('k', 1, 4, 1, 28, 0, 32),
    /* ISD hors budget de la nuit */
    ISD('q', 197, 0, 9, 60, 23000), ISD('q', 211, 0, 10, 40, 24000), ISD('a', 360, 180, 19, 40, 51000),
    ISD('q', 227, 0, 11, 25, 25000), ISD('a', 400, 200, 21, 25, 52000), ISD('a', 440, 220, 23, 15, 53000),
    ISD('a', 480, 240, 25, 10, 54000),
    /* cubes facultatifs de la nuit, les plus gros */
    CUBE('c', 0, 5, 1, 38, 0, 1), CUBE('c', 0, 5, 0, 38, 0, 1), CUBE('c', 0, 6, 1, 38, 0, 1), CUBE('c', 1, 4, 1, 38, 0, 1),
    CUBE('c', 0, 5, 1, 40, 0, 1), CUBE('c', 0, 6, 1, 40, 0, 1), CUBE('c', 0, 5, 1, 42, 0, 1),
};
#define NEXP ((int)(sizeof PLAN / sizeof PLAN[0]))
#define NCONF_ISD 4                                    /* les 4 premières tailles ISD : conformité */

typedef struct {
    int fini;                                          /* 0 : à faire ou en cours ; 1 : fini */
    double duree;
    /* cubes */
    int c, tot, cpt[512];
    cube_av_t av;
    /* ISD */
    int inst_faites, valides;
    double somme;
    char ligne[700];
} etat_t;

static etat_t ETAT[NEXP];
/* débits mesurés, conservés avec l'état : après une reprise, les tailles de conformité ne sont pas refaites */
static struct { double t_iter; int rows_ref, W_ref; } DEBIT = {0, 0, 1};
static char DOSSIER[512];
#define MAGIC 0x46524f4e54303032ULL                    /* "FRONT002" */

static void sauver(void)
{
    char f[600], g[600];
    snprintf(f, sizeof f, "%s/reprise.bin", DOSSIER);
    snprintf(g, sizeof g, "%s/reprise.tmp", DOSSIER);
    FILE *p = fopen(g, "wb");
    if (!p)
        return;
    uint64_t mg = MAGIC;
    int n = NEXP;
    fwrite(&mg, 8, 1, p);
    fwrite(&n, sizeof n, 1, p);
    fwrite(ETAT, sizeof ETAT, 1, p);
    fwrite(&DEBIT, sizeof DEBIT, 1, p);
    if (fclose(p) == 0)
        rename(g, f);
}

static void charger(void)
{
    char f[600];
    snprintf(f, sizeof f, "%s/reprise.bin", DOSSIER);
    FILE *p = fopen(f, "rb");
    if (!p)
        return;
    uint64_t mg = 0;
    int n = 0;
    if (fread(&mg, 8, 1, p) == 1 && fread(&n, sizeof n, 1, p) == 1 && mg == MAGIC && n == NEXP &&
        fread(ETAT, sizeof ETAT, 1, p) == 1 && fread(&DEBIT, sizeof DEBIT, 1, p) == 1)
        fprintf(stderr, "reprise de %s\n", f);
    else {
        memset(ETAT, 0, sizeof ETAT);
        DEBIT.t_iter = 0; DEBIT.rows_ref = 0; DEBIT.W_ref = 1;
    }
    fclose(p);
}

static const char *SENS[2] = {"direct", "inverse"};

static int portee_cube(int sens) { return sens ? 3 : 4; }

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage : %s <dossier> <budget_s>\n", argv[0]);
        return 2;
    }
    snprintf(DOSSIER, sizeof DOSSIER, "%s", argv[1]);
    double budget = atof(argv[2]), t0 = maintenant();
    signal(SIGTERM, sur_signal);
    signal(SIGINT, sur_signal);
    resultat_t res = {.nom = "gpu_frontiere", .titre = "Run spécial GPU : cubes et ISD hors budget de la nuit"};
    if (!bref_init())
        return 2;
    cudaDeviceProp prop;
    CK(cudaGetDeviceProperties(&prop, 0));
    res_mesure(&res, "gpu", "\"%s, sm_%d%d, %d SM\"", prop.name, prop.major, prop.minor, prop.multiProcessorCount);
    g_blocs = 8 * prop.multiProcessorCount;
    br_gpu_init(BR_RC);
    static uint32_t mi[512 * 16];
    br_gpu_mi(BMI, mi, gf_mul);
    CK(cudaMalloc(&g_mi, sizeof mi));
    CK(cudaMemcpy(g_mi, mi, sizeof mi, cudaMemcpyHostToDevice));
    CK(cudaMalloc(&g_acc, 64));
    CK(cudaFuncSetAttribute(k_cube, cudaFuncAttributeMaxDynamicSharedMemorySize, 512 * 16 * 4));
    int occ = 0;
    size_t shm_max = sizeof(uint64_t) * 256 * ISD_WMAX;
    CK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(&occ, k_prange, ISD_FILS, shm_max));
    g_isd_blocs = (occ > 0 ? occ : 1) * prop.multiProcessorCount;
    if (g_isd_blocs > 4096)
        g_isd_blocs = 4096;
    CK(cudaMalloc(&d_H, shm_max));
    CK(cudaMalloc(&d_min, sizeof(unsigned long long)));
    CK(cudaMalloc(&d_solit, sizeof(unsigned long long) * 4096));
    CK(cudaMalloc(&d_sol, sizeof(unsigned long long) * 4096 * ISD_WMAX));
    res_mesure(&res, "blocs", "{\"cubes\": %d, \"isd\": %d}", g_blocs, g_isd_blocs);
    charger();

    /* voisinage du sommet 0 (+ voisins de voisins), comme tests/c/nuit_cryptanalyse.c */
    int nib_v[11], nb_v = 0;
    for (int j = 0; j < BR_N && nb_v < 7; j++)
        if (BM[0][j]) nib_v[nb_v++] = j;
    for (int j = 0; j < BR_N && nb_v < 11; j++)
        if (BM[nib_v[1]][j]) {
            int deja = 0;
            for (int k = 0; k < nb_v; k++) deja |= nib_v[k] == j;
            if (!deja) nib_v[nb_v++] = j;
        }

    /* conformité des cubes : GPU = référence dense, cubes de 2^10, quatre (sens, tours) */
    int conf = 1;
    static const int CC[][2] = {{0, 3}, {0, 5}, {1, 2}, {1, 4}};
    for (int k = 0; k < 4; k++) {
        int nib[11];
        alea_t g;
        alea_init(&g, 31 + (uint64_t)k);
        for (int q = 0; q < 11; q++) nib[q] = (int)alea_borne(&g, BR_N);
        nib[1] = (nib[0] + 1) % BR_N;
        nib[2] = (nib[0] + 2) % BR_N;
        cube_av_t av = {0, {0}};
        uint32_t ref[16];
        cube_gpu(nib, 10, CC[k][1], CC[k][0], 4242 + (uint64_t)k, &av, NULL, NULL);
        cube_ref(nib, 10, CC[k][1], CC[k][0], 4242 + (uint64_t)k, ref);
        conf &= !memcmp(av.acc, ref, 64);
    }
    res_controle(&res, "cubes_gpu_conformes_a_la_reference_dense", conf);
    if (!conf)
        return res_ecrire(&res);

    double taux[2] = {0, 0};                           /* évaluations·tours par seconde, par sens */
    {                                                  /* étalonnage : sans débit connu, aucun gros cube ne part */
        cube_av_t av = {0, {0}};
        cube_gpu(nib_v, 28, 5, 0, 1, &av, &taux[0], NULL);
        memset(&av, 0, sizeof av);
        cube_gpu(nib_v, 25, 4, 1, 1, &av, &taux[1], NULL);
        res_mesure(&res, "debit_tours_par_s", "{\"direct\": %.3g, \"inverse\": %.3g}", taux[0], taux[1]);
        fprintf(stderr, "étalonnage : %.3g tours·évaluations/s en direct, %.3g en inverse\n", taux[0], taux[1]);
    }
    double &t_iter = DEBIT.t_iter;                     /* secondes par itération ISD (dernière taille mesurée) */
    int &rows_ref = DEBIT.rows_ref, &W_ref = DEBIT.W_ref;
    static uint64_t H[256 * ISD_WMAX];
    int temoins_ok = 1, nouveaux = 0, max_t[2] = {0, 0}, couvert[2] = {0, 0};
    int conf_isd = 1, isd_ok = 1, sol_ok = 1, non_lances = 0, isd_cibles = 0, conf_faites = 0;
    double sz[2] = {0, 0};
    int nz[2] = {0, 0};
    static char cubes[20000] = "[", isd[12000] = "[", ligne[800];
    int nc = 0, ni = 0;
    for (int x = 0; x < NEXP && !arret; x++) {
        const exp_t *e = &PLAN[x];
        etat_t *s = &ETAT[x];
        int est_cube = e->type == 'c' || e->type == 'k';
        if (!s->fini) {
            double reste = budget - (maintenant() - t0), est = 0;
            if (est_cube)
                est = taux[e->sens] > 0 ? pow(2.0, e->log2n) * e->K * e->R / taux[e->sens] : 1e30;
            if (!est_cube && t_iter <= 0)
                est = 1e30;                            /* débit inconnu : rien ne part à l'aveugle */
            if (!est_cube && t_iter > 0) {
                int qc = e->type == 'q', rows = qc ? e->n : e->r, W = ((qc ? 2 * e->n : e->n) + 64) / 64;
                double pred = qc ? log2_binom(2 * e->n, 2 * e->w) - log2_binom(e->n, 2 * e->w)
                                 : log2_binom(e->n, e->w) - log2_binom(e->r, e->w);
                est = (e->inst - s->inst_faites) * pow(2.0, pred) * t_iter * ((double)rows / rows_ref) * ((double)W / W_ref);
            }
            if (est > reste && !e->temoin && x >= 3 + NCONF_ISD) {
                const char *quoi = est_cube ? "cube" : "isd";
                if (est_cube)
                    snprintf(ligne, sizeof ligne, "%s{\"type\": \"%c\", \"sens\": \"%s\", \"tours\": %d, \"log2\": %d, "
                             "\"nibbles\": \"%s\", \"statut\": \"non lancé (budget : %.0f s estimés, %.0f s restants)\"}",
                             nc ? ", " : "", e->type, SENS[e->sens], e->R, e->log2n, e->vois ? "voisinage" : "hasard", est, reste);
                else
                    snprintf(ligne, sizeof ligne, "%s{\"type\": \"%s\", \"n\": %d, \"w\": %d, \"statut\": \"non lancé "
                             "(budget : %.0f s estimés, %.0f s restants)\"}", ni ? ", " : "", e->type == 'q' ? "qc" : "aleatoire",
                             e->n, e->w, est, reste);
                strcat(est_cube ? cubes : isd, ligne);
                est_cube ? nc++ : ni++;
                non_lances++;
                fprintf(stderr, "%s n° %d non lancé : %.0f s estimés, %.0f s restants\n", quoi, x, est, reste);
                continue;
            }
            double ts = maintenant();
            if (est_cube) {
                int nib[11], K = e->type == 'k' ? e->K : 1;
                alea_t g;
                alea_init(&g, 9077 + (uint64_t)x);
                for (int k = 0; k < 11; k++) {
                    if (e->vois) nib[k] = nib_v[k];
                    else {
                        int ok, v;
                        do {
                            v = (int)alea_borne(&g, BR_N);
                            ok = 1;
                            for (int l = 0; l < k; l++) ok &= nib[l] != v;
                        } while (!ok);
                        nib[k] = v;
                    }
                }
                for (; s->c < K && !arret; ) {
                    if (!cube_gpu(nib, e->log2n, e->R, e->sens, 7000 + (uint64_t)x * 1000 + (uint64_t)s->c, &s->av,
                                  &taux[e->sens], sauver))
                        break;
                    s->tot += bits_nuls(s->av.acc);
                    for (int b = 0; b < 512; b++)
                        s->cpt[b] += !((s->av.acc[b >> 5] >> (b & 31)) & 1);
                    s->c++;
                    memset(&s->av, 0, sizeof s->av);
                }
                if (s->c < K) {                        /* arrêt demandé */
                    s->duree += maintenant() - ts;
                    break;
                }
                int ext = 0;
                for (int b = 0; b < 512; b++) {
                    int dv = 2 * s->cpt[b] - K;
                    if (dv < 0) dv = -dv;
                    if (dv > ext) ext = dv;
                }
                double z = (s->tot - 256.0 * K) / sqrt(128.0 * K), pb = 1;
                if (K >= 32) {
                    double sm = 0;
                    for (int i = (K + ext) / 2; i <= K; i++)
                        sm += exp(lgamma(K + 1.0) - lgamma(i + 1.0) - lgamma(K - i + 1.0) - K * log(2.0));
                    pb = 2 * 512 * sm;
                    if (pb > 1) pb = 1;
                }
                int dist = s->tot == 512 * K || fabs(z) > 6 || pb < 1e-6;
                s->duree += maintenant() - ts;
                snprintf(s->ligne, sizeof s->ligne, "{\"type\": \"%c\", \"sens\": \"%s\", \"tours\": %d, \"log2\": %d, "
                         "\"nibbles\": \"%s\", \"cubes\": %d, \"bits_somme_nulle\": %d, \"z\": %.2f, \"ecart_bit_max\": %d, "
                         "\"p_bit\": %.2g, \"distingue\": %s, \"temoin\": %s, \"duree_s\": %.0f}", e->type, SENS[e->sens], e->R,
                         e->log2n, e->vois ? "voisinage" : "hasard", K, s->tot, z, ext, pb, dist ? "true" : "false",
                         e->temoin ? "true" : "false", s->duree);
                fprintf(stderr, "cube %s R=%d 2^%d ×%d %s : %d bits nuls (z = %.2f, écart bit %d)%s en %.0f s\n", SENS[e->sens],
                        e->R, e->log2n, K, e->vois ? "voisinage" : "hasard", s->tot, z, ext, dist ? " DISTINGUÉ" : "", s->duree);
            } else {
                int qc = e->type == 'q', rows, m, W, poids;
                for (; s->inst_faites < e->inst && !arret; ) {
                    instance(qc, e->n, e->r, e->w, e->graine + (uint64_t)s->inst_faites, &rows, &m, &W, &poids, H);
                    int v = 0;
                    long it = prange_gpu(H, rows, m, W, poids, 0x15D0C0DEULL ^ (e->graine * 1000003ULL + (uint64_t)s->inst_faites),
                                         &v, &t_iter);
                    if (it < 0)
                        break;
                    s->somme += (double)it;
                    s->valides += v;
                    s->inst_faites++;
                    rows_ref = rows;
                    W_ref = W;
                    if (maintenant() - ts > 60) { sauver(); }
                }
                if (s->inst_faites < e->inst) {
                    s->duree += maintenant() - ts;
                    break;
                }
                double pred = qc ? log2_binom(2 * e->n, 2 * e->w) - log2_binom(e->n, 2 * e->w)
                                 : log2_binom(e->n, e->w) - log2_binom(e->r, e->w);
                double moy = s->somme / e->inst, ratio = moy / pow(2.0, pred), tol = 3.0 / sqrt((double)e->inst) + 0.05;
                s->duree += maintenant() - ts;
                snprintf(s->ligne, sizeof s->ligne, "{\"type\": \"%s\", \"n\": %d, \"r\": %d, \"w\": %d, \"instances\": %d, "
                         "\"iterations_log2\": %.2f, \"prevision_log2\": %.2f, \"ratio\": %.3f, \"tolerance\": %.3f, "
                         "\"solutions_verifiees\": %d, \"conformite_cpu\": %s, \"duree_s\": %.0f}", qc ? "qc" : "aleatoire", e->n,
                         qc ? e->n : e->r, e->w, e->inst, log2(moy), pred, ratio, tol, s->valides,
                         x < 3 + NCONF_ISD ? "true" : "false", s->duree);
                fprintf(stderr, "ISD %s n=%d w=%d : mesuré 2^%.2f, prévu 2^%.2f (ratio %.3f), %d/%d solutions vérifiées, %.0f s\n",
                        qc ? "QC" : "aléatoire", e->n, e->w, log2(moy), pred, ratio, s->valides, e->inst, s->duree);
            }
            s->fini = 1;
            sauver();
        }
        /* bilan de l'expérience finie (maintenant ou lors d'un run précédent) */
        if (est_cube) {
            int dist = strstr(s->ligne, "\"distingue\": true") != NULL;
            if (e->temoin) temoins_ok &= dist;
            else {
                if (e->R > portee_cube(e->sens)) couvert[e->sens] = 1;
                if (dist) { nouveaux++; if (e->R > max_t[e->sens]) max_t[e->sens] = e->R; }
            }
            snprintf(ligne, sizeof ligne, "%s%s", nc ? ", " : "", s->ligne);
            strcat(cubes, ligne);
            nc++;
        } else {
            double pred = e->type == 'q' ? log2_binom(2 * e->n, 2 * e->w) - log2_binom(e->n, 2 * e->w)
                                         : log2_binom(e->n, e->w) - log2_binom(e->r, e->w);
            double ratio = s->somme / e->inst / pow(2.0, pred), tol = 3.0 / sqrt((double)e->inst) + 0.05;
            int bon = fabs(ratio - 1) <= tol;
            if (x < 3 + NCONF_ISD) { conf_isd &= bon; conf_faites++; }
            else { isd_ok &= bon; isd_cibles++; }
            sol_ok &= s->valides == e->inst;
            sz[e->type == 'a'] += (ratio - 1) * sqrt((double)e->inst);
            nz[e->type == 'a']++;
            snprintf(ligne, sizeof ligne, "%s%s", ni ? ", " : "", s->ligne);
            strcat(isd, ligne);
            ni++;
        }
        /* point de sauvegarde lisible */
        resultat_t cp = res;
        char tmp[20100];
        snprintf(tmp, sizeof tmp, "%s]", cubes);
        res_mesure(&cp, "cubes", "%s", tmp);
        snprintf(tmp, sizeof tmp, "%s]", isd);
        res_mesure(&cp, "isd", "%s", tmp);
        res_mesure(&cp, "en_cours", "\"%d/%d\"", x + 1, NEXP);
        res_ecrire(&cp);
    }
    sauver();
    strcat(cubes, "]");
    strcat(isd, "]");
    res_mesure(&res, "cubes", "%s", cubes);
    res_mesure(&res, "isd", "%s", isd);
    double zq = nz[0] ? sz[0] / sqrt(nz[0]) : 0, za = nz[1] ? sz[1] / sqrt(nz[1]) : 0;
    res_mesure(&res, "isd_ecart_cumule_z", "{\"qc\": %.2f, \"aleatoire\": %.2f}", zq, za);
    res_mesure(&res, "distingueurs_au_dela_de_la_portee", "{\"cube_direct\": %d, \"cube_inverse\": %d}", max_t[0], max_t[1]);
    res_mesure(&res, "experiences_non_lancees", "%d", non_lances);
    res_mesure(&res, "interrompu", "%s", arret ? "true" : "false");
    res_mesure(&res, "duree_s", "%.0f", maintenant() - t0);
    res_controle(&res, "temoins_cubes_detectes", temoins_ok);
    res_mesure(&res, "isd_tailles_cibles_mesurees", "%d", isd_cibles);
    res_controle(&res, "isd_gpu_conforme_aux_tailles_mesurees_sur_cpu", conf_isd && conf_faites == NCONF_ISD);
    res_controle(&res, "isd_solutions_toutes_verifiees", sol_ok);
    res_controle(&res, "isd_cout_prange_conforme_a_la_formule", isd_ok && isd_cibles > 0);
    res_controle(&res, "isd_pas_de_derive_systematique", fabs(zq) < 4 && fabs(za) < 4);
    res_controle(&res, "aucun_distingueur_cube_au_dela_de_la_portee_connue", nouveaux == 0);
    res_controle(&res, "cubes_testes_au_dela_de_la_portee_dans_les_deux_sens", couvert[0] && couvert[1]);
    if (arret)
        fprintf(stderr, "arrêt demandé : reprise par le même dossier\n");
    return res_ecrire(&res);
}
