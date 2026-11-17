/* Distingueurs différentiels-linéaires mesurés sur la vraie permutation BRUME-1024q réduite à r tours (DIFF_LIN.md).
 *
 * Pour un nibble d'entrée v et une différence FIXE δ : paires (x, x ⊕ δ·e_v), x uniforme ; après r tours (perm1), pour
 * chacun des 256 nibbles de sortie, histogramme de la différence (16 cases). Corrélation du masque μ (1 … 15) sur ce
 * nibble : ε = Σ_d h[d]·(−1)^{popcount(μ & d)} / n. Écart réduit z = ε·√n. Seuil : Bonferroni sur toutes les cases de
 * l'exécution (α = 10^−3).
 *
 *   dl_verif r log2_paires nb_entrees [graine] [temoin 0|1] [seule_entree]
 *     nb_entrees nibbles v répartis sur l'état × les 15 valeurs de δ ; temoin = 1 : biais planté (le bit 0 du nibble de
 *     sortie 7 reçoit le bit 0 de la différence d'entrée), qui doit être détecté.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/dl_verif.c sillage/c/commun.c -lm
 * Sortie : une ligne JSON (cases significatives détaillées, au plus 64). */
#include <math.h>
#include <omp.h>

#include "brume1024.c"

static inline uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }

static double z_seuil(double tests)
{
    double cible = 1e-3 / tests, lo = 0, hi = 40;
    for (int i = 0; i < 200; i++) {
        double mid = (lo + hi) / 2;
        if (erfc(mid / sqrt(2)) > cible) lo = mid; else hi = mid;
    }
    return hi;
}

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage : dl_verif r log2_paires nb_entrees [graine] [temoin]\n"); return 2; }
    int r = atoi(argv[1]), lp = atoi(argv[2]), nent = atoi(argv[3]);
    uint64_t graine = argc > 4 ? strtoull(argv[4], 0, 0) : 0xD1D1ULL;
    int temoin = argc > 5 ? atoi(argv[5]) : 0;
    int seule = argc > 6 ? atoi(argv[6]) : -1;   /* une seule des nb_entrees (campagne découpée ; seuil global inchangé) */
    if (r < 1 || r > 16 || lp < 8 || lp > 40 || nent < 1 || nent > N1) return 2;
    if (!ref_init() || !init_noyaux()) { fprintf(stderr, "init\n"); return 2; }
    {
        uint8_t a[128], x[N1];
        uint64_t s = graine ^ 99;
        for (int i = 0; i < 128; i++) a[i] = (uint8_t)xs(&s);
        for (int i = 0; i < 128; i++) { x[2 * i] = a[i] & 15; x[2 * i + 1] = a[i] >> 4; }
        perm1(a, r);
        for (int t = 0; t < r; t++) ref_tour(x, t);
        for (int i = 0; i < 128; i++)
            if (a[i] != (uint8_t)(x[2 * i] | x[2 * i + 1] << 4)) { fprintf(stderr, "perm1 ≠ ref_tour\n"); return 3; }
    }
    long n = 1L << lp;
    double tests = (double)nent * 15 * N1 * 15, zs = z_seuil(tests), zmax = 0;
    long nsig = 0, nun = 0;
    int vmax = -1, dmax = -1, qmax = -1, mmax = -1;
    printf("{\"tours\": %d, \"log2_paires\": %d, \"entrees\": %d, \"temoin\": %d, \"cases\": %.0f, \"z_seuil\": %.3f, "
           "\"significatives\": [", r, lp, nent, temoin, tests, zs);
    int imprimees = 0;
    for (int e = 0; e < nent; e++) {
        if (seule >= 0 && e != seule) continue;
        int v = (int)((long)e * N1 / nent);
        for (int delta = 1; delta < 16; delta++) {
            static long h[N1][16];
            memset(h, 0, sizeof h);
#pragma omp parallel
            {
                static __thread long hl[N1][16];
                memset(hl, 0, sizeof hl);
                uint64_t s = graine ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(e * 16 + delta + 1)) ^
                             (uint64_t)omp_get_thread_num() << 40;
                for (int i = 0; i < 4; i++) xs(&s);
#pragma omp for schedule(static)
                for (long i = 0; i < n; i++) {
                    uint8_t a[128], b[128];
                    for (int k = 0; k < 16; k++) { uint64_t u = xs(&s); memcpy(a + 8 * k, &u, 8); }
                    memcpy(b, a, 128);
                    b[v / 2] ^= (uint8_t)(v & 1 ? delta << 4 : delta);
                    perm1(a, r);
                    perm1(b, r);
                    if (temoin) {   /* biais planté : bit 0 du nibble 7 de b ← bit 0 de a ⊕ bit 0 de δ, une paire sur 2 */
                        if (i & 1) b[3] = (uint8_t)((b[3] & ~0x10) | (((a[3] >> 4) ^ delta) & 1) << 4);
                    }
                    for (int k = 0; k < 128; k++) {
                        uint8_t d = a[k] ^ b[k];
                        hl[2 * k][d & 15]++;
                        hl[2 * k + 1][d >> 4]++;
                    }
                }
#pragma omp critical
                for (int q = 0; q < N1; q++)
                    for (int d = 0; d < 16; d++) h[q][d] += hl[q][d];
            }
            for (int q = 0; q < N1; q++) {
                if (h[q][0] == n) nun++;
                for (int mu = 1; mu < 16; mu++) {
                    long sgn = 0;
                    for (int d = 0; d < 16; d++) sgn += (__builtin_popcount((unsigned)(mu & d)) & 1) ? -h[q][d] : h[q][d];
                    double eps = (double)sgn / n, z = eps * sqrt((double)n);
                    if (fabs(z) > fabs(zmax)) { zmax = z; vmax = v; dmax = delta; qmax = q; mmax = mu; }
                    if (fabs(z) > zs) {
                        nsig++;
                        if (imprimees < 64)
                            printf("%s{\"v\": %d, \"delta\": %d, \"sortie\": %d, \"masque\": %d, \"eps\": %.6e, \"z\": %.2f}",
                                   imprimees++ ? ", " : "", v, delta, q, mu, eps, z);
                    }
                }
            }
            fflush(stdout);
        }
    }
    printf("], \"nb_significatives\": %ld, \"nibbles_toujours_nuls\": %ld, \"z_max\": %.3f, \"eps_max\": %.4e, "
           "\"en\": {\"v\": %d, \"delta\": %d, \"sortie\": %d, \"masque\": %d}, \"bruit_eps\": %.3e}\n",
           nsig, nun, zmax, zmax / sqrt((double)n), vmax, dmax, qmax, mmax, 1 / sqrt((double)n));
    return 0;
}
