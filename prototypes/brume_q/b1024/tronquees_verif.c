/* Recherche EMPIRIQUE de différentielles tronquées sur la vraie permutation BRUME-1024q réduite à r tours (étude
 * « structure », ETUDE_GROUPE_STRUCTURE.md § B1) : complément du modèle de tronquees1024.py, qui ne voit ni la DDT ni les
 * dépendances entre tours.
 *
 * Pour chaque nibble d'entrée v (ou paire de nibbles), des paires (x, x ⊕ δ), δ non nul et uniforme sur le(s) nibble(s)
 * choisi(s), x uniforme ; après r tours (perm1, tours 0 … r−1), on compte pour chacun des 256 nibbles de sortie les paires
 * dont la différence y est NULLE. Pour une permutation aléatoire, P = 1/16 : écart réduit z = (c − n/16)/√(n·15/256).
 * Seuil : Bonferroni sur toutes les cases testées (|z| > z_seuil, α = 10^−3 au total).
 * Témoin : à r = 4 depuis un nibble, 32 sorties sont nulles avec probabilité 1 (boule de rayon 4 : 224 nibbles) ; le
 * détecteur doit les signaler avec des z énormes. Le même code tourne à r = 5, 6, 7.
 *
 *   tronquees_verif r log2_paires [nb_entrees] [paires_de_nibbles 0|1] [graine]
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/tronquees_verif.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm
 * Sortie : une ligne JSON. */
#include <math.h>
#include <omp.h>

#include "brume1024.c"

static inline uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }

static double z_seuil(double tests)   /* |z| tel que P(|Z| > z) = 10^−3 / tests (normale), par bissection */
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
    if (argc < 3) { fprintf(stderr, "usage : tronquees_verif r log2_paires [nb_entrees] [paires 0|1] [graine]\n"); return 2; }
    int r = atoi(argv[1]), lp = atoi(argv[2]);
    int nent = argc > 3 ? atoi(argv[3]) : 16, deux = argc > 4 ? atoi(argv[4]) : 0;
    uint64_t graine = argc > 5 ? strtoull(argv[5], 0, 0) : 0x5EED1024ULL;
    if (r < 1 || r > 16 || lp < 8 || lp > 40 || nent < 1 || nent > N1) return 2;
    if (!bref_init() || !ref_init() || !init_noyaux()) { fprintf(stderr, "init\n"); return 2; }
    /* contrôle : perm1 à r tours = r applications de ref_tour */
    {
        uint8_t w[128], x[N1];
        uint64_t s = graine ^ 77;
        for (int i = 0; i < 128; i++) w[i] = (uint8_t)xs(&s);
        for (int i = 0; i < 128; i++) { x[2 * i] = w[i] & 15; x[2 * i + 1] = w[i] >> 4; }
        perm1(w, r);
        for (int t = 0; t < r; t++) ref_tour(x, t);
        for (int i = 0; i < 128; i++)
            if (w[i] != (uint8_t)(x[2 * i] | x[2 * i + 1] << 4)) { fprintf(stderr, "perm1 ≠ ref_tour\n"); return 3; }
    }
    long n = 1L << lp;
    int entrees[N1][2];
    for (int e = 0; e < nent; e++) {   /* nibbles d'entrée répartis ; en mode paire : v et un voisin à distance 1 */
        entrees[e][0] = (int)((long)e * N1 / nent);
        entrees[e][1] = deux ? nbr(entrees[e][0], B1_K[1]) : -1;
    }
    double zs = z_seuil((double)nent * N1);
    double zmax = 0, zmin = 0;
    int nsig = 0, nprob1 = 0;
    printf("{\"tours\": %d, \"log2_paires\": %d, \"entrees\": %d, \"paire_de_nibbles\": %d, \"z_seuil\": %.3f, \"details\": [",
           r, lp, nent, deux, zs);
    for (int e = 0; e < nent; e++) {
        int v = entrees[e][0], v2 = entrees[e][1];
        long cnt[N1];
        memset(cnt, 0, sizeof cnt);
#pragma omp parallel
        {
            long c[N1];
            memset(c, 0, sizeof c);
            uint64_t s = graine ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(e + 1)) ^ (uint64_t)omp_get_thread_num() << 40;
            for (int i = 0; i < 4; i++) xs(&s);
#pragma omp for schedule(static)
            for (long i = 0; i < n; i++) {
                uint8_t a[128], b[128];
                for (int k = 0; k < 16; k++) { uint64_t u = xs(&s); memcpy(a + 8 * k, &u, 8); }
                memcpy(b, a, 128);
                uint8_t d1 = (uint8_t)(xs(&s) % 15 + 1), d2 = (uint8_t)(xs(&s) % 15 + 1);
                b[v / 2] ^= (uint8_t)(v & 1 ? d1 << 4 : d1);
                if (v2 >= 0) b[v2 / 2] ^= (uint8_t)(v2 & 1 ? d2 << 4 : d2);
                perm1(a, r);
                perm1(b, r);
                for (int k = 0; k < 128; k++) {
                    uint8_t d = a[k] ^ b[k];
                    c[2 * k] += !(d & 15);
                    c[2 * k + 1] += !(d >> 4);
                }
            }
#pragma omp critical
            for (int q = 0; q < N1; q++) cnt[q] += c[q];
        }
        double sd = sqrt((double)n * 15.0 / 256.0), zm = 0;
        int qm = 0, sig = 0, p1 = 0;
        for (int q = 0; q < N1; q++) {
            double z = (cnt[q] - n / 16.0) / sd;
            if (fabs(z) > fabs(zm)) { zm = z; qm = q; }
            if (fabs(z) > zs) sig++;
            if (cnt[q] == n) p1++;
            if (z > zmax) zmax = z;
            if (z < zmin) zmin = z;
        }
        nsig += sig; nprob1 += p1;
        printf("%s\n  {\"v\": %d, \"v2\": %d, \"z_max\": %.3f, \"sortie\": %d, \"p_sortie\": %.6f, \"significatifs\": %d, "
               "\"nuls_toujours\": %d}", e ? "," : "", v, v2, zm, qm, (double)cnt[qm] / n, sig, p1);
        fflush(stdout);
    }
    printf("\n ], \"z_max\": %.3f, \"z_min\": %.3f, \"cases_significatives\": %d, \"sorties_toujours_nulles\": %d, "
           "\"conforme_alea\": %s}\n", zmax, zmin, nsig, nprob1, nsig == 0 ? "true" : "false");
    return 0;
}
