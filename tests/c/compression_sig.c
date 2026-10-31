/* Plus petite signature à coût de falsification garanti : grille (D, τ, t, ep), ep multiple de e (K ⊃ F_poly).
 * Théorème 8, deux termes dominants au meilleur τ1 : (q+1)·(P[Bin(τ,p) ≥ τ1] + N^-(τ−τ1+1)), p = ((n+w)/2^ep)^t.
 * Le coût est l'inverse de cette somme. Contrôles : retrouve les coûts et les tailles du dossier.
 *     build/compression_sig   (depuis la racine) → resultats/compression_sig.json
 */
#include <math.h>

#include "resultat.h"

static long double l2add(long double a, long double b)
{
    return a > b ? a + log2l(1 + powl(2, b - a)) : b + log2l(1 + powl(2, a - b));
}

static long double lc(int n, int k) { return (lgammal(n + 1) - lgammal(k + 1) - lgammal(n - k + 1)) / logl(2); }

static double cout(int tau, int D, int n, int w, int ep, int t)
{
    long double lp = t * (log2l(n + w) - ep), best = 0;
    for (int t1 = 1; t1 <= tau + 1; t1++) {
        long double s = -1e9L;
        for (int i = t1; i <= tau; i++)
            s = l2add(s, lc(tau, i) + i * lp + (tau - i) * log2l(1 - powl(2, lp)));
        long double a = -l2add(s, -(long double)D * (tau - t1 + 1));
        if (t1 == 1 || a > best)
            best = a;
    }
    return (double)best;
}

static long taille(int hd, int tau, int D, int sb, int hb, int sk, int ep, int t)
{
    int pts = (t * ep + 7) / 8;
    return hd + (long)tau * (D * sb + hb + sk + pts + 2 * pts);
}

typedef struct { const char *nom; int lam, n, w, e, sb, hb, sk, hd, tau, ep; } prof_t;

int main(void)
{
    static const prof_t PR[2] = {{"SIG-128", 128, 2048, 103, 11, 17, 32, 464, 96, 11, 44},
                                 {"SIG-256", 256, 4096, 206, 12, 33, 64, 977, 160, 23, 48}};
    static const double DOC[2] = {128.3, 264};
    static const long TDOC[2] = {8522, 34867};
    resultat_t r = {.nom = "compression_sig"};
    static char json[8000];
    size_t lj = (size_t)snprintf(json, sizeof json, "[");
    for (int q = 0; q < 2; q++) {
        const prof_t *p = &PR[q];
        double c = cout(p->tau, 12, p->n, p->w, p->ep, 4);
        long z = taille(p->hd, p->tau, 12, p->sb, p->hb, p->sk, p->ep, 4);
        res_controle(&r, q ? "reproduit_sig_256" : "reproduit_sig_128", fabs(c - DOC[q]) < 0.2 && z == TDOC[q]);
        printf("== %s : actuel coût %.1f, %ld o\n", p->nom, c, z);
        for (int D = 12; D <= 18; D++) {
            long m = 1L << 40;
            int mt = 0, mtt = 0, me = 0;
            double mc = 0;
            for (int tau = 1; tau <= 64; tau++)
                for (int t = 2; t <= 8; t++)
                    for (int ep = 2 * p->e; ep <= 64; ep += p->e) {
                        double v = cout(tau, D, p->n, p->w, ep, t);
                        long y = taille(p->hd, tau, D, p->sb, p->hb, p->sk, ep, t);
                        if (v >= p->lam && y < m) { m = y; mt = tau; mtt = t; me = ep; mc = v; }
                    }
            double tps = (double)(1 << (D - 12)) * mt / p->tau;
            printf("D=%2d τ=%2d t=%d ep=%d coût %.1f : %ld o (%+.1f %%), temps ×%.1f\n", D, mt, mtt, me, mc, m, 100.0 * (double)(m - z) / (double)z, tps);
            lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"profil\":\"%s\",\"D\":%d,\"tau\":%d,\"t\":%d,\"ep\":%d,\"cout\":%.1f,\"taille\":%ld,\"temps\":%.1f}", lj > 1 ? "," : "", p->nom, D, mt, mtt, me, mc, m, tps);
        }
    }
    snprintf(json + lj, sizeof json - lj, "]");
    res_mesure(&r, "grille", "%s", json);
    return res_ecrire(&r);
}
