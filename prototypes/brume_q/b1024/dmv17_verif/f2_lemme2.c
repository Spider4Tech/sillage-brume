/* F2 : monde idéal (IXIF) du lemme 2 de DMV17. r = 4, c = 16 (b = 20). Chaque requête a un chemin neuf : t = RO(chemin)
 * uniforme. Mu requêtes non contrôlées (σ = 0, drapeau faux) : s = t. Puis Om requêtes avec drapeau (chemins neufs,
 * Ω = Om, L = 0), partie externe choisie α = valeur externe la plus fréquente parmi les non contrôlées, σ̂ = 0 : s = (α, t̂).
 * On mesure Pr[s-collision] et on le compare à la borne écrite p. 622 :
 *   (C(M,2) − C(L+Ω+1,2))/2^b + C(L+Ω+1,2)/2^c,  M = Mu + Om. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
static uint64_t st = 0x9E3779B97F4A7C15ULL;
static uint64_t xr(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }
int main(int argc, char **argv)
{
    const int R = 4, C = 16, Mu = atoi(argv[1]), Om = atoi(argv[2]);
    const long T = atol(argv[3]);
    long coll = 0;
    uint32_t s[4096];
    for (long e = 0; e < T; e++) {
        int cnt[16] = {0}, n = 0;
        for (int j = 0; j < Mu; j++) {
            uint32_t ob = xr() & 15, in = xr() & 0xFFFF;
            s[n++] = ob << C | in;
            cnt[ob]++;
        }
        int a = 0;   /* témoin : 4e argument → α tiré au hasard au lieu de la valeur la plus chargée */
        if (argc > 4) a = (int)(xr() & 15);
        else for (int v = 1; v < 16; v++) if (cnt[v] > cnt[a]) a = v;
        for (int j = 0; j < Om; j++) s[n++] = (uint32_t)a << C | (xr() & 0xFFFF);
        int c = 0;
        for (int i = 0; i < n && !c; i++) for (int j = i + 1; j < n; j++) if (s[i] == s[j]) { c = 1; break; }
        coll += c;
    }
    const double M = Mu + Om, S = (Om + 1.0) * Om / 2, CM = M * (M - 1) / 2;
    const double borne = (CM - S) / pow(2, R + C) + S / pow(2, C);
    const double p = (double)coll / T, sd = sqrt(p * (1 - p) / T);
    printf("Mu=%d Om=%d essais=%ld : Pr[s-collision] = %.6g ± %.2g ; borne p. 622 = %.6g ; écart = %.1f σ\n", Mu, Om, T, p, sd, borne, (p - borne) / sd);
    return 0;
}
