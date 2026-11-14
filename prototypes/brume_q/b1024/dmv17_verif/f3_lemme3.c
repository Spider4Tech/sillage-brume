/* F3 : monde réel O = (KD_K, f) de DMV17, modèle réduit b = 16, r = 4, c = 12, k = 4, f permutation aléatoire.
 * Ressources : q = 1, L = 0, Ω = 0 (aucun drapeau, aucun chemin répété), M = 3 + F, N ≤ 0,1·2^c − M.
 * Adversaire : Init(iv = 0, σ = 0), Duplexing(0), Duplexing(0) → Z0, Z1, Z2 ; il devine la partie interne x de l'état après
 * Init en testant f(Z0 ‖ x) contre Z1 puis f(·) contre Z2 ; s'il la trouve, il prédit chaque Z suivant par une requête à f
 * et choisit σ̄ = Z_prédit ⊕ α : les F requêtes suivantes ont toutes la partie externe α (flag faux, chemins neufs).
 * On mesure Pr_O(μ_fw > T_fw), T_fw = L + Ω + ν^{2M}_{r,c} = 7, et on le compare à la borne ν/2^c de la p. 629. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
static uint64_t st = 0x2545F4914F6CDD1DULL;
static uint64_t xr(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }
static uint16_t f[65536], perm[4096];
int main(int argc, char **argv)
{
    const int F = 8, M = 3 + F, NU = 7, NMAX = 409 - M;   /* N + M ≤ 0,1·2^12 = 409,6 */
    const long T = atol(argv[1]);
    const int attaque = argc < 3;
    long succes = 0, trouve = 0;
    for (long e = 0; e < T; e++) {
        for (int i = 0; i < 65536; i++) f[i] = (uint16_t)i;
        for (int i = 65535; i > 0; i--) { int j = (int)(xr() % (uint64_t)(i + 1)); uint16_t t = f[i]; f[i] = f[j]; f[j] = t; }
        const uint16_t K = (uint16_t)(xr() & 15);
        uint16_t s, Z[16], sb[16];
        int n = 0, N = 0;
        s = f[(uint16_t)(K << 12 | 0)];                     /* Init(δ, iv = 0), σ = 0 */
        Z[n] = s >> 12; sb[n++] = 0;
        s = f[s]; Z[n] = s >> 12; sb[n++] = 0;              /* Duplexing(0) */
        s = f[s]; Z[n] = s >> 12; sb[n++] = 0;              /* Duplexing(0) : s = état courant (secret) */
        int cand = -1;
        if (attaque) {
            for (int i = 0; i < 4096; i++) perm[i] = (uint16_t)i;
            for (int i = 4095; i > 0; i--) { int j = (int)(xr() % (uint64_t)(i + 1)); uint16_t t = perm[i]; perm[i] = perm[j]; perm[j] = t; }
            for (int g = 0; g < 4096 && N + 2 + F <= NMAX && cand < 0; g++) {
                uint16_t y = f[(uint16_t)(Z[0] << 12 | perm[g])]; N++;
                if ((y >> 12) != Z[1]) continue;
                uint16_t y2 = f[y]; N++;
                if ((y2 >> 12) == Z[2]) cand = y2;          /* état courant supposé */
            }
        }
        uint16_t cur = (uint16_t)cand;
        for (int i = 0; i < F; i++) {
            uint16_t sig = 0;
            if (cand >= 0) { uint16_t p = f[cur]; N++; sig = (uint16_t)(((p >> 12) ^ 0) << 12); cur = p ^ sig; }  /* α = 0 */
            s = f[s]; Z[n] = s >> 12; sb[n++] = sig >> 12; s ^= sig;     /* Duplexing(σ), drapeau faux */
        }
        if (N + M > 409) { fprintf(stderr, "budget dépassé\n"); return 1; }
        int cnt[16] = {0}, mu = 0;
        for (int j = 0; j < n; j++) if (++cnt[Z[j] ^ sb[j]] > mu) mu = cnt[Z[j] ^ sb[j]];
        succes += mu > NU;
        if (cand >= 0) trouve++;
    }
    const double p = (double)succes / T, sd = sqrt(p * (1 - p) / T), borne = NU / 4096.0;
    printf("%s : Pr_O(μ_fw > %d) = %.5f ± %.5f (état deviné : %.4f) ; borne annoncée ν/2^c = %.5f ; rapport %.1f\n",
           attaque ? "adversaire" : "témoin sans attaque", NU, p, sd, (double)trouve / T, borne, p / borne);
    return 0;
}
