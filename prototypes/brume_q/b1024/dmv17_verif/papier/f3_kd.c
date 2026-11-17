/* Gap 2, real world O = (KD_K^f, f) of DMV17 (Sections 6.1 and 6.4): the claim Pr(mu_fw > T_fw) <= nu / 2^c with
 * T_fw = L + Omega + nu^{2(M-L)}_{r,c} fails in O, because the adversary can recover the state with queries to f.
 * Reduced model: b = 16, r = 4, c = 12, k = 4, f a uniform random permutation (a shuffled table).
 * Resources: q = 1, L = 0, Omega = 0 (no flag, no repeated path), M = 3 + F = 11, N + M <= 0.1 * 2^c = 409.6.
 * Adversary: Init(iv = 0, sigma = 0), Duplexing(0), Duplexing(0) -> Z0, Z1, Z2; it guesses the inner part x of the state
 * after Init (random order), testing outer(f(Z0 || x)) = Z1 and then outer(f(f(Z0 || x))) = Z2; with the first candidate
 * that passes it predicts every next Z by one query to f and takes outer(sigma) = Z_predicted + alpha (alpha = 0): the F = 8
 * next queries then all have outer part alpha, with flag = false and new paths.
 * We measure Pr_O(mu_fw > T_fw), T_fw = nu^{22}_{4,12} = 7 (nu_exact.py 22 4 12), against the claimed nu / 2^c.
 * Usage: f3_kd trials [control]      (control: same construction queries, no attack) */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
static uint64_t st = 0x2545F4914F6CDD1DULL;
static uint64_t xr(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }
static uint16_t f[65536], perm[4096];
int main(int argc, char **argv)
{
    const int F = 8, M = 3 + F, NU = 7, NMAX = 409 - M;   /* N + M <= 0.1 * 2^12 = 409.6 */
    const long T = atol(argv[1]);
    const int attack = argc < 3;
    long success = 0, found = 0;
    for (long e = 0; e < T; e++) {
        for (int i = 0; i < 65536; i++) f[i] = (uint16_t)i;
        for (int i = 65535; i > 0; i--) { int j = (int)(xr() % (uint64_t)(i + 1)); uint16_t t = f[i]; f[i] = f[j]; f[j] = t; }
        const uint16_t K = (uint16_t)(xr() & 15);
        uint16_t s, Z[16], sb[16];
        int n = 0, N = 0;
        s = f[(uint16_t)(K << 12 | 0)];                     /* Init(delta, iv = 0), sigma = 0 */
        Z[n] = s >> 12; sb[n++] = 0;
        s = f[s]; Z[n] = s >> 12; sb[n++] = 0;              /* Duplexing(0) */
        s = f[s]; Z[n] = s >> 12; sb[n++] = 0;              /* Duplexing(0): s = current state (secret) */
        int cand = -1;
        if (attack) {
            for (int i = 0; i < 4096; i++) perm[i] = (uint16_t)i;
            for (int i = 4095; i > 0; i--) { int j = (int)(xr() % (uint64_t)(i + 1)); uint16_t t = perm[i]; perm[i] = perm[j]; perm[j] = t; }
            for (int g = 0; g < 4096 && N + 2 + F <= NMAX && cand < 0; g++) {
                uint16_t y = f[(uint16_t)(Z[0] << 12 | perm[g])]; N++;
                if ((y >> 12) != Z[1]) continue;
                uint16_t y2 = f[y]; N++;
                if ((y2 >> 12) == Z[2]) cand = y2;          /* presumed current state */
            }
        }
        uint16_t cur = (uint16_t)cand;
        for (int i = 0; i < F; i++) {
            uint16_t sig = 0;
            if (cand >= 0) { uint16_t p = f[cur]; N++; sig = (uint16_t)(((p >> 12) ^ 0) << 12); cur = p ^ sig; }  /* alpha = 0 */
            s = f[s]; Z[n] = s >> 12; sb[n++] = sig >> 12; s ^= sig;     /* Duplexing(sigma), flag = false */
        }
        if (N + M > 409) { fprintf(stderr, "budget exceeded\n"); return 1; }
        int cnt[16] = {0}, mu = 0;
        for (int j = 0; j < n; j++) if (++cnt[Z[j] ^ sb[j]] > mu) mu = cnt[Z[j] ^ sb[j]];
        success += mu > NU;
        if (cand >= 0) found++;
    }
    const double p = (double)success / T, sd = sqrt(p * (1 - p) / T), claim = NU / 4096.0;
    printf("%s trials=%ld : Pr_O(mu_fw > %d) = %.5f +- %.5f (candidate found: %.4f) ; claimed nu/2^c = %.5f ; ratio %.1f\n",
           attack ? "adversary" : "control", T, NU, p, sd, (double)found / T, claim, p / claim);
    return 0;
}
