/* Gap 2, world P = (RD^{phi,pi}, f) of DMV17 (Section 6.1 and 6.4): the claim Pr(mu_fw > T_fw) <= nu / 2^c, with
 * T_fw = L + Omega + nu^{2(M-L)}_{r,c}, fails in P as well, because a state of RD can repeat (an s-collision).
 * Reduced model: b = r + c, phi and pi lazily sampled (one initialisation, so phi is one uniform value), no query to f.
 * Adversary (q = 1, L = 0, N = 0, Omega flagged queries, M = 1 + Omega + F):
 *   query 1: Init(0, 0, 0, false); queries 2 .. Omega+1: Duplexing(0^b, true)  (outer part of the state forced to 0);
 *   if the outputs show a cycle (Z_j .. Z_{j+v-1} = Z_i .. Z_{i+v-1} for some i < j, period p = j - i), then F queries
 *   Duplexing(sigma, false) with outer(sigma) = Z_{n-p} (the predicted output), which also force the outer part to 0
 *   although they have new paths and no flag; otherwise F queries Duplexing(0, false).
 * mu_fw is computed from the true transcript: max over alpha of #{ queries with outer part of the state after injection = alpha }.
 * Usage: f3_rd r c Omega F v T_fw trials seed [control]     (control: never uses the prediction) */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
static uint64_t st[4];
static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static uint64_t nxt(void) { uint64_t r = rotl(st[1] * 5, 7) * 9, t = st[1] << 17;
    st[2] ^= st[0]; st[3] ^= st[1]; st[1] ^= st[2]; st[0] ^= st[3]; st[2] ^= t; st[3] = rotl(st[3], 45); return r; }
static uint64_t splitmix(uint64_t *x) { uint64_t z = (*x += 0x9E3779B97F4A7C15ULL); z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; return z ^ (z >> 31); }
#define MAXQ 512
int main(int argc, char **argv)
{
    if (argc < 9) { fprintf(stderr, "usage: r c Omega F v T_fw trials seed [control]\n"); return 2; }
    const int r = atoi(argv[1]), c = atoi(argv[2]), Om = atoi(argv[3]), F = atoi(argv[4]), v = atoi(argv[5]), Tfw = atoi(argv[6]);
    const long trials = atol(argv[7]); uint64_t sm = strtoull(argv[8], 0, 10); const int control = argc > 9;
    const int b = r + c, M = 1 + Om + F;
    if (b > 62 || M + 1 > MAXQ || r > 16) { fprintf(stderr, "parameters out of range\n"); return 2; }
    for (int i = 0; i < 4; i++) st[i] = splitmix(&sm);
    const uint64_t mb = (1ULL << b) - 1, mc = (1ULL << c) - 1;
    static uint64_t pin[MAXQ], pout[MAXQ]; static uint32_t Z[MAXQ], outer[MAXQ]; static int cnt[1 << 16];
    long succ = 0, cyc = 0, det = 0;
    for (long t = 0; t < trials; t++) {
        int np = 0, repeat = 0; uint64_t s = nxt() & mb;                      /* phi(0, 0): one uniform value */
        Z[1] = (uint32_t)(s >> c); outer[1] = Z[1];                           /* Init, sigma = 0, flag = false */
        int p = 0;
        for (int j = 2; j <= M; j++) {
            uint64_t y = 0; int found = 0;                                    /* y = pi(s), lazily sampled */
            for (int i = 0; i < np; i++) if (pin[i] == s) { y = pout[i]; found = 1; break; }
            if (found) repeat = 1;
            else { int dup; do { y = nxt() & mb; dup = 0; for (int i = 0; i < np; i++) if (pout[i] == y) { dup = 1; break; } } while (dup);
                   pin[np] = s; pout[np++] = y; }
            Z[j] = (uint32_t)(y >> c);
            if (j <= Om + 1) { s = y & mc; outer[j] = 0; }                    /* Duplexing(0^b, true): outer part := 0 */
            else {
                uint32_t so = (!control && p) ? Z[j - p] : 0;                 /* Duplexing(sigma, false), outer(sigma) = prediction */
                s = y ^ ((uint64_t)so << c); outer[j] = Z[j] ^ so;
            }
            if (j == Om + 1) {                                               /* look for a cycle in Z_2 .. Z_{Omega+1} */
                for (int jj = 3; jj + v - 1 <= Om + 1 && !p; jj++)
                    for (int ii = 2; ii < jj && !p; ii++) { int eq = 1; for (int h = 0; h < v && eq; h++) eq = Z[jj + h] == Z[ii + h]; if (eq) p = jj - ii; }
            }
        }
        int mu = 0;
        for (int j = 1; j <= M; j++) if (++cnt[outer[j]] > mu) mu = cnt[outer[j]];
        for (int j = 1; j <= M; j++) cnt[outer[j]] = 0;
        succ += mu > Tfw; cyc += repeat; det += p > 0;
    }
    const double pr = (double)succ / trials, sd = sqrt(pr * (1 - pr) / trials), claim = (double)(Tfw - Om) / (double)(1ULL << c);
    printf("%s r=%d c=%d Omega=%d F=%d v=%d M=%d T_fw=%d trials=%ld : Pr_P(mu_fw > T_fw) = %.6f +- %.6f ; state repeated %.6f ; cycle detected %.6f ; claimed nu/2^c = %.6f ; ratio %.1f\n",
           control ? "control" : "adversary", r, c, Om, F, v, M, Tfw, trials, pr, sd, (double)cyc / trials, (double)det / trials, claim, pr / claim);
    return 0;
}
