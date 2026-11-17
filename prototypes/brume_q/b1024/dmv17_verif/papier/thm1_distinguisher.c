/* Distinguisher against Theorem 1 of Daemen-Mennink-Van Assche (ASIACRYPT 2017), real world (KD_K^f, f), N = 0.
 * Reduced model: b = r + c bits, f a lazily sampled uniform random permutation, K uniform on k bits, iv = 0.
 * Adversary D (q = 1, L = 0, N = 0, Omega flagged queries, v checks, M = Mu + v + v Omega + 1 construction queries, one chain):
 *   phase 1: Init(0, 0, sigma = 0, false), then Mu + v - 1 calls Duplexing(0, false): queries 1 .. Mu + v, outputs Z_1 ..;
 *            alpha = most frequent value among Z_1 .. Z_Mu (ties: smallest), T = { i <= Mu : Z_i = alpha };
 *            (control "first": alpha = Z_1 instead, T defined the same way)
 *   phase 2: for l = 1 .. Omega: a_l = Duplexing(alpha || 0^c, true), then v - 1 calls Duplexing(0, false);
 *            then one last Duplexing(0, false);
 *   output 1 iff for some l and some x in T or x = a_l' (l' < l): Z_{x+i} = Z_{a_l + i} for i = 1 .. v.
 * world "real": KD; world "rd": RD^{phi,pi} (phi(0,0) uniform, pi a lazily sampled permutation); world "ideal": IXIF
 * (every Z uniform and independent, all the paths being distinct).
 * Usage: thm1_distinguisher r c k Mu Omega v trials seed real|rd|ideal max|first */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <omp.h>
typedef struct { uint64_t s[4]; } rng_t;
static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static inline uint64_t nxt(rng_t *g) { uint64_t *s = g->s, r = rotl(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = rotl(s[3], 45); return r; }
static uint64_t splitmix(uint64_t *x) { uint64_t z = (*x += 0x9E3779B97F4A7C15ULL); z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL; return z ^ (z >> 31); }
#define HB 13
#define HS (1 << HB)
typedef struct { uint64_t key[HS], val[HS]; uint32_t ep[HS]; } tab_t;   /* open addressing, epoch-stamped */
static inline uint32_t hsh(uint64_t x) { return (uint32_t)((x * 0x9E3779B97F4A7C15ULL) >> (64 - HB)); }
static inline int tget(const tab_t *t, uint32_t e, uint64_t k, uint64_t *v) {
    for (uint32_t h = hsh(k);; h = (h + 1) & (HS - 1)) { if (t->ep[h] != e) return 0; if (t->key[h] == k) { *v = t->val[h]; return 1; } } }
static inline void tput(tab_t *t, uint32_t e, uint64_t k, uint64_t v) {
    uint32_t h = hsh(k); while (t->ep[h] == e) h = (h + 1) & (HS - 1); t->ep[h] = e; t->key[h] = k; t->val[h] = v; }
int main(int argc, char **argv)
{
    if (argc < 11) { fprintf(stderr, "usage: r c k Mu Omega v trials seed real|rd|ideal max|first\n"); return 2; }
    const int r = atoi(argv[1]), c = atoi(argv[2]), k = atoi(argv[3]), Mu = atoi(argv[4]), Om = atoi(argv[5]);
    const int v = atoi(argv[6]); const long trials = atol(argv[7]); const uint64_t seed = strtoull(argv[8], 0, 10);
    const int real = !strcmp(argv[9], "real"), rd = !strcmp(argv[9], "rd"), amax = !strcmp(argv[10], "max");
    const int b = r + c, M = Mu + v + v * Om + 1;
    if (b > 62 || k > b || 2 * M + 2 > HS / 2 || r > 20 || v < 1 || Mu < 1 || Om < 1) { fprintf(stderr, "parameters out of range\n"); return 2; }
    const uint64_t mb = (1ULL << b) - 1, mc = (1ULL << c) - 1;
    long ones = 0, colls = 0, onesnocoll = 0; double summu = 0; long mu2 = 0;
    #pragma omp parallel reduction(+:ones, colls, onesnocoll, summu, mu2)
    {
        rng_t g; uint64_t sm = seed * 1000003ULL + (uint64_t)omp_get_thread_num() * 7919ULL + 1;
        for (int i = 0; i < 4; i++) g.s[i] = splitmix(&sm);
        tab_t *fin = calloc(1, sizeof *fin), *fout = calloc(1, sizeof *fout);
        uint32_t *Z = malloc((size_t)(M + 2) * sizeof *Z), *cnt = calloc((size_t)1 << r, sizeof *cnt);
        int *tgt = malloc((size_t)(Mu + Om) * sizeof *tgt);
        uint32_t ep = 0;
        #pragma omp for schedule(static)
        for (long t = 0; t < trials; t++) {
            ep++; if (ep == 0) { memset(fin->ep, 0, sizeof fin->ep); memset(fout->ep, 0, sizeof fout->ep); ep = 1; }
            int coll = 0; uint64_t s = 0;
            /* f(x): lazily sampled permutation, forward queries only */
            #define F(x, y) do { uint64_t _x = (x), _v; if (tget(fin, ep, _x, &_v)) { coll = 1; (y) = _v; } else { \
                do { _v = nxt(&g) & mb; } while (tget(fout, ep, _v, &_x)); tput(fout, ep, _v, 0); tput(fin, ep, (x), _v); (y) = _v; } } while (0)
            #define CALL(j, sig_outer, flag) do { uint64_t tt; \
                if (real) { if ((j) == 1) { uint64_t K = nxt(&g) & ((1ULL << k) - 1); F(K << (b - k), tt); } else F(s, tt); } \
                else if (rd && (j) > 1) F(s, tt); \
                else tt = nxt(&g) & mb; \
                Z[j] = (uint32_t)(tt >> c); \
                s = (flag) ? (((uint64_t)(sig_outer) << c) | (tt & mc)) : (tt ^ ((uint64_t)(sig_outer) << c)); } while (0)
            for (int j = 1; j <= Mu + v; j++) CALL(j, 0, 0);
            uint32_t alpha = 0, mu = 0;
            for (int j = 1; j <= Mu; j++) { uint32_t n = ++cnt[Z[j]]; if (n > mu || (n == mu && Z[j] < alpha)) { mu = n; alpha = Z[j]; } }
            if (!amax) { alpha = Z[1]; mu = cnt[alpha]; }
            int nt = 0;
            for (int j = 1; j <= Mu; j++) { cnt[Z[j]] = 0; if (Z[j] == alpha) tgt[nt++] = j; }
            summu += mu; mu2 += mu >= 2;
            int out = 0, j = Mu + v;
            for (int l = 1; l <= Om; l++) {
                int a = ++j; CALL(a, alpha, 1); for (int i = 1; i < v; i++) { ++j; CALL(j, 0, 0); } tgt[nt++] = a;
            }
            ++j; CALL(j, 0, 0);
            /* decision, from the outputs Z only */
            for (int l = 0; l < Om && !out; l++) { int a = Mu + v + 1 + v * l;
                for (int i = 0; i < (int)mu + l && !out; i++) { int x = tgt[i], eq = 1;
                    for (int h = 1; h <= v && eq; h++) eq = Z[x + h] == Z[a + h];
                    out = eq; } }
            ones += out; colls += coll; onesnocoll += out && !coll;
        }
        free(fin); free(fout); free(Z); free(cnt); free(tgt);
    }
    const double p = (double)ones / trials, sd = sqrt(p * (1 - p) / trials);
    printf("%s alpha=%s r=%d c=%d k=%d Mu=%d Omega=%d v=%d M=%d trials=%ld seed=%llu : Pr[D=1] = %.9e +- %.2e ; f-input repeats %.9e ; D=1 without repeat %ld ; E[|T|] = %.6f ; Pr[|T|>=2] = %.6f\n",
           argv[9], argv[10], r, c, k, Mu, Om, v, M, trials, (unsigned long long)seed, p, sd, (double)colls / trials, onesnocoll, summu / trials, (double)mu2 / trials);
    return 0;
}
