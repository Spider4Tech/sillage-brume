/* Batterie statistique de BRUME-1024q (ROADMAP.md § 3, « Statistical battery on the permutation ») : les tests de la suite
 * (tests/test_c_statistiques.py et tests/test_c_sac.py, écrits pour BRUME-512) portés en C pur sur la permutation de
 * 1 024 bits, sur P₃₂ et sur des tours réduits, pour situer la portée statistique.
 *
 * I. Flux (type NIST SP 800-22 étendu, comme la suite) :
 *    - compteur à R tours : bloc i = débit (80 o) de P_R(K ⊕ i), i (64 bits) placé dans la capacité (octets 80..87) :
 *      entrées de faible distance de Hamming, cas défavorable ; R = 32 (taille T), R = 1 … 8 (taille T/4) ;
 *    - XOF (éponge DOM_SEQ, 32 tours) : 4 sorties de T/4 octets pour 4 messages distincts.
 *    Tests par flux : fréquence, poids des blocs de 32 o (binomiale), fréquence par blocs de 1 Kio, runs, plus longue
 *    suite de 1 par blocs de 10 000 bits, sériel 16 bits (∇ψ², ∇²ψ²), octets, paires d'octets (65 536 cases), octets par
 *    position dans le bloc de 80 o (compteur), autocorrélations (21 décalages), rang des matrices 32 × 32, complexité
 *    linéaire (Berlekamp–Massey, M = 1 000, 20 000 blocs).
 *    Décision : Bonferroni sur les p-valeurs d'un flux (α = 10^−3) et Kolmogorov–Smirnov d'uniformité des p-valeurs.
 * II. Avalanche stricte (SAC) complète, matrice 1 024 × 1 024 : Pr[bit j de P(x) ⊕ P(x ⊕ e_i)], 2^16 échantillons par
 *    entrée (2^14 en inverse) ; max |z| corrigé pour 2^20 cases et χ² global Σ z² ; premier tour indistinguable dans les
 *    deux sens, puis 32 tours.
 * Contrôles : l'inverse rapide (matrice binaire) inverse perm1 et égale ref_tour_inv ; chaque test, appliqué à un flux
 *    biaisé planté (un bit sur 512 forcé, ou corrélation à un décalage), doit échouer ; un flux de référence
 *    (splitmix64) doit passer.
 *    stats1024 [T en Mio, défaut 256] [sortie.json]   (OMP_NUM_THREADS : threads) */
#define SANS_MAIN
#include "brume1024.c"
#include <math.h>

/* ------------------------------------------------------------ p-valeurs */
static double igamc(double a, double x);
static double igam(double a, double x)
{
    if (x <= 0)
        return 0;
    if (x > a + 1)
        return 1 - igamc(a, x);
    double s = 1 / a, t = s, ap = a;
    for (int n = 0; n < 1000000; n++) {
        ap += 1;
        t *= x / ap;
        s += t;
        if (fabs(t) < fabs(s) * 1e-15)
            break;
    }
    return s * exp(-x + a * log(x) - lgamma(a));
}
static double igamc(double a, double x)
{
    if (x <= 0)
        return 1;
    if (x < a + 1)
        return 1 - igam(a, x);
    double b = x + 1 - a, c = 1e300, d = 1 / b, h = d;
    for (int i = 1; i < 1000000; i++) {
        double an = -i * (i - a);
        b += 2;
        d = an * d + b;
        if (fabs(d) < 1e-300) d = 1e-300;
        c = b + an / c;
        if (fabs(c) < 1e-300) c = 1e-300;
        d = 1 / d;
        double del = d * c;
        h *= del;
        if (fabs(del - 1) < 1e-15)
            break;
    }
    return exp(-x + a * log(x) - lgamma(a)) * h;
}
static double p_chi2(double x, double df) { return igamc(df / 2, x / 2); }

/* χ² avec regroupement des cases d'effectif attendu < 5 aux extrémités (comme chi2_regroupe de la suite) */
static double chi2_regroupe(const double *obs, const double *prob, int k, double n)
{
    double x = 0, co = 0, ca = 0, lo = 0, la = 0;
    int df = -1, ouvert = 0;
    for (int i = 0; i < k; i++) {
        co += obs[i];
        ca += prob[i] * n;
        if (ca >= 5) {
            if (ouvert) x += (lo - la) * (lo - la) / la;
            lo = co; la = ca; ouvert = 1; df++;
            co = ca = 0;
        }
    }
    lo += co; la += ca;
    if (ouvert) x += (lo - la) * (lo - la) / la;
    return df > 0 ? p_chi2(x, df) : 1;
}

/* ------------------------------------------------------------ tests sur un flux d'octets */
#define NPMAX 256
typedef struct { const char *nom; double p[NPMAX]; char ptest[NPMAX][48]; int np; } flux_t;
static void ajouter_p(flux_t *f, const char *t, double p)
{
    if (f->np < NPMAX) {
        snprintf(f->ptest[f->np], 48, "%s", t);
        f->p[f->np++] = p < 0 ? 0 : p > 1 ? 1 : p;
    }
}
static int bit(const uint8_t *b, size_t i) { return (b[i >> 3] >> (i & 7)) & 1; }

static void tests_flux(flux_t *f, const uint8_t *b, size_t n, int pos80)
{
    const size_t nb = 8 * n;
    const uint64_t *w = (const uint64_t *)b;
    const size_t nw = n / 8;
    /* fréquence */
    {
        long long un = 0;
#pragma omp parallel for reduction(+ : un)
        for (size_t i = 0; i < nw; i++)
            un += __builtin_popcountll(w[i]);
        double s = 2.0 * un - (double)nb;
        ajouter_p(f, "frequence", erfc(fabs(s) / sqrt(2.0 * nb)));
        /* runs (NIST) */
        double pi = (double)un / nb;
        long long v = 1;                                   /* V = 1 + #{i : b_i ≠ b_{i+1}} */
#pragma omp parallel for reduction(+ : v)
        for (size_t i = 0; i < nw; i++) {
            uint64_t x = w[i], y = (x >> 1) | ((i + 1 < nw ? w[i + 1] & 1 : x >> 63) << 63);  /* dernier bit : avec lui-même */
            v += __builtin_popcountll(x ^ y);
        }
        ajouter_p(f, "runs", fabs(pi - 0.5) >= 2 / sqrt((double)nb) ? 0 :
                  erfc(fabs(v - 2.0 * nb * pi * (1 - pi)) / (2 * sqrt(2.0 * nb) * pi * (1 - pi))));
    }
    /* poids des blocs de 32 octets (binomiale 256, 1/2) */
    {
        static double obs[257], prob[257];
        memset(obs, 0, sizeof obs);
        for (int k = 0; k <= 256; k++)
            prob[k] = exp(lgamma(257) - lgamma(k + 1) - lgamma(257 - k) - 256 * log(2));
        for (size_t i = 0; i + 4 <= nw; i += 4)
            obs[__builtin_popcountll(w[i]) + __builtin_popcountll(w[i + 1]) + __builtin_popcountll(w[i + 2]) +
                __builtin_popcountll(w[i + 3])]++;
        ajouter_p(f, "poids_blocs_32o", chi2_regroupe(obs, prob, 257, (double)(nw / 4)));
    }
    /* fréquence par blocs de 1 Kio (M = 8 192 bits) */
    {
        size_t N = n / 1024;
        double x = 0;
        for (size_t k = 0; k < N; k++) {
            long long u = 0;
            for (int i = 0; i < 128; i++)
                u += __builtin_popcountll(w[128 * k + i]);
            double d = (double)u / 8192 - 0.5;
            x += 4.0 * 8192 * d * d;
        }
        ajouter_p(f, "frequence_blocs_1kio", p_chi2(x, (double)N));
    }
    /* plus longue suite de 1, blocs de 10 000 bits (NIST : K = 6, classes ≤ 10 … ≥ 16) */
    {
        static const double PI_LR[7] = {0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727};
        double obs[7] = {0};
        size_t N = nb / 10000;
        if (N > 200000) N = 200000;
        for (size_t k = 0; k < N; k++) {
            int lr = 0, c = 0;
            for (size_t i = 10000 * k; i < 10000 * (k + 1); i++) {
                c = bit(b, i) ? c + 1 : 0;
                if (c > lr) lr = c;
            }
            obs[lr <= 10 ? 0 : lr >= 16 ? 6 : lr - 10]++;
        }
        double x = 0;
        for (int i = 0; i < 7; i++)
            x += (obs[i] - N * PI_LR[i]) * (obs[i] - N * PI_LR[i]) / (N * PI_LR[i]);
        ajouter_p(f, "plus_longue_suite", p_chi2(x, 6));
    }
    /* octets, paires d'octets (mots de 16 bits non chevauchants) */
    {
        double o8[256] = {0};
        double *o16 = calloc(65536, sizeof *o16);
        for (size_t i = 0; i < n; i++)
            o8[b[i]]++;
        for (size_t i = 0; i + 1 < n; i += 2)
            o16[b[i] | b[i + 1] << 8]++;
        double x = 0, e = n / 256.0;
        for (int i = 0; i < 256; i++)
            x += (o8[i] - e) * (o8[i] - e) / e;
        ajouter_p(f, "octets", p_chi2(x, 255));
        x = 0; e = (n / 2) / 65536.0;
        for (int i = 0; i < 65536; i++)
            x += (o16[i] - e) * (o16[i] - e) / e;
        ajouter_p(f, "paires_d_octets", p_chi2(x, 65535));
        free(o16);
    }
    /* octets par position dans le bloc de 80 o (flux de compteur) */
    if (pos80) {
        double *o = calloc(80 * 256, sizeof *o), x = 0;
        size_t nbl = n / 80;
        for (size_t k = 0; k < nbl; k++)
            for (int j = 0; j < 80; j++)
                o[256 * j + b[80 * k + j]]++;
        double e = nbl / 256.0, pmin = 1;
        for (int j = 0; j < 80; j++) {
            double xj = 0;
            for (int v = 0; v < 256; v++)
                xj += (o[256 * j + v] - e) * (o[256 * j + v] - e) / e;
            x += xj;
            double pj = p_chi2(xj, 255);
            if (pj < pmin) pmin = pj;
        }
        ajouter_p(f, "octets_par_position_global", p_chi2(x, 80 * 255));
        ajouter_p(f, "octets_par_position_pire_sidak", 1 - pow(1 - pmin, 80));
        free(o);
    }
    /* sériel 16 bits chevauchants (NIST : ψ²_m, ∇ψ², ∇²ψ², m = 16), sur au plus 2^30 bits */
    {
        size_t nn = nb < ((size_t)1 << 30) ? nb : (size_t)1 << 30;
        double *c16 = calloc(65536, sizeof *c16), c15[32768] = {0}, c14[16384] = {0};
        uint32_t r = 0;
        for (size_t i = 0; i < nn + 15; i++) {             /* motif circulaire : les 15 premiers bits recommencent */
            r = ((r << 1) | (uint32_t)bit(b, i % nn)) & 0xFFFF;
            if (i >= 15)
                c16[r]++;
        }
        for (int i = 0; i < 65536; i++) c15[i >> 1] += c16[i];
        for (int i = 0; i < 32768; i++) c14[i >> 1] += c15[i];
        double s16 = 0, s15 = 0, s14 = 0;
        for (int i = 0; i < 65536; i++) s16 += c16[i] * c16[i];
        for (int i = 0; i < 32768; i++) s15 += c15[i] * c15[i];
        for (int i = 0; i < 16384; i++) s14 += c14[i] * c14[i];
        double N = (double)nn, p16 = 65536 * s16 / N - N, p15 = 32768 * s15 / N - N, p14 = 16384 * s14 / N - N;
        ajouter_p(f, "seriel_16_nabla", p_chi2(p16 - p15, 32768));
        ajouter_p(f, "seriel_16_nabla2", p_chi2(p16 - 2 * p15 + p14, 16384));
        free(c16);
    }
    /* autocorrélations à 21 décalages (bits) */
    {
        static const int LAGS[21] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 31, 32, 33, 64, 127, 128, 256, 512, 1024, 2048, 4096};
        for (int l = 0; l < 21; l++) {
            const int d = LAGS[l], dw = d / 64, db = d % 64;
            long long a = 0;
            size_t m = nw - dw - 1;
#pragma omp parallel for reduction(+ : a)
            for (size_t i = 0; i < m; i++) {
                uint64_t s = db ? (w[i + dw] >> db) | (w[i + dw + 1] << (64 - db)) : w[i + dw];
                a += __builtin_popcountll(w[i] ^ s);
            }
            double N = 64.0 * m, z = 2 * (a - N / 2) / sqrt(N);
            char t[48];
            snprintf(t, sizeof t, "autocorrelation_%d", d);
            ajouter_p(f, t, erfc(fabs(z) / sqrt(2)));
        }
    }
    /* rang des matrices 32 × 32 sur GF(2) */
    {
        static const double PI_R[3] = {0.133636, 0.577576, 0.288788};  /* ≤ 30, 31, 32 */
        double obs[3] = {0};
        size_t N = n / 128;
        for (size_t k = 0; k < N; k++) {
            uint32_t m[32];
            memcpy(m, b + 128 * k, 128);
            int rg = 0;
            for (int c = 0; c < 32 && rg < 32; c++) {
                int p = rg;
                while (p < 32 && !((m[p] >> c) & 1)) p++;
                if (p == 32) continue;
                uint32_t t = m[p]; m[p] = m[rg]; m[rg] = t;
                for (int i = 0; i < 32; i++)
                    if (i != rg && ((m[i] >> c) & 1)) m[i] ^= m[rg];
                rg++;
            }
            obs[rg >= 32 ? 2 : rg == 31 ? 1 : 0]++;
        }
        double x = 0;
        for (int i = 0; i < 3; i++)
            x += (obs[i] - N * PI_R[i]) * (obs[i] - N * PI_R[i]) / (N * PI_R[i]);
        ajouter_p(f, "rang_32x32", p_chi2(x, 2));
    }
    /* complexité linéaire (NIST, M = 1 000, K = 6), 20 000 blocs au plus */
    {
        static const double PI_LC[7] = {0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833};
        const int M = 1000;
        size_t N = nb / M;
        if (N > 20000) N = 20000;
        double obs[7] = {0};
#pragma omp parallel
        {
            double ol[7] = {0};
#pragma omp for
            for (size_t k = 0; k < N; k++) {
                uint8_t s[1000], C[1001] = {1}, B[1001] = {1}, T[1001];
                for (int i = 0; i < M; i++) s[i] = (uint8_t)bit(b, (size_t)M * k + i);
                int L = 0, m = -1;
                for (int i = 0; i < M; i++) {
                    int d = s[i];
                    for (int j = 1; j <= L; j++) d ^= C[j] & s[i - j];
                    if (d) {
                        memcpy(T, C, sizeof C);
                        for (int j = 0; j + i - m <= M; j++) C[j + i - m] ^= B[j];
                        if (L <= i / 2) { L = i + 1 - L; m = i; memcpy(B, T, sizeof B); }
                    }
                }
                double mu = M / 2.0 + (9 - 1) / 36.0 - (M / 3.0 + 2 / 9.0) / pow(2, M);   /* M pair : (−1)^{M+1} = −1 */
                double t = (M % 2 ? -1 : 1) * (L - mu) + 2 / 9.0;
                ol[t <= -2.5 ? 0 : t <= -1.5 ? 1 : t <= -0.5 ? 2 : t <= 0.5 ? 3 : t <= 1.5 ? 4 : t <= 2.5 ? 5 : 6]++;
            }
#pragma omp critical
            for (int i = 0; i < 7; i++) obs[i] += ol[i];
        }
        double x = 0;
        for (int i = 0; i < 7; i++)
            x += (obs[i] - N * PI_LC[i]) * (obs[i] - N * PI_LC[i]) / (N * PI_LC[i]);
        ajouter_p(f, "complexite_lineaire", p_chi2(x, 6));
    }
}

/* Kolmogorov–Smirnov d'uniformité (p asymptotique de Kolmogorov) */
static double ks_uniforme(const double *p0, int n)
{
    double p[NPMAX];
    memcpy(p, p0, n * sizeof *p);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (p[j] < p[i]) { double t = p[i]; p[i] = p[j]; p[j] = t; }
    double d = 0;
    for (int i = 0; i < n; i++) {
        double a = (i + 1.0) / n - p[i], b2 = p[i] - (double)i / n;
        if (a > d) d = a;
        if (b2 > d) d = b2;
    }
    double l = (sqrt((double)n) + 0.12 + 0.11 / sqrt((double)n)) * d, s = 0;
    for (int k = 1; k < 100; k++)
        s += 2 * ((k & 1) ? 1 : -1) * exp(-2.0 * k * k * l * l);
    return s < 0 ? 0 : s > 1 ? 1 : s;
}

typedef struct { double pmin, bonf, ks; int ok; const char *pire; } verdict_t;
static verdict_t juger(const flux_t *f)
{
    verdict_t v = {1, 1, 1, 1, ""};
    for (int i = 0; i < f->np; i++)
        if (f->p[i] < v.pmin) { v.pmin = f->p[i]; v.pire = f->ptest[i]; }
    v.bonf = fmin(1, v.pmin * f->np);
    v.ks = ks_uniforme(f->p, f->np);
    v.ok = v.bonf >= 1e-3 && v.ks >= 1e-3;
    return v;
}

/* ------------------------------------------------------------ inverse rapide (matrice binaire de M⁻¹) */
static uint64_t MIB[1024][16];
static void init_mib(void)
{
    memset(MIB, 0, sizeof MIB);
    for (int v = 0; v < N1; v++)
        for (int j = 0; j < N1; j++)
            for (int b2 = 0; b2 < 4; b2++) {
                uint8_t t = gf_mul(DMI[v][j], (uint8_t)(1 << b2));
                for (int a = 0; a < 4; a++)
                    if ((t >> a) & 1)
                        MIB[4 * v + a][(4 * j + b2) >> 6] |= 1ULL << ((4 * j + b2) & 63);
            }
}
static void perm_inv(uint8_t w[128], int R)          /* inverse des tours R − 1 … 0 */
{
    for (int r = R - 1; r >= 0; r--) {
        uint64_t x[16], y[16] = {0};
        memcpy(x, w, 128);
        for (int o = 0; o < 1024; o++) {
            uint64_t a = 0;
            for (int k = 0; k < 16; k++)
                a ^= MIB[o][k] & x[k];
            y[o >> 6] |= (uint64_t)(__builtin_popcountll(a) & 1) << (o & 63);
        }
        memcpy(w, y, 128);
        for (int i = 0; i < 128; i++) {
            uint8_t lo = SI[w[i] & 15] ^ B1_RC[r][2 * i], hi = SI[w[i] >> 4] ^ B1_RC[r][2 * i + 1];
            w[i] = (uint8_t)(lo | hi << 4);
        }
    }
}

static inline uint64_t sm64(uint64_t *s)
{
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ------------------------------------------------------------ SAC */
typedef struct { double zmax, pmax, zchi2, pire; int ok; } sac_t;
static double p_max_normales(double z, double m)        /* P[max de m |N(0,1)| ≥ z] */
{
    double q = erfc(z / sqrt(2));
    return q * m < 1e-8 ? q * m : 1 - pow(1 - q, m);
}
static sac_t sac(int R, int lg, int sens, uint64_t graine)
{
    static uint32_t cnt[1024][1024];
    memset(cnt, 0, sizeof cnt);
    const size_t n = (size_t)1 << lg;
#pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < 1024; i++) {
        uint64_t s = graine ^ ((uint64_t)i << 32);
        uint32_t loc[1024] = {0};
        for (size_t e = 0; e < n; e++) {
            uint64_t x[16], y[16];
            for (int k = 0; k < 16; k++) x[k] = y[k] = sm64(&s);
            y[i >> 6] ^= 1ULL << (i & 63);
            if (sens) { perm_inv((uint8_t *)x, R); perm_inv((uint8_t *)y, R); }
            else { perm1((uint8_t *)x, R); perm1((uint8_t *)y, R); }
            for (int k = 0; k < 16; k++) {
                uint64_t d = x[k] ^ y[k];
                while (d) {
                    loc[64 * k + __builtin_ctzll(d)]++;
                    d &= d - 1;
                }
            }
        }
        memcpy(cnt[i], loc, sizeof loc);
    }
    sac_t r = {0, 1, 0, 0, 0};
    double s2 = 0, sd = sqrt(n / 4.0);
    for (int i = 0; i < 1024; i++)
        for (int j = 0; j < 1024; j++) {
            double z = (cnt[i][j] - n / 2.0) / sd;
            s2 += z * z;
            if (fabs(z) > r.zmax) r.zmax = fabs(z);
            double e = fabs((double)cnt[i][j] / n - 0.5);
            if (e > r.pire) r.pire = e;
        }
    const double M = 1024.0 * 1024;
    r.zchi2 = (s2 - M) / sqrt(2 * M);
    r.pmax = p_max_normales(r.zmax, M);
    r.ok = r.pmax > 1e-6 && fabs(r.zchi2) < 6;
    return r;
}

/* ------------------------------------------------------------ flux */
static void flux_compteur(uint8_t *o, size_t n, int R, uint64_t graine)
{
    size_t nbl = (n + RB - 1) / RB;
    uint8_t K[128];
    uint64_t s = graine;
    for (int i = 0; i < 16; i++) { uint64_t v = sm64(&s); memcpy(K + 8 * i, &v, 8); }
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < nbl; i++) {
        uint8_t w[128] __attribute__((aligned(32)));
        memcpy(w, K, 128);
        for (int k = 0; k < 8; k++) w[RB + k] ^= (uint8_t)((uint64_t)i >> (8 * k));
        perm1(w, R);
        size_t l = n - RB * i < RB ? n - RB * i : RB;
        memcpy(o + RB * i, w, l);
    }
}

int main(int argc, char **argv)
{
    size_t T = (size_t)(argc > 1 ? atoi(argv[1]) : 256) << 20;
    const char *sortie = argc > 2 ? argv[2] : "stats1024.json";
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    prepare_iv();
    init_mib();
    FILE *J = fopen(sortie, "w");
    if (!J) return 2;
    int ok_global = 1;
    double t0 = omp_get_wtime();
    /* contrôle de l'inverse rapide */
    int okinv = 1;
    {
        uint64_t s = 7;
        for (int e = 0; e < 32; e++) {
            uint8_t w[128], v[128], x[N1], z[128];
            for (int i = 0; i < 128; i++) w[i] = (uint8_t)sm64(&s);
            int R = 1 + e % 8;
            memcpy(v, w, 128);
            perm1(v, R);
            perm_inv(v, R);
            okinv &= !memcmp(v, w, 128);
            deballer_ref(w, x);
            for (int r = R - 1; r >= 0; r--) ref_tour_inv(x, r);
            emballer_ref(x, z);
            memcpy(v, w, 128);
            perm_inv(v, R);
            okinv &= !memcmp(v, z, 128);
        }
    }
    printf("inverse rapide ≡ ref_tour_inv et inverse de perm1 : %s\n", okinv ? "oui" : "NON");
    ok_global &= okinv;
    fprintf(J, "{\n  \"programme\": \"stats1024\",\n  \"taille_octets\": %zu,\n  \"inverse_rapide_conforme\": %s,\n", T,
            okinv ? "true" : "false");
    uint8_t *b = malloc(T);
    /* témoins : flux de référence (doit passer), flux biaisés (doivent échouer) */
    {
        size_t n = T / 4;
        uint64_t s = 99;
        for (size_t i = 0; i < n / 8; i++) { uint64_t v = sm64(&s); memcpy(b + 8 * i, &v, 8); }
        flux_t f = {.nom = "splitmix64"};
        tests_flux(&f, b, n, 1);
        verdict_t v = juger(&f);
        printf("témoin splitmix64 : pmin %.3g (%s), Bonferroni %.3g, KS %.3g → %s\n", v.pmin, v.pire, v.bonf, v.ks,
               v.ok ? "passe" : "ÉCHOUE");
        int okt = v.ok;
        for (size_t i = 0; i < n; i += 64) b[i] |= 1;           /* un bit sur 512 forcé à 1 */
        flux_t g = {.nom = "biais"};
        tests_flux(&g, b, n, 1);
        verdict_t vb = juger(&g);
        printf("témoin biaisé (1 bit sur 512 forcé) : pmin %.3g (%s) → %s\n", vb.pmin, vb.pire, vb.ok ? "PASSE" : "échoue");
        s = 99;
        for (size_t i = 0; i < n / 8; i++) { uint64_t u = sm64(&s); memcpy(b + 8 * i, &u, 8); }
        for (size_t i = 0; i + 4 < n; i += 97) b[i + 4] = (uint8_t)((b[i + 4] & 0xFE) | (b[i] & 1));  /* corrélation à 32 bits */
        flux_t h = {.nom = "correlation"};
        tests_flux(&h, b, n, 1);
        verdict_t vc = juger(&h);
        printf("témoin corrélé (bit i+32 = bit i, 1 octet sur 97) : pmin %.3g (%s) → %s\n", vc.pmin, vc.pire,
               vc.ok ? "PASSE" : "échoue");
        okt &= !vb.ok && !vc.ok;
        ok_global &= okt;
        fprintf(J, "  \"temoins_conformes\": %s,\n", okt ? "true" : "false");
    }
    fflush(stdout);
    /* flux */
    fprintf(J, "  \"flux\": [\n");
    int premier_flux = 1, portee = 0;
    const int RS[] = {32, 1, 2, 3, 4, 5, 6, 8};
    for (int t = 0; t < 9; t++) {
        flux_t f = {0};
        char nom[64];
        size_t n = t == 0 ? T : T / 4;
        if (t < 8) {
            flux_compteur(b, n, RS[t], 0xC0B7E0 + (uint64_t)RS[t]);
            snprintf(nom, sizeof nom, "compteur_R%d", RS[t]);
        } else {
            for (int q = 0; q < 4; q++) {
                uint8_t msg[16] = "BRUME-1024q XOF";
                msg[15] = (uint8_t)q;
                eponge(msg, 16, DOM_SEQ, b + q * (n / 4), n / 4);
            }
            snprintf(nom, sizeof nom, "xof_eponge_R32");
        }
        f.nom = nom;
        tests_flux(&f, b, n, t < 8);
        verdict_t v = juger(&f);
        if (t < 8 && !v.ok && RS[t] < 32 && RS[t] > portee) portee = RS[t];
        if (t == 0 || t == 8) ok_global &= v.ok;
        printf("%-16s %5zu Mio : %2d tests, pmin %.3g (%s), Bonferroni %.3g, KS %.3g → %s  [%.0f s]\n", nom, n >> 20, f.np,
               v.pmin, v.pire, v.bonf, v.ks, v.ok ? "indistinguable" : "DISTINGUÉ", omp_get_wtime() - t0);
        fflush(stdout);
        fprintf(J, "%s    {\"nom\": \"%s\", \"octets\": %zu, \"p_min\": %.4g, \"pire_test\": \"%s\", \"bonferroni\": %.4g, "
                "\"ks\": %.4g, \"indistinguable\": %s, \"p\": {", premier_flux ? "" : ",\n", nom, n, v.pmin, v.pire, v.bonf, v.ks,
                v.ok ? "true" : "false");
        for (int i = 0; i < f.np; i++)
            fprintf(J, "%s\"%s\": %.4g", i ? ", " : "", f.ptest[i], f.p[i]);
        fprintf(J, "}}");
        premier_flux = 0;
    }
    fprintf(J, "\n  ],\n  \"dernier_tour_distingue_par_les_flux\": %d,\n  \"sac\": {\n", portee);
    free(b);
    /* SAC */
    for (int sens = 0; sens < 2; sens++) {
        const int lg = sens ? 14 : 16;
        int premier = 0;
        fprintf(J, "    \"%s\": {\"echantillons_par_entree\": %d, \"par_tour\": {", sens ? "inverse" : "direct", 1 << lg);
        for (int R = 1; R <= 12; R++) {
            sac_t s = sac(R, lg, sens, 0x5AC0 + 100 * R + sens);
            printf("SAC %s R=%d (2^%d) : max|z| %.2f (p %.3g), z_χ² %.2f, pire case %.4f → %s  [%.0f s]\n",
                   sens ? "inverse" : "direct", R, lg, s.zmax, s.pmax, s.zchi2, s.pire, s.ok ? "indistinguable" : "distingué",
                   omp_get_wtime() - t0);
            fflush(stdout);
            fprintf(J, "%s\"%d\": {\"z_max\": %.2f, \"p_max\": %.3g, \"z_chi2\": %.2f, \"pire_case\": %.4f}", R > 1 ? ", " : "",
                    R, s.zmax, s.pmax, s.zchi2, s.pire);
            if (s.ok) { premier = R; break; }
        }
        sac_t s32 = sac(32, lg - 2, sens, 0x5AC32 + sens);
        printf("SAC %s R=32 (2^%d) : max|z| %.2f (p %.3g), z_χ² %.2f → %s\n", sens ? "inverse" : "direct", lg - 2, s32.zmax,
               s32.pmax, s32.zchi2, s32.ok ? "indistinguable" : "DISTINGUÉ");
        ok_global &= s32.ok && premier > 0;
        fprintf(J, "}, \"premier_tour_indistinguable\": %d, \"32_tours\": {\"echantillons_par_entree\": %d, \"z_max\": %.2f, "
                "\"p_max\": %.3g, \"z_chi2\": %.2f, \"indistinguable\": %s}}%s\n", premier, 1 << (lg - 2), s32.zmax, s32.pmax,
                s32.zchi2, s32.ok ? "true" : "false", sens ? "" : ",");
    }
    fprintf(J, "  },\n  \"duree_s\": %.0f,\n  \"verdict\": \"%s\"\n}\n", omp_get_wtime() - t0, ok_global ? "conforme" : "ECHEC");
    fclose(J);
    printf("verdict : %s (%.0f s)\n", ok_global ? "conforme" : "ÉCHEC", omp_get_wtime() - t0);
    return ok_global ? 0 : 1;
}
