/* Second, independent implementation (C) of the definitions of SPONGE_QROM.md § 2, and a stronger check
 * of Lemma A than the counts of eponge_domaines.py: for every database h outside the property and every
 * free pair (x, y), if h[x -> y] is in the property then (x, y) lies in the set that the proof of § 3
 * predicts (cases a, b, c and the inverse case). The numeric bounds follow from that containment.
 *
 *   exhaustif r c d racine d1 d2 d3 tmax_exhaustif n_alea tmax_alea
 *
 * All databases of size <= tmax_exhaustif are enumerated; n_alea databases of size <= tmax_alea, built to
 * load the counts, are added. Domains {0, d1, d2, d3} (capacity offsets). Exit code 0 if no exception.
 * Build: cc -O2 -o exhaustif exhaustif.c   (with -DTEMOIN the predicted set omits D + D: the run must fail)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static int R, C, DG, B, N, NC, ROOT, K = 4, DOM[4], KPM, DPM[16];
static int fwd[1024];            /* fwd[x] = y or -1 */
static unsigned char imu[1024];  /* y used */
static int srcx[64], nsrc;       /* list of x in the database */
static uint64_t etat = 0x9E3779B97F4A7C15ULL;
static uint64_t alea(void) { etat ^= etat << 13; etat ^= etat >> 7; etat ^= etat << 17; return etat; }

#define CAP(s) ((s) & (NC - 1))
#define DIG(s) (((s) >> C) >> (R - DG))

static unsigned char rs[256];    /* reachable capacities */
static void atteignables(void) {
    int change = 1;
    memset(rs, 0, NC); rs[ROOT] = 1;
    while (change) {
        change = 0;
        for (int i = 0; i < nsrc; i++) {
            int x = srcx[i], y = fwd[x];
            if (rs[CAP(x)] && !rs[CAP(y)]) { rs[CAP(y)] = 1; change = 1; }
        }
    }
}
static int est_i1(void) {
    unsigned char fin[256]; memset(fin, 0, NC);
    for (int i = 0; i < nsrc; i++) {
        int x = srcx[i];
        if (!rs[CAP(x)]) continue;
        int v = CAP(fwd[x]);
        if (v == ROOT || fin[v]) return 1;
        fin[v] = 1;
    }
    return 0;
}
static int est_i2(void) {
    for (int u = 0; u < NC; u++) if (rs[u])
        for (int j = 0; j < KPM; j++) if (DPM[j] && rs[u ^ DPM[j]]) return 1;
    return 0;
}
static int est_finale(int x) { for (int j = 0; j < K; j++) if (rs[CAP(x) ^ DOM[j]]) return 1; return 0; }
/* bits: 1 = B_col ; 2 << w = B_pre(w), w < 2^DG <= 8 */
static unsigned proprietes(void) {
    unsigned res = 0, vus = 0;
    atteignables();
    int a = est_i1();
    if (a) return ~0u;
    if (est_i2()) res |= 1;
    for (int i = 0; i < nsrc; i++) {
        int x = srcx[i];
        if (!est_finale(x)) continue;
        unsigned g = DIG(fwd[x]);
        if (vus >> g & 1) res |= 1;
        vus |= 1u << g;
        res |= 2u << g;
    }
    return res;
}
static void ajoute(int x, int y) { fwd[x] = y; imu[y] = 1; srcx[nsrc++] = x; }
static void retire(void) { int x = srcx[--nsrc]; imu[fwd[x]] = 0; fwd[x] = -1; }

static long n_bases, n_paires, n_mauvaises, exceptions, atteinte;
static double pire_col, pire_pre;

static void controle_base(void) {
    unsigned p0 = proprietes();
    int t = nsrc, nw = 1 << DG;
    unsigned char rs0[256], rd[256], ecol[256], epre[256];
    unsigned digf = 0;
    n_bases++;
    if (p0 == ~0u) return;
    memcpy(rs0, rs, NC);
    memset(rd, 0, NC); memset(ecol, 0, NC); memset(epre, 0, NC);
    for (int u = 0; u < NC; u++) if (rs0[u]) {
        for (int j = 0; j < K; j++) rd[u ^ DOM[j]] = 1;          /* Reach + D */
#ifdef TEMOIN   /* negative witness: the proof without the event I2 in the excluded set; must fail */
        for (int j = 0; j < K; j++) ecol[u ^ DOM[j]] = 1;
#else
        for (int j = 0; j < KPM; j++) ecol[u ^ DPM[j]] = 1;      /* Reach + (D + D) */
#endif
        epre[u] = 1;
    }
    for (int i = 0; i < t; i++) {
        int x = srcx[i];
        for (int j = 0; j < K; j++) { ecol[CAP(x) ^ DOM[j]] = 1; epre[CAP(x) ^ DOM[j]] = 1; }
        int fin = 0; for (int j = 0; j < K; j++) fin |= rs0[CAP(x) ^ DOM[j]];
        if (fin) digf |= 1u << DIG(fwd[x]);
    }
    long bcol = (long)t * (1L << (B - DG)) + ((long)KPM * (t + 1) + (long)K * t) * (1L << R);
    long kp = (long)(K + 1) * t + K;
    long bpre = (1L << (B - DG)) + kp * (1L << R);
    static long cx[1024][9], cy[1024][9];
    for (int i = 0; i < N; i++) for (int j = 0; j <= nw; j++) cx[i][j] = cy[i][j] = 0;
    for (int x = 0; x < N; x++) {
        if (fwd[x] >= 0) continue;
        int xc = CAP(x);
        for (int y = 0; y < N; y++) {
            if (imu[y]) continue;
            ajoute(x, y);
            unsigned p1 = proprietes();
            retire();
            n_paires++;
            unsigned neuf = p1 & ~p0;
            if (!neuf) continue;
            n_mauvaises++;
            if ((neuf & 1)) {                                   /* B_col */
                int prevu = 0;
                if (rd[xc]) {
                    if (digf >> DIG(y) & 1) prevu = 1;                       /* cases b and c: digest */
                    if (rs0[xc] && ecol[CAP(y)]) prevu = 1;                 /* case c: excluded capacity */
                }
                if (!prevu) exceptions++;
                cx[x][0]++; cy[y][0]++;
            }
            for (int w = 0; w < nw; w++) if (neuf >> (w + 1) & 1) {         /* B_pre(w) */
                int prevu = 0;
                if (rd[xc]) {
                    if ((int)DIG(y) == w) prevu = 1;
                    if (rs0[xc] && epre[CAP(y)]) prevu = 1;
                }
                if (!prevu) exceptions++;
                cx[x][w + 1]++; cy[y][w + 1]++;
            }
        }
    }
    for (int i = 0; i < N; i++) {
        long m = cx[i][0] > cy[i][0] ? cx[i][0] : cy[i][0];
        if (!(p0 & 1)) {
            if (m > bcol) exceptions++;
            if (m == bcol) atteinte++;
            if ((double)m / bcol > pire_col) pire_col = (double)m / bcol;
        }
        for (int w = 0; w < nw; w++) if (!(p0 >> (w + 1) & 1)) {
            long mp = cx[i][w + 1] > cy[i][w + 1] ? cx[i][w + 1] : cy[i][w + 1];
            if (mp > bpre) exceptions++;
            if ((double)mp / bpre > pire_pre) pire_pre = (double)mp / bpre;
        }
    }
}
static void enumere(int reste, int xmin) {
    controle_base();
    if (!reste) return;
    for (int x = xmin; x < N; x++)
        for (int y = 0; y < N; y++) if (!imu[y]) { ajoute(x, y); enumere(reste - 1, x + 1); retire(); }
}
/* number of databases of size exactly t: C(N, t) * N!/(N-t)! ; enumere() visits each once (x increasing) */
static double attendu(int tmax) {
    double tot = 0, c = 1, a = 1;
    for (int t = 0; t <= tmax; t++) { tot += c * a; c = c * (N - t) / (t + 1); a *= (N - t); }
    return tot;
}
int main(int argc, char **argv) {
    if (argc != 11) { fprintf(stderr, "usage: exhaustif r c d racine d1 d2 d3 tmax_exhaustif n_alea tmax_alea\n"); return 2; }
    R = atoi(argv[1]); C = atoi(argv[2]); DG = atoi(argv[3]); ROOT = (int)strtol(argv[4], 0, 0);
    DOM[0] = 0; for (int j = 1; j < 4; j++) DOM[j] = (int)strtol(argv[4 + j], 0, 0);
    int tex = atoi(argv[8]); long nal = atol(argv[9]); int tal = atoi(argv[10]);
    B = R + C; N = 1 << B; NC = 1 << C;
    if (N > 1024 || NC > 256 || DG > 3 || DG > R || tal > 60) { fprintf(stderr, "sizes too large\n"); return 2; }
    for (int a = 0; a < 4; a++) for (int b = 0; b < 4; b++) {
        int e = DOM[a] ^ DOM[b], vu = 0;
        for (int j = 0; j < KPM; j++) vu |= DPM[j] == e;
        if (!vu) DPM[KPM++] = e;
    }
    memset(fwd, -1, sizeof fwd);
    printf("r = %d, c = %d, d = %d, N = %d, racine %#x, domaines {0, %#x, %#x, %#x}, |D+D| = %d\n",
           R, C, DG, N, ROOT, DOM[1], DOM[2], DOM[3], KPM);
    enumere(tex, 0);
    double att = attendu(tex);
    printf("  exhaustif jusqu'a la taille %d : %ld bases (attendu %.0f), %ld paires essayees, %ld mauvaises\n",
           tex, n_bases, att, n_paires, n_mauvaises);
    if ((double)n_bases != att) exceptions++;
    long avant = n_bases;
    for (long e = 0; e < nal; e++) {
        int t = tex + 1 + (int)(alea() % (unsigned)(tal - tex)), essais = 0;
        while (nsrc < t && essais++ < 400) {
            int xc, yc, m = (int)(alea() % 100);
            atteignables();
            int u; do u = (int)(alea() % NC); while (!rs[u]);
            if (m < 55) xc = u; else if (m < 85) xc = u ^ DOM[alea() % 4]; else xc = (int)(alea() % NC);
            int x = (int)((alea() % (1u << R)) << C) | xc;
            if (nsrc == 0 && alea() % 10 < 7) x = ROOT;
            m = (int)(alea() % 100);
            if (m < 25 && nsrc) yc = CAP(srcx[alea() % nsrc]) ^ DOM[alea() % 4]; else yc = (int)(alea() % NC);
            int y = (int)((alea() % (1u << R)) << C) | yc;
            if (fwd[x] < 0 && !imu[y]) ajoute(x, y);
        }
        controle_base();
        while (nsrc) retire();
    }
    printf("  aleatoire, tailles %d a %d : %ld bases ; total %ld paires, %ld mauvaises\n",
           tex + 1, tal, n_bases - avant, n_paires, n_mauvaises);
    printf("  pire rapport compte/borne : collision %.3f, preimage %.3f ; borne collision atteinte %ld fois\n",
           pire_col, pire_pre, atteinte);
    printf("  exceptions : %ld\n%s\n", exceptions, exceptions ? "ECHEC" : "TOUT PASSE");
    return exceptions != 0;
}
