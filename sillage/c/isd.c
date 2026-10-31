/* SILLAGE C — estimateur ISD (log2 du coût), miroir de sillage/sillage_common.py :
 * mêmes formules, mêmes parcours, mêmes critères d'arrêt (tests/test_api_c.py compare
 * les deux). Aucune donnée secrète ici. */
#include <math.h>

#include "sillage.h"

static double lg(double x)
{
    int s;
    return lgamma_r(x, &s);
}

static double lb(double n, double k)
{
    if (k < 0 || k > n)
        return -INFINITY;
    return (lg(n + 1) - lg(k + 1) - lg(n - k + 1)) / M_LN2;
}

static double add2(double a, double b)
{
    double m = a > b ? a : b;
    return m + log2(pow(2, a - m) + pow(2, b - m));
}

static double add3(double a, double b, double c)
{
    double m = a > b ? a : b;
    m = m > c ? m : c;
    return m + log2(pow(2, a - m) + pow(2, b - m) + pow(2, c - m));
}

static double gauss(int n, int k) { return log2((double)n * (n - k)); }

double sl_isd_prange(int n, int k, int w) { return lb(n, w) - lb(n - k, w) + gauss(n, k); }

/* o = {coût, p, l, log2 L} ; exposant_interne ≥ 0 : fusion par marche quantique */
double sl_isd_deux_listes(int n, int k, int w, int dumer, int p_max, int l_max, double exposant_interne, double *o)
{
    double g = gauss(n, k), cwn = lb(n, w), best = sl_isd_prange(n, k, w), local = INFINITY;
    int attente = 0, pm = p_max < w ? p_max : w;
    o[1] = o[2] = o[3] = 0;
    for (int p = 2; p <= pm; p += 2) {
        double ici = INFINITY;
        int lm = n - k - (w - p);
        lm = l_max < lm ? l_max : lm;
        for (int l = 0; l <= lm; l += 2) {
            double L = lb((dumer ? k + l : k) / 2.0, p / 2.0);
            double proba = 2 * L + lb(n - k - l, w - p) - cwn;
            double cout = exposant_interne >= 0 ? -proba / 2 + add2(g, exposant_interne * L)
                                                : add3(g, L + 1, 2 * L - l) - proba;
            ici = cout < ici ? cout : ici;
            if (cout < best) {
                best = cout;
                o[1] = p; o[2] = l; o[3] = L;
            }
        }
        attente = ici >= local ? attente + 1 : 0;
        local = ici < local ? ici : local;
        if (attente >= 8)
            break;
    }
    o[0] = best;
    return best;
}

/* o = {coût, p, ε, l, log2 L0, log2 L1} */
double sl_isd_bjmm(int n, int k, int w, int p_max, int e_max, int l_max, double *o)
{
    double t[4];
    double best = sl_isd_deux_listes(n, k, w, 1, 400, 1000, -1.0, t), g = gauss(n, k), cwn = lb(n, w), local = INFINITY;
    int attente = 0, pm = p_max < w ? p_max : w;
    o[1] = o[2] = o[3] = o[4] = o[5] = 0;
    for (int p = 2; p <= pm; p += 2) {
        double local_e = INFINITY, rp = lb(p, p / 2);
        int att_e = 0, lm = n - k - (w - p);
        lm = l_max < lm ? l_max : lm;
        for (int eps = 0; eps <= e_max; eps++) {
            int p1 = p / 2 + eps;
            double ici_e = INFINITY;
            for (int l = 2; l <= lm; l += 2) {
                double R = rp + lb(k + l - p, eps);
                double l1 = R > 0 ? R : 0;
                l1 = l1 < l ? l1 : l;
                double L0 = lb((k + l) / 2.0, p1 / 2.0), L1 = lb(k + l, p1) - l1;
                double cout = add3(g, L0 + 2, add2(2 * L0 - l1 + 1, 2 * L1 - (l - l1)))
                              - (lb(k + l, p) + lb(n - k - l, w - p) - cwn);
                ici_e = cout < ici_e ? cout : ici_e;
                if (cout < best) {
                    best = cout;
                    o[1] = p; o[2] = eps; o[3] = l; o[4] = L0; o[5] = L1;
                }
            }
            att_e = ici_e >= local_e ? att_e + 1 : 0;
            local_e = ici_e < local_e ? ici_e : local_e;
            if (att_e >= 4)
                break;
        }
        attente = local_e >= local ? attente + 1 : 0;
        local = local_e < local ? local_e : local;
        if (attente >= 8)
            break;
    }
    o[0] = best;
    return best;
}

double sl_isd_bjmm_quantique(int n, int k, int w, double exposant, double depart)
{
    double bj = depart, g = gauss(n, k), cwn = lb(n, w);
    int r = n - k, pm = 120 < w ? 120 : w;
    for (int p = 2; p <= pm; p += 2) {
        int lm = r - (w - p);
        lm = 600 < lm ? 600 : lm;
        for (int l = 0; l <= lm; l += 2) {
            double esp = lb(k + l, p), proba = esp + lb(r - l, w - p) - cwn;
            double c = -proba / 2 + add2(g, exposant * esp);
            bj = c < bj ? c : bj;
        }
    }
    return bj;
}
