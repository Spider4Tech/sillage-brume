/* Plus petit chiffré du KEM à garantie égale : pour (D, w, θ), plus petit n d'Artin tel que
 *   - tous les coûts d'attaque restent au moins ceux de la v0.3 (PROOFS § 5, mêmes formules que security_estimate) ;
 *   - la borne δ PROUVÉE (kem.c, sur de vraies clés) respecte le critère :
 *       A : au plus 5 % des clés au-delà de 2^-(λ+8) (critère de choix actuel, test_isd_parametres) ;
 *       B : au plus 10 % des clés rejetées par keygen, seuil 2^-λ (δ reste prouvé clé par clé).
 * Rien ne descend sous les marges actuelles. kem_var.c est kem.c avec une table P modifiable (Makefile).
 *     build/compression_kem   (depuis la racine) → resultats/compression_kem.json
 */
#include <float.h>
#include <math.h>

#include "kem_var.c"
#include "resultat.h"

static const struct { double cle, q; int nref, wref, Dref, weref; } REF[2] = {
    {137.3, 91.1, 50021, 75, 14, 25},
    {264.9, 158.0, 170003, 140, 28, 64},
};

static int artin(uint32_t n)
{
    if (n < 3 || !(n & 1))
        return 0;
    for (uint32_t d = 3; d * d <= n; d += 2)
        if (n % d == 0)
            return 0;
    uint32_t m = n - 1, f = 2;                       /* 2 générateur : 2^((n−1)/q) ≠ 1 pour tout q premier */
    for (; m > 1; f++) {
        if (m % f)
            continue;
        while (m % f == 0)
            m /= f;
        uint64_t r = 1, b = 2;
        for (uint32_t e = (n - 1) / f; e; e >>= 1, b = b * b % n)
            if (e & 1)
                r = r * b % n;
        if (r == 1)
            return 0;
    }
    return 1;
}

typedef struct { double cle, msg, q; uint32_t we; } secu_t;

static double classique(int n, int k, int w, double *pr)
{
    double o[6], t;
    *pr = sl_isd_prange(n, k, w);
    t = sl_isd_deux_listes(n, k, w, 0, 400, 1000, -1.0, o);
    double m = t < *pr ? t : *pr;
    t = sl_isd_deux_listes(n, k, w, 1, 400, 1000, -1.0, o);
    m = t < m ? t : m;
    t = sl_isd_bjmm(n, k, w, 400, 100, 1500, o);
    return t < m ? t : m;
}

static double msg3(uint32_t n, uint32_t n2, uint32_t w, uint32_t we, double gain)
{
    double nb[3] = {n, n, n2}, tb[3] = {w, w, 2.0 * we}, lo = 1e-9, hi = 1e9;
    for (int i = 0; i < 200; i++) {
        double lm = sqrt(lo * hi), pris = 0;
        for (int b = 0; b < 3; b++)
            pris += nb[b] * (1 - fmin(1.0, lm * tb[b] / nb[b]));
        if (pris > n) lo = lm; else hi = lm;
    }
    double it = 0;
    for (int b = 0; b < 3; b++)
        it -= tb[b] * log2(fmin(1.0, hi * tb[b] / nb[b]));
    return it + log2(3.0 * n * n) - gain - log2(n) / 2;
}

/* we : le plus petit qui garde l'attaque à 3 blocs au niveau de la v0.3 (redonne 25 et 64) */
static secu_t securite(int niv, uint32_t n, uint32_t n2, uint32_t w)
{
    double pr, c = classique(2 * (int)n, (int)n, 2 * (int)w, &pr), g = log2(2.0 * n * n);
    secu_t s = {c - log2(n), c - log2(n) / 2, (pr - g) / 2 + g - log2(n), 1};
    while (s.we < 400 && msg3(n, n2, w, s.we, pr - c) < REF[niv].cle)
        s.we++;
    s.msg = fmin(s.msg, msg3(n, n2, w, s.we, pr - c));
    return s;
}

static int cmp(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void regler(int niv, uint32_t n, uint32_t D, uint32_t w, uint32_t we, double th)
{
    params_t *p = &P[niv];
    p->n = n; p->D = D; p->w = w; p->we = we; p->theta = th;
    p->n2 = (p->k / 8) * 128 * D;
#pragma omp parallel
    {
        if (code_rm[niv].Q) {                        /* cache de code par thread : D a pu changer */
            free(code_rm[niv].Q);
            for (int t = 0; t < 8; t++)
                free(code_rm[niv].lignes[t]);
            code_rm[niv].Q = NULL;
        }
    }
}

/* log2 δ de nb clés, triés */
static void bornes(int niv, int nb, double *v)
{
    const params_t *p = &P[niv];
#pragma omp parallel for schedule(dynamic)
    for (int i = 0; i < nb; i++) {
        uint64_t *x = nouveau(p->n), *y = nouveau(p->n);
        uint32_t *pos = malloc(4 * p->w);
        uint8_t g[32];
        if (sl_alea(g, 32)) abort();
        sl_creux(g, 32, (int)p->w, p->n, "eph", pos);
        poser_ct(x, NW(p->n), pos, (int)p->w);
        if (sl_alea(g, 32)) abort();
        sl_creux(g, 32, (int)p->w, p->n, "eph", pos);
        poser_ct(y, NW(p->n), pos, (int)p->w);
        v[i] = borne(niv, x, y);
        free(x); free(y); free(pos);
    }
    qsort(v, (size_t)nb, sizeof *v, cmp);
}

static double fraction_au_dela(const double *v, int nb, double seuil)
{
    int c = 0;
    for (int i = 0; i < nb; i++)
        c += v[i] > seuil;
    return (double)c / nb;
}

/* crit : 0 = A, 1 = B */
static int admissible(int niv, uint32_t n, uint32_t D, uint32_t w, double th, int crit, int nb, double *med, double *rej, secu_t *ps)
{
    uint32_t n2 = (P[niv].k / 8) * 128 * D, lam = P[niv].lam;
    if (n2 > n)
        return 0;
    secu_t s = securite(niv, n, n2, w);
    if (ps) *ps = s;
    if (s.cle < REF[niv].cle || s.msg < REF[niv].cle || s.q < REF[niv].q)
        return 0;
    double v[1024];
    regler(niv, n, D, w, s.we, th);
    bornes(niv, nb, v);
    double a = fraction_au_dela(v, nb, -(double)lam - 8), b = fraction_au_dela(v, nb, -(double)lam);
    if (med) *med = v[nb / 2];
    if (rej) *rej = b;
    return crit == 0 ? a <= 0.05 : b <= 0.10;
}

int main(void)
{
    resultat_t r = {.nom = "compression_kem"};
    sl_init();
    static char json[20000];
    size_t lj = 0;
    lj += (size_t)snprintf(json + lj, sizeof json - lj, "[");
    for (int niv = 0; niv < 2; niv++) {
        const uint32_t lam = P[niv].lam, nref = (uint32_t)REF[niv].nref, wref = (uint32_t)REF[niv].wref, Dref = (uint32_t)REF[niv].Dref;
        double med, rej;
        secu_t s;
        int kf = niv ? 300 : 1000, kr = niv ? 40 : 120;
        admissible(niv, nref, Dref, wref, 0.7, 1, kf, &med, &rej, &s);
        size_t ctref = NB(nref) + NB((P[niv].k / 8) * 128 * Dref);
        printf("== profil %u : actuel n=%u w=%u D=%u we=%u : sécurité %.1f q %.1f, δ médian %.1f, rejet %.1f %%, ct %zu\n", lam, nref, wref, Dref, s.we, fmin(s.cle, s.msg), s.q, med, 100 * rej, ctref);
        res_controle(&r, niv ? "reproduit_sillage_256" : "reproduit_sillage_128",
                     fabs(fmin(s.cle, s.msg) - (niv ? 265.1 : 138.2)) < 0.2 && fabs(med - (niv ? -289.3 : -145.8)) < 3 && s.we == (uint32_t)REF[niv].weref);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"profil\":%u,\"ct_actuel\":%zu,\"delta_median\":%.1f,\"rejet\":%.3f,\"variantes\":[", niv ? "," : "", lam, ctref, med, rej);
        size_t meilleur[2] = {ctref, ctref};
        int prem = 1;
        static const double TH[] = {0.5, 0.6, 0.7, 0.8, 0.9};
        for (int crit = 0; crit < 2; crit++)
            for (uint32_t D = Dref; D + (niv ? 8 : 4) >= Dref && D >= 8; D -= niv ? 2 : 1)
                for (uint32_t w = wref; w <= wref + (niv ? 16 : 8); w += niv ? 4 : 2)
                    for (int t = 0; t < 5; t++) {
                        double th = TH[t];
                        uint32_t lo = (P[niv].k / 8) * 128 * D, hi = nref + nref / 8;
                        if (!admissible(niv, hi, D, w, th, crit, kr, NULL, NULL, NULL))
                            continue;
                        while (hi - lo > nref / 200) {
                            uint32_t m = lo + (hi - lo) / 2;
                            if (admissible(niv, m, D, w, th, crit, kr, NULL, NULL, NULL)) hi = m; else lo = m;
                        }
                        uint32_t n = hi | 1;
                        while (!artin(n)) n += 2;
                        for (int essais = 0; essais < 40 && !admissible(niv, n, D, w, th, crit, kf, &med, &rej, &s); essais++) {
                            n += nref / 400;
                            n |= 1;
                            while (!artin(n)) n += 2;
                        }
                        if (!admissible(niv, n, D, w, th, crit, kf, &med, &rej, &s))
                            continue;
                        size_t ct = NB(n) + NB((P[niv].k / 8) * 128 * D);
                        if (ct < meilleur[crit]) {
                            meilleur[crit] = ct;
                            printf("crit %c D=%u w=%u θ=%.1f : n=%u we=%u ct=%zu (%+.1f %%) pk≈%u sécurité %.1f q %.1f δ médian %.1f rejet %.1f %%\n", 'A' + crit, D, w, th, n, s.we, ct,
                                   100.0 * ((double)ct - (double)ctref) / (double)ctref, (uint32_t)NB(n) + 32, fmin(s.cle, s.msg), s.q, med, 100 * rej);
                            fflush(stdout);
                            lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"critere\":\"%c\",\"D\":%u,\"w\":%u,\"theta\":%.1f,\"n\":%u,\"we\":%u,\"ct\":%zu,\"cle\":%.1f,\"q\":%.1f,\"delta_median\":%.1f,\"rejet\":%.3f}",
                                                   prem ? "" : ",", 'A' + crit, D, w, th, n, s.we, ct, s.cle, s.q, med, rej);
                            prem = 0;
                        }
                    }
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "],\"meilleur_A\":%zu,\"meilleur_B\":%zu}", meilleur[0], meilleur[1]);
        printf("meilleur : A %zu o, B %zu o (actuel %zu)\n", meilleur[0], meilleur[1], ctref);
        fflush(stdout);
    }
    lj += (size_t)snprintf(json + lj, sizeof json - lj, "]");
    res_mesure(&r, "profils", "%s", json);
    return res_ecrire(&r);
}
