/* Sillage-KEM : le rejet des clés se voit-il dans la clé publique ? (plan GPU, attaque C4 ; PROOFS § 1, H1-P sur les
 * clés acceptées).
 *
 * sl_kem_keygen tire (x, y) de poids w et recommence tant que la borne δ prouvée dépasse 2^-λ (7,1 % et 5,9 % des tirages).
 * Le rejet dépend du secret seul ; la clé publique est s = x·h ⊕ y (h dérivé de σ_h, public). Si une statistique de s
 * séparait les clés acceptées des clés rejetées, la distribution des clés publiques réelles serait reconnaissable, et le
 * rejet fuirait de l'information sur (x, y). Le Lemme 0 règle le cas linéaire (la parité de s est le seul invariant
 * linéaire, et elle vaut w·(h(1) + 1) pour toutes les clés) : on teste ici des statistiques non linéaires de s.
 *
 * Méthode : K tirages exactement comme sl_kem_keygen (mêmes fonctions internes, h fixé), rejetés compris. Pour chaque
 * statistique f(s), z de Welch entre clés acceptées et rejetées ; seuil |z| > 4,5 (Bonferroni sur les statistiques et
 * les deux niveaux, faux positif < 10^-4).
 *   f1 = wt(s) ; f2 = #{i : s_i ≠ s_{i+1}} ; f3 = #{i : s_i ≠ s_{i+2}} ; f4 = #{i : s_i = s_{i+1} = s_{i+2} = 1} ;
 *   f5 = wt(s ∧ z^7 s) (indices cycliques modulo n).
 * Mesures d'accompagnement (pas des contrôles : elles sont vraies par construction) : l'écart de moyenne détectable au
 * seuil, en unités et en écarts-types d'une clé ; et l'écart de la borne log2 δ entre les classes, côté secret.
 *     make -C tests/c build/kem_rejet && tests/c/build/kem_rejet [K128 [K256]]   (depuis la racine)
 *         → resultats/kem_rejet.json */
#include <math.h>
#include <omp.h>

#include "kem.c"
#include "resultat.h"

#define NF 5
static const char *const NOMS_F[NF] = {"poids", "transitions_pas_1", "transitions_pas_2", "triplets_de_uns", "et_decale_7"};

typedef struct { double s[2][NF], s2[2][NF], b[2], b2[2]; long n[2]; } stats_t;

static void statistiques(const uint64_t *v, uint32_t n, double f[NF])
{
    uint8_t *t = sl_malloc(n + 7);
    for (uint32_t i = 0; i < n; i++) t[i] = (uint8_t)((v[i >> 6] >> (i & 63)) & 1);
    for (int k = 0; k < 7; k++) t[n + k] = t[k];
    long a = 0, b = 0, c = 0, d = 0, e = 0;
    for (uint32_t i = 0; i < n; i++) {
        a += t[i];
        b += t[i] != t[i + 1];
        c += t[i] != t[i + 2];
        d += t[i] & t[i + 1] & t[i + 2];
        e += t[i] & t[i + 7];
    }
    free(t);
    f[0] = (double)a, f[1] = (double)b, f[2] = (double)c, f[3] = (double)d, f[4] = (double)e;
}

static double welch(double s0, double q0, long n0, double s1, double q1, long n1)
{
    double m0 = s0 / n0, m1 = s1 / n1, v0 = (q0 - n0 * m0 * m0) / (n0 - 1), v1 = (q1 - n1 * m1 * m1) / (n1 - 1);
    return (m1 - m0) / sqrt(v0 / n0 + v1 / n1);
}

static void campagne(int niveau, long K, resultat_t *res, int *ok_global)
{
    const params_t *p = &P[niveau];
    uint8_t sigma_h[32];
    sl_alea(sigma_h, 32);
    construire_code(niveau);
    stats_t S;
    memset(&S, 0, sizeof S);
    int parite_ok = 1;
    int parite_ref = -1;
#pragma omp parallel
    {
        stats_t L;
        memset(&L, 0, sizeof L);
        const uint64_t *h;
        const uint32_t *pi;
        derives(niveau, sigma_h, &h, &pi);
        uint64_t *x = nouveau(p->n), *y = nouveau(p->n), *s = nouveau(p->n);
        uint32_t *px = sl_malloc(4 * p->w), *py = sl_malloc(4 * p->w);
        uint8_t g[32];
        int par = -1, par_ok = 1;
#pragma omp for schedule(dynamic, 64)
        for (long k = 0; k < K; k++) {
            memset(x, 0, (NW(p->n) + 4) * 8);
            memset(y, 0, (NW(p->n) + 4) * 8);
            memset(s, 0, (NW(p->n) + 4) * 8);
            sl_alea(g, 32); sl_creux(g, 32, (int)p->w, p->n, "eph", px);
            sl_alea(g, 32); sl_creux(g, 32, (int)p->w, p->n, "eph", py);
            poser_ct(x, NW(p->n), px, (int)p->w);
            poser_ct(y, NW(p->n), py, (int)p->w);
            double b = borne(niveau, x, y);
            int c = b > -(double)p->lam;          /* 1 = rejetée par sl_kem_keygen */
            mul_ct(x, h, p->n, s, p->n);
            poser_ct(s, NW(p->n), py, (int)p->w);
            double f[NF];
            statistiques(s, p->n, f);
            int pa = (int)f[0] & 1;
            if (par < 0) par = pa; else par_ok &= pa == par;
            for (int i = 0; i < NF; i++) L.s[c][i] += f[i], L.s2[c][i] += f[i] * f[i];
            L.b[c] += b, L.b2[c] += b * b;
            L.n[c]++;
        }
#pragma omp critical
        {
            for (int c = 0; c < 2; c++) {
                for (int i = 0; i < NF; i++) S.s[c][i] += L.s[c][i], S.s2[c][i] += L.s2[c][i];
                S.b[c] += L.b[c], S.b2[c] += L.b2[c], S.n[c] += L.n[c];
            }
            if (par >= 0) {
                if (parite_ref < 0) parite_ref = par;
                parite_ok &= par_ok && par == parite_ref;
            }
        }
        free(x); free(y); free(s); free(px); free(py);
    }
    const char *nom = niveau ? "256" : "128";
    char cle[128], json[2048];
    int lg = snprintf(json, sizeof json, "{\"cles\": %ld, \"rejetees\": %ld, \"taux_rejet\": %.4f, \"z\": {", K, S.n[1],
                      (double)S.n[1] / K);
    double zmax = 0;
    for (int i = 0; i < NF; i++) {
        double z = welch(S.s[0][i], S.s2[0][i], S.n[0], S.s[1][i], S.s2[1][i], S.n[1]);
        if (fabs(z) > zmax) zmax = fabs(z);
        lg += snprintf(json + lg, sizeof json - lg, "%s\"%s\": %.2f", i ? ", " : "", NOMS_F[i], z);
    }
    /* écart de moyenne détectable sur le poids (|z| = 4,5) */
    double n0 = (double)S.n[0], n1 = (double)S.n[1], m0 = S.s[0][0] / n0, v0 = (S.s2[0][0] - n0 * m0 * m0) / (n0 - 1);
    double m1 = S.s[1][0] / n1, v1 = (S.s2[1][0] - n1 * m1 * m1) / (n1 - 1);
    double et = sqrt(v0 / n0 + v1 / n1);
    (void)m1;
    /* côté secret : la borne elle-même */
    double zb = welch(S.b[0], S.b2[0], S.n[0], S.b[1], S.b2[1], S.n[1]);
    lg += snprintf(json + lg, sizeof json - lg, "}, \"z_max\": %.2f, \"ecart_detectable_sur_le_poids\": %.2f, "
                   "\"ecart_detectable_en_ecarts_types_d_une_cle\": %.4f, \"z_borne_log2_delta\": %.1f}",
                   zmax, 4.5 * et, 4.5 * et / sqrt(v0), zb);
    snprintf(cle, sizeof cle, "sillage_%s", nom);
    res_mesure(res, cle, "%s", json);
    snprintf(cle, sizeof cle, "%s_parite_de_s_identique_pour_toutes_les_cles", nom);
    res_controle(res, cle, parite_ok);
    snprintf(cle, sizeof cle, "%s_aucune_statistique_ne_separe_acceptees_et_rejetees", nom);
    res_controle(res, cle, zmax < 4.5);
    snprintf(cle, sizeof cle, "%s_taux_de_rejet_plausible", nom);
    res_controle(res, cle, S.n[1] > 0 && (double)S.n[1] / K < 0.2);
    *ok_global &= parite_ok;
}

int main(int argc, char **argv)
{
    long K0 = argc > 1 ? atol(argv[1]) : 32768, K1 = argc > 2 ? atol(argv[2]) : 8192;
    resultat_t res = {.nom = "kem_rejet", .titre = "Sillage-KEM : le rejet des clés ne se voit pas dans la clé publique"};
    int ok = 1;
    campagne(0, K0, &res, &ok);
    campagne(1, K1, &res, &ok);
    return res_ecrire(&res);
}
