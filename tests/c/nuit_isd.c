/* Campagne de nuit : attaques ISD réelles (Prange) sur des instances
 * réduites de plus en plus grandes, pour valider la formule de
 * l'estimateur sur une plage plus large que la batterie (qui s'arrête à
 * 2^12 itérations). Tailles croissantes, quasi-cycliques (KEM, n premier
 * d'Artin, 45 % du budget au plus) puis aléatoires (SIG) ; chaque taille n'est
 * lancée que si son coût, extrapolé de la précédente, tient dans le budget.
 * n = 280 aléatoire est mesuré sur 300 instances, pour trancher la dérive
 * observée le 2026-10-30 (ratios 1,07 / 1,17 / 1,22) ; l'écart cumulé par type
 * (z de Stouffer) la surveille. Gain quasi-cyclique (n syndromes décalés)
 * mesuré contre le crédit de log2 n de l'estimateur, sur des n plus grands.
 *     build/nuit_isd <budget_s>  → resultats/nuit_isd.{json,md}
 */
#define ISD_SANS_MAIN
#include "isd_reel.c"

#include <time.h>

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    double budget = argc > 1 ? atof(argv[1]) : 300, t0 = maintenant();
    resultat_t res = {.nom = "nuit_isd", .titre = "ISD réel à plus grande échelle (nuit)"};
    /* (type, n, r ou 0, w, instances) par coût croissant ; QC : n premier d'Artin */
    static const int L[][5] = {
        {0, 149, 0, 6, 150}, {0, 163, 0, 7, 120}, {0, 179, 0, 8, 120}, {0, 197, 0, 9, 60}, {0, 211, 0, 10, 40},
        {0, 227, 0, 11, 25}, {0, 251, 0, 12, 15},
        {1, 200, 100, 11, 150}, {1, 240, 120, 13, 120}, {1, 280, 140, 15, 300}, {1, 320, 160, 17, 60},
        {1, 360, 180, 19, 40}, {1, 400, 200, 21, 25}, {1, 440, 220, 23, 15}, {1, 480, 240, 25, 10},
    };
    int nl = (int)(sizeof L / sizeof *L), ok = 1, nmes = 0;
    char buf[8192] = "[";
    double somme_z[2] = {0, 0};
    int nb_z[2] = {0, 0};
    double dernier[2] = {0, 0}, pred_der[2] = {0, 0}, n_der[2] = {0, 0}, inst_der[2] = {0, 0};
    for (int k = 0; k < nl; k++) {
        int ty = L[k][0], n = L[k][1], r = L[k][2], w = L[k][3], inst = L[k][4];
        if (ty == 0 && !artin(n)) continue;
        double pred = ty == 0 ? log2_binom(2 * n, 2 * w) - log2_binom(n, 2 * w) : log2_binom(n, w) - log2_binom(r, w);
        double reste = (ty == 0 ? 0.45 : 0.85) * budget - (maintenant() - t0), est = 0;
        if (dernier[ty] > 0) {                          /* extrapolation : itérations × coût d'une élimination */
            double dim = ty == 0 ? n : r, dim0 = n_der[ty];
            est = dernier[ty] * pow(2.0, pred - pred_der[ty]) * pow(dim / dim0, 3) * inst / inst_der[ty];
        }
        if (est > reste) {
            snprintf(buf + strlen(buf), 300, "%s{\"type\": \"%s\", \"n\": %d, \"w\": %d, \"prevision_log2\": %.2f, "
                     "\"statut\": \"non lancé (≈ %.0f s estimés, %.0f s restants)\"}", nmes ? ", " : "",
                     ty ? "aleatoire" : "qc", n, w, pred, est, reste);
            nmes++;
            continue;
        }
        double ts = maintenant();
        stat_t s = ty == 0 ? mesure_qc(n, w, 1, inst, 20000u + 1000u * (uint64_t)k)
                           : mesure_aleatoire(n, r, w, inst, 40000u + 1000u * (uint64_t)k);
        double d = maintenant() - ts;
        dernier[ty] = d; pred_der[ty] = pred; n_der[ty] = ty == 0 ? n : r; inst_der[ty] = inst;
        /* intervalle à ±3σ pour une moyenne de géométriques : ratio ∈ 1 ± 3/√inst */
        double tol = 3.0 / sqrt((double)inst);
        int bon = fabs(s.ratio - 1) <= tol + 0.05;
        ok &= bon;
        somme_z[ty] += (s.ratio - 1) * sqrt((double)inst);
        nb_z[ty]++;
        snprintf(buf + strlen(buf), 400, "%s{\"type\": \"%s\", \"n\": %d, \"r\": %d, \"w\": %d, \"instances\": %d, "
                 "\"iterations_log2\": %.2f, \"prevision_log2\": %.2f, \"ratio\": %.3f, \"tolerance\": %.3f, \"duree_s\": %.0f}",
                 nmes ? ", " : "", ty ? "aleatoire" : "qc", n, ty ? r : n, w, inst, log2(s.moy), pred, s.ratio, tol + 0.05, d);
        nmes++;
        fprintf(stderr, "%s n=%d w=%d : mesuré 2^%.2f, prévu 2^%.2f (ratio %.3f) en %.0f s\n", ty ? "aléatoire" : "QC",
                n, w, log2(s.moy), pred, s.ratio, d);
        resultat_t cp = res;
        char tmp[8300];
        snprintf(tmp, sizeof tmp, "%s]", buf);
        res_mesure(&cp, "tailles", "%s", tmp);
        res_ecrire(&cp);
    }
    strcat(buf, "]");
    res_mesure(&res, "tailles", "%s", buf);
    double zq = nb_z[0] ? somme_z[0] / sqrt(nb_z[0]) : 0, za = nb_z[1] ? somme_z[1] / sqrt(nb_z[1]) : 0;
    res_mesure(&res, "ecart_cumule_z", "{\"qc\": %.2f, \"aleatoire\": %.2f}", zq, za);
    res_controle(&res, "pas_de_derive_systematique_de_la_formule", fabs(zq) < 4 && fabs(za) < 4);
    /* gain quasi-cyclique : itérations pour 1 syndrome (formule validée) / pour n syndromes */
    char gq[1024] = "[";
    int ok_gain = 1, ng = 0;
    static const int G[][3] = {{149, 6, 200}, {163, 7, 200}, {179, 8, 150}, {197, 9, 100}};
    for (int k = 0; k < 4; k++) {
        int n = G[k][0], w = G[k][1], inst = G[k][2];
        double ts = maintenant();
        if (budget - (ts - t0) < 5) break;
        stat_t s = mesure_qc(n, w, n, inst, 60000u + 1000u * (uint64_t)k);
        double gain = log2(pow(2.0, s.pred_log2) / s.moy), credit = log2((double)n);
        ok_gain &= gain <= credit + 3.0 / sqrt((double)inst) * 1.5 + 0.1;
        snprintf(gq + strlen(gq), 160, "%s{\"n\": %d, \"w\": %d, \"instances\": %d, \"gain_log2\": %.2f, \"credit_log2\": %.2f, \"duree_s\": %.0f}",
                 ng ? ", " : "", n, w, inst, gain, credit, maintenant() - ts);
        ng++;
        fprintf(stderr, "gain QC n=%d : 2^%.2f pour un crédit de 2^%.2f\n", n, gain, credit);
    }
    strcat(gq, "]");
    res_mesure(&res, "gain_quasi_cyclique", "%s", gq);
    res_controle(&res, "gain_quasi_cyclique_ne_depasse_pas_le_credit", ok_gain && ng > 0);
    res_mesure(&res, "duree_s", "%.0f", maintenant() - t0);
    res_controle(&res, "cout_prange_conforme_a_la_formule_a_toutes_les_tailles", ok);
    return res_ecrire(&res);
}
