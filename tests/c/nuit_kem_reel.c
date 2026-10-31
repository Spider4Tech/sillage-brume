/* Campagne de nuit : décodage du KEM réel à grande échelle.
 *
 * Pour des clés fraîches (validées par la borne de Chernoff de keygen),
 * on chiffre des messages μ CONNUS avec l'implémentation C réelle
 * (sl_kem_encaps_det), puis on recalcule v ⊕ (u·x)|_{n2} avec la clé
 * secrète. nv ⊕ cw(μ) est exactement le bruit : on mesure ses poids réels sur les
 * hyperplans du code RM(1,7), et non une simulation.
 *  - échecs : bruit ≥ 32·D sur un hyperplan d'au moins un bloc (seuil 448 / 896) ;
 *    attendu : aucun (δ ≤ 2^-λ prouvé pour chaque clé) ;
 *  - queue empirique : bascules maximales par chiffré et par groupe,
 *    comparées à la borne de Chernoff de la clé (log2 de la probabilité
 *    d'échec) et à la marge restante jusqu'au seuil ;
 *  - recoupement : un chiffré sur 64 est aussi décapsulé par sl_kem_decaps,
 *    qui doit rendre le même secret ;
 *  - rejet implicite (un chiffré sur 997) : un bit inversé, un chiffré
 *    aléatoire et un encodage non canonique doivent donner exactement
 *    H(σ_rej, chiffré réduit), de façon déterministe ;
 *  - borne de keygen recalculée sans sliding window (quelques clés), taux de
 *    rejet de keygen mesuré, et campagne dédiée sur la pire clé rencontrée
 *    (7 % du budget) : la borne la plus faible est la plus intéressante à viser.
 * Le contrôle « toutes les clés sous la borne » n'apporte que la confirmation
 * que keygen applique son filtre : la validation vient du recalcul naïf.
 * Sauvegarde périodique du JSON.
 *     build/nuit_kem_reel <budget_s>  → resultats/nuit_kem_reel.{json,md}
 */
#include <math.h>
#include <omp.h>
#include <time.h>

#include "kem.c"
#include "resultat.h"

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

/* borne de Chernoff de la clé, recalculée sans réutiliser fenetres() ni la
 * transformée de Walsh de kem.c : positions, appartenance directe à S, même θ. Sans la table
 * entière (arrondi vers le haut), elle est très légèrement inférieure à celle de keygen. */
static double borne_naive(int niv, const uint64_t *x, const uint64_t *y)
{
    const params_t *p = &P[niv];
    construire_code(niv);
    const uint8_t *Q = code_rm[niv].Q;
    uint32_t L = 128 * p->D, n = p->n, *pos[2];
    uint8_t *dans = calloc(n, 1);
    const uint64_t *vs[2] = {x, y};
    for (int v = 0; v < 2; v++) {
        pos[v] = malloc(4 * p->w);
        int k = 0;
        for (uint32_t i = 0; i < n; i++)
            if (vs[v][i >> 6] >> (i & 63) & 1)
                pos[v][k++] = i;
    }
    double pire = 0;
    for (int u = 1; u < 128; u++)
        for (int b = 0; b < 2; b++) {
            memset(dans, 0, L);
            for (uint32_t q = 0; q < L; q++)
                dans[q] = (uint8_t)((__builtin_popcount((unsigned)u & Q[q]) & 1) == b);
            double m[2];
            for (int v = 0; v < 2; v++) {
                double s = 0;
#pragma omp parallel for reduction(+ : s) schedule(static)
                for (uint32_t t = 0; t < n; t++) {
                    int c = 0;
                    for (uint32_t j = 0; j < p->w; j++) {
                        uint32_t q = t + pos[v][j];
                        q = q >= n ? q - n : q;
                        c += q < L && dans[q];
                    }
                    s += exp(p->theta * c);
                }
                m[v] = s / n;
            }
            if (m[0] * m[1] > pire)
                pire = m[0] * m[1];
        }
    free(pos[0]); free(pos[1]); free(dans);
    double S = 64.0 * p->D, th = p->theta;
    double f = -th * S / 2 + p->w * log(pire) + 2.0 * p->we * log1p(S / p->n2 * expm1(th));
    return (f + log(254.0 * (p->k / 8))) / log(2.0);
}

/* plus grand poids du bruit sur un hyperplan du bloc j */
static uint32_t bruit_bloc(int niv, const uint64_t *b)
{
    uint32_t L = 128 * P[niv].D;
    const uint8_t *Q = code_rm[niv].Q;
    int T[128] = {0};
    for (uint32_t q = 0; q < L; q++)
        T[Q[q]] += (int)(b[q >> 6] >> (q & 63) & 1);
    for (int h = 1; h < 128; h <<= 1)
        for (int i = 0; i < 128; i += 2 * h)
            for (int j = i; j < i + h; j++) {
                int a = T[j], c = T[j + h];
                T[j] = a + c;
                T[j + h] = a - c;
            }
    int mx = 0;
    for (int u = 1; u < 128; u++)
        if (abs(T[u]) > mx)
            mx = abs(T[u]);
    return (uint32_t)(T[0] + mx) / 2;
}

/* secret de rejet attendu : H(σ_rej, chiffré réduit) */
static void secret_rejet(const params_t *p, const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    size_t nb = NB(p->n), lct = nb + NB(p->n2);
    uint8_t *ctc = malloc(lct);
    memcpy(ctc, ct, lct);
    if (p->n & 7) ctc[nb - 1] &= (uint8_t)((1u << (p->n & 7)) - 1);
    if (p->n2 & 7) ctc[lct - 1] &= (uint8_t)((1u << (p->n2 & 7)) - 1);
    const uint8_t *parts[2] = {sk + 2 * nb + 32, ctc};
    size_t lens[2] = {32, lct};
    sl_shake_dom("SILLAGE-KEM|rej", NULL, 0, parts, lens, 2, ss, p->ss);
    free(ctc);
}

typedef struct {
    uint64_t chiffres, groupes, echecs, recoupes, recoupes_ko, cles;
    uint64_t rejets, rejets_ko, naives, naives_ko, tirages, tirages_rejetes;
    uint64_t pire_chiffres, pire_echecs;
    int pire_bascules;
    double ecart_naif_max, pire_borne_dediee;
    uint64_t hist_max[1024];        /* bascules maximales par chiffré */
    uint64_t hist_grp[1024];        /* bascules par groupe */
    double pire_borne, meilleure_borne;
} stats_t;

static void campagne(int niv, double budget, stats_t *st)
{
    const params_t *p = &P[niv];
    size_t lpk, lsk, lct, lss, nb = NB(p->n);
    sl_kem_tailles(niv, &lpk, &lsk, &lct, &lss);
    double t0 = maintenant();
    st->pire_borne = -1e9;
    st->meilleure_borne = 0;
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *pk_p = malloc(lpk), *sk_p = malloc(lsk);
    const int PAR_CLE = niv ? 4000 : 20000;
    /* taux de rejet de keygen : mêmes tirages que sl_kem_keygen */
    {
        uint64_t *x = nouveau(p->n), *y = nouveau(p->n);
        uint32_t *px = malloc(4 * p->w), *py = malloc(4 * p->w);
        uint8_t gr[32];
        for (int i = 0; i < (niv ? 200 : 1000); i++) {
            memset(x, 0, (NW(p->n) + 4) * 8); memset(y, 0, (NW(p->n) + 4) * 8);
            sl_alea(gr, 32); sl_creux(gr, 32, (int)p->w, p->n, "eph", px);
            sl_alea(gr, 32); sl_creux(gr, 32, (int)p->w, p->n, "eph", py);
            poser_ct(x, NW(p->n), px, (int)p->w);
            poser_ct(y, NW(p->n), py, (int)p->w);
            st->tirages++;
            st->tirages_rejetes += borne(niv, x, y) > -(double)p->lam;
        }
        free(x); free(y); free(px); free(py);
    }
    while (maintenant() - t0 < 0.93 * budget) {
        sl_kem_keygen(niv, pk, sk);
        st->cles++;
        uint64_t *x = nouveau(p->n), *y = nouveau(p->n);
        charger(x, sk, p->n);
        charger(y, sk + nb, p->n);
        double b = borne(niv, x, y);
        if (b > st->pire_borne) {
            st->pire_borne = b;
            memcpy(pk_p, pk, lpk); memcpy(sk_p, sk, lsk);
        }
        if (st->cles % 64 == 1) {                      /* recalcul indépendant */
            double bn = borne_naive(niv, x, y), e = fabs(bn - b);
            st->naives++;
            st->naives_ko += e > 0.5;                   /* arrondi de la table de keygen */
            if (e > st->ecart_naif_max) st->ecart_naif_max = e;
        }
        if (b < st->meilleure_borne) st->meilleure_borne = b;
        { uint8_t c0[1 << 16], s0[64], mu0[32] = {0}; sl_kem_encaps_det(niv, pk, mu0, c0, s0); }  /* cache h, π */
#pragma omp parallel
        {
            uint64_t *u = nouveau(p->n), *nv = nouveau(p->n2);
            uint8_t *ct = malloc(lct), *ctm = malloc(lct), mu[32], ss[64], ss2[64], ss3[64], att[64];
            alea_t g;
            alea_init(&g, (uint64_t)st->cles * 7919 + (uint64_t)omp_get_thread_num() * 104729 + (uint64_t)niv);
            uint64_t lc = 0, le = 0, lr = 0, lrk = 0, lj = 0, ljk = 0, hm[1024] = {0}, hg[1024] = {0};
#pragma omp for schedule(dynamic, 64)
            for (int k = 0; k < PAR_CLE; k++) {
                for (int i = 0; i < 32; i++) mu[i] = (uint8_t)alea64(&g);
                sl_kem_encaps_det(niv, pk, mu, ct, ss);
                memset(u, 0, (NW(p->n) + 4) * 8);
                memset(nv, 0, (NW(p->n2) + 4) * 8);
                charger(u, ct, p->n);
                charger(nv, ct + nb, p->n2);
                mul_ct(x, u, p->n, nv, p->n2);            /* nv = v ⊕ (u·x)|n2 */
                poser_mot(niv, mu, nv);                    /* nv = bruit */
                uint32_t mx = 0;
                for (uint32_t i = 0; i < p->k / 8; i++) {
                    uint32_t bruit = bruit_bloc(niv, nv + i * (128 * p->D / 64));
                    hg[bruit < 1024 ? bruit : 1023]++;
                    if (bruit > mx) mx = bruit;
                }
                hm[mx < 1024 ? mx : 1023]++;
                le += mx >= 32 * p->D;
                lc++;
                if (k % 64 == 0) {                         /* recoupement avec la décapsulation réelle */
                    sl_kem_decaps(niv, sk, ct, ss2);
                    lr++;
                    lrk += memcmp(ss, ss2, lss) != 0;
                }
                if (k % 997 == 0)                          /* rejet implicite */
                    for (int v = 0; v < 3; v++) {
                        memcpy(ctm, ct, lct);
                        if (v == 0)
                            ctm[alea64(&g) % lct] ^= (uint8_t)(1u << (alea64(&g) & 7));
                        else if (v == 1)
                            for (size_t q = 0; q < lct; q++) ctm[q] = (uint8_t)alea64(&g);
                        else
                            ctm[nb - 1] |= (uint8_t)(1u << (p->n & 7));   /* bit au-delà de n */
                        if (v == 1 && (p->n & 7))
                            ctm[nb - 1] &= (uint8_t)((1u << (p->n & 7)) - 1);
                        sl_kem_decaps(niv, sk, ctm, ss2);
                        sl_kem_decaps(niv, sk, ctm, ss3);
                        secret_rejet(p, sk, ctm, att);
                        lj++;
                        ljk += memcmp(ss2, att, lss) != 0 || memcmp(ss2, ss3, lss) != 0 || !memcmp(ss2, ss, lss);
                    }
            }
#pragma omp critical
            {
                st->chiffres += lc; st->echecs += le; st->recoupes += lr; st->recoupes_ko += lrk;
                st->rejets += lj; st->rejets_ko += ljk;
                for (int i = 0; i < 1024; i++) { st->hist_max[i] += hm[i]; st->hist_grp[i] += hg[i]; }
            }
            free(u); free(nv); free(ct); free(ctm);
        }
        st->groupes = st->chiffres * (p->k / 8);
        free(x); free(y);
    }
    /* campagne dédiée à la pire clé : le maximum des bascules y est le plus haut attendu */
    {
        uint64_t *x = nouveau(p->n);
        charger(x, sk_p, p->n);
        uint8_t c0[1 << 19], s0[64], mu0[32] = {0};
        sl_kem_encaps_det(niv, pk_p, mu0, c0, s0);     /* recharge h, π */
        st->pire_borne_dediee = st->pire_borne;
        while (maintenant() - t0 < budget) {
#pragma omp parallel
            {
                uint64_t *u = nouveau(p->n), *nv = nouveau(p->n2);
                uint8_t *ct = malloc(lct), mu[32], ss[64];
                alea_t g;
                alea_init(&g, st->pire_chiffres + (uint64_t)omp_get_thread_num() * 104729 + 31 * (uint64_t)niv + 5);
                uint64_t lc = 0, le = 0;
                int lm = 0;
#pragma omp for schedule(dynamic, 64)
                for (int k = 0; k < PAR_CLE; k++) {
                    for (int i = 0; i < 32; i++) mu[i] = (uint8_t)alea64(&g);
                    sl_kem_encaps_det(niv, pk_p, mu, ct, ss);
                    memset(u, 0, (NW(p->n) + 4) * 8);
                    memset(nv, 0, (NW(p->n2) + 4) * 8);
                    charger(u, ct, p->n);
                    charger(nv, ct + nb, p->n2);
                    mul_ct(x, u, p->n, nv, p->n2);
                    poser_mot(niv, mu, nv);
                    for (uint32_t i = 0; i < p->k / 8; i++) {
                        uint32_t bruit = bruit_bloc(niv, nv + i * (128 * p->D / 64));
                        if ((int)bruit > lm) lm = (int)bruit;
                        le += bruit >= 32 * p->D;
                    }
                    lc++;
                }
#pragma omp critical
                {
                    st->pire_chiffres += lc; st->pire_echecs += le;
                    if (lm > st->pire_bascules) st->pire_bascules = lm;
                }
                free(u); free(nv); free(ct);
            }
        }
        free(x);
    }
    free(pk); free(sk); free(pk_p); free(sk_p);
}

static void ecrire(resultat_t *res, int niv, const stats_t *st, double duree)
{
    const params_t *p = &P[niv];
    const char *lv = niv ? "Sillage-256" : "Sillage-128";
    char nom[96];
    int mx = 0;
    for (int i = 0; i < 1024; i++) if (st->hist_max[i]) mx = i;
    /* queue : P(max ≥ t) empirique, pour quelques seuils */
    char q[2048] = "{";
    uint64_t cum = 0;
    int premier = 1;
    for (int t = mx; t >= 0 && t >= mx - 40; t--) {
        cum += st->hist_max[t];
        if ((mx - t) % 5 == 0) {
            snprintf(q + strlen(q), 64, "%s\"%d\": %.3f", premier ? "" : ", ", t,
                     log2((double)cum / (double)(st->chiffres ? st->chiffres : 1)));
            premier = 0;
        }
    }
    strcat(q, "}");
    double moy = 0;
    for (int i = 0; i < 1024; i++) moy += (double)i * st->hist_grp[i];
    moy /= (double)(st->groupes ? st->groupes : 1);
    snprintf(nom, sizeof nom, "%s", lv);
    res_mesure(res, nom, "{\"cles\": %llu, \"chiffres\": %llu, \"groupes\": %llu, \"echecs\": %llu, \"bascules_max\": %d, "
               "\"seuil\": %u, \"marge\": %d, \"bascules_moyennes_par_groupe\": %.2f, \"log2_P_max_ge_t\": %s, "
               "\"borne_chernoff_log2_pire_cle\": %.1f, \"borne_chernoff_log2_meilleure_cle\": %.1f, "
               "\"recoupements_decaps\": %llu, \"recoupements_differents\": %llu, \"rejets_implicites\": %llu, "
               "\"taux_rejet_keygen\": %.4f, \"bornes_recalculees\": %llu, \"ecart_max_borne_recalculee\": %.4f, "
               "\"pire_cle\": {\"borne_log2\": %.1f, \"chiffres\": %llu, \"bascules_max\": %d, \"echecs\": %llu}, "
               "\"duree_s\": %.0f}",
               (unsigned long long)st->cles, (unsigned long long)st->chiffres, (unsigned long long)st->groupes,
               (unsigned long long)st->echecs, mx, 32 * p->D, (int)(32 * p->D) - mx, moy, q, st->pire_borne,
               st->meilleure_borne, (unsigned long long)st->recoupes, (unsigned long long)st->recoupes_ko,
               (unsigned long long)st->rejets, (double)st->tirages_rejetes / (double)(st->tirages ? st->tirages : 1),
               (unsigned long long)st->naives, st->ecart_naif_max, st->pire_borne_dediee,
               (unsigned long long)st->pire_chiffres, st->pire_bascules, (unsigned long long)st->pire_echecs, duree);
    snprintf(nom, sizeof nom, "%s_aucun_echec_de_decodage", lv);
    res_controle(res, nom, st->echecs == 0 && st->chiffres > 0);
    snprintf(nom, sizeof nom, "%s_decapsulation_reelle_conforme", lv);
    res_controle(res, nom, st->recoupes > 0 && st->recoupes_ko == 0);
    snprintf(nom, sizeof nom, "%s_toutes_les_cles_sous_la_borne_2_moins_lambda", lv);
    res_controle(res, nom, st->pire_borne <= -(double)p->lam);
    snprintf(nom, sizeof nom, "%s_borne_de_keygen_confirmee_par_recalcul_naif", lv);
    res_controle(res, nom, st->naives > 0 && st->naives_ko == 0);
    snprintf(nom, sizeof nom, "%s_rejet_implicite_conforme", lv);
    res_controle(res, nom, st->rejets > 0 && st->rejets_ko == 0);
    snprintf(nom, sizeof nom, "%s_pire_cle_sans_echec", lv);
    res_controle(res, nom, st->pire_chiffres > 0 && st->pire_echecs == 0);
    fprintf(stderr, "%s : %llu chiffrés, %llu clés, %llu échecs, bascules max %d / seuil %u\n", lv,
            (unsigned long long)st->chiffres, (unsigned long long)st->cles, (unsigned long long)st->echecs, mx, 32 * p->D);
}

int main(int argc, char **argv)
{
    double budget = argc > 1 ? atof(argv[1]) : 120;
    resultat_t res = {.nom = "nuit_kem_reel", .titre = "Sillage-KEM réel à grande échelle (nuit)"};
    sl_init();
    static stats_t s128, s256;
    double t = maintenant();
    campagne(0, 0.7 * budget, &s128);
    double d128 = maintenant() - t;
    { resultat_t cp = res; ecrire(&cp, 0, &s128, d128); res_ecrire(&cp); }
    t = maintenant();
    campagne(1, 0.3 * budget, &s256);
    ecrire(&res, 0, &s128, d128);
    ecrire(&res, 1, &s256, maintenant() - t);
    return res_ecrire(&res);
}
