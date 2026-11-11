/* b3_gpu_hote.c — B3 (boomerang à 3 tours, PROTOCOLE.md § 4.4) sur GPU, apparié et conforme au C.
 *
 * Reprend departage.c tel quel (modèle, S-box, prédicteur de Markov, union des sélections, générateur)
 * et ne déporte que le comptage des quartets (b3_gpu.cu). Pour CHAQUE combinaison et CHAQUE S-box :
 *   1. contrôle exact : 2^lg_ctrl quartets comptés par le C (b3_rapide) ET par le GPU avec la même
 *      graine : les deux comptes doivent être égaux à l'unité près ;
 *   2. identité : 2^lg_id quartets, reformulation rapide (C) == inversion complète (C) ;
 *   3. mesure : 2^lg quartets sur GPU, graine 0xB30000 + lg, flux = indice de la combinaison,
 *      exactement comme `departage b3` (les comptes à lg égal coïncident avec ceux du C).
 * Le moindre écart arrête le programme (code 1) sans écrire de mesure.
 *
 * Usage : b3_gpu [-o DIR] lg K lg_ctrl lg_id SBOX...
 * Construction (conteneur tgh, CUDA 12.9) : voir run_b3_gpu.sh                                    */
#define main departage_main
#include "departage.c"
#undef main

int b3_gpu_compter(const void *param, uint64_t graine, uint64_t flux, uint64_t n, unsigned long long *k);
size_t b3_gpu_taille_param(void);
int b3_gpu_info(char *nom, size_t lg);

/* miroir exact de struct b3_param (b3_gpu.cu) ; la taille est vérifiée au démarrage */
typedef struct {
    uint8_t T0[N * D][16];
    uint8_t EI[N * D];
    uint8_t S[16], SI[16], GM[16][16], GINV[16];
    uint8_t RC1[N];
    uint8_t MIjp[N];
    uint8_t MIi[N];
    uint8_t MMi[N];
    uint8_t ROWK[D], ROWC[D];
    int i, a, dp, rc0i, rc2jp;
} b3_param_h;

static void preparer(const sbox_t *S, const combo_t *c, b3_param_h *p)
{
    memset(p, 0, sizeof *p);
    memcpy(p->T0, S->T[0], sizeof p->T0);
    for (int e = 0; e < N * D; e++) p->EI[e] = BR_EI[e];
    memcpy(p->S, S->s, 16);
    memcpy(p->SI, S->si, 16);
    memcpy(p->GM, GM, sizeof GM);
    memcpy(p->GINV, GINV, sizeof GINV);
    for (int k = 0; k < N; k++) {
        p->RC1[k] = BR_RC[1][k];
        p->MIjp[k] = MI[k][c->jp];
        p->MIi[k] = MI[c->i][k];
        p->MMi[k] = MM[k][c->i];
    }
    for (int q = 0; q < D; q++) { p->ROWK[q] = (uint8_t)ROWK[c->jp][q]; p->ROWC[q] = ROWC[c->jp][q]; }
    p->i = c->i; p->a = c->a; p->dp = c->dp;
    p->rc0i = BR_RC[0][c->i];
    p->rc2jp = BR_RC[2][c->jp];
}

static double predire_un(sbox_t *S, const combo_t *c)
{
    table_g(S);
    double pr = 0;
    for (int b = 1; b < 16; b++)
        for (int g = 1; g < 16; g++)
            for (int e = 1; e < 16; e++) {
                double w = S->ddt[c->a][b] * S->ddt[g][c->dp] * S->ddt[c->a][e] / 4096.0;
                for (int l = 0; l < D && w > 0; l++) {
                    int kk = COLJ[c->i][l], cc = COLC[c->i][l];
                    w *= G3[GM[cc][b]][GM[MI[kk][c->jp]][g]][GM[cc][e]] / 16.0;
                }
                pr += w;
            }
    return pr;
}

int b3_gpu_balayer(const void *param, uint64_t graine, uint64_t flux0, uint64_t n, unsigned long long k[225]);

/* ------------------------------------------------------------------------------------------ */
/* balayage exhaustif : TOUTES les combinaisons (i, a, j', δ') — 128 × 15 × 128 × 15 = 3 686 400   */
/* ------------------------------------------------------------------------------------------ */
/* Pour chaque S-box : 2^lg_bal quartets par combinaison (graine 0xB3D0, flux = 225(128 i + j') + c,
 * mêmes états pour toutes les S-box). Sélection : les `top` meilleurs comptes de CHAQUE S-box,
 * union. Confirmation sur l'union, toutes S-box, graine indépendante 0xB3D2 et 2^lg_conf quartets,
 * précédée du contrôle exact C == GPU (graine 0xB3D1, 2^lg_ctrl) et de l'identité rapide ==
 * inversion complète (2^lg_id). Lève la restriction « K meilleures du prédicteur, j' hors portée »
 * de la mesure B3 (AUDIT_LIMITES.md § 3.3) : statut EMPIRIQUE, espace de recherche complet pour
 * α et δ' de poids 1.                                                                          */
typedef struct { uint32_t k; uint32_t id; } cpt_t;
static int cmp_cpt(const void *x, const void *y)
{
    uint32_t a = ((const cpt_t *)x)->k, b = ((const cpt_t *)y)->k;
    return a < b ? 1 : a > b ? -1 : (int)(((const cpt_t *)x)->id - ((const cpt_t *)y)->id);
}

static int portee_de(int i, int jp, int *zeros)
{
    int p = 0, z = 0;
    for (int q = 0; q < D; q++)
        for (int l = 0; l < D; l++)
            if (ROWK[jp][q] == COLJ[i][l]) p = 1;
    for (int l = 0; l < D; l++) z += MI[COLJ[i][l]][jp] == 0;
    *zeros = z;
    return p;
}

static int cmd_balayage(int lg_bal, int top, int lg_conf, int lg_ctrl, int lg_id, int nc, char **specs)
{
    const int NCOMB = N * N * 225;
    sbox_t *S = calloc(nc, sizeof(sbox_t));
    for (int q = 0; q < nc; q++)
        if (!sbox_lire(specs[q], &S[q])) { fprintf(stderr, "S-box illisible : %s\n", specs[q]); return 2; }
    b3_param_h *p = malloc(sizeof *p);
    cpt_t *c = malloc(sizeof(cpt_t) * NCOMB);
    uint32_t *uni = malloc(sizeof(uint32_t) * (size_t)nc * top);
    int nu = 0;
    double t0 = maintenant();
    FILE *h = ouvrir("b3bal", "histogramme", "json");
    fprintf(h, "{\n  \"quartets_par_combinaison\": %.0f, \"graine\": \"0xB3D0\", \"combinaisons\": %d,\n"
               "  \"histogramme_des_comptes\": {", ldexp(1, lg_bal), NCOMB);
    FILE *ft = ouvrir("b3bal", "meilleurs_balayage", "csv");
    fprintf(ft, "sbox,rang,i,a,j_p,delta_p,a_portee,zeros_MI,retours_balayage,quartets_balayage\n");
    for (int q = 0; q < nc; q++) {
        unsigned long long k[225];
        uint64_t n = 1ULL << lg_bal;
        for (int i = 0; i < N; i++)
            for (int jp = 0; jp < N; jp++) {
                combo_t cb = {0, i, 1, jp, 1};
                preparer(&S[q], &cb, p);
                uint32_t f0 = (uint32_t)((i * N + jp) * 225);
                if (b3_gpu_balayer(p, 0xB3D0, f0, n, k)) return 2;
                for (int t = 0; t < 225; t++) { c[f0 + t].k = (uint32_t)k[t]; c[f0 + t].id = f0 + t; }
            }
        /* histogramme des comptes */
        uint32_t kmax = 0;
        for (int t = 0; t < NCOMB; t++) if (c[t].k > kmax) kmax = c[t].k;
        uint32_t *hist = calloc(kmax + 1, sizeof(uint32_t));
        for (int t = 0; t < NCOMB; t++) hist[c[t].k]++;
        fprintf(h, "%s\n    \"%s\": {", q ? "," : "", S[q].nom);
        int pr = 0;
        for (uint32_t v = 0; v <= kmax; v++)
            if (hist[v]) { fprintf(h, "%s\"%u\": %u", pr ? ", " : "", v, hist[v]); pr = 1; }
        fprintf(h, "}");
        free(hist);
        qsort(c, NCOMB, sizeof(cpt_t), cmp_cpt);
        /* contrôle exact du balayage : recomptage C de 10 rangs, du meilleur au pire */
        for (int t = 0; t < 10; t++) {
            int r = t < 2 ? t : (int)((int64_t)(t - 1) * (NCOMB - 1) / 8);
            uint32_t id = c[r].id;
            int i = id / 225 / N, jp = id / 225 % N, a = id % 225 / 15 + 1, dp = id % 15 + 1;
            uint64_t kc = 0;
#pragma omp parallel for reduction(+ : kc) schedule(static)
            for (uint64_t s = 0; s < n; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB3D0, id, s, x);
                kc += b3_rapide(&S[q], i, a, jp, dp, x);
            }
            if (kc != c[r].k) {
                fprintf(stderr, "ECART balayage C/GPU : %s rang %d (i=%d a=%d j'=%d d'=%d) : C=%llu GPU=%u\n", S[q].nom,
                        r, i, a, jp, dp, (unsigned long long)kc, c[r].k);
                return 1;
            }
        }
        for (int r = 0; r < top; r++) {
            uint32_t id = c[r].id;
            int i = id / 225 / N, jp = id / 225 % N, a = id % 225 / 15 + 1, dp = id % 15 + 1, z;
            int po = portee_de(i, jp, &z);
            fprintf(ft, "%s,%d,%d,%d,%d,%d,%d,%d,%u,%llu\n", S[q].nom, r, i, a, jp, dp, po, z, c[r].k,
                    (unsigned long long)n);
            int dup = 0;
            for (int u = 0; u < nu; u++) dup |= uni[u] == id;
            if (!dup) uni[nu++] = id;
        }
        fflush(ft);
        printf("BAL %-10s balayage fini : max %u/2^%d (2^%.3f), %d combinaisons dans l'union (%.0fs)\n", S[q].nom, c[0].k,
               lg_bal, log2((double)c[0].k) - lg_bal, nu, maintenant() - t0);
        fflush(stdout);
    }
    fprintf(h, "\n  }\n}\n");
    fclose(h);
    fclose(ft);
    /* confirmation sur l'union, toutes les S-box */
    FILE *f = ouvrir("b3bal", "confirmation", "csv");
    fprintf(f, "sbox,i,a,j_p,delta_p,a_portee,zeros_MI,quartets,retours,P_log2,wilson4sigma_bas,wilson4sigma_haut,"
               "controle_quartets,controle_c,controle_gpu,identite_quartets,identite_ecarts\n");
    double *pm = calloc(nc, sizeof(double)), *plo = calloc(nc, sizeof(double)), *phi = calloc(nc, sizeof(double));
    uint32_t *arg = calloc(nc, sizeof(uint32_t));
    for (int u = 0; u < nu; u++) {
        uint32_t id = uni[u];
        combo_t cb = {0, (int)(id / 225 / N), (int)(id % 225 / 15 + 1), (int)(id / 225 % N), (int)(id % 15 + 1)};
        int z, po = portee_de(cb.i, cb.jp, &z);
        for (int q = 0; q < nc; q++) {
            preparer(&S[q], &cb, p);
            uint64_t nct = 1ULL << lg_ctrl, kc = 0;
            unsigned long long kg = 0;
#pragma omp parallel for reduction(+ : kc) schedule(static)
            for (uint64_t s = 0; s < nct; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB3D1, id, s, x);
                kc += b3_rapide(&S[q], cb.i, cb.a, cb.jp, cb.dp, x);
            }
            if (b3_gpu_compter(p, 0xB3D1, id, nct, &kg)) return 2;
            if (kc != kg) {
                fprintf(stderr, "ECART C/GPU : %s (i=%d a=%d j'=%d d'=%d) : C=%llu GPU=%llu\n", S[q].nom, cb.i, cb.a,
                        cb.jp, cb.dp, (unsigned long long)kc, kg);
                return 1;
            }
            uint64_t nid = 1ULL << lg_id, diff = 0;
#pragma omp parallel for reduction(+ : diff) schedule(static)
            for (uint64_t s = 0; s < nid; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB3B4, id, s, x);
                diff += b3_rapide(&S[q], cb.i, cb.a, cb.jp, cb.dp, x) != b3_complet(&S[q], cb.i, cb.a, cb.jp, cb.dp, x);
            }
            if (diff) {
                fprintf(stderr, "ECART identite : %s (i=%d a=%d j'=%d d'=%d) : %llu\n", S[q].nom, cb.i, cb.a, cb.jp,
                        cb.dp, (unsigned long long)diff);
                return 1;
            }
            uint64_t n = 1ULL << lg_conf;
            unsigned long long k = 0;
            if (b3_gpu_compter(p, 0xB3D2, id, n, &k)) return 2;
            double pe = (double)k / n, lo, hi;
            wilson((double)k, (double)n, 4.0, &lo, &hi);
            fprintf(f, "%s,%d,%d,%d,%d,%d,%d,%llu,%llu,%.4f,%.9g,%.9g,%llu,%llu,%llu,%llu,%llu\n", S[q].nom, cb.i, cb.a,
                    cb.jp, cb.dp, po, z, (unsigned long long)n, k, k ? log2(pe) : -99.0, lo, hi,
                    (unsigned long long)nct, (unsigned long long)kc, kg, (unsigned long long)nid,
                    (unsigned long long)diff);
            if (pe > pm[q]) { pm[q] = pe; plo[q] = lo; phi[q] = hi; arg[q] = id; }
        }
        fflush(f);
        if (u % 32 == 31) { printf("CONF %d/%d combinaisons confirmees (%.0fs)\n", u + 1, nu, maintenant() - t0); fflush(stdout); }
    }
    fclose(f);
    FILE *g = ouvrir("b3bal", "synthese", "json");
    fprintf(g, "{\n  \"mesure\": \"B3 exhaustif : probabilite de retour du boomerang a 3 tours, TOUTES les combinaisons "
               "(i, a, j', delta') avec alpha = a e_i et delta = M(delta' e_j') (128*15*128*15 = %d)\",\n"
               "  \"statut\": \"EMPIRIQUE\",\n  \"balayage\": {\"quartets_par_combinaison\": %.0f, \"graine\": \"0xB3D0\"},\n"
               "  \"selection\": \"union des %d meilleurs comptes du balayage de chaque S-box : %d combinaisons\",\n"
               "  \"confirmation\": {\"quartets\": %.0f, \"graine\": \"0xB3D2 (independante du balayage)\", "
               "\"controle_exact_c_gpu_quartets\": %.0f, \"identite_quartets\": %.0f, \"ok\": true},\n"
               "  \"P_max_confirmee\": {",
            NCOMB, ldexp(1, lg_bal), top, nu, ldexp(1, lg_conf), ldexp(1, lg_ctrl), ldexp(1, lg_id));
    for (int q = 0; q < nc; q++) {
        uint32_t id = arg[q];
        int z, po = portee_de(id / 225 / N, id / 225 % N, &z);
        fprintf(g, "%s\n    \"%s\": {\"log2\": %.4f, \"wilson4sigma_log2\": [%.4f, %.4f], \"i\": %u, \"a\": %u, "
                   "\"j_p\": %u, \"delta_p\": %u, \"a_portee\": %d, \"zeros_MI\": %d}",
                q ? "," : "", S[q].nom, log2(pm[q]), log2(plo[q]), log2(phi[q]), id / 225 / N, id % 225 / 15 + 1,
                id / 225 % N, id % 15 + 1, po, z);
    }
    fprintf(g, "\n  },\n  \"duree_s\": %.1f\n}\n", maintenant() - t0);
    fclose(g);
    printf("fin balayage : %d combinaisons confirmees x %d S-box, controles C/GPU et identite OK (%.0fs)\n", nu, nc,
           maintenant() - t0);
    return 0;
}

int main(int argc, char **argv)
{
    int k0 = 1;
    if (k0 + 1 < argc && !strcmp(argv[k0], "-o")) { g_sortie = argv[k0 + 1]; k0 += 2; }
    if (b3_gpu_taille_param() != sizeof(b3_param_h)) {
        fprintf(stderr, "struct b3_param : tailles hote %zu / GPU %zu\n", sizeof(b3_param_h), b3_gpu_taille_param());
        return 2;
    }
    if (argc - k0 >= 7 && !strcmp(argv[k0], "balayage")) {
        init_modele();
        return cmd_balayage(atoi(argv[k0 + 1]), atoi(argv[k0 + 2]), atoi(argv[k0 + 3]), atoi(argv[k0 + 4]),
                            atoi(argv[k0 + 5]), argc - k0 - 6, argv + k0 + 6);
    }
    if (argc - k0 < 5) {
        fprintf(stderr, "usage : b3_gpu [-o DIR] lg K lg_ctrl lg_id SBOX...\n"
                        "        b3_gpu [-o DIR] balayage lg_bal top lg_conf lg_ctrl lg_id SBOX...\n");
        return 2;
    }
    init_modele();
    int lg = atoi(argv[k0]), K = atoi(argv[k0 + 1]), lg_ctrl = atoi(argv[k0 + 2]), lg_id = atoi(argv[k0 + 3]);
    int nc = argc - k0 - 4;
    char **specs = argv + k0 + 4;
    sbox_t *S = calloc(nc, sizeof(sbox_t));
    for (int q = 0; q < nc; q++)
        if (!sbox_lire(specs[q], &S[q])) { fprintf(stderr, "S-box illisible : %s\n", specs[q]); return 2; }
    /* union des sélections : même code et même ordre que cmd_b3 */
    combo_t *uni = calloc((size_t)nc * K, sizeof(combo_t));
    int *source = calloc((size_t)nc * K, sizeof(int));
    int nu = 0;
    combo_t *top = calloc(K, sizeof(combo_t));
    for (int q = 0; q < nc; q++) {
        b3_predire(&S[q], K, top);
        for (int t = 0; t < K; t++) {
            int dup = 0;
            for (int u = 0; u < nu; u++)
                if (uni[u].i == top[t].i && uni[u].a == top[t].a && uni[u].jp == top[t].jp && uni[u].dp == top[t].dp)
                    dup = 1;
            if (!dup) { uni[nu] = top[t]; source[nu] = q; nu++; }
        }
    }
    char gpu[256];
    if (b3_gpu_info(gpu, sizeof gpu)) return 2;
    char nomf[32];
    snprintf(nomf, sizeof nomf, "gpu_lg%d", lg);
    FILE *f = ouvrir("b3", nomf, "csv");
    fprintf(f, "sbox,i,a,j_p,delta_p,selection_par,prediction_markov,quartets,retours,P_empirique,P_log2,"
               "wilson4sigma_bas,wilson4sigma_haut,controle_c_gpu_quartets,controle_c,controle_gpu,"
               "identite_quartets,identite_ecarts\n");
    double *pmax = calloc(nc, sizeof(double)), *pmaxlo = calloc(nc, sizeof(double)), *pmaxhi = calloc(nc, sizeof(double));
    int *argmax = calloc(nc, sizeof(int));
    double t0 = maintenant(), tgpu = 0;
    b3_param_h *p = malloc(sizeof *p);
    for (int u = 0; u < nu; u++) {
        combo_t c = uni[u];
        for (int q = 0; q < nc; q++) {
            preparer(&S[q], &c, p);
            /* 1. contrôle exact C == GPU (graine de la mesure à lg_ctrl, comme departage b3 lg_ctrl) */
            uint64_t nct = 1ULL << lg_ctrl, kc = 0;
            unsigned long long kg = 0;
#pragma omp parallel for reduction(+ : kc) schedule(static)
            for (uint64_t s = 0; s < nct; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB30000 + (uint64_t)lg_ctrl, (uint64_t)u, s, x);
                kc += b3_rapide(&S[q], c.i, c.a, c.jp, c.dp, x);
            }
            if (b3_gpu_compter(p, 0xB30000 + (uint64_t)lg_ctrl, (uint64_t)u, nct, &kg)) return 2;
            if (kc != kg) {
                fprintf(stderr, "ECART C/GPU : %s combinaison %d (i=%d a=%d j'=%d d'=%d) : C=%llu GPU=%llu\n",
                        S[q].nom, u, c.i, c.a, c.jp, c.dp, (unsigned long long)kc, kg);
                return 1;
            }
            /* 2. identité reformulation rapide == inversion complète */
            uint64_t nid = 1ULL << lg_id, diff = 0;
#pragma omp parallel for reduction(+ : diff) schedule(static)
            for (uint64_t s = 0; s < nid; s++) {
                uint8_t x[N];
                etat_aleatoire(0xB3B3, (uint64_t)u, s, x);
                diff += b3_rapide(&S[q], c.i, c.a, c.jp, c.dp, x) != b3_complet(&S[q], c.i, c.a, c.jp, c.dp, x);
            }
            if (diff) {
                fprintf(stderr, "ECART identite : %s combinaison %d : %llu\n", S[q].nom, u, (unsigned long long)diff);
                return 1;
            }
            /* 3. mesure GPU */
            uint64_t n = 1ULL << lg;
            unsigned long long k = 0;
            double tg = maintenant();
            if (b3_gpu_compter(p, 0xB30000 + (uint64_t)lg, (uint64_t)u, n, &k)) return 2;
            tgpu += maintenant() - tg;
            double pe = (double)k / n, lo, hi;
            wilson((double)k, (double)n, 4.0, &lo, &hi);
            double pr = predire_un(&S[q], &c);
            fprintf(f, "%s,%d,%d,%d,%d,%s,%.9g,%llu,%llu,%.9g,%.4f,%.9g,%.9g,%llu,%llu,%llu,%llu,%llu\n", S[q].nom, c.i,
                    c.a, c.jp, c.dp, S[source[u]].nom, pr, (unsigned long long)n, k, pe, k ? log2(pe) : -INFINITY, lo, hi,
                    (unsigned long long)nct, (unsigned long long)kc, kg, (unsigned long long)nid,
                    (unsigned long long)diff);
            fflush(f);
            if (pe > pmax[q]) { pmax[q] = pe; pmaxlo[q] = lo; pmaxhi[q] = hi; argmax[q] = u; }
            printf("B3G %-10s (i=%3d a=%2d j'=%3d d'=%2d) pred=2^%.2f mes=2^%.4f [%llu/2^%d] ctrl %llu=%llu id=0 (%.0fs)\n",
                   S[q].nom, c.i, c.a, c.jp, c.dp, log2(pr), k ? log2(pe) : -99.0, k, lg, (unsigned long long)kc, kg,
                   maintenant() - t0);
            fflush(stdout);
        }
    }
    fclose(f);
    FILE *g = ouvrir("b3", nomf, "json");
    fprintf(g, "{\n  \"mesure\": \"B3 : probabilite de retour du boomerang a 3 tours (tours 1-3), alpha = a e_i, "
               "delta = M(delta' e_j'), comptage GPU\",\n  \"statut\": \"EMPIRIQUE\",\n  \"gpu\": \"%s\",\n"
               "  \"selection\": \"union des %d meilleures combinaisons du predicteur de Markov de chaque S-box "
               "(j' hors portee de N[i]), meme code que departage b3\",\n  \"quartets_par_combinaison\": %.0f,\n"
               "  \"graine\": \"0xB30000+lg, flux = indice de combinaison (identique a departage b3)\",\n"
               "  \"controle_exact_c_gpu\": {\"quartets\": %.0f, \"ok\": true},\n"
               "  \"identite_rapide_vs_inverse_complete\": {\"quartets\": %.0f, \"ok\": true},\n"
               "  \"combinaisons\": %d,\n  \"P_max_mesuree\": {",
            gpu, K, ldexp(1, lg), ldexp(1, lg_ctrl), ldexp(1, lg_id), nu);
    for (int q = 0; q < nc; q++)
        fprintf(g, "%s\n    \"%s\": {\"P\": %.9g, \"log2\": %.4f, \"wilson4sigma_log2\": [%.4f, %.4f], "
                   "\"i\": %d, \"a\": %d, \"j_p\": %d, \"delta_p\": %d}",
                q ? "," : "", S[q].nom, pmax[q], log2(pmax[q]), log2(pmaxlo[q]), log2(pmaxhi[q]), uni[argmax[q]].i,
                uni[argmax[q]].a, uni[argmax[q]].jp, uni[argmax[q]].dp);
    fprintf(g, "\n  },\n  \"duree_s\": %.1f,\n  \"duree_gpu_s\": %.1f\n}\n", maintenant() - t0, tgpu);
    fclose(g);
    printf("fin : %d combinaisons x %d S-box, tous les controles C/GPU et identite OK (%.0fs, GPU %.0fs)\n", nu, nc,
           maintenant() - t0, tgpu);
    return 0;
}
