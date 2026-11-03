/* Sillage-SIG : attaque de Kales–Zaverucha à échelle réduite, broyage de h1 et de h2 sur GPU, vrai vérifieur C.
 * Version GPU de tests/c/sig_kz.c : même instance, mêmes clés et même faux témoin (tests/c/sig_kz_commun.h), mêmes stratégies
 * et même bilan, sur des campagnes 100 fois plus grandes.
 *   - étape 1 (GPU, sig_kz_gpu.cu) : chaque tentative de h1 est une mise en gage complète (arbre GGM, 4 × 256 feuilles,
 *     aux, engagements, h1, défis) ; le GPU renvoie le nombre de répétitions à faux positif de chaque tentative ;
 *   - étape 2 : pour chaque h1 retenu, l'hôte refait la mise en gage en C (engager), vérifie le nombre de faux positifs,
 *     calcule les vues du vérifieur (vue_verifieur, code C) des feuilles 0 et N − 1 de chaque répétition libre ; la vue
 *     d'une feuille c s'en déduit axe par axe (le côté simulé ne dépend que du bit d de c), ce que l'hôte vérifie feuille
 *     par feuille sur les premiers h1 retenus de chaque stratégie ; le GPU énumère les cibles de h2 ; l'hôte rejoue la
 *     cible gagnante (signer_avec) et soumet la signature à sl_sig_verify ;
 *   - le taux de faux positifs n'est plus mesuré mais EXACT : T(r) = 0 est évalué sur tout K (valeur_T), et
 *     Pr[faux positif] = 1 − (1 − z/|K|)(1 − 1/|K|) avec z racines ; la prédiction de chaque stratégie l'utilise, et le
 *     taux observé sur la campagne doit lui être conforme.
 * Conformité : 256 sels au hasard, h1 et faux positifs du GPU = C ; défis de h2 du GPU = C sur les 256 premières cibles du
 * premier h1 retenu ; chaque h1 retenu recalculé en C ; chaque succès rejoué en C.
 *     make -C tests/gpu build/sig_kz_gpu && tests/gpu/build/sig_kz_gpu [essais] [essais_quantitatifs]   (depuis la racine)
 *     → resultats/sig_kz_gpu.json ; lanceur : ./runtestg-gpu.sh */
#include <time.h>

#include "sig_kz_commun.h"
#include "sig_kz_gpu.h"

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + 1e-9 * (double)t.tv_nsec;
}

/* diffusion de la répétition pour la feuille cachée c, à partir des vues des feuilles 0 (l0) et N − 1 (l1) */
static void composer(const uint8_t *l0, const uint8_t *l1, uint32_t c, uint8_t *o)
{
    memcpy(o, l0, 2 * pts);
    for (uint32_t d = 0; d < p->D; d++)
        memcpy(o + (2 + 3 * (size_t)d) * pts, (c >> d & 1 ? l1 : l0) + (2 + 3 * (size_t)d) * pts, 3 * pts);
}

/* diffusion complète pour l'indice u des cibles (u en base N sur les répétitions libres) */
static void diffusion_u(const uint8_t *lignes, uint32_t libres, uint64_t u, uint32_t *cible)
{
    for (uint32_t rep = 0; rep < p->tau; rep++) {
        cible[rep] = 0;
        if (libres >> rep & 1) { cible[rep] = (uint32_t)(u % N); u /= N; }
        composer(lignes + (2 * rep) * lrep_d, lignes + (2 * rep + 1) * lrep_d, cible[rep], diff + rep * lrep_d);
    }
}

int main(int argc, char **argv)
{
    int essais = argc > 1 ? atoi(argv[1]) : 300;
    int equant = argc > 2 ? atoi(argv[2]) : 100000;
    if (essais < 1) essais = 1;
    if (equant < 1) equant = 1;
    const char *graine_env = getenv("SIG_KZ_GRAINE");
    uint64_t graine = graine_env ? strtoull(graine_env, NULL, 0) : 0x5349474b5aULL;   /* « SIGKZ » */
    alea_init(&rng, graine);
    double t0 = maintenant();
    resultat_t res = {.nom = "sig_kz_gpu",
                      .titre = "Sillage-SIG : attaque de Kales–Zaverucha à échelle réduite, broyage sur GPU, vrai vérifieur C"};
    if (!instance_preparer(&res)) return res_ecrire(&res);

    /* taux exact de faux positifs : racines de T sur tout K, et ε = 0 */
    uint32_t K = 1u << p->ep, racines = 0;
    uint8_t *tz = sl_calloc(K / 8, 1);
    for (uint32_t r = 0; r < K; r++) {
        s.r[0] = r;
        if (valeur_T(&s, xn, sk, 0) == 0) { tz[r >> 3] |= (uint8_t)(1u << (r & 7)); racines++; }
    }
    double pf_exact = 1 - (1 - (double)racines / K) * (1 - 1.0 / K);
    res_mesure(&res, "faux_positifs_exacts", "{\"racines_de_T\": %u, \"corps\": %u, \"taux\": %.6f, \"borne_lemme_6\": %.6f}",
               racines, K, pf_exact, plemme);
    res_controle(&res, "taux_exact_de_faux_positifs_sous_la_borne_du_lemme_6", pf_exact <= plemme);

    /* GPU */
    kz_dims_t dims = {N, p->D, p->tau, p->t, p->sb, p->hb, (uint32_t)Lp, (uint32_t)(xbo + 2 * qbo), (uint32_t)pts, (uint32_t)La,
                      p->ep, (uint32_t)lrep_d, p->pb};
    uint8_t masque[64];
    memset(masque, 0xFF, sizeof masque);
    masquer_part(p, masque);
    char nom[256] = "";
    int gpu_ok = kz_gpu_init(&dims, sk, s.pkh, s.mh, masque, tz, nom, sizeof nom) == 0;
    fprintf(stderr, "  GPU : %s\n", nom[0] ? nom : "aucun");
    res_controle(&res, "gpu_disponible_et_dimensions_conformes", gpu_ok);
    if (!gpu_ok) return res_ecrire(&res);

    /* conformité de l'étape 1 : h1 et faux positifs du GPU = C, sur 256 sels au hasard */
    enum { NCONF = 256 };
    uint8_t *sels = sl_malloc(32 * NCONF), *h1g = sl_malloc((size_t)p->hb * NCONF), nfg[NCONF];
    tirer(sels, 32 * NCONF);
    int conf1 = kz_gpu_h1_sels(sels, NCONF, h1g, nfg) == 0, fp_conf = 0;
    for (int i = 0; conf1 && i < NCONF; i++) {
        memcpy(s.salt, sels + 32 * i, 32);
        engager(&s, sk, pk, msg, sizeof msg);
        int nf = 0;
        for (uint32_t rep = 0; rep < p->tau; rep++) nf += faux_positif(&s, xn, sk, rep);
        conf1 &= !memcmp(s.h1, h1g + (size_t)p->hb * i, p->hb) && nf == nfg[i];
        fp_conf += nf;
    }
    res_mesure(&res, "conformite_h1", "{\"sels\": %d, \"repetitions_a_faux_positif\": %d}", NCONF, fp_conf);
    res_controle(&res, "conformite_gpu_c_h1_et_faux_positifs", conf1);
    if (!conf1) { kz_gpu_fin(); return res_ecrire(&res); }

    /* étapes 1 (GPU, lots d'environ 0,25 s) et 2 (hôte + GPU) */
    bilan_t B[NS];
    long nrep_camp = 0, nfp_camp = 0, tentatives = 0;
    int h1_confirmes = 1, succes_confirmes = 1, compo_ok = 1, compo_h1 = 0, conf2 = -1;
    double ms_h1 = 0, t_etape2 = 0;
    uint32_t lot = 1u << 16;
    uint8_t *lignes = sl_malloc(2 * (size_t)p->tau * lrep_d), *vue = sl_malloc(lrep_d), *nf = NULL;
    size_t cap_nf = 0;
    for (size_t si = 0; si < NS; si++) {
        bilan_t *b = &B[si];
        memset(b, 0, sizeof *b);
        b->ne = kz_essais(si, essais, equant);
        uint32_t ne = (uint32_t)b->ne, nact = ne, a0 = 0, q1max = (uint32_t)STRAT[si].q1;
        uint32_t *actifs = sl_malloc(4 * (size_t)ne);
        int32_t *premier = sl_malloc(4 * (size_t)ne);
        uint8_t *nf_ret = sl_calloc(ne, 1);
        for (uint32_t e = 0; e < ne; e++) { actifs[e] = e; premier[e] = -1; }
        while (nact && a0 < q1max) {                        /* tous les essais actifs en sont à la même tentative a0 */
            uint32_t C = lot / nact;
            if (C < 1) C = 1;
            if (C > q1max - a0) C = q1max - a0;
            uint32_t par = lot / C, garde = 0;
            if (par < 1) par = 1;
            for (uint32_t deb = 0; deb < nact; deb += par) {
                uint32_t nb = nact - deb < par ? nact - deb : par;
                if ((size_t)nb * C > cap_nf) { free(nf); cap_nf = (size_t)nb * C; nf = sl_malloc(cap_nf); }
                float ms = 0;
                if (kz_gpu_h1(graine, (uint32_t)si, actifs + deb, nb, a0, C, nf, &ms)) {
                    res_controle(&res, "campagne_gpu_sans_erreur", 0);
                    kz_gpu_fin();
                    return res_ecrire(&res);
                }
                ms_h1 += ms;
                tentatives += (long)nb * C;
                for (uint32_t k = 0; k < nb; k++) {
                    uint32_t e = actifs[deb + k];
                    for (uint32_t j = 0; j < C; j++) {
                        int v = nf[(size_t)k * C + j];
                        nrep_camp += p->tau; nfp_camp += v;
                        if (v >= STRAT[si].seuil) { premier[e] = (int32_t)(a0 + j); nf_ret[e] = (uint8_t)v; break; }
                    }
                    if (premier[e] < 0) actifs[garde++] = e;    /* garde ≤ deb + k : on n'écrase rien qui reste à lire */
                }
                if (ms > 1) {                               /* vise ≈ 0,25 s par noyau (chien de garde d'affichage) */
                    double f = 250.0 / ms;
                    f = f < 0.5 ? 0.5 : f > 2 ? 2 : f;
                    lot = (uint32_t)(lot * f);
                    if (lot < 1u << 12) lot = 1u << 12;
                    if (lot > 1u << 22) lot = 1u << 22;
                }
            }
            nact = garde;
            a0 += C;
        }
        double t2 = maintenant();
        int compo_strat = 0;
        for (uint32_t e = 0; e < ne; e++) {                 /* étape 2, dans l'ordre des essais */
            b->q1tot += premier[e] < 0 ? STRAT[si].q1 : premier[e] + 1;
            if (premier[e] < 0) continue;
            b->retenus++;
            b->nf_hist[nf_ret[e]]++;
            kz_sel(graine, (uint32_t)si, e, (uint32_t)premier[e], s.salt);
            engager(&s, sk, pk, msg, sizeof msg);
            int fp[4] = {0}, nfc = 0;
            uint32_t libres = 0, m = 0;
            for (uint32_t rep = 0; rep < p->tau; rep++) {
                fp[rep] = faux_positif(&s, xn, sk, rep);
                nfc += fp[rep];
                uint8_t *l0 = lignes + (2 * rep) * lrep_d, *l1 = l0 + lrep_d;
                if (fp[rep]) { memcpy(l0, s.dh + rep * lrep_d, lrep_d); memcpy(l1, l0, lrep_d); continue; }
                libres |= 1u << rep; m++;
                vue_verifieur(&s, pk, rep, 0, l0);
                vue_verifieur(&s, pk, rep, N - 1, l1);
            }
            h1_confirmes &= nfc == nf_ret[e];
            if (compo_strat < 2) {                          /* vue composée = vue du vérifieur, pour toute feuille */
                for (uint32_t rep = 0; rep < p->tau; rep++)
                    if (libres >> rep & 1)
                        for (uint32_t c = 0; c < N; c++) {
                            vue_verifieur(&s, pk, rep, c, dv);
                            composer(lignes + (2 * rep) * lrep_d, lignes + (2 * rep + 1) * lrep_d, c, vue);
                            compo_ok &= !memcmp(dv, vue, lrep_d);
                        }
                compo_strat++; compo_h1++;
            }
            uint64_t M = 1;
            for (uint32_t i = 0; i < m; i++) M *= N;
            uint64_t lim = (uint64_t)STRAT[si].q2 < M ? (uint64_t)STRAT[si].q2 : M;
            int64_t u = -1;
            uint32_t cible[4];
            if (conf2 < 0) {                                /* conformité de l'étape 2 sur les 256 premières cibles */
                uint32_t ndbg = lim < 256 ? (uint32_t)lim : 256, *cig = sl_malloc(4 * (size_t)p->tau * 256);
                conf2 = kz_gpu_h2(s.salt, s.h1, lignes, libres, lim, &u, cig, ndbg) == 0;
                for (uint32_t k = 0; conf2 && k < ndbg; k++) {
                    diffusion_u(lignes, libres, k, cible);
                    signer_avec(&s, diff, sig, ci);
                    for (uint32_t rep = 0; rep < p->tau; rep++) conf2 &= ci[rep] == cig[p->tau * k + rep];
                }
                free(cig);
            } else if (kz_gpu_h2(s.salt, s.h1, lignes, libres, lim, &u, NULL, 0)) {
                res_controle(&res, "campagne_gpu_sans_erreur", 0);
                kz_gpu_fin();
                return res_ecrire(&res);
            }
            if (u >= 0) {                                   /* succès : rejoué en C, puis vrai vérifieur */
                diffusion_u(lignes, libres, (uint64_t)u, cible);
                size_t ls = signer_avec(&s, diff, sig, ci);
                int ok = 1;
                for (uint32_t rep = 0; rep < p->tau; rep++) ok &= !(libres >> rep & 1) || ci[rep] == cible[rep];
                succes_confirmes &= ok;
                if (ok) {
                    b->gagne++;
                    b->valides += sl_sig_verify(NIV, pk, msg, sizeof msg, sig, ls);
                }
                b->q2tot += u + 1;
            } else
                b->q2tot += (long)lim;
        }
        t_etape2 += maintenant() - t2;
        free(actifs); free(premier); free(nf_ret);
    }

    double pf = (double)nfp_camp / (double)nrep_camp;
    res_mesure(&res, "faux_positifs_campagne", "{\"mesure\": %.6f, \"repetitions\": %ld, \"taux_exact\": %.6f, \"borne_lemme_6\": %.4f}",
               pf, nrep_camp, pf_exact, plemme);
    res_controle(&res, "faux_positifs_de_la_campagne_conformes_au_taux_exact",
                 fabs(pf - pf_exact) <= 4 * sqrt(pf_exact * (1 - pf_exact) / (double)nrep_camp));
    res_controle(&res, "campagne_gpu_sans_erreur", 1);
    res_controle(&res, "conformite_gpu_c_h2", conf2 == 1);
    res_controle(&res, "h1_retenus_par_le_gpu_confirmes_par_le_c", h1_confirmes);
    res_controle(&res, "succes_gpu_rejoues_par_le_c", succes_confirmes);
    res_controle(&res, "vue_composee_par_axes_identique_a_vue_verifieur", compo_ok && compo_h1 > 0);
    kz_bilan(&res, B, pf_exact);
    /* permutations Keccak par tentative : graine maîtresse, h1, défis ; par répétition : racine, N − 1 nœuds, N parts,
     * N − 1 engagements, engagement de N − 1, haché des engagements */
    long perm = 1 + 2 + 1 + (long)p->tau * (1 + (N - 1) + N + (N - 1) + 1 + (16 + 32 + 4 + (long)N * p->hb) / 136 + 1);
    double tt = maintenant() - t0;
    res_mesure(&res, "gpu", "{\"nom\": \"%s\", \"tentatives_h1\": %ld, \"permutations_par_tentative\": %ld, "
               "\"temps_noyaux_h1_s\": %.2f, \"tentatives_par_s\": %.0f, \"permutations_par_s\": %.3g, "
               "\"h1_controles_vue_par_vue\": %d, \"temps_etape2_s\": %.1f, \"temps_total_s\": %.1f}",
               nom, tentatives, perm, ms_h1 / 1000, tentatives / (ms_h1 / 1000), tentatives * (double)perm / (ms_h1 / 1000),
               compo_h1, t_etape2, tt);
    fprintf(stderr, "  GPU : %ld tentatives de h1 en %.1f s de noyau (%.0f/s, %.3g permutations Keccak/s) ; étape 2 : %.1f s ; total %.1f s\n",
            tentatives, ms_h1 / 1000, tentatives / (ms_h1 / 1000), tentatives * (double)perm / (ms_h1 / 1000), t_etape2, tt);
    kz_gpu_fin();
    return res_ecrire(&res);
}
