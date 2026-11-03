/* Sillage-SIG : attaque de Kales–Zaverucha à échelle intermédiaire contre le VRAI vérifieur C (plan GPU, D1 ; PROOFS § 3.3,
 * Théorème 8). Jusqu'ici, la borne n'était confrontée qu'au modèle jouet de tests/test_sig_modele.py (N = 4, τ = 3, GF(256)).
 *
 * Instance réduite, mêmes algorithmes que sig.c (inclus, table de paramètres rendue modifiable) : n = 64, F_poly = GF(2^6),
 * K = GF(2^12), k = 45, w = 3, t = 1, N = 2^8 feuilles, τ = 4 répétitions.
 *   - clé publique SANS témoin : aucun x de poids ≤ w n'a le syndrome y (vérifié exhaustivement) ;
 *   - faux témoin : x de poids minimal parmi x_A de poids ≤ 3, Q annule w positions de son support, P comme dans keygen ;
 *     sk = x_A ‖ Q ‖ P donné au signataire honnête, qui ne vérifie rien ;
 *   - une répétition est un « faux positif » si le défi (r, ε) annule l'erreur : sa diffusion honnête passe alors pour toute feuille
 *     cachée ; sinon le tricheur engage, pour une feuille cible, la diffusion que le vérifieur recalculera si c'est elle qui est cachée ;
 *   - attaque : moudre h1 jusqu'à t1 faux positifs, puis h2 jusqu'à ce que les τ − t1 autres feuilles cachées soient les cibles.
 * Contrôles : avec un VRAI témoin, la vue du vérifieur recalculée ici coïncide avec la diffusion honnête pour toute feuille et la
 * signature est acceptée (la réplication du vérifieur est exacte, feuille par feuille) ; chaque falsification est acceptée par
 * sl_sig_verify ; la fréquence de succès ne dépasse pas la borne du Théorème 8 (formule de tests/test_sig_modele.py :: _borne_8) ;
 * une stratégie à borne basse (≈ 0,049) est mesurée sur 1000 essais (par défaut) et son IC exact à 95 % est reporté ; chaque
 * fréquence doit aussi coïncider (IC à 99,9 %) avec la probabilité exacte de la stratégie (prediction), h2 énuméré sans répétition.
 * L'aléa est reproductible (SIG_KZ_GRAINE). La mesure quantitative du plan D1 (N = 2^12, 2^35 à 2^42) reste hors de portée du CPU.
 *     make -C tests/c build/sig_kz && tests/c/build/sig_kz [essais] [essais_quantitatifs]   (depuis la racine) → resultats/sig_kz.json
 * Les outils (instance, vérifieur répliqué, bornes, bilan) sont dans sig_kz_commun.h, partagé avec tests/gpu/sig_kz_gpu.c. */

#include "sig_kz_commun.h"

int main(int argc, char **argv)
{
    int essais = argc > 1 ? atoi(argv[1]) : 12;
    int equant = argc > 2 ? atoi(argv[2]) : 1000;
    if (essais < 1) essais = 1;
    if (equant < 1) equant = 1;
    const char *graine_env = getenv("SIG_KZ_GRAINE");
    uint64_t graine = graine_env ? strtoull(graine_env, NULL, 0) : 0x5349474b5aULL;   /* « SIGKZ » */
    alea_init(&rng, graine);
    resultat_t res = {.nom = "sig_kz", .titre = "Sillage-SIG : attaque de Kales–Zaverucha à échelle intermédiaire, vrai vérifieur C"};
    if (!instance_preparer(&res)) return res_ecrire(&res);

    /* 4. attaque : seuil t1 faux positifs sur h1, puis h2 sur les autres répétitions.
     * Avec k faux positifs, h2 définit une application cible ↦ défis sur les M = N^(τ−k) cibles des autres répétitions, dont
     * il faut un point fixe ; il peut ne pas en exister (probabilité ≈ e^{-1}). Le tricheur énumère donc les cibles SANS
     * répétition (attaquant optimal à q2 donné : un tirage répété ne refait que la même requête), au plus min(q2, M).
     * La fréquence observée est confrontée à la borne du Théorème 8 ET à la probabilité exacte de cette stratégie (prediction),
     * calculée avec le taux de faux positifs mesuré sur toutes les répétitions de la campagne : un harnais affaibli (falsification
     * manquée, défi mal relu) passerait sous la borne sans être détecté, il ne passe pas la prédiction. */
    bilan_t B[NS];
    long nrep_camp = 0, nfp_camp = 0;
    static uint8_t vues[4][256][4096];
    for (size_t si = 0; si < NS; si++) {
        alea_init(&rng, graine ^ (0x9e3779b97f4a7c15ULL * (uint64_t)(si + 1)));   /* flux indépendant par stratégie */
        bilan_t *b = &B[si];
        memset(b, 0, sizeof *b);
        b->ne = kz_essais(si, essais, equant);
        for (int e = 0; e < b->ne; e++) {
            long q1 = 0, q2 = 0;
            int fini = 0;
            while (q1 < STRAT[si].q1 && !fini) {
                q1++;
                tirer(s.salt, 32);
                engager(&s, sk, pk, msg, sizeof msg);
                int fp[4] = {0}, nf = 0;
                for (uint32_t rep = 0; rep < p->tau; rep++) {
                    fp[rep] = faux_positif(&s, xn, sk, rep);
                    nf += fp[rep];
                }
                nrep_camp += p->tau; nfp_camp += nf;
                if (nf < STRAT[si].seuil) continue;
                b->retenus++; b->nf_hist[nf]++;
                if (getenv("SIG_KZ_TRACE")) fprintf(stderr, "    [%s] h1 retenu après %ld essais, %d faux positifs\n", STRAT[si].nom, q1, nf);
                if (getenv("SIG_KZ_VERIF_FP"))
                    for (uint32_t rep = 0; rep < p->tau; rep++)
                        if (fp[rep])
                            for (uint32_t c = 0; c < N; c++) {
                                vue_verifieur(&s, pk, rep, c, dv);
                                if (memcmp(dv, s.dh + rep * lrep_d, lrep_d))
                                    fprintf(stderr, "    faux positif inexact : rep %u, feuille %u\n", rep, c);
                            }
                /* vues du vérifieur pour chaque feuille des répétitions sans faux positif */
                uint32_t libres[4], m = 0, cible[4] = {0};
                for (uint32_t rep = 0; rep < p->tau; rep++)
                    if (!fp[rep]) { libres[m++] = rep; for (uint32_t c = 0; c < N; c++) vue_verifieur(&s, pk, rep, c, vues[rep][c]); }
                long M = 1;
                for (uint32_t i = 0; i < m; i++) M *= N;
                long lim = STRAT[si].q2 < M ? STRAT[si].q2 : M;
                int reussi = 0;
                for (long u = 0; u < lim; u++) {               /* cibles distinctes : u écrit en base N sur les répétitions libres */
                    q2++;
                    long v = u;
                    for (uint32_t i = 0; i < m; i++) { cible[libres[i]] = (uint32_t)(v % N); v /= N; }
                    for (uint32_t rep = 0; rep < p->tau; rep++)
                        memcpy(diff + rep * lrep_d, fp[rep] ? s.dh + rep * lrep_d : vues[rep][cible[rep]], lrep_d);
                    size_t ls = signer_avec(&s, diff, sig, ci);
                    int ok = 1;
                    for (uint32_t rep = 0; rep < p->tau; rep++) ok &= fp[rep] || ci[rep] == cible[rep];
                    if (ok) {
                        if (getenv("SIG_KZ_TRACE")) fprintf(stderr, "    succès après %ld essais de h2\n", q2);
                        b->gagne++;
                        b->valides += sl_sig_verify(NIV, pk, msg, sizeof msg, sig, ls);
                        reussi = 1;
                        break;
                    }
                }
                if (getenv("SIG_KZ_TRACE") && !reussi) fprintf(stderr, "    échec après %ld essais de h2 (nf=%d)\n", q2, nf);
                fini = 1;                                  /* comme le modèle : un seul h1 retenu, puis h2 jusqu'au budget */
            }
            b->q1tot += q1; b->q2tot += q2;
        }
    }

    /* taux de faux positifs de la campagne (toutes répétitions de tous les h1), puis bilan par stratégie */
    double pf = (double)nfp_camp / (double)nrep_camp;
    res_mesure(&res, "faux_positifs_campagne", "{\"mesure\": %.5f, \"repetitions\": %ld, \"borne_lemme_6\": %.4f}", pf, nrep_camp, plemme);
    res_controle(&res, "faux_positifs_de_la_campagne_sous_la_borne_du_lemme_6",
                 pf <= plemme + 4 * sqrt(plemme * (1 - plemme) / (double)nrep_camp));
    kz_bilan(&res, B, pf);
    return res_ecrire(&res);
}
