/* Revue du temps constant de la SIG C, au niveau du flot de contrôle
 * (audit externe, seconde passe, point 6).
 *
 * gcc instrumente chaque bloc de base de sig.c (-fsanitize-coverage=trace-pc)
 * et l'on compare l'empreinte de la suite des blocs exécutés :
 *  1. signature complète avec le MÊME aléa (sl_alea rejoué) et des clés secrètes DIFFÉRENTES
 *     (aléatoires, et x_A concentré en tête) : même trace attendue. Les défis dépendent de la clé
 *     par le hachage, mais aucun bloc ne se choisit sur eux au signataire, hors r ∈ F_poly
 *     (probabilité 2^-33 par point : défi public) ;
 *  2. génération de clé avec des aléas différents : même trace attendue ;
 *  3. fonctions masquées appelées directement avec des secrets différents : simuler (part),
 *     mat_vec_ct (x_A) : même trace attendue ;
 *  4. témoin positif : le chemin direct (colonnes sautées) doit, lui, changer de trace.
 * Ce contrôle couvre le flot de contrôle de sig.c ; les adresses mémoire le sont par
 * tests/test_c_sig_valgrind.py.
 *     build/sig_flux   (depuis la racine) → resultats/sig_flux.json
 */
#include <omp.h>

#include "sig.c"
#include "resultat.h"

extern uint64_t trace_h, trace_n;

void trace_debut(void);
void trace_fin(void);
void alea_rejouer(uint64_t graine);

int main(void)
{
    resultat_t res = {.nom = "sig_flux"};
    omp_set_num_threads(1);          /* la trace n'est pas atomique */
    sl_init();
    int niv = 0;
    const sp_t *p = &SP[niv];
    size_t spk, ssk, smax, sl = 0, Lp = L_PART(p), rw = NW(p->r);
    sl_sig_tailles(niv, &spk, &ssk, &smax);
    uint8_t *pk = malloc(spk), *sk = malloc(ssk), *sig = malloc(smax), msg[32] = "message";
    tables(niv);                                       /* construites une fois, hors trace */
    /* 1. signature : même aléa, clés différentes */
    uint64_t h0 = 0, n0 = 0;
    int ok_sign = 1, cles = 0;
    for (int c = 0; c < 6; c++) {
        alea_rejouer(1000 + (uint64_t)c);
        sl_sig_keygen(niv, pk, sk);                    /* clé c (H' commune : graine = aléa rejoué ensuite) */
        if (c == 5) {                                  /* x_A concentré dans les premières positions */
            memset(sk, 0, XB(p));
            for (uint32_t k = 0; k < p->w; k++) sk[k >> 3] |= (uint8_t)(1 << (k & 7));
        }
        memset(pk, 0x5a, 32);                          /* même graine de H' pour toutes les signatures */
        alea_rejouer(77);
        /* appel indirect : sinon gcc ≥ 14 peut dupliquer ce corps de boucle pour c == 5 et y inliner
         * sl_sig_sign : le premier bloc changerait d'adresse, sans aucun rapport avec la clé */
        static int (*volatile signer)(int, const uint8_t *, const uint8_t *, const uint8_t *, size_t, uint8_t *, size_t *) = sl_sig_sign;
        trace_debut();
        signer(niv, sk, pk, msg, sizeof msg, sig, &sl);
        trace_fin();
        if (c == 0) { h0 = trace_h; n0 = trace_n; }
        else ok_sign &= trace_h == h0 && trace_n == n0;
        cles++;
    }
    res_mesure(&res, "signature", "{\"cles\": %d, \"blocs_executes\": %llu}", cles, (unsigned long long)n0);
    res_controle(&res, "signature_flot_independant_de_la_cle_secrete", ok_sign);
    /* 2. génération de clé : aléas différents */
    int ok_kg = 1;
    for (int c = 0; c < 6; c++) {
        alea_rejouer(5000 + (uint64_t)c);
        trace_debut();
        sl_sig_keygen(niv, pk, sk);
        trace_fin();
        if (c == 0) { h0 = trace_h; n0 = trace_n; }
        else ok_kg &= trace_h == h0 && trace_n == n0;
    }
    res_controle(&res, "generation_de_cle_flot_independant_du_secret", ok_kg);
    /* 3. fonctions masquées, appel direct */
    alea_t g;
    alea_init(&g, 99);
    uint8_t *part = malloc(Lp), seedH[32] = {1}, y[NB(1229)] = {0};
    const uint64_t *H = matrice(niv, seedH);
    tables(niv);
    prep_t Pr;
    Pr.L = malloc(8 * (size_t)p->t * p->n);
    Pr.pw = malloc(8 * (size_t)p->t * p->w);
    uint64_t r[T_MAX], eps[T_MAX], oa[T_MAX], ob[T_MAX], x1[T_MAX], x2[T_MAX], x3[T_MAX], acc[NW(1229) + 1];
    for (uint32_t j = 0; j < p->t; j++) {
        uint64_t m = (1ULL << p->ep) - 1;
        r[j] = alea64(&g) & m; eps[j] = alea64(&g) & m; oa[j] = alea64(&g) & m; ob[j] = alea64(&g) & m;
    }
    preparer(niv, r, &Pr);
    uint64_t hs[8], hv[8];                             /* comparés après : un test sur c ferait dupliquer la boucle par gcc */
    int ok_sim = 1, ok_mv = 1;
    for (int c = 0; c < 8; c++) {
        for (size_t i = 0; i < Lp; i++) part[i] = (uint8_t)alea64(&g);
        masquer_part(p, part);
        trace_debut(); simuler(niv, part, H, y, eps, &Pr, 1, oa, ob, x1, x2, x3); trace_fin();
        hs[c] = trace_h;
        trace_debut(); mat_vec_ct(p, H, part, acc); trace_fin();
        hv[c] = trace_h;
    }
    for (int c = 1; c < 8; c++) {
        ok_sim &= hs[c] == hs[0];
        ok_mv &= hv[c] == hv[0];
    }
    res_controle(&res, "simuler_flot_independant_de_la_part", ok_sim);
    res_controle(&res, "mat_vec_ct_flot_independant_de_x", ok_mv);
    /* 4. témoin positif : colonnes sautées selon les bits */
    uint64_t t1 = 0, t2 = 0;
    for (int c = 0; c < 2; c++) {
        for (size_t i = 0; i < XB(p); i++) part[i] = (uint8_t)alea64(&g);
        trace_debut();
        memset(acc, 0, sizeof acc);
        for (uint32_t j = 0; j < p->k; j++) {
            if (part[j >> 3] >> (j & 7) & 1)
                for (size_t q = 0; q < rw; q++)
                    acc[q] ^= H[(size_t)j * rw + q];
        }
        trace_fin();
        if (c == 0) t1 = trace_h; else t2 = trace_h;
    }
    res_controle(&res, "temoin_chemin_direct_detecte", t1 != t2);
    return res_ecrire(&res);
}
