/* SILLAGE C — benchmark (un cœur) : chiffrement d'éléments de tailles et
 * de natures différentes, KEM, signature. Sortie JSON sur stdout
 * (exploitée par tests/bench_c.py). Chaque aller-retour est vérifié.
 *     ./bench [taille_max_octets]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <omp.h>

#include "sillage.h"

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + 1e-9 * t.tv_nsec;
}

/* meilleur temps moyen par opération sur 3 séries d'au moins 0,1 s */
#define MESURE(res, code)                                                   \
    do {                                                                    \
        double best_ = 1e30;                                                \
        for (int rep_ = 0; rep_ < 3; rep_++) {                              \
            long it_ = 0;                                                   \
            double t0_ = maintenant(), t_;                                  \
            do { code; it_++; t_ = maintenant() - t0_; }                    \
            while (t_ < 0.1 || it_ < 3);                                    \
            if (t_ / it_ < best_) best_ = t_ / it_;                         \
        }                                                                   \
        (res) = best_;                                                      \
    } while (0)

static void contenu(int nature, uint8_t *m, size_t n)
{
    static const char *texte = "Le sillage d'un navire s'efface lentement sur la mer calme. ";
    char tmp[64];
    size_t i = 0;
    switch (nature) {
    case 0: for (; i < n; i++) m[i] = (uint8_t)texte[i % strlen(texte)]; break;
    case 1: sl_alea(m, n); break;
    case 2: memset(m, 0, n); break;
    default:
        while (i < n) {
            int k = snprintf(tmp, sizeof tmp, "{\"id\":%zu,\"val\":%zu,\"ok\":true},", i, (i * 7919) % 1000);
            for (int j = 0; j < k && i < n; j++) m[i++] = (uint8_t)tmp[j];
        }
    }
}

static const char *NATURE[4] = {"texte", "aleatoire", "zeros", "json"};

int main(int argc, char **argv)
{
    size_t tmax = argc > 1 ? (size_t)atoll(argv[1]) : (size_t)16 << 20;
    static const size_t TAILLES[] = {0, 16, 64, 256, 1024, 4096, 16384, 65536, 262144,
                                     1048576, 4194304, 16777216};
    sl_init();
    uint8_t cle[64], nonce[SL_NONCE], tag[32], tag2[32], meta[8], ss[64], ss2[64];
    sl_alea(cle, 64);
    sl_alea(nonce, SL_NONCE);
    double t;
    printf("{\n");

    /* permutation seule */
    uint8_t etat[64] = {0};
    MESURE(t, sl_brume_permute(etat));
    printf(" \"permutation_us\": %.4f,\n", 1e6 * t);
    MESURE(t, sl_brume_permute_ref(etat));
    printf(" \"permutation_ref_us\": %.4f,\n", 1e6 * t);
    {
        static uint8_t lot[32][64];
        MESURE(t, sl_brume_permute_lot(lot));
        printf(" \"permutation_lot_us_par_etat\": %.4f,\n", 1e6 * t / 32);
    }

    /* petits messages : clé passée à chaque appel ou contexte de clé */
    {
        uint8_t m64[64] = {0}, c64[64], t64[16];
        sl_aead_cle_t ctx;
        double ta, tb;
        MESURE(ta, sl_aead_encrypt(0, cle, nonce, NULL, 0, m64, 64, c64, t64));
        sl_aead_cle(&ctx, 0, cle);
        MESURE(tb, sl_aead_encrypt_ctx(&ctx, nonce, NULL, 0, m64, 64, c64, t64));
        printf(" \"aead64_us\": %.4f, \"aead64_ctx_us\": %.4f,\n", 1e6 * ta, 1e6 * tb);
    }

    /* AEAD multi-messages : n messages indépendants de taille S, 32 Mio au total */
    printf(" \"multi\": [");
    static const size_t TM[] = {64, 1024, 16384, 1048576};
    int nth = omp_get_max_threads();
    for (int ti = 0; ti < 4; ti++) {
        size_t S = TM[ti], n = ((size_t)32 << 20) / S;
        uint8_t *dat = malloc(n * S), *chf = malloc(n * S), *cl = malloc(64 * n), *no = malloc(SL_NONCE * n),
                *tg = malloc(32 * n), *hs = malloc(32 * n);
        const uint8_t **pp = malloc(n * sizeof *pp);
        uint8_t **cp = malloc(n * sizeof *cp);
        size_t *ln = malloc(n * sizeof *ln);
        sl_alea(dat, n * S); sl_alea(cl, 64 * n); sl_alea(no, SL_NONCE * n);
        for (size_t i = 0; i < n; i++) { pp[i] = dat + i * S; cp[i] = chf + i * S; ln[i] = S; }
        double t1, tn, th;
        omp_set_num_threads(1);
        MESURE(t1, sl_aead_encrypt_multi(0, n, cl, no, NULL, NULL, pp, ln, cp, tg));
        omp_set_num_threads(nth);
        MESURE(tn, sl_aead_encrypt_multi(0, n, cl, no, NULL, NULL, pp, ln, cp, tg));
        MESURE(th, sl_hash_multi(n, pp, ln, hs, 32));
        int ok = 1;                       /* contrôle : un message au hasard */
        uint8_t *c1 = malloc(S), t2[16];
        size_t j = n / 3;
        sl_aead_encrypt(0, cl + 64 * j, no + SL_NONCE * j, NULL, 0, pp[j], S, c1, t2);
        ok = !memcmp(c1, cp[j], S) && !memcmp(t2, tg + 16 * j, 16);
        sl_aead_encrypt_multi(0, n, cl, no, NULL, NULL, pp, ln, cp, tg);
        ok &= !memcmp(c1, cp[j], S) && !memcmp(t2, tg + 16 * j, 16);
        double tcc;                       /* même clé pour tous : contexte précalculé */
        sl_aead_cle_t ctx;
        sl_aead_cle(&ctx, 0, cl);
        MESURE(tcc, sl_aead_encrypt_multi_ctx(&ctx, n, no, NULL, NULL, pp, ln, cp, tg));
        sl_aead_encrypt(0, cl, no + SL_NONCE * j, NULL, 0, pp[j], S, c1, t2);     /* contrôle, clé commune */
        ok &= !memcmp(c1, cp[j], S) && !memcmp(t2, tg + 16 * j, 16);
        printf("%s\n  {\"taille\": %zu, \"messages\": %zu, \"mo_s_1_coeur\": %.1f, \"mo_s_tous\": %.1f, "
               "\"hachage_mo_s_tous\": %.1f, \"mo_s_tous_cle_commune\": %.1f, \"threads\": %d, \"ok\": %s}",
               ti ? "," : "", S, n, n * S / t1 / 1e6, n * S / tn / 1e6, n * S / th / 1e6, n * S / tcc / 1e6,
               nth, ok ? "true" : "false");
        fflush(stdout);
        free(c1); free(hs); free(dat); free(chf); free(cl); free(no); free(tg); free(pp); free(cp); free(ln);
    }
    printf("\n ],\n");

    /* AEAD parallèle d'un seul message, contre le séquentiel */
    printf(" \"aead_p\": [");
    size_t TP[4] = {16 << 10, 256 << 10, 1 << 20, 16 << 20};
    for (int ti = 0; ti < 4; ti++) {
        size_t S = TP[ti];
        uint8_t *x = malloc(S), *y = malloc(S), kp[64] = {1}, np[SL_NONCE] = {2}, tp[32];
        sl_alea(x, S);
        double ts, t1, tn;
        MESURE(ts, sl_aead_encrypt(0, kp, np, NULL, 0, x, S, y, tp));
        omp_set_num_threads(1);
        MESURE(t1, sl_aead_p_encrypt(0, kp, np, NULL, 0, x, S, y, tp));
        omp_set_num_threads(nth);
        MESURE(tn, sl_aead_p_encrypt(0, kp, np, NULL, 0, x, S, y, tp));
        printf("%s\n  {\"taille\": %zu, \"sequentiel_mo_s\": %.1f, \"p_mo_s_1_coeur\": %.1f, \"p_mo_s_tous\": %.1f, \"threads\": %d}",
               ti ? "," : "", S, S / ts / 1e6, S / t1 / 1e6, S / tn / 1e6, nth);
        fflush(stdout);
        free(x); free(y);
    }
    printf("\n ],\n");

    /* hachage arborescent d'un seul gros message (feuilles en parallèle) */
    printf(" \"arbre\": [");
    size_t TA[2] = {1 << 20, 16 << 20};
    for (int ti = 0; ti < 2; ti++) {
        size_t S = TA[ti];
        uint8_t *x = malloc(S), h1[32], h2[32];
        sl_alea(x, S);
        double ts, t1, tn;
        MESURE(ts, sl_hash(x, S, h1, 32));
        omp_set_num_threads(1);
        MESURE(t1, sl_hash_arbre(x, S, h1, 32));
        omp_set_num_threads(nth);
        MESURE(tn, sl_hash_arbre(x, S, h2, 32));
        printf("%s\n  {\"taille\": %zu, \"sequentiel_mo_s\": %.1f, \"arbre_mo_s_1_coeur\": %.1f, "
               "\"arbre_mo_s_tous\": %.1f, \"threads\": %d, \"ok\": %s}",
               ti ? "," : "", S, S / ts / 1e6, S / t1 / 1e6, S / tn / 1e6, nth, memcmp(h1, h2, 32) ? "false" : "true");
        fflush(stdout);
        free(x);
    }
    printf("\n ],\n");

    /* KEM */
    omp_set_num_threads(1);
    printf(" \"kem\": {");
    for (int niv = 0; niv < 2; niv++) {
        size_t lpk, lsk, lct, lss;
        sl_kem_tailles(niv, &lpk, &lsk, &lct, &lss);
        uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *ct = malloc(lct);
        uint8_t *pk2 = malloc(lpk), *sk2 = malloc(lsk);
        double tk, te, td, tf;
        sl_kem_keygen(niv, pk2, sk2);
        MESURE(tk, sl_kem_keygen(niv, pk, sk));
        MESURE(te, sl_kem_encaps(niv, pk, ct, ss));
        MESURE(td, sl_kem_decaps(niv, sk, ct, ss2));
        int ok = !memcmp(ss, ss2, lss), bascule = 0;
        /* clé publique changeante (un serveur qui répond à plusieurs clients) : h et π à recalculer */
        MESURE(tf, sl_kem_encaps(niv, (bascule ^= 1) ? pk2 : pk, ct, ss));
        printf("%s\n  \"%s\": {\"keygen_ms\": %.4f, \"encaps_ms\": %.4f, \"decaps_ms\": %.4f, "
               "\"encaps_pk_changeante_ms\": %.4f, \"pk\": %zu, \"ct\": %zu, \"ok\": %s}", niv ? "," : "",
               niv ? "Sillage-256" : "Sillage-128", 1e3 * tk, 1e3 * te, 1e3 * td, 1e3 * tf, lpk, lct, ok ? "true" : "false");
        free(pk); free(sk); free(ct); free(pk2); free(sk2);
    }
    printf("\n },\n");

    /* SIG */
    printf(" \"sig\": {");
    for (int niv = 0; niv < 2; niv++) {
        size_t lpk, lsk, lmax, ls = 0;
        sl_sig_tailles(niv, &lpk, &lsk, &lmax);
        uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *sig = malloc(lmax), msg[32] = "message";
        double tk, ts, tv;
        int ok = 1;
        MESURE(tk, sl_sig_keygen(niv, pk, sk));
        MESURE(ts, sl_sig_sign(niv, sk, pk, msg, 32, sig, &ls));
        MESURE(tv, ok &= sl_sig_verify(niv, pk, msg, 32, sig, ls));
        omp_set_num_threads(nth);
        double tsn, tvn;
        MESURE(tsn, sl_sig_sign(niv, sk, pk, msg, 32, sig, &ls));
        MESURE(tvn, ok &= sl_sig_verify(niv, pk, msg, 32, sig, ls));
        omp_set_num_threads(1);
        printf("%s\n  \"%s\": {\"keygen_ms\": %.4f, \"sign_ms\": %.4f, \"verify_ms\": %.4f, "
               "\"sign_tous_les_coeurs_ms\": %.4f, \"verify_tous_les_coeurs_ms\": %.4f, "
               "\"sig\": %zu, \"ok\": %s}", niv ? "," : "", niv ? "Sillage-SIG-256" : "Sillage-SIG-128",
               1e3 * tk, 1e3 * ts, 1e3 * tv, 1e3 * tsn, 1e3 * tvn, ls, ok ? "true" : "false");
        free(pk); free(sk); free(sig);
    }
    printf("\n },\n");

    /* tailles × natures */
    size_t lpk, lsk, lct, lss;
    sl_kem_tailles(0, &lpk, &lsk, &lct, &lss);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *ckem = malloc(lct);
    sl_kem_keygen(0, pk, sk);
    printf(" \"tailles\": [");
    int prem = 1;
    for (int nat = 0; nat < 4; nat++)
        for (size_t ti = 0; ti < sizeof TAILLES / sizeof *TAILLES && TAILLES[ti] <= tmax; ti++) {
            size_t n = TAILLES[ti];
            uint8_t *m = malloc(n + 1), *c = malloc(n + 1), *p = malloc(n + 1), *c2 = malloc(n + 1);
            uint8_t *par = malloc(sl_te_par_len(n) + 1);
            size_t corr[64], nc = 0;     /* un seul octet abîmé → une correction */
            contenu(nat, m, n);
            int ok = 1;
            double th, ta, tad, t256, tte, tted = 0, th2, tkd;
            /* hybride : encapsulation + dérivation de clé + AEAD (comme bench_tailles.py) */
            uint8_t k64[64];
            const uint8_t *parts[1] = {ss};
            size_t lens[1] = {32};
            MESURE(th, sl_kem_encaps(0, pk, ckem, ss));
            sl_shake_dom("SILLAGE|brume-key", NULL, 0, parts, lens, 1, k64, 64);
            MESURE(ta, sl_aead_encrypt(0, k64, nonce, (const uint8_t *)"hdr", 3, m, n, c, tag));
            MESURE(tkd, sl_kem_decaps(0, sk, ckem, ss2));
            ok &= !memcmp(ss, ss2, 32);
            MESURE(tad, ok &= sl_aead_decrypt(0, k64, nonce, (const uint8_t *)"hdr", 3, c, n, tag, p) == 0);
            ok &= !memcmp(m, p, n);
            MESURE(t256, sl_aead_encrypt(1, cle, nonce, NULL, 0, m, n, c, tag2));
            ok &= sl_aead_decrypt(1, cle, nonce, NULL, 0, c, n, tag2, p) == 0 && !memcmp(m, p, n);
            MESURE(tte, sl_te_encrypt(0, cle, nonce, NULL, 0, m, n, c, par, tag, meta));
            if (n) {                     /* un octet abîmé au milieu, corrigé */
                int okc = 1;
                MESURE(tted, {
                    memcpy(c2, c, n);
                    c2[n / 2] ^= 0x5A;
                    okc &= sl_te_decrypt(0, cle, nonce, NULL, 0, c2, n, par, sl_te_par_len(n), tag,
                                         meta, p, corr, &nc) == 0 && nc == 1 && corr[0] == n / 2;
                });
                ok &= okc && !memcmp(m, p, n);
            }
            MESURE(th2, sl_hash(m, n, k64, 32));
            printf("%s\n  {\"nature\": \"%s\", \"taille\": %zu, \"ok\": %s, \"kem_encaps_ms\": %.4f, "
                   "\"kem_decaps_ms\": %.4f, \"aead_chiffrement_ms\": %.5f, \"aead_dechiffrement_ms\": %.5f, "
                   "\"aead256_ms\": %.5f, \"te_chiffrement_ms\": %.5f, \"te_correction_ms\": %.5f, "
                   "\"hachage_ms\": %.5f, \"hybride_total_ms\": %.5f}",
                   prem ? "" : ",", NATURE[nat], n, ok ? "true" : "false", 1e3 * th, 1e3 * tkd, 1e3 * ta,
                   1e3 * tad, 1e3 * t256, 1e3 * tte, 1e3 * tted, 1e3 * th2, 1e3 * (th + ta));
            fflush(stdout);
            prem = 0;
            free(m); free(c); free(p); free(c2); free(par);
        }
    printf("\n ]\n}\n");
    return 0;
}
