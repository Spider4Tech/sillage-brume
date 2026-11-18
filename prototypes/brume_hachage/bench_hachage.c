/* Bench comparatif du prototype brume_hachage : le même programme, lié une fois à la couche SHAKE256 de la bibliothèque
 * et une fois à hachage_brume.c (c = 384 ou 512). Mesure les primitives de hachage, le KEM Sillage-256, la signature
 * VOLE-256 / VOLE-256f et la signature v0.4 ; vérifie chaque aller-retour, et refuse une signature altérée.
 * Sortie JSON sur stdout. Temps : meilleur temps moyen sur 3 séries d'au moins 0,1 s (comme sillage/c/bench.c). */
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sillage.h"

/* fournis par hachage_brume.c seulement */
unsigned long sl_hachage_permutations(void) __attribute__((weak));
int sl_hachage_capacite(void) __attribute__((weak));

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + 1e-9 * t.tv_nsec;
}

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

static unsigned long nperm(void) { return sl_hachage_permutations ? sl_hachage_permutations() : 0; }
#define PERMS(var, code) do { unsigned long a_ = nperm(); code; (var) = nperm() - a_; } while (0)

int main(void)
{
    sl_init();
    int nth = omp_get_max_threads();
    const char *var = sl_hachage_capacite ? (sl_hachage_capacite() == 512 ? "brume1024q-c512" : "brume1024q-c384") : "shake256";
    int ok_tout = 1;
    printf("{\n \"variante\": \"%s\", \"threads\": %d,\n", var, nth);

    /* contrôle de l'éponge : à c = 384, la couche de hachage EST le XOF de la bibliothèque (KAT de la SPEC § 4) */
    if (sl_hachage_capacite && sl_hachage_capacite() == 384) {
        static const size_t L[] = {0, 1, 63, 64, 79, 80, 81, 159, 160, 1000};
        int ok = 1;
        for (size_t i = 0; i < sizeof L / sizeof *L; i++) {
            uint8_t m[1000], a[200], b[200];
            for (size_t k = 0; k < L[i]; k++) m[k] = (uint8_t)(k * 31 + 7);
            sl_shake256(m, L[i], a, 200);
            sl_xof(m, L[i], b, 200);
            ok &= !memcmp(a, b, 200);
        }
        printf(" \"eponge_egale_sl_xof\": %s,\n", ok ? "true" : "false");
        ok_tout &= ok;
    }

    /* primitives (un cœur) */
    omp_set_num_threads(1);
    {
        static uint8_t gros[1 << 16];
        uint8_t in[64] = {1}, out[64];
        const uint8_t *parts[1] = {in};
        size_t lens[1] = {64};
        double t_dom, t_abs, t_sq, t_flux;
        MESURE(t_dom, sl_shake_dom("SILLAGE-KEM|ss", NULL, 0, parts, lens, 1, out, 32));
        MESURE(t_abs, sl_shake256(gros, sizeof gros, out, 32));
        sl_shake_t h;
        sl_shake_init(&h);
        sl_shake_final(&h);
        MESURE(t_sq, sl_shake_squeeze(&h, gros, sizeof gros));
        sl_flux_t f;
        sl_flux_init(&f, "SILLAGE-KEM|pi", in, 32);
        volatile uint32_t puits = 0;
        MESURE(t_flux, for (int i = 0; i < 16384; i++) puits ^= sl_flux_next(&f));
        (void)puits;
        unsigned long p_dom;
        PERMS(p_dom, sl_shake_dom("SILLAGE-KEM|ss", NULL, 0, parts, lens, 1, out, 32));
        printf(" \"primitives\": {\"hash_64o_vers_32o_us\": %.4f, \"absorption_mo_s\": %.1f, \"extraction_mo_s\": %.1f, "
               "\"flux_mo_s\": %.1f, \"permutations_hash_64o\": %lu},\n",
               1e6 * t_dom, sizeof gros / t_abs / 1e6, sizeof gros / t_sq / 1e6, 65536 / t_flux / 1e6, p_dom);
    }

    /* KEM Sillage-256 (niveau 1), un cœur */
    {
        size_t lpk, lsk, lct, lss;
        sl_kem_tailles(1, &lpk, &lsk, &lct, &lss);
        uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *ct = malloc(lct), *pk2 = malloc(lpk), *sk2 = malloc(lsk);
        uint8_t ss[64], ss2[64];
        double tk, te, td, tf;
        unsigned long pk_, pe_, pd_;
        sl_kem_keygen(1, pk2, sk2);
        MESURE(tk, sl_kem_keygen(1, pk, sk));
        MESURE(te, sl_kem_encaps(1, pk, ct, ss));
        MESURE(td, sl_kem_decaps(1, sk, ct, ss2));
        int ok = !memcmp(ss, ss2, lss), bascule = 0;
        MESURE(tf, sl_kem_encaps(1, (bascule ^= 1) ? pk2 : pk, ct, ss));
        PERMS(pk_, sl_kem_keygen(1, pk, sk));
        PERMS(pe_, sl_kem_encaps(1, pk, ct, ss));
        PERMS(pd_, sl_kem_decaps(1, sk, ct, ss2));
        ok &= !memcmp(ss, ss2, lss);
        ct[0] ^= 1;                                   /* rejet implicite : un autre secret */
        sl_kem_decaps(1, sk, ct, ss2);
        ok &= memcmp(ss, ss2, lss) != 0;
        ok_tout &= ok;
        printf(" \"kem\": {\"Sillage-256\": {\"keygen_ms\": %.4f, \"encaps_ms\": %.4f, \"decaps_ms\": %.4f, "
               "\"encaps_pk_changeante_ms\": %.4f, \"permutations\": {\"keygen\": %lu, \"encaps\": %lu, \"decaps\": %lu}, "
               "\"ok\": %s}},\n", 1e3 * tk, 1e3 * te, 1e3 * td, 1e3 * tf, pk_, pe_, pd_, ok ? "true" : "false");
        free(pk); free(sk); free(ct); free(pk2); free(sk2);
    }

    /* signature VOLE (v0.5) : profils 1 (VOLE-256) et 3 (VOLE-256f) */
    printf(" \"vole\": {");
    static const int PV[2] = {1, 3};
    for (int i = 0; i < 2; i++) {
        int pr = PV[i];
        size_t lpk, lsk, lsig;
        sl_vole_tailles(pr, &lpk, &lsk, &lsig);
        uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *sig = malloc(lsig), msg[32] = "message";
        double tk, ts, tv, tsn, tvn;
        unsigned long ps_, pv_;
        int ok = 1;
        omp_set_num_threads(1);
        MESURE(tk, sl_vole_keygen(pr, pk, sk));
        MESURE(ts, sl_vole_sign(pr, sk, msg, 32, sig));
        MESURE(tv, ok &= sl_vole_verify(pr, pk, msg, 32, sig, lsig) == 1);
        PERMS(ps_, sl_vole_sign(pr, sk, msg, 32, sig));
        PERMS(pv_, ok &= sl_vole_verify(pr, pk, msg, 32, sig, lsig) == 1);
        omp_set_num_threads(nth);
        MESURE(tsn, sl_vole_sign(pr, sk, msg, 32, sig));
        MESURE(tvn, ok &= sl_vole_verify(pr, pk, msg, 32, sig, lsig) == 1);
        sig[lsig / 2] ^= 1;
        ok &= sl_vole_verify(pr, pk, msg, 32, sig, lsig) == 0;
        ok_tout &= ok;
        printf("%s\n  \"%s\": {\"keygen_ms\": %.4f, \"sign_ms\": %.4f, \"verify_ms\": %.4f, "
               "\"sign_tous_les_coeurs_ms\": %.4f, \"verify_tous_les_coeurs_ms\": %.4f, "
               "\"permutations\": {\"sign\": %lu, \"verify\": %lu}, \"sig\": %zu, \"ok\": %s}",
               i ? "," : "", pr == 1 ? "VOLE-256" : "VOLE-256f", 1e3 * tk, 1e3 * ts, 1e3 * tv, 1e3 * tsn, 1e3 * tvn,
               ps_, pv_, lsig, ok ? "true" : "false");
        free(pk); free(sk); free(sig);
    }
    printf("\n },\n");

    /* signature v0.4 (référence conservée dans la bibliothèque) */
    printf(" \"sig_v04\": {");
    for (int niv = 0; niv < 2; niv++) {
        size_t lpk, lsk, lmax, ls = 0;
        sl_sig_tailles(niv, &lpk, &lsk, &lmax);
        uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *sig = malloc(lmax), msg[32] = "message";
        double tk, ts, tv, tsn;
        int ok = 1;
        omp_set_num_threads(1);
        MESURE(tk, sl_sig_keygen(niv, pk, sk));
        MESURE(ts, sl_sig_sign(niv, sk, pk, msg, 32, sig, &ls));
        MESURE(tv, ok &= sl_sig_verify(niv, pk, msg, 32, sig, ls) == 1);
        omp_set_num_threads(nth);
        MESURE(tsn, sl_sig_sign(niv, sk, pk, msg, 32, sig, &ls));
        sig[ls / 2] ^= 1;
        ok &= sl_sig_verify(niv, pk, msg, 32, sig, ls) != 1;
        ok_tout &= ok;
        printf("%s\n  \"%s\": {\"keygen_ms\": %.4f, \"sign_ms\": %.4f, \"verify_ms\": %.4f, "
               "\"sign_tous_les_coeurs_ms\": %.4f, \"sig\": %zu, \"ok\": %s}", niv ? "," : "",
               niv ? "Sillage-SIG-256" : "Sillage-SIG-128", 1e3 * tk, 1e3 * ts, 1e3 * tv, 1e3 * tsn, ls, ok ? "true" : "false");
        free(pk); free(sk); free(sig);
    }
    printf("\n },\n \"ok\": %s\n}\n", ok_tout ? "true" : "false");
    return !ok_tout;
}
