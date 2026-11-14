/* Banc comparatif : BRUME-1024q (prototype, c = 384, 32 tours, 128 bits quantiques visés) contre la suite classique
 * (BRUME-512, c = 256, et BRUME-512-256, c = 384, via l'API publique de sillage/c). Mêmes messages, même machine, même
 * compilation ; médiane de 9 séries ; chaque série dure au moins ~50 ms.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/bench_comparatif.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c \
 *      -lm -o tests/c/build/bench_comparatif && tests/c/build/bench_comparatif   → resultats/bench_comparatif_1024q.json
 */
#include "brume1024.c"

#define NS 9

static double med(double *t)
{
    return mediane(t, NS);
}

/* temps par appel (ns) d'une opération, médiane de NS séries d'au moins ~50 ms */
#define CHRONO(res_ns, CODE)                                                                   \
    do {                                                                                       \
        long n_ = 1;                                                                           \
        for (;;) {                                                                             \
            double t0_ = maintenant();                                                         \
            for (long i_ = 0; i_ < n_; i_++) { CODE; }                                         \
            if (maintenant() - t0_ > 0.05) break;                                              \
            n_ *= 2;                                                                           \
        }                                                                                      \
        double tt_[NS];                                                                        \
        for (int s_ = 0; s_ < NS; s_++) {                                                      \
            double t0_ = maintenant();                                                         \
            for (long i_ = 0; i_ < n_; i_++) { CODE; }                                         \
            tt_[s_] = (maintenant() - t0_) / n_ * 1e9;                                         \
        }                                                                                      \
        res_ns = med(tt_);                                                                     \
    } while (0)

static char js[1 << 16];
static size_t lj;
static void ligne(const char *op, size_t taille, double suite, double suite_c384, double q)   /* suite_c384 : 2e colonne de la suite */
{
    const char *u = taille >= 65536 ? "Mo/s" : "ns";
    if (taille >= 65536) {
        printf("| %-34s | %9zu | %10.1f | %10.1f | %10.1f | ×%.2f |\n", op, taille, suite, suite_c384, q, q / suite);
    } else {
        printf("| %-34s | %9zu | %10.0f | %10.0f | %10.0f | ×%.2f |\n", op, taille, suite, suite_c384, q, suite / q);
    }
    lj += (size_t)snprintf(js + lj, sizeof js - lj, "%s{\"operation\":\"%s\",\"octets\":%zu,\"unite\":\"%s\",\"suite_c256\":%.2f,"
                           "\"suite_c384\":%.2f,\"brume1024q\":%.2f}", lj > 1 ? "," : "", op, taille, u, suite, suite_c384, q);
}

int main(void)
{
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    prepare_iv();
    sl_init();
    const int ncoeurs = omp_get_num_procs();
    size_t TM = (size_t)64 << 20;
    uint8_t *m = malloc(TM), *c = malloc(TM), h[64], tag[32];
    for (size_t i = 0; i < TM; i++)
        m[i] = (uint8_t)(i * 2654435761u >> 13);
    uint8_t cle[64], nonce[24];
    memcpy(cle, m, 64);
    memcpy(nonce, m + 64, 24);
    lj = (size_t)snprintf(js, sizeof js, "[");
    printf("Machine : %d threads. Suite : BRUME-512 (c = 256, 128 bits classiques) et BRUME-512-256 (c = 384) ; "
           "BRUME-1024q : c = 384, 32 tours (128 bits quantiques visés).\n", ncoeurs);
    printf("Latences en ns par appel (ratio = suite / 1024q : > 1 si 1024q est plus rapide) ; débits en Mo/s (ratio = 1024q / suite).\n\n");
    printf("| %-34s | %9s | %10s | %10s | %10s | %s |\n", "Opération (ns)", "Octets", "Suite", "Suite (2)", "1024q", "Ratio");
    printf("|---|---|---|---|---|---|\n");
    double a, b, q;
    /* permutation */
    uint8_t e5[64] = {1}, e1[128] = {2};
    CHRONO(a, sl_brume_permute(e5));
    CHRONO(q, perm1(e1, R1));
    ligne("permutation (1 état)", 0, a, a, q);
    /* hachage court : suite sl_hash (sortie 32 o, défaut), 1024q hachage par défaut (sortie 64 o) */
    const size_t courts[] = {0, 64, 256, 1024, 4096};
    for (int k = 0; k < 5; k++) {
        size_t L = courts[k];
        CHRONO(a, sl_hash(m, L, h, 32));
        CHRONO(b, sl_hash(m, L, h, 64));
        CHRONO(q, arbre(m, L, h, 64, 1));
        char nom[64];
        snprintf(nom, sizeof nom, "hachage : suite 32 o | (2) 64 o");
        ligne(nom, L, a, b, q);
    }
    /* AEAD court : suite profil 0 (c = 256) et 1 (c = 384), 1024q */
    const size_t ac[] = {0, 64, 1024, 4096};
    for (int k = 0; k < 4; k++) {
        size_t L = ac[k];
        CHRONO(a, sl_aead_encrypt(0, cle, nonce, m, 16, m, L, c, tag));
        CHRONO(b, sl_aead_encrypt(1, cle, nonce, m, 16, m, L, c, tag));
        CHRONO(q, aead(perm1, cle, nonce, m, 16, m, L, 0, c, tag));
        ligne("AEAD : suite c256 | (2) c384", L, a, b, q);
    }
    printf("\n");
    printf("| %-34s | %9s | %10s | %10s | %10s | %s |\n", "Débit (Mo/s)", "Octets", "Suite", "Suite (2)", "1024q", "Ratio");
    printf("|---|---|---|---|---|---|\n");
    /* débits longs */
    size_t L1 = (size_t)1 << 20, L2 = (size_t)64 << 20;
    CHRONO(a, sl_hash(m, L1, h, 32));
    CHRONO(q, eponge(m, L1, DOM_SEQ, h, 64));
    ligne("éponge séquentielle, 1 cœur", L1, L1 / a * 1e3, L1 / a * 1e3, L1 / q * 1e3);
    omp_set_num_threads(1);
    CHRONO(a, sl_hash_arbre(m, (size_t)16 << 20, h, 32));
    CHRONO(q, arbre(m, (size_t)16 << 20, h, 64, 1));
    ligne("arbre, 1 cœur", (size_t)16 << 20, ((size_t)16 << 20) / a * 1e3, ((size_t)16 << 20) / a * 1e3, ((size_t)16 << 20) / q * 1e3);
    omp_set_num_threads(ncoeurs);
    CHRONO(a, sl_hash_arbre(m, L2, h, 32));
    CHRONO(q, arbre(m, L2, h, 64, 1));
    char nom[64];
    snprintf(nom, sizeof nom, "arbre, %d threads", ncoeurs);
    ligne(nom, L2, L2 / a * 1e3, L2 / a * 1e3, L2 / q * 1e3);
    CHRONO(a, sl_aead_encrypt(0, cle, nonce, m, 16, m, L1, c, tag));
    CHRONO(b, sl_aead_encrypt(1, cle, nonce, m, 16, m, L1, c, tag));
    CHRONO(q, aead(perm1, cle, nonce, m, 16, m, L1, 0, c, tag));
    ligne("AEAD 1 cœur : c256 | (2) c384", L1, L1 / a * 1e3, L1 / b * 1e3, L1 / q * 1e3);
    snprintf(js + lj, sizeof js - lj, "]");
    FILE *f = fopen("resultats/bench_comparatif_1024q.json", "w");
    if (f) {
        fprintf(f, "{\"threads\": %d, \"tours_1024q\": %d, \"mesures\": %s, \"empreinte\": %u}\n", ncoeurs, R1, js,
                (unsigned)(h[0] ^ tag[0] ^ c[0] ^ e5[0] ^ e1[0]));
        fclose(f);
    }
    free(m);
    free(c);
    return 0;
}
