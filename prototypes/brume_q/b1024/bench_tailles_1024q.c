/* Banc par taille, sur le modèle de resultats/BENCH_C.md : la suite classique (AEAD-128 = BRUME-512, c = 256 ;
 * AEAD-256 = BRUME-512-256, c = 384 ; sl_hash) contre BRUME-1024q (c = 384, 32 tours ; AEAD à clé dans tout l'état ;
 * hachage par défaut = arbre). Contenu aléatoire, un cœur sauf mention, médiane de 7 séries d'au moins ~0,1 s.
 * Allers-retours vérifiés (déchiffrement + tag) pour chaque taille et chaque AEAD.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/bench_tailles_1024q.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c \
 *      -lm -o tests/c/build/bench_tailles_1024q && tests/c/build/bench_tailles_1024q > resultats/BENCH_1024Q.md
 */
#include "brume1024.c"

#define NS 7

static double chrono_ns(void (*f)(void *), void *arg)
{
    long n = 1;
    for (;;) {
        double t0 = maintenant();
        for (long i = 0; i < n; i++)
            f(arg);
        if (maintenant() - t0 > 0.1)
            break;
        n *= 2;
    }
    double t[NS];
    for (int s = 0; s < NS; s++) {
        double t0 = maintenant();
        for (long i = 0; i < n; i++)
            f(arg);
        t[s] = (maintenant() - t0) / n * 1e9;
    }
    return mediane(t, NS);
}

typedef struct {
    const uint8_t *m, *cle, *nonce;
    uint8_t *c, *tag, *h;
    size_t len;
    int profil;
} arg_t;

static void f_suite(void *p) { arg_t *a = p; sl_aead_encrypt(a->profil, a->cle, a->nonce, a->m, 16, a->m, a->len, a->c, a->tag); }
static void f_q(void *p) { arg_t *a = p; aead(perm1, a->cle, a->nonce, a->m, 16, a->m, a->len, 0, a->c, a->tag); }
static void f_hs(void *p) { arg_t *a = p; sl_hash(a->m, a->len, a->h, 32); }
static void f_hq(void *p) { arg_t *a = p; arbre(a->m, a->len, a->h, 64, 1); }
static void f_hq32(void *p) { arg_t *a = p; arbre(a->m, a->len, a->h, 64, 2); }   /* sans les lots bitslicés */
static void f_es(void *p) { arg_t *a = p; sl_hash(a->m, a->len, a->h, 32); }
static void f_eq(void *p) { arg_t *a = p; eponge(a->m, a->len, DOM_SEQ, a->h, 64); }
static void f_as(void *p) { arg_t *a = p; sl_hash_arbre(a->m, a->len, a->h, 32); }

/* multi-messages */
typedef struct {
    size_t n, len;
    const uint8_t *cles, *nonces, *msgs;
    uint8_t *cts, *tags;
    const uint8_t **pp;
    uint8_t **cp;
    size_t *lens;
    int profil;
} multi_t;
static void f_ms(void *p)
{
    multi_t *a = p;
    sl_aead_encrypt_multi(a->profil, a->n, a->cles, a->nonces, NULL, NULL, a->pp, a->lens, a->cp, a->tags);
}
static void f_mq(void *p)
{
    multi_t *a = p;
    aead_multi(a->n, a->cles, a->nonces, a->msgs, 16, a->msgs, a->len, a->cts, a->tags);
}

static void tps(char *s, double ns)
{
    if (ns < 1e6)
        sprintf(s, "%.2f µs", ns / 1e3);
    else
        sprintf(s, "%.2f ms", ns / 1e6);
}

static double mios(size_t len, double ns) { return len ? len / (ns * 1e-9) / 1048576.0 : 0; }

int main(void)
{
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    sl_init();
    prepare_iv();
    const int nc = omp_get_num_procs();
    size_t TM = (size_t)32 << 20;
    uint8_t *m = malloc(TM), *c = malloc(TM), *d = malloc(TM), h[64], tag[32], tag2[32];
    alea_t g;
    alea_init(&g, 0xBE7C);
    for (size_t i = 0; i < TM; i++)
        m[i] = (uint8_t)alea64(&g);
    uint8_t cle[64], nonce[24];
    memcpy(cle, m + 7, 64);
    memcpy(nonce, m + 99, 24);
    char cpu[128] = "?";
    FILE *ci = fopen("/proc/cpuinfo", "r");
    if (ci) {
        char l[256];
        while (fgets(l, sizeof l, ci))
            if (!strncmp(l, "model name", 10)) {
                char *p = strchr(l, ':');
                snprintf(cpu, sizeof cpu, "%s", p ? p + 2 : l);
                cpu[strcspn(cpu, "\n")] = 0;
                break;
            }
        fclose(ci);
    }
    /* allers-retours */
    int ar = 1;
    const size_t T[] = {0, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216};
    const int NT = sizeof T / sizeof *T;
    for (int k = 0; k < NT; k++) {
        size_t L = T[k];
        for (int pr = 0; pr < 2; pr++) {
            sl_aead_encrypt(pr, cle, nonce, m, 16, m, L, c, tag);
            ar &= sl_aead_decrypt(pr, cle, nonce, m, 16, c, L, tag, d) == 0 && !memcmp(d, m, L);
        }
        aead(perm1, cle, nonce, m, 16, m, L, 0, c, tag);
        aead(perm1, cle, nonce, m, 16, c, L, 1, d, tag2);
        ar &= !memcmp(d, m, L) && !memcmp(tag, tag2, 32);
    }
    printf("# Benchmark par taille — BRUME-1024q (prototype) contre la suite classique\n\n");
    printf("%s, **un seul cœur** (sauf les lignes « tous les cœurs », %d threads) ; `-O3 -march=native` ; même binaire pour les "
           "deux. Allers-retours vérifiés : **%s**.\n\n", cpu, nc, ar ? "tous OK" : "ÉCHEC");
    printf("- **AEAD-128** = BRUME-512 (c = 256 : 128 bits classiques, 2^85 contre les collisions quantiques) ; **AEAD-256** = "
           "BRUME-512-256 (c = 384) ; **AEAD-1024q** = BRUME-1024q (c = 384, 32 tours, clé dans tout l'état). Clé 64 o, nonce 24 o, "
           "16 o de données associées.\n");
    printf("- **Hachage suite** = `sl_hash` (empreinte 32 o) ; **hachage 1024q** = hachage par défaut (arbre au-delà de 8 Kio, "
           "empreinte 64 o) ; tous deux sur un seul cœur dans la première table.\n\n");
    printf("## Chiffrement et hachage selon la taille (contenu aléatoire)\n\n");
    printf("| Taille | AEAD-128 | Mio/s | AEAD-256 | Mio/s | **AEAD-1024q** | **Mio/s** | 1024q / AEAD-128 | 1024q / AEAD-256 | Hachage suite | "
           "**Hachage 1024q** | 1024q / suite |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    omp_set_num_threads(1);   /* section à un seul cœur pour les deux (l'arbre de 1024q est sinon parallèle) */
    for (int k = 0; k < NT; k++) {
        arg_t a = {m, cle, nonce, c, tag, h, T[k], 0};
        double t128 = chrono_ns(f_suite, &a);
        a.profil = 1;
        double t256 = chrono_ns(f_suite, &a);
        double tq = chrono_ns(f_q, &a);
        double hs = chrono_ns(f_hs, &a), hq = chrono_ns(f_hq, &a);
        char s1[32], s2[32], s3[32], s4[32], s5[32], tl[32];
        tps(s1, t128); tps(s2, t256); tps(s3, tq); tps(s4, hs); tps(s5, hq);
        if (T[k] >= 1048576)
            sprintf(tl, "%zu Mio", T[k] >> 20);
        else if (T[k] >= 1024)
            sprintf(tl, "%zu Kio", T[k] >> 10);
        else
            sprintf(tl, "%zu o", T[k]);
        char m1[16] = "—", m2[16] = "—", m3[16] = "—";
        if (T[k]) {
            sprintf(m1, "%.2f", mios(T[k], t128));
            sprintf(m2, "%.2f", mios(T[k], t256));
            sprintf(m3, "%.2f", mios(T[k], tq));
        }
        printf("| %s | %s | %s | %s | %s | **%s** | **%s** | ×%.2f | ×%.2f | %s | **%s** | ×%.2f |\n", tl, s1, m1, s2, m2, s3, m3,
               t128 / tq, t256 / tq, s4, s5, hs / hq);
        fflush(stdout);
    }
    omp_set_num_threads(nc);
    /* multi-messages */
    printf("\n## Chiffrement multi-messages (lots bitslicés de 256 et lots de 32, 32 Mio au total, clés et nonces distincts)\n\n");
    printf("| Taille d'un message | Messages | AEAD-128, 1 cœur | AEAD-128, tous les cœurs | AEAD-256, tous les cœurs | **AEAD-1024q, 1 cœur** | "
           "**AEAD-1024q, tous les cœurs** | 1024q / AEAD-128 (tous) | 1024q / AEAD-256 (tous) |\n|---|---|---|---|---|---|---|---|---|\n");
    const size_t TMm[] = {64, 1024, 16384, 1048576};
    uint8_t *cles = malloc(64 * 524288), *nonces = malloc(24 * 524288), *tags = malloc(32 * 524288);
    for (size_t i = 0; i < 64 * 524288; i++)
        cles[i] = (uint8_t)alea64(&g);
    for (size_t i = 0; i < 24 * 524288; i++)
        nonces[i] = (uint8_t)alea64(&g);
    for (int k = 0; k < 4; k++) {
        size_t L = TMm[k], n = TM / L;
        const uint8_t **pp = malloc(sizeof(uint8_t *) * n);
        uint8_t **cp = malloc(sizeof(uint8_t *) * n);
        size_t *lens = malloc(sizeof(size_t) * n);
        for (size_t i = 0; i < n; i++) {
            pp[i] = m + i * L;
            cp[i] = c + i * L;
            lens[i] = L;
        }
        multi_t a = {n, L, cles, nonces, m, c, tags, pp, cp, lens, 0};
        omp_set_num_threads(1);
        double s1 = chrono_ns(f_ms, &a), q1 = chrono_ns(f_mq, &a);
        omp_set_num_threads(nc);
        double sn = chrono_ns(f_ms, &a), qn = chrono_ns(f_mq, &a);
        a.profil = 1;
        double sn256 = chrono_ns(f_ms, &a);
        double mo = TM / 1e6;
        char tl[32];
        if (L >= 1048576) sprintf(tl, "%zu Mio", L >> 20);
        else if (L >= 1024) sprintf(tl, "%zu Kio", L >> 10);
        else sprintf(tl, "%zu o", L);
        printf("| %s | %zu | %.0f Mo/s | %.0f Mo/s | %.0f Mo/s | **%.0f Mo/s** | **%.0f Mo/s** | ×%.2f | ×%.2f |\n", tl, n, mo / (s1 * 1e-9),
               mo / (sn * 1e-9), mo / (sn256 * 1e-9), mo / (q1 * 1e-9), mo / (qn * 1e-9), sn / qn, sn256 / qn);
        fflush(stdout);
        free(pp); free(cp); free(lens);
    }
    /* gros message */
    printf("\n## Hachage d'un seul gros message : séquentiel et arborescent\n\n");
    printf("| Taille | Suite, séquentiel | Suite, arbre 1 cœur | Suite, arbre tous les cœurs | **1024q, séquentiel** | **1024q, arbre 1 cœur** | "
           "**1024q, arbre tous les cœurs** |\n|---|---|---|---|---|---|---|\n");
    const size_t TG2[] = {1048576, 16777216};
    for (int k = 0; k < 2; k++) {
        arg_t a = {m, cle, nonce, c, tag, h, TG2[k], 0};
        double es = chrono_ns(f_es, &a), eq = chrono_ns(f_eq, &a);
        omp_set_num_threads(1);
        double as1 = chrono_ns(f_as, &a), aq1 = chrono_ns(f_hq, &a);
        omp_set_num_threads(nc);
        double asn = chrono_ns(f_as, &a), aqn = chrono_ns(f_hq, &a);
        double L = TG2[k] / 1e6;
        printf("| %zu Mio | %.0f Mo/s | %.0f Mo/s | %.0f Mo/s | **%.0f Mo/s** | **%.0f Mo/s** | **%.0f Mo/s** |\n", TG2[k] >> 20,
               L / (es * 1e-9), L / (as1 * 1e-9), L / (asn * 1e-9), L / (eq * 1e-9), L / (aq1 * 1e-9), L / (aqn * 1e-9));
        fflush(stdout);
    }
    /* arbre : lots de 32 contre lots bitslicés de 256 (priorité 2 de ROADMAP.md) */
    printf("\n## Arbre 1024q : lots de 32 états contre lots bitslicés de 256 feuilles\n\n");
    printf("| Taille | Lots de 32, 1 cœur | **Bitslicé, 1 cœur** | Gain | Lots de 32, %d threads | **Bitslicé, %d threads** | Gain |\n"
           "|---|---|---|---|---|---|---|\n", nc, nc);
    const size_t TG3[] = {(size_t)1 << 20, (size_t)4 << 20, (size_t)16 << 20, (size_t)64 << 20};
    uint8_t *g64 = malloc((size_t)64 << 20);
    for (size_t i = 0; i < ((size_t)64 << 20); i++)
        g64[i] = m[i % TM];
    for (int k = 0; k < 4; k++) {
        arg_t a = {g64, cle, nonce, c, tag, h, TG3[k], 0};
        omp_set_num_threads(1);
        double b1 = chrono_ns(f_hq32, &a), q1 = chrono_ns(f_hq, &a);
        omp_set_num_threads(nc);
        double bn = chrono_ns(f_hq32, &a), qn = chrono_ns(f_hq, &a);
        double L = TG3[k] / 1e6;
        printf("| %zu Mio | %.0f Mo/s | **%.0f Mo/s** | ×%.2f | %.0f Mo/s | **%.0f Mo/s** | ×%.2f |\n", TG3[k] >> 20, L / (b1 * 1e-9),
               L / (q1 * 1e-9), b1 / q1, L / (bn * 1e-9), L / (qn * 1e-9), bn / qn);
        fflush(stdout);
    }
    free(g64);
    printf("\nRatios : > 1 quand BRUME-1024q est plus rapide. BRUME-1024q : prototype non relu ; KAT du profil à 32 tours figés ; "
           "temps constant mesuré (dudect, ctgrind), pas prouvé.\n");
    return ar ? 0 : 1;
}
