/* BRUME-1024q — temps constant mesuré, méthode « dudect » (Reparaz, Balasch, Verbauwhede 2017), protocole de la suite
 * (tests/c/temps.c) : temps (rdtscp) d'une opération sur une entrée FIXE (classe 0) ou ALÉATOIRE (classe 1) ; classes tirées
 * au hasard et entrelacées ; un paquet d'entrées est préparé AVANT ses mesures, puis chaque entrée est recopiée dans un
 * tampon commun par le même memcpy dans les deux classes (mêmes adresses, même empreinte de cache) ; test t de Welch après
 * rognage au 90e centile (et à la médiane, indicatif). |t| ≥ 4,5 : fuite probable. En cas de dépassement, une seconde mesure
 * deux fois plus longue est notée, sans blanchir la première.
 * Opérations :
 *   permutation   noyau AVX2 à 1 état, état secret (128 octets) ;
 *   lot           noyau AVX2 à 32 états, les 32 états secrets ;
 *   aead          AEAD (clé dans tout l'état), clé et clair (64 octets) secrets, nonce fixe, sans AAD ;
 *   aead_cle      clé fixe contre aléatoire, clair aléatoire dans les deux classes ;
 *   aead_clair    clair fixe contre aléatoire, clé aléatoire dans les deux classes ;
 *   aa            mêmes données fixes dans les deux classes : biais du banc (doit rester sous le seuil) ;
 *   temoin        aa + 300 cycles d'attente en classe 1 : sensibilité du banc (doit être détecté) ;
 *   permutation_ref  référence dense par tables (indices dépendant des données) : témoin indicatif, sans contrôle ;
 *   ouvrir       déchiffrement vérifié (aead_ouvrir), clé et clair secrets, tag valide (chemin d'acceptation) ;
 *   ouvrir_rejet le même avec un tag faux (chemin de rejet, sortie effacée). Le verdict étant public, on ne compare pas
 *                acceptation et rejet entre eux : chaque mesure compare clé fixe et clé aléatoire sur le même chemin.
 * Un test statistique ne prouve pas l'absence de fuite ; il en détecte. À lancer sur une machine au repos, jamais pendant
 * un calcul GPU.
 *   cc -O3 -march=native -fopenmp -DSANS_MAIN -I sillage/c -I tests/c -I prototypes/brume_q/b1024 \
 *      prototypes/brume_q/b1024/temps1024.c sillage/c/commun.c sillage/c/brume512.c sillage/c/brume512_avx2.c -lm \
 *      -o tests/c/build/temps1024 && OMP_NUM_THREADS=1 tests/c/build/temps1024   → resultats/temps1024.json
 *   tests/c/build/temps1024 <opération> <mesures> : une seule opération, sortie JSON sur une ligne. */
#include <math.h>
#include <x86intrin.h>

#include "brume1024.c"

#define PAQ 256
#define SEUIL 4.5
#define NT (32 * 128)   /* taille du tampon : 32 états pour le lot */

enum { OP_PERM, OP_LOT, OP_AEAD, OP_AEAD_CLE, OP_AEAD_CLAIR, OP_AA, OP_TEMOIN, OP_PERM_REF, OP_OUVRIR, OP_OUVRIR_REJET, NOP };
static const char *const NOMS[NOP] = {"permutation", "lot", "aead", "aead_cle", "aead_clair", "aa", "temoin", "permutation_ref",
                                      "ouvrir", "ouvrir_rejet"};

static double t_coupe(double *const t[2], const long nc[2], double seuil)
{
    double m[2], v[2];
    long k[2];
    for (int c = 0; c < 2; c++) {
        double s = 0, s2 = 0;
        k[c] = 0;
        for (long i = 0; i < nc[c]; i++)
            if (t[c][i] <= seuil) { s += t[c][i]; s2 += t[c][i] * t[c][i]; k[c]++; }
        m[c] = k[c] ? s / k[c] : 0;
        v[c] = k[c] ? s2 / k[c] - m[c] * m[c] : 0;
    }
    if (!k[0] || !k[1])
        return k[0] ? -1e6 : 1e6;
    return (m[0] - m[1]) / sqrt(v[0] / k[0] + v[1] / k[1]);
}

static int cmpd(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

typedef struct { double t90, t50, cyc[2]; long n; } mesure_t;

static mesure_t mesurer(int op, long n)
{
    static uint8_t res[PAQ][NT] __attribute__((aligned(64))), alea[PAQ][NT];
    static uint8_t tampon[NT] __attribute__((aligned(64))), fixe[NT], rct[PAQ][64], rtg[PAQ][32], ct[64], tg[32], clair[64];
    uint8_t (*st)[128] = (uint8_t (*)[128])tampon, sortie[64], tag[32], nonce[24] = {0}, cls[PAQ], acc = 0;
    /* octets secrets par opération ; pour aead_cle / aead_clair, la moitié publique est aléatoire dans les deux classes */
    size_t ns = op == OP_LOT ? NT : 128;
    sl_alea(fixe, NT);
    double *t[2] = {malloc(n * sizeof(double)), malloc(n * sizeof(double))};
    long nc[2] = {0, 0};
    for (long base = 0; base < n; base += PAQ) {
        sl_alea(cls, PAQ);
        for (int i = 0; i < PAQ; i++) {
            sl_alea(alea[i], ns);
            cls[i] &= 1;
            int c = (op == OP_AA || op == OP_TEMOIN) ? 0 : cls[i];
            memcpy(res[i], c ? alea[i] : fixe, ns);
            if (op == OP_AEAD_CLE)            /* clair (octets 64..127) aléatoire dans les deux classes */
                memcpy(res[i] + 64, alea[i] + 64, 64);
            if (op == OP_AEAD_CLAIR)          /* clé (octets 0..63) aléatoire dans les deux classes */
                memcpy(res[i], alea[i], 64);
            if (op == OP_OUVRIR || op == OP_OUVRIR_REJET) {   /* chiffré et tag préparés hors mesure */
                aead(perm1, res[i], nonce, NULL, 0, res[i] + 64, 64, 0, rct[i], rtg[i]);
                if (op == OP_OUVRIR_REJET)
                    rtg[i][7] ^= 1;
            }
        }
        for (int i = 0; i < PAQ && base + i < n; i++) {
            int c = cls[i];
            unsigned aux;
            memcpy(tampon, res[i], ns);
            memcpy(ct, rct[i], 64);
            memcpy(tg, rtg[i], 32);
            uint64_t t0 = __rdtscp(&aux);
            switch (op) {
            case OP_PERM: perm1(tampon, R1); break;
            case OP_LOT: lot(st, R1); break;
            case OP_PERM_REF: perm_ref(tampon, R1); break;
            case OP_OUVRIR:
            case OP_OUVRIR_REJET: acc ^= (uint8_t)aead_ouvrir(tampon, nonce, NULL, 0, ct, 64, tg, clair); break;
            case OP_TEMOIN:
                aead(perm1, tampon, nonce, NULL, 0, tampon + 64, 64, 0, sortie, tag);
                if (c) {
                    uint64_t d = __rdtscp(&aux);
                    while (__rdtscp(&aux) - d < 300) { }
                }
                break;
            default: aead(perm1, tampon, nonce, NULL, 0, tampon + 64, 64, 0, sortie, tag); break;
            }
            uint64_t t1 = __rdtscp(&aux);
            t[c][nc[c]++] = (double)(t1 - t0);
            acc ^= tampon[0] ^ tag[0];
        }
    }
    long tot = nc[0] + nc[1];
    double *tout = malloc(tot * sizeof(double));
    memcpy(tout, t[0], nc[0] * sizeof(double));
    memcpy(tout + nc[0], t[1], nc[1] * sizeof(double));
    qsort(tout, tot, sizeof(double), cmpd);
    mesure_t r = {.n = n};
    r.t90 = t_coupe(t, nc, tout[(long)(0.9 * tot)]);
    r.t50 = t_coupe(t, nc, tout[(long)(0.5 * tot)]);
    for (int c = 0; c < 2; c++) {   /* médianes par classe */
        qsort(t[c], nc[c], sizeof(double), cmpd);
        r.cyc[c] = nc[c] ? t[c][nc[c] / 2] : 0;
    }
    if (acc == 0x5A)                  /* empêche l'élimination des calculs */
        fprintf(stderr, " ");
    free(tout); free(t[0]); free(t[1]);
    return r;
}

static void afficher(int op, mesure_t r)
{
    printf("{\"operation\": \"%s\", \"mesures\": %ld, \"cycles_fixe_mediane\": %.0f, \"cycles_aleatoire_mediane\": %.0f, "
           "\"t_welch\": %.2f, \"t_p50\": %.2f}\n", NOMS[op], r.n, r.cyc[0], r.cyc[1], r.t90, r.t50);
}

int main(int argc, char **argv)
{
    if (!bref_init() || !ref_init() || !init_noyaux())
        return 2;
    prepare_iv();
    sl_init();
    if (argc > 1) {
        for (int op = 0; op < NOP; op++)
            if (!strcmp(argv[1], NOMS[op])) {
                afficher(op, mesurer(op, argc > 2 ? atol(argv[2]) : 200000));
                return 0;
            }
        fprintf(stderr, "opération inconnue : %s\n", argv[1]);
        return 2;
    }
    resultat_t res = {.nom = "temps1024", .titre = "BRUME-1024q (prototype) : temps constant mesure (dudect)"};
    const long N[NOP] = {1000000, 40000, 500000, 500000, 500000, 500000, 200000, 20000, 500000, 500000};
    double t[NOP];
    for (int op = 0; op < NOP; op++) {
        mesure_t r = mesurer(op, N[op]);
        afficher(op, r);
        t[op] = r.t90;
        char cle[64];
        snprintf(cle, sizeof cle, "%s_t", NOMS[op]);
        res_mesure(&res, cle, "%.2f", r.t90);
        snprintf(cle, sizeof cle, "%s_t_p50", NOMS[op]);
        res_mesure(&res, cle, "%.2f", r.t50);
        snprintf(cle, sizeof cle, "%s_cycles", NOMS[op]);
        res_mesure(&res, cle, "[%.0f, %.0f]", r.cyc[0], r.cyc[1]);
        res_mesure(&res, strcat(strcpy(cle, NOMS[op]), "_mesures"), "%ld", r.n);
        if (fabs(r.t90) >= SEUIL && op != OP_TEMOIN && op != OP_PERM_REF) {   /* seconde mesure, notée, ne blanchit pas */
            mesure_t r2 = mesurer(op, 2 * N[op]);
            afficher(op, r2);
            snprintf(cle, sizeof cle, "%s_seconde_mesure_t", NOMS[op]);
            res_mesure(&res, cle, "%.2f", r2.t90);
        }
    }
    res_controle(&res, "banc_sensible_temoin_300_cycles_detecte", fabs(t[OP_TEMOIN]) >= SEUIL);
    res_controle(&res, "banc_sans_biais_aa", fabs(t[OP_AA]) < SEUIL);
    res_controle(&res, "permutation_1_etat_sans_fuite_detectee", fabs(t[OP_PERM]) < SEUIL);
    res_controle(&res, "permutation_32_etats_sans_fuite_detectee", fabs(t[OP_LOT]) < SEUIL);
    res_controle(&res, "aead_cle_et_clair_sans_fuite_detectee", fabs(t[OP_AEAD]) < SEUIL);
    res_controle(&res, "aead_cle_seule_sans_fuite_detectee", fabs(t[OP_AEAD_CLE]) < SEUIL);
    res_controle(&res, "aead_clair_seul_sans_fuite_detectee", fabs(t[OP_AEAD_CLAIR]) < SEUIL);
    res_controle(&res, "aead_ouvrir_acceptation_sans_fuite_detectee", fabs(t[OP_OUVRIR]) < SEUIL);
    res_controle(&res, "aead_ouvrir_rejet_sans_fuite_detectee", fabs(t[OP_OUVRIR_REJET]) < SEUIL);
    return res_ecrire(&res);
}
