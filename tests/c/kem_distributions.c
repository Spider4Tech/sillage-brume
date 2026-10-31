/* Hypothèses H1-P / H2-P de Sillage-KEM : distributions de s, u, v
 * (audit externe, seconde passe, point 4 : corrélations résiduelles).
 *
 * 1. Certificat sur instances réduites (n premier d'Artin, troncature
 *    n2 < n) : pour h et s fixés, rang sur F2 des différences des vecteurs
 *    (u ‖ v′), u = r1·h ⊕ r2 et v′ = (r1·s)|_{n2} ⊕ e, sur n + n2 + 40
 *    tirages. Si le rang vaut n + n2 − 1, la parité de u est le SEUL
 *    invariant linéaire de la distribution de H2-P : aucun distingueur
 *    linéaire autre que celui que H2-P prend déjà en compte.
 * 2. Tailles réelles (Sillage-128 et Sillage-256, implémentation C) :
 *    - invariants de parité : s(1) = u(1) = β(h) pour toutes les clés et
 *      tous les chiffrés, parité de v équilibrée ;
 *    - biais par position de u et de v (N chiffrés d'une même clé) : |z|
 *      maximal comparé au maximum attendu de n gaussiennes ;
 *    - corrélations u_i ⊕ v_i (même indice) et u_i ⊕ v_j (paires au hasard),
 *      et corrélations s_i ⊕ u_i entre clé publique et chiffré, sur des
 *      clés différentes (une clé par chiffré) ;
 *    - poids de u et de v : moyennes comparées à n/2 et n2/2.
 * Ce sont des tests de détection : ils ne prouvent pas H1-P ni H2-P, mais
 * cherchent les corrélations résiduelles que la troncature ou la structure
 * quasi-cyclique pourraient laisser.
 *     build/kem_distributions   (depuis la racine) → resultats/kem_distributions.json
 */
#include <math.h>

#include "kem.c"
#include "resultat.h"

#define TMAX 256
#define LM ((2 * TMAX + 63) / 64 + 1)

static int bitv(const uint64_t *v, size_t i) { return v[i >> 6] >> (i & 63) & 1; }

static void creux_toy(alea_t *g, int n, int w, uint8_t *v)
{
    memset(v, 0, (size_t)n);
    for (int k = 0; k < w;) {
        int p = (int)alea_borne(g, (uint64_t)n);
        if (!v[p]) { v[p] = 1; k++; }
    }
}

static void mul_toy(int n, const uint8_t *a, const uint8_t *b, uint8_t *c)
{
    for (int i = 0; i < n; i++) {
        uint8_t x = 0;
        for (int j = 0; j < n; j++)
            x ^= a[j] & b[((i - j) % n + n) % n];
        c[i] = x;
    }
}

/* rang des différences (u ‖ v′), h et s fixés */
static int rang_h2p(int n, int n2, int w, int we, uint64_t graine)
{
    alea_t g;
    alea_init(&g, graine);
    uint8_t h[TMAX], x[TMAX], y[TMAX], s[TMAX], r1[TMAX], r2[TMAX], e[TMAX], t[TMAX], u[TMAX], v[TMAX];
    for (int i = 0; i < n; i++)
        h[i] = (uint8_t)(alea64(&g) & 1);
    creux_toy(&g, n, w, x); creux_toy(&g, n, w, y);
    mul_toy(n, x, h, s);
    for (int i = 0; i < n; i++) s[i] ^= y[i];
    int L = n + n2, K = L + 40, nl = 0, rang = 0;
    uint64_t (*B)[LM] = calloc((size_t)K, sizeof *B), z0[LM] = {0};
    for (int k = 0; k <= K; k++) {
        creux_toy(&g, n, w, r1); creux_toy(&g, n, w, r2); creux_toy(&g, n2, we, e);
        mul_toy(n, r1, h, u);
        for (int i = 0; i < n; i++) u[i] ^= r2[i];
        mul_toy(n, r1, s, t);
        for (int i = 0; i < n2; i++) v[i] = t[i] ^ e[i];
        uint64_t z[LM] = {0};
        for (int i = 0; i < n; i++) if (u[i]) z[i >> 6] |= 1ULL << (i & 63);
        for (int i = 0; i < n2; i++) if (v[i]) z[(n + i) >> 6] |= 1ULL << ((n + i) & 63);
        if (k == 0) { memcpy(z0, z, sizeof z0); continue; }
        for (int q = 0; q < LM; q++) B[nl][q] = z[q] ^ z0[q];
        nl++;
    }
    for (int col = 0; col < L; col++) {
        int r = rang;
        while (r < nl && !bitv(B[r], (size_t)col)) r++;
        if (r == nl) continue;
        for (int q = 0; q < LM; q++) { uint64_t tt = B[r][q]; B[r][q] = B[rang][q]; B[rang][q] = tt; }
        for (int i = 0; i < nl; i++)
            if (i != rang && bitv(B[i], (size_t)col))
                for (int q = 0; q < LM; q++) B[i][q] ^= B[rang][q];
        rang++;
    }
    free(B);
    return rang;
}

static int parite(const uint8_t *b, size_t nbits)
{
    int p = 0;
    for (size_t i = 0; i < nbits; i++)
        p ^= b[i >> 3] >> (i & 7) & 1;
    return p;
}

static double zmax_attendu(double m) { return sqrt(2 * log(m)); }

/* statistiques aux tailles réelles pour un niveau */
static void reel(resultat_t *res, int niv, int N, int cles)
{
    const params_t *p = &P[niv];
    size_t lpk, lsk, lct, lss, nb = NB(p->n);
    sl_kem_tailles(niv, &lpk, &lsk, &lct, &lss);
    uint8_t *pk = malloc(lpk), *sk = malloc(lsk), *ct = malloc(lct), ss[64];
    char nom[96];
    const char *lv = niv ? "Sillage-256" : "Sillage-128";
    /* invariants sur plusieurs clés */
    int ok_s = 1, ok_u = 1, vimp = 0, ntot = 0;
    uint32_t *csu = calloc(p->n, 4);
    for (int c = 0; c < cles; c++) {
        sl_kem_keygen(niv, pk, sk);
        const uint64_t *h;
        const uint32_t *pi;
        derives(niv, pk, &h, &pi);
        int h1 = 0;
        for (size_t i = 0; i < NW(p->n); i++) h1 ^= __builtin_popcountll(h[i]) & 1;
        int beta = (int)(p->w & 1) * (h1 ^ 1);
        ok_s &= parite(pk + 32, p->n) == beta;
        for (int k = 0; k < 4; k++) {
            sl_kem_encaps(niv, pk, ct, ss);
            ok_u &= parite(ct, p->n) == beta;
            vimp += parite(ct + nb, p->n2);
            ntot++;
            if (k == 0)
                for (uint32_t i = 0; i < p->n; i++)
                    csu[i] += (uint32_t)(((ct[i >> 3] ^ pk[32 + (i >> 3)]) >> (i & 7)) & 1);
        }
    }
    double zsu = 0, sdk = sqrt(cles / 4.0);
    for (uint32_t i = 0; i < p->n; i++)
        zsu = fmax(zsu, fabs(csu[i] - cles / 2.0) / sdk);
    free(csu);
    snprintf(nom, sizeof nom, "%s_invariant_de_parite_s_et_u", lv);
    res_controle(res, nom, ok_s && ok_u);
    double zv = (vimp - ntot / 2.0) / sqrt(ntot / 4.0);
    snprintf(nom, sizeof nom, "%s_parite_de_v_equilibree", lv);
    res_controle(res, nom, fabs(zv) < 4);
    /* biais et corrélations : N chiffrés d'une même clé */
    sl_kem_keygen(niv, pk, sk);
    uint32_t *cu = calloc(p->n, 4), *cv = calloc(p->n2, 4), *cuv = calloc(p->n2, 4);
    enum { NP = 2000 };
    static uint32_t ia[NP], ib[NP], cp[NP];
    alea_t g;
    alea_init(&g, 4242 + (uint64_t)niv);
    for (int k = 0; k < NP; k++) { ia[k] = (uint32_t)alea_borne(&g, p->n); ib[k] = (uint32_t)alea_borne(&g, p->n2); cp[k] = 0; }
    double su = 0, sv = 0;
    for (int k = 0; k < N; k++) {
        sl_kem_encaps(niv, pk, ct, ss);
        const uint8_t *u = ct, *v = ct + nb;
        int wu = 0, wv = 0;
        for (uint32_t i = 0; i < p->n; i++) {
            int b = u[i >> 3] >> (i & 7) & 1;
            cu[i] += (uint32_t)b; wu += b;
        }
        for (uint32_t i = 0; i < p->n2; i++) {
            int b = v[i >> 3] >> (i & 7) & 1;
            cv[i] += (uint32_t)b; wv += b;
            cuv[i] += (uint32_t)(b ^ (u[i >> 3] >> (i & 7) & 1));
        }
        for (int q = 0; q < NP; q++)
            cp[q] += (uint32_t)((u[ia[q] >> 3] >> (ia[q] & 7) & 1) ^ (v[ib[q] >> 3] >> (ib[q] & 7) & 1));
        su += wu; sv += wv;
    }
    double sd = sqrt(N / 4.0), zu = 0, zvv = 0, zuv = 0, zp = 0;
    for (uint32_t i = 0; i < p->n; i++) {
        zu = fmax(zu, fabs(cu[i] - N / 2.0) / sd);
    }
    for (uint32_t i = 0; i < p->n2; i++) {
        zvv = fmax(zvv, fabs(cv[i] - N / 2.0) / sd);
        zuv = fmax(zuv, fabs(cuv[i] - N / 2.0) / sd);
    }
    for (int q = 0; q < NP; q++)
        zp = fmax(zp, fabs(cp[q] - N / 2.0) / sd);
    double zwu = (su / N - p->n / 2.0) / (sqrt(p->n / 4.0) / sqrt(N)), zwv = (sv / N - p->n2 / 2.0) / (sqrt(p->n2 / 4.0) / sqrt(N));
    double lim_n = zmax_attendu(p->n) + 1.5, lim_np = zmax_attendu(NP) + 1.5;
    snprintf(nom, sizeof nom, "%s_statistiques", lv);
    res_mesure(res, nom, "{\"chiffres\": %d, \"z_max_biais_u\": %.2f, \"z_max_biais_v\": %.2f, \"z_max_u_i_xor_v_i\": %.2f, "
               "\"z_max_u_i_xor_v_j_paires\": %.2f, \"z_max_s_i_xor_u_i_sur_cles\": %.2f, \"cles\": %d, \"z_poids_moyen_u\": %.2f, \"z_poids_moyen_v\": %.2f, "
               "\"z_max_attendu_n_positions\": %.2f, \"z_parite_v\": %.2f}",
               N, zu, zvv, zuv, zp, zsu, cles, zwu, zwv, zmax_attendu(p->n), zv);
    snprintf(nom, sizeof nom, "%s_aucun_biais_par_position_detecte", lv);
    res_controle(res, nom, zu < lim_n && zvv < lim_n);
    snprintf(nom, sizeof nom, "%s_aucune_correlation_u_v_ou_s_u_detectee", lv);
    res_controle(res, nom, zuv < lim_n && zsu < lim_n && zp < lim_np);
    snprintf(nom, sizeof nom, "%s_poids_moyens_conformes", lv);
    res_controle(res, nom, fabs(zwu) < 4 && fabs(zwv) < 4);
    fprintf(stderr, "%s : z_max u %.2f v %.2f u⊕v %.2f paires %.2f s⊕u %.2f (attendu ≈ %.2f)\n", lv, zu, zvv, zuv, zp, zsu,
            zmax_attendu(p->n));
    free(pk); free(sk); free(ct); free(cu); free(cv); free(cuv);
}

int main(void)
{
    resultat_t res = {.nom = "kem_distributions"};
    sl_init();
    static const int T[][4] = {{101, 94, 6, 5}, {131, 120, 7, 6}, {149, 140, 8, 6}, {197, 186, 9, 8}, {227, 216, 10, 9}};
    char buf[512] = "{";
    int ok = 1;
    for (int k = 0; k < 5; k++) {
        int n = T[k][0], n2 = T[k][1], rg = rang_h2p(n, n2, T[k][2], T[k][3], 31337u + (uint64_t)k);
        ok &= rg == n + n2 - 1;
        snprintf(buf + strlen(buf), 64, "%s\"%d/%d\": [%d, %d]", k ? ", " : "", n, n2, rg, n + n2 - 1);
    }
    strcat(buf, "}");
    res_mesure(&res, "rang_differences_u_v_par_n_n2_mesure_attendu", "%s", buf);
    res_controle(&res, "parite_de_u_seul_invariant_lineaire_de_H2P", ok);
    reel(&res, 0, 4000, 600);
    reel(&res, 1, 1000, 150);
    return res_ecrire(&res);
}
