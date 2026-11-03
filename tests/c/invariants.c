/* Invariants non linéaires de BRUME-512 avec ses vraies constantes (plan GPU, attaque A6 ; PREUVES § 4.2 bis).
 *
 * Critère de Beierle, Canteaut, Leander et Rotella (CRYPTO 2017, « Proving resistance against invariant attacks: how
 * to choose the round constants ») : pour un chiffrement Add(c_t) ∘ L ∘ S ∘ … ∘ Add(c_1) ∘ L ∘ S, un invariant g commun à
 * la couche de S-box et à toutes les couches Add(c_i) ∘ L a pour structures linéaires tout le sous-espace
 * W_L(D) = plus petit sous-espace stable par L contenant D = {c_i ⊕ c_j}. Si dim W_L(D) ≥ n − 1, g est de degré ≤ 1,
 * donc affine ; un invariant affine de la couche de S-box serait une composante affine de S, ce que la S-box n'a pas
 * (toutes ses composantes sont de degré ≥ 2). L'attaque par invariant (Todo–Leander–Sasaki), et par sous-espace
 * invariant (Leander et al.), ne s'applique alors à aucune S-box.
 *
 * BRUME : x_{r+1} = M·S(x_r ⊕ rc_r). Les couches « M puis constante » sont Add(rc_{r+1}) ∘ M pour r = 0 … 30 :
 * D est formé des 31 constantes intérieures rc_1 … rc_31 (rc_0 et le dernier M n'y entrent pas : prudent).
 * M est ici l'application GF(2)-linéaire sur 512 bits (bit 4v + k = bit k du nibble v), calculée à partir des seules
 * tables générées (brume512_tables.h).
 *
 * Hors de ce critère : invariants différents d'un tour à l'autre et invariants en boucle fermée (Beyne, ASIACRYPT 2018,
 * valeurs propres des matrices de corrélation), invariants d'une permutation à clé.
 *     make -C tests/c build/invariants && tests/c/build/invariants   (depuis la racine) → resultats/invariants.json */
#include <stdint.h>
#include <string.h>

#include "brume512_tables.h"
#include "resultat.h"

typedef struct { uint64_t w[8]; } v512;

static int gmul(int a, int b)
{
    int r = 0;
    for (int i = 0; i < 4; i++) {
        if (b & 1) r ^= a;
        b >>= 1; a <<= 1;
        if (a & 16) a ^= BR_POLY;
    }
    return r & 15;
}

static int nib(const v512 *x, int v) { return (int)((x->w[v >> 4] >> (4 * (v & 15))) & 15); }
static void pose(v512 *x, int v, int c) { x->w[v >> 4] ^= (uint64_t)c << (4 * (v & 15)); }

/* couche linéaire M seule (sans S-box ni constante) */
static v512 appliquer_M(const v512 *y)
{
    v512 x = {{0}};
    for (int e = 0; e < BR_ARETES; e++)
        pose(&x, e / BR_DEG, gmul(BR_EC[e], nib(y, BR_EI[e])));
    return x;
}

static v512 constante(int r)
{
    v512 c = {{0}};
    for (int v = 0; v < BR_N; v++) pose(&c, v, BR_RC[r][v]);
    return c;
}

/* base échelonnée sur GF(2)^512 : piv[i] = vecteur dont le bit de tête est i */
typedef struct { v512 piv[512]; int a[512], dim; } base_t;

static int bit(const v512 *x, int i) { return (int)((x->w[i >> 6] >> (i & 63)) & 1); }

/* réduit x contre la base ; ajoute le reste s'il est non nul (retour : 1 si ajouté) */
static int ajouter(base_t *B, v512 x)
{
    for (int i = 511; i >= 0; i--)
        if (bit(&x, i)) {
            if (!B->a[i]) { B->piv[i] = x; B->a[i] = 1; B->dim++; return 1; }
            for (int k = 0; k < 8; k++) x.w[k] ^= B->piv[i].w[k];
        }
    return 0;
}

/* dim W_L(D), D = {rc_i ⊕ rc_j : premier ≤ i < j ≤ dernier}, L = M (ou l'identité si identite) ; *dimD = dim span(D) */
static int dim_W_L(int premier, int dernier, int *dimD, int identite)
{
    static base_t B;
    static v512 file[512];
    memset(&B, 0, sizeof B);
    int nf = 0;
    v512 c0 = constante(premier);
    for (int j = premier + 1; j <= dernier; j++) {          /* rc_i ⊕ rc_j engendré par les rc_premier ⊕ rc_j */
        v512 d = constante(j);
        for (int k = 0; k < 8; k++) d.w[k] ^= c0.w[k];
        if (ajouter(&B, d)) file[nf++] = d;
    }
    if (dimD) *dimD = B.dim;
    for (int q = 0; q < nf; q++) {                          /* clôture par M : chaque vecteur ajouté est transformé */
        v512 m = identite ? file[q] : appliquer_M(&file[q]);
        if (ajouter(&B, m)) file[nf++] = m;
    }
    return B.dim;
}
static int dim_W(int premier, int dernier, int *dimD) { return dim_W_L(premier, dernier, dimD, 0); }

int main(void)
{
    resultat_t res = {.nom = "invariants", .titre = "Invariants non linéaires de BRUME-512 (critère de Beierle–Canteaut–Leander–Rotella)"};

    /* 1. aucune composante affine de la S-box : <β, S(x)> de degré ≥ 2 pour tout β ≠ 0 */
    int deg_min = 4;
    for (int beta = 1; beta < 16; beta++) {
        int t[16], d = 0;
        for (int x = 0; x < 16; x++) t[x] = __builtin_parity(BR_SBOX[x] & beta);
        for (int i = 1; i < 16; i <<= 1)
            for (int x = 0; x < 16; x++) if (x & i) t[x] ^= t[x ^ i];
        for (int m = 0; m < 16; m++) if (t[m] && __builtin_popcount(m) > d) d = __builtin_popcount(m);
        if (d < deg_min) deg_min = d;
    }
    res_controle(&res, "sbox_sans_composante_affine", deg_min >= 2);
    res_mesure(&res, "sbox_degre_minimal_des_composantes", "%d", deg_min);

    /* 2. M est une bijection (sinon le critère s'énonce autrement) : rang 512 */
    {
        static base_t B;
        memset(&B, 0, sizeof B);
        for (int i = 0; i < 512; i++) {
            v512 e = {{0}};
            e.w[i >> 6] = 1ULL << (i & 63);
            ajouter(&B, appliquer_M(&e));
        }
        res_controle(&res, "M_inversible_sur_GF2_512", B.dim == 512);
    }

    /* 3. permutation complète : D formé de rc_1 … rc_31 */
    int dD, d = dim_W(1, BR_TOURS - 1, &dD);
    res_mesure(&res, "dim_span_D_32_tours", "%d", dD);
    res_mesure(&res, "dim_W_M_D_32_tours", "%d", d);
    res_controle(&res, "W_M_D_plein_32_tours_aucun_invariant", d >= 511);

    /* 4. tours réduits : pour toute fenêtre de t constantes consécutives, dim W ; plus petite fenêtre toujours pleine */
    int t_plein = 0, dmin2 = 512;
    char detail[4096];
    int lg = snprintf(detail, sizeof detail, "{");
    for (int t = 2; t <= BR_TOURS - 1 && !t_plein; t++) {
        int pire = 512;
        for (int p = 1; p + t - 1 <= BR_TOURS - 1; p++) {
            int dw = dim_W(p, p + t - 1, NULL);
            if (dw < pire) pire = dw;
        }
        if (t == 2) dmin2 = pire;
        lg += snprintf(detail + lg, sizeof detail - lg, "%s\"%d\": %d", t > 2 ? ", " : "", t, pire);
        if (pire >= 511) t_plein = t;
    }
    snprintf(detail + lg, sizeof detail - lg, "}");
    res_mesure(&res, "dim_W_pire_fenetre_par_nombre_de_constantes", "%s", detail);
    res_mesure(&res, "constantes_consecutives_suffisantes", "%d", t_plein);
    res_mesure(&res, "dim_W_deux_constantes_pire_cas", "%d", dmin2);
    res_controle(&res, "fenetre_pleine_trouvee", t_plein > 0);

    /* 5. témoin négatif : avec L = identité, W = span(D) (dim 30), comme pour Midori-64 : le critère ne conclut pas */
    int dId = dim_W_L(1, BR_TOURS - 1, NULL, 1);
    res_mesure(&res, "temoin_dim_W_L_identite", "%d", dId);
    res_controle(&res, "temoin_L_identite_W_non_plein", dId == dD && dId < 511);
    return res_ecrire(&res);
}
