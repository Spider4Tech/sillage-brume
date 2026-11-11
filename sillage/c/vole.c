/* Sillage-SIG v0.5 : signature VOLE-in-the-Head sur SD régulier (PROOFS § 3 bis, SPEC § 4 bis), d'après le prototype de la piste 9
 * (prototypes/vole/vole_proto.c, qui inclut ce fichier et y ajoute attaques, contrôles et mesures).
 *
 * Témoin : pour chaque bloc, d vecteurs élémentaires de tailles μ_t ; leur produit tensoriel donne le bloc de x (blocs EXACTS,
 * bloc = Π μ_t, Lemme 17.1). Polynômes p_j(X) = w_j X + V_j, évalués par le vérifieur en Δ. Contraintes homogénéisées de degré d,
 * mêlées par γ : leur terme en X^d est nul si le témoin est valide. α = coefficients de degré < d de ce polynôme masqué.
 * Graines de λ + 8 bits, sel de 32 octets, grinding minimal du Théorème 17, codimension ⌈log2 C(n, w)⌉ (Lemme 17.2).
 * API (sillage.h) : sl_vole_tailles, sl_vole_keygen, sl_vole_sign, sl_vole_sign_sel, sl_vole_verify ; profils 0 à 3 :
 * VOLE-128, VOLE-256, VOLE-128f, VOLE-256f. Erreurs de mémoire et d'aléa propagées, jamais de signature partielle.
 * Le paramètre interne « attaque » des fonctions statiques ne sert qu'au prototype ; l'API passe toujours 0.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>
#include <time.h>

#include "sillage.h"

#ifdef SL_VALGRIND
#define VALGRIND_SECRET(p, n) VALGRIND_MAKE_MEM_UNDEFINED(p, n)
#else
#define VALGRIND_SECRET(p, n) ((void)0)
#endif

#define WMAX 4
#define DMAX 6
typedef uint64_t u64;
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "les éléments du corps sont sérialisés depuis la mémoire");

/* Deux régimes. Les tests et les mesures s'arrêtent franchement (fatal, alloue). L'API (keygen, signer, verifier_r) passe par
 * alloc_api et alea_api, qui renvoient une erreur : elle est propagée, les secrets sont effacés, la signature remise à zéro. */
static void fatal(const char *quoi) { fprintf(stderr, "sillage vole : %s\n", quoi); abort(); }   /* invariants internes */

/* injection d'échecs (tests) : la n-ième allocation ou le n-ième tirage de l'API échoue ; -1 : jamais */
static long inj_alloc = -1, inj_alea = -1;

static void *alloc_api(size_t a, size_t b)
{
    size_t t;
    if (inj_alloc >= 0 && inj_alloc-- == 0) return NULL;
    return __builtin_mul_overflow(a, b, &t) ? NULL : calloc(t ? t : 1, 1);
}


static inline void le32(uint8_t *o, uint32_t v) { for (int i = 0; i < 4; i++) o[i] = (uint8_t)(v >> (8 * i)); }
static inline uint32_t lit32(const uint8_t *o) { uint32_t v = 0; for (int i = 0; i < 4; i++) v |= (uint32_t)o[i] << (8 * i); return v; }
static inline uint8_t masque_egal(uint32_t a, uint32_t b) { return (uint8_t)(0 - (((a ^ b) - 1u) >> 31)); }   /* a, b < 2^31 */

/* Aléa reproductible pour les KAT : un seul fil, compteur haché */
static int kat_actif;
static uint32_t kat_ctr;
static int alea_api(void *o, size_t n)
{
    if (inj_alea >= 0 && inj_alea-- == 0) return -1;
    if (kat_actif) {
        uint8_t c[4];
        le32(c, kat_ctr++);
        sl_shake_dom("SILLAGE-VOLE|kat", c, 4, NULL, NULL, 0, o, n);
        return 0;
    }
    return sl_alea(o, n) ? -1 : 0;
}

/* gbits : modèle réduit seulement, γ tiré dans un sous-groupe additif de 2^gbits éléments (attaque sur γ exécutable) */
typedef struct { const char *nom; int lam, n, cod, w, bloc, d, mu[DMAX], tau, kap, wpow, topen, B, gbits, rapide; } vp_t;   /* rapide : profils f */

/* n, cod, w, μ : vole_params (blocs exacts, codimension ⌈log2 C(n, w)⌉ de la réduction exacte, Lemme 17.2) ; τ, κ, T_open : SDitH v2.0, table 4 ;
 * wpow : plus petit grinding qui atteint λ au Théorème 17 (contrôle *_wpow_minimal) */
static const vp_t PR128 = {"VOLE-128", 128, 19456, 720, 76, 256, 4, {4, 4, 4, 4}, 11, 11, 10, 107, 16, 0, 0};
static const vp_t PR256 = {"VOLE-256", 256, 38912, 1432, 152, 256, 4, {4, 4, 4, 4}, 21, 12, 7, 216, 16, 0, 0};
/* variantes rapides : N = 2^8 comme SDitH2-fast (T_open de SDitH), 5 à 10 fois moins de feuilles, signature plus grande */
static const vp_t PR128F = {"VOLE-128f", 128, 19456, 720, 76, 256, 4, {4, 4, 4, 4}, 16, 8, 3, 101, 16, 0, 1};
static const vp_t PR256F = {"VOLE-256f", 256, 38912, 1432, 152, 256, 4, {4, 4, 4, 4}, 32, 8, 3, 207, 16, 0, 1};

typedef struct {
    const vp_t *p;
    int Bl, Sb, Ls, W, k, cB, sw, witb, witB, nb, pairs, m;   /* Bl : élément du corps ; Sb : graine (λ + 8 bits) ; Ls : sel */
    size_t L, N;
    uint8_t prefixe[14];                                 /* protocole, version, profil : préfixe de tout hachage */
} ctx_t;

/* 0, ou -1 si le profil sort des capacités du prototype ou si bloc ≠ Π μ (bloc vide possible) */
static int ctx_init(ctx_t *c, const vp_t *p)
{
    c->p = p; c->Bl = p->lam / 8; c->Sb = c->Bl + 1; c->Ls = 32; c->W = p->lam / 64; c->k = p->n - p->cod; c->cB = p->cod / 8;
    c->sw = 0; c->pairs = 0;
    for (int t = 0; t < p->d; t++) {
        c->sw += p->mu[t] - 1;
        c->pairs += (p->mu[t] - 1) * (p->mu[t] - 2) / 2;
    }
    c->witb = p->w * c->sw; c->witB = (c->witb + 7) / 8;
    c->nb = c->witB + (p->d - 1) * c->Bl + (p->lam + p->B) / 8;
    c->m = p->cod + p->w * c->pairs;
    c->N = (size_t)1 << p->kap; c->L = (size_t)p->tau << p->kap;
    memcpy(c->prefixe, "SILLAGE-VOLE", 12);
    c->prefixe[12] = 2;                                  /* version 2 : blocs exacts, graines de λ + 8 bits, sel de 32 octets */
    /* octet de profil : λ/64, +16 modèle réduit, +32 γ réduit, +64 variante rapide (séparation des profils de même λ) */
    c->prefixe[13] = (uint8_t)(p->lam / 64 + (p->n < 1024 ? 16 : 0) + (p->gbits ? 32 : 0) + (p->rapide ? 64 : 0));
    int mum = 0, prod = 1;
    for (int t = 0; t < p->d && t < DMAX; t++) { mum = p->mu[t] > mum ? p->mu[t] : mum; prod *= p->mu[t]; }
    if (c->W > WMAX || p->d > DMAX || p->d < 2 || mum > 8 || p->tau * p->kap > p->lam || p->tau > 64 || p->cod % 8 || p->bloc > 4096 || c->cB > 512
        || c->nb > 512 || p->n % p->w || p->bloc != p->n / p->w || p->bloc != prod || p->gbits < 0 || p->gbits > p->lam
        || (size_t)p->tau * (size_t)p->kap + (size_t)p->wpow > 512)
        return -1;
    return 0;
}

#define PROTO_SEUL __attribute__((unused))            /* aides du prototype (prototypes/vole/vole_proto.c) */
PROTO_SEUL static void ctx_ok(ctx_t *c, const vp_t *p)
{
    if (ctx_init(c, p)) fatal("profil hors des capacités du prototype");
}

/* ---------------------------------------------------------------- GF(2^λ) */
static inline void gf_mul(int W, const u64 *a, const u64 *b, u64 *o)
{
    if (W < 1 || W > WMAX) __builtin_unreachable();      /* ctx_init : W ≤ WMAX ; renseigne gcc (-Warray-bounds) */
    u64 t[2 * WMAX] = {0}, l, h;
    for (int i = 0; i < W; i++)
        for (int j = 0; j < W; j++) {
            sl_clmul64(a[i], b[j], &l, &h);
            t[i + j] ^= l; t[i + j + 1] ^= h;
        }
    const u64 r = W == 2 ? 0x87 : 0x425;             /* x^128 + x^7 + x^2 + x + 1, x^256 + x^10 + x^5 + x^2 + 1 */
    u64 v = 0;
    for (int i = 0; i < W; i++) {
        sl_clmul64(t[W + i], r, &l, &h);
        t[i] ^= l;
        if (i + 1 < W) t[i + 1] ^= h; else v = h;
    }
    sl_clmul64(v, r, &l, &h);
    t[0] ^= l;
    for (int i = 0; i < W; i++) o[i] = t[i];
}
static inline void fxor(int W, u64 *o, const u64 *a) { for (int i = 0; i < W; i++) o[i] ^= a[i]; }
static inline int bit(const uint8_t *v, size_t i) { return (v[i >> 3] >> (i & 7)) & 1; }

/* ---------------------------------------------------------------- hachage */
/* Grammaire unique : préfixe ‖ dom ‖ champs. Pour un profil et un domaine, les longueurs sont fixes, sauf le message, toujours en dernier. */
static void H(const ctx_t *x, uint8_t dom, const void *a, size_t la, const void *b, size_t lb_, const void *z, size_t lc, void *o, size_t lo)
{
    sl_shake_t s;
    sl_shake_init(&s);
    sl_shake_absorb(&s, x->prefixe, sizeof x->prefixe);
    sl_shake_absorb(&s, &dom, 1);
    if (la) sl_shake_absorb(&s, a, la);
    if (lb_) sl_shake_absorb(&s, b, lb_);
    if (lc) sl_shake_absorb(&s, z, lc);
    sl_shake_final(&s);
    sl_shake_squeeze(&s, o, lo);
}

/* quatre appels à H(c, dom, sel, ls, i, 4, graine, lg), en un bloc de SHAKE (contrôle : h4_egale_quatre_appels_scalaires) ;
 * pour un domaine, ls et lg sont fixes : 'H' (λ/8, λ/8), 'n' et 'l' (sel de 32 octets, graine de λ/8 + 1 octets) */
static void H4(const ctx_t *c, uint8_t dom, const uint8_t *salt, size_t ls, const uint32_t idx[4], const uint8_t *const g[4], size_t lg,
               uint8_t *const o[4], size_t lo)
{
    uint8_t m[4][14 + 1 + 64 + 4 + 64];
    const uint8_t *pm[4];
    size_t l = 0;
    if (ls > 64 || lg > 64) fatal("H4 : longueur hors capacité");
    for (int j = 0; j < 4; j++) {
        memcpy(m[j], c->prefixe, sizeof c->prefixe); l = sizeof c->prefixe;
        m[j][l++] = dom;
        memcpy(m[j] + l, salt, ls); l += ls;
        le32(m[j] + l, idx[j]); l += 4;
        if (g[j]) { memcpy(m[j] + l, g[j], lg); } else { memset(m[j] + l, 0, lg); }
        l += lg;
        pm[j] = m[j];
    }
    sl_shake4(pm, l, o, lo);
}

static void developper_H(const ctx_t *c, const uint8_t *seed, uint8_t *cols)
{
    size_t k = (size_t)c->k, cB = (size_t)c->cB;
#pragma omp parallel for schedule(static)
    for (size_t j = 0; j < (k + 3) / 4; j++) {
        uint8_t tmp[4][512];
        uint32_t idx[4];
        const uint8_t *g[4];
        uint8_t *o[4];
        for (size_t q = 0; q < 4; q++) {
            idx[q] = (uint32_t)(4 * j + q); g[q] = seed;
            o[q] = 4 * j + q < k ? cols + (4 * j + q) * cB : tmp[q];
        }
        H4(c, 'H', seed, (size_t)c->Bl, idx, g, (size_t)c->Bl, o, cB);
    }
}

/* ---------------------------------------------------------------- clés */
typedef struct { uint8_t seed[32], y[512]; } vpk_t;                /* seule forme normative : encoder_pk */
typedef struct { uint8_t seed[32]; uint8_t *cols; } hcache_t;      /* H développée, liée à la graine qui l'a produite */

static size_t encoder_pk(const ctx_t *c, const vpk_t *pk, uint8_t *o)
{
    memcpy(o, pk->seed, (size_t)c->Bl);
    memcpy(o + c->Bl, pk->y, (size_t)c->cB);
    return (size_t)c->Bl + (size_t)c->cB;
}

/* Parcourt tout le bloc : ni division ni accès selon la position secrète ; les chiffres viennent de l'indice public.
 * Un bloc par itération (parallèle), sw bits dans un mot, puis rangement séquentiel (blocs à cheval sur un octet). */
static void bits_temoin(const ctx_t *c, const uint16_t *pos, uint8_t *wit)
{
    const vp_t *p = c->p;
    uint32_t vb[512];                                    /* w ≤ n/2 ≤ 512 pour les profils (sw ≤ 28 bits) */
    if (p->w > 512 || c->sw > 32) fatal("bits_temoin : profil hors capacité");
    int P0 = 1;
    for (int t = 1; t < p->d; t++) P0 *= p->mu[t];
#pragma omp parallel for schedule(static)
    for (int i = 0; i < p->w; i++) {
        uint32_t v = 0;
        for (int idx = 0; idx < p->bloc; idx++) {
            uint32_t m = (uint32_t)(int32_t)(int8_t)masque_egal((uint32_t)idx, pos[i]);
            int r = idx, P = P0, o = 0;
            for (int t = 0; t < p->d; t++) {
                int dg = r / P;
                r %= P;
                for (int k = 0; k < p->mu[t] - 1; k++, o++)
                    v |= m & ((uint32_t)(dg == k) << o);
                if (t + 1 < p->d) P /= p->mu[t + 1];
            }
        }
        vb[i] = v;
    }
    memset(wit, 0, (size_t)c->witB);
    for (int i = 0; i < p->w; i++)
        for (int k = 0; k < c->sw; k++) {
            size_t o = (size_t)i * (size_t)c->sw + (size_t)k;
            wit[o >> 3] |= (uint8_t)(((vb[i] >> k) & 1u) << (o & 7));
        }
    sl_effacer(vb, sizeof vb);
}

/* y = H·x, en parcourant toutes les colonnes du bloc sous masque */
static void syndrome(const ctx_t *c, const uint8_t *cols, const uint16_t *pos, uint8_t *y)
{
    const vp_t *p = c->p;
    size_t cB = (size_t)c->cB;
    memset(y, 0, cB);
    for (int i = 0; i < p->w; i++)
        for (int idx = 0; idx < p->bloc; idx++) {
            uint8_t m = masque_egal((uint32_t)idx, pos[i]);
            int q = i * p->bloc + idx;
            if (q < c->k) {
                const uint8_t *col = cols + (size_t)q * cB;
                for (size_t b = 0; b < cB; b++) y[b] ^= col[b] & m;
            } else {
                y[(q - c->k) >> 3] ^= (uint8_t)(m & (1u << ((q - c->k) & 7)));
            }
        }
}

/* 0, ou -1 si l'aléa manque (clé et positions effacées) */
static int keygen(const ctx_t *c, vpk_t *pk, uint16_t *pos, hcache_t *hc)
{
    const vp_t *p = c->p;
    memset(pk, 0, sizeof *pk);
    if (alea_api(pk->seed, (size_t)c->Bl)) return -1;
    developper_H(c, pk->seed, hc->cols);
    memcpy(hc->seed, pk->seed, sizeof hc->seed);
    const uint32_t seuil = 65536u % (uint32_t)p->bloc;
    for (int i = 0; i < p->w; i++) {
        uint32_t m;
        int rejet;
        do {                                                 /* Lemire : uniforme, sans division selon le secret */
            uint8_t a[2];
            if (alea_api(a, 2)) {
                sl_effacer(pos, (size_t)p->w * 2);
                memset(pk, 0, sizeof *pk);
                return -1;
            }
            VALGRIND_SECRET(a, 2);
            m = (uint32_t)(a[0] | (a[1] << 8)) * (uint32_t)p->bloc;
            rejet = (m & 0xFFFF) < seuil;
            SL_PUBLIC(&rejet, sizeof rejet);                 /* ne révèle qu'un tirage écarté */
        } while (rejet);
        pos[i] = (uint16_t)(m >> 16);
    }
    syndrome(c, hc->cols, pos, pk->y);
    SL_PUBLIC(pk->y, sizeof pk->y);
    return 0;
}

/* ---------------------------------------------------------------- arbre GGM unique */
static void developper_arbre(const ctx_t *c, const uint8_t *salt, uint8_t *nd, uint8_t *connu)
{
    size_t Sb = (size_t)c->Sb, L = c->L;
    for (size_t lo = 1; lo < L; lo *= 2) {
        size_t hi = 2 * lo < L ? 2 * lo : L;
        size_t nb = (hi - lo + 3) / 4;
#pragma omp parallel for schedule(static)
        for (size_t q = 0; q < nb; q++) {
            uint32_t idx[4];
            const uint8_t *g[4];
            uint8_t tmp[4][2 * 64], *o[4];
            for (size_t j = 0; j < 4; j++) {
                size_t pa = lo + 4 * q + j;
                idx[j] = (uint32_t)pa;
                g[j] = pa < hi && connu[pa] ? nd + pa * Sb : NULL;
                o[j] = tmp[j];
            }
            H4(c, 'n', salt, (size_t)c->Ls, idx, g, Sb, o, 2 * Sb);
            for (size_t j = 0; j < 4; j++) {
                size_t pa = lo + 4 * q + j;
                if (pa < hi && connu[pa])
                    for (size_t f = 0; f < 2; f++) {
                        memcpy(nd + (2 * pa + f) * Sb, tmp[j] + f * Sb, Sb);
                        connu[2 * pa + f] = 1;
                    }
            }
            sl_effacer(tmp, sizeof tmp);
        }
    }
}

/* marque les ancêtres des feuilles cachées ; renvoie le nombre de nœuds à révéler */
static int marquer(const ctx_t *c, const uint32_t *ch, uint8_t *cache)
{
    size_t L = c->L;
    memset(cache, 0, 2 * L);
    for (int e = 0; e < c->p->tau; e++)
        for (size_t x = L + (size_t)ch[e] * (size_t)c->p->tau + (size_t)e; x >= 1; x /= 2)
            cache[x] = 1;
    int n = 0;
    for (size_t x = 2; x < 2 * L; x++)
        n += !cache[x] && cache[x / 2];
    return n;
}

/* nombre de nœuds que marquer() révélerait, sans parcourir l'arbre : M = réunion des chemins des τ feuilles cachées
 * (racine comprise). Tout nœud marqué interne (< L) a ses deux fils dans l'arbre et au moins un fils marqué ; tout nœud marqué
 * sauf la racine est le fils marqué d'un seul parent marqué ; les nœuds marqués ≥ L sont les τ feuilles cachées. Donc
 * révélés = Σ_{p ∈ M, p < L} (2 − fils marqués) = 2(|M| − τ) − (|M| − 1) = |M| − 2τ + 1. (contrôle : decompte_ouverture_egal_a_marquer) */
static int ouverts(const ctx_t *c, const uint32_t *ch)
{
    uint32_t tab[4096];                                  /* |M| ≤ τ·(log2(2L) + 1) ≤ 64 × 20 < 4096 */
    memset(tab, 0, sizeof tab);
    int m = 0;
    for (int e = 0; e < c->p->tau; e++)
        for (uint32_t x = (uint32_t)(c->L + (size_t)ch[e] * (size_t)c->p->tau + (size_t)e); x >= 1; x >>= 1) {
            uint32_t h = (x * 2654435761u) >> 20;
            while (tab[h] && tab[h] != x) h = (h + 1) & 4095;
            if (tab[h] == x) break;                      /* déjà présent : ses ancêtres le sont aussi */
            tab[h] = x;
            m++;
        }
    return m - 2 * c->p->tau + 1;
}

/* défi final : τ indices de κ bits et wpow bits nuls ; -1 si refusé */
static int defi(const ctx_t *c, const uint8_t *h3, uint32_t ctr, uint32_t *ch, uint8_t *cache)
{
    const vp_t *p = c->p;
    uint8_t o[64] = {0}, ec[4];
    le32(ec, ctr);
    size_t tb = (size_t)p->tau * (size_t)p->kap;
    H(c, 'd', h3, 2 * (size_t)c->Bl, ec, 4, NULL, 0, o, (tb + (size_t)p->wpow + 7) / 8);   /* ctx_init : ≤ 64 octets */
    for (int e = 0; e < p->tau; e++) {
        uint32_t v = 0;
        for (int b = 0; b < p->kap; b++)
            v |= (uint32_t)bit(o, (size_t)e * (size_t)p->kap + (size_t)b) << b;
        ch[e] = v;
    }
    for (int b = 0; b < p->wpow; b++)
        if (bit(o, tb + (size_t)b))
            return -1;
    return marquer(c, ch, cache) <= p->topen ? 0 : -1;
}

/* plus petit ctr dont le défi passe (wpow bits nuls, ouverture ≤ T_open) : le même que la boucle séquentielle, donc mêmes
 * signatures et mêmes KAT. Lots de 4 SHAKE (sl_shake4) répartis sur les threads ; *essais = ctr + 1, comme la boucle. */
static uint32_t premier_defi(const ctx_t *c, const uint8_t *h3, long *essais)
{
    const vp_t *p = c->p;
    size_t hb = 2 * (size_t)c->Bl, tb = (size_t)p->tau * (size_t)p->kap, lo = (tb + (size_t)p->wpow + 7) / 8;
    size_t lm = sizeof c->prefixe + 1 + hb + 4;
    int nt = omp_get_max_threads();
    uint32_t lot = (uint32_t)(4 * 32 * nt);
    for (uint32_t base = 0;; base += lot) {
        uint32_t meilleur = UINT32_MAX;
#pragma omp parallel for schedule(static) reduction(min : meilleur)
        for (uint32_t g = 0; g < lot / 4; g++) {
            uint8_t m[4][14 + 1 + 64 + 4], o[4][64];
            const uint8_t *pm[4];
            uint8_t *po[4];
            for (int j = 0; j < 4; j++) {
                memcpy(m[j], c->prefixe, sizeof c->prefixe);
                m[j][sizeof c->prefixe] = 'd';
                memcpy(m[j] + sizeof c->prefixe + 1, h3, hb);
                le32(m[j] + sizeof c->prefixe + 1 + hb, base + 4 * g + (uint32_t)j);
                pm[j] = m[j]; po[j] = o[j];
            }
            sl_shake4(pm, lm, po, lo);
            for (int j = 0; j < 4; j++) {
                int nul = 1;
                for (int b = 0; b < p->wpow && nul; b++) nul = !bit(o[j], tb + (size_t)b);
                if (!nul) continue;
                uint32_t ch[64];
                for (int e = 0; e < p->tau; e++) {
                    uint32_t v = 0;
                    for (int b = 0; b < p->kap; b++) v |= (uint32_t)bit(o[j], (size_t)e * (size_t)p->kap + (size_t)b) << b;
                    ch[e] = v;
                }
                uint32_t ctr = base + 4 * g + (uint32_t)j;
                if (ouverts(c, ch) <= p->topen && ctr < meilleur) meilleur = ctr;
            }
        }
        if (meilleur != UINT32_MAX) {
            *essais = (long)meilleur + 1;
            return meilleur;
        }
    }
}

/* ---------------------------------------------------------------- une répétition : com, q_b = Σ ((i ⊕ i*)_b)·r_i, Σ r_i ; -1 si mémoire */
static int repetition(const ctx_t *c, const uint8_t *salt, int e, const uint8_t *nd, const uint8_t *connu,
                      uint8_t *coms, uint8_t *qv, uint8_t *u, uint32_t cache)
{
    size_t N = c->N, nb = (size_t)c->nb, Bl = (size_t)c->Bl, Sb = (size_t)c->Sb, L = c->L;
    int kap = c->p->kap;
    /* T morceaux alignés de C positions : chacun hache ses feuilles et replie localement les log2 C premiers niveaux ;
     * les niveaux suivants replient les T sommes. Même somme XOR que le repliement global, dans un autre ordre. */
    size_t T = N >= 64 ? 16 : 1, C = N / T;
    int kc = __builtin_ctzl(C);                          /* niveaux repliés dans un morceau */
    uint8_t *S = alloc_api(N, nb), *qp = alloc_api(T * (size_t)kap, nb);
    if (!S || !qp) { free(S); free(qp); return -1; }
#pragma omp parallel for schedule(static)
    for (size_t t = 0; t < T; t++) {
        uint8_t *Sc = S + t * C * nb, *qt = qp + t * (size_t)kap * nb;
        for (size_t s0 = 0; s0 < C; s0 += 4) {          /* position s de S ← feuille i = s ⊕ cache ; les 4 restent groupées */
            uint32_t idx[4];
            const uint8_t *g[4];
            uint8_t *o[4], buf[4][512 + 128];
            size_t ii[4];
            for (size_t j = 0; j < 4; j++) {
                size_t sp = t * C + s0 + j, i = sp ^ cache, x = L + i * (size_t)c->p->tau + (size_t)e;  /* entrelacé */
                ii[j] = i;
                idx[j] = (uint32_t)x;
                g[j] = s0 + j < C && i < N && connu[x] ? nd + x * Sb : NULL;
                o[j] = buf[j];
            }
            H4(c, 'l', salt, (size_t)c->Ls, idx, g, Sb, o, 2 * Bl + nb);
            for (size_t j = 0; j < 4 && s0 + j < C; j++) {
                size_t i = ii[j], x = L + i * (size_t)c->p->tau + (size_t)e;
                if (!connu[x]) {                                /* la feuille cachée : r = 0, com donné par la signature */
                    memset(Sc + (s0 + j) * nb, 0, nb);
                    continue;
                }
                memcpy(coms + i * 2 * Bl, buf[j], 2 * Bl);
                memcpy(Sc + (s0 + j) * nb, buf[j] + 2 * Bl, nb);
            }
            sl_effacer(buf, sizeof buf);
        }
        for (int b = 0; b < kc; b++) {
            uint8_t *qb = qt + (size_t)b * nb;
            size_t m = C >> b;
            for (size_t j = 0; j < m / 2; j++) {
                uint8_t *s0p = Sc + 2 * j * nb, *s1p = Sc + (2 * j + 1) * nb, *dp = Sc + j * nb;
                for (size_t z = 0; z < nb; z++) {
                    uint8_t x = s0p[z], y = s1p[z];
                    qb[z] ^= y;
                    dp[z] = x ^ y;
                }
            }
        }
    }
    for (int b = 0; b < kap; b++) {
        uint8_t *qb = qv + (size_t)b * nb;
        memset(qb, 0, nb);
        if (b < kc)
            for (size_t t = 0; t < T; t++)
                for (size_t z = 0; z < nb; z++) qb[z] ^= qp[(t * (size_t)kap + (size_t)b) * nb + z];
    }
    /* niveaux kc..κ−1 : sommes des morceaux, en S + t·C·nb */
    for (int b = kc; b < kap; b++) {
        uint8_t *qb = qv + (size_t)b * nb;
        size_t m = N >> b, pas = C * nb;
        for (size_t j = 0; j < m / 2; j++) {
            uint8_t *s0p = S + (2 * j) * (size_t)((size_t)1 << (b - kc)) * pas, *s1p = S + (2 * j + 1) * (size_t)((size_t)1 << (b - kc)) * pas;
            uint8_t *dp = S + j * (size_t)((size_t)1 << (b + 1 - kc)) * pas;
            for (size_t z = 0; z < nb; z++) {
                uint8_t x = s0p[z], y = s1p[z];
                qb[z] ^= y;
                dp[z] = x ^ y;
            }
        }
    }
    if (u) memcpy(u, S, nb);
    sl_effacer(S, N * nb); sl_effacer(qp, T * (size_t)kap * nb);
    free(S); free(qp);
    return 0;
}

/* M = [M' | I] : M·v, λ + B bits */
static void hash_M(const ctx_t *c, const uint8_t *rows, const uint8_t *v, uint8_t *o)
{
    size_t rb = (size_t)(c->p->lam + c->p->B), corps = 8 * (size_t)c->nb - rb, rB = (corps + 7) / 8;
    memset(o, 0, rb / 8);
    for (size_t r = 0; r < rb; r++) {
        const uint8_t *row = rows + r * rB;
        uint8_t acc = 0;
        for (size_t z = 0; z < rB; z++)
            acc ^= row[z] & (z + 1 == rB && (corps & 7) ? (uint8_t)(v[z] & ((1u << (corps & 7)) - 1)) : v[z]);
        acc ^= acc >> 4; acc ^= acc >> 2; acc ^= acc >> 1;
        uint8_t bt = (uint8_t)((acc & 1) ^ bit(v, corps + r));
        o[r >> 3] |= (uint8_t)(bt << (r & 7));
    }
}

static uint8_t *lignes_M(const ctx_t *c, const uint8_t *h1)
{
    size_t rb = (size_t)(c->p->lam + c->p->B), corps = 8 * (size_t)c->nb - rb, rB = (corps + 7) / 8;
    uint8_t *rows = alloc_api(1, rb * rB);
    if (rows) H(c, 'M', h1, 2 * (size_t)c->Bl, NULL, 0, NULL, 0, rows, rb * rB);
    return rows;
}

/* γ, puis g = γᵀ·H sur les n colonnes, et γ·y ; -1 si mémoire. Profil à gbits : γ_j dans un sous-groupe de 2^gbits éléments */
static int melanges(const ctx_t *c, const uint8_t *h2, const uint8_t *cols, const uint8_t *y, u64 *gam, u64 *g, u64 *gy)
{
    int W = c->W;
    size_t cB = (size_t)c->cB;
    H(c, 'g', h2, 2 * (size_t)c->Bl, NULL, 0, NULL, 0, gam, (size_t)c->m * (size_t)c->Bl);
    if (c->p->gbits)
        for (size_t j = 0; j < (size_t)c->m; j++)
            for (int z = 0; z < W; z++) {
                int lo = c->p->gbits - 64 * z;
                gam[j * (size_t)W + (size_t)z] &= lo >= 64 ? ~0ULL : lo <= 0 ? 0 : (1ULL << lo) - 1;
            }
    /* tables par octet : T[B][v] = Σ_{t ∈ v} γ_{8B+t} (construites en parallèle ; les tables par quartet sont plus lentes) */
    u64 *T = alloc_api(cB * 256 * (size_t)W, 8);
    if (!T) return -1;
#pragma omp parallel for schedule(static)
    for (size_t B = 0; B < cB; B++)
        for (int v = 1; v < 256; v++) {
            u64 *d = T + (B * 256 + (size_t)v) * (size_t)W;
            memcpy(d, T + (B * 256 + (size_t)(v & (v - 1))) * (size_t)W, (size_t)W * 8);
            fxor(W, d, gam + (B * 8 + (size_t)__builtin_ctz((unsigned)v)) * (size_t)W);
        }
#pragma omp parallel for schedule(static)
    for (int j = 0; j < c->k; j++) {
        u64 a[WMAX] = {0};
        const uint8_t *col = cols + (size_t)j * cB;
        for (size_t B = 0; B < cB; B++)
            fxor(W, a, T + (B * 256 + col[B]) * (size_t)W);
        memcpy(g + (size_t)j * (size_t)W, a, (size_t)W * 8);
    }
    for (int r = 0; r < c->p->cod; r++)
        memcpy(g + (size_t)(c->k + r) * (size_t)W, gam + (size_t)r * (size_t)W, (size_t)W * 8);
    memset(gy, 0, (size_t)W * 8);
    for (size_t B = 0; B < cB; B++)
        fxor(W, gy, T + (B * 256 + y[B]) * (size_t)W);
    free(T);
    return 0;
}

/* produit des contraintes, côté signataire : coefficients C_0..C_d de Σ γ_j F_j(X) ; -1 si mémoire */
static int contraintes_poly(const ctx_t *c, const uint8_t *wit, const u64 *V, const u64 *gam, const u64 *g, const u64 *gy, u64 *C)
{
    const vp_t *p = c->p;
    int W = c->W, d = p->d;
    size_t zero = (size_t)W * 8 * (size_t)(d + 1);
    memset(C, 0, zero);
    size_t Pw = 1;
    for (int t = 0; t < d; t++) Pw *= (size_t)p->mu[t];
    /* tampons par thread alloués avant la région parallèle : un échec se propage sans quitter un thread */
    int nt = omp_get_max_threads();
    size_t za = (size_t)(d + 1) * (size_t)W, zA = Pw * (size_t)(d + 1) * (size_t)W;
    u64 *accs = alloc_api((size_t)nt * za, 8), *As = alloc_api((size_t)nt * zA, 8), *Bs = alloc_api((size_t)nt * zA, 8);
    if (!accs || !As || !Bs) { free(accs); free(As); free(Bs); return -1; }
#pragma omp parallel num_threads(nt)
    {
        int id = omp_get_thread_num();
        u64 *acc = accs + (size_t)id * za, *A = As + (size_t)id * zA, *Bb = Bs + (size_t)id * zA;
#pragma omp for schedule(static)
        for (int i = 0; i < p->w; i++) {
            size_t o = (size_t)i * (size_t)c->sw;
            size_t pz = (size_t)p->cod + (size_t)i * (size_t)c->pairs;
            size_t taille = 1;
            memset(A, 0, (size_t)(d + 1) * (size_t)W * 8);
            A[0] = 1;                                                /* produit vide : 1 */
            for (int t = 0; t < d; t++) {
                int mu = p->mu[t];
                u64 Vd[8][WMAX] = {{0}}, bd[8];
                u64 sb = 0;
                for (int v = 0; v < mu - 1; v++) {
                    bd[v] = (u64)bit(wit, o + (size_t)v);
                    sb ^= bd[v];
                    memcpy(Vd[v], V + (o + (size_t)v) * (size_t)W, (size_t)W * 8);
                    fxor(W, Vd[mu - 1], Vd[v]);
                }
                bd[mu - 1] = 1 ^ sb;
                /* paires : p_v p_v' X^(d−2), de terme dominant b_v b_v' */
                for (int v = 0; v < mu - 1; v++)
                    for (int x = v + 1; x < mu - 1; x++) {
                        u64 tmp[WMAX], pr[3][WMAX];
                        gf_mul(W, Vd[v], Vd[x], pr[0]);
                        for (int z = 0; z < W; z++)
                            pr[1][z] = (Vd[v][z] & (0 - bd[x])) ^ (Vd[x][z] & (0 - bd[v]));
                        memset(pr[2], 0, (size_t)W * 8);
                        pr[2][0] = bd[v] & bd[x];
                        for (int l = 0; l < 3; l++) {
                            gf_mul(W, pr[l], gam + pz * (size_t)W, tmp);
                            fxor(W, acc + (size_t)(l + d - 2) * (size_t)W, tmp);
                        }
                        pz++;
                    }
                /* produit tensoriel par ce niveau */
                size_t nv = taille * (size_t)mu;
                memset(Bb, 0, nv * (size_t)(t + 2) * (size_t)W * 8);
                for (size_t a = 0; a < taille; a++)
                    for (int v = 0; v < mu; v++) {
                        u64 *dst = Bb + (a * (size_t)mu + (size_t)v) * (size_t)(t + 2) * (size_t)W;
                        const u64 *src = A + a * (size_t)(t + 1) * (size_t)W;
                        u64 tmp[WMAX];
                        for (int l = 0; l <= t; l++) {
                            gf_mul(W, src + (size_t)l * (size_t)W, Vd[v], tmp);
                            fxor(W, dst + (size_t)l * (size_t)W, tmp);
                            for (int z = 0; z < W; z++)
                                dst[(size_t)(l + 1) * (size_t)W + (size_t)z] ^= src[(size_t)l * (size_t)W + (size_t)z] & (0 - bd[v]);
                        }
                    }
                u64 *sw = A; A = Bb; Bb = sw;
                taille = nv;
                o += (size_t)mu - 1;
            }
            size_t decal = (size_t)i * (size_t)p->bloc;
            for (int q = 0; q < p->bloc; q++) {
                const u64 *gi = g + (decal + (size_t)q) * (size_t)W;
                const u64 *xq = A + (size_t)q * (size_t)(d + 1) * (size_t)W;
                u64 tmp[WMAX];
                for (int l = 0; l <= d; l++) {
                    gf_mul(W, xq + (size_t)l * (size_t)W, gi, tmp);
                    fxor(W, acc + (size_t)l * (size_t)W, tmp);
                }
            }
        }
#pragma omp critical
        for (size_t z = 0; z < za; z++) C[z] ^= acc[z];
    }
    sl_effacer(accs, (size_t)nt * za * 8); sl_effacer(As, (size_t)nt * zA * 8); sl_effacer(Bs, (size_t)nt * zA * 8);
    free(accs); free(As); free(Bs);
    fxor(W, C + (size_t)d * (size_t)W, gy);                          /* − (γ·y) X^d */
    return 0;
}

/* même somme, côté vérifieur : valeur en Δ, q = polynômes du témoin déjà évalués ; -1 si mémoire */
static int contraintes_val(const ctx_t *c, const u64 *q, const u64 *Dl, const u64 *pwD, const u64 *gam, const u64 *g, const u64 *gy, u64 *val)
{
    const vp_t *p = c->p;
    int W = c->W, d = p->d;
    (void)Dl;
    u64 r[WMAX] = {0};
    size_t Pw = 1;
    for (int t = 0; t < d; t++) Pw *= (size_t)p->mu[t];
    int nt = omp_get_max_threads();
    size_t zA = Pw * (size_t)W;
    u64 *As = alloc_api((size_t)nt * zA, 8), *Bs = alloc_api((size_t)nt * zA, 8);
    if (!As || !Bs) { free(As); free(Bs); return -1; }
#pragma omp parallel num_threads(nt)
    {
        u64 acc[WMAX] = {0}, tmp[WMAX];
        int id = omp_get_thread_num();
        u64 *A = As + (size_t)id * zA, *Bb = Bs + (size_t)id * zA;
#pragma omp for schedule(static)
        for (int i = 0; i < p->w; i++) {
            size_t o = (size_t)i * (size_t)c->sw, pz = (size_t)p->cod + (size_t)i * (size_t)c->pairs, taille = 1;
            memset(A, 0, (size_t)W * 8);
            A[0] = 1;
            for (int t = 0; t < d; t++) {
                int mu = p->mu[t];
                u64 qd[8][WMAX];
                memcpy(qd[mu - 1], pwD + (size_t)W, (size_t)W * 8);       /* X − Σ p_v */
                for (int v = 0; v < mu - 1; v++) {
                    memcpy(qd[v], q + (o + (size_t)v) * (size_t)W, (size_t)W * 8);
                    fxor(W, qd[mu - 1], qd[v]);
                }
                for (int v = 0; v < mu - 1; v++)
                    for (int x = v + 1; x < mu - 1; x++) {
                        u64 z1[WMAX], z2[WMAX];
                        gf_mul(W, qd[v], qd[x], z1);
                        gf_mul(W, z1, pwD + (size_t)(d - 2) * (size_t)W, z2);
                        gf_mul(W, z2, gam + pz * (size_t)W, tmp);
                        fxor(W, acc, tmp);
                        pz++;
                    }
                size_t nv = taille * (size_t)mu;
                for (size_t a = 0; a < taille; a++)
                    for (int v = 0; v < mu; v++)
                        gf_mul(W, A + a * (size_t)W, qd[v], Bb + (a * (size_t)mu + (size_t)v) * (size_t)W);
                u64 *sw = A; A = Bb; Bb = sw;
                taille = nv;
                o += (size_t)mu - 1;
            }
            size_t decal = (size_t)i * (size_t)p->bloc;
            for (int q2 = 0; q2 < p->bloc; q2++) {
                gf_mul(W, A + (size_t)q2 * (size_t)W, g + (decal + (size_t)q2) * (size_t)W, tmp);
                fxor(W, acc, tmp);
            }
        }
#pragma omp critical
        fxor(W, r, acc);
    }
    free(As); free(Bs);
    u64 tmp[WMAX];
    gf_mul(W, gy, pwD + (size_t)d * (size_t)W, tmp);
    fxor(W, r, tmp);
    memcpy(val, r, (size_t)W * 8);
    return 0;
}

/* bits de la section [o, o + λ) comme élément du corps */
static void sect_F(const ctx_t *c, const uint8_t *u, size_t o, u64 *a)
{
    memcpy(a, u + o / 8, (size_t)c->Bl);
}

/* Σ ξ^l V_{o+l} */
static void sect_V(const ctx_t *c, const u64 *V, size_t o, u64 *b)
{
    int W = c->W, lam = c->p->lam;
    memset(b, 0, (size_t)W * 8);
    for (int l = 0; l < lam; l++) {
        u64 xi[WMAX] = {0}, t[WMAX];
        xi[l / 64] = 1ULL << (l % 64);
        gf_mul(W, xi, V + (o + (size_t)l) * (size_t)W, t);
        fxor(W, b, t);
    }
}

/* V_j : bit (eκ + b) = bit j de qv[e][b] */
static void transposer(const ctx_t *c, const uint8_t *qv, u64 *V)
{
    size_t nbit = 8 * (size_t)c->nb, nb = (size_t)c->nb, W = (size_t)c->W;
    int tau = c->p->tau, kap = c->p->kap;
#pragma omp parallel for schedule(static)
    for (size_t j = 0; j < nbit; j++) {
        u64 *d = V + j * W;
        memset(d, 0, W * 8);
        for (int e = 0; e < tau; e++)
            for (int b = 0; b < kap; b++) {
                size_t pos = (size_t)e * (size_t)kap + (size_t)b;
                d[pos / 64] |= (u64)bit(qv + ((size_t)e * (size_t)kap + (size_t)b) * nb, j) << (pos % 64);
            }
    }
}

static size_t taille_sig(const ctx_t *c)
{
    const vp_t *p = c->p;
    size_t Bl = (size_t)c->Bl, ub = (size_t)(p->lam + p->B) / 8;
    return (size_t)c->Ls + 2 * Bl + (size_t)(p->tau - 1) * (size_t)c->nb + ub + (size_t)c->witB + (size_t)p->d * Bl + (size_t)p->topen * (size_t)c->Sb
           + (size_t)p->tau * 2 * Bl + 4;
}

/* transcription des coms + aux → h_com ; -1 si mémoire */
static int hacher_coms(const ctx_t *c, const uint8_t *salt, const uint8_t *hm, const uint8_t *coms, const uint8_t *aux, uint8_t *h)
{
    size_t Bl = (size_t)c->Bl, Ls = (size_t)c->Ls, hb = 2 * Bl, rep = c->N * 2 * Bl;
    int tau = c->p->tau;
    uint8_t *hs = alloc_api(1, (size_t)tau * hb);
    if (!hs) return -1;
#pragma omp parallel for schedule(static)
    for (int e = 0; e < tau; e++) {
        uint8_t ee[4];
        le32(ee, (uint32_t)e);
        H(c, 'c', salt, Ls, ee, 4, coms + (size_t)e * rep, rep, hs + (size_t)e * hb, hb);
    }
    uint8_t t[128];
    H(c, 'C', salt, Ls, hm, hb, hs, (size_t)tau * hb, t, hb);
    H(c, 'A', t, hb, aux, (size_t)(tau - 1) * (size_t)c->nb, NULL, 0, h, hb);
    free(hs);
    return 0;
}

/* Attaques des modèles réduits (banc des trois défis du Théorème 17, PROOFS § 3 bis) ; 0 = signature honnête.
 *   1 : défi Δ — sans témoin, α annule le résidu en d points de E, puis grinding de Δ parmi eux (terme q₃·d·2^−(τκ+wpow)) ;
 *   2 : défi γ — sans témoin, le témoin engagé change (donc h2) jusqu'à ce que le terme de degré d s'annule (terme q₂·2^−λ,
 *       exécutable sur un profil à gbits seulement) ;
 *   3 : contrôle VOLE — aux incohérent dans la répétition 1 et défi de cette répétition parié d'avance, grinding honnête :
 *       accepté si et seulement si le pari tombe (2^−κ) ;
 *   4 : idem, grinding jusqu'à ce que le défi de la répétition 1 égale le pari (coût ×2^κ).
 * Renvoie le nombre d'essais (de Δ ; de γ pour 2), ou -1 si mémoire ou aléa manquent : sig est alors remise à zéro. */
PROTO_SEUL static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + 1e-9 * (double)t.tv_nsec;
}

/* -DVOLE_PROFIL : temps cumulés par phase du signataire (outil de mesure, sans effet sur les sorties) */
#ifdef VOLE_PROFIL
static double prof_t[16], prof_t0;
static const char *prof_n[16];
#define PT0() (prof_t0 = maintenant())
#define PT(i, nom) do { double t_ = maintenant(); prof_t[i] += t_ - prof_t0; prof_n[i] = nom; prof_t0 = t_; } while (0)
#else
#define PT0() ((void)0)
#define PT(i, nom) ((void)0)
#endif

/* stratégie de Kales–Zaverucha adaptée (attaque 5, prototype seulement) : budgets de requêtes à H_2 (γ) puis à H_d (Δ) */
static long kz_q2 = 1, kz_q3 = 0;

#define EFFACE_LIBERE(p, n) do { if (p) { sl_effacer(p, n); free(p); } } while (0)
static long signer_sel(const ctx_t *c, const vpk_t *pk, const hcache_t *hc, const uint16_t *pos, const uint8_t *msg, size_t lmsg,
                       const uint8_t *sel, uint8_t *sig, int attaque)
{
    const vp_t *p = c->p;
    size_t Bl = (size_t)c->Bl, Sb = (size_t)c->Sb, Ls = (size_t)c->Ls, hb = 2 * Bl, nb = (size_t)c->nb, L = c->L, W = (size_t)c->W;
    size_t ub = (size_t)(p->lam + p->B) / 8, zs = taille_sig(c);
    int tau = p->tau, kap = p->kap, d = p->d;
    long essais = -1, essais_g = 0;
    uint8_t salt[64], epk[32 + 512], hm[128], h1[128], h2[128], h3[128], hv[128];
    u64 gy[WMAX];
    uint8_t *rows = NULL;
    uint8_t *nd = alloc_api(2 * L, Sb), *connu = alloc_api(2 * L, 1), *cache = alloc_api(1, 2 * L);
    uint8_t *coms = alloc_api((size_t)tau * c->N, hb), *qv = alloc_api((size_t)tau * (size_t)kap, nb), *us = alloc_api((size_t)tau, nb);
    uint8_t *aux = alloc_api((size_t)tau, nb), *wit = alloc_api(nb, 1), *epos = alloc_api((size_t)p->w, 2);
    uint8_t *ht = alloc_api((size_t)tau * (size_t)kap, ub), *dw = alloc_api(1, (size_t)c->witB), *ut = alloc_api(ub, 1);
    u64 *V = alloc_api(8 * nb * W, 8), *gam = alloc_api((size_t)c->m * W, 8), *g = alloc_api((size_t)p->n * W, 8), *C = alloc_api((size_t)(d + 1) * W, 8);
    if (!nd || !connu || !cache || !coms || !qv || !us || !aux || !wit || !epos || !ht || !dw || !ut || !V || !gam || !g || !C)
        goto fin;
    if (memcmp(hc->seed, pk->seed, Bl) || ((attaque == 2 || attaque == 5) && !p->gbits) || ((attaque == 3 || attaque == 4) && tau < 2))
        goto fin;
    const uint8_t *cols = hc->cols;
    PT0();
    if (sel) memcpy(salt, sel, Ls);                                   /* sel imposé : conformité, KAT */
    else if (alea_api(salt, Ls)) goto fin;
    size_t lpk = encoder_pk(c, pk, epk);
    H(c, 'm', epk, lpk, msg, lmsg, NULL, 0, hm, hb);
    bits_temoin(c, pos, wit);
    for (int i = 0; i < p->w; i++) { epos[2 * i] = (uint8_t)pos[i]; epos[2 * i + 1] = (uint8_t)(pos[i] >> 8); }
    H(c, 'r', epos, (size_t)p->w * 2, salt, Ls, hm, hb, nd + Sb, Sb);
    connu[1] = 1;
    PT(0, "témoin, racine");
    developper_arbre(c, salt, nd, connu);
    PT(1, "arbre GGM");
    for (int e = 0; e < tau; e++)
        if (repetition(c, salt, e, nd, connu, coms + (size_t)e * c->N * hb, qv + (size_t)e * (size_t)kap * nb, us + (size_t)e * nb, 0))
            goto fin;
    PT(2, "feuilles et VOLE");
    for (int e = 1; e < tau; e++)
        for (size_t z = 0; z < nb; z++)
            aux[(size_t)(e - 1) * nb + z] = us[z] ^ us[(size_t)e * nb + z];
    uint32_t pari = 0;
    if (attaque == 3 || attaque == 4) {                               /* aux₁ ⊕= δ ; v₁,b ⊕= pari_b·δ : cohérent si ch₁ = pari */
        uint8_t dl[512];
        if (alea_api(dl, nb) || alea_api(&pari, 4)) goto fin;
        dl[0] |= 1;
        pari &= (1u << kap) - 1;
        for (size_t z = 0; z < nb; z++) aux[z] ^= dl[z];
        for (int b = 0; b < kap; b++)
            if ((pari >> b) & 1)
                for (size_t z = 0; z < nb; z++) qv[((size_t)kap + (size_t)b) * nb + z] ^= dl[z];
    }
    if (hacher_coms(c, salt, hm, coms, aux, h1)) goto fin;
    PT(3, "hachage des engagements");
    SL_PUBLIC(h1, hb); SL_PUBLIC(aux, (size_t)tau * nb);
    rows = lignes_M(c, h1);
    if (!rows) goto fin;
    hash_M(c, rows, us, ut);
#pragma omp parallel for schedule(static)
    for (int x = 0; x < tau * kap; x++)
        hash_M(c, rows, qv + (size_t)x * nb, ht + (size_t)x * ub);
    H(c, 'v', h1, hb, ht, (size_t)tau * (size_t)kap * ub, NULL, 0, hv, hb);
    PT(4, "contrôle VOLE (M)");
    transposer(c, qv, V);
    PT(5, "transposition");
    int gamma_ok = 0, echec = 0;
    for (;;) {
        essais_g++;
        for (int z = 0; z < c->witB; z++) dw[z] = wit[z] ^ us[z];
        if (c->witb & 7) dw[c->witB - 1] &= (uint8_t)((1u << (c->witb & 7)) - 1);
        H(c, '2', hv, hb, ut, ub, dw, (size_t)c->witB, h2, hb);
        if (melanges(c, h2, cols, pk->y, gam, g, gy)) goto fin;
        PT(6, "γ et γᵀH");
        if (contraintes_poly(c, wit, V, gam, g, gy, C)) goto fin;
        PT(7, "contraintes (polynômes)");
        if (attaque != 2 && attaque != 5) break;
        u64 nul = 0;                                                  /* attaque γ : C_d nul par chance, sinon autre témoin */
        for (size_t z = 0; z < W; z++) nul |= C[(size_t)d * W + z];
        if (!nul) { gamma_ok = 1; break; }
        if (attaque == 5 && essais_g >= kz_q2) break;                 /* budget q₂ épuisé : on vise Δ */
        uint32_t z;
        if (alea_api(&z, 4)) goto fin;
        z %= (uint32_t)c->witb;
        wit[z >> 3] ^= (uint8_t)(1u << (z & 7));
    }
    SL_PUBLIC(h2, hb); SL_PUBLIC(ut, ub); SL_PUBLIC(dw, (size_t)c->witB);
    /* masque : A_t = a_t X + b_t, M(X) = Σ A_t X^(t−1) */
    u64 alpha[DMAX][WMAX] = {{0}};
    for (int l = 0; l < d; l++) memcpy(alpha[l], C + (size_t)l * W, W * 8);
    size_t om = 8 * (size_t)c->witB;
    for (int t = 1; t < d; t++) {
        u64 a[WMAX], b[WMAX];
        sect_F(c, us, om + (size_t)(t - 1) * (size_t)p->lam, a);
        sect_V(c, V, om + (size_t)(t - 1) * (size_t)p->lam, b);
        fxor((int)W, alpha[t - 1], b);
        fxor((int)W, alpha[t], a);
    }
    u64 racines[DMAX][WMAX];
    int viser_delta = attaque == 1 || (attaque == 5 && !gamma_ok);
    if (viser_delta) {                                                /* R(X) = c_d Π (X + ρ_t), retiré de α ; ρ_t distincts */
        u64 R[DMAX + 1][WMAX] = {{0}};
        memcpy(R[0], C + (size_t)d * W, W * 8);
        for (int t = 0; t < d; t++) {
            uint32_t v = 0;
            memset(racines[t], 0, W * 8);
            /* ρ_t ∈ E : τκ bits aléatoires */
            for (int deja = 1; deja;) {
                memset(racines[t], 0, W * 8);
                for (int b = 0; b < tau * kap; b++) {
                    if (b % 32 == 0 && alea_api(&v, 4)) goto fin;
                    racines[t][b / 64] |= (u64)((v >> (b % 32)) & 1) << (b % 64);
                }
                deja = 0;
                for (int u = 0; u < t; u++) deja |= !memcmp(racines[u], racines[t], W * 8);
            }
            for (int l = t + 1; l >= 0; l--) {
                u64 x[WMAX];
                gf_mul((int)W, R[l], racines[t], x);
                if (l) { for (size_t z = 0; z < W; z++) R[l][z] = x[z] ^ R[l - 1][z]; } else memcpy(R[0], x, W * 8);
            }
        }
        for (int l = 0; l < d; l++) fxor((int)W, alpha[l], R[l]);
    }
    uint8_t ab[DMAX * 32];
    for (int l = 0; l < d; l++) memcpy(ab + (size_t)l * Bl, alpha[l], Bl);
    H(c, '3', h2, hb, ab, (size_t)d * Bl, NULL, 0, h3, hb);
    SL_PUBLIC(ab, (size_t)d * Bl); SL_PUBLIC(h3, hb);
    PT(8, "masque, α");
    uint32_t ctr = 0, ch[64] = {0};
    long n_d = 0;
    if (!viser_delta && attaque != 4) {                               /* recherche parallèle, même ctr que la boucle */
        ctr = premier_defi(c, h3, &n_d);
        if (defi(c, h3, ctr, ch, cache) < 0) fatal("premier_defi incohérent avec defi");
    }
    else for (;; ctr++) {
        n_d++;
        if (attaque == 5 && n_d > kz_q3) { echec = 1; break; }       /* budget q₃ épuisé : signature invalide */
        if (defi(c, h3, ctr, ch, cache) < 0)
            continue;
        if (attaque == 4 && ch[1] != pari)
            continue;
        if (!viser_delta)
            break;
        u64 D[WMAX] = {0};
        for (int e = 0; e < tau; e++)
            for (int b = 0; b < kap; b++) {
                int pz = e * kap + b;
                D[pz / 64] |= (u64)((ch[e] >> b) & 1) << (pz % 64);
            }
        int t = 0;
        for (; t < d && memcmp(D, racines[t], W * 8); t++) {}
        if (t < d)
            break;
    }
    uint8_t *o = sig;
    memcpy(o, salt, Ls); o += Ls;
    memcpy(o, h3, hb); o += hb;
    memcpy(o, aux, (size_t)(tau - 1) * nb); o += (size_t)(tau - 1) * nb;
    memcpy(o, ut, ub); o += ub;
    memcpy(o, dw, (size_t)c->witB); o += c->witB;
    memcpy(o, ab, (size_t)d * Bl); o += (size_t)d * Bl;
    uint8_t *on = o;
    memset(on, 0, (size_t)p->topen * Sb);
    for (size_t x = 2; x < 2 * L; x++)
        if (!cache[x] && cache[x / 2]) {
            memcpy(on, nd + x * Sb, Sb);
            on += Sb;
        }
    o += (size_t)p->topen * Sb;
    for (int e = 0; e < tau; e++) {
        memcpy(o, coms + ((size_t)e * c->N + ch[e]) * hb, hb);
        o += hb;
    }
    le32(o, ctr);
    PT(9, "grinding, sortie");
    essais = attaque == 2 ? essais_g : attaque == 5 ? !echec : n_d;   /* attaque 5 : 1 si falsification produite */
fin:
    if (essais < 0 && sig) memset(sig, 0, zs);                         /* jamais de signature partielle */
    /* graines, masques et témoin ; le reste est public ou s'en déduit */
    EFFACE_LIBERE(nd, 2 * L * Sb); EFFACE_LIBERE(qv, (size_t)tau * (size_t)kap * nb); EFFACE_LIBERE(us, (size_t)tau * nb);
    EFFACE_LIBERE(wit, nb); EFFACE_LIBERE(V, 8 * nb * W * 8); EFFACE_LIBERE(C, (size_t)(d + 1) * W * 8);
    EFFACE_LIBERE(coms, (size_t)tau * c->N * hb); EFFACE_LIBERE(ht, (size_t)tau * (size_t)kap * ub); EFFACE_LIBERE(epos, (size_t)p->w * 2);
    EFFACE_LIBERE(aux, (size_t)tau * nb); EFFACE_LIBERE(dw, (size_t)c->witB); EFFACE_LIBERE(ut, ub);
    sl_effacer(salt, sizeof salt); sl_effacer(hv, sizeof hv);
    free(connu); free(cache); free(gam); free(g); free(rows);
    return essais;
}

PROTO_SEUL static long signer(const ctx_t *c, const vpk_t *pk, const hcache_t *hc, const uint16_t *pos, const uint8_t *msg, size_t lmsg, uint8_t *sig, int attaque)
{
    return signer_sel(c, pk, hc, pos, msg, lmsg, NULL, sig, attaque);
}

/* 1 : acceptée ; 0 : rejetée ; -1 : mémoire indisponible (jamais une acceptation) */
static int verifier_r(const ctx_t *c, const vpk_t *pk, const hcache_t *hc, const uint8_t *msg, size_t lmsg, const uint8_t *sig, size_t siglen)
{
    const vp_t *p = c->p;
    if (!sig || !msg || siglen != taille_sig(c) || memcmp(hc->seed, pk->seed, (size_t)c->Bl))
        return 0;
    const uint8_t *cols = hc->cols;
    size_t Bl = (size_t)c->Bl, Sb = (size_t)c->Sb, Ls = (size_t)c->Ls, hb = 2 * Bl, nb = (size_t)c->nb, L = c->L, W = (size_t)c->W;
    size_t ub = (size_t)(p->lam + p->B) / 8;
    int tau = p->tau, kap = p->kap, d = p->d, ok = -1;
    const uint8_t *salt = sig, *h3 = salt + Ls, *aux = h3 + hb, *ut = aux + (size_t)(tau - 1) * nb, *dw = ut + ub;
    const uint8_t *ab = dw + c->witB, *nds = ab + (size_t)d * Bl, *chs = nds + (size_t)p->topen * Sb, *pct = chs + (size_t)tau * hb;
    uint32_t ctr = lit32(pct), ch[64];
    uint8_t epk[32 + 512], hm[128], h1[128], h2[128], h3c[128], hv[128];
    uint8_t *rows = NULL;
    uint8_t *nd = alloc_api(2 * L, Sb), *connu = alloc_api(2 * L, 1), *cache = alloc_api(1, 2 * L);
    uint8_t *coms = alloc_api((size_t)tau * c->N, hb), *qv = alloc_api((size_t)tau * (size_t)kap, nb), *ht = alloc_api((size_t)tau * (size_t)kap, ub);
    u64 *q = alloc_api(8 * nb * W, 8), *gam = alloc_api((size_t)c->m * W, 8), *g = alloc_api((size_t)p->n * W, 8), gy[WMAX];
    if (!nd || !connu || !cache || !coms || !qv || !ht || !q || !gam || !g)
        goto fin;
    ok = 0;
    if (defi(c, h3, ctr, ch, cache) < 0)
        goto fin;
    if ((c->witb & 7) && (dw[c->witB - 1] >> (c->witb & 7)))
        goto fin;
    H(c, 'm', epk, encoder_pk(c, pk, epk), msg, lmsg, NULL, 0, hm, hb);
    {   /* nœuds révélés, remplissage nul exigé (encodage unique) */
        const uint8_t *on = nds;
        for (size_t x = 2; x < 2 * L; x++)
            if (!cache[x] && cache[x / 2]) {
                memcpy(nd + x * Sb, on, Sb);
                connu[x] = 1;
                on += Sb;
            }
        for (const uint8_t *z = on; z < chs; z++)
            if (*z)
                goto fin;
    }
    developper_arbre(c, salt, nd, connu);
    for (int e = 0; e < tau; e++) {
        if (repetition(c, salt, e, nd, connu, coms + (size_t)e * c->N * hb, qv + (size_t)e * (size_t)kap * nb, NULL, ch[e])) { ok = -1; goto fin; }
        memcpy(coms + ((size_t)e * c->N + ch[e]) * hb, chs + (size_t)e * hb, hb);
        if (e)
            for (int b = 0; b < kap; b++)
                if ((ch[e] >> b) & 1)
                    for (size_t z = 0; z < nb; z++)
                        qv[((size_t)e * (size_t)kap + (size_t)b) * nb + z] ^= aux[(size_t)(e - 1) * nb + z];
    }
    if (hacher_coms(c, salt, hm, coms, aux, h1)) { ok = -1; goto fin; }
    rows = lignes_M(c, h1);
    if (!rows) { ok = -1; goto fin; }
#pragma omp parallel for schedule(static) collapse(2)
    for (int e = 0; e < tau; e++)
        for (int b = 0; b < kap; b++) {
            size_t x = (size_t)e * (size_t)kap + (size_t)b;
            hash_M(c, rows, qv + x * nb, ht + x * ub);
            if ((ch[e] >> b) & 1)
                for (size_t z = 0; z < ub; z++)
                    ht[x * ub + z] ^= ut[z];
        }
    H(c, 'v', h1, hb, ht, (size_t)tau * (size_t)kap * ub, NULL, 0, hv, hb);
    H(c, '2', hv, hb, ut, ub, dw, (size_t)c->witB, h2, hb);
    H(c, '3', h2, hb, ab, (size_t)d * Bl, NULL, 0, h3c, hb);
    if (memcmp(h3c, h3, hb))
        goto fin;
    {
        u64 D[WMAX] = {0}, pw[DMAX + 1][WMAX] = {{0}};
        for (int e = 0; e < tau; e++)
            for (int b = 0; b < kap; b++) {
                int pz = e * kap + b;
                D[pz / 64] |= (u64)((ch[e] >> b) & 1) << (pz % 64);
            }
        pw[0][0] = 1;
        for (int l = 1; l <= d; l++) gf_mul((int)W, pw[l - 1], D, pw[l]);
        if (melanges(c, h2, cols, pk->y, gam, g, gy)) { ok = -1; goto fin; }
        transposer(c, qv, q);
#pragma omp parallel for schedule(static)
        for (int j = 0; j < c->witb; j++)
            if (bit(dw, (size_t)j))
                fxor((int)W, q + (size_t)j * W, D);
        u64 g_d[WMAX], s[WMAX];
        u64 pwf[(DMAX + 1) * WMAX];                                   /* contraintes_val lit au pas de W */
        for (int l = 0; l <= d; l++) memcpy(pwf + (size_t)l * W, pw[l], W * 8);
        if (contraintes_val(c, q, D, pwf, gam, g, gy, g_d)) { ok = -1; goto fin; }
        /* M(Δ) + Σ γ F(Δ) = Σ α_l Δ^l */
        memcpy(s, g_d, W * 8);
        size_t om = 8 * (size_t)c->witB;
        for (int t = 1; t < d; t++) {
            u64 m[WMAX], x[WMAX];
            sect_V(c, q, om + (size_t)(t - 1) * (size_t)p->lam, m);
            gf_mul((int)W, m, pw[t - 1], x);
            fxor((int)W, s, x);
        }
        for (int l = 0; l < d; l++) {
            u64 a[WMAX] = {0}, x[WMAX];
            memcpy(a, ab + (size_t)l * Bl, Bl);
            gf_mul((int)W, a, pw[l], x);
            fxor((int)W, s, x);
        }
        u64 z = 0;
        for (size_t i = 0; i < W; i++) z |= s[i];
        ok = z == 0;
    }
fin:
    free(nd); free(connu); free(cache); free(coms); free(qv); free(ht); free(q); free(gam); free(g); free(rows);
    return ok;
}

PROTO_SEUL static int verifier(const ctx_t *c, const vpk_t *pk, const hcache_t *hc, const uint8_t *msg, size_t lmsg, const uint8_t *sig, size_t siglen)
{
    return verifier_r(c, pk, hc, msg, lmsg, sig, siglen) == 1;
}



/* ================================================================ API publique (sillage.h) */
static const vp_t *const VOLE_PROFILS[4] = {&PR128, &PR256, &PR128F, &PR256F};

static int vole_ctx(int profil, ctx_t *c)
{
    return profil < 0 || profil > 3 ? -1 : ctx_init(c, VOLE_PROFILS[profil]);
}

void sl_vole_tailles(int profil, size_t *pk, size_t *sk, size_t *sig)
{
    ctx_t c;
    if (vole_ctx(profil, &c)) { *pk = *sk = *sig = 0; return; }
    *pk = (size_t)c.Bl + (size_t)c.cB;
    *sk = *pk + (size_t)c.p->w;                          /* pk ‖ positions (un octet chacune : bloc = 256) */
    *sig = taille_sig(&c);
}

void sl_vole_kat(int actif, uint32_t ctr) { kat_actif = actif; kat_ctr = ctr; }

static void decoder_pk(const ctx_t *c, const uint8_t *b, vpk_t *pk)
{
    memset(pk, 0, sizeof *pk);
    memcpy(pk->seed, b, (size_t)c->Bl);
    memcpy(pk->y, b + c->Bl, (size_t)c->cB);
}

static int cache_H(const ctx_t *c, const vpk_t *pk, hcache_t *hc)
{
    hc->cols = alloc_api((size_t)c->k, (size_t)c->cB);
    if (!hc->cols) return -1;
    developper_H(c, pk->seed, hc->cols);
    memcpy(hc->seed, pk->seed, sizeof hc->seed);
    return 0;
}

int sl_vole_keygen(int profil, uint8_t *pk, uint8_t *sk)
{
    ctx_t c;
    if (vole_ctx(profil, &c) || c.p->bloc > 256) return -1;
    vpk_t k;
    uint16_t pos[512];
    hcache_t hc = {.cols = alloc_api((size_t)c.k, (size_t)c.cB)};
    if (!hc.cols) return -1;
    int r = keygen(&c, &k, pos, &hc);
    if (!r) {
        size_t lpk = encoder_pk(&c, &k, pk);
        memcpy(sk, pk, lpk);
        for (int i = 0; i < c.p->w; i++) sk[lpk + (size_t)i] = (uint8_t)pos[i];
    }
    sl_effacer(pos, sizeof pos);
    free(hc.cols);
    return r;
}

int sl_vole_sign_sel(int profil, const uint8_t *sk, const uint8_t *msg, size_t len, const uint8_t *sel, uint8_t *sig)
{
    ctx_t c;
    if (vole_ctx(profil, &c) || !sk || !sig || (!msg && len)) return -1;
    vpk_t k;
    uint16_t pos[512];
    hcache_t hc;
    size_t lpk = (size_t)c.Bl + (size_t)c.cB;
    decoder_pk(&c, sk, &k);
    for (int i = 0; i < c.p->w; i++) pos[i] = sk[lpk + (size_t)i];
    VALGRIND_SECRET(pos, (size_t)c.p->w * 2);
    if (cache_H(&c, &k, &hc)) { sl_effacer(pos, sizeof pos); memset(sig, 0, taille_sig(&c)); return -1; }
    long e = signer_sel(&c, &k, &hc, pos, msg ? msg : (const uint8_t *)"", len, sel, sig, 0);
    sl_effacer(pos, sizeof pos);
    free(hc.cols);
    return e < 0 ? -1 : 0;
}

int sl_vole_sign(int profil, const uint8_t *sk, const uint8_t *msg, size_t len, uint8_t *sig)
{
    return sl_vole_sign_sel(profil, sk, msg, len, NULL, sig);
}

int sl_vole_verify(int profil, const uint8_t *pk, const uint8_t *msg, size_t len, const uint8_t *sig, size_t siglen)
{
    ctx_t c;
    if (vole_ctx(profil, &c) || !pk || (!msg && len)) return 0;
    vpk_t k;
    hcache_t hc;
    decoder_pk(&c, pk, &k);
    if (cache_H(&c, &k, &hc)) return -1;
    int r = verifier_r(&c, &k, &hc, msg ? msg : (const uint8_t *)"", len, sig, siglen);
    free(hc.cols);
    return r;
}
