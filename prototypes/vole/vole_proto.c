/* Piste 9, devenue Sillage-SIG v0.5 : banc d'essai du schéma VOLE-in-the-Head de sillage/c/vole.c (inclus ci-dessous, même
 * source que la bibliothèque). Ajoute aux fonctions du cœur : profils réduits, attaques exécutées (défis Δ, γ, contrôle VOLE,
 * SUF), contrôles indépendants, KAT, fuzz, injection d'échecs, dudect, ctgrind et mesures. Paramètres : vole_params.c.
 * Revue de code : docs/VOLE_CODE_REVIEW.md. Sécurité : PROOFS § 3 bis.
 *     build/vole_proto   (depuis la racine) → resultats/vole_proto.json
 *     build/vole_proto --kat | --fuzz N [graine] | --injection | --dudect N | --bench N | --kz N (→ resultats/vole_kz.json)
 *     compilé avec -DSL_VALGRIND : --ct [128|256], --ct-temoin (ctgrind)
 */
#define VOLE_PROTOTYPE
#include "resultat.h"
#include "vole.c"                                         /* sillage/c/vole.c : le cœur, partagé avec la bibliothèque */

static void *alloue(size_t a, size_t b)
{
    size_t t;
    void *p = __builtin_mul_overflow(a, b, &t) ? NULL : calloc(t ? t : 1, 1);
    if (!p) fatal("allocation impossible");
    return p;
}

static void alea(void *o, size_t n)
{
    if (alea_api(o, n)) fatal("aléa système indisponible");
}

/* modèle réduit des attaques : E de taille N^τ = 2^12, soit 2^10 essais attendus pour d = 4 ; blocs de 16 = 2^4 */
static const vp_t PRTOY = {"VOLE-reduit", 128, 128, 64, 8, 16, 4, {2, 2, 2, 2}, 2, 6, 0, 1 << 12, 16, 0, 0};
/* Kales–Zaverucha adapté à VOLE, échelle intermédiaire : vrais blocs de 256 (μ = (4,4,4,4)), corps GF(2^128), H de 80 lignes,
 * τ = 4, κ = 4 (τκ = 16), γ dans un sous-groupe de 2^12 éléments ; T_open = 32 ne refuse jamais (≤ τ·log2(2L) = 28 nœuds) */
static const vp_t PRKZ = {"VOLE-KZ", 128, 2048, 80, 8, 256, 4, {4, 4, 4, 4}, 4, 4, 0, 32, 16, 12, 0};
/* même modèle, γ réduit à 2^10 valeurs : la chance sur γ coûte 2^10 essais de h2 */
static const vp_t PRGAM = {"VOLE-reduit-gamma", 128, 128, 64, 8, 16, 4, {2, 2, 2, 2}, 2, 6, 0, 1 << 12, 16, 10, 0};


static int cmpd(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* ---------------------------------------------------------------- contrôles indépendants du flux signer/vérifier */
/* référence bit à bit de gf_mul, sans produit sans retenue */
static void gf_mul_ref(int W, const u64 *a, const u64 *b, u64 *o)
{
    const u64 r = W == 2 ? 0x87 : 0x425;
    u64 x[WMAX], acc[WMAX] = {0};
    memcpy(x, a, (size_t)W * 8);
    for (int i = 0; i < W * 64; i++) {
        if ((b[i / 64] >> (i % 64)) & 1)
            fxor(W, acc, x);
        u64 h = x[W - 1] >> 63;
        for (int j = W - 1; j > 0; j--) x[j] = (x[j] << 1) | (x[j - 1] >> 63);
        x[0] = (x[0] << 1) ^ (r & (0 - h));
    }
    memcpy(o, acc, (size_t)W * 8);
}

static int ctl_corps(void)
{
    int ok = 1;
    for (int W = 2; W <= 4; W += 2)
        for (int i = 0; i < 2000; i++) {
            u64 a[WMAX], b[WMAX], x[WMAX], y[WMAX];
            alea(a, sizeof a); alea(b, sizeof b);
            if (i < 8) memset(a, i & 1 ? 0xFF : 0, sizeof a);       /* valeurs extrêmes : retenue maximale de la réduction */
            gf_mul(W, a, b, x);
            gf_mul_ref(W, a, b, y);
            ok &= !memcmp(x, y, (size_t)W * 8);
        }
    return ok;
}

static int ctl_h4(const ctx_t *c)
{
    uint8_t sel[64], g[4][64], o[4][256], z[256];
    uint32_t idx[4] = {0, 1, 0x01020304, 0xFFFFFFFF};
    const uint8_t *pg[4];
    uint8_t *po[4];
    alea(sel, sizeof sel);
    for (int q = 0; q < 4; q++) { alea(g[q], sizeof g[q]); pg[q] = g[q]; po[q] = o[q]; }
    H4(c, 'n', sel, (size_t)c->Ls, idx, pg, (size_t)c->Sb, po, sizeof o[0]);
    int ok = 1;
    for (int q = 0; q < 4; q++) {
        uint8_t e[4];
        le32(e, idx[q]);
        H(c, 'n', sel, (size_t)c->Ls, e, 4, g[q], (size_t)c->Sb, z, sizeof z);
        ok &= !memcmp(z, o[q], sizeof z);
    }
    return ok;
}

/* tous les défis de petits arbres : nœuds révélés comptés à la main, reconstruction exacte, feuilles cachées inconnues */
static int ctl_arbres(void)
{
    int ok = 1;
    for (int tau = 1; tau <= 3; tau++)
        for (int kap = 1; kap <= 3; kap++) {
            vp_t v = PRTOY;
            v.tau = tau; v.kap = kap; v.topen = 1 << 20;
            ctx_t c;
            ctx_ok(&c, &v);
            size_t L = c.L, Sb = (size_t)c.Sb, N = c.N;
            uint8_t *nd = alloue(2 * L, Sb), *connu = alloue(2 * L, 1), *cache = alloue(2 * L, 1), *n2 = alloue(2 * L, Sb), *c2 = alloue(2 * L, 1), sel[64];
            alea(sel, sizeof sel);
            alea(nd + Sb, Sb);
            connu[1] = 1;
            developper_arbre(&c, sel, nd, connu);
            for (size_t x = L; x < 2 * L; x++) ok &= connu[x];
            size_t total = 1;
            for (int e = 0; e < tau; e++) total *= N;
            for (size_t code = 0; code < total; code++) {
                uint32_t ch[3] = {0};
                size_t r = code;
                for (int e = 0; e < tau; e++) { ch[e] = (uint32_t)(r % N); r /= N; }
                int n = marquer(&c, ch, cache), compte = 0;
                memset(c2, 0, 2 * L);
                memset(n2, 0, 2 * L * Sb);
                for (size_t x = 2; x < 2 * L; x++)
                    if (!cache[x] && cache[x / 2]) { memcpy(n2 + x * Sb, nd + x * Sb, Sb); c2[x] = 1; compte++; }
                ok &= n == compte;
                developper_arbre(&c, sel, n2, c2);
                for (int e = 0; e < tau; e++)
                    for (size_t i = 0; i < N; i++) {
                        size_t x = L + i * (size_t)tau + (size_t)e;
                        ok &= x < 2 * L;
                        if (i == ch[e]) ok &= !c2[x];
                        else ok &= c2[x] && !memcmp(n2 + x * Sb, nd + x * Sb, Sb);
                    }
            }
            free(nd); free(connu); free(cache); free(n2); free(c2);
        }
    return ok;
}

/* Σ C_l Δ^l = valeur côté vérifieur, sur témoin valide ou non ; C_d nul si et seulement si le témoin est valide */
static int ctl_contraintes(const ctx_t *c, const hcache_t *hc, const vpk_t *pk, const uint16_t *pos)
{
    const vp_t *p = c->p;
    size_t W = (size_t)c->W, nb = (size_t)c->nb;
    int d = p->d, ok = 1;
    u64 *V = alloue(8 * nb * W, 8), *q = alloue(8 * nb * W, 8), *gam = alloue((size_t)c->m * W, 8), *g = alloue((size_t)p->n * W, 8), gy[WMAX], *C = alloue((size_t)(d + 1) * W, 8);
    uint8_t *wit = alloue(nb, 1), h2[128];
    uint16_t *fx = alloue((size_t)p->w, 2);
    alea(h2, 2 * (size_t)c->Bl);
    melanges(c, h2, hc->cols, pk->y, gam, g, gy);
    for (int essai = 0; essai < 3; essai++) {
        memcpy(fx, pos, (size_t)p->w * 2);
        if (essai == 1) fx[0] = (uint16_t)((fx[0] + 1) % p->bloc);   /* élémentaire, mais syndrome faux */
        bits_temoin(c, fx, wit);
        if (essai == 2) wit[0] |= 3;                                 /* deux bits à 1 : paires violées si μ > 2 */
        alea(V, 8 * nb * W * 8);
        contraintes_poly(c, wit, V, gam, g, gy, C);
        u64 nul = 0;
        for (size_t z = 0; z < W; z++) nul |= C[(size_t)d * W + z];
        int valide = !memcmp(fx, pos, (size_t)p->w * 2) && essai == 0;
        ok &= (nul == 0) == valide;
        u64 D[WMAX], pw[(DMAX + 1) * WMAX] = {0}, val[WMAX], s[WMAX] = {0}, t[WMAX];
        alea(D, sizeof D);
        pw[0] = 1;
        for (int l = 1; l <= d; l++) gf_mul((int)W, pw + (size_t)(l - 1) * W, D, pw + (size_t)l * W);
        for (int j = 0; j < c->witb; j++) {
            memcpy(q + (size_t)j * W, V + (size_t)j * W, W * 8);
            if (bit(wit, (size_t)j)) fxor((int)W, q + (size_t)j * W, D);
        }
        contraintes_val(c, q, D, pw, gam, g, gy, val);
        for (int l = 0; l <= d; l++) {
            gf_mul((int)W, C + (size_t)l * W, pw + (size_t)l * W, t);
            fxor((int)W, s, t);
        }
        ok &= !memcmp(s, val, W * 8);
    }
    free(V); free(q); free(gam); free(g); free(C); free(wit); free(fx);
    return ok;
}

/* Annexe normative (SPEC § 4 bis.7), écrite d'après le texte de l'annexe et non d'après contraintes_poly : pas de produit
 * tensoriel incrémental ni de table γᵀH. Pour le bloc i, le chiffre t (o_t = i·sw + Σ_{t'<t}(μ_{t'} − 1)) :
 *   P_{i,t,v}(X) = b_{o_t+v}·X + V_{o_t+v}  (v < μ_t − 1),   P_{i,t,μ_t−1}(X) = (1 ⊕ Σ_v b_{o_t+v})·X + Σ_v V_{o_t+v} ;
 *   Q_{i,q}(X) = Π_t P_{i,t,δ_t(q)}(X), δ_t(q) = ⌊q / Π_{t'>t} μ_{t'}⌋ mod μ_t ;
 *   C(X) = Σ_r γ_r·(Σ_j H_{r,j}·Q_j(X) + y_r·X^d) + Σ_{i,t, v<x<μ_t−1} γ_{r_tot + π(i,t,v,x)}·X^{d−2}·P_{i,t,v}(X)·P_{i,t,x}(X),
 * j = i·b + q, H_{r,j} = bit r de la colonne j de H′ (j < k) ou [r = j − k], π dans l'ordre (i, t, v, x) croissant.
 * Renvoie le nombre d'éléments de γ utilisés (doit valoir m). */
static size_t contraintes_annexe(const ctx_t *c, const uint8_t *wit, const u64 *V, const u64 *gam, const uint8_t *cols, const uint8_t *y, u64 *C)
{
    const vp_t *p = c->p;
    int W = c->W, d = p->d, r_tot = p->cod;
    memset(C, 0, (size_t)(d + 1) * (size_t)W * 8);
    size_t nb_gam = (size_t)r_tot;
    for (int i = 0; i < p->w; i++) {
        /* polynômes de degré 1 des chiffres : P[t][v] = (coef0, coef1) */
        u64 P[DMAX][8][2][WMAX];
        memset(P, 0, sizeof P);
        int o = i * c->sw;
        for (int t = 0; t < d; t++) {
            int mu = p->mu[t], sb = 0;
            for (int v = 0; v < mu - 1; v++) {
                int bv = bit(wit, (size_t)(o + v));
                memcpy(P[t][v][0], V + (size_t)(o + v) * (size_t)W, (size_t)W * 8);
                P[t][v][1][0] = (u64)bv;
                fxor(W, P[t][mu - 1][0], P[t][v][0]);
                sb ^= bv;
            }
            P[t][mu - 1][1][0] = (u64)(1 ^ sb);
            for (int v = 0; v < mu - 1; v++)                 /* paires, ordre (t, v, x) croissant */
                for (int x = v + 1; x < mu - 1; x++) {
                    u64 pr[3][WMAX] = {{0}}, tmp[WMAX];
                    for (int a = 0; a < 2; a++)
                        for (int bb = 0; bb < 2; bb++) {
                            gf_mul(W, P[t][v][a], P[t][x][bb], tmp);
                            fxor(W, pr[a + bb], tmp);
                        }
                    for (int l = 0; l < 3; l++) {
                        gf_mul(W, pr[l], gam + nb_gam * (size_t)W, tmp);
                        fxor(W, C + (size_t)(l + d - 2) * (size_t)W, tmp);
                    }
                    nb_gam++;
                }
            o += mu - 1;
        }
        for (int q = 0; q < p->bloc; q++) {
            /* Q(X) = Π_t P[t][δ_t(q)](X), multiplication naïve */
            u64 Q[DMAX + 1][WMAX] = {{0}}, R2[DMAX + 1][WMAX];
            Q[0][0] = 1;
            int reste = q;
            for (int t = 0; t < d; t++) {
                int Pt = 1;
                for (int u = t + 1; u < d; u++) Pt *= p->mu[u];
                int dg = (reste / Pt) % p->mu[t];
                memset(R2, 0, sizeof R2);
                for (int l = 0; l <= t; l++)
                    for (int a = 0; a < 2; a++) {
                        u64 tmp[WMAX];
                        gf_mul(W, Q[l], P[t][dg][a], tmp);
                        fxor(W, R2[l + a], tmp);
                    }
                memcpy(Q, R2, sizeof Q);
            }
            int j = i * p->bloc + q;
            u64 h[WMAX] = {0};                               /* h_j = Σ_r γ_r H_{r,j}, lu bit à bit */
            for (int rr = 0; rr < r_tot; rr++) {
                int hr = j < c->k ? (cols[(size_t)j * (size_t)c->cB + (size_t)(rr >> 3)] >> (rr & 7)) & 1 : rr == j - c->k;
                if (hr) fxor(W, h, gam + (size_t)rr * (size_t)W);
            }
            for (int l = 0; l <= d; l++) {
                u64 tmp[WMAX];
                gf_mul(W, Q[l], h, tmp);
                fxor(W, C + (size_t)l * (size_t)W, tmp);
            }
        }
    }
    for (int rr = 0; rr < r_tot; rr++)                       /* + Σ_r γ_r y_r X^d */
        if ((y[rr >> 3] >> (rr & 7)) & 1) fxor(W, C + (size_t)d * (size_t)W, gam + (size_t)rr * (size_t)W);
    return nb_gam;
}

/* contraintes_poly ≡ annexe normative, sur témoins valides et invalides (une position décalée, deux bits à 1 dans un chiffre,
 * bit au hasard), V et γ aléatoires ; C_d nul si et seulement si le témoin est valide ; γ entièrement utilisé (m éléments) */
static int ctl_annexe(const ctx_t *c, const hcache_t *hc, const vpk_t *pk, const uint16_t *pos)
{
    const vp_t *p = c->p;
    size_t W = (size_t)c->W, nb = (size_t)c->nb;
    int d = p->d, ok = 1;
    u64 *V = alloue(8 * nb * W, 8), *gam = alloue((size_t)c->m * W, 8), *g = alloue((size_t)p->n * W, 8), gy[WMAX];
    u64 *C1 = alloue((size_t)(d + 1) * W, 8), *C2 = alloue((size_t)(d + 1) * W, 8);
    uint8_t *wit = alloue(nb, 1), h2[128];
    uint16_t *fx = alloue((size_t)p->w, 2);
    for (int essai = 0; essai < 4; essai++) {
        alea(h2, sizeof h2);
        if (melanges(c, h2, hc->cols, pk->y, gam, g, gy)) fatal("melanges");
        alea(V, 8 * nb * W * 8);
        memcpy(fx, pos, (size_t)p->w * 2);
        if (essai == 1) fx[3] = (uint16_t)((fx[3] + 1) % p->bloc);
        bits_temoin(c, fx, wit);
        if (essai == 2) wit[0] |= 3;
        if (essai == 3) { uint32_t z; alea(&z, 4); z %= (uint32_t)c->witb; wit[z >> 3] ^= (uint8_t)(1u << (z & 7)); }
        if (contraintes_poly(c, wit, V, gam, g, gy, C1)) fatal("contraintes");
        size_t ng = contraintes_annexe(c, wit, V, gam, hc->cols, pk->y, C2);
        u64 nul = 0;
        for (size_t z = 0; z < W; z++) nul |= C1[(size_t)d * W + z];
        ok &= !memcmp(C1, C2, (size_t)(d + 1) * W * 8) && ng == (size_t)c->m && (nul == 0) == (essai == 0);
    }
    free(V); free(gam); free(g); free(C1); free(C2); free(wit); free(fx);
    return ok;
}

/* P_open : proportion des défis (τ indices uniformes) dont l'ouverture tient en T_open nœuds, par ouverts() (égal à marquer,
 * contrôle decompte_ouverture_egal_a_marquer). Coût attendu du grinding : 2^wpow / P_open ; entropie min. du défi accepté
 * (oracle aléatoire) : τκ + log2 P_open. La borne du Théorème 17 se compte par requête et n'en dépend pas (Lemme 17.5). */
static double p_open(const ctx_t *c, long n, uint64_t graine)
{
    long acc = 0;
#pragma omp parallel reduction(+ : acc)
    {
        uint64_t s = graine ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(omp_get_thread_num() + 1));
#pragma omp for schedule(static)
        for (long t = 0; t < n; t++) {
            uint32_t ch[64];
            for (int e = 0; e < c->p->tau; e++) {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                ch[e] = (uint32_t)(s >> 20) & ((uint32_t)c->N - 1);
            }
            acc += ouverts(c, ch) <= c->p->topen;
        }
    }
    return (double)acc / (double)n;
}

/* frontières des champs de la signature */
static int frontieres(const ctx_t *c, size_t *f)
{
    const vp_t *p = c->p;
    size_t Bl = (size_t)c->Bl, ub = (size_t)(p->lam + p->B) / 8, x = 0;
    int n = 0;
    f[n++] = x; x += (size_t)c->Ls;                      /* sel */
    f[n++] = x; x += 2 * Bl;                             /* h3 */
    f[n++] = x; x += (size_t)(p->tau - 1) * (size_t)c->nb;   /* aux */
    f[n++] = x; x += ub;                                 /* u hachée */
    f[n++] = x; x += (size_t)c->witB;                    /* Δwit */
    f[n++] = x; x += (size_t)p->d * Bl;                  /* α */
    f[n++] = x; x += (size_t)p->topen * (size_t)c->Sb;  /* nœuds */
    f[n++] = x; x += (size_t)p->tau * 2 * Bl;            /* engagements cachés */
    f[n++] = x; x += 4;                                  /* compteur */
    f[n++] = x;
    return n;
}

/* KAT : empreinte de pk ‖ signature, aléa déterministe. Identique sur x86-64 et ARM64 (--kat sous qemu). */
static void empreinte_kat(const vp_t *v, uint8_t *o)
{
    ctx_t c;
    ctx_ok(&c, v);
    hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
    uint16_t pos[256];
    vpk_t pk;
    kat_actif = 1; kat_ctr = 0;
    keygen(&c, &pk, pos, &hc);
    size_t zs = taille_sig(&c);
    uint8_t *m = alloue(zs + 600, 1);
    size_t l = encoder_pk(&c, &pk, m);
    signer(&c, &pk, &hc, pos, (const uint8_t *)"kat", 3, m + l, 0);
    kat_actif = 0;
    sl_shake256(m, l + zs, o, 16);
    free(m); free(hc.cols);
}

/* après le premier calcul sur x86-64 ; vérifiés aussi sous qemu-aarch64 */
#include "vole_kat.h"

static void hexa(const uint8_t *b, char *o) { for (int i = 0; i < 16; i++) sprintf(o + 2 * i, "%02x", b[i]); }

static int mode_kat(void)
{
    const vp_t *PS[5] = {&PR128, &PR256, &PRTOY, &PR128F, &PR256F};
    int ok = 1;
    for (int q = 0; q < 5; q++) {
        uint8_t h[16];
        char x[33];
        empreinte_kat(PS[q], h);
        hexa(h, x);
        printf("%s %s %s\n", PS[q]->nom, x, strcmp(x, KAT[q]) ? "DIFFÉRENT" : "ok");
        ok &= !strcmp(x, KAT[q]);
    }
    return !ok;
}

/* sous ASan/UBSan : tout ce qui diffère de la signature exacte doit être rejeté, sans lecture hors du tampon */
static int mode_fuzz(long n, uint32_t graine)
{
    kat_actif = 1;                                       /* rejouable : la graine suffit à reproduire un échec */
    kat_ctr = graine << 16;
    ctx_t c;
    ctx_ok(&c, &PRTOY);
    hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
    uint16_t pos[8];
    vpk_t pk;
    keygen(&c, &pk, pos, &hc);
    size_t zs = taille_sig(&c);
    uint8_t *sig = alloue(zs, 1);
    const uint8_t msg[] = "fuzz";
    signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0);
    int ok = verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
    long acceptees = 0;
    for (long i = 0; i < n; i++) {
        uint32_t a[3];
        alea(a, sizeof a);
        size_t l = a[0] % 8 == 0 ? a[1] % (zs + 64) : zs;
        uint8_t *b = malloc(l ? l : 1);                      /* taille exacte : ASan voit tout dépassement */
        if (!b) fatal("allocation impossible");
        memcpy(b, sig, l < zs ? l : zs);
        if (l > zs) memset(b + zs, 0, l - zs);
        int diff = l != zs;
        if (l)
            for (uint32_t k = 0; k <= a[2] % 4; k++) {
                uint32_t z;
                alea(&z, 4);
                uint8_t m = (uint8_t)(1 << (z >> 29));
                b[z % l] ^= m;
            }
        if (l == zs) diff = memcmp(b, sig, zs) != 0;
        int r = verifier(&c, &pk, &hc, msg, sizeof msg, b, l);
        acceptees += r && diff;
        free(b);
    }
    printf("fuzz : %ld essais, signature exacte %s, %ld altérations acceptées\n", n, ok ? "acceptée" : "REJETÉE", acceptees);
    free(sig); free(hc.cols);
    return !(ok && acceptees == 0);
}

#ifdef SL_VALGRIND
/* --ct : keygen et signature, positions secrètes ; --ct-temoin : le branchement du témoin doit être détecté */
static int mode_ct(int temoin, const vp_t *v)
{
    ctx_t c;
    ctx_ok(&c, v);
    hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
    uint16_t pos[256];
    vpk_t pk;
    keygen(&c, &pk, pos, &hc);
    VALGRIND_SECRET(pos, (size_t)v->w * 2);
    if (temoin) {
        volatile int t = 0;
        if (pos[0] & 1) t = 1;
        (void)t;
    }
    size_t zs = taille_sig(&c);
    uint8_t *sig = alloue(zs, 1);
    signer(&c, &pk, &hc, pos, (const uint8_t *)"ct", 2, sig, 0);
    VALGRIND_MAKE_MEM_DEFINED(sig, zs);
    int ok = verifier(&c, &pk, &hc, (const uint8_t *)"ct", 2, sig, zs);
    printf("signature %s\n", ok ? "acceptée" : "REJETÉE");
    return !ok;
}
#endif

/* ---------------------------------------------------------------- mesures : plusieurs clés, répartition, H froide et chaude */
typedef struct { double moy, med, p90; } stat_t;
static stat_t stats(double *v, int n)
{
    stat_t s = {0, 0, 0};
    qsort(v, (size_t)n, sizeof *v, cmpd);
    for (int i = 0; i < n; i++) s.moy += v[i] / n;
    s.med = v[n / 2]; s.p90 = v[(n * 9) / 10];
    return s;
}

static void moyenne_ecart(const double *v, int n, double *m, double *sd)
{
    double s = 0, s2 = 0;
    for (int i = 0; i < n; i++) { s += v[i]; s2 += v[i] * v[i]; }
    *m = s / n;
    *sd = sqrt(fmax(s2 / n - *m * *m, 0) * n / (n - 1));
}

/* Théorème 17 (PROOFS § 3 bis) : coefficient de q dans la borne, rapporté à 2·2^−λ (notion coût/avantage : λ bits si ≤ 1).
 * q compte toutes les requêtes de F, signatures et points évalués par le vérifieur compris (q ≥ q_S) ; q ≤ 2^(λ−2), q_S ≤ 2^64.
 * Pas de terme en q_S² pour un sel répété : à (sel, H(m)) fixés le signataire est déterministe, le simulateur mémorise. */
static double borne_17(const vp_t *p, int wpow)
{
    int lam = p->lam;
    double tN = (double)p->tau * ldexp(1, p->kap);
    double t = (double)p->tau * (p->tau - 1) / 2 * ldexp(1, -(lam + p->B))        /* contrôle VOLE : deux u distincts égaux sous M */
             + ldexp(1, -lam)                                                      /* γ : C_d nul pour un témoin invalide */
             + p->d * ldexp(1, -(p->tau * p->kap + wpow))                          /* Δ : racine du résidu (paris compris) */
             + ldexp(1, -(lam + 8))                                                /* graines cachées, λ + 8 bits */
             + (ldexp(1, lam - 2) + tN * ldexp(1, 64)) * ldexp(1, -2 * lam)        /* q(q + τN(q_S + 1))/2^ℓ, ℓ = 2λ */
             + 3 * ldexp(1, 64 - 2 * lam);                                         /* programmation de M, γ et Δ : q_S·q/2^ℓ chacun */
    return t / ldexp(2, -lam);
}

/* Théorème 17-Q (PROOFS § 3 bis.5), d'après Baum et al., « Shorter, Tighter, FAESTer » (ePrint 2026/164) :
 * Théorème 54 (sûreté tour par tour ⇒ Fiat–Shamir en QROM) : Adv^KO ≤ 30·Q³·2^−2λ + 10·Q²·ε, ε = max des erreurs tour par
 * tour (contrôle VOLE, γ, Δ) ; Théorème 56 : Adv^CMA ≤ 2·Adv^KO (clés « lossy », D-H3-R) + q_S·2·√(3Q)·2^−λ + …
 * Renvoie log2 Q où la borne atteint 1 (q_S = 2^64) : le niveau prouvé en requêtes quantiques, à comparer à λ/2 (Grover). */
static double niveau_qrom(const vp_t *p)
{
    int lam = p->lam;
    double eM = (double)p->tau * (p->tau - 1) / 2 * ldexp(1, -(lam + p->B)), eg = ldexp(1, -lam);
    double eD = p->d * ldexp(1, -(p->tau * p->kap + p->wpow)), em = fmax(eM, fmax(eg, eD));
    double lo = 0, hi = lam;
    for (int i = 0; i < 200; i++) {
        double l = (lo + hi) / 2, Q = exp2(l);
        double f = 2 * (10 * Q * Q * em + 30 * Q * Q * Q * ldexp(1, -2 * lam)) + ldexp(1, 64) * 2 * sqrt(3 * Q) * ldexp(1, -lam);
        if (f < 1) lo = l; else hi = l;
    }
    return lo;
}

/* Proposition 17.3 (SUF-CMA) et 17.4 (liaison), PROOFS § 3 bis.6 :
 *  - encodage unique : toute signature qui diffère d'un bit est rejetée (exhaustif, modèle réduit à T_open = 40) ;
 *  - seule malléabilité structurelle : un autre ctr donnant EXACTEMENT le même défi (τκ bits, wpow nuls). Exécutée sur le modèle
 *    réduit (τκ = 12, wpow = 0) : coût prédit 2^(τκ+wpow) = 4 096 essais, la signature modifiée est acceptée ;
 *  - aléa défaillant : même sel et même message → même signature ; même sel et autre message → aucune graine ouverte commune ;
 *  - liaison : la signature est rejetée sous une autre clé (autre graine, H recalculée) et pour un autre message. */
static int ctl_suf_liaison(double *moy_ctr, double *z_ctr, long *bits, int *liaison)
{
    int ok = 1;
    vp_t v = PRTOY;
    v.topen = 40;                                         /* ≥ 2·log2(2L) : jamais refusé, signature courte */
    ctx_t c;
    ctx_ok(&c, &v);
    hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
    uint16_t pos[8];
    vpk_t pk;
    keygen(&c, &pk, pos, &hc);
    size_t zs = taille_sig(&c);
    uint8_t *sig = alloue(zs, 1), *mod = alloue(zs, 1);
    const uint8_t msg[] = "suf";
    if (signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0) < 0) fatal("signer");
    ok &= verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
    long n = 0, acc = 0;                                  /* (1) chaque bit de chaque octet */
    for (size_t i = 0; i < zs; i++)
        for (int b = 0; b < 8; b++) {
            memcpy(mod, sig, zs);
            mod[i] ^= (uint8_t)(1u << b);
            acc += verifier(&c, &pk, &hc, msg, sizeof msg, mod, zs);
            n++;
        }
    *bits = n;
    ok &= acc == 0;
    /* (2) autre ctr, même défi : le seul degré de liberté hors hachés */
    enum { NS = 200 };
    double v_[NS];
    size_t off = zs - 4;
    uint32_t ch0[64], ch1[64];
    uint8_t *cache = alloue(1, 2 * c.L);
    int acc2 = 0;
    for (int t = 0; t < NS; t++) {
        if (signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0) < 0) fatal("signer");
        uint32_t ctr = lit32(sig + off);
        const uint8_t *h3 = sig + c.Ls;
        if (defi(&c, h3, ctr, ch0, cache) < 0) fatal("défi");
        long essais = 0;
        for (uint32_t x = 1;; x++) {
            uint32_t ctr2 = ctr + x;
            essais++;
            if (defi(&c, h3, ctr2, ch1, cache) < 0) continue;
            if (memcmp(ch0, ch1, (size_t)v.tau * 4)) continue;
            memcpy(mod, sig, zs);
            le32(mod + off, ctr2);
            acc2 += verifier(&c, &pk, &hc, msg, sizeof msg, mod, zs) && memcmp(mod, sig, zs);
            break;
        }
        v_[t] = (double)essais;
    }
    double m, sd, att = ldexp(1, v.tau * v.kap + v.wpow);
    moyenne_ecart(v_, NS, &m, &sd);
    *moy_ctr = m;
    *z_ctr = (m - att) / (sd / sqrt(NS));
    ok &= acc2 == NS && fabs(*z_ctr) < 4;
    free(cache);
    /* (3) aléa défaillant sur un profil complet : sel imposé (mode KAT) */
    {
        ctx_t c1;
        ctx_ok(&c1, &PR128);
        hcache_t h1c = {.cols = alloue((size_t)c1.k, (size_t)c1.cB)}, h2c = {.cols = alloue((size_t)c1.k, (size_t)c1.cB)};
        uint16_t p1[256], p2[256];
        vpk_t k1, k2;
        keygen(&c1, &k1, p1, &h1c);
        keygen(&c1, &k2, p2, &h2c);
        size_t z1 = taille_sig(&c1);
        uint8_t *a = alloue(z1, 1), *b2 = alloue(z1, 1), *d3 = alloue(z1, 1);
        const uint8_t m1[] = "message 1", m2[] = "message 2";
        kat_actif = 1;
        kat_ctr = 7777; signer(&c1, &k1, &h1c, p1, m1, sizeof m1, a, 0);
        kat_ctr = 7777; signer(&c1, &k1, &h1c, p1, m1, sizeof m1, b2, 0);
        kat_ctr = 7777; signer(&c1, &k1, &h1c, p1, m2, sizeof m2, d3, 0);
        kat_actif = 0;
        int meme = !memcmp(a, b2, z1), sel_egal = !memcmp(a, d3, (size_t)c1.Ls), commune = 0;
        size_t on = (size_t)c1.Ls + 2 * (size_t)c1.Bl + (size_t)(PR128.tau - 1) * (size_t)c1.nb + (size_t)(PR128.lam + PR128.B) / 8
                    + (size_t)c1.witB + (size_t)PR128.d * (size_t)c1.Bl, Sb = (size_t)c1.Sb;
        uint8_t zero[64] = {0};
        for (int i = 0; i < PR128.topen; i++)
            for (int j = 0; j < PR128.topen; j++) {
                const uint8_t *x = a + on + (size_t)i * Sb, *y = d3 + on + (size_t)j * Sb;
                if (memcmp(x, zero, Sb) && !memcmp(x, y, Sb)) commune++;
            }
        ok &= meme && sel_egal && commune == 0;
        /* (4) liaison : autre clé (autre graine, sa propre H), autre message, clé à y modifié */
        int l1 = !verifier(&c1, &k2, &h2c, m1, sizeof m1, a, z1);
        int l2 = !verifier(&c1, &k1, &h1c, m2, sizeof m2, a, z1);
        vpk_t k3 = k1;
        k3.y[c1.cB - 1] ^= 0x80;
        int l3 = !verifier(&c1, &k3, &h1c, m1, sizeof m1, a, z1);
        *liaison = l1 && l2 && l3 && verifier(&c1, &k1, &h1c, m1, sizeof m1, a, z1);
        ok &= *liaison;
        printf("SUF/liaison : sel imposé → même message %s, autre message : même sel %s, %d graine(s) ouverte(s) commune(s) ; "
               "autre clé %s, autre message %s, y modifié %s\n", meme ? "signature identique" : "SIGNATURES DIFFÉRENTES",
               sel_egal ? "oui" : "non", commune, l1 ? "rejetée" : "ACCEPTÉE", l2 ? "rejeté" : "ACCEPTÉ", l3 ? "rejeté" : "ACCEPTÉ");
        free(a); free(b2); free(d3); free(h1c.cols); free(h2c.cols);
    }
    free(sig); free(mod); free(hc.cols);
    return ok;
}

/* échecs injectés (modèle réduit) : keygen, signer et verifier_r renvoient une erreur, sans signature partielle ni acceptation */
static int ctl_injection(void)
{
    ctx_t c;
    ctx_ok(&c, &PRTOY);
    hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
    uint16_t pos[8];
    vpk_t pk, vide;
    memset(&vide, 0, sizeof vide);
    int ok = 1, ek = 0, es = 0, ev = 0, sig_ok = 0, ver_ok = 0;
    for (long k = 0; k < 64; k++) {                                   /* graine, puis tirages des positions */
        inj_alea = k;
        int rk = keygen(&c, &pk, pos, &hc);
        inj_alea = -1;
        if (!rk) break;
        ok &= rk == -1 && !memcmp(&pk, &vide, sizeof pk);
        ek++;
    }
    if (keygen(&c, &pk, pos, &hc)) fatal("keygen");
    size_t zs = taille_sig(&c);
    uint8_t *sig = alloue(zs, 1), *zero = alloue(zs, 1);
    const uint8_t msg[] = "injection";
    for (long k = 0; k < 256; k++) {                                  /* chaque allocation du signataire, tour à tour */
        memset(sig, 0xAA, zs);
        inj_alloc = k;
        long e = signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0);
        inj_alloc = -1;
        if (e >= 0) { sig_ok = verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs); break; }
        ok &= !memcmp(sig, zero, zs);
        es++;
    }
    memset(sig, 0xAA, zs);
    inj_alea = 0;                                                     /* sel */
    long e = signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0);
    inj_alea = -1;
    ok &= e < 0 && !memcmp(sig, zero, zs);
    if (signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0) < 0) fatal("signer");
    for (long k = 0; k < 256; k++) {
        inj_alloc = k;
        int v = verifier_r(&c, &pk, &hc, msg, sizeof msg, sig, zs);
        inj_alloc = -1;
        if (v == 1) { ver_ok = 1; break; }
        ok &= v == -1;
        ev++;
    }
    printf("injection : keygen %d échecs d'aléa, signer %d échecs d'allocation + 1 d'aléa, vérifieur %d échecs ; jamais de signature partielle ni d'acceptation\n", ek, es, ev);
    free(sig); free(zero); free(hc.cols);
    return ok && ek > 0 && es >= 16 && ev >= 9 && sig_ok && ver_ok;
}

#if defined(__x86_64__)
#include <x86intrin.h>
static inline uint64_t cycles(void) { unsigned a; _mm_lfence(); uint64_t t = __rdtscp(&a); _mm_lfence(); return t; }
#else
static inline uint64_t cycles(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec; }
#endif

/* témoin de dudect : préparation du témoin avec sortie anticipée sur la position secrète (fuite voulue) */
static void bits_temoin_fuite(const ctx_t *c, const uint16_t *pos, uint8_t *wit)
{
    const vp_t *p = c->p;
    memset(wit, 0, (size_t)c->witB);
    for (int i = 0; i < p->w; i++)
        for (int idx = 0; idx < p->bloc; idx++)
            if (idx == pos[i]) {
                wit[(size_t)i * (size_t)c->sw / 8] ^= (uint8_t)idx;
                break;
            }
}

/* t de Welch sur des mesures, et sur les mesures sous le 90e centile commun (interruptions écartées) */
static void welch(const double *x, const int *cl, int n, double *t, double *tc)
{
    double *s = alloue((size_t)n, sizeof *s);
    memcpy(s, x, (size_t)n * sizeof *s);
    qsort(s, (size_t)n, sizeof *s, cmpd);
    double seuils[2] = {INFINITY, s[(n * 9) / 10]};
    free(s);
    for (int r = 0; r < 2; r++) {
        double m[2] = {0, 0}, q[2] = {0, 0};
        long k[2] = {0, 0};
        for (int i = 0; i < n; i++)
            if (x[i] <= seuils[r]) { k[cl[i]]++; m[cl[i]] += x[i]; q[cl[i]] += x[i] * x[i]; }
        for (int j = 0; j < 2; j++) { m[j] /= (double)k[j]; q[j] = q[j] / (double)k[j] - m[j] * m[j]; }
        double v = (m[0] - m[1]) / sqrt(q[0] / (double)k[0] + q[1] / (double)k[1]);
        if (r) *tc = v; else *t = v;
    }
}

/* --dudect N : valeur secrète fixe contre aléatoire, un cœur ; machine et GPU au repos. VOLE-128, chemins secrets hors grinding
 * (le grinding ne dépend que de valeurs publiques) : témoin et syndrome de keygen, contraintes_poly. Seuil |t| < 4,5 ; le témoin
 * (sortie anticipée) doit dépasser. */
static int mode_dudect(int n)
{
    omp_set_num_threads(1);
    ctx_t c;
    ctx_ok(&c, &PR128);
    const vp_t *p = c.p;
    hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
    uint16_t fixe[256], pos[256];
    vpk_t pk;
    keygen(&c, &pk, fixe, &hc);
    size_t W = (size_t)c.W, nb = (size_t)c.nb;
    u64 *V = alloue(8 * nb * W, 8), *gam = alloue((size_t)c.m * W, 8), *g = alloue((size_t)p->n * W, 8), gy[WMAX], *C = alloue((size_t)(p->d + 1) * W, 8);
    uint8_t h2[128], *wit = alloue(nb, 1), y[512];
    alea(V, 8 * nb * W * 8);
    alea(h2, sizeof h2);
    if (melanges(&c, h2, hc.cols, pk.y, gam, g, gy)) fatal("melanges");
    double *x = alloue((size_t)n, sizeof *x);
    int *cl = alloue((size_t)n, sizeof *cl), ok = 1;
    uint16_t (*entrees)[256] = alloue((size_t)n, sizeof *entrees);
    const char *noms[3] = {"témoin et syndrome (keygen)", "contraintes_poly (signature)", "TÉMOIN : sortie anticipée"};
    for (int op = 0; op < 3; op++) {
        int m = op == 1 ? n / 5 : n;                                  /* contraintes_poly ≈ 5 fois plus lente */
        for (int i = 0; i < m; i++) {
            uint8_t b;
            alea(&b, 1);
            cl[i] = b & 1;
            if (cl[i]) {
                for (int j = 0; j < p->w; j++) {
                    uint16_t z;
                    alea(&z, 2);
                    entrees[i][j] = (uint16_t)(z % p->bloc);
                }
            } else if (op == 2) {
                memset(entrees[i], 0, sizeof entrees[i]);             /* le témoin fuit sur la position : 0 sort tout de suite */
            } else {
                memcpy(entrees[i], fixe, sizeof entrees[i]);
            }
        }
        for (int i = 0; i < m; i++) {
            memcpy(pos, entrees[i], sizeof pos);
            uint64_t t0 = cycles();
            if (op == 0) { bits_temoin(&c, pos, wit); syndrome(&c, hc.cols, pos, y); }
            else if (op == 1) { bits_temoin(&c, pos, wit); if (contraintes_poly(&c, wit, V, gam, g, gy, C)) fatal("contraintes"); }
            else bits_temoin_fuite(&c, pos, wit);
            x[i] = (double)(cycles() - t0);
        }
        double t, tc;
        welch(x, cl, m, &t, &tc);
        int depasse = fabs(t) > 4.5 || fabs(tc) > 4.5;
        printf("dudect %-32s %6d mesures : t = %+7.2f, sous le 90e centile t = %+7.2f %s\n", noms[op], m, t, tc,
               op == 2 ? (depasse ? "(fuite détectée, attendu)" : "TÉMOIN NON DÉTECTÉ") : (depasse ? "DÉPASSEMENT" : "ok"));
        ok &= op == 2 ? depasse : !depasse;
    }
    free(V); free(gam); free(g); free(C); free(wit); free(x); free(cl); free(entrees); free(hc.cols);
    return !ok;
}

/* --kz N : la stratégie de Kales–Zaverucha transposée aux trois tours de VOLE (h2 puis Δ), contre le vrai vérifieur, sur PRKZ.
 * Pour un budget (q₂, q₃) : q₂ requêtes à H_2 pour un γ qui annule C_d (2^−12 chacune), sinon d = 4 racines dans E et q₃
 * requêtes à H_d (4·2^−16 chacune). Prédiction exacte 1 − (1 − 2^−12)^q₂·(1 − 2^−14)^q₃ ; borne du Théorème 17
 * q₂·2^−12 + q₃·2^−14 (les autres termes valent moins de 2^−100 ici). Chaque falsification annoncée doit être acceptée par le
 * vérifieur, chaque échec rejeté ; la fréquence doit être dans l'IC à 99,9 % de la prédiction et pas au-dessus de la borne. */
static int mode_kz(long n)
{
    resultat_t r = {.nom = "vole_kz"};
    ctx_t c;
    ctx_ok(&c, &PRKZ);
    hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
    uint16_t pos[16], faux[16];
    vpk_t pk;
    if (keygen(&c, &pk, pos, &hc)) fatal("keygen");
    memcpy(faux, pos, sizeof faux);
    faux[0] ^= 1;
    /* clé SANS témoin, comme sig_kz : y uniforme (H ne dépend que de la graine). Un témoin régulier existe avec probabilité
     * ≤ b^w/2^r = 2^64/2^80 = 2^−16. Avec la vraie clé, la marche aléatoire de l'attaque γ (un bit changé par essai, départ à
     * 2 bits du vrai témoin) retombait parfois sur le témoin : succès honnête, compté à tort comme falsification (+4 σ, 11 nov.) */
    alea(pk.y, (size_t)c.cB);
    size_t zs = taille_sig(&c);
    static const long B[4][2] = {{256, 4096}, {1024, 1}, {1, 16384}, {4096, 16384}};
    static char json[4000];
    size_t lj = (size_t)snprintf(json, sizeof json, "[");
    int ok_v = 1, ok_p = 1, ok_b = 1;
    omp_set_max_active_levels(1);
    for (int b = 0; b < 4; b++) {
        kz_q2 = B[b][0]; kz_q3 = B[b][1];
        long succes = 0, incoherent = 0;
#pragma omp parallel for schedule(dynamic) reduction(+ : succes, incoherent)
        for (long t = 0; t < n; t++) {
            uint8_t *sig = alloue(zs, 1);
            const uint8_t msg[] = "falsification";
            long e = signer(&c, &pk, &hc, faux, msg, sizeof msg, sig, 5);
            if (e < 0) fatal("signer (attaque 5)");
            int v = verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
            succes += v;
            incoherent += v != (e == 1);
            free(sig);
        }
        double q2 = (double)kz_q2, q3 = (double)kz_q3;
        double pred = 1 - pow(1 - ldexp(1, -PRKZ.gbits), q2) * pow(1 - PRKZ.d * ldexp(1, -PRKZ.tau * PRKZ.kap), q3);
        double borne = q2 * ldexp(1, -PRKZ.gbits) + q3 * PRKZ.d * ldexp(1, -PRKZ.tau * PRKZ.kap), f = (double)succes / (double)n;
        double sd = sqrt(pred * (1 - pred) / (double)n), z = (f - pred) / sd;
        int dans_ic = fabs(z) < 3.29, sous_borne = f - 3.29 * sqrt(f * (1 - f) / (double)n + 1e-12) <= borne;
        ok_v &= incoherent == 0; ok_p &= dans_ic; ok_b &= sous_borne;
        printf("budget (q2, q3) = (%ld, %ld) : %ld/%ld falsifications (%.4f), prédiction exacte %.4f (z = %+.2f), borne du Th. 17 %.4f ; "
               "annonces incohérentes avec le vérifieur : %ld\n", kz_q2, kz_q3, succes, n, f, pred, z, borne, incoherent);
        fflush(stdout);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"q2\":%ld,\"q3\":%ld,\"essais\":%ld,\"falsifications\":%ld,\"frequence\":%.5f,"
                               "\"prediction\":%.5f,\"z\":%.2f,\"borne\":%.5f}", b ? "," : "", kz_q2, kz_q3, n, succes, f, pred, z, borne);
    }
    snprintf(json + lj, sizeof json - lj, "]");
    res_controle(&r, "chaque_falsification_annoncee_acceptee_et_chaque_echec_rejete", ok_v);
    res_controle(&r, "frequence_dans_l_ic_99_9_de_la_prediction_exacte", ok_p);
    res_controle(&r, "frequence_pas_au_dessus_de_la_borne_du_theoreme_17", ok_b);
    res_mesure(&r, "budgets", "%s", json);
    free(hc.cols);
    return res_ecrire(&r);
}

/* --bench N : médianes de N signatures et vérifications par profil (une clé, H en cache), à 1 thread puis au maximum */
static int mode_bench(int n)
{
    const vp_t *PP[4] = {&PR128, &PR256, &PR128F, &PR256F};
    int nth = omp_get_max_threads(), passes[2] = {1, nth};
    double *v = alloue((size_t)n, sizeof *v), *sg = alloue((size_t)n, sizeof *sg);
    for (int pz = 0; pz < 2; pz++) {
        omp_set_num_threads(passes[pz]);
        for (int q = 0; q < 4; q++) {
            ctx_t c;
            ctx_ok(&c, PP[q]);
            hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
            uint16_t pos[256];
            vpk_t pk;
            if (keygen(&c, &pk, pos, &hc)) fatal("keygen");
            size_t zs = taille_sig(&c);
            uint8_t *sig = alloue(zs, 1);
            for (int i = 0; i < n; i++) {
                double t0 = maintenant();
                if (signer(&c, &pk, &hc, pos, (const uint8_t *)"bench", 5, sig, 0) < 0) fatal("signer");
                sg[i] = maintenant() - t0;
                t0 = maintenant();
                if (!verifier(&c, &pk, &hc, (const uint8_t *)"bench", 5, sig, zs)) fatal("vérification");
                v[i] = maintenant() - t0;
            }
            qsort(v, (size_t)n, sizeof *v, cmpd); qsort(sg, (size_t)n, sizeof *sg, cmpd);
            printf("%-10s %2d thread(s), %5zu o : signe méd %7.2f ms (p10 %7.2f, p90 %7.2f) ; vérifie méd %7.2f ms\n", PP[q]->nom, passes[pz], zs,
                   1e3 * sg[n / 2], 1e3 * sg[n / 10], 1e3 * sg[(9 * n) / 10], 1e3 * v[n / 2]);
            fflush(stdout);
            free(sig); free(hc.cols);
        }
    }
    free(v); free(sg);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--kat")) return mode_kat();
    if (argc > 1 && !strcmp(argv[1], "--fuzz")) return mode_fuzz(argc > 2 ? atol(argv[2]) : 2000, argc > 3 ? (uint32_t)atol(argv[3]) : 1);
    if (argc > 1 && !strcmp(argv[1], "--injection")) return !ctl_injection();
    if (argc > 1 && !strcmp(argv[1], "--bench")) return mode_bench(argc > 2 ? atoi(argv[2]) : 50);
    if (argc > 1 && !strcmp(argv[1], "--kz")) return mode_kz(argc > 2 ? atol(argv[2]) : 400);
    if (argc > 1 && !strcmp(argv[1], "--dudect")) return mode_dudect(argc > 2 ? atoi(argv[2]) : 20000);
#ifdef SL_VALGRIND
    if (argc > 1 && !strcmp(argv[1], "--ct"))                    /* --ct 128 | 256 : profil complet, paires comprises */
        return mode_ct(0, argc > 2 ? (atoi(argv[2]) == 256 ? &PR256 : &PR128) : &PRTOY);
    if (argc > 1 && !strcmp(argv[1], "--ct-temoin")) return mode_ct(1, &PRTOY);
#endif
    resultat_t r = {.nom = "vole_proto"};
    static char json[24000];
    size_t lj = (size_t)snprintf(json, sizeof json, "[");
    const vp_t *PS[4] = {&PR128, &PR256, &PR128F, &PR256F};
    static const long ACT[4] = {8522, 34867, 8522, 34867};
    int nth = omp_get_max_threads();
    res_controle(&r, "corps_egal_a_une_reference_bit_a_bit", ctl_corps());
    res_controle(&r, "arbres_reduits_exhaustifs", ctl_arbres());
    {   /* décompte direct de l'ouverture (grinding) = marquer, sur des défis aléatoires et extrêmes des profils */
        int ok = 1;
        const vp_t *PK[5] = {&PR128, &PR256, &PRTOY, &PR128F, &PR256F};
        for (int q = 0; q < 5; q++) {
            ctx_t c;
            ctx_ok(&c, PK[q]);
            uint8_t *cache = alloue(1, 2 * c.L);
            for (int i = 0; i < 3000; i++) {
                uint32_t ch[64];
                for (int e = 0; e < c.p->tau; e++) {
                    alea(&ch[e], 4);
                    ch[e] = i < 3 ? (i == 0 ? 0 : i == 1 ? (uint32_t)c.N - 1 : (uint32_t)e % (uint32_t)c.N) : ch[e] & ((uint32_t)c.N - 1);
                }
                ok &= ouverts(&c, ch) == marquer(&c, ch, cache);
            }
            free(cache);
        }
        res_controle(&r, "decompte_ouverture_egal_a_marquer", ok);
    }
    {
        int ok = 1;
        for (int q = 0; q < 5; q++) {
            const vp_t *PK[5] = {&PR128, &PR256, &PRTOY, &PR128F, &PR256F};
            uint8_t h[16], h2[16];
            char x[33];
            omp_set_num_threads(1);
            empreinte_kat(PK[q], h);
            omp_set_num_threads(nth);
            empreinte_kat(PK[q], h2);
            hexa(h, x);
            ok &= !memcmp(h, h2, 16) && !strcmp(x, KAT[q]);
        }
        res_controle(&r, "kat_identiques_quel_que_soit_le_nombre_de_threads", ok);
    }
    for (int q = 0; q < 4; q++) {
        ctx_t c;
        ctx_ok(&c, PS[q]);
        const vp_t *p = c.p;
        char nom[80];
        hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
        uint16_t pos[256];
        vpk_t pk;
        size_t zs = taille_sig(&c), lpk = (size_t)c.Bl + (size_t)c.cB;
        uint8_t *sig = alloue(zs + 1, 1), *mod = alloue(zs + 1, 1), epk[32 + 512];
        const uint8_t msg[] = "message de test";
        enum { NK = 5, NM = 8 };
        double ts[2][NK * NM], tv[2][NK * NM], tk[NK], th[NK], essais = 0;
        int ok = 1, ix[2] = {0, 0};
        for (int key = 0; key < NK; key++) {
            omp_set_num_threads(1);
            double t0 = maintenant();
            keygen(&c, &pk, pos, &hc);
            tk[key] = maintenant() - t0;
            uint8_t *froid = alloue((size_t)c.k, (size_t)c.cB);
            t0 = maintenant();
            developper_H(&c, pk.seed, froid);
            th[key] = maintenant() - t0;
            ok &= !memcmp(froid, hc.cols, (size_t)c.k * (size_t)c.cB);
            free(froid);
            for (int th_i = 0; th_i < 2; th_i++) {
                omp_set_num_threads(th_i ? nth : 1);
                for (int i = 0; i < NM; i++) {
                    t0 = maintenant();
                    long e = signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0);
                    ts[th_i][ix[th_i]] = maintenant() - t0;
                    if (!th_i) essais += (double)e;
                    t0 = maintenant();
                    ok &= verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
                    tv[th_i][ix[th_i]++] = maintenant() - t0;
                }
            }
        }
        omp_set_num_threads(nth);
        stat_t s1 = stats(ts[0], NK * NM), sn = stats(ts[1], NK * NM), v1 = stats(tv[0], NK * NM), vn = stats(tv[1], NK * NM), ks = stats(tk, NK), hs = stats(th, NK);
        uint8_t *gros = alloue(1 << 20, 1);
        double t0 = maintenant();
        signer(&c, &pk, &hc, pos, gros, 1 << 20, sig, 0);
        double tgros = maintenant() - t0;
        free(gros);
        signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0);
        printf("%s : %zu o (actuelle %ld, %+.0f %%), pk %zu o, %d clés × %d messages, grille de paramètres\n", p->nom, zs, ACT[q], 100.0 * ((double)zs - (double)ACT[q]) / (double)ACT[q], lpk, NK, NM);
        printf("  signe, 1 cœur : moy %.1f méd %.1f p90 %.1f ms ; %d threads : moy %.1f méd %.1f p90 %.1f ms ; %.0f essais de défi\n", 1e3 * s1.moy, 1e3 * s1.med, 1e3 * s1.p90, nth, 1e3 * sn.moy, 1e3 * sn.med, 1e3 * sn.p90, essais / (NK * NM));
        printf("  vérifie, 1 cœur : moy %.1f méd %.1f p90 %.1f ms ; %d threads : moy %.1f méd %.1f p90 %.1f ms\n", 1e3 * v1.moy, 1e3 * v1.med, 1e3 * v1.p90, nth, 1e3 * vn.moy, 1e3 * vn.med, 1e3 * vn.p90);
        printf("  keygen %.1f ms ; H froide %.1f ms (1 cœur) ; message de 1 Mio : %.1f ms (%d threads)\n", 1e3 * ks.moy, 1e3 * hs.moy, 1e3 * tgros, nth);
        fflush(stdout);
        snprintf(nom, sizeof nom, "%s_signature_valide_acceptee", p->nom);
        res_controle(&r, nom, ok && verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs));
        snprintf(nom, sizeof nom, "%s_taille_pk_conforme_a_son_encodage", p->nom);
        res_controle(&r, nom, encoder_pk(&c, &pk, epk) == lpk);
        snprintf(nom, sizeof nom, "%s_h4_egale_quatre_appels_scalaires", p->nom);
        res_controle(&r, nom, ctl_h4(&c));
        snprintf(nom, sizeof nom, "%s_contraintes_signataire_et_verifieur_egales", p->nom);
        res_controle(&r, nom, ctl_contraintes(&c, &hc, &pk, pos));
        snprintf(nom, sizeof nom, "%s_contraintes_conformes_a_l_annexe_normative", p->nom);
        res_controle(&r, nom, ctl_annexe(&c, &hc, &pk, pos));
        {   /* P_open mesuré, et cohérence avec le nombre moyen d'essais de défi des signatures ci-dessus */
            long ne = 1000000;
            double po = p_open(&c, ne, 0xC0FFEEULL + (uint64_t)q), sdp = sqrt(po * (1 - po) / (double)ne);
            double attendu = ldexp(1, p->wpow) / po, mes = essais / (NK * NM);
            /* moyenne de NK·NM lois géométriques : écart-type relatif ≈ 1/√(NK·NM) */
            double z = (mes - attendu) / (attendu / sqrt((double)(NK * NM)));
            printf("  P_open = %.5f ± %.5f (10^6 défis) : grinding attendu %.0f essais (mesuré %.0f, z = %+.2f) ; "
                   "entropie min. du défi accepté %.2f bits sur %d\n", po, sdp, attendu, mes, z, p->tau * p->kap + log2(po), p->tau * p->kap);
            snprintf(nom, sizeof nom, "%s_grinding_conforme_a_p_open", p->nom);
            res_controle(&r, nom, fabs(z) < 4);
            lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"profil_popen\":\"%s\",\"p_open\":%.6f,\"essais_attendus\":%.1f,\"essais_mesures\":%.1f,"
                                   "\"entropie_min_defi\":%.2f}", q || lj > 1 ? "," : "", p->nom, po, attendu, mes, p->tau * p->kap + log2(po));
        }
        /* altérations : premier et dernier octet de chaque champ, plus des positions au hasard */
        size_t f[12];
        int nf = frontieres(&c, f), rejets = 0, total = 0;
        snprintf(nom, sizeof nom, "%s_frontieres_conformes_a_la_taille", p->nom);
        res_controle(&r, nom, f[nf - 1] == zs);
        for (int s = 0; s + 1 < nf; s++)
            for (int b = 0; b < 2; b++) {
                memcpy(mod, sig, zs);
                mod[b ? f[s + 1] - 1 : f[s]] ^= 1;
                total++;
                rejets += !verifier(&c, &pk, &hc, msg, sizeof msg, mod, zs);
            }
        for (int i = 0; i < 16; i++) {
            uint32_t a;
            alea(&a, 4);
            memcpy(mod, sig, zs);
            mod[a % zs] ^= (uint8_t)(1 << (a >> 29));
            total++;
            rejets += !verifier(&c, &pk, &hc, msg, sizeof msg, mod, zs);
        }
        snprintf(nom, sizeof nom, "%s_alterations_rejetees", p->nom);
        res_controle(&r, nom, rejets == total);
        /* longueurs : nulle, 1, ±1, et chaque frontière de champ */
        int lok = !verifier(&c, &pk, &hc, msg, sizeof msg, NULL, zs) && !verifier(&c, &pk, &hc, msg, sizeof msg, sig, 0) && !verifier(&c, &pk, &hc, msg, sizeof msg, sig, 1)
                  && !verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs - 1) && !verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs + 1);
        for (int s = 0; s + 1 < nf; s++)
            lok &= !verifier(&c, &pk, &hc, msg, sizeof msg, sig, f[s]);
        snprintf(nom, sizeof nom, "%s_longueurs_invalides_rejetees", p->nom);
        res_controle(&r, nom, lok);
        const uint8_t autre[] = "autre message!!";
        snprintf(nom, sizeof nom, "%s_autre_message_rejete", p->nom);
        res_controle(&r, nom, !verifier(&c, &pk, &hc, autre, sizeof autre, sig, zs));
        vpk_t pk2 = pk;
        pk2.y[0] ^= 1;
        snprintf(nom, sizeof nom, "%s_autre_cle_rejetee", p->nom);
        res_controle(&r, nom, !verifier(&c, &pk2, &hc, msg, sizeof msg, sig, zs));
        vpk_t pk3 = pk;
        pk3.seed[0] ^= 1;                                    /* H en cache d'une autre graine */
        snprintf(nom, sizeof nom, "%s_matrice_d_une_autre_cle_rejetee", p->nom);
        res_controle(&r, nom, !verifier(&c, &pk3, &hc, msg, sizeof msg, sig, zs));
        if (q < 2) {
            snprintf(nom, sizeof nom, "%s_plus_petite_de_moitie", p->nom);
            res_controle(&r, nom, 2 * (long)zs < ACT[q]);
        } else {                                                   /* variantes rapides : au moins un tiers de moins */
            snprintf(nom, sizeof nom, "%s_plus_petite_d_un_tiers", p->nom);
            res_controle(&r, nom, 3 * (long)zs < 2 * ACT[q]);
        }
        {   /* blocs exacts : les positions 0 et Π μ − 1 sont des colonnes réelles, aucune ne laisse un bloc vide */
            uint16_t px[256];
            vpk_t pkx = pk;
            memcpy(px, pos, sizeof px);
            px[0] = 0; px[1] = (uint16_t)(p->bloc - 1);
            syndrome(&c, hc.cols, px, pkx.y);
            int bon = signer(&c, &pkx, &hc, px, msg, sizeof msg, sig, 0) >= 0 && verifier(&c, &pkx, &hc, msg, sizeof msg, sig, zs);
            snprintf(nom, sizeof nom, "%s_blocs_exacts_positions_extremes_acceptees", p->nom);
            res_controle(&r, nom, bon && memcmp(pkx.y, pk.y, (size_t)c.cB));
        }
        double b17 = borne_17(p, p->wpow), b17m = borne_17(p, p->wpow - 1);
        printf("  Théorème 17 : coefficient de q = %.3f × 2·2^−%d (λ bits si ≤ 1) ; avec wpow − 1 : %.3f\n", b17, p->lam, b17m);
        snprintf(nom, sizeof nom, "%s_theoreme_17_atteint_lambda", p->nom);
        res_controle(&r, nom, b17 <= 1);
        snprintf(nom, sizeof nom, "%s_wpow_minimal", p->nom);
        res_controle(&r, nom, b17m > 1);
        double nq = niveau_qrom(p);
        printf("  Théorème 17-Q : niveau prouvé en QROM 2^%.1f requêtes quantiques (Grover sur γ : 2^%d)\n", nq, p->lam / 2);
        snprintf(nom, sizeof nom, "%s_qrom_a_moins_de_3_bits_de_grover", p->nom);
        res_controle(&r, nom, nq > p->lam / 2 - 3);
        lj += (size_t)snprintf(json + lj, sizeof json - lj,
                               "%s{\"profil\":\"%s\",\"signature\":%zu,\"actuelle\":%ld,\"pk\":%zu,\"cles\":%d,\"messages_par_cle\":%d,\"threads\":%d,"
                               "\"signe_1\":{\"moy\":%.1f,\"med\":%.1f,\"p90\":%.1f},\"signe_n\":{\"moy\":%.1f,\"med\":%.1f,\"p90\":%.1f},"
                               "\"verifie_1\":{\"moy\":%.1f,\"med\":%.1f,\"p90\":%.1f},\"verifie_n\":{\"moy\":%.1f,\"med\":%.1f,\"p90\":%.1f},\"keygen_ms\":%.1f,\"H_froide_ms\":%.1f}",
                               ",", p->nom, zs, ACT[q], lpk, NK, NM, nth, 1e3 * s1.moy, 1e3 * s1.med, 1e3 * s1.p90, 1e3 * sn.moy, 1e3 * sn.med, 1e3 * sn.p90,
                               1e3 * v1.moy, 1e3 * v1.med, 1e3 * v1.p90, 1e3 * vn.moy, 1e3 * vn.med, 1e3 * vn.p90, 1e3 * ks.moy, 1e3 * hs.moy);
        free(hc.cols); free(sig); free(mod);
    }
    /* ---- banc des trois défis du Théorème 17, sur modèles réduits, un thread (reproductible, sans surcoût OpenMP) ---- */
    omp_set_num_threads(1);
    {
        ctx_t c;
        ctx_ok(&c, &PRTOY);
        hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
        uint16_t pos[8], faux[8];
        vpk_t pk;
        keygen(&c, &pk, pos, &hc);
        size_t zs = taille_sig(&c);
        uint8_t *sig = alloue(zs, 1);
        const uint8_t msg[] = "cible";
        int ok = 1;
        signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0);
        ok &= verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
        res_controle(&r, "reduit_signature_honnete_acceptee", ok);
        memcpy(faux, pos, sizeof faux);
        faux[0] = (uint16_t)(pos[0] ^ 1);                              /* faux témoin : syndrome faux */
        signer(&c, &pk, &hc, faux, msg, sizeof msg, sig, 0);
        res_controle(&r, "reduit_faux_temoin_rejete", !verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs));
        /* défi Δ : sans témoin, d racines dans E ; coût attendu |E|/d = 2^12/4 essais de Δ */
        enum { ND = 600 };
        int acc = 0;
        double v[ND], att = (double)(1 << (PRTOY.tau * PRTOY.kap)) / PRTOY.d;
        for (int i = 0; i < ND; i++) {
            v[i] = (double)signer(&c, &pk, &hc, faux, msg, sizeof msg, sig, 1);
            acc += verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
        }
        double m, sd, z;
        moyenne_ecart(v, ND, &m, &sd);
        z = (m - att) / (sd / sqrt(ND));
        printf("défi Δ (modèle réduit) : %d/%d falsifications acceptées, %.0f ± %.0f essais (prédiction |E|/d = %.0f, z = %+.2f)\n", acc, ND, m, sd / sqrt(ND), att, z);
        res_controle(&r, "reduit_attaque_delta_acceptee_par_le_verifieur", acc == ND);
        res_controle(&r, "reduit_attaque_delta_cout_egal_a_la_prediction", fabs(z) < 4);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, ",{\"defi_delta\":{\"essais\":%d,\"acceptees\":%d,\"moyenne\":%.1f,\"prediction\":%.1f,\"z\":%.2f}}", ND, acc, m, att, z);
        /* contrôle VOLE : aux incohérent dans la répétition 1, défi parié ; accepté si et seulement si le pari tombe (2^−κ) */
        enum { NV = 6400, NV4 = 300 };
        int acc3 = 0;
        for (int i = 0; i < NV; i++) {
            signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 3);
            acc3 += verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
        }
        double pv = 1.0 / (double)(1 << PRTOY.kap), ev = NV * pv, zv = (acc3 - ev) / sqrt(ev * (1 - pv));
        int acc4 = 0;
        double v4[NV4];
        for (int i = 0; i < NV4; i++) {
            v4[i] = (double)signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 4);
            acc4 += verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
        }
        double m4, sd4;
        moyenne_ecart(v4, NV4, &m4, &sd4);
        double z4 = (m4 - (1 << PRTOY.kap)) / (sd4 / sqrt(NV4));
        printf("contrôle VOLE (modèle réduit) : incohérence acceptée %d/%d (prédiction 2^−κ : %.1f, z = %+.2f) ; avec grinding vers le pari %d/%d, %.1f essais (prédiction %d, z = %+.2f)\n",
               acc3, NV, ev, zv, acc4, NV4, m4, 1 << PRTOY.kap, z4);
        res_controle(&r, "reduit_controle_vole_incoherence_acceptee_au_taux_2_moins_kappa", acc3 > 0 && fabs(zv) < 4);
        res_controle(&r, "reduit_controle_vole_pari_force_accepte_au_cout_2_kappa", acc4 == NV4 && fabs(z4) < 4);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, ",{\"controle_vole\":{\"signatures\":%d,\"acceptees\":%d,\"prediction\":%.1f,\"z\":%.2f,\"forcees\":%d,\"forcees_acceptees\":%d,\"essais_moyens\":%.1f,\"z_force\":%.2f}}",
                               NV, acc3, ev, zv, NV4, acc4, m4, z4);
        free(hc.cols); free(sig);
        /* témoin sur un nombre de bits non multiple de 8 : le remplissage de Δwit doit être nul */
        vp_t vv = PRTOY;
        vv.w = 7; vv.n = 112;
        ctx_t c2;
        ctx_ok(&c2, &vv);
        hcache_t h2 = {.cols = alloue((size_t)c2.k, (size_t)c2.cB)};
        vpk_t pk2;
        uint16_t pos2[8];
        keygen(&c2, &pk2, pos2, &h2);
        size_t z2 = taille_sig(&c2), f[12];
        uint8_t *s2 = alloue(z2, 1);
        signer(&c2, &pk2, &h2, pos2, msg, sizeof msg, s2, 0);
        int nf = frontieres(&c2, f), bon = verifier(&c2, &pk2, &h2, msg, sizeof msg, s2, z2);
        (void)nf;
        s2[f[5] - 1] ^= 0x80;
        res_controle(&r, "remplissage_de_delta_wit_exige_nul", bon && !verifier(&c2, &pk2, &h2, msg, sizeof msg, s2, z2));
        free(h2.cols); free(s2);
    }
    {   /* défi γ : γ réduit à 2^gbits valeurs ; sans témoin, changer le témoin engagé jusqu'à C_d = 0 coûte 2^gbits essais de h2 */
        ctx_t c;
        ctx_ok(&c, &PRGAM);
        hcache_t hc = {.cols = alloue((size_t)c.k, (size_t)c.cB)};
        uint16_t pos[8], faux[8];
        vpk_t pk;
        keygen(&c, &pk, pos, &hc);
        size_t zs = taille_sig(&c);
        uint8_t *sig = alloue(zs, 1);
        const uint8_t msg[] = "cible gamma";
        signer(&c, &pk, &hc, pos, msg, sizeof msg, sig, 0);
        int hon = verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs);
        memcpy(faux, pos, sizeof faux);
        faux[0] = (uint16_t)(pos[0] ^ 1);
        signer(&c, &pk, &hc, faux, msg, sizeof msg, sig, 0);
        res_controle(&r, "reduit_gamma_honnete_accepte_faux_temoin_rejete", hon && !verifier(&c, &pk, &hc, msg, sizeof msg, sig, zs));
        enum { NG = 200 };
        int acc = 0;
        double v[NG], att = (double)(1 << PRGAM.gbits);
        vpk_t pks = pk;                                      /* clé sans témoin (y uniforme ; témoin régulier : probabilité ≤ 2^−32) */
        alea(pks.y, (size_t)c.cB);
        for (int i = 0; i < NG; i++) {
            v[i] = (double)signer(&c, &pks, &hc, faux, msg, sizeof msg, sig, 2);
            acc += verifier(&c, &pks, &hc, msg, sizeof msg, sig, zs);
        }
        double m, sd;
        moyenne_ecart(v, NG, &m, &sd);
        double z = (m - att) / (sd / sqrt(NG));
        printf("défi γ (γ réduit à 2^%d) : %d/%d falsifications acceptées, %.0f ± %.0f essais de h2 (prédiction %.0f, z = %+.2f)\n", PRGAM.gbits, acc, NG, m, sd / sqrt(NG), att, z);
        res_controle(&r, "reduit_attaque_gamma_acceptee_par_le_verifieur", acc == NG);
        res_controle(&r, "reduit_attaque_gamma_cout_egal_a_la_prediction", fabs(z) < 4);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, ",{\"defi_gamma\":{\"gbits\":%d,\"essais\":%d,\"acceptees\":%d,\"moyenne\":%.1f,\"prediction\":%.1f,\"z\":%.2f}}", PRGAM.gbits, NG, acc, m, att, z);
        free(hc.cols); free(sig);
    }
    omp_set_num_threads(nth);
    {   /* blocs exacts : un profil dont le bloc n'est pas Π μ (l'ancien VOLE-128) est refusé */
        vp_t ancien = PR128;
        ancien.n = 18620; ancien.w = 76; ancien.bloc = 245;
        ctx_t c;
        res_controle(&r, "blocs_exacts_ancien_profil_245_refuse", ctx_init(&c, &ancien) == -1 && ctx_init(&c, &PR128) == 0 && ctx_init(&c, &PR256) == 0
                                                                  && ctx_init(&c, &PR128F) == 0 && ctx_init(&c, &PR256F) == 0);
    }
    res_controle(&r, "injection_d_echecs_sans_signature_partielle", ctl_injection());
    {
        double mc, zc;
        long nbits;
        int li;
        omp_set_num_threads(1);
        int ok = ctl_suf_liaison(&mc, &zc, &nbits, &li);
        omp_set_num_threads(nth);
        printf("SUF : %ld signatures à un bit près, toutes rejetées si le contrôle passe ; autre ctr de même défi trouvé en %.0f essais "
               "(prédiction 2^(τκ+wpow) = 4096, z = %+.2f), signature modifiée acceptée\n", nbits, mc, zc);
        res_controle(&r, "suf_encodage_unique_et_seule_malleabilite_ctr_au_cout_predit", ok);
        res_controle(&r, "liaison_cle_message_et_alea_defaillant", li);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, ",{\"suf\":{\"bits_testes\":%ld,\"essais_ctr\":%.0f,\"prediction\":4096,\"z\":%.2f}}", nbits, mc, zc);
    }
    snprintf(json + lj, sizeof json - lj, "]");
    res_mesure(&r, "resultats", "%s", json);
    return res_ecrire(&r);
}
