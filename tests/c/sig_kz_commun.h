/* Outils communs aux deux versions de l'attaque de Kales–Zaverucha à échelle réduite :
 * tests/c/sig_kz.c (CPU) et tests/gpu/sig_kz_gpu.c (broyage de h1 et de h2 sur GPU, vrai vérifieur C).
 * Instance réduite, signataire honnête ou tricheur, réplication du vérifieur, faux témoin, bornes et prédiction exacte,
 * contrôles de préparation (instance_preparer) et bilan statistique par stratégie (kz_bilan). Aucune donnée n'y est
 * propre à l'une des versions : les deux tirent les mêmes clés et le même faux témoin pour une même graine. */
#ifndef SIG_KZ_COMMUN_H
#define SIG_KZ_COMMUN_H
#include <math.h>

#include "sig_var.c"
#include "resultat.h"

#define NIV 0

/* corps des défis K = GF(2^KZ_EP) ⊃ F_poly = GF(2^6) (6 | KZ_EP) : 12 par défaut (tests/c/sig_kz.c, tests/gpu/sig_kz_gpu),
 * 18 pour la version GPU à faux positifs rares (tests/gpu/sig_kz_gpu_k18, plan D1) */
#ifndef KZ_EP
#define KZ_EP 12
#endif
#if KZ_EP == 12
#define KZ_PB ((1ULL << 12) | 0x53)                       /* x^12 + x^6 + x^4 + x + 1 */
#elif KZ_EP == 18
#define KZ_PB ((1ULL << 18) | (1ULL << 7) | 1)            /* x^18 + x^7 + 1 */
#else
#error "KZ_EP : 12 ou 18"
#endif
static const sp_t *p = &SP[NIV];

/* --------------------------------------------------------- aléa reproductible */
static alea_t rng;

static void tirer(void *o, size_t n)
{
    uint8_t *b = o;
    while (n) {
        uint64_t x = alea64(&rng);
        size_t k = n < sizeof x ? n : sizeof x;
        memcpy(b, &x, k);
        b += k; n -= k;
    }
}

/* --------------------------------------------------------- intervalle de confiance exact */
/* Clopper–Pearson bilatéral au niveau 1 − alpha : queues binomiales sommées en log (stable pour tout n, coût O(n) par point). */
static double log_pmf(int n, int k, double x)
{
    return lgamma(n + 1.0) - lgamma(k + 1.0) - lgamma(n - k + 1.0)
         + k * log(x) + (n - k) * log1p(-x);
}

static double queue_binom(int n, int k, double x, int superieure)
{
    int deb = superieure ? k : 0, fin = superieure ? n : k;
    double m = -INFINITY, s = 0;
    for (int i = deb; i <= fin; i++) {
        double t = log_pmf(n, i, x);
        if (t > m) { s = s * exp(m - t) + 1.0; m = t; }
        else s += exp(t - m);
    }
    return s * exp(m);
}

static void ic_cp(int succes, int n, double alpha, double *bas, double *haut)
{
    if (succes == 0)
        *bas = 0;
    else {
        double lo = 0, hi = 1;
        for (int i = 0; i < 80; i++) {
            double m = (lo + hi) / 2;
            if (queue_binom(n, succes, m, 1) < alpha / 2) lo = m; else hi = m;
        }
        *bas = (lo + hi) / 2;
    }
    if (succes == n)
        *haut = 1;
    else {
        double lo = 0, hi = 1;
        for (int i = 0; i < 80; i++) {
            double m = (lo + hi) / 2;
            if (queue_binom(n, succes, m, 0) > alpha / 2) lo = m; else hi = m;
        }
        *haut = (lo + hi) / 2;
    }
}

static int irreductible(uint64_t poly, uint32_t deg, const uint32_t *div, int nd)   /* Rabin : x^(2^deg) = x, x^(2^(deg/q)) ≠ x */
{
    uint64_t x = 2, y = x;
    for (uint32_t i = 0; i < deg; i++) y = gfm(y, y, poly, deg);
    if (y != x) return 0;
    for (int j = 0; j < nd; j++) {
        y = x;
        for (uint32_t i = 0; i < deg / div[j]; i++) y = gfm(y, y, poly, deg);
        if (y == x) return 0;
    }
    return 1;
}

static int reduire(void)
{
    sp_t q = {64, 45, 19, 3, 6, KZ_EP, 1, 8, 4, 16, 32, (1ULL << 6) | 0x3, KZ_PB, 0};
    SP[NIV] = q;
    static const uint32_t d6[2] = {2, 3}, dk[2] = {2, 3};  /* diviseurs premiers de 6, 12 et 18 */
    if (!irreductible(SP[NIV].pe, 6, d6, 2) || !irreductible(SP[NIV].pb, KZ_EP, dk, 2)) return 0;
    for (uint64_t g = 2; g < 1ULL << KZ_EP; g++) {         /* racine dans K du polynôme de F_poly : X^6 + X + 1 */
        uint64_t g2 = gfm(g, g, SP[NIV].pb, KZ_EP), g4 = gfm(g2, g2, SP[NIV].pb, KZ_EP), g6 = gfm(g4, g2, SP[NIV].pb, KZ_EP);
        if ((g6 ^ g ^ 1) == 0) { SP[NIV].g = g; return 1; }
    }
    return 0;
}

/* --------------------------------------------------------- état d'un signataire (honnête ou tricheur) */
typedef struct {
    uint8_t salt[32], pkh[HB_MAX], mh[HB_MAX], h1[HB_MAX];
    uint8_t *arbres, *coms, *auxs, *cotes, *tots, *hs, *dh, *ouv;   /* dh : diffusion honnête */
    uint64_t r[64], eps[64];
} etat_t;

static size_t Lp, La, xbo, qbo, pts, lrep_d, Lt;
static uint32_t N;

static void allouer(etat_t *s)
{
    uint32_t tau = p->tau, D = p->D;
    s->arbres = sl_malloc(tau * Lt); s->coms = sl_malloc((size_t)tau * N * p->hb); s->auxs = sl_malloc(tau * La);
    s->cotes = sl_malloc((size_t)tau * D * Lp); s->tots = sl_malloc(tau * Lp); s->hs = sl_malloc((size_t)tau * p->hb);
    s->dh = sl_malloc(tau * lrep_d); s->ouv = sl_malloc(tau * 2 * pts);
}

/* engagements et h1 (copie de sl_sig_sign_sel), puis défis et diffusion honnête */
static void engager(etat_t *s, const uint8_t *sk, const uint8_t *pk, const uint8_t *msg, size_t len)
{
    uint32_t D = p->D, tau = p->tau, sb = p->sb, hb = p->hb, t = p->t;
    const uint64_t *H = matrice(NIV, pk);
    uint8_t mseed[HB_MAX];
    sig_hacher_pk(p, pk, s->pkh);
    hacher_msg(p, msg, len, s->mh);
    { const uint8_t *a[3] = {sk, s->salt, s->mh}; size_t la[3] = {xbo + 2 * qbo, 32, hb}; hacher("SILLAGE-SIG|mseed", a, la, 3, mseed, hb); }
    for (uint32_t rep = 0; rep < tau; rep++) {
        uint8_t *tr = s->arbres + rep * Lt, *cm = s->coms + (size_t)rep * N * hb, *cote = s->cotes + (size_t)rep * D * Lp;
        uint8_t *tot = s->tots + rep * Lp, *aux = s->auxs + rep * La, rb[4], *connu = sl_calloc(2 * N, 1);
        be32(rb, rep);
        { const uint8_t *a[2] = {mseed, rb}; size_t la[2] = {hb, 4}; hacher("SILLAGE-SIG|r", a, la, 2, tr + sb, sb); }
        connu[1] = 1;
        developper(p, s->salt, rep, tr, connu);
        free(connu);
        feuilles(p, s->salt, rep, tr, -1, cote, tot, cm);
        for (size_t i = 0; i < xbo + 2 * qbo; i++) aux[i] = sk[i] ^ tot[i];
        const uint8_t *ta = tot + xbo + 2 * qbo, *tb = ta + pts, *tc = tb + pts;
        uint64_t ab[T_MAX];
        for (uint32_t j = 0; j < t; j++) ab[j] = GF(lire_bits(ta, (size_t)j * p->ep, p->ep), lire_bits(tb, (size_t)j * p->ep, p->ep));
        empaqueter(p, ab, aux + xbo + 2 * qbo);
        for (size_t i = 0; i < pts; i++) aux[xbo + 2 * qbo + i] ^= tc[i];
        for (uint32_t d = 0; d <= D; d++) {
            uint8_t *x = d < D ? cote + (size_t)d * Lp : tot;
            xor_oct(x, aux, xbo + 2 * qbo);
            xor_oct(x + xbo + 2 * qbo + 2 * pts, aux + xbo + 2 * qbo, pts);
        }
        com_dernier(p, s->salt, rep, tr + (size_t)(2 * N - 1) * sb, aux, cm + (size_t)(N - 1) * hb);
        hacher_coms(p, s->salt, rep, cm, s->hs + (size_t)rep * hb);
    }
    hacher_h1(p, s->salt, s->pkh, s->mh, s->hs, s->h1);
    defis1(p, s->h1, s->r, s->eps);
    tables(NIV);
    for (uint32_t rep = 0; rep < tau; rep++) {
        prep_t Pr;
        Pr.L = sl_malloc(8 * (size_t)t * p->n); Pr.pw = sl_malloc(8 * (size_t)t * p->w);
        preparer(NIV, s->r + (size_t)rep * t, &Pr);
        uint64_t oa[T_MAX], ob[T_MAX], x1[T_MAX], x2[T_MAX], x3[T_MAX];
        const uint64_t *er = s->eps + (size_t)rep * t;
        uint8_t *dr = s->dh + rep * lrep_d;
        simuler(NIV, s->tots + rep * Lp, H, pk + 32, er, &Pr, 1, NULL, NULL, oa, ob, x3);
        empaqueter(p, oa, dr); empaqueter(p, ob, dr + pts);
        memcpy(s->ouv + rep * 2 * pts, dr, 2 * pts);
        for (uint32_t d = 0; d < D; d++) {
            simuler(NIV, s->cotes + ((size_t)rep * D + d) * Lp, H, pk + 32, er, &Pr, 0, oa, ob, x1, x2, x3);
            empaqueter(p, x1, dr + (2 + 3 * (size_t)d) * pts);
            empaqueter(p, x2, dr + (3 + 3 * (size_t)d) * pts);
            empaqueter(p, x3, dr + (4 + 3 * (size_t)d) * pts);
        }
        free(Pr.L); free(Pr.pw);
    }
}

/* corps d'une répétition de signature si la feuille cachée est c (copie de la sérialisation de sl_sig_sign_sel) */
static size_t corps_rep(const etat_t *s, uint32_t rep, uint32_t c, uint8_t *o)
{
    uint32_t D = p->D, sb = p->sb, hb = p->hb, j = N + c;
    uint8_t *o0 = o;
    for (uint32_t l = 0; l < D; l++) { memcpy(o, s->arbres + rep * Lt + (size_t)(j ^ 1) * sb, sb); o += sb; j >>= 1; }
    memcpy(o, s->coms + ((size_t)rep * N + c) * hb, hb);
    for (size_t i = 0; i < La; i++) o[hb + i] = c != N - 1 ? s->auxs[rep * La + i] : 0;
    memcpy(o + hb + La, s->ouv + rep * 2 * pts, 2 * pts);
    return (size_t)(o + hb + La + 2 * pts - o0);
}

/* diffusion que le vérifieur recalcule pour une répétition, feuille cachée c (copie du corps de boucle de sl_sig_verify) */
static void vue_verifieur(const etat_t *s, const uint8_t *pk, uint32_t rep, uint32_t c, uint8_t *dr)
{
    uint32_t D = p->D, sb = p->sb, hb = p->hb, t = p->t;
    const uint64_t *H = matrice(NIV, pk);
    static _Thread_local uint8_t q[1 << 16];               /* un tampon par thread (étape 2 parallèle du GPU) */
    corps_rep(s, rep, c, q);
    const uint8_t *com = q + (size_t)D * sb, *aux = com + hb, *al = aux + La, *be = al + pts;
    uint8_t *tr = sl_calloc(2 * (size_t)N, sb), *connu = sl_calloc(2 * (size_t)N, 1), *cm = sl_malloc((size_t)N * hb);
    uint8_t *cote = sl_malloc((size_t)D * Lp), *tot = sl_malloc(Lp);
    uint32_t j = N + c;
    for (uint32_t l = 0; l < D; l++) { memcpy(tr + (size_t)(j ^ 1) * sb, q + (size_t)l * sb, sb); connu[j ^ 1] = 1; j >>= 1; }
    developper(p, s->salt, rep, tr, connu);
    feuilles(p, s->salt, rep, tr, (int32_t)c, cote, tot, cm);
    free(connu);
    if (c != N - 1)
        for (uint32_t d = 0; d <= D; d++) {
            uint8_t *x = d < D ? cote + (size_t)d * Lp : tot;
            xor_oct(x, aux, xbo + 2 * qbo);
            xor_oct(x + xbo + 2 * qbo + 2 * pts, aux + xbo + 2 * qbo, pts);
        }
    prep_t Pr;
    Pr.L = sl_malloc(8 * (size_t)t * p->n); Pr.pw = sl_malloc(8 * (size_t)t * p->w);
    preparer(NIV, s->r + (size_t)rep * t, &Pr);
    uint64_t oa[T_MAX], ob[T_MAX], x1[T_MAX], x2[T_MAX], x3[T_MAX];
    for (uint32_t k = 0; k < t; k++) { oa[k] = lire_bits(al, (size_t)k * p->ep, p->ep); ob[k] = lire_bits(be, (size_t)k * p->ep, p->ep); }
    const uint64_t *er = s->eps + (size_t)rep * t;
    memcpy(dr, al, 2 * pts);
    for (uint32_t d = 0; d < D; d++) {
        const uint8_t *cd = cote + (size_t)d * Lp;
        if (c >> d & 1) {
            uint8_t *c0 = sl_malloc(Lp);
            memcpy(c0, cd, Lp); xor_oct(c0, tot, Lp);
            simuler(NIV, c0, H, pk + 32, er, &Pr, 1, oa, ob, x1, x2, x3);
            free(c0);
            for (uint32_t k = 0; k < t; k++) { x1[k] ^= oa[k]; x2[k] ^= ob[k]; }
        } else
            simuler(NIV, cd, H, pk + 32, er, &Pr, 0, oa, ob, x1, x2, x3);
        empaqueter(p, x1, dr + (2 + 3 * (size_t)d) * pts);
        empaqueter(p, x2, dr + (3 + 3 * (size_t)d) * pts);
        empaqueter(p, x3, dr + (4 + 3 * (size_t)d) * pts);
    }
    free(Pr.L); free(Pr.pw); free(tr); free(cm); free(cote); free(tot);
}

/* valeur T(r) = S(r)·Q(r) + P(r)·F(r), évaluée dans K à partir du témoin complet x et de sk = x_A ‖ Q ‖ P
 * (même formule que tests/test_sig_modele.py :: _valeur_T). t = 1 dans cette instance. */
static uint64_t valeur_T(const etat_t *s, const uint8_t *x, const uint8_t *sk, uint32_t rep)
{
    uint32_t n = p->n, w = p->w, e = p->e;
    const uint8_t *Qb = sk + xbo, *Pb = sk + xbo + qbo;
    prep_t Pr;
    Pr.L = sl_malloc(8 * (size_t)p->t * n); Pr.pw = sl_malloc(8 * (size_t)p->t * w);
    preparer(NIV, s->r + (size_t)rep * p->t, &Pr);
    uint64_t S = 0, Qr = Pr.rw[0], Prv = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t m = 0 - (uint64_t)(x[i >> 3] >> (i & 7) & 1);
        S ^= Pr.L[i] & m;
    }
    for (uint32_t i = 0; i < w; i++) {
        uint64_t q = lire_bits(Qb, (size_t)i * e, e), d = lire_bits(Pb, (size_t)i * e, e), qe = 0, pe = 0;
        for (uint32_t c = 0; c < e; c++) {
            qe ^= tab_sig[NIV].base[c] & (0 - (q >> c & 1));
            pe ^= tab_sig[NIV].base[c] & (0 - (d >> c & 1));
        }
        Qr ^= GF(qe, Pr.pw[i]);
        Prv ^= GF(pe, Pr.pw[i]);
    }
    uint64_t T = GF(S, Qr) ^ GF(Prv, Pr.Fr[0]);
    free(Pr.L); free(Pr.pw);
    return T;
}

/* faux positif : ε·T(r) = 0 dans K, condition exacte du Lemme 6 (même test que Rep.faux_positif dans le modèle).
 * Elle vaut pour toute feuille cachée (Proposition 6) et évite de recalculer N vues par répétition. */
static int faux_positif(const etat_t *s, const uint8_t *x, const uint8_t *sk, uint32_t rep)
{
    return s->eps[rep] == 0 || valeur_T(s, x, sk, rep) == 0;
}

/* signature complète : diffusion fournie, feuilles cachées tirées de h2 */
static size_t signer_avec(const etat_t *s, const uint8_t *diff, uint8_t *sig, uint32_t *ci)
{
    uint8_t h2[HB_MAX];
    hacher_h2(p, s->salt, s->pkh, s->mh, s->h1, diff, p->tau * lrep_d, h2);
    defis2(p, h2, ci);
    uint8_t *o = sig;
    memcpy(o, s->salt, 32); memcpy(o + 32, s->h1, p->hb); memcpy(o + 32 + p->hb, h2, p->hb);
    o += 32 + 2 * (size_t)p->hb;
    for (uint32_t rep = 0; rep < p->tau; rep++) o += corps_rep(s, rep, ci[rep], o);
    return (size_t)(o - sig);
}

/* --------------------------------------------------------- clés */
static int poids(const uint8_t *v, size_t nb) { int w = 0; for (size_t i = 0; i < nb; i++) w += __builtin_popcount(v[i]); return w; }

/* plus petit poids de x = (x_A, y ⊕ H'x_A) pour x_A de poids ≤ 3 ; renvoie le meilleur x_A */
static int meilleur_xa(const uint8_t *pk, uint8_t *best)
{
    const uint64_t *H = matrice(NIV, pk);
    uint32_t k = p->k;
    int bw = 1 << 30;
    uint8_t xa[16];
    uint64_t acc[NW(1229) + 1];
    for (int a = -1; a < (int)k; a++)
        for (int b = a; b < (int)k; b++)
            for (int c = b; c < (int)k; c++) {
                if ((a >= 0 && a == b) || (b >= 0 && b == c) || c < 0) { if (!(a == -1 && b == -1 && c == -1)) continue; }
                memset(xa, 0, sizeof xa);
                if (a >= 0) xa[a >> 3] |= 1 << (a & 7);
                if (b >= 0) xa[b >> 3] |= 1 << (b & 7);
                if (c >= 0) xa[c >> 3] |= 1 << (c & 7);
                mat_vec_ct(p, H, xa, acc);
                uint8_t xbv[8] = {0};
                memcpy(xbv, acc, NB(p->r));
                for (size_t i = 0; i < NB(p->r); i++) xbv[i] ^= pk[32 + i];
                int w = poids(xa, NB(k)) + poids(xbv, NB(p->r));
                if (w < bw) { bw = w; memcpy(best, xa, NB(k)); }
            }
    return bw;
}

/* sk factice à partir de x = (x_A, x_B) et de w positions de son support (Q, P comme dans keygen) */
static void sk_de(const uint8_t *xa, const uint32_t *pos, uint8_t *sk)
{
    uint32_t w = p->w, e = p->e;
    uint64_t Q[W_MAX + 1] = {1}, P[W_MAX] = {0};
    for (uint32_t q = 0; q < w; q++) {
        for (uint32_t i = q + 1; i > 0; i--) Q[i] = Q[i - 1] ^ GE(Q[i], pos[q]);
        Q[0] = GE(Q[0], pos[q]);
    }
    for (uint32_t q = 0; q < w; q++) {
        uint64_t c = 0;
        for (uint32_t i = w; i > 0; i--) { c = Q[i] ^ GE(c, pos[q]); P[i - 1] ^= c; }
    }
    memset(sk, 0, xbo + 2 * qbo);
    memcpy(sk, xa, xbo);
    for (uint32_t i = 0; i < w; i++) {
        ecrire_bits(sk + xbo, (size_t)i * e, e, Q[i]);
        ecrire_bits(sk + xbo + qbo, (size_t)i * e, e, P[i]);
    }
}

static double binom(int n, int k) { double r = 1; for (int i = 0; i < k; i++) r = r * (n - i) / (i + 1); return r; }
static double borne_8(double q1, double q2, double prep)
{
    int tau = (int)p->tau;
    double best = 1;
    for (int t1 = 1; t1 <= tau + 1; t1++) {
        double queue = 0;
        for (int i = t1; i <= tau; i++) queue += binom(tau, i) * pow(prep, i) * pow(1 - prep, tau - i);
        double b = fmin(1.0, (q1 + 1) * queue + (q2 + 1) * pow((double)N, -(tau - t1 + 1)));
        if (b < best) best = b;
    }
    return best;
}

/* probabilité de succès EXACTE de la stratégie simulée ici, pour un taux de faux positifs pf par répétition :
 * étape 1 : un h1 à au moins `seuil` faux positifs parmi q1 essais, 1 − (1 − P1)^q1 avec P1 = P(Bin(τ, pf) ≥ seuil) ;
 * étape 2 : avec k faux positifs, les m = τ − k autres répétitions offrent M = N^m cibles distinctes, chacune point fixe de
 * cible ↦ défis avec probabilité 1/M (h2 oracle aléatoire, défis uniformes) ; on en énumère min(q2, M) : 1 − (1 − 1/M)^min(q2, M). */
static double prediction(int seuil, double q1, double q2, double pf, double *e1, double *e2)
{
    int tau = (int)p->tau;
    double P1 = 0, s2 = 0;
    for (int k = seuil; k <= tau; k++) {
        double pk = binom(tau, k) * pow(pf, k) * pow(1 - pf, tau - k), M = pow((double)N, tau - k);
        P1 += pk;
        s2 += pk * (M <= 1 ? 1.0 : -expm1(fmin(q2, M) * log1p(-1.0 / M)));
    }
    *e1 = -expm1(q1 * log1p(-P1));
    *e2 = P1 > 0 ? s2 / P1 : 0;
    return *e1 * *e2;
}


/* --------------------------------------------------------- instance du test */
static uint8_t *pk, *sk, *sig, *diff, *dv, xn[16];
static size_t lpk, lsk, lsig;
static etat_t s;
static uint32_t ci[32];
static double plemme;
static const uint8_t msg[] = "falsification";

/* paramètres, contrôles 1 à 4 (vrai témoin, clé sans témoin, faux témoin, faux positifs sous le Lemme 6).
 * Renvoie 0 si l'instance réduite est invalide. rng doit être initialisé (même consommation que l'ancien main). */
static int instance_preparer(resultat_t *res)
{
    if (!reduire()) { res_controle(res, "parametres_reduits_valides", 0); return 0; }
    res_controle(res, "parametres_reduits_valides", 1);
    N = 1u << p->D; Lp = L_PART(p); La = L_AUX(p); xbo = XB(p); qbo = QB(p); pts = PTS(p);
    lrep_d = (2 + 3 * (size_t)p->D) * pts; Lt = (size_t)2 * N * p->sb;
    sl_sig_tailles(NIV, &lpk, &lsk, &lsig);
    pk = sl_malloc(lpk); sk = sl_malloc(lsk); sig = sl_malloc(lsig); diff = sl_malloc(p->tau * lrep_d);
    dv = sl_malloc(lrep_d);
    allouer(&s);

    /* 1. contrôle : vrai témoin → vue du vérifieur = diffusion honnête pour toute feuille, signature acceptée */
    sl_sig_keygen(NIV, pk, sk);
    tirer(s.salt, 32);
    engager(&s, sk, pk, msg, sizeof msg);
    int ident = 1;
    for (uint32_t rep = 0; rep < p->tau; rep++)
        for (uint32_t c = 0; c < N; c++) { vue_verifieur(&s, pk, rep, c, dv); ident &= !memcmp(dv, s.dh + rep * lrep_d, lrep_d); }
    size_t l = signer_avec(&s, s.dh, sig, ci);
    res_controle(res, "vrai_temoin_vue_verifieur_identique_et_signature_acceptee", ident && l == lsig && sl_sig_verify(NIV, pk, msg, sizeof msg, sig, l));

    /* 2. clé publique sans témoin, faux témoin */
    int ess = 0, bw = 0;
    uint8_t xa[16];
    memset(xn, 0, sizeof xn);
    do {
        tirer(pk, 32);
        tirer(pk + 32, NB(p->r));
        pk[32 + NB(p->r) - 1] &= (uint8_t)((1u << (p->r & 7)) - 1);
        bw = meilleur_xa(pk, xa);
        ess++;
    } while (bw <= (int)p->w && ess < 1000);
    res_controle(res, "cle_publique_sans_temoin_de_poids_au_plus_w", bw > (int)p->w);
    {   /* support de x, w premières positions */
        const uint64_t *H = matrice(NIV, pk);
        uint64_t acc[NW(1229) + 1];
        mat_vec_ct(p, H, xa, acc);
        memcpy(xn, xa, xbo);
        for (uint32_t i = 0; i < p->r; i++) {
            int bit = (int)(((uint8_t *)acc)[i >> 3] >> (i & 7) & 1) ^ (pk[32 + (i >> 3)] >> (i & 7) & 1);
            uint32_t jj = p->k + i;
            if (bit) xn[jj >> 3] |= 1 << (jj & 7);
        }
        uint32_t pos[W_MAX], np = 0;
        for (uint32_t i = 0; i < p->n && np < p->w; i++) if (xn[i >> 3] >> (i & 7) & 1) pos[np++] = i;
        sk_de(xa, pos, sk);
    }
    res_mesure(res, "poids_du_faux_temoin", "%d", bw);

    /* 3. taux de faux positifs par répétition (mesuré), borne du Lemme 6 : (n + w)/|K| pour t = 1 */
    plemme = (double)(p->n + p->w) / (double)(1u << p->ep);
    long nfp = 0, nrep = 0;
    int ntirages = 600;
    for (int it = 0; it < ntirages; it++) {
        tirer(s.salt, 32);
        engager(&s, sk, pk, msg, sizeof msg);
        for (uint32_t rep = 0; rep < p->tau; rep++) { nfp += faux_positif(&s, xn, sk, rep); nrep++; }
    }
    double pemp = (double)nfp / nrep;
    res_mesure(res, "faux_positifs_par_repetition", "{\"mesure\": %.4f, \"repetitions\": %ld, \"borne_lemme_6\": %.4f}", pemp, nrep, plemme);
    res_controle(res, "faux_positifs_sous_la_borne_du_lemme_6", pemp <= plemme * 1.5 + 3 * sqrt(plemme / nrep));

    return 1;
}

/* --------------------------------------------------------- stratégies et bilan */
/* deux stratégies à borne < 1 (dont une quantitative à borne basse) et un grand budget pour la faisabilité */
typedef struct { const char *nom; int seuil; long q1, q2; int div; int mini; int quantitatif; } strat_t;
#if KZ_EP == 12
static const strat_t STRAT[] = {
    {"h1_2_puis_h2", 2, 400, 40000, 1, 0, 0},
    {"h1_2_puis_h2_borne_basse", 2, 25, 131072, 1, 0, 1},
    {"h1_2_puis_h2_grand_budget", 2, 4000, 500000, 2, 6, 0},
};
#else   /* K = GF(2^18) : un h1 à deux faux positifs coûte ≈ 2,8·10^6 tentatives ; mêmes rôles, budgets q1 en conséquence */
static const strat_t STRAT[] = {
    {"h1_2_puis_h2", 2, 1L << 20, 40000, 1, 0, 0},
    {"h1_2_puis_h2_borne_basse", 2, 1L << 17, 131072, 1, 0, 1},
    {"h1_2_puis_h2_grand_budget", 2, 1L << 24, 500000, 2, 6, 0},
};
#endif
enum { NS = sizeof STRAT / sizeof STRAT[0] };

typedef struct { int gagne, retenus, ne; long valides, q1tot, q2tot, nf_hist[5]; } bilan_t;

/* nombre d'essais d'une stratégie : quantitatif → equant, sinon essais / div, au moins mini et au moins 1 */
static int kz_essais(size_t si, int essais, int equant)
{
    int ne = STRAT[si].quantitatif ? equant : essais / STRAT[si].div;
    if (ne < STRAT[si].mini) ne = STRAT[si].mini;
    if (ne < 1) ne = 1;                                 /* au moins un essai : sinon fréquence 0/0 */
    return ne;
}

/* mesure « attaques » et cinq contrôles : falsifications acceptées, borne du Théorème 8 (IC à 99,9 %), borne au-dessus de
 * l'IC95 quantitatif, prédiction exacte (pf : taux de faux positifs par répétition retenu pour la prédiction), grand budget */
static void kz_bilan(resultat_t *res, const bilan_t *B, double pf)
{
    int toutes_valides = 1, sous_borne = 1, forge_vue = 0, borne_hors_ic = 1, conforme = 1;
    char det[8192];
    int lg = snprintf(det, sizeof det, "{");
    for (size_t si = 0; si < NS; si++) {
        int gagne = B[si].gagne, ne = B[si].ne, ret = B[si].retenus;
        double freq = (double)gagne / ne, b = borne_8((double)STRAT[si].q1, (double)STRAT[si].q2, plemme), e1, e2;
        double pred = prediction(STRAT[si].seuil, (double)STRAT[si].q1, (double)STRAT[si].q2, pf, &e1, &e2);
        double icb, ich, ib3, ih3;
        ic_cp(gagne, ne, 0.05, &icb, &ich);
        ic_cp(gagne, ne, 0.001, &ib3, &ih3);
        toutes_valides &= B[si].valides == gagne;
        sous_borne &= ib3 <= b;                             /* borne non réfutée au niveau 99,9 % */
        conforme &= ib3 <= pred && pred <= ih3;             /* prédiction exacte dans l'IC à 99,9 % */
        if (STRAT[si].quantitatif && ne >= 500) borne_hors_ic &= b >= ich;   /* IC trop large en dessous de 500 essais */
        if (STRAT[si].div > 1) forge_vue |= gagne > 0;
        lg += snprintf(det + lg, sizeof det - lg, "%s\"%s\": {\"succes\": %d, \"essais\": %d, \"acceptees_par_le_verifieur\": %ld, "
                       "\"frequence\": %.4f, \"ic95\": [%.4f, %.4f], \"ic999\": [%.4f, %.4f], \"borne_theoreme_8\": %.4f, "
                       "\"prediction\": %.4f, \"h1_retenus\": %d, \"etape1\": {\"mesure\": %.4f, \"prediction\": %.4f}, "
                       "\"etape2\": {\"mesure\": %.4f, \"prediction\": %.4f}, \"faux_positifs_du_h1_retenu\": [%ld, %ld, %ld], "
                       "\"q1_moyen\": %.0f, \"q2_moyen\": %.0f}",
                       si ? ", " : "", STRAT[si].nom, gagne, ne, B[si].valides, freq, icb, ich, ib3, ih3, b, pred, ret,
                       (double)ret / ne, e1, ret ? (double)gagne / ret : 0.0, e2, B[si].nf_hist[2], B[si].nf_hist[3], B[si].nf_hist[4],
                       (double)B[si].q1tot / ne, (double)B[si].q2tot / ne);
        fprintf(stderr, "  %s : %d/%d falsifications, %ld acceptées, prédiction %.4f, borne %.3f, IC95 [%.4f, %.4f]\n",
                STRAT[si].nom, gagne, ne, B[si].valides, pred, b, icb, ich);
    }
    snprintf(det + lg, sizeof det - lg, "}");
    res_mesure(res, "attaques", "%s", det);
    res_controle(res, "chaque_falsification_acceptee_par_le_vrai_verifieur", toutes_valides);
    res_controle(res, "frequence_de_succes_sous_la_borne_du_theoreme_8", sous_borne);
    res_controle(res, "borne_du_theoreme_8_au_dessus_de_l_ic95_quantitatif", borne_hors_ic);
    res_controle(res, "frequence_de_succes_conforme_a_la_prediction_exacte", conforme);
    res_controle(res, "falsification_obtenue_au_grand_budget", forge_vue);
}
#endif
