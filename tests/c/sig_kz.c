/* Sillage-SIG : attaque de Kales–Zaverucha à échelle intermédiaire contre le VRAI vérifieur C (plan GPU, D1 ; PREUVES § 3.3,
 * Théorème 8). Jusqu'ici, la borne n'était confrontée qu'au modèle jouet de tests/test_sig_modele.py (N = 4, τ = 3, GF(256)).
 *
 * Instance réduite, mêmes algorithmes que sig.c (inclus, table de paramètres rendue modifiable) : n = 64, F_poly = GF(2^6),
 * K = GF(2^12), k = 45, w = 3, t = 1, N = 2^8 feuilles, τ = 4 répétitions.
 *   - clé publique SANS témoin : aucun x de poids ≤ w n'a le syndrome y (vérifié exhaustivement) ;
 *   - faux témoin : x de poids minimal parmi x_A de poids ≤ 3, Q annule w positions de son support, P comme dans keygen ;
 *     sk = x_A ‖ Q ‖ P donné au signataire honnête, qui ne vérifie rien ;
 *   - une répétition est un « faux positif » si le défi (r, ε) annule l'erreur : sa diffusion honnête passe alors pour toute feuille
 *     cachée ; sinon le tricheur engage, pour une feuille cible, la diffusion que le vérifieur recalculera si c'est elle qui est cachée ;
 *   - attaque : moudre h1 jusqu'à t1 faux positifs, puis h2 jusqu'à ce que les τ − t1 autres feuilles cachées soient les cibles.
 * Contrôles : avec un VRAI témoin, la vue du vérifieur recalculée ici coïncide avec la diffusion honnête pour toute feuille et la
 * signature est acceptée (la réplication du vérifieur est exacte) ; chaque falsification est acceptée par sl_sig_verify ; la
 * fréquence de succès ne dépasse pas la borne du Théorème 8 (formule de tests/test_sig_modele.py :: _borne_8).
 *     make -C tests/c build/sig_kz && tests/c/build/sig_kz [essais]   (depuis la racine) → resultats/sig_kz.json */
#include <math.h>

#include "sig_var.c"
#include "resultat.h"

#define NIV 0
static const sp_t *p = &SP[NIV];

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
    sp_t q = {64, 45, 19, 3, 6, 12, 1, 8, 4, 16, 32, (1ULL << 6) | 0x3, (1ULL << 12) | 0x53, 0};
    SP[NIV] = q;
    static const uint32_t d6[2] = {2, 3}, d12[2] = {2, 3};
    if (!irreductible(SP[NIV].pe, 6, d6, 2) || !irreductible(SP[NIV].pb, 12, d12, 2)) return 0;
    for (uint64_t g = 2; g < 4096; g++) {                  /* racine dans K du polynôme de F_poly : X^6 + X + 1 */
        uint64_t g2 = gfm(g, g, SP[NIV].pb, 12), g4 = gfm(g2, g2, SP[NIV].pb, 12), g6 = gfm(g4, g2, SP[NIV].pb, 12);
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
    static uint8_t q[1 << 16];
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

/* faux positif : la diffusion honnête passe pour toute feuille cachée. Avec c = 0, aucun axe ne passe par la part totale
 * (bits de c tous nuls) : il faut des feuilles ayant des bits à 1 ; on teste c = 1 et c = N − 2. */
static int faux_positif(const etat_t *s, const uint8_t *pk, uint32_t rep, uint8_t *dv)
{
    vue_verifieur(s, pk, rep, 1, dv);
    int ok = !memcmp(dv, s->dh + rep * lrep_d, lrep_d);
    vue_verifieur(s, pk, rep, N - 2, dv);
    return ok && !memcmp(dv, s->dh + rep * lrep_d, lrep_d);
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

int main(int argc, char **argv)
{
    int essais = argc > 1 ? atoi(argv[1]) : 12;
    resultat_t res = {.nom = "sig_kz", .titre = "Sillage-SIG : attaque de Kales–Zaverucha à échelle intermédiaire, vrai vérifieur C"};
    if (!reduire()) { res_controle(&res, "parametres_reduits_valides", 0); return res_ecrire(&res); }
    res_controle(&res, "parametres_reduits_valides", 1);
    N = 1u << p->D; Lp = L_PART(p); La = L_AUX(p); xbo = XB(p); qbo = QB(p); pts = PTS(p);
    lrep_d = (2 + 3 * (size_t)p->D) * pts; Lt = (size_t)2 * N * p->sb;
    size_t lpk, lsk, lsig;
    sl_sig_tailles(NIV, &lpk, &lsk, &lsig);
    uint8_t *pk = sl_malloc(lpk), *sk = sl_malloc(lsk), *sig = sl_malloc(lsig), *diff = sl_malloc(p->tau * lrep_d);
    uint8_t *dv = sl_malloc(lrep_d);
    static const uint8_t msg[] = "falsification";
    etat_t s;
    allouer(&s);
    uint32_t ci[32];

    /* 1. contrôle : vrai témoin → vue du vérifieur = diffusion honnête pour toute feuille, signature acceptée */
    sl_sig_keygen(NIV, pk, sk);
    sl_alea(s.salt, 32);
    engager(&s, sk, pk, msg, sizeof msg);
    int ident = 1;
    for (uint32_t rep = 0; rep < p->tau; rep++)
        for (uint32_t c = 0; c < N; c += 17) { vue_verifieur(&s, pk, rep, c, dv); ident &= !memcmp(dv, s.dh + rep * lrep_d, lrep_d); }
    size_t l = signer_avec(&s, s.dh, sig, ci);
    res_controle(&res, "vrai_temoin_vue_verifieur_identique_et_signature_acceptee", ident && l == lsig && sl_sig_verify(NIV, pk, msg, sizeof msg, sig, l));

    /* 2. clé publique sans témoin, faux témoin */
    int ess = 0, bw = 0;
    uint8_t xa[16];
    do {
        sl_alea(pk, 32);
        sl_alea(pk + 32, NB(p->r));
        pk[32 + NB(p->r) - 1] &= (uint8_t)((1u << (p->r & 7)) - 1);
        bw = meilleur_xa(pk, xa);
        ess++;
    } while (bw <= (int)p->w && ess < 1000);
    res_controle(&res, "cle_publique_sans_temoin_de_poids_au_plus_w", bw > (int)p->w);
    {   /* support de x, w premières positions */
        const uint64_t *H = matrice(NIV, pk);
        uint64_t acc[NW(1229) + 1];
        mat_vec_ct(p, H, xa, acc);
        uint8_t xn[16] = {0};
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
    res_mesure(&res, "poids_du_faux_temoin", "%d", bw);

    /* 3. taux de faux positifs par répétition (mesuré), borne du Lemme 6 : (n + w)/|K| pour t = 1 */
    double plemme = (double)(p->n + p->w) / (double)(1u << p->ep);
    long nfp = 0, nrep = 0;
    int ntirages = 600;
    for (int it = 0; it < ntirages; it++) {
        sl_alea(s.salt, 32);
        engager(&s, sk, pk, msg, sizeof msg);
        for (uint32_t rep = 0; rep < p->tau; rep++) { nfp += faux_positif(&s, pk, rep, dv); nrep++; }
    }
    double pemp = (double)nfp / nrep;
    res_mesure(&res, "faux_positifs_par_repetition", "{\"mesure\": %.4f, \"repetitions\": %ld, \"borne_lemme_6\": %.4f}", pemp, nrep, plemme);
    res_controle(&res, "faux_positifs_sous_la_borne_du_lemme_6", pemp <= plemme * 1.5 + 3 * sqrt(plemme / nrep));

    /* 4. attaque : seuil t1 faux positifs sur h1, puis h2 sur les autres répétitions */
    /* budgets : deux où la borne est < 1 (fréquence comparée à la borne), un grand pour montrer des falsifications acceptées */
    static const struct { const char *nom; int seuil; long q1, q2; int div; } STRAT[] = {
        {"h1_2_puis_h2", 2, 400, 40000, 1},
        {"h1_3_puis_h2", 3, 6000, 600, 1},
        {"h1_2_puis_h2_grand_budget", 2, 2000, 200000, 2},
    };
    int toutes_valides = 1, sous_borne = 1, forge_vue = 0;
    char det[2048];
    int lg = snprintf(det, sizeof det, "{");
    static uint8_t vues[4][256][4096];
    for (size_t si = 0; si < sizeof STRAT / sizeof STRAT[0]; si++) {
        int gagne = 0, valides = 0, ne = essais / STRAT[si].div;
        long q1tot = 0, q2tot = 0;
        for (int e = 0; e < ne; e++) {
            long q1 = 0, q2 = 0;
            int fini = 0;
            while (q1 < STRAT[si].q1 && !fini) {
                q1++;
                sl_alea(s.salt, 32);
                engager(&s, sk, pk, msg, sizeof msg);
                int fp[4] = {0}, nf = 0;
                for (uint32_t rep = 0; rep < p->tau; rep++) {
                    fp[rep] = faux_positif(&s, pk, rep, dv);
                    nf += fp[rep];
                }
                if (nf < STRAT[si].seuil) continue;
                if (getenv("SIG_KZ_TRACE")) fprintf(stderr, "    [%s] h1 retenu après %ld essais, %d faux positifs\n", STRAT[si].nom, q1, nf);
                /* vues du vérifieur pour chaque feuille des répétitions sans faux positif */
                for (uint32_t rep = 0; rep < p->tau; rep++)
                    if (!fp[rep]) for (uint32_t c = 0; c < N; c++) vue_verifieur(&s, pk, rep, c, vues[rep][c]);
                uint32_t cible[4];
                for (; q2 < STRAT[si].q2; ) {
                    q2++;
                    uint8_t rnd[8];
                    sl_alea(rnd, sizeof rnd);
                    for (uint32_t rep = 0; rep < p->tau; rep++) {
                        cible[rep] = rnd[rep] % N;
                        memcpy(diff + rep * lrep_d, fp[rep] ? s.dh + rep * lrep_d : vues[rep][cible[rep]], lrep_d);
                    }
                    size_t ls = signer_avec(&s, diff, sig, ci);
                    int ok = 1;
                    for (uint32_t rep = 0; rep < p->tau; rep++) ok &= fp[rep] || ci[rep] == cible[rep];
                    if (ok) {
                        if (getenv("SIG_KZ_TRACE")) fprintf(stderr, "    succès après %ld essais de h2\n", q2);
                        gagne++;
                        valides += sl_sig_verify(NIV, pk, msg, sizeof msg, sig, ls);
                        fini = 1;
                        break;
                    }
                }
                fini = 1;                                  /* comme le modèle : un seul h1 retenu, puis h2 jusqu'au budget */
            }
            q1tot += q1; q2tot += q2;
        }
        double freq = (double)gagne / ne, b = borne_8((double)STRAT[si].q1, (double)STRAT[si].q2, plemme);
        toutes_valides &= valides == gagne;
        sous_borne &= freq <= b + 2 * sqrt(b * (1 - b) / ne) + 1.0 / ne;
        if (STRAT[si].div > 1) forge_vue |= gagne > 0;
        lg += snprintf(det + lg, sizeof det - lg, "%s\"%s\": {\"succes\": %d, \"essais\": %d, \"acceptees_par_le_verifieur\": %d, "
                       "\"frequence\": %.3f, \"borne_theoreme_8\": %.3f, \"q1_moyen\": %.0f, \"q2_moyen\": %.0f}",
                       si ? ", " : "", STRAT[si].nom, gagne, ne, valides, freq, b, (double)q1tot / ne, (double)q2tot / ne);
        fprintf(stderr, "  %s : %d/%d falsifications, %d acceptées, borne %.3f\n", STRAT[si].nom, gagne, ne, valides, b);
    }
    snprintf(det + lg, sizeof det - lg, "}");
    res_mesure(&res, "attaques", "%s", det);
    res_controle(&res, "chaque_falsification_acceptee_par_le_vrai_verifieur", toutes_valides);
    res_controle(&res, "frequence_de_succes_sous_la_borne_du_theoreme_8", sous_borne);
    res_controle(&res, "falsification_obtenue_au_grand_budget", forge_vue);
    return res_ecrire(&res);
}
