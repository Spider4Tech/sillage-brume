/* SILLAGE C — Sillage-SIG : MPC-in-the-Head à hypercube sur le décodage de syndrome binaire
 * (miroir exact de sillage/sillage_sig.py, voir sa description et PREUVES § 3).
 * H' (k colonnes de r bits, dérivées de seed_H) est mise en cache, une entrée par niveau et par
 * thread. Les répétitions sont réparties sur les cœurs (OpenMP, répartition statique : le
 * découpage ne dépend d'aucune donnée).
 *
 * Temps constant côté signataire (keygen, sign) : le témoin, les graines et les parts ne
 * passent que par des XOR, des masques et des produits sans retenue. Aucun branchement ni accès
 * mémoire n'en dépend. h1 et h2 sont publics (dans la signature) : les défis qui en dérivent
 * peuvent indexer et brancher.
 */
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>

#include "sillage.h"

/* sb = graines (λ + 8 bits), hb = hachés (2λ bits) ; pe, pb irréductibles ; g : racine de pe dans GF(2^ep) */
typedef struct { uint32_t n, k, r, w, e, ep, t, D, tau, sb, hb; uint64_t pe, pb, g; } sp_t;
static const sp_t SP[2] = {
    {2048, 1434, 614, 103, 11, 44, 4, 12, 11, 17, 32, (1ULL << 11) | 5, (1ULL << 44) | 33, 0x110004f8689ULL},
    {4096, 2867, 1229, 206, 12, 48, 4, 12, 23, 33, 64, (1ULL << 12) | 9, (1ULL << 48) | 0x291, 0x1c48e8c6fad3ULL},
};
#define NB(x) (((x) + 7) / 8)
#define NW(x) (((x) + 63) / 64)
#define XB(p) NB((p)->k)
#define QB(p) NB((p)->w * (p)->e)
#define PTS(p) NB((p)->t * (p)->ep)
#define L_PART(p) (XB(p) + 2 * QB(p) + 3 * PTS(p))
#define L_AUX(p) (XB(p) + 2 * QB(p) + PTS(p))
#define HB_MAX 64
#define SB_MAX 33
#define T_MAX 4
#define D_MAX 12
#define W_MAX 206
#define N_MAX 4096

/* ------------------------------------------------------------- corps */
static inline uint64_t gfm(uint64_t a, uint64_t b, uint64_t poly, uint32_t deg)
{
    uint64_t lo, hi, R = poly ^ (1ULL << deg), m = (1ULL << deg) - 1;
    sl_clmul64(a, b, &lo, &hi);
    uint64_t haut = (lo >> deg) | (hi << (64 - deg)), l2, h2;
    sl_clmul64(haut, R, &l2, &h2);
    uint64_t r = (lo & m) ^ (l2 & m), reste = (l2 >> deg) | (h2 << (64 - deg));
    sl_clmul64(reste, R, &l2, &h2);
    return r ^ l2;
}
#define GF(a, b) gfm((a), (b), p->pb, p->ep)
#define GE(a, b) gfm((a), (b), p->pe, p->e)

/* Tables publiques, partagées : φ(i) pour i ∈ F_poly, base de φ */
static struct { uint64_t *phi, base[12]; } tab_sig[2];

static void tables(int niv)
{
    const sp_t *p = &SP[niv];
#pragma omp critical(sl_sig_tables)
    if (!tab_sig[niv].phi) {
        uint64_t *t = calloc(p->n, 8), c = 1;
        for (uint32_t i = 0; i < p->e; i++) {
            tab_sig[niv].base[i] = c;
            for (uint32_t j = 0; j < 1u << i; j++)
                t[(1u << i) + j] = t[j] ^ c;
            c = GF(c, p->g);
        }
        tab_sig[niv].phi = t;
    }
}

/* ponytail: un H par thread appelant (≈ 110 / 440 Ko), jamais libéré ; pool borné si des threads éphémères signent en masse */
static _Thread_local struct { uint8_t seed[32]; uint64_t *H; } cache_H[2];

/* ------------------------------------------------------------- H' */
static const uint64_t *matrice(int niv, const uint8_t seed[32])
{
    const sp_t *p = &SP[niv];
    size_t rw = NW(p->r), rb = NB(p->r);
    if (cache_H[niv].H && !memcmp(cache_H[niv].seed, seed, 32))
        return cache_H[niv].H;
    if (!cache_H[niv].H)
        cache_H[niv].H = calloc((size_t)p->k * rw, 8);
    uint64_t *Hm = cache_H[niv].H;
    /* colonne j = SHAKE256("SILLAGE-SIG|Hcol|" ‖ j_be64 ‖ "|" ‖ graine), 4 par 4 */
#pragma omp parallel for schedule(static)
    for (uint32_t i = 0; i < p->k / 4 + 1; i++) {
        uint8_t m[4][17 + 8 + 1 + 32], sortie[8 * (NW(3400) + 1)];
        const uint8_t *pm[4] = {m[0], m[1], m[2], m[3]};
        uint8_t *out[4];
        for (uint32_t j = 0; j < 4; j++) {
            uint32_t c = 4 * i + j;
            memcpy(m[j], "SILLAGE-SIG|Hcol|", 17);
            for (int b = 0; b < 8; b++)
                m[j][17 + b] = (uint8_t)((uint64_t)c >> (56 - 8 * b));
            m[j][25] = '|';
            memcpy(m[j] + 26, seed, 32);
            out[j] = c < p->k ? (uint8_t *)(Hm + (size_t)c * rw) : sortie;
            if (c < p->k)
                Hm[(size_t)c * rw + rw - 1] = 0;
        }
        sl_shake4(pm, sizeof m[0], out, rb);
        if (p->r & 63)
            for (uint32_t j = 0; j < 4 && 4 * i + j < p->k; j++)
                Hm[(size_t)(4 * i + j) * rw + rw - 1] &= (1ULL << (p->r & 63)) - 1;
    }
    memcpy(cache_H[niv].seed, seed, 32);
    return Hm;
}

/* x_B = H'·x_A, masqué (r mots) */
__attribute__((noinline)) static void mat_vec_ct(const sp_t *p, const uint64_t *H, const uint8_t *xa, uint64_t *acc)
{
    size_t rw = NW(p->r);
    memset(acc, 0, rw * 8);
    for (uint32_t j = 0; j < p->k; j++) {
        uint64_t m = 0 - (uint64_t)(xa[j >> 3] >> (j & 7) & 1);
        __asm__ volatile("" : "+r"(m));                    /* gcc recréerait un branchement sur le bit */
        const uint64_t *C = H + (size_t)j * rw;
        for (size_t i = 0; i < rw; i++)
            acc[i] ^= C[i] & m;
    }
}

/* ------------------------------------------------------- champs de bits */
static inline uint64_t lire_bits(const uint8_t *b, size_t pos, uint32_t nb)
{
    uint64_t v = 0;
    size_t o = pos >> 3;
    memcpy(&v, b + o, 8 < (pos + nb + 7) / 8 - o ? 8 : (pos + nb + 7) / 8 - o);
    return (v >> (pos & 7)) & ((1ULL << nb) - 1);
}

static inline void ecrire_bits(uint8_t *b, size_t pos, uint32_t nb, uint64_t v)
{
    size_t o = pos >> 3, fin = (pos + nb + 7) / 8;
    uint64_t x = 0;
    memcpy(&x, b + o, fin - o);
    x |= v << (pos & 7);
    memcpy(b + o, &x, fin - o);
}

static void empaqueter(const sp_t *p, const uint64_t *v, uint8_t *o)
{
    memset(o, 0, PTS(p));
    for (uint32_t j = 0; j < p->t; j++)
        ecrire_bits(o, (size_t)j * p->ep, p->ep, v[j]);
}

/* bits de bourrage d'une part : les masques suivent les champs */
static void masquer_part(const sp_t *p, uint8_t *x)
{
    size_t xb = XB(p), qb = QB(p), pts = PTS(p);
    if (p->k & 7)
        x[xb - 1] &= (uint8_t)((1 << (p->k & 7)) - 1);
    if ((p->w * p->e) & 7) {
        uint8_t m = (uint8_t)((1 << ((p->w * p->e) & 7)) - 1);
        x[xb + qb - 1] &= m;
        x[xb + 2 * qb - 1] &= m;
    }
    if ((p->t * p->ep) & 7)
        for (int i = 1; i <= 3; i++)
            x[xb + 2 * qb + (size_t)i * pts - 1] &= (uint8_t)((1 << ((p->t * p->ep) & 7)) - 1);
}

static void xor_oct(uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        a[i] ^= b[i];
}

static inline void be32(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16); o[2] = (uint8_t)(v >> 8); o[3] = (uint8_t)v;
}

/* ------------------------------------------------------------- arbre et feuilles */
/* Message "SILLAGE-SIG|<t>|" ‖ sel ‖ rep ‖ i ‖ graine (<t> d'un caractère) */
static size_t msg_noeud(const sp_t *p, char tag, const uint8_t *salt, uint32_t rep, uint32_t i, const uint8_t *g, uint8_t *m)
{
    memcpy(m, "SILLAGE-SIG|", 12);
    m[12] = (uint8_t)tag; m[13] = '|';
    memcpy(m + 14, salt, 32);
    be32(m + 46, rep);
    be32(m + 50, i);
    memcpy(m + 54, g, p->sb);
    return 54 + p->sb;
}

/* Fils des nœuds connus, niveau par niveau et 4 par 4 (t : 2N graines, connu : drapeaux publics) */
static void developper(const sp_t *p, const uint8_t *salt, uint32_t rep, uint8_t *t, uint8_t *connu)
{
    uint32_t N = 1u << p->D, sb = p->sb;
    uint8_t m[4][54 + SB_MAX], vide[2 * SB_MAX];
    const uint8_t *pm[4] = {m[0], m[1], m[2], m[3]};
    size_t L = 54 + sb;
    for (uint32_t deb = 1; deb < N; deb <<= 1) {
        uint32_t lot[4], nb = 0;
        for (uint32_t j = deb; j < 2 * deb; j++) {
            if (connu[j]) {
                msg_noeud(p, 'a', salt, rep, j, t + (size_t)j * sb, m[nb]);
                lot[nb++] = j;
            }
            if (nb == 4 || (j == 2 * deb - 1 && nb)) {
                uint8_t *out[4];
                for (uint32_t q = 0; q < 4; q++) {
                    if (q >= nb)
                        memcpy(m[q], m[0], L);
                    out[q] = q < nb ? t + (size_t)2 * lot[q] * sb : vide;
                    if (q < nb)
                        connu[2 * lot[q]] = connu[2 * lot[q] + 1] = 1;
                }
                sl_shake4(pm, L, out, 2 * sb);
                nb = 0;
            }
        }
    }
    sl_effacer(m, sizeof m);
    sl_effacer(vide, sizeof vide);
}

/* Parts et engagements : cote[d] = Σ parts de bit d à 1, tot = Σ parts (2N additions).
 * cache < N : feuille sans graine, part nulle (vérifieur). L'engagement de N−1 reste à faire. */
static void feuilles(const sp_t *p, const uint8_t *salt, uint32_t rep, const uint8_t *t, int32_t cache,
                     uint8_t *cote, uint8_t *tot, uint8_t *coms)
{
    uint32_t N = 1u << p->D, D = p->D, sb = p->sb, hb = p->hb;
    size_t Lp = L_PART(p);
    uint8_t *pile = malloc(D * Lp), *px = malloc(4 * Lp), m[4][54 + SB_MAX], *cx = malloc(4 * hb);
    const uint8_t *pm[4] = {m[0], m[1], m[2], m[3]};
    memset(cote, 0, D * Lp);
    for (uint32_t i = 0; i < N; i += 4) {
        uint8_t *op[4] = {px, px + Lp, px + 2 * Lp, px + 3 * Lp}, *oc[4] = {cx, cx + hb, cx + 2 * hb, cx + 3 * hb};
        for (uint32_t q = 0; q < 4; q++)
            msg_noeud(p, 'f', salt, rep, i + q, t + (size_t)(N + i + q) * sb, m[q]);
        sl_shake4(pm, 54 + sb, op, Lp);
        for (uint32_t q = 0; q < 4; q++)
            msg_noeud(p, 'c', salt, rep, i + q, t + (size_t)(N + i + q) * sb, m[q]);
        sl_shake4(pm, 54 + sb, oc, hb);
        for (uint32_t q = 0; q < 4; q++) {
            uint32_t ii = i + q;
            uint8_t *x = op[q];
            if ((int32_t)ii == cache)
                memset(x, 0, Lp);
            else
                memcpy(coms + (size_t)ii * hb, oc[q], hb);
            masquer_part(p, x);
            uint32_t l;
            for (l = 0; l < D; l++) {                     /* hypercube, repli des paires */
                if (!(ii >> l & 1)) {
                    memcpy(pile + (size_t)l * Lp, x, Lp);
                    break;
                }
                xor_oct(cote + (size_t)l * Lp, x, Lp);
                xor_oct(x, pile + (size_t)l * Lp, Lp);
            }
            if (l == D)
                memcpy(tot, x, Lp);
        }
    }
    sl_effacer(pile, D * Lp); sl_effacer(px, 4 * Lp); sl_effacer(m, sizeof m); sl_effacer(cx, 4 * hb);
    free(pile); free(px); free(cx);
}

/* ------------------------------------------------------------- MPC */
typedef struct { uint64_t Fr[T_MAX], rw[T_MAX], *L, *pw; } prep_t;      /* L[j·n + i], pw[j·w + i] */

static void preparer(int niv, const uint64_t *r, prep_t *P)
{
    const sp_t *p = &SP[niv];
    uint32_t n = p->n, w = p->w;
    const uint64_t *phi = tab_sig[niv].phi;
    uint64_t *pre = malloc(8 * (size_t)n);
    for (uint32_t j = 0; j < p->t; j++) {
        uint64_t rj = r[j], Fr = rj, *L = P->L + (size_t)j * n, *pw = P->pw + (size_t)j * w;
        for (uint32_t i = 0; i < p->e; i++)
            Fr = GF(Fr, Fr);
        Fr ^= rj;
        P->Fr[j] = Fr;
        if (!Fr) {                                         /* r public, dans F_poly : L_i = 1 si f_i = r */
            for (uint32_t i = 0; i < n; i++)
                L[i] = phi[i] == rj;
        } else {                                           /* inversion groupée (Montgomery) */
            uint64_t acc = 1;
            for (uint32_t i = 0; i < n; i++) {
                pre[i] = acc;
                acc = GF(acc, phi[i] ^ rj);
            }
            uint64_t inv = 1, c = acc;                     /* acc^(2^ep − 2) */
            for (uint32_t i = 0; i + 1 < p->ep; i++) {
                c = GF(c, c);
                inv = GF(inv, c);
            }
            inv = GF(inv, Fr);                             /* F(r)/Π */
            for (uint32_t i = n; i-- > 0;) {
                L[i] = GF(pre[i], inv);
                inv = GF(inv, phi[i] ^ rj);
            }
        }
        uint64_t c = 1;
        for (uint32_t i = 0; i < w; i++) {
            pw[i] = c;
            c = GF(c, rj);
        }
        P->rw[j] = c;
    }
    free(pre);
}

/* Diffusion d'un côté : (α_s, β_s, v_s), un groupe de t valeurs par quantité.
 * cte : le côté porte les constantes (y, r^w, α·β). oa, ob : valeurs ouvertes, ou NULL (v non calculé). */
__attribute__((noinline)) static void simuler(int niv, const uint8_t *part, const uint64_t *H, const uint8_t *y, const uint64_t *eps,
                    const prep_t *P, int cte, const uint64_t *oa, const uint64_t *ob,
                    uint64_t *al, uint64_t *be, uint64_t *v)
{
    const sp_t *p = &SP[niv];
    uint32_t k = p->k, w = p->w, e = p->e, ep = p->ep, t = p->t, n = p->n, r = p->r;
    size_t xb = XB(p), qb = QB(p), pts = PTS(p), rw = NW(r);
    const uint8_t *xa = part, *Qb = part + xb, *Pb = part + xb + qb, *ab = part + xb + 2 * qb;
    uint64_t xB[NW(1229) + 1], Qe[W_MAX], Pe[W_MAX];
    mat_vec_ct(p, H, xa, xB);
    if (cte) {                                             /* y public */
        uint64_t ym[NW(1229) + 1] = {0};
        memcpy(ym, y, NB(r));
        for (size_t i = 0; i < rw; i++)
            xB[i] ^= ym[i];
    }
    for (uint32_t i = 0; i < w; i++) {                     /* plongement, par masques */
        uint64_t q = lire_bits(Qb, (size_t)i * e, e), d = lire_bits(Pb, (size_t)i * e, e), a = 0, b = 0;
        for (uint32_t c = 0; c < e; c++) {
            a ^= tab_sig[niv].base[c] & (0 - (q >> c & 1));
            b ^= tab_sig[niv].base[c] & (0 - (d >> c & 1));
        }
        Qe[i] = a; Pe[i] = b;
    }
    for (uint32_t j = 0; j < t; j++) {
        const uint64_t *L = P->L + (size_t)j * n, *pw = P->pw + (size_t)j * w;
        uint64_t S = 0, Qr = cte ? P->rw[j] : 0, Pr = 0;
        for (uint32_t i = 0; i < k; i++) {
            uint64_t m = 0 - (uint64_t)(xa[i >> 3] >> (i & 7) & 1);
            __asm__ volatile("" : "+r"(m));
            S ^= L[i] & m;
        }
        for (uint32_t i = 0; i < r; i++) {
            uint64_t m = 0 - (xB[i >> 6] >> (i & 63) & 1);
            __asm__ volatile("" : "+r"(m));
            S ^= L[k + i] & m;
        }
        for (uint32_t i = 0; i < w; i++) {
            Qr ^= GF(Qe[i], pw[i]);
            Pr ^= GF(Pe[i], pw[i]);
        }
        uint64_t a = lire_bits(ab, (size_t)j * ep, ep), b = lire_bits(ab + pts, (size_t)j * ep, ep);
        al[j] = GF(eps[j], Qr) ^ a;
        be[j] = S ^ b;
        if (oa) {
            uint64_t c = lire_bits(ab + 2 * pts, (size_t)j * ep, ep);
            uint64_t x = c ^ GF(oa[j], b) ^ GF(ob[j], a) ^ GF(GF(eps[j], P->Fr[j]), Pr);
            v[j] = cte ? x ^ GF(oa[j], ob[j]) : x;
        }
    }
    sl_effacer(xB, sizeof xB); sl_effacer(Qe, sizeof Qe); sl_effacer(Pe, sizeof Pe);
}

/* ------------------------------------------------------------- hachés et défis */
static void hacher(const char *dom, const uint8_t *const *parts, const size_t *lens, int np, uint8_t *o, size_t l)
{
    sl_shake_dom(dom, NULL, 0, parts, lens, np, o, l);
}

/* (r, ε) par répétition : 6 octets petit-boutistes, masqués à ep bits */
static void defis1(const sp_t *p, const uint8_t *h1, uint64_t *r, uint64_t *eps)
{
    size_t o = (size_t)2 * p->tau * p->t * 6;
    uint8_t *s = malloc(o);
    const uint8_t *a[1] = {h1};
    size_t la[1] = {p->hb};
    hacher("SILLAGE-SIG|ch1", a, la, 1, s, o);
    uint64_t m = (1ULL << p->ep) - 1;
    for (size_t i = 0; i < (size_t)p->tau * p->t; i++) {
        uint64_t x = 0, y = 0;
        memcpy(&x, s + 12 * i, 6);
        memcpy(&y, s + 12 * i + 6, 6);
        r[i] = x & m;
        eps[i] = y & m;
    }
    free(s);
}

static void defis2(const sp_t *p, const uint8_t *h2, uint32_t *ci)
{
    uint8_t s[2 * 32];
    const uint8_t *a[1] = {h2};
    size_t la[1] = {p->hb};
    hacher("SILLAGE-SIG|ch2", a, la, 1, s, 2 * (size_t)p->tau);
    for (uint32_t i = 0; i < p->tau; i++)
        ci[i] = (s[2 * i] | (uint32_t)s[2 * i + 1] << 8) & ((1u << p->D) - 1);
}

static void sig_hacher_pk(const sp_t *p, const uint8_t *pk, uint8_t *pkh)
{
    const uint8_t *a[1] = {pk};
    size_t la[1] = {32 + NB(p->r)};
    hacher("SILLAGE-SIG|pkh", a, la, 1, pkh, p->hb);
}

static void hacher_msg(const sp_t *p, const uint8_t *m, size_t len, uint8_t *mh)
{
    const uint8_t *a[1] = {m};
    size_t la[1] = {len};
    hacher("SILLAGE-SIG|msg", a, la, 1, mh, p->hb);
}

static void hacher_coms(const sp_t *p, const uint8_t *salt, uint32_t rep, const uint8_t *coms, uint8_t *h)
{
    uint8_t rb[4];
    be32(rb, rep);
    const uint8_t *a[3] = {salt, rb, coms};
    size_t la[3] = {32, 4, (size_t)p->hb << p->D};
    hacher("SILLAGE-SIG|com", a, la, 3, h, p->hb);
}

static void com_dernier(const sp_t *p, const uint8_t *salt, uint32_t rep, const uint8_t *seed, const uint8_t *aux, uint8_t *o)
{
    uint8_t rb[4], ib[4];
    be32(rb, rep);
    be32(ib, (1u << p->D) - 1);
    const uint8_t *a[5] = {salt, rb, ib, seed, aux};
    size_t la[5] = {32, 4, 4, p->sb, L_AUX(p)};
    hacher("SILLAGE-SIG|c", a, la, 5, o, p->hb);
}

static void hacher_h1(const sp_t *p, const uint8_t *salt, const uint8_t *pkh, const uint8_t *mh, const uint8_t *hs, uint8_t *h1)
{
    const uint8_t *a[4] = {salt, pkh, mh, hs};
    size_t la[4] = {32, p->hb, p->hb, (size_t)p->tau * p->hb};
    hacher("SILLAGE-SIG|h1", a, la, 4, h1, p->hb);
}

static void hacher_h2(const sp_t *p, const uint8_t *salt, const uint8_t *pkh, const uint8_t *mh, const uint8_t *h1,
                      const uint8_t *diff, size_t ld, uint8_t *h2)
{
    const uint8_t *a[5] = {salt, pkh, mh, h1, diff};
    size_t la[5] = {32, p->hb, p->hb, p->hb, ld};
    hacher("SILLAGE-SIG|h2", a, la, 5, h2, p->hb);
}

/* ------------------------------------------------------------- API */
void sl_sig_tailles(int niv, size_t *pk, size_t *sk, size_t *sig_max)
{
    const sp_t *p = &SP[niv];
    *pk = 32 + NB(p->r);
    *sk = XB(p) + 2 * QB(p);
    *sig_max = 32 + 2 * (size_t)p->hb + (size_t)p->tau * ((size_t)p->D * p->sb + p->hb + L_AUX(p) + 2 * PTS(p));
}

int sl_sig_keygen(int niv, uint8_t *pk, uint8_t *sk)
{
    const sp_t *p = &SP[niv];
    uint32_t k = p->k, w = p->w, e = p->e;
    uint8_t g[32], xn[NB(4096)];
    if (sl_alea(pk, 32) || sl_alea(g, 32))
        return -3;
    uint32_t pos[W_MAX];
    sl_creux(g, 32, (int)w, p->n, "SILLAGE-SIG|x", pos);
    memset(xn, 0, NB(p->n));
    for (uint32_t q = 0; q < w; q++)                       /* écriture par balayage masqué */
        for (size_t o = 0; o < NB(p->n); o++) {
            uint32_t d = (uint32_t)o ^ (pos[q] >> 3);
            xn[o] |= (uint8_t)(1u << (pos[q] & 7)) & (uint8_t)(0 - (((d | (0 - d)) >> 31) ^ 1));
        }
    /* Q = Π (X + f), P = Σ Q/(X + f) : F'(f) = 1 */
    uint64_t Q[W_MAX + 1] = {1}, P[W_MAX] = {0};
    for (uint32_t q = 0; q < w; q++) {
        for (uint32_t i = q + 1; i > 0; i--)
            Q[i] = Q[i - 1] ^ GE(Q[i], pos[q]);
        Q[0] = GE(Q[0], pos[q]);
    }
    for (uint32_t q = 0; q < w; q++) {
        uint64_t c = 0;
        for (uint32_t i = w; i > 0; i--) {
            c = Q[i] ^ GE(c, pos[q]);
            P[i - 1] ^= c;
        }
    }
    memset(sk, 0, XB(p) + 2 * QB(p));
    memcpy(sk, xn, XB(p));
    if (k & 7)
        sk[XB(p) - 1] &= (uint8_t)((1 << (k & 7)) - 1);
    for (uint32_t i = 0; i < w; i++) {
        ecrire_bits(sk + XB(p), (size_t)i * e, e, Q[i]);
        ecrire_bits(sk + XB(p) + QB(p), (size_t)i * e, e, P[i]);
    }
    uint64_t y[NW(1229) + 1];
    mat_vec_ct(p, matrice(niv, pk), sk, y);
    uint8_t yb[NB(1229) + 8];
    memcpy(yb, y, NB(p->r));
    for (uint32_t i = 0; i < p->r; i++) {                  /* y = H'·x_A + x_B, x_B = x[k, n) */
        uint32_t j = k + i;
        yb[i >> 3] ^= (uint8_t)((xn[j >> 3] >> (j & 7) & 1) << (i & 7));
    }
    memcpy(pk + 32, yb, NB(p->r));
    sl_effacer(g, 32); sl_effacer(xn, sizeof xn); sl_effacer(pos, sizeof pos); sl_effacer(y, sizeof y);
    sl_effacer(yb, sizeof yb); sl_effacer(Q, sizeof Q); sl_effacer(P, sizeof P);
    return 0;
}

int sl_sig_sign_sel(int niv, const uint8_t *sk, const uint8_t *pk, const uint8_t *msg, size_t len,
                    const uint8_t salt[32], uint8_t *sig, size_t *siglen)
{
    const sp_t *p = &SP[niv];
    uint32_t N = 1u << p->D, D = p->D, tau = p->tau, sb = p->sb, hb = p->hb, t = p->t;
    size_t Lp = L_PART(p), La = L_AUX(p), xb = XB(p), qb = QB(p), pts = PTS(p), lrep_d = (2 + 3 * (size_t)D) * pts;
    const uint64_t *H = matrice(niv, pk);
    uint8_t pkh[HB_MAX], mh[HB_MAX], mseed[HB_MAX], h1[HB_MAX], h2[HB_MAX];
    sig_hacher_pk(p, pk, pkh);
    hacher_msg(p, msg, len, mh);
    {   /* graine maîtresse couverte par sk : un aléa défaillant ne répète pas les graines d'un message à l'autre */
        const uint8_t *a[3] = {sk, salt, mh};
        size_t la[3] = {xb + 2 * qb, 32, hb};
        hacher("SILLAGE-SIG|mseed", a, la, 3, mseed, hb);
    }
    size_t Lt = (size_t)2 * N * sb;
    uint8_t *arbres = malloc(tau * Lt), *coms = malloc((size_t)tau * N * hb), *auxs = malloc(tau * La);
    uint8_t *cotes = malloc((size_t)tau * D * Lp), *tots = malloc(tau * Lp), *hs = malloc((size_t)tau * hb);
    uint8_t *diff = malloc(tau * lrep_d), *ouv = malloc(tau * 2 * pts);
#pragma omp parallel for schedule(static)
    for (uint32_t rep = 0; rep < tau; rep++) {
        uint8_t *tr = arbres + rep * Lt, *cm = coms + (size_t)rep * N * hb, *cote = cotes + (size_t)rep * D * Lp;
        uint8_t *tot = tots + rep * Lp, *aux = auxs + rep * La, rb[4], *connu = calloc(2 * N, 1);
        be32(rb, rep);
        {
            const uint8_t *a[2] = {mseed, rb};
            size_t la[2] = {hb, 4};
            hacher("SILLAGE-SIG|r", a, la, 2, tr + sb, sb);
        }
        connu[1] = 1;
        developper(p, salt, rep, tr, connu);
        free(connu);
        feuilles(p, salt, rep, tr, -1, cote, tot, cm);
        /* aux = témoin ⊕ Σ parts ; c : a·b ⊕ Σ c */
        for (size_t i = 0; i < xb + 2 * qb; i++)
            aux[i] = sk[i] ^ tot[i];
        const uint8_t *ta = tot + xb + 2 * qb, *tb = ta + pts, *tc = tb + pts;
        uint64_t ab[T_MAX];
        for (uint32_t j = 0; j < t; j++)
            ab[j] = GF(lire_bits(ta, (size_t)j * p->ep, p->ep), lire_bits(tb, (size_t)j * p->ep, p->ep));
        empaqueter(p, ab, aux + xb + 2 * qb);
        for (size_t i = 0; i < pts; i++)
            aux[xb + 2 * qb + i] ^= tc[i];
        sl_effacer(ab, sizeof ab);
        /* la feuille N−1 (tous ses bits à 1) reçoit aux, sur x_A, Q, P et c seulement */
        for (uint32_t d = 0; d <= D; d++) {
            uint8_t *x = d < D ? cote + (size_t)d * Lp : tot;
            xor_oct(x, aux, xb + 2 * qb);
            xor_oct(x + xb + 2 * qb + 2 * pts, aux + xb + 2 * qb, pts);
        }
        com_dernier(p, salt, rep, tr + (size_t)(2 * N - 1) * sb, aux, cm + (size_t)(N - 1) * hb);
        hacher_coms(p, salt, rep, cm, hs + (size_t)rep * hb);
    }
    hacher_h1(p, salt, pkh, mh, hs, h1);
    SL_PUBLIC(h1, hb);                                     /* publié dans la signature */
    uint64_t *r = malloc(8 * (size_t)tau * t), *eps = malloc(8 * (size_t)tau * t);
    defis1(p, h1, r, eps);
    tables(niv);
#pragma omp parallel for schedule(static)
    for (uint32_t rep = 0; rep < tau; rep++) {
        const uint64_t *Hr = H;
        prep_t Pr;
        Pr.L = malloc(8 * (size_t)t * p->n);
        Pr.pw = malloc(8 * (size_t)t * p->w);
        preparer(niv, r + (size_t)rep * t, &Pr);
        uint64_t oa[T_MAX], ob[T_MAX], x1[T_MAX], x2[T_MAX], x3[T_MAX];
        const uint64_t *er = eps + (size_t)rep * t;
        uint8_t *dr = diff + rep * lrep_d;
        simuler(niv, tots + rep * Lp, Hr, pk + 32, er, &Pr, 1, NULL, NULL, oa, ob, x3);
        empaqueter(p, oa, dr);
        empaqueter(p, ob, dr + pts);
        memcpy(ouv + rep * 2 * pts, dr, 2 * pts);
        for (uint32_t d = 0; d < D; d++) {
            simuler(niv, cotes + ((size_t)rep * D + d) * Lp, Hr, pk + 32, er, &Pr, 0, oa, ob, x1, x2, x3);
            empaqueter(p, x1, dr + (2 + 3 * (size_t)d) * pts);
            empaqueter(p, x2, dr + (3 + 3 * (size_t)d) * pts);
            empaqueter(p, x3, dr + (4 + 3 * (size_t)d) * pts);
        }
        free(Pr.L); free(Pr.pw);
    }
    hacher_h2(p, salt, pkh, mh, h1, diff, tau * lrep_d, h2);
    SL_PUBLIC(h2, hb);
    uint32_t ci[32];
    defis2(p, h2, ci);
    uint8_t *o = sig;
    memcpy(o, salt, 32); memcpy(o + 32, h1, hb); memcpy(o + 32 + hb, h2, hb);
    o += 32 + 2 * (size_t)hb;
    for (uint32_t rep = 0; rep < tau; rep++) {
        uint32_t j = N + ci[rep];
        for (uint32_t l = 0; l < D; l++) {
            memcpy(o, arbres + rep * Lt + (size_t)(j ^ 1) * sb, sb);
            o += sb;
            j >>= 1;
        }
        memcpy(o, coms + ((size_t)rep * N + ci[rep]) * hb, hb);
        uint8_t garde = (uint8_t)(0 - (uint8_t)(ci[rep] != N - 1));   /* dernière feuille cachée : aux, inutile, vaut 0 */
        for (size_t i = 0; i < La; i++)
            o[hb + i] = auxs[rep * La + i] & garde;
        memcpy(o + hb + La, ouv + rep * 2 * pts, 2 * pts);
        o += hb + La + 2 * pts;
    }
    *siglen = (size_t)(o - sig);
    sl_effacer(arbres, tau * Lt); sl_effacer(cotes, (size_t)tau * D * Lp); sl_effacer(tots, tau * Lp);
    sl_effacer(mseed, sizeof mseed);
    free(arbres); free(coms); free(auxs); free(cotes); free(tots); free(hs); free(diff); free(ouv); free(r); free(eps);
    return 0;
}

int sl_sig_sign(int niv, const uint8_t *sk, const uint8_t *pk, const uint8_t *msg,
                size_t len, uint8_t *sig, size_t *siglen)
{
    uint8_t salt[32];
    if (sl_alea(salt, 32))
        return -3;
    return sl_sig_sign_sel(niv, sk, pk, msg, len, salt, sig, siglen);
}

int sl_sig_verify(int niv, const uint8_t *pk, const uint8_t *msg, size_t len,
                  const uint8_t *sig, size_t siglen)
{
    const sp_t *p = &SP[niv];
    uint32_t N = 1u << p->D, D = p->D, tau = p->tau, sb = p->sb, hb = p->hb, t = p->t;
    size_t Lp = L_PART(p), La = L_AUX(p), xb = XB(p), qb = QB(p), pts = PTS(p), lrep_d = (2 + 3 * (size_t)D) * pts;
    size_t att, a1, a2;
    sl_sig_tailles(niv, &a1, &a2, &att);
    if (siglen != att)
        return 0;
    if ((p->r & 7) && (pk[32 + NB(p->r) - 1] >> (p->r & 7)))
        return 0;
    size_t lr = (size_t)D * sb + hb + La + 2 * pts;
    const uint8_t *salt = sig, *h1 = sig + 32, *h2 = sig + 32 + hb, *corps = sig + 32 + 2 * (size_t)hb;
    uint8_t *masque = malloc(Lp);                           /* encodage canonique */
    memset(masque, 0xFF, Lp);
    masquer_part(p, masque);
    int ok = 1;
    for (uint32_t rep = 0; rep < tau && ok; rep++) {
        const uint8_t *a = corps + rep * lr + (size_t)D * sb + hb;
        for (size_t i = 0; i < xb + 2 * qb; i++)
            ok &= !(a[i] & ~masque[i]);
        if ((p->t * p->ep) & 7)
            for (int q = 1; q <= 3; q++)
                ok &= !(a[xb + 2 * qb + (size_t)q * pts - 1] >> ((p->t * p->ep) & 7));
    }
    free(masque);
    if (!ok)
        return 0;
    const uint64_t *H = matrice(niv, pk);
    uint8_t pkh[HB_MAX], mh[HB_MAX], h1c[HB_MAX], h2c[HB_MAX];
    sig_hacher_pk(p, pk, pkh);
    hacher_msg(p, msg, len, mh);
    uint32_t ci[32];
    defis2(p, h2, ci);
    for (uint32_t rep = 0; rep < tau; rep++)                 /* encodage unique : aux = 0 si la dernière feuille est cachée */
        if (ci[rep] == N - 1)
            for (size_t i = 0; i < La; i++)
                if (corps[rep * lr + (size_t)D * sb + hb + i])
                    return 0;
    uint64_t *r = malloc(8 * (size_t)tau * t), *eps = malloc(8 * (size_t)tau * t);
    defis1(p, h1, r, eps);
    tables(niv);
    uint8_t *hs = malloc((size_t)tau * hb), *diff = malloc(tau * lrep_d);
#pragma omp parallel for schedule(static)
    for (uint32_t rep = 0; rep < tau; rep++) {
        const uint8_t *q = corps + rep * lr, *com = q + (size_t)D * sb, *aux = com + hb, *al = aux + La, *be = al + pts;
        uint8_t *tr = calloc(2 * (size_t)N, sb), *connu = calloc(2 * (size_t)N, 1), *cm = malloc((size_t)N * hb);
        uint8_t *cote = malloc((size_t)D * Lp), *tot = malloc(Lp);
        uint32_t j = N + ci[rep];
        for (uint32_t l = 0; l < D; l++) {
            memcpy(tr + (size_t)(j ^ 1) * sb, q + (size_t)l * sb, sb);
            connu[j ^ 1] = 1;
            j >>= 1;
        }
        developper(p, salt, rep, tr, connu);
        feuilles(p, salt, rep, tr, (int32_t)ci[rep], cote, tot, cm);
        free(connu);
        memcpy(cm + (size_t)ci[rep] * hb, com, hb);
        if (ci[rep] != N - 1) {
            for (uint32_t d = 0; d <= D; d++) {
                uint8_t *x = d < D ? cote + (size_t)d * Lp : tot;
                xor_oct(x, aux, xb + 2 * qb);
                xor_oct(x + xb + 2 * qb + 2 * pts, aux + xb + 2 * qb, pts);
            }
            com_dernier(p, salt, rep, tr + (size_t)(2 * N - 1) * sb, aux, cm + (size_t)(N - 1) * hb);
        }
        hacher_coms(p, salt, rep, cm, hs + (size_t)rep * hb);
        prep_t Pr;
        Pr.L = malloc(8 * (size_t)t * p->n);
        Pr.pw = malloc(8 * (size_t)t * p->w);
        preparer(niv, r + (size_t)rep * t, &Pr);
        uint64_t oa[T_MAX], ob[T_MAX], x1[T_MAX], x2[T_MAX], x3[T_MAX];
        for (uint32_t c = 0; c < t; c++) {
            oa[c] = lire_bits(al, (size_t)c * p->ep, p->ep);
            ob[c] = lire_bits(be, (size_t)c * p->ep, p->ep);
        }
        const uint64_t *er = eps + (size_t)rep * t;
        uint8_t *dr = diff + rep * lrep_d;
        memcpy(dr, al, 2 * pts);
        for (uint32_t d = 0; d < D; d++) {
            const uint8_t *cd = cote + (size_t)d * Lp;
            if (ci[rep] >> d & 1) {                        /* cachée du côté 1 : on simule le côté 0 */
                uint8_t *c0 = malloc(Lp);
                memcpy(c0, cd, Lp);
                xor_oct(c0, tot, Lp);
                simuler(niv, c0, H, pk + 32, er, &Pr, 1, oa, ob, x1, x2, x3);
                free(c0);
                for (uint32_t c = 0; c < t; c++) {
                    x1[c] ^= oa[c];
                    x2[c] ^= ob[c];
                }
            } else
                simuler(niv, cd, H, pk + 32, er, &Pr, 0, oa, ob, x1, x2, x3);
            empaqueter(p, x1, dr + (2 + 3 * (size_t)d) * pts);
            empaqueter(p, x2, dr + (3 + 3 * (size_t)d) * pts);
            empaqueter(p, x3, dr + (4 + 3 * (size_t)d) * pts);
        }
        free(Pr.L); free(Pr.pw); free(tr); free(cm); free(cote); free(tot);
    }
    hacher_h1(p, salt, pkh, mh, hs, h1c);
    hacher_h2(p, salt, pkh, mh, h1, diff, tau * lrep_d, h2c);
    uint8_t d = 0;
    for (uint32_t k = 0; k < hb; k++)
        d |= (uint8_t)(h1c[k] ^ h1[k]) | (uint8_t)(h2c[k] ^ h2[k]);
    free(hs); free(diff); free(r); free(eps);
    return d == 0;
}
