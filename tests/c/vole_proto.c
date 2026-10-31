/* Piste 9 : prototype de signature VOLE-in-the-Head sur SD régulier, à la SDitH v2.0 (PIOP de degré d, arbre GGM unique,
 * rejet d'ouverture, grinding). Sert à mesurer tailles et temps et à exécuter l'attaque de la borne : ce n'est PAS un
 * format de SILLAGE, ni un clone interopérable de SDitH, et son temps constant n'est pas vérifié. Paramètres : vole_params.c.
 *
 * Témoin : pour chaque bloc, d vecteurs élémentaires de tailles μ_t ; leur produit tensoriel donne le bloc de x. Polynômes
 * p_j(X) = w_j X + V_j, évalués par le vérifieur en Δ. Contraintes homogénéisées de degré d, mêlées par γ : leur terme en X^d
 * est nul si le témoin est valide. α = coefficients de degré < d de ce polynôme masqué.
 *     build/vole_proto   (depuis la racine) → resultats/vole_proto.json
 */
#include <math.h>
#include <omp.h>
#include <time.h>

#include "resultat.h"
#include "sillage.h"

#define WMAX 4
#define DMAX 6
typedef uint64_t u64;
typedef struct { const char *nom; int lam, n, cod, w, bloc, d, mu[DMAX], tau, kap, wpow, topen, B; } vp_t;

/* n, cod, w : vole_params (marges ISD de la SIG actuelle) ; τ, κ, T_open : SDitH v2.0, table 4 */
static const vp_t PR128 = {"VOLE-128", 128, 18620, 616, 76, 245, 4, {4, 4, 4, 4}, 11, 11, 9, 107, 16};
static const vp_t PR256 = {"VOLE-256", 256, 38456, 1224, 152, 253, 4, {4, 4, 4, 4}, 21, 12, 6, 216, 16};
/* modèle réduit de l'attaque : E de taille N^τ = 2^12, soit 2^10 essais attendus pour d = 4 */
static const vp_t PRTOY = {"VOLE-reduit", 128, 128, 64, 8, 16, 4, {2, 2, 2, 2}, 2, 6, 0, 1 << 12, 16};

typedef struct {
    const vp_t *p;
    int Bl, W, k, cB, sw, witb, witB, nb, pairs, m;
    size_t L, N;
} ctx_t;

static void ctx_init(ctx_t *c, const vp_t *p)
{
    c->p = p; c->Bl = p->lam / 8; c->W = p->lam / 64; c->k = p->n - p->cod; c->cB = p->cod / 8;
    c->sw = 0; c->pairs = 0;
    for (int t = 0; t < p->d; t++) {
        c->sw += p->mu[t] - 1;
        c->pairs += (p->mu[t] - 1) * (p->mu[t] - 2) / 2;
    }
    c->witb = p->w * c->sw; c->witB = (c->witb + 7) / 8;
    c->nb = c->witB + (p->d - 1) * c->Bl + (p->lam + p->B) / 8;
    c->m = p->cod + p->w * c->pairs;
    c->N = (size_t)1 << p->kap; c->L = (size_t)p->tau << p->kap;
}

/* ---------------------------------------------------------------- GF(2^λ) */
static inline void fmul(int W, const u64 *a, const u64 *b, u64 *o)
{
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
static void H(uint8_t dom, const void *a, size_t la, const void *b, size_t lb_, const void *c, size_t lc, void *o, size_t lo)
{
    sl_shake_t s;
    sl_shake_init(&s);
    sl_shake_absorb(&s, "SILLAGE-VOLE", 12);
    sl_shake_absorb(&s, &dom, 1);
    if (la) sl_shake_absorb(&s, a, la);
    if (lb_) sl_shake_absorb(&s, b, lb_);
    if (lc) sl_shake_absorb(&s, c, lc);
    sl_shake_final(&s);
    sl_shake_squeeze(&s, o, lo);
}

/* quatre entrées de même forme sel ‖ dom ‖ i ‖ graine (en un bloc de SHAKE) */
static void H4(const ctx_t *c, uint8_t dom, const uint8_t *salt, const uint32_t idx[4], const uint8_t *const g[4], uint8_t *const o[4], size_t lo)
{
    uint8_t m[4][4 + 1 + 4 + 2 * 64];
    const uint8_t *pm[4];
    size_t l = 0;
    for (int j = 0; j < 4; j++) {
        l = 0;
        memcpy(m[j], salt, (size_t)c->Bl); l += (size_t)c->Bl;
        m[j][l++] = dom;
        memcpy(m[j] + l, &idx[j], 4); l += 4;
        if (g[j]) { memcpy(m[j] + l, g[j], (size_t)c->Bl); } else { memset(m[j] + l, 0, (size_t)c->Bl); }
        l += (size_t)c->Bl;
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
        H4(c, 'H', seed, idx, g, o, cB);
    }
}

/* ---------------------------------------------------------------- clés */
typedef struct { uint8_t seed[32], y[256]; } vpk_t;

static void bits_temoin(const ctx_t *c, const uint16_t *pos, uint8_t *wit)
{
    const vp_t *p = c->p;
    memset(wit, 0, (size_t)c->witB);
    size_t o = 0;
    for (int i = 0; i < p->w; i++) {
        int r = pos[i], P = 1;
        for (int t = p->d - 1; t > 0; t--) P *= p->mu[t];
        for (int t = 0; t < p->d; t++) {
            int dg = r / P;
            r %= P;
            for (int v = 0; v < p->mu[t] - 1; v++, o++)
                wit[o >> 3] |= (uint8_t)((dg == v) << (o & 7));
            if (t + 1 < p->d) P /= p->mu[t + 1];
        }
    }
}

static void keygen(const ctx_t *c, vpk_t *pk, uint16_t *pos, uint8_t *cols)
{
    const vp_t *p = c->p;
    if (sl_alea(pk->seed, 32)) abort();
    developper_H(c, pk->seed, cols);
    memset(pk->y, 0, sizeof pk->y);
    for (int i = 0; i < p->w; i++) {
        uint32_t a;
        do { if (sl_alea(&a, 4)) abort(); a &= 0xFFFF; } while (a >= (uint32_t)(65536 - 65536 % p->bloc));
        pos[i] = (uint16_t)(a % (uint32_t)p->bloc);
        int q = i * p->bloc + pos[i];
        if (q < c->k) {
            for (int b = 0; b < c->cB; b++) pk->y[b] ^= cols[(size_t)q * (size_t)c->cB + (size_t)b];
        } else {
            pk->y[(q - c->k) >> 3] ^= (uint8_t)(1 << ((q - c->k) & 7));
        }
    }
}

/* ---------------------------------------------------------------- arbre GGM unique */
static void developper_arbre(const ctx_t *c, const uint8_t *salt, uint8_t *nd, uint8_t *connu)
{
    size_t Bl = (size_t)c->Bl, L = c->L;
    for (size_t lo = 1; lo < L; lo *= 2) {
        size_t hi = 2 * lo < L ? 2 * lo : L;
        size_t nb = (hi - lo + 3) / 4;
#pragma omp parallel for schedule(static)
        for (size_t q = 0; q < nb; q++) {
            uint32_t idx[4];
            const uint8_t *g[4];
            uint8_t tmp[4][128], *o[4];
            for (size_t j = 0; j < 4; j++) {
                size_t pa = lo + 4 * q + j;
                idx[j] = (uint32_t)pa;
                g[j] = pa < hi && connu[pa] ? nd + pa * Bl : NULL;
                o[j] = tmp[j];
            }
            H4(c, 'n', salt, idx, g, o, 2 * Bl);
            for (size_t j = 0; j < 4; j++) {
                size_t pa = lo + 4 * q + j;
                if (pa < hi && connu[pa])
                    for (size_t f = 0; f < 2; f++) {
                        memcpy(nd + (2 * pa + f) * Bl, tmp[j] + f * Bl, Bl);
                        connu[2 * pa + f] = 1;
                    }
            }
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

/* défi final : τ indices de κ bits et wpow bits nuls ; -1 si refusé */
static int defi(const ctx_t *c, const uint8_t *h3, uint32_t ctr, uint32_t *ch, uint8_t *cache)
{
    const vp_t *p = c->p;
    uint8_t o[64] = {0};
    size_t tb = (size_t)p->tau * (size_t)p->kap;
    H('d', h3, 2 * (size_t)c->Bl, &ctr, 4, NULL, 0, o, (tb + (size_t)p->wpow + 7) / 8);
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

/* ---------------------------------------------------------------- une répétition : com, q_b = Σ ((i ⊕ i*)_b)·r_i, Σ r_i */
static void repetition(const ctx_t *c, const uint8_t *salt, int e, const uint8_t *nd, const uint8_t *connu,
                       uint8_t *coms, uint8_t *qv, uint8_t *u, uint32_t cache)
{
    size_t N = c->N, nb = (size_t)c->nb, Bl = (size_t)c->Bl, L = c->L;
    uint8_t *S = malloc(N * nb);
    uint8_t (*tmp)[64] = malloc(4 * 64);
#pragma omp parallel for schedule(static)
    for (size_t q = 0; q < (N + 3) / 4; q++) {
        uint32_t idx[4];
        const uint8_t *g[4];
        uint8_t *o[4], buf[4][512 + 128];
        for (size_t j = 0; j < 4; j++) {
            size_t i = 4 * q + j, x = L + i * (size_t)c->p->tau + (size_t)e;  /* entrelacé : les chemins cachés fusionnent */
            idx[j] = (uint32_t)x;
            g[j] = i < N && connu[x] ? nd + x * Bl : NULL;
            o[j] = buf[j];
        }
        H4(c, 'l', salt, idx, g, o, 2 * Bl + nb);
        for (size_t j = 0; j < 4 && 4 * q + j < N; j++) {
            size_t i = 4 * q + j, x = L + i * (size_t)c->p->tau + (size_t)e;
            if (!connu[x]) {                                    /* la feuille cachée : r = 0, com donné par la signature */
                memset(S + (i ^ cache) * nb, 0, nb);
                continue;
            }
            memcpy(coms + i * 2 * Bl, buf[j], 2 * Bl);
            memcpy(S + (i ^ cache) * nb, buf[j] + 2 * Bl, nb);
        }
    }
    for (int b = 0; b < c->p->kap; b++) {
        uint8_t *qb = qv + (size_t)b * nb;
        memset(qb, 0, nb);
        size_t m = N >> b;
        for (size_t j = 0; j < m / 2; j++) {
            uint8_t *s0 = S + 2 * j * nb, *s1 = S + (2 * j + 1) * nb, *d = S + j * nb;
            for (size_t z = 0; z < nb; z++) {
                uint8_t x = s0[z], y = s1[z];
                qb[z] ^= y;
                d[z] = x ^ y;
            }
        }
    }
    if (u) memcpy(u, S, nb);
    free(S); free(tmp);
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
    uint8_t *rows = malloc(rb * rB);
    H('M', h1, 2 * (size_t)c->Bl, NULL, 0, NULL, 0, rows, rb * rB);
    return rows;
}

/* γ, puis g = γᵀ·H sur les n colonnes, et γ·y */
static void melanges(const ctx_t *c, const uint8_t *h2, const uint8_t *cols, const uint8_t *y, u64 *gam, u64 *g, u64 *gy)
{
    int W = c->W;
    size_t cB = (size_t)c->cB;
    H('g', h2, 2 * (size_t)c->Bl, NULL, 0, NULL, 0, gam, (size_t)c->m * (size_t)c->Bl);
    u64 *T = calloc(cB * 256 * (size_t)W, 8);
    for (size_t B = 0; B < cB; B++)
        for (int v = 1; v < 256; v++) {
            int bas = __builtin_ctz((unsigned)v);
            u64 *d = T + (B * 256 + (size_t)v) * (size_t)W;
            memcpy(d, T + (B * 256 + (size_t)(v & (v - 1))) * (size_t)W, (size_t)W * 8);
            fxor(W, d, gam + (B * 8 + (size_t)bas) * (size_t)W);
        }
#pragma omp parallel for schedule(static)
    for (int j = 0; j < c->k; j++) {
        u64 *d = g + (size_t)j * (size_t)W;
        memset(d, 0, (size_t)W * 8);
        for (size_t B = 0; B < cB; B++)
            fxor(W, d, T + (B * 256 + cols[(size_t)j * cB + B]) * (size_t)W);
    }
    for (int r = 0; r < c->p->cod; r++)
        memcpy(g + (size_t)(c->k + r) * (size_t)W, gam + (size_t)r * (size_t)W, (size_t)W * 8);
    memset(gy, 0, (size_t)W * 8);
    for (size_t B = 0; B < cB; B++)
        fxor(W, gy, T + (B * 256 + y[B]) * (size_t)W);
    free(T);
}

/* produit des contraintes, côté signataire : coefficients C_0..C_d de Σ γ_j F_j(X) */
static void contraintes_poly(const ctx_t *c, const uint8_t *wit, const u64 *V, const u64 *gam, const u64 *g, const u64 *gy, u64 *C)
{
    const vp_t *p = c->p;
    int W = c->W, d = p->d;
    size_t zero = (size_t)W * 8 * (size_t)(d + 1);
    memset(C, 0, zero);
    size_t Pw = 1;
    for (int t = 0; t < d; t++) Pw *= (size_t)p->mu[t];
#pragma omp parallel
    {
        u64 *acc = calloc((size_t)(d + 1) * (size_t)W, 8);
        u64 *A = malloc(Pw * (size_t)(d + 1) * (size_t)W * 8), *Bb = malloc(Pw * (size_t)(d + 1) * (size_t)W * 8);
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
                        fmul(W, Vd[v], Vd[x], pr[0]);
                        for (int z = 0; z < W; z++)
                            pr[1][z] = (Vd[v][z] & (0 - bd[x])) ^ (Vd[x][z] & (0 - bd[v]));
                        memset(pr[2], 0, (size_t)W * 8);
                        pr[2][0] = bd[v] & bd[x];
                        for (int l = 0; l < 3; l++) {
                            fmul(W, pr[l], gam + pz * (size_t)W, tmp);
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
                            fmul(W, src + (size_t)l * (size_t)W, Vd[v], tmp);
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
                    fmul(W, xq + (size_t)l * (size_t)W, gi, tmp);
                    fxor(W, acc + (size_t)l * (size_t)W, tmp);
                }
            }
        }
#pragma omp critical
        for (size_t z = 0; z < (size_t)(d + 1) * (size_t)W; z++) C[z] ^= acc[z];
        free(acc); free(A); free(Bb);
    }
    fxor(W, C + (size_t)d * (size_t)W, gy);                          /* − (γ·y) X^d */
}

/* même somme, côté vérifieur : valeur en Δ, q = polynômes du témoin déjà évalués */
static void contraintes_val(const ctx_t *c, const u64 *q, const u64 *Dl, const u64 *pwD, const u64 *gam, const u64 *g, const u64 *gy, u64 *val)
{
    const vp_t *p = c->p;
    int W = c->W, d = p->d;
    (void)Dl;
    u64 r[WMAX] = {0};
    size_t Pw = 1;
    for (int t = 0; t < d; t++) Pw *= (size_t)p->mu[t];
#pragma omp parallel
    {
        u64 acc[WMAX] = {0}, tmp[WMAX];
        u64 *A = malloc(Pw * (size_t)W * 8), *Bb = malloc(Pw * (size_t)W * 8);
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
                        fmul(W, qd[v], qd[x], z1);
                        fmul(W, z1, pwD + (size_t)(d - 2) * (size_t)W, z2);
                        fmul(W, z2, gam + pz * (size_t)W, tmp);
                        fxor(W, acc, tmp);
                        pz++;
                    }
                size_t nv = taille * (size_t)mu;
                for (size_t a = 0; a < taille; a++)
                    for (int v = 0; v < mu; v++)
                        fmul(W, A + a * (size_t)W, qd[v], Bb + (a * (size_t)mu + (size_t)v) * (size_t)W);
                u64 *sw = A; A = Bb; Bb = sw;
                taille = nv;
                o += (size_t)mu - 1;
            }
            size_t decal = (size_t)i * (size_t)p->bloc;
            for (int q2 = 0; q2 < p->bloc; q2++) {
                fmul(W, A + (size_t)q2 * (size_t)W, g + (decal + (size_t)q2) * (size_t)W, tmp);
                fxor(W, acc, tmp);
            }
        }
#pragma omp critical
        fxor(W, r, acc);
        free(A); free(Bb);
    }
    u64 tmp[WMAX];
    fmul(W, gy, pwD + (size_t)d * (size_t)W, tmp);
    fxor(W, r, tmp);
    memcpy(val, r, (size_t)W * 8);
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
        fmul(W, xi, V + (o + (size_t)l) * (size_t)W, t);
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
    return 3 * Bl + (size_t)(p->tau - 1) * (size_t)c->nb + ub + (size_t)c->witB + (size_t)p->d * Bl + (size_t)p->topen * Bl + (size_t)p->tau * 2 * Bl + 4;
}

/* transcription des coms + aux → h_com */
static void hacher_coms(const ctx_t *c, const uint8_t *salt, const uint8_t *hm, const uint8_t *coms, const uint8_t *aux, uint8_t *h)
{
    size_t Bl = (size_t)c->Bl, hb = 2 * Bl, rep = c->N * 2 * Bl;
    int tau = c->p->tau;
    uint8_t *hs = malloc((size_t)tau * hb);
#pragma omp parallel for schedule(static)
    for (int e = 0; e < tau; e++)
        H('c', salt, Bl, &e, 4, coms + (size_t)e * rep, rep, hs + (size_t)e * hb, hb);
    uint8_t t[128];
    H('C', salt, Bl, hm, hb, hs, (size_t)tau * hb, t, hb);
    H('A', t, hb, aux, (size_t)(tau - 1) * (size_t)c->nb, NULL, 0, h, hb);
    free(hs);
}

/* attaque : si racines ≠ NULL, α est choisi pour annuler le résidu aux d points donnés (sans témoin), et le signataire cherche Δ parmi eux */
static long signer(const ctx_t *c, const vpk_t *pk, const uint8_t *cols, const uint16_t *pos, const uint8_t *msg, size_t lmsg, uint8_t *sig, int attaque)
{
    const vp_t *p = c->p;
    size_t Bl = (size_t)c->Bl, hb = 2 * Bl, nb = (size_t)c->nb, L = c->L, W = (size_t)c->W, ub = (size_t)(p->lam + p->B) / 8;
    int tau = p->tau, kap = p->kap, d = p->d;
    uint8_t *nd = calloc(2 * L, Bl), *connu = calloc(2 * L, 1), *cache = malloc(2 * L);
    uint8_t *coms = malloc((size_t)tau * c->N * hb), *qv = malloc((size_t)tau * (size_t)kap * nb), *us = malloc((size_t)tau * nb);
    uint8_t *aux = malloc((size_t)tau * nb), *wit = calloc(nb, 1), *uu = calloc(nb, 1), salt[64], hm[128], h1[128], h2[128], h3[128];
    uint8_t *ht = malloc(((size_t)tau * (size_t)kap) * ub), hv[128], *dw = malloc((size_t)c->witB), *ut = calloc(ub, 1);
    u64 *V = malloc(8 * nb * W * 8), *gam = malloc((size_t)c->m * W * 8), *g = malloc((size_t)p->n * W * 8), gy[WMAX], *C = malloc((size_t)(d + 1) * W * 8);
    if (sl_alea(salt, Bl)) abort();
    H('m', pk, sizeof *pk, msg, lmsg, NULL, 0, hm, hb);
    bits_temoin(c, pos, wit);
    H('r', pos, (size_t)p->w * 2, salt, Bl, hm, hb, nd + Bl, Bl);
    connu[1] = 1;
    developper_arbre(c, salt, nd, connu);
    for (int e = 0; e < tau; e++)
        repetition(c, salt, e, nd, connu, coms + (size_t)e * c->N * hb, qv + (size_t)e * (size_t)kap * nb, us + (size_t)e * nb, 0);
    for (int e = 1; e < tau; e++)
        for (size_t z = 0; z < nb; z++)
            aux[(size_t)(e - 1) * nb + z] = us[z] ^ us[(size_t)e * nb + z];
    hacher_coms(c, salt, hm, coms, aux, h1);
    uint8_t *rows = lignes_M(c, h1);
    hash_M(c, rows, us, ut);
    for (int x = 0; x < tau * kap; x++)
        hash_M(c, rows, qv + (size_t)x * nb, ht + (size_t)x * ub);
    H('v', h1, hb, ht, (size_t)tau * (size_t)kap * ub, NULL, 0, hv, hb);
    for (int z = 0; z < c->witB; z++) dw[z] = wit[z] ^ us[z];
    if (c->witb & 7) dw[c->witB - 1] &= (uint8_t)((1u << (c->witb & 7)) - 1);
    H('2', hv, hb, ut, ub, dw, (size_t)c->witB, h2, hb);
    melanges(c, h2, cols, pk->y, gam, g, gy);
    transposer(c, qv, V);
    contraintes_poly(c, wit, V, gam, g, gy, C);
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
    if (attaque) {                                                    /* R(X) = c_d Π (X + ρ_t), retiré de α */
        u64 R[DMAX + 1][WMAX] = {{0}};
        memcpy(R[0], C + (size_t)d * W, W * 8);
        for (int t = 0; t < d; t++) {
            uint32_t v;
            if (sl_alea(&v, 4)) abort();
            memset(racines[t], 0, W * 8);
            /* ρ_t ∈ E : τκ bits aléatoires */
            for (int b = 0; b < tau * kap; b++) {
                if (b % 32 == 0 && sl_alea(&v, 4)) abort();
                racines[t][b / 64] |= (u64)((v >> (b % 32)) & 1) << (b % 64);
            }
            for (int l = t + 1; l >= 0; l--) {
                u64 x[WMAX];
                fmul((int)W, R[l], racines[t], x);
                if (l) { for (size_t z = 0; z < W; z++) R[l][z] = x[z] ^ R[l - 1][z]; } else memcpy(R[0], x, W * 8);
            }
        }
        for (int l = 0; l < d; l++) fxor((int)W, alpha[l], R[l]);
    }
    uint8_t ab[DMAX * 32];
    for (int l = 0; l < d; l++) memcpy(ab + (size_t)l * Bl, alpha[l], Bl);
    H('3', h2, hb, ab, (size_t)d * Bl, NULL, 0, h3, hb);
    uint32_t ctr = 0, ch[64];
    long essais = 0;
    for (;; ctr++) {
        essais++;
        if (defi(c, h3, ctr, ch, cache) < 0)
            continue;
        if (!attaque)
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
    memcpy(o, salt, Bl); o += Bl;
    memcpy(o, h3, hb); o += hb;
    memcpy(o, aux, (size_t)(tau - 1) * nb); o += (size_t)(tau - 1) * nb;
    memcpy(o, ut, ub); o += ub;
    memcpy(o, dw, (size_t)c->witB); o += c->witB;
    memcpy(o, ab, (size_t)d * Bl); o += (size_t)d * Bl;
    uint8_t *on = o;
    memset(on, 0, (size_t)p->topen * Bl);
    for (size_t x = 2; x < 2 * L; x++)
        if (!cache[x] && cache[x / 2]) {
            memcpy(on, nd + x * Bl, Bl);
            on += Bl;
        }
    o += (size_t)p->topen * Bl;
    for (int e = 0; e < tau; e++) {
        memcpy(o, coms + ((size_t)e * c->N + ch[e]) * hb, hb);
        o += hb;
    }
    memcpy(o, &ctr, 4);
    free(nd); free(connu); free(cache); free(coms); free(qv); free(us); free(aux); free(wit); free(uu); free(ht); free(dw); free(ut); free(V); free(gam); free(g); free(C); free(rows);
    return essais;
}

static int verifier(const ctx_t *c, const vpk_t *pk, const uint8_t *cols, const uint8_t *msg, size_t lmsg, const uint8_t *sig)
{
    const vp_t *p = c->p;
    size_t Bl = (size_t)c->Bl, hb = 2 * Bl, nb = (size_t)c->nb, L = c->L, W = (size_t)c->W, ub = (size_t)(p->lam + p->B) / 8;
    int tau = p->tau, kap = p->kap, d = p->d, ok = 0;
    const uint8_t *salt = sig, *h3 = salt + Bl, *aux = h3 + hb, *ut = aux + (size_t)(tau - 1) * nb, *dw = ut + ub;
    const uint8_t *ab = dw + c->witB, *nds = ab + (size_t)d * Bl, *chs = nds + (size_t)p->topen * Bl, *pct = chs + (size_t)tau * hb;
    uint32_t ctr, ch[64];
    memcpy(&ctr, pct, 4);
    uint8_t *nd = calloc(2 * L, Bl), *connu = calloc(2 * L, 1), *cache = malloc(2 * L);
    uint8_t *coms = malloc((size_t)tau * c->N * hb), *qv = malloc((size_t)tau * (size_t)kap * nb), hm[128], h1[128], h2[128], h3c[128], hv[128];
    uint8_t *ht = malloc((size_t)tau * (size_t)kap * ub);
    u64 *q = malloc(8 * nb * W * 8), *gam = malloc((size_t)c->m * W * 8), *g = malloc((size_t)p->n * W * 8), gy[WMAX];
    uint8_t *rows = NULL;
    if (defi(c, h3, ctr, ch, cache) < 0)
        goto fin;
    if ((c->witb & 7) && (dw[c->witB - 1] >> (c->witb & 7)))
        goto fin;
    H('m', pk, sizeof *pk, msg, lmsg, NULL, 0, hm, hb);
    {   /* nœuds révélés, remplissage nul exigé (encodage unique) */
        const uint8_t *on = nds;
        for (size_t x = 2; x < 2 * L; x++)
            if (!cache[x] && cache[x / 2]) {
                memcpy(nd + x * Bl, on, Bl);
                connu[x] = 1;
                on += Bl;
            }
        for (const uint8_t *z = on; z < chs; z++)
            if (*z)
                goto fin;
    }
    developper_arbre(c, salt, nd, connu);
    for (int e = 0; e < tau; e++) {
        repetition(c, salt, e, nd, connu, coms + (size_t)e * c->N * hb, qv + (size_t)e * (size_t)kap * nb, NULL, ch[e]);
        memcpy(coms + ((size_t)e * c->N + ch[e]) * hb, chs + (size_t)e * hb, hb);
        if (e)
            for (int b = 0; b < kap; b++)
                if ((ch[e] >> b) & 1)
                    for (size_t z = 0; z < nb; z++)
                        qv[((size_t)e * (size_t)kap + (size_t)b) * nb + z] ^= aux[(size_t)(e - 1) * nb + z];
    }
    hacher_coms(c, salt, hm, coms, aux, h1);
    rows = lignes_M(c, h1);
    for (int e = 0; e < tau; e++)
        for (int b = 0; b < kap; b++) {
            size_t x = (size_t)e * (size_t)kap + (size_t)b;
            hash_M(c, rows, qv + x * nb, ht + x * ub);
            if ((ch[e] >> b) & 1)
                for (size_t z = 0; z < ub; z++)
                    ht[x * ub + z] ^= ut[z];
        }
    H('v', h1, hb, ht, (size_t)tau * (size_t)kap * ub, NULL, 0, hv, hb);
    H('2', hv, hb, ut, ub, dw, (size_t)c->witB, h2, hb);
    H('3', h2, hb, ab, (size_t)d * Bl, NULL, 0, h3c, hb);
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
        for (int l = 1; l <= d; l++) fmul((int)W, pw[l - 1], D, pw[l]);
        melanges(c, h2, cols, pk->y, gam, g, gy);
        transposer(c, qv, q);
#pragma omp parallel for schedule(static)
        for (int j = 0; j < c->witb; j++)
            if (bit(dw, (size_t)j))
                fxor((int)W, q + (size_t)j * W, D);
        u64 g_d[WMAX], s[WMAX];
        u64 pwf[(DMAX + 1) * WMAX];                                   /* contraintes_val lit au pas de W */
        for (int l = 0; l <= d; l++) memcpy(pwf + (size_t)l * W, pw[l], W * 8);
        contraintes_val(c, q, D, pwf, gam, g, gy, g_d);
        /* M(Δ) + Σ γ F(Δ) = Σ α_l Δ^l */
        memcpy(s, g_d, W * 8);
        size_t om = 8 * (size_t)c->witB;
        for (int t = 1; t < d; t++) {
            u64 m[WMAX], x[WMAX];
            sect_V(c, q, om + (size_t)(t - 1) * (size_t)p->lam, m);
            fmul((int)W, m, pw[t - 1], x);
            fxor((int)W, s, x);
        }
        for (int l = 0; l < d; l++) {
            u64 a[WMAX] = {0}, x[WMAX];
            memcpy(a, ab + (size_t)l * Bl, Bl);
            fmul((int)W, a, pw[l], x);
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

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + 1e-9 * (double)t.tv_nsec;
}

int main(void)
{
    resultat_t r = {.nom = "vole_proto"};
    static char json[8000];
    size_t lj = (size_t)snprintf(json, sizeof json, "[");
    const vp_t *PS[2] = {&PR128, &PR256};
    static const long ACT[2] = {8522, 34867};
    int nth = omp_get_max_threads();
    for (int q = 0; q < 2; q++) {
        ctx_t c;
        ctx_init(&c, PS[q]);
        const vp_t *p = c.p;
        char nom[80];
        uint8_t *cols = malloc((size_t)c.k * (size_t)c.cB);
        uint16_t pos[256];
        vpk_t pk;
        keygen(&c, &pk, pos, cols);
        size_t zs = taille_sig(&c);
        uint8_t *sig = malloc(zs), *mod = malloc(zs);
        const uint8_t msg[] = "message de test";
        long essais = 0;
        omp_set_num_threads(1);
        double t0 = maintenant();
        int nb = 30;                                                   /* le grinding rend le temps de signature variable */
        for (int i = 0; i < nb; i++) essais += signer(&c, &pk, cols, pos, msg, sizeof msg, sig, 0);
        double ts1 = (maintenant() - t0) / nb;
        t0 = maintenant();
        int ok = verifier(&c, &pk, cols, msg, sizeof msg, sig);
        double tv1 = maintenant() - t0;
        uint8_t *cols2 = malloc((size_t)c.k * (size_t)c.cB);           /* H développée à chaque appel : à ajouter si la pk n'est pas en cache */
        t0 = maintenant();
        developper_H(&c, pk.seed, cols2);
        double th1 = maintenant() - t0;
        free(cols2);
        omp_set_num_threads(nth);
        t0 = maintenant();
        for (int i = 0; i < nb; i++) signer(&c, &pk, cols, pos, msg, sizeof msg, sig, 0);
        double tsn = (maintenant() - t0) / nb;
        t0 = maintenant();
        ok &= verifier(&c, &pk, cols, msg, sizeof msg, sig);
        double tvn = maintenant() - t0;
        printf("%s : %zu o (actuelle %ld, %+.0f %%), pk %d o, signe %.1f ms / %.1f ms (%d threads), vérifie %.1f / %.1f ms, H %.1f ms (un cœur), %.0f essais de défi\n", p->nom, zs, ACT[q], 100.0 * ((double)zs - (double)ACT[q]) / (double)ACT[q],
               c.Bl + c.cB, 1e3 * ts1, 1e3 * tsn, nth, 1e3 * tv1, 1e3 * tvn, 1e3 * th1, (double)essais / nb);
        fflush(stdout);
        snprintf(nom, sizeof nom, "%s_signature_valide_acceptee", p->nom);
        res_controle(&r, nom, ok);
        /* altérations : un bit par section, et sur des positions tirées au hasard */
        size_t Bl = (size_t)c.Bl, ub = (size_t)(p->lam + p->B) / 8;
        size_t sec[8] = {0, Bl, 3 * Bl, 3 * Bl + (size_t)(p->tau - 1) * (size_t)c.nb, 3 * Bl + (size_t)(p->tau - 1) * (size_t)c.nb + ub, 0, 0, zs - 4};
        sec[5] = sec[4] + (size_t)c.witB;
        sec[6] = sec[5] + (size_t)p->d * Bl;
        int rejets = 0, total = 0;
        for (int s = 0; s < 8; s++) {
            memcpy(mod, sig, zs);
            mod[sec[s]] ^= 1;
            total++;
            rejets += !verifier(&c, &pk, cols, msg, sizeof msg, mod);
        }
        for (int i = 0; i < 24; i++) {
            uint32_t a;
            if (sl_alea(&a, 4)) abort();
            memcpy(mod, sig, zs);
            mod[a % zs] ^= (uint8_t)(1 << (a >> 29));
            total++;
            rejets += !verifier(&c, &pk, cols, msg, sizeof msg, mod);
        }
        snprintf(nom, sizeof nom, "%s_alterations_rejetees", p->nom);
        res_controle(&r, nom, rejets == total);
        const uint8_t autre[] = "autre message!!";
        snprintf(nom, sizeof nom, "%s_autre_message_rejete", p->nom);
        res_controle(&r, nom, !verifier(&c, &pk, cols, autre, sizeof autre, sig));
        vpk_t pk2 = pk;
        pk2.y[0] ^= 1;
        snprintf(nom, sizeof nom, "%s_autre_cle_rejetee", p->nom);
        res_controle(&r, nom, !verifier(&c, &pk2, cols, msg, sizeof msg, sig));
        snprintf(nom, sizeof nom, "%s_plus_petite_de_moitie", p->nom);
        res_controle(&r, nom, 2 * (long)zs < ACT[q]);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"profil\":\"%s\",\"signature\":%zu,\"actuelle\":%ld,\"pk\":%d,\"signe_ms_1\":%.1f,\"signe_ms_n\":%.1f,\"verifie_ms_1\":%.1f,\"verifie_ms_n\":%.1f,\"H_ms_1\":%.1f,\"threads\":%d}",
                               q ? "," : "", p->nom, zs, ACT[q], c.Bl + c.cB, 1e3 * ts1, 1e3 * tsn, 1e3 * tv1, 1e3 * tvn, 1e3 * th1, nth);
        free(cols); free(sig); free(mod);
    }
    /* modèle réduit : sans témoin, α annule le résidu en d points de E, puis recherche de Δ parmi eux */
    {
        ctx_t c;
        ctx_init(&c, &PRTOY);
        uint8_t *cols = malloc((size_t)c.k * (size_t)c.cB);
        uint16_t pos[8], faux[8];
        vpk_t pk;
        keygen(&c, &pk, pos, cols);
        size_t zs = taille_sig(&c);
        uint8_t *sig = malloc(zs);
        const uint8_t msg[] = "cible";
        int ok = 1;
        signer(&c, &pk, cols, pos, msg, sizeof msg, sig, 0);
        ok &= verifier(&c, &pk, cols, msg, sizeof msg, sig);
        res_controle(&r, "reduit_signature_honnete_acceptee", ok);
        memset(faux, 0, sizeof faux);
        faux[0] = pos[0] ^ 1;                                          /* faux témoin */
        for (int i = 1; i < 8; i++) faux[i] = pos[i];
        signer(&c, &pk, cols, faux, msg, sizeof msg, sig, 0);
        res_controle(&r, "reduit_faux_temoin_rejete", !verifier(&c, &pk, cols, msg, sizeof msg, sig));
        int nt = 60, acc = 0;
        double som = 0;
        for (int i = 0; i < nt; i++) {
            som += (double)signer(&c, &pk, cols, faux, msg, sizeof msg, sig, 1);
            acc += verifier(&c, &pk, cols, msg, sizeof msg, sig);
        }
        double att = (double)(1 << (PRTOY.tau * PRTOY.kap)) / PRTOY.d, moy = som / nt;
        printf("attaque sur modèle réduit : %d/%d acceptées, %.0f essais en moyenne (borne N^τ/d = %.0f)\n", acc, nt, moy, att);
        res_controle(&r, "reduit_attaque_acceptee_par_le_verifieur", acc == nt);
        /* moyenne de 60 lois géométriques : écart relatif ≈ 13 % ; d racines tirées au hasard, rarement confondues */
        res_controle(&r, "reduit_cout_attaque_conforme_a_la_borne", moy > 0.6 * att && moy < 1.6 * att);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, ",{\"attaque_reduite\":{\"acceptees\":%d,\"essais\":%d,\"moyenne\":%.0f,\"borne\":%.0f}}", acc, nt, moy, att);
        free(cols); free(sig);
    }
    snprintf(json + lj, sizeof json - lj, "]");
    res_mesure(&r, "resultats", "%s", json);
    return res_ecrire(&r);
}
