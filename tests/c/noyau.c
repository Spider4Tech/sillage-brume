/* Noyau C des tests intensifs SILLAGE (chargé par tests/noyau_c.py).
 *
 * Aucune table n'est définie ici : bn_init() reçoit les tables calculées par
 * sillage/brume512.py (source unique) ; tests/noyau_c.py vérifie la
 * conformité bit à bit avec l'implémentation Python avant tout usage.
 *
 * Convention : un état = 128 nibbles (uint8 & 0xF) ; le bit b est le bit
 * (b % 4) du nibble b / 4. sens = 0 : tours 0..R-1 de P ; sens = 1 : les R
 * derniers tours de P^-1 (tours NR-1 .. NR-R), pour les distingueurs
 * « inside-out ». Toutes les fonctions lourdes sont parallèles (OpenMP) et
 * reproductibles quel que soit le nombre de threads (graine par paquet).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

#define N 128
#define NE 896
#define DEG 7
#define RMAX 32
#define PAQUET 4096

static uint64_t LIN[N][16][8];       /* M · (y en position j), empaqueté (128 Kio) */
static uint8_t SB[16];
static uint64_t TINV[N][16][8];      /* M^-1 · (x en position j), 512 bits empaquetés */
static uint8_t SINV[16];
static uint8_t RC[RMAX][N];
static int NR;

int bn_init(int nr, int ne, const uint8_t *t, const int32_t *ei, const int32_t *seg,
            const uint8_t *minv, const uint8_t *sinv, const uint8_t *rc, const uint8_t *gm)
{
    if (nr > RMAX || ne != NE)
        return -1;
    NR = nr;
    /* t[r][e][x] = c_e · S(x ⊕ RC[r][E_I[e]]) ; l'arête e va de E_I[e] au
     * sommet e / DEG (graphe 7-régulier : degré 6 + boucle) */
    for (int v = 0; v <= N; v++)
        if (seg[v] != DEG * v)
            return -2;
    for (int x = 0; x < 16; x++)
        SB[sinv[x]] = (uint8_t)x;
    /* c_e · y = t[0][e][S^-1(y) ⊕ RC[0][j]] : on retire S et RC de la table
     * fusionnée pour ne garder que M (indépendante du tour, tient en L2) */
    memset(LIN, 0, sizeof LIN);
    for (int e = 0; e < NE; e++)
        for (int y = 0; y < 16; y++) {
            int v = e / DEG, j = ei[e];
            uint64_t g = t[(size_t)e * 16 + (sinv[y] ^ rc[j])];
            LIN[j][y][v >> 4] ^= g << (4 * (v & 15));
        }
    memcpy(SINV, sinv, 16);
    memcpy(RC, rc, (size_t)nr * N);
    memset(TINV, 0, sizeof TINV);
    for (int j = 0; j < N; j++)
        for (int x = 0; x < 16; x++)
            for (int i = 0; i < N; i++) {
                uint64_t g = gm[minv[i * N + j] * 16 + x];
                TINV[j][x][i >> 4] |= g << (4 * (i & 15));
            }
    return 0;
}

/* ------------------------------------------------------------ permutation */
/* Les deux sens utilisent des tables « 512 bits par nibble d'entrée » :
 * 128 XOR de 8 mots par tour, puis dépaquetage. */
static inline void deballer(const uint64_t *acc, uint8_t *s)
{
    for (int i = 0; i < N; i++)
        s[i] = (acc[i >> 4] >> (4 * (i & 15))) & 15;
}

static inline void tour(uint8_t *s, int r)
{
    uint64_t acc[8] = {0};
    for (int j = 0; j < N; j++) {
        const uint64_t *u = LIN[j][SB[s[j] ^ RC[r][j]]];
        for (int w = 0; w < 8; w++)
            acc[w] ^= u[w];
    }
    deballer(acc, s);
}

static inline void tour_inv(uint8_t *s, int r)
{
    uint64_t acc[8] = {0};
    for (int j = 0; j < N; j++) {
        const uint64_t *u = TINV[j][s[j]];
        for (int w = 0; w < 8; w++)
            acc[w] ^= u[w];
    }
    for (int i = 0; i < N; i++)
        s[i] = SINV[(acc[i >> 4] >> (4 * (i & 15))) & 15] ^ RC[r][i];
}

/* M^-1 seule (sans S-box ni constante) : ramène une sortie de P juste
 * après la couche de S-box du dernier tour. */
static inline void lin_inv(const uint8_t *s, uint8_t *o)
{
    uint64_t acc[8] = {0};
    for (int j = 0; j < N; j++) {
        const uint64_t *u = TINV[j][s[j]];
        for (int w = 0; w < 8; w++)
            acc[w] ^= u[w];
    }
    deballer(acc, o);
}

static inline void perm(uint8_t *s, int R, int sens)
{
    if (sens == 0)
        for (int r = 0; r < R; r++)
            tour(s, r);
    else
        for (int k = 0; k < R; k++)
            tour_inv(s, NR - 1 - k);
}

void bn_permute(uint8_t *st, int64_t n, int R, int sens)
{
#pragma omp parallel for schedule(static)
    for (int64_t i = 0; i < n; i++)
        perm(st + i * N, R, sens);
}

/* -------------------------------------------------------------- aléa */
typedef struct { uint64_t s[4]; } rng_t;

static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

static inline uint64_t splitmix(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static inline void rng_init(rng_t *r, uint64_t graine, uint64_t idx)
{
    uint64_t x = graine ^ (idx * 0xd1342543de82ef95ULL + 0x632be59bd9b4e019ULL);
    for (int i = 0; i < 4; i++)
        r->s[i] = splitmix(&x);
}

static inline uint64_t rng_next(rng_t *r)    /* xoshiro256** */
{
    uint64_t *s = r->s, res = rotl(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t; s[3] = rotl(s[3], 45);
    return res;
}

static inline uint64_t rng_borne(rng_t *r, uint64_t n)
{
    return (uint64_t)(((__uint128_t)rng_next(r) * n) >> 64);
}

static inline void etat_alea(rng_t *r, uint8_t *s)
{
    for (int i = 0; i < N; i += 16) {
        uint64_t z = rng_next(r);
        for (int j = 0; j < 16; j++)
            s[i + j] = (z >> (4 * j)) & 15;
    }
}

#define POUR_PAQUETS(n)                                                        \
    int64_t npaq_ = ((n) + PAQUET - 1) / PAQUET;                               \
    _Pragma("omp for schedule(dynamic)")                                       \
    for (int64_t p_ = 0; p_ < npaq_; p_++)

/* ------------------------------------------------------- cubes (intégrales) */
/* out = XOR de P(base ⊕ m) sur les 2^k valeurs des bits listés. */
void bn_cube(const uint8_t *base, const int32_t *bits, int k, int R, int sens, uint8_t *out)
{
    memset(out, 0, N);
    uint64_t total = 1ULL << k;
#pragma omp parallel
    {
        uint8_t acc[N] = {0}, s[N];
        POUR_PAQUETS((int64_t)total) {
            uint64_t fin = (uint64_t)(p_ + 1) * PAQUET < total ? (uint64_t)(p_ + 1) * PAQUET : total;
            for (uint64_t m = (uint64_t)p_ * PAQUET; m < fin; m++) {
                memcpy(s, base, N);
                for (int j = 0; j < k; j++)
                    if (m >> j & 1)
                        s[bits[j] >> 2] ^= (uint8_t)(1 << (bits[j] & 3));
                perm(s, R, sens);
                for (int i = 0; i < N; i++)
                    acc[i] ^= s[i];
            }
        }
#pragma omp critical
        for (int i = 0; i < N; i++)
            out[i] ^= acc[i];
    }
}

/* Cube sur un sous-espace affine : out = XOR de P(base ⊕ Σ_{j ∈ m} vec_j) sur
 * les 2^k combinaisons des k vecteurs (128 nibbles chacun), parcourues en
 * code de Gray (un XOR de vecteur par évaluation). */
void bn_cube_vec(const uint8_t *base, const uint8_t *vec, int k, int R, int sens, uint8_t *out)
{
    memset(out, 0, N);
    uint64_t total = 1ULL << k;
#pragma omp parallel
    {
        uint8_t acc[N] = {0}, x[N], s[N];
        POUR_PAQUETS((int64_t)total) {
            uint64_t deb = (uint64_t)p_ * PAQUET;
            uint64_t fin = deb + PAQUET < total ? deb + PAQUET : total;
            uint64_t g = deb ^ (deb >> 1);
            memcpy(x, base, N);
            for (int j = 0; j < k; j++)
                if (g >> j & 1)
                    for (int v = 0; v < N; v++)
                        x[v] ^= vec[j * N + v];
            for (uint64_t m = deb; m < fin; m++) {
                if (m > deb) {                  /* Gray : bit qui change = ctz(m) */
                    const uint8_t *u = vec + (size_t)__builtin_ctzll(m) * N;
                    for (int v = 0; v < N; v++)
                        x[v] ^= u[v];
                }
                memcpy(s, x, N);
                perm(s, R, sens);
                for (int i = 0; i < N; i++)
                    acc[i] ^= s[i];
            }
        }
#pragma omp critical
        for (int i = 0; i < N; i++)
            out[i] ^= acc[i];
    }
}

/* ------------------------------------------------------- différentiel */
/* hist[v*16 + δ] : distribution de la différence de sortie au nibble v
 * (post = 1 : de M^-1 · différence, alignée sur les S-box du dernier tour) ;
 * *exact : nombre de paires de différence de sortie = cible (si non NULL). */
void bn_diff(const uint8_t *din, int R, int sens, int post, int64_t n, uint64_t graine,
             const uint8_t *cible, uint64_t *exact, uint64_t *hist)
{
    memset(hist, 0, sizeof(uint64_t) * N * 16);
    *exact = 0;
#pragma omp parallel
    {
        uint64_t h[N * 16] = {0}, ex = 0;
        uint8_t a[N], b[N];
        rng_t g;
        POUR_PAQUETS(n) {
            rng_init(&g, graine, (uint64_t)p_);
            int64_t fin = (p_ + 1) * PAQUET < n ? (p_ + 1) * PAQUET : n;
            for (int64_t i = p_ * PAQUET; i < fin; i++) {
                etat_alea(&g, a);
                for (int v = 0; v < N; v++)
                    b[v] = a[v] ^ din[v];
                perm(a, R, sens);
                perm(b, R, sens);
                for (int v = 0; v < N; v++)
                    a[v] ^= b[v];
                if (post) {
                    lin_inv(a, b);
                    memcpy(a, b, N);
                }
                int egal = 1;
                for (int v = 0; v < N; v++) {
                    uint8_t d = a[v];
                    h[v * 16 + d]++;
                    if (cible && d != cible[v])
                        egal = 0;
                }
                ex += cible && egal;
            }
        }
#pragma omp critical
        {
            for (int i = 0; i < N * 16; i++)
                hist[i] += h[i];
            *exact += ex;
        }
    }
}

/* ------------------------------------------------------------ linéaire */
static const uint8_t PAR4[16] = {0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0};

static inline uint8_t parite(const uint8_t *m, const uint8_t *x)
{
    uint8_t p = 0;
    for (int v = 0; v < N; v++)
        p ^= PAR4[m[v] & x[v]];
    return p;
}

/* Nombre d'échantillons où <a, x> = <b, P(x)>. */
uint64_t bn_lin(const uint8_t *ma, const uint8_t *mb, int R, int sens, int64_t n, uint64_t graine)
{
    uint64_t acc = 0;
#pragma omp parallel reduction(+ : acc)
    {
        uint8_t x[N], y[N];
        rng_t g;
        POUR_PAQUETS(n) {
            rng_init(&g, graine, (uint64_t)p_);
            int64_t fin = (p_ + 1) * PAQUET < n ? (p_ + 1) * PAQUET : n;
            for (int64_t i = p_ * PAQUET; i < fin; i++) {
                etat_alea(&g, x);
                memcpy(y, x, N);
                perm(y, R, sens);
                acc += parite(ma, x) == parite(mb, y);
            }
        }
    }
    return acc;
}

/* cnt[(v*16 + z_v)*2 + <a, x>] avec z = P(x) (post = 1 : z = M^-1 P(x)) :
 * histogrammes conjoints d'où se déduisent les corrélations de <a, x> avec
 * les 128 × 15 masques de sortie à un nibble. */
void bn_lin_nib(const uint8_t *ma, int R, int sens, int post, int64_t n, uint64_t graine,
                uint64_t *cnt)
{
    memset(cnt, 0, sizeof(uint64_t) * N * 32);
#pragma omp parallel
    {
        uint64_t c[N * 32] = {0};
        uint8_t x[N], y[N], z[N];
        rng_t g;
        POUR_PAQUETS(n) {
            rng_init(&g, graine, (uint64_t)p_);
            int64_t fin = (p_ + 1) * PAQUET < n ? (p_ + 1) * PAQUET : n;
            for (int64_t i = p_ * PAQUET; i < fin; i++) {
                etat_alea(&g, x);
                memcpy(y, x, N);
                perm(y, R, sens);
                const uint8_t *o = y;
                if (post) {
                    lin_inv(y, z);
                    o = z;
                }
                uint8_t pa = parite(ma, x);
                for (int v = 0; v < N; v++)
                    c[(v * 16 + o[v]) * 2 + pa]++;
            }
        }
#pragma omp critical
        for (int i = 0; i < N * 32; i++)
            cnt[i] += c[i];
    }
}

/* ----------------------------------------------------------------- SAC */
/* cnt[i*512 + j] = #{bit j de P(x) ⊕ P(x ⊕ e_i) = 1}. */
void bn_sac(int R, int sens, int64_t n, uint64_t graine, uint64_t *cnt)
{
    memset(cnt, 0, sizeof(uint64_t) * 512 * 512);
#pragma omp parallel
    {
        uint32_t *c = calloc(512 * 512, sizeof(uint32_t));
        uint8_t x[N], y0[N], s[N];
        rng_t g;
        int64_t np = (n + 255) / 256;
#pragma omp for schedule(dynamic)
        for (int64_t p = 0; p < np; p++) {
            rng_init(&g, graine, (uint64_t)p);
            int64_t fin = (p + 1) * 256 < n ? (p + 1) * 256 : n;
            for (int64_t t = p * 256; t < fin; t++) {
                etat_alea(&g, x);
                memcpy(y0, x, N);
                perm(y0, R, sens);
                for (int i = 0; i < 512; i++) {
                    memcpy(s, x, N);
                    s[i >> 2] ^= (uint8_t)(1 << (i & 3));
                    perm(s, R, sens);
                    uint32_t *ci = c + (size_t)i * 512;
                    for (int v = 0; v < N; v++) {
                        uint8_t d = s[v] ^ y0[v];
                        ci[4 * v] += d & 1;
                        ci[4 * v + 1] += (d >> 1) & 1;
                        ci[4 * v + 2] += (d >> 2) & 1;
                        ci[4 * v + 3] += (d >> 3) & 1;
                    }
                }
            }
        }
#pragma omp critical
        for (int i = 0; i < 512 * 512; i++)
            cnt[i] += c[i];
        free(c);
    }
}

/* -------------------------------------------------------------- flux */
static inline void sortir(const uint8_t *s, int debit, uint8_t *o)
{
    for (int i = 0; i < debit / 2; i++)
        o[i] = (uint8_t)(s[2 * i] | (s[2 * i + 1] << 4));
}

/* Mode compteur : bloc i = débit de P(base ⊕ i), i écrit sur les nibbles 64..79. */
void bn_flux_compteur(const uint8_t *base, int64_t nblocs, int R, int debit, uint8_t *out)
{
#pragma omp parallel for schedule(static)
    for (int64_t i = 0; i < nblocs; i++) {
        uint8_t s[N];
        memcpy(s, base, N);
        for (int j = 0; j < 16; j++)
            s[64 + j] ^= (uint8_t)(((uint64_t)i >> (4 * j)) & 15);
        perm(s, R, 0);
        sortir(s, debit, out + i * (debit / 2));
    }
}

/* m éponges indépendantes en essorage : sortie du débit puis permutation. */
void bn_flux_eponge(const uint8_t *etats, int m, int64_t nblocs, int R, int debit, uint8_t *out)
{
#pragma omp parallel for schedule(static, 1)
    for (int q = 0; q < m; q++) {
        uint8_t s[N];
        memcpy(s, etats + (size_t)q * N, N);
        uint8_t *o = out + (size_t)q * nblocs * (debit / 2);
        for (int64_t b = 0; b < nblocs; b++) {
            perm(s, R, 0);
            sortir(s, debit, o + b * (debit / 2));
        }
    }
}

/* -------------------------------------------------------- statistiques */
/* Bits lus de poids faible en premier dans chaque octet. */
static inline int bit(const uint8_t *b, int64_t i) { return (b[i >> 3] >> (i & 7)) & 1; }

/* 64 bits à partir du bit p (le tampon doit avoir 16 octets de marge). */
static inline uint64_t lire64(const uint8_t *b, int64_t p)
{
    uint64_t lo, hi;
    memcpy(&lo, b + (p >> 3), 8);
    int r = p & 7;
    if (!r)
        return lo;
    hi = b[(p >> 3) + 8];
    return (lo >> r) | (hi << (64 - r));
}

void bn_pop_blocs(const uint8_t *buf, int64_t nblocs, int bloc, uint32_t *out)
{
#pragma omp parallel for schedule(static)
    for (int64_t i = 0; i < nblocs; i++) {
        uint32_t c = 0;
        const uint8_t *p = buf + i * bloc;
        int j = 0;
        for (; j + 8 <= bloc; j += 8) {
            uint64_t w;
            memcpy(&w, p + j, 8);
            c += (uint32_t)__builtin_popcountll(w);
        }
        for (; j < bloc; j++)
            c += (uint32_t)__builtin_popcount(p[j]);
        out[i] = c;
    }
}

/* Autocorrélation : désaccords entre les bits i et i+lag (i < neff, renvoyé). */
uint64_t bn_autocorr(const uint8_t *buf, int64_t nbits, int64_t lag, int64_t *neff)
{
    int64_t nmots = (nbits - lag) / 64;
    uint64_t d = 0;
#pragma omp parallel for reduction(+ : d) schedule(static)
    for (int64_t w = 0; w < nmots; w++)
        d += (uint64_t)__builtin_popcountll(lire64(buf, 64 * w) ^ lire64(buf, 64 * w + lag));
    *neff = nmots * 64;
    return d;
}

/* Motifs chevauchants de m bits (flux cyclique) : cnt[motif] ; motif = bits
 * i..i+m-1, le bit i en poids fort. */
void bn_motifs(const uint8_t *buf, int64_t nbits, int m, uint64_t *cnt)
{
    uint64_t taille = 1ULL << m, masque = taille - 1;
    memset(cnt, 0, sizeof(uint64_t) * taille);
    int nth = omp_get_max_threads();
    int64_t tranche = (nbits + nth - 1) / nth;
#pragma omp parallel num_threads(nth)
    {
        uint64_t *c = calloc(taille, sizeof(uint64_t));
#pragma omp for schedule(static)
        for (int t = 0; t < nth; t++) {
            int64_t deb = t * tranche, fin = deb + tranche < nbits ? deb + tranche : nbits;
            if (deb < fin) {
                uint64_t w = 0;
                for (int j = m - 1; j >= 1; j--)      /* m-1 bits précédant deb */
                    w = (w << 1) | (uint64_t)bit(buf, ((deb - j) % nbits + nbits) % nbits);
                for (int64_t i = deb; i < fin; i++) {
                    w = ((w << 1) | (uint64_t)bit(buf, i)) & masque;
                    c[w]++;
                }
            }
        }
#pragma omp critical
        for (uint64_t i = 0; i < taille; i++)
            cnt[i] += c[i];
        free(c);
    }
}

/* Longueurs de séquences (runs) : hist[b*64 + L] (L plafonnée à 63), exact,
 * y compris les séquences à cheval sur les tranches (fusion en fin). */
void bn_runs(const uint8_t *buf, int64_t nbits, uint64_t *hist)
{
    enum { NT = 64 };
    memset(hist, 0, sizeof(uint64_t) * 128);
    int64_t tranche = (nbits + NT - 1) / NT;
    int64_t tete_l[NT], queue_l[NT];
    int tete_b[NT], queue_b[NT];
#pragma omp parallel
    {
        uint64_t h[128] = {0};
#pragma omp for schedule(static)
        for (int t = 0; t < NT; t++) {
            int64_t deb = t * tranche, fin = deb + tranche < nbits ? deb + tranche : nbits;
            int b0 = bit(buf, deb), cur = b0;
            int64_t L = 0, premier = -1;
            for (int64_t i = deb; i < fin; i++) {
                int b = bit(buf, i);
                if (b == cur) {
                    L++;
                } else {
                    if (premier < 0)
                        premier = L;
                    else
                        h[cur * 64 + (L < 63 ? L : 63)]++;
                    cur = b;
                    L = 1;
                }
            }
            tete_b[t] = b0;
            tete_l[t] = premier < 0 ? -1 : premier;   /* -1 : tranche = une seule séquence */
            queue_b[t] = cur;
            queue_l[t] = L;
        }
#pragma omp critical
        for (int i = 0; i < 128; i++)
            hist[i] += h[i];
    }
    /* fusion séquentielle des bords */
    int cb = tete_b[0];
    int64_t cl = 0;
    for (int t = 0; t < NT; t++) {
        if (tete_l[t] < 0) {                  /* tranche uniforme */
            if (queue_b[t] == cb) cl += queue_l[t];
            else { hist[cb * 64 + (cl < 63 ? cl : 63)] += cl > 0; cb = queue_b[t]; cl = queue_l[t]; }
            continue;
        }
        if (tete_b[t] == cb) cl += tete_l[t];
        else { hist[cb * 64 + (cl < 63 ? cl : 63)] += cl > 0; cl = tete_l[t]; cb = tete_b[t]; }
        hist[cb * 64 + (cl < 63 ? cl : 63)]++;
        cb = queue_b[t];
        cl = queue_l[t];
    }
    hist[cb * 64 + (cl < 63 ? cl : 63)] += cl > 0;
}

/* Rang binaire de matrices 32×32 (128 octets chacune) : hist[rang]. */
void bn_rangs(const uint8_t *buf, int64_t nmat, uint64_t *hist)
{
    memset(hist, 0, sizeof(uint64_t) * 33);
#pragma omp parallel
    {
        uint64_t h[33] = {0};
#pragma omp for schedule(static)
        for (int64_t q = 0; q < nmat; q++) {
            uint32_t L[32];
            memcpy(L, buf + q * 128, 128);
            int rang = 0;
            for (int col = 0; col < 32 && rang < 32; col++) {
                int piv = -1;
                for (int i = rang; i < 32; i++)
                    if (L[i] >> col & 1) { piv = i; break; }
                if (piv < 0)
                    continue;
                uint32_t tmp = L[piv]; L[piv] = L[rang]; L[rang] = tmp;
                for (int i = 0; i < 32; i++)
                    if (i != rang && (L[i] >> col & 1))
                        L[i] ^= L[rang];
                rang++;
            }
            h[rang]++;
        }
#pragma omp critical
        for (int i = 0; i < 33; i++)
            hist[i] += h[i];
    }
}

/* Complexité linéaire (Berlekamp–Massey) de nblocs blocs de M bits. */
void bn_complexite(const uint8_t *buf, int M, int64_t nblocs, int32_t *L)
{
#pragma omp parallel
    {
        uint8_t *s = malloc(M), *C = malloc(M + 1), *Bv = malloc(M + 1), *Tm = malloc(M + 1);
#pragma omp for schedule(static)
        for (int64_t q = 0; q < nblocs; q++) {
            for (int i = 0; i < M; i++)
                s[i] = (uint8_t)bit(buf, q * M + i);
            memset(C, 0, M + 1); memset(Bv, 0, M + 1);
            C[0] = Bv[0] = 1;
            int l = 0, mm = -1;
            for (int nn = 0; nn < M; nn++) {
                uint8_t d = s[nn];
                for (int i = 1; i <= l; i++)
                    d ^= C[i] & s[nn - i];
                if (d) {
                    memcpy(Tm, C, M + 1);
                    for (int i = 0; i + nn - mm <= M; i++)
                        C[i + nn - mm] ^= Bv[i];
                    if (l <= nn / 2) {
                        l = nn + 1 - l;
                        mm = nn;
                        memcpy(Bv, Tm, M + 1);
                    }
                }
            }
            L[q] = l;
        }
        free(s); free(C); free(Bv); free(Tm);
    }
}

/* ------------------------------------------------- bruit de décodage KEM */
/* Pour la clé (x, y) (positions), simule le bruit après déchiffrement :
 *   r1·y ⊕ r2·x ⊕ e1 ⊕ π(e2)   (restreint aux n2 premiers bits)
 * avec r1, r2 de poids w uniformes dans Z_n, e1, π(e2) de poids we uniformes
 * dans [0, n2) (π est fixe : π(e2) a la loi de e2). Pour chaque bloc de L = 128·D
 * bits : plus grand poids du bruit sur un hyperplan S_{u,b} du code RM(1,7), de Q
 * (positions, sillage_kem._positions). hmax[t] : max sur les blocs ; hgrp[t] : tous
 * les blocs. Hist. de 64·D + 1 cases ; le décodage échoue dès t ≥ 32·D. */
static void tirer(rng_t *g, int w, int64_t n, int32_t *pos)
{
    for (int i = 0; i < w;) {
        int32_t p = (int32_t)rng_borne(g, (uint64_t)n);
        int dup = 0;
        for (int j = 0; j < i; j++)
            if (pos[j] == p) { dup = 1; break; }
        if (!dup)
            pos[i++] = p;
    }
}

static inline int stat_bloc(const uint64_t *W, int L, const uint8_t *Q)
{
    int T[128] = {0};
    for (int q = 0; q < L; q++)
        T[Q[q]] += (int)(W[q >> 6] >> (q & 63) & 1);
    for (int h = 1; h < 128; h <<= 1)
        for (int i = 0; i < 128; i += 2 * h)
            for (int j = i; j < i + h; j++) {
                int a = T[j], b = T[j + h];
                T[j] = a + b;
                T[j + h] = a - b;
            }
    int mx = 0;
    for (int u = 1; u < 128; u++) {
        int a = T[u] < 0 ? -T[u] : T[u];
        if (a > mx) mx = a;
    }
    return (T[0] + mx) / 2;
}

void bn_kem_bruit(const int32_t *xpos, const int32_t *ypos, int w, int64_t n, int64_t n2,
                  int k, int D, int we, const uint8_t *Q, int64_t essais, uint64_t graine,
                  uint64_t *hmax, uint64_t *hgrp)
{
    int d = 64 * D, L = 128 * D;
    memset(hmax, 0, sizeof(uint64_t) * (d + 1));
    memset(hgrp, 0, sizeof(uint64_t) * (d + 1));
    int64_t nmots = (n2 + 63) / 64;
#pragma omp parallel
    {
        uint64_t *hm = calloc(d + 1, 8), *hg = calloc(d + 1, 8);
        uint64_t *W = malloc(nmots * 8);
        int32_t *r = malloc(sizeof(int32_t) * (w > we ? w : we));
        rng_t g;
        int64_t np = (essais + 63) / 64;
#pragma omp for schedule(dynamic)
        for (int64_t p = 0; p < np; p++) {
            rng_init(&g, graine, (uint64_t)p);
            int64_t fin = (p + 1) * 64 < essais ? (p + 1) * 64 : essais;
            for (int64_t t = p * 64; t < fin; t++) {
                memset(W, 0, nmots * 8);
                for (int q = 0; q < 2; q++) {
                    const int32_t *cle = q ? xpos : ypos;
                    tirer(&g, w, n, r);
                    for (int a = 0; a < w; a++)
                        for (int b = 0; b < w; b++) {
                            int64_t s = (int64_t)r[a] + cle[b];
                            if (s >= n) s -= n;
                            if (s < n2) W[s >> 6] ^= 1ULL << (s & 63);
                        }
                }
                for (int q = 0; q < 2; q++) {
                    tirer(&g, we, n2, r);
                    for (int a = 0; a < we; a++)
                        W[r[a] >> 6] ^= 1ULL << (r[a] & 63);
                }
                int mx = 0;
                for (int grp = 0; grp < k / 8; grp++) {
                    int c = stat_bloc(W + (int64_t)grp * (L / 64), L, Q);
                    hg[c]++;
                    if (c > mx) mx = c;
                }
                hm[mx]++;
            }
        }
#pragma omp critical
        for (int i = 0; i <= d; i++) { hmax[i] += hm[i]; hgrp[i] += hg[i]; }
        free(hm); free(hg); free(W); free(r);
    }
}
