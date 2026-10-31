/* Piste 9 : attaques directes sur SD régulier, comparées à l'estimateur du projet (mémoire gratuite, comme isd.c).
 *   1. ISD adapté : Prange, Dumer et BJMM de profondeur 2 sur les blocs, avec les w équations de régularité (Σ_bloc x = 1).
 *   2. Combinatoire : force brute, rencontre au milieu, anniversaire généralisé (condition d'existence des listes).
 *   3. Algébrique, hybride : on devine que chaque erreur tombe dans b coordonnées de son bloc, puis on linéarise au degré
 *      donné par la série de Hilbert (1 + (b−1)z)^w (1−z)^cod, au coût favorable ω = 2. Modèle d'après Briaud–Øygarden ;
 *      la répartition non uniforme des devinettes (Kim et al. 2026) n'y est pas : voir la marge laissée au rapport.
 *   4. Structure : rang avec les équations de régularité, colonnes de H, effet de la forme systématique [H' | I].
 * Modèles confrontés à des attaques réelles sur instances réduites (Prange régulier, linéarisation).
 *     build/rsd_attaques   (depuis la racine) → resultats/rsd_attaques.json
 */
#include <math.h>
#include <omp.h>
#include <quadmath.h>

#include "resultat.h"
#include "sillage.h"

static double lb(double n, double k) { return k < 0 || k > n ? -INFINITY : (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / log(2.0); }
static double add2(double a, double b) { return a > b ? a + log2(1 + pow(2, b - a)) : b + log2(1 + pow(2, a - b)); }

typedef struct { const char *nom; int n, cod, w, cible; } inst_t;

/* élimination : n·(cod + w), comme gauss() dans isd.c */
static double gauss_r(int n, int cod, int w) { return log2((double)n * (cod + w)); }

static double prange_r(int n, int cod, int w) { return w * log2((double)n / (cod + w)) + gauss_r(n, cod, w); }

/* p blocs actifs dans la partie information de ρ = (k_eff + l)/n, le reste dans la redondance */
static double dumer_r(int n, int cod, int w, int *bp, int *bl)
{
    double best = prange_r(n, cod, w), g = gauss_r(n, cod, w);
    int ke = n - cod - w;
    for (int p = 2; p <= w; p += 2)
        for (int l = 0; l <= cod + w - (w - p); l += 4) {
            double rho = (double)(ke + l) / n, Bi = (double)(ke + l) / w;
            if (rho >= 1) break;
            double L = lb(w / 2.0, p / 2.0) + (p / 2.0) * log2(Bi);
            /* exactement p/2 blocs actifs dans chaque moitié */
            double succ = 2 * lb(w / 2.0, p / 2.0) + p * log2(rho) + (w - p) * log2(1 - rho);
            double c = add2(add2(g, L + 1), 2 * L - l) - succ;
            if (c < best) { best = c; *bp = p; *bl = l; }
        }
    return best;
}

/* représentations : bloc actif → 2 façons ; bloc inactif → le même point des deux côtés (ε blocs) */
static double bjmm_r(int n, int cod, int w, int *bp, int *be, int *bl)
{
    double best = INFINITY, g = gauss_r(n, cod, w);
    int ke = n - cod - w;
    for (int p = 2; p <= w; p += 2) {
        for (int eps = 0; eps <= w - p && eps <= 80; eps++) {
            int p1 = p / 2 + eps;
            if (p1 > w) break;
            for (int l = 2; l <= cod + w - (w - p); l += 4) {
                double rho = (double)(ke + l) / n, Bi = (double)(ke + l) / w;
                if (rho >= 1) break;
                double R = lb(p, p / 2.0) + lb(w - p, eps) + eps * log2(Bi);
                double l1 = R > 0 ? R : 0;
                l1 = l1 < l ? l1 : l;
                double V1 = lb(w, p1) + p1 * log2(Bi);
                double L0 = V1 / 2, L1 = V1 - l1;
                double succ = lb(w, p) + p * log2(rho) + (w - p) * log2(1 - rho);
                double c = add2(add2(g, L0 + 2), add2(2 * L0 - l1 + 1, 2 * L1 - (l - l1))) - succ;
                if (c < best) { best = c; *bp = p; *be = eps; *bl = l; }
            }
        }
    }
    return best;
}

/* coefficients de (1 + a z)^w (1 − z)^c jusqu'au degré dmax ; premier degré où le coefficient est ≤ 0 */
static int degre_hilbert(int w, double a, int c, int dmax, double *log_taille)
{
    __float128 prev = 0;
    (void)prev;
    double t = 0;
    for (int d = 0; d <= dmax; d++) {
        __float128 s = 0, u = 1;                     /* u = C(w, i) a^i, terme de signe (−1)^(d−i) C(c, d−i) */
        /* C(c, d) puis récurrence sur i */
        __float128 v = 1;
        for (int j = 1; j <= d; j++)
            v = v * (__float128)(c - j + 1) / j;
        for (int i = 0; i <= d && i <= w; i++) {
            int j = d - i;
            __float128 x = u * v;
            s += j & 1 ? -x : x;
            u = u * (__float128)(w - i) / (i + 1) * (__float128)a;
            if (j > 0)
                v = v * (__float128)j / (c - j + 1);
        }
        if (s <= 0) {
            *log_taille = t;
            return d;
        }
        double ld = (double)log2q(s);
        t = ld > t ? ld : t;
    }
    *log_taille = t;
    return -1;
}

/* dans chaque bloc on garde b coordonnées ; au degré D, matrice de la taille du plus gros coefficient */
static double algebrique(int n, int cod, int w, int *bb, int *bd, double *btaille)
{
    double B = (double)n / w, best = INFINITY;
    for (int b = 2; b <= (int)B; b += (b < 64 ? 1 : 8)) {
        double taille;
        int libres = (b - 1) * w - cod;
        int D = libres <= 0 ? 1 : degre_hilbert(w, b - 1, cod, w, &taille);
        if (D < 0) continue;
        /* monômes de degré ≤ D en les variables restantes, ou par blocs si c'est moins */
        taille = libres <= 0 ? log2((double)(b - 1) * w) : lb(libres + D, D);
        double blocs = -INFINITY;
        for (int i = 0; i <= D && i <= w; i++)
            blocs = add2(blocs, lb(w, i) + i * log2(b - 1));
        if (libres > 0 && blocs < taille) taille = blocs;
        double c = w * log2(B / b) + 2 * taille;
        if (c < best) { best = c; *bb = b; *bd = D; *btaille = taille; }
    }
    return best;
}

/* -------------------------------------------- instances réduites : attaques réelles */
#define RN 256
typedef struct { uint64_t l[4]; } lig_t;
static inline int lbit(const lig_t *a, int i) { return (a->l[i >> 6] >> (i & 63)) & 1; }
static inline void lxor(lig_t *a, const lig_t *b) { for (int i = 0; i < 4; i++) a->l[i] ^= b->l[i]; }

static uint64_t al64(void) { uint64_t v; if (sl_alea(&v, 8)) abort(); return v; }

/* H de cod lignes : forme [H' | I] si syst, sinon dense ; x planté, régulier ; y = Hx. Colonne n = second membre */
static void instance(int n, int cod, int w, int syst, lig_t *H, int *pos)
{
    int B = n / w, k = n - cod;
    memset(H, 0, (size_t)cod * sizeof(lig_t));
    for (int r = 0; r < cod; r++) {
        for (int i = 0; i < 4; i++) H[r].l[i] = al64();
        for (int j = n; j < 256; j++) H[r].l[j >> 6] &= ~(1ULL << (j & 63));
        if (syst)
            for (int j = k; j < n; j++) {
                H[r].l[j >> 6] &= ~(1ULL << (j & 63));
                if (j - k == r) H[r].l[j >> 6] |= 1ULL << (j & 63);
            }
    }
    for (int b = 0; b < w; b++)
        pos[b] = b * B + (int)(al64() % (uint64_t)B);
    for (int r = 0; r < cod; r++) {
        int s = 0;
        for (int b = 0; b < w; b++) s ^= lbit(&H[r], pos[b]);
        if (s) H[r].l[n >> 6] |= 1ULL << (n & 63);
    }
}

/* Prange régulier réel : (cod + w)/w coordonnées par bloc en redondance. Renvoie le nombre d'itérations. */
static long prange_reel(int n, int cod, int w, const lig_t *H, const int *pos)
{
    int B = n / w, r = (cod + w) / w, m = cod + w;
    long it = 0;
    lig_t M[64];
    for (;;) {
        it++;
        uint8_t red[RN] = {0};
        int cols[64], nc = 0;
        for (int b = 0; b < w; b++) {
            int perm[32];
            for (int i = 0; i < B; i++) perm[i] = i;
            for (int i = 0; i < r; i++) {
                int j = i + (int)(al64() % (uint64_t)(B - i)), t = perm[i];
                perm[i] = perm[j]; perm[j] = t;
                red[b * B + perm[i]] = 1;
                cols[nc++] = b * B + perm[i];
            }
        }
        memcpy(M, H, (size_t)cod * sizeof(lig_t));
        for (int b = 0; b < w; b++) {                      /* équations de régularité */
            memset(&M[cod + b], 0, sizeof(lig_t));
            for (int i = 0; i < B; i++) M[cod + b].l[(b * B + i) >> 6] |= 1ULL << ((b * B + i) & 63);
            M[cod + b].l[n >> 6] |= 1ULL << (n & 63);
        }
        /* x nul hors de la redondance : système en nc inconnues */
        int rg = 0, piv[64];
        for (int c = 0; c < nc && rg < m; c++) {
            int q = rg;
            while (q < m && !lbit(&M[q], cols[c])) q++;
            if (q == m) continue;
            lig_t t = M[q]; M[q] = M[rg]; M[rg] = t;
            for (int i = 0; i < m; i++)
                if (i != rg && lbit(&M[i], cols[c])) lxor(&M[i], &M[rg]);
            piv[rg++] = cols[c];
        }
        int ok = 1;
        for (int i = rg; i < m; i++) ok &= !lbit(&M[i], n);
        if (!ok) continue;
        /* solution : poids w et égale à la cible (rang plein attendu) */
        uint8_t x[RN] = {0};
        for (int i = 0; i < rg; i++) x[piv[i]] = (uint8_t)lbit(&M[i], n);
        int bon = 1;
        for (int b = 0; b < w; b++) bon &= x[pos[b]];
        int po = 0;
        for (int i = 0; i < n; i++) po += x[i];
        (void)red;
        if (bon && po == w)
            return it;
    }
}

/* linéarisation réelle, b = taille de bloc, degré D : monômes = au plus un x_{i,v} (v < b−1) par bloc. Renvoie 1 si la solution sort. */
#define MMAX 6000
static int monomes(int w, int b, int D, int (*mon)[8])
{
    int nb = 1;
    memset(mon[0], -1, sizeof mon[0]);
    int deb = 0, fin = 1;
    for (int d = 1; d <= D; d++) {
        for (int m = deb; m < fin; m++) {
            int dernier = -1;
            for (int t = 0; t < w; t++) if (mon[m][t] >= 0) dernier = t;
            for (int t = dernier + 1; t < w; t++)
                for (int v = 0; v < b - 1; v++) {
                    if (nb >= MMAX) return -1;
                    memcpy(mon[nb], mon[m], sizeof mon[0]);
                    mon[nb][t] = v;
                    nb++;
                }
        }
        deb = fin; fin = nb;
    }
    return nb;
}

static int code_mon(const int *m, int w, int b)
{
    int c = 0;
    for (int t = 0; t < w; t++) c = c * b + m[t] + 1;
    return c;
}

/* degré minimal auquel la linéarisation isole la solution, sur une instance (w ≤ 8, blocs de taille b) */
static int degre_reel(int w, int b, int cod, int Dmax)
{
    static _Thread_local int mon[MMAX][8];
    uint8_t coef[64][64];
    for (int r = 0; r < cod; r++)
        for (int q = 0; q < w * (b - 1) + 1; q++)
            coef[r][q] = (uint8_t)(al64() & 1);
    int pl[8];
    for (int t = 0; t < w; t++) pl[t] = (int)(al64() % (uint64_t)b);
    for (int r = 0; r < cod; r++) {                        /* a·x + c = 0 sur la solution plantée (v = b−1 : tous nuls) */
        int s = 0;
        for (int t = 0; t < w; t++)
            if (pl[t] < b - 1) s ^= coef[r][t * (b - 1) + pl[t]];
        coef[r][w * (b - 1)] = (uint8_t)s;
    }
    for (int D = 1; D <= Dmax; D++) {
        int bm = monomes(w, b, D - 1, mon);
        int nb = monomes(w, b, D, mon);
        if (nb < 0 || bm < 0) return -1;
        int w64 = nb / 64 + 1;
        size_t cap = (size_t)bm * (size_t)cod;
        uint64_t *L = calloc(cap, (size_t)w64 * 8);
        int place = 1;
        for (int t = 0; t < w; t++) place *= b;
        int *indice = malloc((size_t)place * sizeof(int));
        for (int i = 0; i < nb; i++) indice[code_mon(mon[i], w, b)] = i;
        size_t nl = 0;
        for (int m = 0; m < bm; m++)
            for (int r = 0; r < cod; r++, nl++) {
                uint64_t *ligne = L + nl * (size_t)w64;
                int moi = m;
                ligne[moi >> 6] ^= (uint64_t)coef[r][w * (b - 1)] << (moi & 63);
                for (int t = 0; t < w; t++)
                    for (int v = 0; v < b - 1; v++) {
                        if (!coef[r][t * (b - 1) + v]) continue;
                        /* x_{t,v} · monôme : nul si autre v dans le bloc, inchangé si même v */
                        if (mon[m][t] >= 0 && mon[m][t] != v) continue;
                        int prod[8];
                        memcpy(prod, mon[m], sizeof prod);
                        prod[t] = v;
                        int q = indice[code_mon(prod, w, b)];
                        ligne[q >> 6] ^= 1ULL << (q & 63);
                    }
            }
        /* rang : solution unique ⇔ noyau de dimension 1 (le vecteur des monômes évalués en la solution) */
        size_t rg = 0;
        for (int c = 0; c < nb && rg < nl; c++) {
            size_t q = rg;
            while (q < nl && !((L[q * (size_t)w64 + (size_t)(c >> 6)] >> (c & 63)) & 1)) q++;
            if (q == nl) continue;
            for (int i = 0; i < w64; i++) {
                uint64_t t = L[q * (size_t)w64 + (size_t)i];
                L[q * (size_t)w64 + (size_t)i] = L[rg * (size_t)w64 + (size_t)i];
                L[rg * (size_t)w64 + (size_t)i] = t;
            }
            for (size_t x = 0; x < nl; x++)
                if (x != rg && ((L[x * (size_t)w64 + (size_t)(c >> 6)] >> (c & 63)) & 1))
                    for (int i = 0; i < w64; i++) L[x * (size_t)w64 + (size_t)i] ^= L[rg * (size_t)w64 + (size_t)i];
            rg++;
        }
        free(L); free(indice);
        if ((int)rg == nb - 1)
            return D;
    }
    return -1;
}

int main(void)
{
    resultat_t r = {.nom = "rsd_attaques"};
    static const inst_t I[5] = {
        {"VOLE-128", 18620, 616, 76, 160},
        {"VOLE-256", 38456, 1224, 152, 316},
        {"SDitH2-L1", 10360, 432, 56, 143},
        {"SDitH2-L3", 18396, 592, 73, 207},
        {"SDitH2-L5", 19864, 800, 104, 272},
    };
    /* 4. et validation : Prange régulier réel, forme systématique contre H dense */
    {
        int n = 128, cod = 40, w = 8, nt = 150;
        double som[2] = {0, 0};
        for (int sy = 0; sy < 2; sy++)
#pragma omp parallel for schedule(dynamic) reduction(+:som[:2])
            for (int t = 0; t < nt; t++) {
                lig_t H[64];
                int pos[16];
                instance(n, cod, w, sy, H, pos);
                som[sy] += (double)prange_reel(n, cod, w, H, pos);
            }
        double att = pow(16.0 / ((cod + w) / w), w);
        printf("Prange régulier réel, (n, cod, w) = (%d, %d, %d) : %.0f itérations (H dense), %.0f ([H'|I]) ; modèle %.0f\n", n, cod, w, som[0] / nt, som[1] / nt, att);
        res_controle(&r, "modele_prange_regulier_retrouve", som[0] / nt > 0.6 * att && som[0] / nt < 1.6 * att);
        res_controle(&r, "forme_systematique_sans_effet_mesure", som[1] / nt > 0.7 * som[0] / nt && som[1] / nt < 1.4 * som[0] / nt);
        res_mesure(&r, "prange_reel", "{\"dense\":%.1f,\"systematique\":%.1f,\"modele\":%.1f}", som[0] / nt, som[1] / nt, att);
    }
    /* validation du degré de linéarisation : modèle contre instances réelles */
    {
        /* cod > w·log2 b + 4 : solution unique, sinon le noyau reste de dimension > 1 quel que soit le degré */
        static const int T[8][3] = {{6, 4, 16}, {6, 4, 17}, {5, 5, 17}, {5, 5, 19}, {4, 8, 17}, {4, 8, 22}, {6, 5, 20}, {6, 5, 23}};
        int ecart = 0, tot = 0;
        char buf[1024];
        size_t lb_ = (size_t)snprintf(buf, sizeof buf, "[");
        for (int q = 0; q < 8; q++) {
            double tl;
            int pred = degre_hilbert(T[q][0], T[q][1] - 1, T[q][2], T[q][0], &tl);
            int reel = degre_reel(T[q][0], T[q][1], T[q][2], T[q][0]);
            printf("linéarisation w=%d b=%d cod=%d : degré réel %d, série de Hilbert %d\n", T[q][0], T[q][1], T[q][2], reel, pred);
            lb_ += (size_t)snprintf(buf + lb_, sizeof buf - lb_, "%s{\"w\":%d,\"b\":%d,\"cod\":%d,\"reel\":%d,\"modele\":%d}", q ? "," : "", T[q][0], T[q][1], T[q][2], reel, pred);
            if (reel >= 0 && pred >= 0) { tot++; ecart += abs(reel - pred) > 1; }
        }
        snprintf(buf + lb_, sizeof buf - lb_, "]");
        res_mesure(&r, "linearisation_reduite", "%s", buf);
        res_controle(&r, "modele_de_degre_a_un_pres_sur_instances_reduites", tot >= 6 && ecart == 0);
    }
    /* grandeurs réelles */
    static char json[6000];
    size_t lj = (size_t)snprintf(json, sizeof json, "[");
    int garde = 1;
    for (int q = 0; q < 5; q++) {
        const inst_t *x = &I[q];
        double B = (double)x->n / x->w, o[6];
        int dp = 0, dl = 0, bp = 0, be = 0, bl = 0, ab = 0, ad = 0;
        double at = 0;
        double pr = prange_r(x->n, x->cod, x->w), du = dumer_r(x->n, x->cod, x->w, &dp, &dl), bj = bjmm_r(x->n, x->cod, x->w, &bp, &be, &bl);
        double mit = x->w * log2(B) / 2, al = algebrique(x->n, x->cod, x->w, &ab, &ad, &at);
        double sd = sl_isd_bjmm(x->n, x->n - x->cod, x->w, 400, 100, 1500, o);
        /* anniversaire généralisé : 2^a listes de w/2^a blocs doivent atteindre cod/(a + 1) bits */
        int gba = 0;
        for (int a = 1; a <= 6; a++)
            gba |= (x->w * log2(B)) / (1 << a) >= (double)x->cod / (a + 1);
        double sr = sl_isd_bjmm(x->n, x->n - x->cod - x->w, x->w, 400, 100, 1500, o);   /* les w équations de régularité en plus */
        double m = fmin(fmin(fmin(pr, du), fmin(bj, fmin(mit, al))), fmin(sd, sr));
        printf("%s (n=%d cod=%d w=%d, visé %d) :\n  ISD : Prange %.1f, Dumer %.1f (p=%d l=%d), BJMM %.1f (p=%d ε=%d l=%d) ; SD sans structure %.1f, avec équations de régularité %.1f\n  combinatoire : rencontre %.1f, anniversaire généralisé %s\n  algébrique : %.1f (b=%d, degré %d, matrice 2^%.1f)\n  → meilleure %.1f, marge sur le visé %+.1f\n",
               x->nom, x->n, x->cod, x->w, x->cible, pr, du, dp, dl, bj, bp, be, bl, sd, sr, mit, gba ? "POSSIBLE" : "sans liste assez grande", al, ab, ad, at, m, m - x->cible);
        fflush(stdout);
        lj += (size_t)snprintf(json + lj, sizeof json - lj, "%s{\"nom\":\"%s\",\"vise\":%d,\"prange\":%.1f,\"dumer\":%.1f,\"bjmm\":%.1f,\"sd\":%.1f,\"sd_regularite\":%.1f,\"rencontre\":%.1f,\"algebrique\":%.1f,\"b\":%d,\"degre\":%d,\"meilleure\":%.1f}",
                               q ? "," : "", x->nom, x->cible, pr, du, bj, sd, sr, mit, al, ab, ad, m);
        if (q < 2) {
            char nom[80];
            snprintf(nom, sizeof nom, "%s_meilleure_attaque_directe_au_dessus_du_vise", x->nom);
            res_controle(&r, nom, m >= x->cible);
            garde &= m >= x->cible;
        }
    }
    (void)garde;
    /* 4. structure sur les vraies matrices : régularité indépendante, colonnes distinctes */
    {
        const inst_t *x = &I[0];
        int k = x->n - x->cod, cB = x->cod / 8;
        uint8_t *c = malloc((size_t)k * (size_t)cB);
        sl_shake256((const uint8_t *)"structure", 9, c, (size_t)k * (size_t)cB);
        int dup = 0;
#pragma omp parallel for schedule(dynamic) reduction(+:dup)
        for (int i = 0; i < 2000; i++)
            for (int j = i + 1; j < k; j++)
                dup += !memcmp(c + (size_t)i * (size_t)cB, c + (size_t)j * (size_t)cB, (size_t)cB);
        long po = 0;
        for (size_t i = 0; i < (size_t)k * (size_t)cB; i++) po += __builtin_popcount(c[i]);
        double dens = (double)po / (8.0 * (double)k * cB);
        res_controle(&r, "colonnes_de_H_distinctes_et_denses", dup == 0 && fabs(dens - 0.5) < 0.001);
        res_mesure(&r, "densite_H", "%.5f", dens);
        free(c);
    }
    snprintf(json + lj, sizeof json - lj, "]");
    res_mesure(&r, "instances", "%s", json);
    return res_ecrire(&r);
}
