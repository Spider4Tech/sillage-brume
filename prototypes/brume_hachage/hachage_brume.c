/* Prototype (hors suite) : la couche de hachage de la bibliothèque (SHAKE256, sillage/c/commun.c) remplacée par une
 * éponge BRUME-1024q. Le KEM (kem.c), la signature VOLE (vole.c) et la signature v0.4 (sig.c) sont compilés tels quels
 * par-dessus : seules les fonctions ci-dessous changent. README.md de ce dossier.
 *
 * Éponge : la permutation de la bibliothèque (sl_brume_permute, constant-time), le cadrage de la SPEC § 3.1 en mode 5
 * (éponge), le domaine XOF 0 et le bourrage 0x01 de la SPEC § 3.2. Débit :
 *   - par défaut, c = 384 (80 octets) : c'est exactement sl_xof de la bibliothèque (vérifié par bench_hachage) ;
 *   - -DBRUME_CAPACITE=512 : c = 512 (64 octets), même construction, octet de débit du cadre = 128 (r/4) au lieu de 160.
 *     Ce profil n'existe pas dans la SPEC : c'est la variante de catégorie 5 pour les préimages (NIST_CATEGORIES § 4).
 *
 * Correspondance avec la couche SHAKE :
 *   - sl_shake_init/absorb/final/squeeze : la même interface incrémentale, l'état BRUME (128 octets) dans sl_shake_t ;
 *     l'IV (état après le cadre et une permutation) est calculé une fois ;
 *   - sl_flux_* : même mode compteur que SHAKE (bloc c = XOF(dom ‖ "|bits|" ‖ graine ‖ "|" ‖ c_be64), 64 octets) ;
 *   - sl_shake4 : 4 éponges à la suite (un lot de 32 états ne coûte que 681 ns par état contre 770, BENCH_C.md) ;
 *   - sl_creux, sl_echanges, sl_perm : recopiés de commun.c sans changement (ils ne dépendent que du flux).
 * Compilation : commun.c est compilé avec ses fonctions de hachage renommées (-Dsl_shake_init=kk_shake_init, …, voir le
 * Makefile), pour garder le reste (allocation, aléa, effacement) sans le recopier.
 * -DCOMPTER : compte les permutations (sl_hachage_permutations). */
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "sillage.h"

#ifndef BRUME_CAPACITE
#define BRUME_CAPACITE 384
#endif
#if BRUME_CAPACITE == 512
#define RB 64
#elif BRUME_CAPACITE == 384
#define RB 80
#else
#error "BRUME_CAPACITE : 384 ou 512"
#endif
#define DOM_XOF 0

unsigned long sl_hachage_permutations(void);
int sl_hachage_capacite(void) { return BRUME_CAPACITE; }

#ifdef COMPTER
static unsigned long nperm;
unsigned long sl_hachage_permutations(void) { return __atomic_load_n(&nperm, __ATOMIC_RELAXED); }
#define COMPTE() __atomic_fetch_add(&nperm, 1, __ATOMIC_RELAXED)
#else
unsigned long sl_hachage_permutations(void) { return 0; }
#define COMPTE() ((void)0)
#endif

static void P(uint8_t *s)
{
    COMPTE();
    sl_brume_permute(s);
}

static uint8_t IV[128];
static pthread_once_t iv_une_fois = PTHREAD_ONCE_INIT;

static void iv_calcul(void)
{
    sl_init();                      /* tables de BRUME-1024q ; sans effet si déjà fait */
    memset(IV, 0, sizeof IV);
    IV[121] = 32;                   /* cadre de la SPEC § 3.1 : tours, débit en nibbles, mode 5 (éponge) */
    IV[124] = (uint8_t)(RB * 2);    /* 160 pour c = 384 (comme la SPEC), 128 pour c = 512 */
    IV[125] = 0x10;
    IV[126] = 0x71;
    IV[127] = 5;
    P(IV);
}

void sl_shake_init(sl_shake_t *h)
{
    pthread_once(&iv_une_fois, iv_calcul);
    memset(h, 0, sizeof *h);
    memcpy(h->s, IV, 128);
}

void sl_shake_absorb(sl_shake_t *h, const void *d, size_t len)
{
    const uint8_t *p = d;
    uint8_t *st = (uint8_t *)h->s;
    while (len) {
        size_t k = RB - h->pos < len ? RB - h->pos : len;
        for (size_t i = 0; i < k; i++)
            st[h->pos + i] ^= p[i];
        h->pos += k; p += k; len -= k;
        if (h->pos == RB) {
            P(st);
            h->pos = 0;
        }
    }
}

void sl_shake_final(sl_shake_t *h)
{
    uint8_t *st = (uint8_t *)h->s;
    st[h->pos] ^= 0x01;
    st[127] ^= (uint8_t)(DOM_XOF << 4);
    P(st);
    h->pos = 0;
}

void sl_shake_squeeze(sl_shake_t *h, void *out, size_t len)
{
    uint8_t *o = out, *st = (uint8_t *)h->s;
    while (len) {
        if (h->pos == RB) {
            P(st);
            h->pos = 0;
        }
        size_t k = RB - h->pos < len ? RB - h->pos : len;
        memcpy(o, st + h->pos, k);
        h->pos += k; o += k; len -= k;
    }
}

void sl_shake256(const uint8_t *m, size_t len, uint8_t *out, size_t outlen)
{
    sl_shake_t h;
    sl_shake_init(&h);
    sl_shake_absorb(&h, m, len);
    sl_shake_final(&h);
    sl_shake_squeeze(&h, out, outlen);
}

void sl_shake_dom(const char *dom, const uint8_t *dom2, size_t dom2len,
                  const uint8_t *const *parts, const size_t *lens, int nparts,
                  uint8_t *out, size_t outlen)
{
    sl_shake_t h;
    sl_shake_init(&h);
    sl_shake_absorb(&h, dom, strlen(dom));
    if (dom2len)
        sl_shake_absorb(&h, dom2, dom2len);
    sl_shake_absorb(&h, "|", 1);
    for (int i = 0; i < nparts; i++)
        sl_shake_absorb(&h, parts[i], lens[i]);
    sl_shake_final(&h);
    sl_shake_squeeze(&h, out, outlen);
}

void sl_shake4(const uint8_t *const m[4], size_t len, uint8_t *const out[4], size_t outlen)
{
    for (int j = 0; j < 4; j++)
        sl_shake256(m[j], len, out[j], outlen);
}

void sl_flux_init(sl_flux_t *f, const char *dom, const uint8_t *seed, size_t seedlen)
{
    if (seedlen > sizeof f->seed)
        abort();
    strncpy(f->dom, dom, sizeof f->dom - 1);
    f->dom[sizeof f->dom - 1] = 0;
    memcpy(f->seed, seed, seedlen);
    f->seedlen = seedlen;
    f->ctr = 0;
    f->pos = (int)sizeof f->buf;
}

static void flux_blocs(sl_flux_t *f)
{
    size_t ld = strlen(f->dom);
    for (int j = 0; j < 4; j++) {
        uint8_t c[8];
        for (int i = 0; i < 8; i++)
            c[i] = (uint8_t)((f->ctr + j) >> (56 - 8 * i));
        sl_shake_t h;
        sl_shake_init(&h);
        sl_shake_absorb(&h, f->dom, ld);
        sl_shake_absorb(&h, "|bits|", 6);
        sl_shake_absorb(&h, f->seed, f->seedlen);
        sl_shake_absorb(&h, "|", 1);
        sl_shake_absorb(&h, c, 8);
        sl_shake_final(&h);
        sl_shake_squeeze(&h, f->buf + 64 * j, 64);
        sl_effacer(&h, sizeof h);
    }
    f->ctr += 4;
    f->pos = 0;
}

static inline uint32_t flux_suivant(sl_flux_t *f)
{
    if (f->pos == (int)sizeof f->buf)
        flux_blocs(f);
    uint32_t x;
    memcpy(&x, f->buf + f->pos, 4);
    f->pos += 4;
    return __builtin_bswap32(x);
}

uint32_t sl_flux_next(sl_flux_t *f) { return flux_suivant(f); }

/* ---- recopiés de sillage/c/commun.c (v0.6), sans changement ---- */
void sl_creux(const uint8_t *seed, size_t seedlen, int poids, uint32_t n, const char *dom, uint32_t *pos)
{
    sl_flux_t f;
    sl_flux_init(&f, dom, seed, seedlen);
    uint32_t span = 1;
    while (span < n)
        span <<= 1;
    double p = (double)(n - (uint32_t)poids) / span, l = 128 * 0.6931471805599453;
    double mu = poids + l + sqrt((poids + l) * (poids + l) - (double)poids * poids);
    long M = (long)ceil(mu / p);
    uint32_t tmp[1024 + 1];
    int k = 0;
    memset(tmp, 0, sizeof tmp);
    if (poids > 1024)
        M = 0;                                  /* (hors des paramètres SILLAGE) */
    for (long t = 0; t < M; t++) {
        uint32_t r = flux_suivant(&f) & (span - 1);
        uint32_t ok = (uint32_t)((int32_t)(r - n) >> 31) & 1;        /* r < n */
        uint32_t vu = 0;
        __asm__ volatile("" : "+r"(k));           /* gcc découperait sinon la boucle sur j < k */
        for (int j = 0; j < poids; j++) {                             /* parcours complet */
            uint32_t ici = -(((uint32_t)(j ^ k) - 1) >> 31);          /* j = k : k dépend des rejets */
            vu |= (uint32_t)(tmp[j] == r) & (uint32_t)((j - k) >> 31 & 1);   /* j < k */
            tmp[j] = (tmp[j] & ~ici) | (r & ici);                     /* écrit toujours en k, avance si accepté */
        }
        ok &= (vu ^ 1) & (uint32_t)((k - poids) >> 31 & 1);          /* non vu, k < poids */
        k += (int)ok;
    }
    SL_PUBLIC(&k, sizeof k);                      /* k = poids, sauf avec probabilité < 2^-128 */
    memcpy(pos, tmp, (size_t)(k < poids ? k : poids) * sizeof *pos);
    while (k < poids) {
        uint32_t r = sl_flux_next(&f) & (span - 1);
        uint32_t vu = 0;
        for (int j = 0; j < k; j++)
            vu |= pos[j] == r;
        if (r < n && !vu)
            pos[k++] = r;
    }
}

void sl_echanges(const uint8_t *seed, size_t seedlen, uint32_t m, const char *dom, uint32_t *r)
{
    sl_flux_t f;
    sl_flux_init(&f, dom, seed, seedlen);
    for (uint32_t i = m ? m - 1 : 0; i > 0;) {
        uint32_t x = flux_suivant(&f) & ((2u << (31 - __builtin_clz(i))) - 1);
        r[i] = x;
        i -= x <= i;
    }
    sl_effacer(&f, sizeof f);
}

void sl_perm(const uint8_t *seed, size_t seedlen, uint32_t m, const char *dom, uint32_t *perm)
{
    uint32_t *r = sl_malloc(4 * (size_t)m);
    sl_echanges(seed, seedlen, m, dom, r);
    for (uint32_t i = 0; i < m; i++)
        perm[i] = i;
    for (uint32_t i = m ? m - 1 : 0; i > 0; i--) {
        uint32_t t = perm[i]; perm[i] = perm[r[i]]; perm[r[i]] = t;
    }
    free(r);
}
