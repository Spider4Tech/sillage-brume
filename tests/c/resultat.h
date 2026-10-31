/* Résultat d'un test C au format de la batterie (tests/run_all.py) :
 * resultats/<nom>.json = {"controles": {nom: bool, …}, "mesures": {nom: valeur JSON, …}}.
 * Le programme est lancé depuis la racine du dépôt. */
#ifndef RESULTAT_H
#define RESULTAT_H
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RES_MAX 128

typedef struct {
    const char *nom, *titre;            /* titre : section Markdown resultats/<nom>.md (facultatif) */
    int nc, nm;
    char *cn[RES_MAX], *mn[RES_MAX], *mv[RES_MAX];
    int cv[RES_MAX];
} resultat_t;

static void res_controle(resultat_t *r, const char *nom, int ok)
{
    r->cn[r->nc] = strdup(nom);
    r->cv[r->nc++] = ok != 0;
    fprintf(stderr, "  %-60s %s\n", nom, ok ? "OK" : "ÉCHEC");
}

/* mesure : valeur JSON déjà formée (nombre, chaîne entre guillemets, objet…) */
static void res_mesure(resultat_t *r, const char *nom, const char *fmt, ...)
{
    static char buf[20000];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    r->mn[r->nm] = strdup(nom);
    r->mv[r->nm++] = strdup(buf);
}

static int res_ecrire(const resultat_t *r)
{
    char chemin[256];
    snprintf(chemin, sizeof chemin, "resultats/%s.json", r->nom);
    FILE *f = fopen(chemin, "w");
    if (!f) {
        perror(chemin);
        return 2;
    }
    fprintf(f, "{\n \"controles\": {");
    for (int i = 0; i < r->nc; i++)
        fprintf(f, "%s\n  \"%s\": %s", i ? "," : "", r->cn[i], r->cv[i] ? "true" : "false");
    fprintf(f, "\n },\n \"mesures\": {");
    for (int i = 0; i < r->nm; i++)
        fprintf(f, "%s\n  \"%s\": %s", i ? "," : "", r->mn[i], r->mv[i]);
    fprintf(f, "\n }\n}\n");
    if (ferror(f) | fclose(f)) {
        perror(chemin);
        return 2;
    }
    if (r->titre) {                                  /* synthèse lisible (campagnes de nuit) */
        snprintf(chemin, sizeof chemin, "resultats/%s.md", r->nom);
        if ((f = fopen(chemin, "w"))) {
            int ko = 0;
            for (int i = 0; i < r->nc; i++)
                ko += !r->cv[i];
            fprintf(f, "## %s\n\n%d/%d contrôles réussis.\n\n| Contrôle | Résultat |\n|---|---|\n",
                    r->titre, r->nc - ko, r->nc);
            for (int i = 0; i < r->nc; i++)
                fprintf(f, "| `%s` | %s |\n", r->cn[i], r->cv[i] ? "OK" : "**ÉCHEC**");
            fprintf(f, "\n| Mesure | Valeur |\n|---|---|\n");
            for (int i = 0; i < r->nm; i++)
                fprintf(f, "| `%s` | `%s` |\n", r->mn[i], r->mv[i]);
            fprintf(f, "\n");
            fclose(f);
        }
    }
    int ok = 1;
    for (int i = 0; i < r->nc; i++)
        ok &= r->cv[i];
    fprintf(stderr, "%s : %d contrôles, %s\n", r->nom, r->nc, ok ? "tous réussis" : "ÉCHECS");
    return ok ? 0 : 1;                               /* 1 : contrôle en échec, JSON écrit ; 2 : résultats non écrits */
}

/* xoshiro256** : aléa reproductible des tests */
typedef struct { uint64_t s[4]; } alea_t;
static inline uint64_t alea_rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
static inline uint64_t alea64(alea_t *a)
{
    uint64_t *s = a->s, r = alea_rotl(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = alea_rotl(s[3], 45);
    return r;
}
static inline void alea_init(alea_t *a, uint64_t graine)
{
    for (int i = 0; i < 4; i++) {                    /* splitmix64 */
        uint64_t z = (graine += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        a->s[i] = z ^ (z >> 31);
    }
}
static inline uint64_t alea_borne(alea_t *a, uint64_t n) { return alea64(a) % n; }   /* biais négligeable (n ≪ 2^64) */

#endif
