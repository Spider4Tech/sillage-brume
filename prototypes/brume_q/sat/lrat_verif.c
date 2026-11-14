/* Vérificateur LRAT minimal, indépendant du solveur : CNF DIMACS + preuve LRAT texte ⇒ « VERIFIEE » si et
 * seulement si chaque lemme se déduit par propagation unitaire sur les SEULES clauses citées (étapes RUP),
 * et si la clause vide est déduite. Les étapes RAT (indices négatifs) sont refusées : CaDiCaL n'en émet pas
 * en mode --lrat, et les accepter demanderait un contrôle de plus. Toute anomalie (indice inconnu ou supprimé,
 * clause citée ni unitaire ni conflictuelle, indice non croissant) fait échouer la vérification.
 *
 *   lrat_verif fichier.cnf preuve.lrat
 * Compilation : cc -O2 -o lrat_verif prototypes/brume_q/sat/lrat_verif.c
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int *l;
    int n;
} clause_t;

static clause_t *db;
static long cap_db;
static int8_t *val;      /* val[v] ∈ {−1, 0, 1} */
static int *trail, ntrail, nvars;

static FILE *in_f;
static char buf[1 << 20];
static size_t bpos, blen;

static int lit_car(void)
{
    if (bpos == blen) {
        blen = fread(buf, 1, sizeof buf, in_f);
        bpos = 0;
        if (!blen)
            return EOF;
    }
    return buf[bpos++];
}

/* lit un entier ; 'd' renvoyé via *mot = 1 ; retourne 0 en fin de fichier */
static int lit_jeton(long *x, int *mot)
{
    int c;
    *mot = 0;
    for (;;) {
        c = lit_car();
        if (c == EOF)
            return 0;
        if (c == 'c') {          /* commentaire jusqu'à la fin de ligne */
            while ((c = lit_car()) != EOF && c != '\n')
                ;
            continue;
        }
        if (c == 'd') {
            *mot = 1;
            return 1;
        }
        if (c == '-' || (c >= '0' && c <= '9'))
            break;
    }
    int neg = c == '-';
    long v = neg ? 0 : c - '0';
    while ((c = lit_car()) >= '0' && c <= '9')
        v = 10 * v + (c - '0');
    *x = neg ? -v : v;
    return 1;
}

static void range(long id, int *l, int n)
{
    if (id >= cap_db) {
        long nc = cap_db ? cap_db : 1 << 16;
        while (nc <= id)
            nc *= 2;
        db = realloc(db, sizeof(clause_t) * nc);
        memset(db + cap_db, 0, sizeof(clause_t) * (nc - cap_db));
        cap_db = nc;
    }
    db[id].l = l;
    db[id].n = n;
}

static int8_t valeur(int l) { return l > 0 ? val[l] : -val[-l]; }

static void affecte(int l)
{
    int v = l > 0 ? l : -l;
    val[v] = l > 0 ? 1 : -1;
    trail[ntrail++] = v;
}

static void defait(void)
{
    while (ntrail)
        val[trail[--ntrail]] = 0;
}

static void echec(const char *m, long id)
{
    printf("lrat_verif ECHEC : %s (lemme %ld)\n", m, id);
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage : %s fichier.cnf preuve.lrat\n", argv[0]);
        return 2;
    }
    /* CNF */
    FILE *f = fopen(argv[1], "r");
    if (!f)
        return 2;
    char ligne[4096];
    long nclauses = 0;
    while (fgets(ligne, sizeof ligne, f))
        if (ligne[0] == 'p') {
            if (sscanf(ligne, "p cnf %d %ld", &nvars, &nclauses) != 2)
                return 2;
            break;
        }
    in_f = f;
    int *tmp = malloc(sizeof(int) * (nvars + 2)), nt = 0, mot;
    long x, id = 0;
    while (lit_jeton(&x, &mot)) {
        if (mot)
            return 2;
        if (x == 0) {
            int *c = malloc(sizeof(int) * (nt ? nt : 1));
            memcpy(c, tmp, sizeof(int) * nt);
            range(++id, c, nt);
            nt = 0;
        } else {
            if (labs(x) > nvars || nt > nvars)
                echec("litteral hors bornes dans la CNF", id);
            tmp[nt++] = (int)x;
        }
    }
    fclose(f);
    if (id != nclauses)
        echec("nombre de clauses de la CNF", id);
    val = calloc(nvars + 1, 1);
    trail = malloc(sizeof(int) * (nvars + 1));
    /* preuve */
    in_f = fopen(argv[2], "r");
    if (!in_f)
        return 2;
    bpos = blen = 0;
    long dernier = nclauses, lemmes = 0, suppr = 0, indices = 0;
    int vide = 0;
    for (;;) {
        long lid;
        if (!lit_jeton(&lid, &mot))
            break;
        if (mot || lid <= 0)
            echec("indice de lemme attendu", lid);
        if (!lit_jeton(&x, &mot))
            echec("ligne tronquee", lid);
        if (mot) {               /* suppression : lid d i1 i2 … 0 */
            for (;;) {
                if (!lit_jeton(&x, &mot) || mot)
                    echec("suppression tronquee", lid);
                if (x == 0)
                    break;
                if (x < 0 || x >= cap_db || !db[x].l)
                    echec("suppression d'une clause inconnue", lid);
                free(db[x].l);
                db[x].l = NULL;
                suppr++;
            }
            continue;
        }
        if (lid <= dernier)
            echec("indice de lemme non croissant", lid);
        dernier = lid;
        /* littéraux du lemme */
        nt = 0;
        int taut = 0;
        while (x != 0) {
            if (labs(x) > nvars || nt > nvars)
                echec("litteral hors bornes", lid);
            tmp[nt++] = (int)x;
            if (!lit_jeton(&x, &mot) || mot)
                echec("lemme tronque", lid);
        }
        for (int i = 0; i < nt; i++) {
            int8_t v = valeur(tmp[i]);
            if (v == 1)
                taut = 1;        /* l et ¬l dans le lemme : tautologie */
            else if (v == 0)
                affecte(-tmp[i]);
        }
        /* indices : propagation sur les clauses citées */
        int conflit = taut;
        for (;;) {
            if (!lit_jeton(&x, &mot) || mot)
                echec("indices tronques", lid);
            if (x == 0)
                break;
            indices++;
            if (conflit)
                continue;        /* indices restants après le conflit : sans effet */
            if (x < 0)
                echec("etape RAT (non supportee)", lid);
            if (x >= cap_db || !db[x].l)
                echec("indice inconnu ou supprime", lid);
            clause_t *c = &db[x];
            int libre = 0, nlibre = 0, vrai = 0;
            for (int i = 0; i < c->n; i++) {
                int8_t v = valeur(c->l[i]);
                if (v == 1) {
                    vrai = 1;
                    break;
                }
                if (v == 0) {
                    nlibre++;
                    libre = c->l[i];
                }
            }
            if (vrai || nlibre > 1)
                echec("clause citee ni unitaire ni conflictuelle", lid);
            if (nlibre == 0)
                conflit = 1;
            else
                affecte(libre);
        }
        defait();
        if (!conflit)
            echec("pas de conflit apres les indices", lid);
        int *c = malloc(sizeof(int) * (nt ? nt : 1));
        memcpy(c, tmp, sizeof(int) * nt);
        range(lid, c, nt);
        lemmes++;
        if (nt == 0) {
            vide = 1;
            break;
        }
    }
    fclose(in_f);
    printf("lrat_verif : %ld clauses d'entree, %ld lemmes RUP verifies (%ld indices), %ld suppressions ; clause vide %s\n",
           nclauses, lemmes, indices, suppr, vide ? "deduite" : "ABSENTE");
    printf("lrat_verif %s\n", vide ? "VERIFIEE" : "ECHEC");
    return vide ? 0 : 1;
}
