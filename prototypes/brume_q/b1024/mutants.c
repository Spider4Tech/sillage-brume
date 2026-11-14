/* Score de mutation de brume1024.c (ROADMAP.md § 2) : énumère de petites mutations du code de la bibliothèque (tout ce qui
 * précède la section « contrôles et mesures » : référence dense, noyaux, modes, AEAD, référence DMV17), une par mutant.
 * Le script de campagne compile chaque mutant et lance la batterie (BRUME1024_RAPIDE=1) : un mutant est « tué » si un
 * contrôle échoue, si le programme plante ou dépasse le délai ; il « survit » si les 17 contrôles passent. Les mutants qui
 * ne compilent pas sont écartés du score. Chaque survivant est à examiner : test manquant, ou mutation équivalente.
 *   mutants compter <brume1024.c>                    : nombre de mutants
 *   mutants ecrire <brume1024.c> <k> <sortie.c>      : écrit le mutant k ; décrit la mutation sur la sortie standard
 * Opérateurs : ^ ↔ |, & → |, + ↔ -, << ↔ >>, < ↔ <=, > ↔ >=, == ↔ !=, && ↔ ||, ^= ↔ |=, += ↔ -=, entier n → n+1 et n−1,
 * _mm256_xor_si256 → _mm256_or_si256, _mm256_and_si256 → _mm256_or_si256, suppression d'une affectation simple. Commentaires, chaînes et lignes de
 * préprocesseur ne sont pas mutés. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int ligne, col, lon; const char *rempl; char nouv[32]; } mut_t;
static mut_t *MU;
static int NMU, CAPMU;
static char **L;
static int NL;

static void ajouter(int l, int c, int lon, const char *r)
{
    if (NMU == CAPMU) {
        CAPMU = CAPMU ? 2 * CAPMU : 1024;
        MU = realloc(MU, sizeof *MU * CAPMU);
    }
    MU[NMU] = (mut_t){l, c, lon, NULL, ""};
    snprintf(MU[NMU].nouv, sizeof MU[NMU].nouv, "%s", r);
    NMU++;
}

static void lire(const char *f)
{
    FILE *e = fopen(f, "r");
    if (!e) { perror(f); exit(2); }
    char tampon[8192];
    int cap = 0;
    while (fgets(tampon, sizeof tampon, e)) {
        if (NL == cap) { cap = cap ? 2 * cap : 2048; L = realloc(L, sizeof *L * cap); }
        L[NL++] = strdup(tampon);
    }
    fclose(e);
}

static void enumerer(void)
{
    int dans_com = 0;
    for (int l = 0; l < NL; l++) {
        const char *s = L[l];
        if (strstr(s, "contrôles et mesures */"))
            break;
        const char *p = s;
        while (*p == ' ' || *p == '\t') p++;
        if (!dans_com && *p == '#')
            continue;
        int n = (int)strlen(s);
        /* suppression d'une instruction d'affectation simple (une ligne, sans déclaration ni contrôle de flux) */
        if (!dans_com) {
            static const char *const DEBUTS[] = {"const ", "static ", "uint", "int ", "size_t ", "__m", "double ", "long ", "char ",
                                                 "unsigned ", "return", "for ", "for(", "if ", "if(", "while", "else", "do ",
                                                 "case ", "default", "typedef", "enum", "struct", "#", "/", "*", "}", "{"};
            int exclu = 0;
            for (size_t i = 0; i < sizeof DEBUTS / sizeof *DEBUTS; i++)
                exclu |= !strncmp(p, DEBUTS[i], strlen(DEBUTS[i]));
            const char *pv = strchr(p, ';');
            if (!exclu && pv && !strchr(p, '{') && !strchr(p, '}') && strchr(p, '=') && strchr(p, '=') < pv) {
                const char *apres = pv + 1;
                while (*apres == ' ' || *apres == '\t') apres++;
                if (*apres == '\n' || *apres == 0 || !strncmp(apres, "/*", 2))
                    ajouter(l, (int)(p - s), (int)(pv - p) + 1, ";");
            }
        }
        for (int c = 0; c < n; c++) {
            if (dans_com) {
                if (s[c] == '*' && s[c + 1] == '/') { dans_com = 0; c++; }
                continue;
            }
            if (s[c] == '/' && s[c + 1] == '*') { dans_com = 1; c++; continue; }
            if (s[c] == '/' && s[c + 1] == '/') break;
            if (s[c] == '"' || s[c] == '\'') {   /* chaîne ou caractère : sauté */
                char q = s[c];
                for (c++; c < n && s[c] != q; c++)
                    if (s[c] == '\\') c++;
                continue;
            }
            if (isalpha((unsigned char)s[c]) || s[c] == '_') {   /* identifiant : intrinsèques seulement */
                int d = c;
                while (d < n && (isalnum((unsigned char)s[d]) || s[d] == '_')) d++;
                if (d - c == 16 && !strncmp(s + c, "_mm256_xor_si256", 16)) ajouter(l, c, 16, "_mm256_or_si256");
                if (d - c == 16 && !strncmp(s + c, "_mm256_and_si256", 16)) ajouter(l, c, 16, "_mm256_or_si256");
                c = d - 1;
                continue;
            }
            if (isdigit((unsigned char)s[c])) {   /* littéral entier (décimal ou hexadécimal), suffixes U/L tolérés */
                int d = c;
                long v;
                char *fin;
                v = strtol(s + c, &fin, 0);
                d = (int)(fin - s);
                if (d < n && s[d] == '.') { c = d; continue; }   /* flottant : ignoré */
                while (d < n && (s[d] == 'U' || s[d] == 'u' || s[d] == 'L' || s[d] == 'l')) d++;
                char r[32];
                snprintf(r, sizeof r, "%ld", v + 1);
                ajouter(l, c, (int)(fin - s) - c, r);
                if (v > 0) {
                    snprintf(r, sizeof r, "%ld", v - 1);
                    ajouter(l, c, (int)(fin - s) - c, r);
                }
                c = d - 1;
                continue;
            }
            static const char *const OP[][2] = {
                {"<<=", NULL}, {">>=", NULL}, {"->", NULL}, {"++", NULL}, {"--", NULL},
                {"&&", "||"}, {"||", "&&"}, {"==", "!="}, {"!=", "=="}, {"<=", "<"}, {">=", ">"},
                {"<<", ">>"}, {">>", "<<"}, {"^=", "|="}, {"|=", "^="}, {"&=", NULL}, {"+=", "-="}, {"-=", "+="},
                {"^", "|"}, {"|", "^"}, {"&", "|"}, {"+", "-"}, {"-", "+"}, {"<", "<="}, {">", ">="},
            };
            for (size_t o = 0; o < sizeof OP / sizeof *OP; o++) {
                size_t lo = strlen(OP[o][0]);
                if (!strncmp(s + c, OP[o][0], lo)) {
                    if (OP[o][1])
                        ajouter(l, c, (int)lo, OP[o][1]);
                    c += (int)lo - 1;
                    break;
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 3)
        return 2;
    lire(argv[2]);
    enumerer();
    if (!strcmp(argv[1], "compter")) {
        printf("%d\n", NMU);
        return 0;
    }
    if (strcmp(argv[1], "ecrire") || argc < 5)
        return 2;
    int k = atoi(argv[3]);
    if (k < 0 || k >= NMU)
        return 3;
    const mut_t *m = &MU[k];
    FILE *s = fopen(argv[4], "w");
    if (!s) { perror(argv[4]); return 2; }
    for (int l = 0; l < NL; l++) {
        if (l != m->ligne) { fputs(L[l], s); continue; }
        fwrite(L[l], 1, (size_t)m->col, s);
        fputs(m->nouv, s);
        fputs(L[l] + m->col + m->lon, s);
    }
    fclose(s);
    char avant[64];
    snprintf(avant, sizeof avant, "%.*s", m->lon < 63 ? m->lon : 63, L[m->ligne] + m->col);
    char contexte[160];
    snprintf(contexte, sizeof contexte, "%s", L[m->ligne]);
    contexte[strcspn(contexte, "\n")] = 0;
    char *c = contexte;
    while (*c == ' ') c++;
    printf("ligne %d, colonne %d : « %s » → « %s » | %.110s\n", m->ligne + 1, m->col + 1, avant, m->nouv, c);
    return 0;
}
