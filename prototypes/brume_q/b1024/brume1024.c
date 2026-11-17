/* BRUME-1024q — v0.6 : le code est passé dans la bibliothèque (sillage/c/brume1024.c) et ses contrôles dans la batterie
 * (tests/c/brume1024.c, qui inclut la bibliothèque). Ce fichier y renvoie, pour que les outils de ce dossier qui font
 * « #include "brume1024.c" » (avec -DSANS_MAIN) continuent de compiler, sur le code de la bibliothèque.
 *   cc -O3 -march=native -fopenmp -I sillage/c -I tests/c -I prototypes/brume_q/b1024 OUTIL.c sillage/c/commun.c -lm */
#include "../../../tests/c/brume1024.c"
