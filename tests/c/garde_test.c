/* Témoin du détecteur (tests/test_c_fuzz.py) : chaque cas DOIT faire échouer le programme.
   Cas 0 à 2 : allocateur à pages de garde (garde.c). Cas 3 et 4 : UBSan en mode trap, compilé avec les mêmes options que
   fuzz.c ; sans eux, rien ne montrait que les pièges UBSan étaient actifs. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  int cas = atoi(argv[1]); volatile unsigned char *p = malloc(37); volatile unsigned char x = 0;
  if (cas == 0) { p[37] = 1; free((void*)p); }          /* 1 octet de trop (bourrage) */
  if (cas == 1) { x = p[37 + 20]; }                     /* lecture au-delà de la page */
  if (cas == 2) { free((void*)p); x = p[0]; }           /* après libération */
  if (cas == 3) { int t[4] = {1, 2, 3, 4}; volatile int i = argc + 4; x = (unsigned char)t[i]; }   /* indice hors tableau */
  if (cas == 4) { volatile int a = INT_MAX; a = a + argc; x = (unsigned char)a; }                 /* débordement signé */
  /* Cas 5 et 6 : même erreurs que 0 et 2, sur un pointeur « blanchi » que UBSan (object-size) ne peut pas suivre :
     seul l'allocateur à pages de garde peut les voir (SIGABRT par le canari, SIGSEGV par la page). */
  volatile uintptr_t u = (uintptr_t)p; volatile unsigned char *q = (volatile unsigned char *)u;
  if (cas == 5) { q[37] = 1; free((void *)q); }
  if (cas == 6) { free((void *)q); x = q[0]; }
  printf("non détecté (cas %d) %d\n", cas, x); return 0; }
