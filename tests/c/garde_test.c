/* Témoin du détecteur (tests/test_c_fuzz.py) : chaque cas DOIT faire échouer le programme. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  int cas = atoi(argv[1]); volatile unsigned char *p = malloc(37); volatile unsigned char x = 0;
  if (cas == 0) { p[37] = 1; free((void*)p); }          /* 1 octet de trop (bourrage) */
  if (cas == 1) { x = p[37 + 20]; }                     /* lecture au-delà de la page */
  if (cas == 2) { free((void*)p); x = p[0]; }           /* après libération */
  printf("non détecté (cas %d) %d\n", cas, x); return 0; }
