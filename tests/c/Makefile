# Tests C natifs de la batterie : chaque programme, lancé depuis la racine
# du dépôt, écrit resultats/<nom>.json (tests/c/resultat.h).
#   make -C tests/c            → build/<test> pour tous les tests natifs
CC      ?= gcc
CFLAGS  ?= -O3 -march=native -fopenmp -Wall -Wextra
LIB     := ../../sillage/c
SRC     := $(LIB)/commun.c $(LIB)/brume512.c $(LIB)/brume512_avx2.c $(LIB)/kem.c $(LIB)/sig.c
NATIFS  := structure_miss isd_reel isd_comparaison diffusion_support kem_distributions sig_flux brume_attaques mini_brume
NUIT    := nuit_cryptanalyse nuit_kem_reel nuit_isd
all: $(addprefix build/,$(NATIFS))
nuit: $(addprefix build/,$(NUIT))
build/%: %.c resultat.h brume_ref.h $(SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -I $(LIB) -o $@ $< $(SRC) -lm
# kem_distributions et nuit_kem_reel incluent kem.c (fonctions internes) : on ne le relie pas une seconde fois
build/kem_distributions build/nuit_kem_reel: build/%: %.c resultat.h $(SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -I $(LIB) -o $@ $< $(filter-out $(LIB)/kem.c,$(SRC)) -lm
# sig_flux : sig.c instrumenté (trace-pc), sl_alea déterministe (trace_pc.c),
# commun.c avec son sl_alea renommé
build/sig_flux: sig_flux.c trace_pc.c resultat.h $(SRC)
	@mkdir -p build
	$(CC) $(CFLAGS) -c -o build/trace_pc.o trace_pc.c
	$(CC) $(CFLAGS) -Dsl_alea=sl_alea_systeme -I $(LIB) -c -o build/commun_rejeu.o $(LIB)/commun.c
	$(CC) $(CFLAGS) -fsanitize-coverage=trace-pc -I $(LIB) -o $@ $< build/trace_pc.o build/commun_rejeu.o \
		$(LIB)/brume512.c $(LIB)/brume512_avx2.c -lm
.PHONY: all nuit
