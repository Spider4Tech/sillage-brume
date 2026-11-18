# Prototype brume_hachage : le KEM et les signatures de la bibliothèque avec BRUME-1024q à la place de SHAKE256.
#   make          les trois variantes du bench (build/bench_shake, build/bench_c384, build/bench_c512)
#   make bench    les lance et écrit BENCH.md (comparer.py)
#   make compter  variantes BRUME avec compteur de permutations
# Les sources de la bibliothèque sont prises telles quelles dans sillage/c ; seul commun.c est compilé avec ses fonctions
# de hachage renommées (kk_…), remplacées par hachage_brume.c.
CC     ?= gcc
CFLAGS ?= -O3 -march=native -fopenmp -Wall -Wextra -Wno-unused-function
LIB     = ../../sillage/c
INC     = -I $(LIB)
AUTRES  = $(LIB)/brume1024.c $(LIB)/kem.c $(LIB)/sig.c $(LIB)/vole.c $(LIB)/isd.c
HDR     = $(LIB)/sillage.h
RENOMME = -Dsl_shake_init=kk_shake_init -Dsl_shake_absorb=kk_shake_absorb -Dsl_shake_final=kk_shake_final \
          -Dsl_shake_squeeze=kk_shake_squeeze -Dsl_shake_dom=kk_shake_dom -Dsl_shake256=kk_shake256 \
          -Dsl_shake4=kk_shake4 -Dsl_flux_init=kk_flux_init -Dsl_flux_next=kk_flux_next -Dsl_creux=kk_creux \
          -Dsl_echanges=kk_echanges -Dsl_perm=kk_perm

all: build/bench_shake build/bench_c384 build/bench_c512

build/commun_sans_hachage.o: $(LIB)/commun.c $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) $(RENOMME) -c -o $@ $<

build/bench_shake: bench_hachage.c $(LIB)/commun.c $(AUTRES) $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INC) -o $@ bench_hachage.c $(LIB)/commun.c $(AUTRES) -lm

build/bench_c%: bench_hachage.c hachage_brume.c build/commun_sans_hachage.o $(AUTRES) $(HDR)
	$(CC) $(CFLAGS) $(INC) -DBRUME_CAPACITE=$* -o $@ bench_hachage.c hachage_brume.c build/commun_sans_hachage.o $(AUTRES) -lm -lpthread

build/compter_c%: bench_hachage.c hachage_brume.c build/commun_sans_hachage.o $(AUTRES) $(HDR)
	$(CC) $(CFLAGS) $(INC) -DCOMPTER -DBRUME_CAPACITE=$* -o $@ bench_hachage.c hachage_brume.c build/commun_sans_hachage.o $(AUTRES) -lm -lpthread

compter: build/compter_c384 build/compter_c512

bench: all compter
	./build/bench_shake > build/shake.json
	./build/bench_c384 > build/c384.json
	./build/bench_c512 > build/c512.json
	./build/compter_c384 > build/compter_c384.json
	./build/compter_c512 > build/compter_c512.json
	python3 comparer.py build > BENCH.md

clean:
	rm -rf build

.PHONY: all compter bench clean
