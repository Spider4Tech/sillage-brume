# Prototype hors suite (docs/PISTES.md, piste 10) : BRUME-512 bitslicé sur 256 états, AVX2.
#   make -C prototypes/brume_bitslice        → build/banc (contrôles, puis cycles ; lancer sur un cœur au repos :
#                                             taskset -c 2 prototypes/brume_bitslice/build/banc)
CC     ?= gcc
CFLAGS ?= -O3 -march=native -fopenmp -Wall -Wextra
LIB    := ../../sillage/c
SRC    := $(LIB)/commun.c $(LIB)/brume512.c $(LIB)/brume512_avx2.c

all: build/banc

build/gen_asm: gen_asm.c $(LIB)/brume512_tables.h
	@mkdir -p build
	$(CC) -O2 -I $(LIB) -o $@ $<

build/bs_tour.S: build/gen_asm
	$< > $@

build/banc: banc.c bs.c bs.h sbox_bs.h compteurs.h build/bs_tour.S $(SRC)
	$(CC) $(CFLAGS) -I $(LIB) -I . -o $@ banc.c bs.c build/bs_tour.S $(SRC) -lm

clean:
	rm -rf build

.PHONY: all clean
