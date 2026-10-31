# SILLAGE — implémentation C de référence
#   make          bibliothèque partagée + benchmark
#   make tables   régénère brume512_tables.h depuis sillage/brume512.py
CC      ?= gcc
CFLAGS  ?= -O3 -march=native -fopenmp -Wall -Wextra
SRC      = commun.c brume512.c brume512_avx2.c kem.c sig.c isd.c

all: build/libsillage.so build/bench

build/libsillage.so: $(SRC) sillage.h brume512_tables.h brume512_simd.h
	@mkdir -p build
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $(SRC) -lm

build/bench: bench.c $(SRC) sillage.h brume512_tables.h brume512_simd.h
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ bench.c $(SRC) -lm

tables:
	cd ../.. && python3 -m sillage.c.gen_tables   # brume512_tables.h + brume512_simd.h

clean:
	rm -rf build

.PHONY: all tables clean
