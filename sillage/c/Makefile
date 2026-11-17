# SILLAGE — implémentation C de référence
#   make          bibliothèque partagée + benchmark
#   les tables de BRUME-1024q (brume1024_*.h) sont générées par prototypes/brume_q/b1024/gen_b1024.c et gen_bitslice.c
CC      ?= gcc
CFLAGS  ?= -O3 -march=native -fopenmp -Wall -Wextra
SRC      = commun.c brume1024.c kem.c sig.c vole.c isd.c

all: build/libsillage.so build/bench

build/libsillage.so: $(SRC) sillage.h brume1024_tables.h brume1024_portable.h brume1024_bs.h brume1024_lot.h
	@mkdir -p build
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $(SRC) -lm

build/bench: bench.c $(SRC) sillage.h brume1024_tables.h brume1024_portable.h brume1024_bs.h brume1024_lot.h
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ bench.c $(SRC) -lm

clean:
	rm -rf build

.PHONY: all clean
