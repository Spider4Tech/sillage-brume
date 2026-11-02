# Outils GPU (CUDA) — depuis la racine : make -C tests/gpu
NVCC  ?= /usr/local/cuda/bin/nvcc
L      = ../../sillage/c
NVFL   = -O3 -arch=sm_89 -I$(L) -I../c -Xcompiler -O3,-march=native,-fopenmp
LIB    = $(L)/commun.c $(L)/brume512.c $(L)/brume512_avx2.c

all: build/brume_gpu build/campagne_dl

build/%: %.cu brume.cuh $(LIB)
	@mkdir -p build
	$(NVCC) $(NVFL) -o $@ $< $(LIB) -lgomp -lm

.PHONY: all
