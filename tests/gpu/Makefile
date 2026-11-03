# Outils GPU (CUDA) — depuis la racine : make -C tests/gpu
# Binaire portable : sm_75 (Turing : RTX 20xx, Quadro RTX), sm_89 (Ada : RTX 40xx, L4, L40S), sm_90 (Hopper : H100, H200)
# et PTX compute_90 pour les cartes plus récentes. CUDA 12 au moins.
# Une seule architecture : make -C tests/gpu ARCHS=75
NVCC  ?= $(firstword $(wildcard /usr/local/cuda/bin/nvcc) $(shell command -v nvcc) nvcc)
ARCHS ?= 75 89 90
L      = ../../sillage/c
GENC   = $(foreach a,$(ARCHS),-gencode arch=compute_$(a),code=sm_$(a)) -gencode arch=compute_$(lastword $(ARCHS)),code=compute_$(lastword $(ARCHS))
NVFL   = -O3 $(GENC) -I$(L) -I../c -Xcompiler -O3,-march=native,-fopenmp
LIB    = $(L)/commun.c $(L)/brume512.c $(L)/brume512_avx2.c

all: build/brume_gpu build/campagne_dl

build/%: %.cu brume.cuh $(LIB) Makefile
	@mkdir -p build
	$(NVCC) $(NVFL) -o $@ $< $(LIB) -lgomp -lm

.PHONY: all
