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

# sig_kz_gpu : hôte C (code SIG réel, tests/c/sig_kz_commun.h) + noyaux CUDA ; lanceur : ./runtestg-gpu.sh
CC    ?= cc
CFL    = -O3 -march=native -fopenmp -Wall -Wextra -I$(L) -I../c -I../c/build
../c/build/sig_var.c: $(L)/sig.c
	$(MAKE) -C ../c build/sig_var.c
build/sig_kz_gpu: sig_kz_gpu.c sig_kz_gpu.cu sig_kz_gpu.h ../c/sig_kz_commun.h ../c/build/sig_var.c ../c/resultat.h $(LIB) Makefile
	@mkdir -p build
	$(CC) $(CFL) -c -o build/sig_kz_gpu_hote.o sig_kz_gpu.c
	$(NVCC) $(NVFL) -Xptxas -v -o $@ sig_kz_gpu.cu build/sig_kz_gpu_hote.o $(LIB) -lgomp -lm 2>build/sig_kz_gpu.ptxas || { cat build/sig_kz_gpu.ptxas; exit 1; }
build/sig_kz_gpu_k18: sig_kz_gpu.c sig_kz_gpu.cu sig_kz_gpu.h ../c/sig_kz_commun.h ../c/build/sig_var.c ../c/resultat.h $(LIB) Makefile
	@mkdir -p build
	$(CC) $(CFL) -DKZ_EP=18 -c -o build/sig_kz_gpu_k18_hote.o sig_kz_gpu.c
	$(NVCC) $(NVFL) -DKZ_EP=18 -Xptxas -v -o $@ sig_kz_gpu.cu build/sig_kz_gpu_k18_hote.o $(LIB) -lgomp -lm 2>build/sig_kz_gpu_k18.ptxas || { cat build/sig_kz_gpu_k18.ptxas; exit 1; }

.PHONY: all
