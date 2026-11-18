# SILLAGE v0.6 in the NIST security categories: gate model

*18 November 2026. Model: `tests/modele_portes.py`; checks: `tests/test_modele_portes.py` (battery, theme "Paramètres").*

This places each component of the suite in the NIST categories 1 to 5 with a **gate model**: the cost of every attack is
counted in gates of all kinds (Clifford+T) and in full circuit depth, like the NIST thresholds. The earlier estimate for
the v0.4 signature (`docs/PROOFS.md` § 5 bis) counted only Toffoli gates and Toffoli depth, so it was not on the same
scale as the thresholds.

**What the numbers are.** Every cost is a **lower bound favourable to the attacker** (for instance, Keccak-f counts fewer
T gates than the published circuit of Amy et al.). A category reached here is therefore a floor *for this model*. The
model is ours and not reviewed. It covers the attacks listed below; an attack outside this list is not covered.

## 1. Thresholds

A category requires both columns. MAXDEPTH ∈ {2^40, 2^64, 2^96}, and every value must hold for all three.

| Category | Reference | Classical gates | Quantum gates (NIST 2016) | Quantum gates (JNRV 2020) |
|---|---|---|---|---|
| 1 | AES-128 key search | 2^143 | 2^170 / MAXDEPTH | 2^157 / MAXDEPTH |
| 2 | SHA-256 collision | 2^146 | — | — |
| 3 | AES-192 key search | 2^207 | 2^233 / MAXDEPTH | 2^221 / MAXDEPTH |
| 4 | SHA-384 collision | 2^210 | — | — |
| 5 | AES-256 key search | 2^272 | 2^298 / MAXDEPTH | 2^285 / MAXDEPTH |

"NIST 2016" is the call for proposals (from Grassl et al.). "JNRV 2020" is the AES Grover oracle of Jaques, Naehrig,
Roetteler and Virdia (EUROCRYPT 2020); Jang et al. (2022) correct it to 2^156.3, 2^221.6 and 2^286.1. Both columns are given
because they lead to different conclusions for the signature.

## 2. Building blocks

- **Grover under bounded depth** (Zalka): √N·g gates if √N·d ≤ MAXDEPTH, otherwise N·g·d / MAXDEPTH (machines in
  parallel). Check: with an AES-128 oracle of g·d = 2^42, it gives the NIST threshold 2^170 / MAXDEPTH.
- **Toffoli**: 15 Clifford+T gates, depth 12 (Amy–Maslov–Mosca–Roetteler 2013).
- **Keccak-f[1600]**, computed then uncomputed: 1 600 Toffoli and 3 200 CNOT per round, depth 29 per round, so
  **2^20.3 gates and depth 2^10.4**; 2^19.0 T gates, below the 2^19.9 per iteration of Amy et al. (SAC 2016) for SHA3-256;
  classically 2^17.6 operations.
- **BRUME-1024q**, computed then uncomputed: the 17-gate S-box circuit read from `brume1024_portable.h` (10 non-linear
  gates, 7 XOR, non-linear depth 4), 34.4 XOR per vertex for the linear layer (Paar), so **2^21.6 gates and depth 2^11.8**;
  classically 2^18.8 operations.
- **Prange accelerated by Grover**: one iteration is a reversible Gaussian elimination, r²·n Toffoli in r layers.
  Multiple targets (quasi-cyclic rotations, DOOM) shorten the search: Grover only gains ½·log₂ of the number of targets.

## 3. Results

| Component | Classical | Limiting quantum attack | Category, NIST 2016 | Category, JNRV 2020 | Missing for 5 (NIST 2016) |
|---|---|---|---|---|---|
| Sillage-KEM-128 | 2^138.2 (ISD) | none: quantum ISD is dearer than classical ISD at MAXDEPTH 2^40 and 2^64 | **none** (4.8 bits short of 1, classically) | **none** | 133.8 |
| Sillage-KEM-256 | 2^265.1 (ISD) | same | **3** | **3** | 6.9 (classical) |
| VOLE-128 / 128f | 2^145.6 | Grover on the final challenge Δ: 2^119.8 at MAXDEPTH 2^40 | **none** (10.2 bits short of 1) | **1** | — |
| VOLE-256 / 256f | 2^273.6 | Grover on Δ: 2^247.8 at MAXDEPTH 2^40 | **3** | **5** (2.8-bit margin) | 10.2 |
| AEAD BRUME-1024q, known attacks (model Q1, σ ≤ 2^64) | 2^336.8 | Grover on the inner part of a state, σ targets: 2^313.4 | **5** | **5** | 0 |
| AEAD BRUME-1024q, what the Q1 proof guarantees | 2^336.8 | proved bound: 2^157.5 queries to P, so ≥ 2^179.1 gates | **1** | **1** (1.9 bits short of 3) | 78.9 |
| Hash BRUME-1024q, collisions | 2^210.8 | generic exponents of SHA-384 (c = 384) | **4** | **4** | not applicable |
| Hash BRUME-1024q, preimages | 2^210.8 (2^192 calls) | none below the classical attack | **3** | **3** | 61.2 (classical) |
| Hash, preimages, free quantum memory (BHT, 2^128) | 2^210.8 | BHT on the capacity: 2^149.6 | 1 | 1 | — |
| Hash, what the quantum proof guarantees | 2^210.8 | proved bound: 2^124.1 queries, ≥ 2^145.7 gates | 1 | 1 | — |

Details for every attack and every MAXDEPTH: `python3 -m tests.modele_portes`, or `resultats/modele_portes.json`.

**Reading.**
- **KEM.** The quantum side never limits: under the depth limits, Prange–Grover costs more than classical ISD. The level
  is set by **classical** ISD. Sillage-128 (2^138.2 operations without memory cost) is **4.8 bits under the 2^143 gates of
  category 1**, and Sillage-256 (2^265.1) is 6.9 bits under category 5. Counting the memory of the BJMM lists
  (2^36.6 and 2^41.9 entries) would raise both, but by an amount this model does not establish.
- **Signature.** The binding attack is Grover on the **final challenge Δ** of τκ + wpow bits (a single Keccak per
  iteration), then the hidden seed of λ + 8 bits. The challenge γ, the challenge M and ISD are not binding.
- **AEAD.** Category 5 against the known attacks, with margin. The proof (Q1, not reviewed) only guarantees category 1 in
  gates: a bound in queries does not use the depth limit, and the term 2q·√(2σ/2^384) allows 2^157.5 queries.
- **Hash.** It sits in category 4 for collisions because its generic exponents are those of SHA-384 (2^192
  classically, 2^(2c/5) and 2^(c/3) quantum), and one permutation costs at least one compression of SHA-384
  (2^18.8 against 2^18). For preimages, 2^192 calls give category 3 and rule out 5. Quantum collision-type attacks
  (BHT, CNS) are not counted as cheaper than the classical one, as NIST does for SHA-384 (memory has a cost: Jaques–Schanck
  2019). With free quantum memory, the preimage drops to category 1.

**The suite as a whole** takes the weakest component of each profile:

| Profile | NIST 2016 | JNRV 2020 | Limited by |
|---|---|---|---|
| 128 (KEM-128, VOLE-128, BRUME-1024q) | **none** | **none** | classical ISD of the KEM; Δ challenge of VOLE-128 |
| 256 (KEM-256, VOLE-256, BRUME-1024q) | **3** | **3** | KEM-256 (classical) and hash preimages; VOLE-256 too, with the 2016 thresholds |

## 4. What category 5 would take (profile 256)

| Component | Change | Effect in the model | Cost |
|---|---|---|---|
| KEM-256 | parameters giving +6.9 bits of classical ISD (w and n higher) | category 5 classically | new parameters and KATs, larger keys and ciphertexts; to size with `test_isd_parametres` |
| VOLE-256 | grinding wpow 7 → **18**, or one more repetition | Δ reaches 2^258.7 at MAXDEPTH 2^40 (threshold 2^258) | 2^18 hashes per signature for the grinding; or a larger signature |
| VOLE-256 | seeds of λ + 8 → **λ + 12** bits | the seed attack reaches category 5 | a few bytes per signature |
| Hash | capacity c = 384 → **512** (rate 640 → 512 bits) | preimages 2^274.8 (threshold 2^272) | about −20 % of speed; new profile and KATs |
| AEAD | nothing for the known attacks; a reviewed and tighter Q1 proof for a proved category | — | research |

With the JNRV 2020 thresholds, VOLE-256 is already in category 5, and only the KEM and the hash stand in the way.
For profile 128, category 1 needs +4.8 bits of classical ISD for the KEM, and, with the 2016 thresholds, wpow 10 → 21
and seeds of λ + 12 bits for VOLE-128.

## 5. Limits

- The model counts gates and depth, not qubits or the cost of error correction. Every element is a lower bound: real
  circuits are larger, so the categories here are floors.
- The KEM and ISD costs come from the estimators of the suite (`sillage_common.py`): binary operations without memory
  cost, compared with gates.
- Attacks not listed in § 3 (structural attacks on BRUME-1024q, attacks on regular SD beyond ISD, non-generic quantum
  attacks) are outside the model; their status is that of the documents cited in the README.
- The quantum proofs used here (AEAD Q1, hash) are ours and not reviewed.
