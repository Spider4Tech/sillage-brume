# Documentation index

Every document exists in English and in French. The French version is the reference text: the code and the test names cite it (for example “PREUVES § 4.4” or “piste 8”), and a change to it is mirrored in the English version with the same section numbers.

| English | French (reference) | Content | Status |
|---|---|---|---|
| [`SPEC.md`](SPEC.md) | — (English only for now) | Normative specification: encodings, tables, algorithms and known answers for BRUME-512 and its modes, Sillage-KEM and Sillage-SIG | Draft for review, written from the reference implementation |
| [`PROOFS.md`](PROOFS.md) | [`PREUVES.md`](PREUVES.md) | Assumptions, theorems and proofs for the KEM, the signature, BRUME-512, the AEAD and hash modes; parameter derivations; quantum analysis; what remains outside the proofs | Maintained |
| [`AUDIT_REPORT.md`](AUDIT_REPORT.md) | [`RAPPORT_AUDIT.md`](RAPPORT_AUDIT.md) | Development history: every flaw found (by the test suite, by external reviews or by re-reading), how it was found and how it was fixed; dated errata | Maintained |
| [`LEADS.md`](LEADS.md) | [`PISTES.md`](PISTES.md) | Measured optimisations and research leads that were **not** adopted, and the security conditions under which they could be | Maintained |
| [`DESIGN_NOTE.md`](DESIGN_NOTE.md) | [`guide.md`](guide.md) | The original design note: the “cryptography by decoding” idea behind the suite | Historical; the constructions have since departed from it |
| [`CAMPAIGN_24H.md`](CAMPAIGN_24H.md) | [`CAMPAGNE_24H.md`](CAMPAGNE_24H.md) | How to run the long test and cryptanalysis campaigns on another machine (Linux or Windows through WSL 2) | Operational guide |
| [`GPU_CRYPTANALYSIS_PLAN.md`](GPU_CRYPTANALYSIS_PLAN.md) | [`PLAN_CRYPTANALYSE_GPU.md`](PLAN_CRYPTANALYSE_GPU.md) | Planned GPU cryptanalysis: reduced-round BRUME distinguishers, cubes, hash collisions, quasi-cyclic ISD, reaction attacks | Plan; the first campaign has started (`tests/gpu/`) |
| [`VOLE_CODE_REVIEW.md`](VOLE_CODE_REVIEW.md) | [`REVUE_CODE_VOLE.md`](REVUE_CODE_VOLE.md) | A code review of the VOLE-in-the-Head signature prototype (`prototypes/vole/vole_proto.c`), which is not part of the suite | Review; how each finding was handled is in `LEADS.md`, lead 9 |

## Where results live

`resultats/` keeps only summaries and certificates in the repository: [`SYNTHESE.md`](../resultats/SYNTHESE.md) (latest full test run), [`EMPREINTES.md`](../resultats/EMPREINTES.md) (SHA-256 fingerprints of sources, KATs and results), the benchmarks, and the division-property trail certificates (`pistes_*.json`). These files, the code comments and the test names are in French. Per-test JSON files and campaign logs are produced locally.

## A short French glossary

For reading the code, the test names and the result files:

| French | English |
|---|---|
| preuve, énoncé, hypothèse | proof, statement, assumption |
| borne, majoration | bound, upper bound |
| chiffré, clair | ciphertext, plaintext |
| distingueur, piste | distinguisher, trail (or lead, in `PISTES.md`) |
| tour, débit, capacité | round, rate, capacity |
| contrôle, mesure, témoin | check (pass/fail), measurement, control |
| correctif, errata | correction, errata |
| campagne de nuit | long (overnight) test campaign |
