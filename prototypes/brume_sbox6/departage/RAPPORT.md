# Rapport de départage — BRUME / SBOX6 / SBOX_V3 / SBOX_V4 / candidates du recuit

Rédigé le 11 novembre 2026 selon `PROTOCOLE.md` (règle de décision fixée avant les calculs).
Toutes les valeurs ci-dessous sont relues dans les sorties brutes ; aucune n'est recopiée d'un
journal intermédiaire.

## 1. S-box comparées

| Nom | Table S(0)…S(15) | Origine |
|---|---|---|
| BRUME | `891AC406DF37E2B5` | en service |
| SBOX6 | `F2CDB7E30465A891` | écartée (profil DDT/BCT plat) |
| SBOX_V3 | `E936FBA8C40571D2` | campagne du 8 nov. |
| SBOX_V4 | `A4F60295C873D1BE` | campagne du 9 nov. |
| CAND_A1 | `AD412650BFEC7893` | recuit A1 (départ V3, R1) |
| CAND_A2 | `BC0FE76A5D483291` | recuit A2 (départ V4, R1) |
| CAND_B1 | `5B1C697302F4DAE8` | recuit B1 (départ BRUME, variante R1′ : BCT ≤ 10) |
| CAND_B2 | `17B8F40AC6E3D295` | recuit B2 (variante R1′) |

Les recuits (`resultats/20261110_departage/recuit_*`) minimisent le **prédicteur** B3 (statut MODELE).
Aucune mesure n'a servi à la sélection : toutes les mesures B3 ci-dessous utilisent des graines
indépendantes du recuit.

## 2. Exécutions

| Dossier | Contenu | Machine |
|---|---|---|
| `resultats/20261111_finalistes/` | `run_departage.sh` complet : contrôle, local, D2, B2, L2 (31 fenêtres), D3, L3, B3 2^26 (K = 6), INT 3 bases | CPU, 12 threads, 1 h 01 |
| `resultats/20261111_finalistes_gpu/lg26_K6` | B3 GPU, même sélection et mêmes graines que le run CPU | RTX 4070 Ti |
| `resultats/20261111_finalistes_gpu/lg30_K6` | B3 GPU à 2^30 quartets par mesure | idem |
| `resultats/20261111_finalistes_gpu/lg28_K32` | B3 GPU, sélection élargie à K = 32 (162 combinaisons) | idem |
| `resultats/20261111_finalistes_gpu/balayage_lg14` | B3 **exhaustif** : les 3 686 400 combinaisons (i, a, j′, δ′), confirmation 2^26 | idem |
| `resultats/20261111_finalistes_int16/`, `_int64/` | INT à 16 puis 64 bases | CPU |

Métadonnées (commit `4160aa6`, arbre propre, gcc 16.2.1, SHA-256 des sources, des tables et de
`libsillage.so`) dans chaque dossier. Les étapes GPU lg26 et lg30 ont été compilées depuis la
première version de `b3_gpu.cu` (SHA-256 `fd2549a0…`) ; le noyau a ensuite été factorisé
(`0b7e7050…`) pour ajouter le balayage, sans changer le calcul. Dans les deux cas, chaque mesure
est précédée du contrôle exact C = GPU (§ 3).

## 3. Contrôles (R4) — tous réussis

| Contrôle | Résultat |
|---|---|
| Modèle = `sl_brume_permute_ref` (32 tours, 2 000 états), M·M⁻¹ = I, adjoint, aller-retour, rang 7 | OK |
| Propriétés locales recalculées en Python pur, indépendamment du C (DU, LAT, BCT, lignes DDT, degrés) | identiques pour les 8 S-box |
| D2, B2, L2 : contrôles empiriques à 4 σ (2^24 paires / 2^22 quartets / 2^24 entrées) | 264 fichiers `controles_ok: true`, 0 `false` ; 24 lignes D2/B2/L2 et 240 fenêtres L2 « ctrl=OK » |
| D3, L3 : témoins revérifiés par recalcul indépendant avec M complète | `verif=OK` pour les 16 |
| B3 : reformulation rapide = inversion complète, quartet par quartet | 0 écart (2^16 par mesure CPU, 2^12 / 2^10 par mesure GPU) |
| B3 : comptes GPU = comptes C, même graine | **identiques à l'unité près** : 344 / 344 lignes du run CPU à 2^26 ; contrôle 2^16 (resp. 2^14) avant chaque mesure GPU ; 10 rangs recomptés par S-box dans le balayage |

## 4. Mesures exactes (EXACT_RESTREINT ; D2 promu EXACT par le certificat C2)

| S-box | R1 | BCT | D2 hull max | L2 max (31 fenêtres) | B2 deux couches | D3 (bits) | L3 (bits) |
|---|---|---|---|---|---|---|---|
| BRUME | non (BCT 10) | 10 | 2^-15,989 | 2^-7,830 | 2^-2,300 | 83 | 39 |
| SBOX6 | non (0 ligne DDT max 2) | 6 | 2^-15,978 | 2^-7,892 | 2^-3,000 | 81 | 40 |
| SBOX_V3 | oui | 8 | 2^-16,000 | 2^-7,830 | 2^-2,193 | 86 | 40 |
| SBOX_V4 | oui | 8 | 2^-15,989 | 2^-7,892 | 2^-2,300 | 87 | 40 |
| **CAND_A1** | oui | 8 | **2^-16,000** | 2^-7,830 | 2^-2,300 | 86 | 40 |
| CAND_A2 | oui | 8 | 2^-15,994 | 2^-7,830 | 2^-2,300 | 87 | 40 |
| CAND_B1 | non (BCT 10 ; R1′ oui) | 10 | 2^-15,989 | 2^-7,860 | 2^-2,300 | **88** | 40 |
| CAND_B2 | oui | 8 | 2^-15,989 | 2^-7,830 | 2^-2,300 | 86 | 40 |

## 5. B3 — boomerang à 3 tours (EMPIRIQUE)

Maximum mesuré par S-box, intervalle de Wilson à 4 σ :

| S-box | K = 6, 2^30 quartets | Balayage exhaustif, confirmation 2^26 | argmax (i, a, j′, δ′) |
|---|---|---|---|
| BRUME | 2^-8,476 [-8,480 ; -8,473] | 2^-8,477 | (16, 3, 92, 14) |
| SBOX6 | 2^-8,142 | 2^-8,134 | (16, 9, 92, 9) |
| SBOX_V3 | 2^-8,401 | 2^-8,396 | (16, 6, 92, 11) |
| SBOX_V4 | 2^-7,860 | 2^-7,859 | (16, 7, 92, 7) |
| **CAND_A1** | **2^-8,753 [-8,756 ; -8,749]** | **2^-8,753** | (16, 12, 92, 7) |
| CAND_A2 | 2^-8,659 | 2^-8,662 | (16, 4, 92, 15) |
| CAND_B1 | 2^-8,643 | 2^-8,641 | (16, 10, 92, 15) |
| CAND_B2 | 2^-8,678 | 2^-8,687 | (16, 11, 92, 14) |

- La sélection élargie (K = 32) retrouve exactement les mêmes maxima et arguments.
- **Balayage exhaustif** (nouveau, sur GPU). On mesure les 128 × 15 × 128 × 15 = 3 686 400
  combinaisons de chaque S-box à 2^14 quartets, j′ à portée compris. On confirme ensuite l'union des
  32 meilleurs comptes de chaque S-box, soit 166 combinaisons, avec une graine indépendante. Ces
  166 combinaisons tombent **toutes** sur le couple (i = 16, j′ = 92). C'est le seul couple où 5
  des 7 coefficients M⁻¹[N[16], 92] sont nuls. Le maximum et son argument coïncident avec la
  sélection du prédicteur pour les 8 S-box. La réserve « B3 mesuré = minorant, restreint aux j′
  hors portée et aux K meilleures prédictions » (`AUDIT_LIMITES.md` § 3.3) est donc levée
  empiriquement, pour α et δ′ de poids 1.
- Le couple (16, 92) est une **faiblesse de la couche de diffusion**, indépendante de la S-box.
  Une S-box ne fait que moduler la probabilité de ce couple, de 2^-7,86 à 2^-8,75.

## 6. INT — intégrales (EMPIRIQUE)

Le run complet utilise 3 bases. Un bit déséquilibré y paraît nul par hasard avec une probabilité
1/8 : les écarts observés entre S-box (1 à 16 bits) étaient de cet ordre. À 16 bases, il reste
quelques écarts d'un bit (dont un bit « robuste » de BRUME seule au tour 5). À **64 bases**, tous
disparaissent. Les profils de bits robustes sont **identiques** pour les 8 S-box, à chaque tour,
dans les 18 configurations : direct t = 4 à 20 sur 5 tours, inverse t = 4 à 16 sur 4 tours, deux
géométries. INT ne départage pas ces S-box ; il passe dans la liste de `PROTOCOLE.md` § 1.

## 7. Règle de décision

| S-box | R1 | R2 (aucune régression) | R3 (gain strict) | R4 | Verdict |
|---|---|---|---|---|---|
| SBOX6 | non | non (D3, D2, B3) | — | oui | rejetée |
| SBOX_V3 | oui | non (B2, B3) | — | oui | rejetée |
| SBOX_V4 | oui | non (B3 2^-7,86) | — | oui | rejetée |
| **CAND_A1** | oui | oui | D3 +3, L3 +1, D2 (2^-16,000), B3 −0,28 bit | oui | **satisfait R1–R4** |
| CAND_A2 | oui | oui | D3 +4, L3 +1, D2, B3 −0,18 bit | oui | satisfait R1–R4 |
| CAND_B2 | oui | oui | D3 +3, L3 +1, B3 −0,20 bit | oui | satisfait R1–R4 |
| CAND_B1 | **non** (BCT 10) | oui | D3 +5, L3 +1, L2, B3 −0,17 bit | oui | seulement sous R1′, ajoutée après coup |

R2 « B3 non significativement supérieur » et R3 « B3 significativement meilleur » sont jugés sur
les intervalles de Wilson à 4 σ, disjoints dans tous les cas cités.

**Meilleure candidate : CAND_A1 = `AD412650BFEC7893`.** Elle a le plus petit B3, la seule mesure qui
distingue réellement les S-box optimales dans BRUME-512. Elle a aussi le meilleur D2, égal à celui
de V3, et ne régresse sur aucune mesure. CAND_A2 est meilleure sur D3 (87 contre 86) mais moins
bonne sur B3 et D2. Le choix entre les deux est un arbitrage, pas un résultat.

## 8. Ce que ces résultats ne disent pas

1. **Les gains sont petits.** 0,28 bit sur le pire boomerang à 3 tours, 3 bits sur la meilleure
   caractéristique restreinte à 3 tours, 1 bit en linéaire. Rien ne porte sur 32 tours.
2. **D3 et L3 restent EXACT_RESTREINT, et le certificat tronqué ne peut pas les promouvoir.** La
   promotion exigerait 2·C3 ≥ D3 ≥ 83, soit C3 ≥ 42, et C3 ≥ L3 ≥ 39. Or CP-SAT a déjà exhibé un
   motif réalisable de la relaxation à 30 S-box actives, [4, 21, 5], donc C3 ≤ 30. Plus de temps
   de calcul n'y changera rien. Il faudrait une relaxation qui tienne compte de l'algèbre linéaire
   réelle sur GF(16) (le motif [4, 21, 5] n'est peut-être pas réalisable).
3. **B3 est empirique**, et seulement pour α et δ′ de poids 1. Des différences de poids supérieur ne
   sont pas couvertes.
4. **Le pire boomerang vient de M.** Le couple (16, 92) existe pour toute S-box. Le corriger
   relève de la couche linéaire, pas de ce départage.
5. **Adoption.** Changer la S-box change l'algorithme : KAT, cache de division property
   (`resultats/pistes_division.json`), preuves de portée DP, empreintes, et donc toute la batterie.
   CAND_A1 reste une **proposition** ; la décision revient à l'auteur. `sillage/` n'a pas été modifié.

## 9. Reproduction

```bash
cd prototypes/brume_sbox6/departage
./run_departage.sh resultats/<dossier> CAND_A1=AD412650BFEC7893 CAND_A2=BC0FE76A5D483291 \
    CAND_B1=5B1C697302F4DAE8 CAND_B2=17B8F40AC6E3D295                        # CPU, ≈ 1 h
./run_b3_gpu.sh resultats/<dossier>_gpu/lg30_K6 30 6 CAND_A1=… CAND_A2=… CAND_B1=… CAND_B2=…   # ≈ 11 min
./run_b3_balayage.sh resultats/<dossier>_gpu/balayage_lg14 14 32 26 CAND_A1=… …                   # ≈ 10 min
resultats/20261111_finalistes_int64/lancer.sh                                                    # ≈ 11 min
```

Les scripts GPU compilent dans le conteneur tgh (CUDA 12.9). Ils s'arrêtent (code 1) au premier
écart C/GPU ou au premier écart d'identité. Température GPU : 77 °C au plus aux relevés, jamais 3 lectures de suite ≥ 81 °C (seuil d'alerte du suivi).
