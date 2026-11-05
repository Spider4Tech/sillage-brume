# Empreintes SHA-256 — SILLAGE v0.4

Batterie : 574/574 contrôles, 59 tests.
Python 3.12.3, gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0.

## KAT

| Entrée | Sortie |
|---|---|
| `brume512_hash(b'abc', 32)` | `ce516e8c2af5a81909dbfb9d59225809c86dfcb8e13998392962fd65691dd7bd` |
| `brume512_hash_arbre(b'abc', 32)` | `5dd1dcb0b955987a48097577392c12507b5c4f5726a5ba73687c45bb4496c115` |
| `BRUME-512 AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')` | `1e27b2f1c1e6f77ee42d609bce1c6643ec0525ab11e3fc` |
| `BRUME-512p AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')` | `2bd5853b6dc2c65ab7b555e169695de65ecb2c365eaffa` |

## Sources Python

| Fichier | SHA-256 |
|---|---|
| `sillage/__init__.py` | `ed6fe89e2f5edf82c3cffece84abddb6d07d35cb97fcb8d4abf5a66381bfb23f` |
| `sillage/brume512.py` | `89e4a506c1bd3192ce6f205400a10bff46551d2cb800c3a7a71f7d824f090a15` |
| `sillage/brume512_tables.py` | `3c621e2c86896d46b198301afbe41dd374c7d9f7bd7b78473fa4117765c7c111` |
| `sillage/demo.py` | `71b63d0414bf103ef9fdf7da5012141c499ba444aa1d72819649e447585df5ab` |
| `sillage/rapide.py` | `eac8be0af6d8e6061c210e36ab508d5cbbb328ffbcfaeaa5049f5cfdafcb7600` |
| `sillage/select_params.py` | `fd18de70eb6796e192b9d73b9cc8a9a5c78250f59344ac0843013b9bccd8e4c6` |
| `sillage/sillage_c.py` | `09385de54d153d9a1169402f5e38cda6a3b910d694f4240beb441902ebd76c40` |
| `sillage/sillage_common.py` | `a6eed082af65906daac7f1fbc7a9280da03f071bd421ee96f79ff3e34b5f23be` |
| `sillage/sillage_kem.py` | `522385739deb78e2f34153d46494bd3b16fc8095c42e44363506e80d1786c37f` |
| `sillage/sillage_sig.py` | `c3a66765be93150ce88242b20b56ad28d533cfbee794ef0e20dc983e2e4db112` |

## Sources C et en-têtes générés

| Fichier | SHA-256 |
|---|---|
| `sillage/c/Makefile` | `895fa40561ef4c0c7069644a819ef5daf789d08d5030b4cf809e9291f02a1c1e` |
| `sillage/c/bench.c` | `1239353fa3bb6e3b2b43eb1eca85381ab68a0ff34233db6576c7f134ba17a12e` |
| `sillage/c/brume512.c` | `c5658c11125fabc6bef197aa8153e43e7118f818ae00b4c949c9c59fa61ff262` |
| `sillage/c/brume512_avx2.c` | `333ee50ddde81c87d626f2ee9f71a332b5f1fded21c8ac8643ccc824559222d3` |
| `sillage/c/brume512_simd.h` | `a4f5e25a633485e6569587326eee727eceaa5e49f440a80c0e3f5ab1ffb34afe` |
| `sillage/c/brume512_tables.h` | `007d80ff07b85d9c8f909c09c965375f8fcd92c81df09c3c54007bf09d856792` |
| `sillage/c/commun.c` | `86fcc8eeaae2ab2ce5090c554aba059803201470da38e7bc49b7925cc13498a2` |
| `sillage/c/isd.c` | `b2885305a022218073c77181275d1d9cae3c327abe3025c4f0da0452d59eed50` |
| `sillage/c/kem.c` | `02af924eda3838923bcc2e3608648f9c8a872a5869425fede59d39cc98499f4a` |
| `sillage/c/sig.c` | `071f9d2449d6dc6e7d416e122f48b0f2957710fa9e880d7c7662ccfb11e66e70` |
| `sillage/c/sillage.h` | `34605dce4d11652bb3865fc996ae2ce3b29f28a0e8500ace1d5adfa760d542b2` |

## Tests

| Fichier | SHA-256 |
|---|---|
| `tests/__init__.py` | `bc7d93e2923d07458b29793d8272372e5f66fd8cdbb31688205f6a17cb9b126d` |
| `tests/banc_statiques.py` | `5dc23fa9b575d056ec433c139f93a15757f643149ff4762708703e184fc6d91f` |
| `tests/banc_trails.py` | `72696ef0e252522eb9d99c96ebb690c2a978a3f2e2249ede0232d630b8d18ff5` |
| `tests/banc_wide_trail.py` | `5135fc76d41f2854c40f7bba73d55902da201faf5abb9ed65a0133d0abf6c939` |
| `tests/bench_c.py` | `a38d6f6c857d0f6d52612086bceeff23130ee3796c2e2da1f619e3e5cc8fd651` |
| `tests/bench_perf.py` | `6cd03cbe715503e47756818136b1459964600ed091a7b592c40e4af64e708ba3` |
| `tests/bench_tailles.py` | `2ed7703c77770fb778de05b6b089cecbeccbdedc43acbcf7aac5e22ad1e2dc94` |
| `tests/c/Makefile` | `25bfe69c783e40fc231521595a33b28150a8a9bf8cec8b3466a82d2e2d37dd2b` |
| `tests/c/brume_attaques.c` | `f2d3976342e4f9c7feeab4448f53afa4dfd7912acce7713b0011ad5853b1dec7` |
| `tests/c/brume_gd2.c` | `82f88c7c407a0c5a86a03ba29cb7ca273ca973bfb25614343b16a68e76c2bde4` |
| `tests/c/brume_ref.h` | `9b26ab8feb9c109c0ca47d0d030e0693c2226413b52872acffd815f99f3f701b` |
| `tests/c/compression_kem.c` | `768bd0e181c7db82feb087a6354e90d7a62c11075153e5bf760efb306f0ba201` |
| `tests/c/compression_sig.c` | `b97477e549d98c8262bcc702539ebb72cf9a97472241369a50d1aaadd7eef0e4` |
| `tests/c/diffusion_support.c` | `c7fabb6e23e96763cff33f2126da322404fd9a90c9bf882a7f8e0961fd425d42` |
| `tests/c/fuzz.c` | `a7dd9427cf60f7ad4e838adba96f035b7d552cc5740068cd0ce628aa67eedc0b` |
| `tests/c/garde.c` | `50930a275b518b36a5a63edf1f4c48aeb5c56ab98335f4eec9891908a282dee7` |
| `tests/c/garde_test.c` | `84909ac34274d51460fd223197ab293abe75fe1729021a65cf3796ce4f5b06ce` |
| `tests/c/h1p_fourier.c` | `6f40edad0b61aa8e2350fd5df77814f4d4acb47c13a42fb828f2f762e283a52b` |
| `tests/c/invariants.c` | `dad2131e018a05087f07a18c0d0603212704c46cbc42492660b86f45a6714285` |
| `tests/c/isd_comparaison.c` | `8a6933df5d2267711887c0ea59fd0be2946d6708d28c03bbc0a2a5aea75609fb` |
| `tests/c/isd_reel.c` | `1b1c6853cbded1d0b1c86ee38c33208a4f6ddeb9b900946436529d84fd729f12` |
| `tests/c/kem_distributions.c` | `ccd75e0606fdafcfd86e89032e4eb49fda6e76e07f6a321ff06d1bf6e5ec432b` |
| `tests/c/kem_rejet.c` | `095a5718b149e03d99139453a50d2d8625e531e7206de111cf8a98756e4db170` |
| `tests/c/kem_valgrind.c` | `4000bfb3352ac1b94ff3fd336eb71142adcec13675a50b7da9dbb93bc945deba` |
| `tests/c/mini_brume.c` | `756bde1881bacc74d3b7dab1e82449ec2c97b517e46a370a1873dc5b05e1d637` |
| `tests/c/noyau.c` | `4b6e7584b0f1fba466c11a9a034cda790167556d6e4c4ef3a6463526c1d263d4` |
| `tests/c/nuit_cryptanalyse.c` | `05e5d2588b9689f2cc404d04c3a145a51ee65c1e2a9909997a4788e31fff47b5` |
| `tests/c/nuit_isd.c` | `2c91530e47187ea9e68982b80b292a07a68cae37f4401670ec82b8f6179a1f3e` |
| `tests/c/nuit_kem_reel.c` | `19f0f62098944fce2b301ccbc26a9abe3087c4e9446e28f579b3e164e105aa24` |
| `tests/c/resultat.h` | `65186d1ad0cf9aa1e9b191277d2f73fffbfc58ef00120f841901bd0cf735d2b1` |
| `tests/c/revue_c.c` | `f285a467bb7c66c71e2b6be0f06e0f7cebc5eb061baeadf5e45d239cd9d821cc` |
| `tests/c/rsd_attaques.c` | `e47a1c6af326c7804098bbb873f69eb2fc738b55eebb2ed1684c0d3d0f41d740` |
| `tests/c/sat_trails.c` | `843b03c9c827e3a66bf7f8d75420b6b69e50e96c9af03000aeb3c02503fb8e6d` |
| `tests/c/sig_ct.c` | `17a9a1dde668cd44f84ebeb05da74c96e176c916110d79f39deb655d09e92920` |
| `tests/c/sig_flux.c` | `b2f36ca2694e12b11b7800b59350d08b71f0d2f2257e5d34b7e3e4105aeac697` |
| `tests/c/sig_kz.c` | `dfa8cc225159292c25abd10cac39b4235f15aa68a579e5c3408f9dff5d043bf2` |
| `tests/c/sig_kz_commun.h` | `a35a29224c2983318d442d2aa378d06a3caa6c97dd330c7b83d70c3135daf25e` |
| `tests/c/sig_valgrind.c` | `834f634ed3f1b0c5321fd693b345632f7970855b32a97b88c7fd1d0984d188d3` |
| `tests/c/simd_conformite.c` | `73c2b1507eb2d7a9ee162dcb7a884aaf72cfae10027c6e01d9931b5effa63603` |
| `tests/c/structure_miss.c` | `8064bb4d1267a2f41607723b98920d58b037c1c7ec2b284c006041e0378dc69a` |
| `tests/c/temps.c` | `6179243c8afb959d0c4b79356825f70c044793acbba406592d9c5e7419b57e32` |
| `tests/c/trace_pc.c` | `97300089809ac8bb53d3fc3f183a4c7eff4a069e9737d9aecf58b683383f0741` |
| `tests/commun.py` | `4c42c8e3bb8ff345006777c6ffa1fe08a8cc78ec45181be2d5c044f3edef968e` |
| `tests/dp_cpsat.py` | `9f7efe1431e9a0e0286bb88c77cbaa6484689d7c974a8627ea9e578512013370` |
| `tests/dp_queue.py` | `fdad527d13321006d4a3cedbadb4fca77bfffeb3a3c865da4391481bcfe61425` |
| `tests/dp_sat.py` | `98b1fb72dba68d1acae98369747458819bdb837def7f054d4e30dc81b2aa8733` |
| `tests/empreintes.py` | `6670a7924bfab8370742a8201a62b1008f3f17924c90765150cae3a78c8de68a` |
| `tests/noyau_c.py` | `8b2531d11172dd1a013c40044fa779b2d7d06f53c68bf6623a6981f47a275588` |
| `tests/nuit_brume.py` | `103bf05648c97f70a1dab2184d28aeeb212a3c6f912deb2b6f71d095f77e89c3` |
| `tests/pistes_monomiales.py` | `d3e71c04cd304e754967867f4a2d5fcaafbd646e41d2406ab2b53fcd3ee5f840` |
| `tests/run_all.py` | `ddfd124a1c3798d75375d95e0af168e968d0a627563552bc97ba67fec183be1c` |
| `tests/test_aead.py` | `174b1d4eded90afb749947f1e7ead1470c838aba7b9797b4cf9da55e96fe23a7` |
| `tests/test_aead_modele.py` | `e663adb2d461585c2f492522edadfec7c804e2c381a1e77aa6c30c6299846c5c` |
| `tests/test_aead_parallele.py` | `12cf87ea26acb7b51064dcb0c383457fd9d3bd2cdfb8bc5af119da78182c81ee` |
| `tests/test_api_c.py` | `f208c554c99501c7795996c10e2fe2e4c850ea0504dc050d1328dee84e8ea2b3` |
| `tests/test_banc_cryptanalyse.py` | `8e9333cd247b8f13865e1d1fd4160ce4a17c0b750b156be98720e793451a6b96` |
| `tests/test_beam_trails.py` | `56ec9933df2913378e03dbee67f446524e9fb53feae262c4efa5b492cdf650a4` |
| `tests/test_branch_exact.py` | `992dc0212a81eb6d4e099f9bcc88f124a049f60603c22e4ce0849453a00854cb` |
| `tests/test_brume_algebre.py` | `3c69ee1770987821d63316b32f7f4ff7ad655367d17d344dc97a382f9c4c83ac` |
| `tests/test_c_cube_init.py` | `396b0375b79e50097a872013c615592fe56e7a0938637ef4ec87e713c178c137` |
| `tests/test_c_degre.py` | `620251a9c1693b1c5c9826038463f62238377eda9c1330afad877e937f60b629` |
| `tests/test_c_diff_lin.py` | `67d65a871148e40db872b08df9120be51c7d48818a1873bea98de8980693abd8` |
| `tests/test_c_fuzz.py` | `33733b99ea4da652d7132aac1bac20f13b27a1b85224cc3216ac0f649b5b9be8` |
| `tests/test_c_impl.py` | `aac0692862bfb5ecfc2531fcadb5be8d6a5655dfd9a3cbbb30b73e0c230a9d09` |
| `tests/test_c_integral.py` | `cce3c1eecd94ceb3d7a6c0b7d97d1288ac9272ba67bc8b15c9327e37bef2fba8` |
| `tests/test_c_kem_bruit.py` | `886ae7c06a634728bb73136ea20157d4a6255033d791fed0dadfd083eb26711b` |
| `tests/test_c_kem_valgrind.py` | `a0b9af2b9453a9376e2e645af4058d004b356fc399a089e64e2a24cbec1242ec` |
| `tests/test_c_sac.py` | `96f05eb652fdba3287255323133d71409753e1e086418bd13ae3f74cc60a0a7b` |
| `tests/test_c_sig_valgrind.py` | `ee36d0c92fc538fc368646917717ef35c4b99de3c25c6fd9837adeff88e1f3cc` |
| `tests/test_c_simd.py` | `14693c84c45bf2da834bd78ea746c5c0b0eeca4e965bdffeb31ad973e31514fa` |
| `tests/test_c_statistiques.py` | `20f3b4d5f278e17a16e6fd4cd8a11eddd9985ef27231d426d8cd2833aab9996a` |
| `tests/test_c_temps.py` | `567abb8f22b40864fa8f92cfce2eb39f663337e2614637fa102820ac8c4d9bfd` |
| `tests/test_cycles.py` | `51a723218088e50988fcb480dd42515e366ccc360bf81bdc72e52a76c5861165` |
| `tests/test_diff_lin_empirique.py` | `a6dd68f75f356982c89929b5d0f7b9c21f66f2b7f227bc7797596192ec7ddaab` |
| `tests/test_diffusion_stats.py` | `c2cf152e8aa7f13f6aed5a806f1bce05af6b5c5bf14d613c6e5f8d02646d7a9c` |
| `tests/test_division_property.py` | `0ea52a7add42fd4b2ed8ef41cfba0a1b989511fe52994515a0b3a6358f5992ff` |
| `tests/test_dp_exact.py` | `ede53abeb2360a6c53150e5e2ac7f846a6d2d90cb93b7edb5ce5cf6e5fb37b7c` |
| `tests/test_dp_modele.py` | `604bd5b3453e496bd3337a7390d8aad81d7adff379f70b60255279c941e83b2b` |
| `tests/test_dp_tous_cubes.py` | `5d5f724895a1a4e820b0bcc4bcb08aa3377a79a59d7459b616a47f8b8dc89275` |
| `tests/test_dp_validation.py` | `656d51bb814ef190f95add9ba1cc8dd6bb0eeddb60e338baf8ee332305f5d368` |
| `tests/test_fonctionnel.py` | `f0e4a39ebf502c8ed392669e90f658e14731b082b17e4c04cba1aac4581af6ee` |
| `tests/test_hachage.py` | `11b615831c5b07fbf822ecffda9a46ef348bf31018e6ffbb70af5b7a39b3c61c` |
| `tests/test_hachage_arbre.py` | `938d3a4745d47c545ceef2a2dc8e1936e582c9bb13969bb496320a90a0665713` |
| `tests/test_hull.py` | `4a5fd66aec69e3c241951306459769ca1ff099f6eee719990eb1b416e4e01dab` |
| `tests/test_indiff_arbre.py` | `96a13d3acbfedffe4efc316af2be5d9c06d4cec459380c67dfc785eab0186aa1` |
| `tests/test_integral_degre.py` | `faf0a3f4ebe36036b32f2ce9ccb9de4ba325717d89993b4549c34d6af24c6211` |
| `tests/test_isd_parametres.py` | `f04e1feaf26ba80f3db912b27aec4abf70d0ab8656f0c45b92e86cd60779f65c` |
| `tests/test_kem.py` | `ee187d8c7c12f59a4f92fe237374b178497bc28ce770de30106427e3d77a4402` |
| `tests/test_mode_aead.py` | `dc9d8b9fbc4fff0264011e62e6163c47f9b03c75d1f836009ce2c133dddd1483` |
| `tests/test_robustesse.py` | `4cdd96f277111e518018058451042c265aa9e93da6908d96a2a47fe5f3ba9783` |
| `tests/test_sig.py` | `53231c7da1e69fa5557f84f49923f59fa64a48264c6a365d5326b087d527e12c` |
| `tests/test_sig_modele.py` | `db283b3a25e019fcc5a78bded7761efe1c8be6b3b86ff452c31f6272b8154880` |
| `tests/test_symetries_invariants.py` | `44a97254544ed4ece405b6e84dae21184b842484ff8da1bb82a18327642252a0` |
| `tests/test_te.py` | `889c1dfaf9aad82478719bd734e95ae2be08d3ff606f641891be2c4d9da4cc45` |

## Prototypes (hors suite)

| Fichier | SHA-256 |
|---|---|
| `prototypes/brume_bitslice/Makefile` | `733cfdcfeec79f955ea2b8f6200ce9ef0d57ae50a6abba7c04975483504a508d` |
| `prototypes/brume_bitslice/banc.c` | `b30751a251d3f9882c9c5ef7f59e5e5216091ae64a3a73f463a9ce1b48198804` |
| `prototypes/brume_bitslice/bs.c` | `8a06d5e138c6a587bf3751060e8bc8238428b098e85868f764449ebb3b12f3ee` |
| `prototypes/brume_bitslice/bs.h` | `05e3338b02269a7b487d6a4ba9662b6a961ef18c43ad337b8dd6dad4c0ce3fba` |
| `prototypes/brume_bitslice/compteurs.h` | `c854a3e337bb312ddb548f25b8b2b71185f1b480c52284070afea52b9760ab0c` |
| `prototypes/brume_bitslice/gen_asm.c` | `e481285c3f0fefb0c0217da14ce09b48fe65244423fbed997732de2068923783` |
| `prototypes/brume_bitslice/sbox_bs.h` | `59d1dd128cc13212b981c832287fede57fce947eb0bf62e7e1abc157e70c3691` |
| `prototypes/vole/vole_kat.h` | `b72f26bc437c4685f5175cc3956a3b35540a5fa2f608de77b6d923dfc56cf256` |
| `prototypes/vole/vole_params.c` | `f84f53c714832f392d63a593b3ee84ead5bc0a48f194683dabf4e57ebdf57f06` |
| `prototypes/vole/vole_proto.c` | `a6527cc3f58bdbd7e18c44d909b9900bb7e9b4a57ed8e328071bfad0b66db207` |

## Certificats (pistes de division property)

| Fichier | SHA-256 |
|---|---|
| `resultats/pistes_division.json` | `494c340bc8e669378098f19fed72b49ecc00e11b10e23b65e7ccbb220fe17a6c` |
| `resultats/pistes_exactes.json` | `2c511cd9f6a5a0bed47188d92a5161218fb91f4ff4b49d0d37f65773f7349bfb` |

## Résultats de la batterie

| Fichier | SHA-256 |
|---|---|
| `resultats/SYNTHESE.md` | `6865c713902411a7df4aa16d65264dd6c214c89d3a55adff2243b16927c01700` |
| `resultats/aead.json` | `b91185ddf202b24c80d815a17efa9342e1e833cedd33d2524a2c353ec6dd8d7d` |
| `resultats/aead_modele.json` | `99f38fca951ef123211b2b4d706d70f8a5429e5824af617e6acdd0ad6f703185` |
| `resultats/aead_parallele.json` | `4fb6e0e56e82c5edac3d138353e818e2d4959b883e7ab2acc9d289ddde0efa60` |
| `resultats/api_c.json` | `a6e07688dc0df3fb28ef606ddcbaf99500c9186d2068114fca5cc5389806ec58` |
| `resultats/banc_cryptanalyse.json` | `f2db4cd157152947fdd9701464503e80e982d94d23683a4ee3fc63ce696b006d` |
| `resultats/beam_trails.json` | `c25f4c31e407ebd70df0edf97926eb606cb87b48cb1c4d7ab002dae0d84edfe6` |
| `resultats/bench_c.json` | `f2e2ce15bdd8846a0299918dd86ed3bec59a34a0a80058b7960af98e7f563dad` |
| `resultats/bench_tailles.json` | `e247d79fc9975b776f60d070d59dcd0f01e7e7b021be7d9b94746bba8a71e5d4` |
| `resultats/branch_exact.json` | `cb8b463cbca6c10f59a33532f6bcb2d2d699cd0519ba6687a91d11a91838ca61` |
| `resultats/brume_algebre.json` | `c9b2cfe93c5bd7ca8c151ed8ec1c128caff991e23220cab3de713d0a4900fdae` |
| `resultats/brume_attaques.json` | `4d33c538cee2941ca4b74dc056e99a598de14a5410e7c187cc4665d3d0c2c115` |
| `resultats/brume_gd2.json` | `592a2acdc96337a1ee38801258e22412ab75f2d5f22a55be4dc6619222aa8d7c` |
| `resultats/brume_gpu.json` | `680830ff99cf9ed43e69bf47262ddca943ac3409db16ed46c08b2cb4f54c379c` |
| `resultats/c_cube_init.json` | `fa6cd415f544625ea053f444e2ade7aad33dff8f017d942e632fac8a695aa91a` |
| `resultats/c_degre.json` | `61a75ceb9b0498710adcd614823ca9fbcd1bb8236fdde8fda4f66d75ce164acb` |
| `resultats/c_diff_lin.json` | `b32482ded8dcac7b8901d777cc60ab3f6f322fd3c9384750fc47008b25a695ed` |
| `resultats/c_diff_lin_x4.json` | `5000755ba3699799516cd4e061e294f9d82296ba46bb6920637041941126537b` |
| `resultats/c_fuzz.json` | `0c4c0eef52395633eb33f1d76363f8584b8515b4da2a0cbbeb9bffa0d7c8e5a3` |
| `resultats/c_impl.json` | `5b68d34b38d532b09d26080b3dbe62c8cf14657f81c5c4cfa94d1eb7a1b85e89` |
| `resultats/c_integral.json` | `fe17e47315c4fb3969e4b86977b234ed7416ff26ed6234d91d8504eda98b4157` |
| `resultats/c_integral_x8.json` | `886d2341ef7325edd1ecb465617f98c7cea2180ada2cc73b4140830cefdcef13` |
| `resultats/c_kem_bruit.json` | `1f50ee040f65cde03400cf88610d39d3e2a86f0eff5c143661dddd7d393890d2` |
| `resultats/c_kem_bruit_x4.json` | `776cebd292199f6f376f7975ca4b903dc6e7c01ff0f119753d11545229097989` |
| `resultats/c_kem_valgrind.json` | `b9ec1bc5a3fd0c71bf23539ebf54afb120c26a4207456ab7e3718301fa07cb0f` |
| `resultats/c_sac.json` | `abaeea3551c2d705fc67a3adf0831e98f2667821e6dbfe03ab5ef3bbc3859582` |
| `resultats/c_sac_x4.json` | `591df87caff6c769a69a8445b2d1068bc64e5dd44d9661014f19288ee9bbff3f` |
| `resultats/c_sig_valgrind.json` | `0bc530416f6d361f1e523c8f22d70982e4ddaa1c6f2d67f88f9edb43357837b3` |
| `resultats/c_simd.json` | `1831c6a5c65f744ca2f8a037c1600e760b5f86faa6db8e08396449bd09aebf45` |
| `resultats/c_statistiques.json` | `871cf2efb1925d19001c1296f67ae7582ee3a63391c9b0977df8c02d4b0f85f6` |
| `resultats/c_statistiques_x4.json` | `cd06d13fc74fba027fffeeb6ffc592326eacba48922cd57a58b16bfad88d8610` |
| `resultats/c_temps.json` | `a874d23eadd80a77ee3c9dfa8e61e5236397e457f01190f0aa97f5c7e05dad6c` |
| `resultats/cache_trails.json` | `4833b63ca63002838b96bcdc17487a3dfd682868fde7d00bd3213e46b141cb14` |
| `resultats/compression_kem.json` | `ad2119229ebf21ea5907c8aeb4e62f7dcd1b35815b5b6aff087aecc3de248785` |
| `resultats/compression_sig.json` | `feee314a3c2e1aec4d1bfd5adb84f8a737c1de0e224c436a0b93e176e38c6bf8` |
| `resultats/cycles.json` | `1325f0c84f64a060da5fee19555a1949e11a011106b1c046d10de0ddc76b847d` |
| `resultats/diff_lin_empirique.json` | `6b38121822fadfef4c7d2f8f7fc6dd7c37385d5a157c3e5cd9ed9d14b7776836` |
| `resultats/diffusion_stats.json` | `815bb71b5c1f6acd0f8ca8a9d0addd27d7cd3646b39052605622987f610d324d` |
| `resultats/diffusion_support.json` | `290d83404f63dfecfd311429ea6e1df23826703f091a89771abc125abd2254ea` |
| `resultats/division_property.json` | `df0ee81372305023144cbc21f8822484b922609095997d2af05b1bbef0c4a625` |
| `resultats/dp_exact.json` | `e3c7fd727e4a83b4dd722e48c81bfd53a9e6d9577e6fa1c019a00dbb2a43f009` |
| `resultats/dp_modele.json` | `43b7e88054650f5bb9222963dcf91806d7df60188adadf0abbe8c279bb10a7d1` |
| `resultats/dp_tous_cubes.json` | `c8074279fe3b598b82c1c292f417149859deb37ad73ef8cee15e8d5ede1c7564` |
| `resultats/dp_validation.json` | `8d0497b43e5d55c10d9bedb273cafa133aebc85a58855ca931482fdd9e410ca5` |
| `resultats/fonctionnel.json` | `a4a6f4f43956f1c7db8754dd93f106e633e325eb97b31c48a3d1f77544c0ff7f` |
| `resultats/gpu_dl.json` | `fdbc0497ff58afec5e729ad90e1ce18b3f1aeb7c8c18c40b91f03f36152c3ef4` |
| `resultats/h1p_fourier.json` | `0dec37c4f7dcb819f05149ec119af45fccbbedef48ac9bc748174f4d55e3c7a0` |
| `resultats/hachage.json` | `bf1f99c5dc6f8ca3d595abe4cebd66f684dfa25829afa403219d587d150e3719` |
| `resultats/hachage_arbre.json` | `886483087de7e4ead5ba8063dff669effbc3941401baf3538a7c742e988c5936` |
| `resultats/hull.json` | `90342c2b045a3233873297de0461a8962785c69086ccba82fff224999d83e43b` |
| `resultats/indiff_arbre.json` | `2d8bc1405130c7539c4849e1e2d6c1a20fd0a736a8d1eed71f421d8776959b8c` |
| `resultats/integral_degre.json` | `5f03cdcea50d8d2482c954b85bde8e947dcc8c4d311c8d34f1e440f39e6a0ca5` |
| `resultats/invariants.json` | `da13f3f5027ba37f8449286621e401017c775ad3ae962f337660b9ffd18f1463` |
| `resultats/isd_comparaison.json` | `cbf2bd2e5de2cb5385abbe0bb2e1dc3c455f20e90738816e16b6a5f66f104d4e` |
| `resultats/isd_parametres.json` | `a9e29894105ece7d9157eae1fab5961a0faea6e5df2eabe958c849fe9d7aebf8` |
| `resultats/isd_reel.json` | `ff79972f5125fd007c12cc27e1155d424384db95478ea00c87fce73a44e7f339` |
| `resultats/kem.json` | `a9f38fca78f1083568c97884d03530a1c71abb92682b09c08d01c774e0d97088` |
| `resultats/kem_distributions.json` | `411c3cdd0adf88173757fd7491e39a4cb53774b9feee18adaf9074341636e95c` |
| `resultats/kem_rejet.json` | `781b9c91d10c51a18698ea52a4ac4194eb6310dc63e6ddbe470b42895ef12fe9` |
| `resultats/mini_brume.json` | `107136a548045c2209cac0021c10caabf898d1eaf2fb32f3404f869a73528573` |
| `resultats/mini_brume_detail.json` | `11df7f972256f1ef88728b3f871619d4331a80965bbef71c17a868a347d031b3` |
| `resultats/mini_brume_instances.json` | `2b3faff303072706ac13b888384474b173fa1ee0a859013d12eeecc366c71cf4` |
| `resultats/mode_aead.json` | `d1cdd256eb031796b28dd9c790a180aa411a63225dc7de0c0d82a7aa4053c389` |
| `resultats/nuit_brume.json` | `2909aae8eda445af818cd70e677718f605980331bfd7b344bd7dd71087050650` |
| `resultats/nuit_cryptanalyse.json` | `2972fd2241473f8f20b2c776c4a1e440409c61de8fa2b287ba410c1a0f49519d` |
| `resultats/nuit_fuzz.json` | `820f29006ad65afeb5f89677ef64874eaa66bc479b6b334577d8b7316d8e1570` |
| `resultats/nuit_isd.json` | `ec4ec849e7c5e65d4e8edf4f74faf3dc23b0d11b5512c4f89da5ae9cf44293bd` |
| `resultats/nuit_kem_reel.json` | `0886be6f0f952e2e570d7071a8ce4c7cb0c3acd7aba8e587ae3ff9bbe599a128` |
| `resultats/nuit_temps.json` | `394576598e1e4df1d48a569013a4ce385dadf6c2f5f8dd680d2638b0ac5c6447` |
| `resultats/nuit_vole.json` | `841454e0bc6bb932e3ed18f9db09e8e003e76b85abc40a63282f7c8e20430f03` |
| `resultats/revue_c.json` | `4ba04534bbc9821d8b1184407d492669946877f654f9271b024298a5bf78debf` |
| `resultats/robustesse.json` | `dee2869f81b3969019cde6a36cb8c83227bf7405f22f48b77c2e193cf5cdff5b` |
| `resultats/rsd_attaques.json` | `a42b56e8b9b273549675547ef4bb9b5a5a5844375c265596ca4a8b91e54a2ebc` |
| `resultats/sig.json` | `2c83f5f37976ebeceb1b331e28ce0fe1865f936bf13796a7ad90dfa560d24853` |
| `resultats/sig_flux.json` | `e121427e838cc942b7f91b43a854cd9b5cfdb754e9f1d44572fcf0c00344ef67` |
| `resultats/sig_kz.json` | `f46ab751ab9461b5690f01042698bd4acc185e6563173e3e880c3072b976b3a8` |
| `resultats/sig_modele.json` | `adcf2ad501e8d2a3d0658cb810f9af9f2a76ab3e804aa81ba98c5ce65580304e` |
| `resultats/statiques.json` | `3a82c07a40ce053af6bb5815c193ae0a865099e1d7cbf907f604e0584193ea5f` |
| `resultats/structure_miss.json` | `792d62c718361c1fbbbfda9a320889fdec7dd8d414e2608cd2699483be50df7d` |
| `resultats/symetries_invariants.json` | `14c13d99a122f55bcdae93efb5e6e7abfb7d9c4e678822482983a13ac7d534a9` |
| `resultats/synthese.json` | `d0a72ee43a0f4e68be4c4d8702459bf4f7e6ca18675296ccb3f853c0072c9d3d` |
| `resultats/te.json` | `19b3b92d061b07253c7b7dc732bc4d1169c01cdfc66036566ac47dc88ad4838c` |
| `resultats/trails.json` | `f149e63c675ec2061ffdd1d9240ae9a34a72b2b72d8f9f34f45180a3ec59797f` |
| `resultats/vole_params.json` | `30e65f8e34624898f81e0c2c512615eb9568226da2d185414e95c709ccc71973` |
| `resultats/vole_proto.json` | `d7822a9312d5e4848958a4126940be3a84ebb8fed831846cd794901ba437cb72` |
| `resultats/wide_trail.json` | `908b2ded5bf3ecfb84c1a3a4071b4d1fd8e5c6baa7bce91a6a89a56926ba3657` |

## Preuves et rapports

| Fichier | SHA-256 |
|---|---|
| `docs/AUDIT_EXTERNE.md` | `15181ffed3a873c321f66b349144a0030f07e45f021e088b030613a554ca0a31` |
| `docs/AUDIT_REPORT.md` | `77edab51ac73500339fea3f17d27174534a00955ba74c3d30294bc39363b3f10` |
| `docs/CAMPAIGN_24H.md` | `b043a4c2e76e9e3702fc9213a4f38acd940ae537e432d6dbbe74a4a23548ad5a` |
| `docs/DESIGN_NOTE.md` | `ade0afa112999029530930f6312ffe3df5cd65f9b6a827357326ff7bf560c29e` |
| `docs/GPU_CRYPTANALYSIS_PLAN.md` | `1a5e1c43ac2bfd0ba070296d917d7cd5c5630b52bc51e5ab21b2deb9048016dc` |
| `docs/LEADS.md` | `bc0a762fd59d7485e682bfc87b6b1ff3ce6b37aaa75c23c9fe7a542d5ce8c901` |
| `docs/PROOFS.md` | `834f018b002b1d243d76ceca33ecf486465785d3223d16f8882e05b45e1ba9c8` |
| `docs/README.md` | `4f0e217d68503311cf42fbc8d4405146959d5bc5462d9a67e36e17ec5ba8efdb` |
| `docs/REVUE_CODE_DEPOT_C.md` | `9185183f7c008508342eae0f3ce3b19077c6bbe671645584c766337c88c7e2f1` |
| `docs/SPEC.md` | `a43e07484913c3730768340304714353b77f020850e13fbc79b4de982919008c` |
| `docs/VOLE_CODE_REVIEW.md` | `6ac1e10eb0acb9392a80dcf50820734b20555713997b7f948ab76c59e4df4e1b` |
| `docs/rapport-piste-compression.md` | `1d79705c40b5be919a7c0124543868c777a5994373a4da25d248baa75f40ccac` |
| `docs/rapport31codex.md` | `367dac368aa8582b826df979f3323ad822dd42b0252294d3956373283e181c60` |
