# Empreintes SHA-256 — SILLAGE v0.4

Batterie : 533/534 contrôles, 53 tests.
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
| `sillage/brume512.py` | `a51ffbd37edc928164fb5d941b0781fbbbda2ca1beb63eda0bc11c71d9b32644` |
| `sillage/brume512_tables.py` | `3c621e2c86896d46b198301afbe41dd374c7d9f7bd7b78473fa4117765c7c111` |
| `sillage/demo.py` | `71b63d0414bf103ef9fdf7da5012141c499ba444aa1d72819649e447585df5ab` |
| `sillage/rapide.py` | `eac8be0af6d8e6061c210e36ab508d5cbbb328ffbcfaeaa5049f5cfdafcb7600` |
| `sillage/select_params.py` | `fd18de70eb6796e192b9d73b9cc8a9a5c78250f59344ac0843013b9bccd8e4c6` |
| `sillage/sillage_c.py` | `8d0653f9e2cb75542c8c974da1df28b1e45cfe21817d3e80f413a9c212b7d1de` |
| `sillage/sillage_common.py` | `a6eed082af65906daac7f1fbc7a9280da03f071bd421ee96f79ff3e34b5f23be` |
| `sillage/sillage_kem.py` | `0b99fd4bb94445116f31904874efe65491e243e70f281bef5df1fceb96f9ead5` |
| `sillage/sillage_sig.py` | `be31a5b97577741027506c3ff0dc1dc1d791c0acc5caee98008c90a0815fbb1e` |

## Sources C et en-têtes générés

| Fichier | SHA-256 |
|---|---|
| `sillage/c/Makefile` | `895fa40561ef4c0c7069644a819ef5daf789d08d5030b4cf809e9291f02a1c1e` |
| `sillage/c/bench.c` | `1239353fa3bb6e3b2b43eb1eca85381ab68a0ff34233db6576c7f134ba17a12e` |
| `sillage/c/brume512.c` | `ba67b6484cb50a4de7f0337b7147041eccca5aa23ac928123601d02012101d6e` |
| `sillage/c/brume512_avx2.c` | `b6f9e2fd2b640658a1442e4b4f9642c5884715504400fc6b12777869f7a5e09d` |
| `sillage/c/brume512_simd.h` | `a4f5e25a633485e6569587326eee727eceaa5e49f440a80c0e3f5ab1ffb34afe` |
| `sillage/c/brume512_tables.h` | `007d80ff07b85d9c8f909c09c965375f8fcd92c81df09c3c54007bf09d856792` |
| `sillage/c/commun.c` | `4905ccf725dff3009fa4618a886da57aa3cc92550a199ca4f7751a14429a659e` |
| `sillage/c/isd.c` | `b2885305a022218073c77181275d1d9cae3c327abe3025c4f0da0452d59eed50` |
| `sillage/c/kem.c` | `c21e8ecb750fc8481a1e73f835a80a25c529dc00d601c5226f6af5d3e45e90ca` |
| `sillage/c/sig.c` | `c4b1f3f11a1fea196e93873f0a13d8c0edc06cb62089cb7f4dd2f0d0e198058b` |
| `sillage/c/sillage.h` | `dd3cfa243096b3665c4454c4e959007239d4f2e70e399127ff380708f4139f97` |

## Tests

| Fichier | SHA-256 |
|---|---|
| `tests/__init__.py` | `bc7d93e2923d07458b29793d8272372e5f66fd8cdbb31688205f6a17cb9b126d` |
| `tests/banc_statiques.py` | `5dc23fa9b575d056ec433c139f93a15757f643149ff4762708703e184fc6d91f` |
| `tests/banc_trails.py` | `72696ef0e252522eb9d99c96ebb690c2a978a3f2e2249ede0232d630b8d18ff5` |
| `tests/banc_wide_trail.py` | `5135fc76d41f2854c40f7bba73d55902da201faf5abb9ed65a0133d0abf6c939` |
| `tests/bench_c.py` | `908e0eadafa6b89650d3c75406a1b39d8677cceb95014abb74485d457c7f6995` |
| `tests/bench_perf.py` | `6cd03cbe715503e47756818136b1459964600ed091a7b592c40e4af64e708ba3` |
| `tests/bench_tailles.py` | `2ed7703c77770fb778de05b6b089cecbeccbdedc43acbcf7aac5e22ad1e2dc94` |
| `tests/c/Makefile` | `d6000c82915f651fc62ad51411a71941c5cd5532bcab618c2b452686941fb61e` |
| `tests/c/brume_attaques.c` | `f2d3976342e4f9c7feeab4448f53afa4dfd7912acce7713b0011ad5853b1dec7` |
| `tests/c/brume_ref.h` | `9b26ab8feb9c109c0ca47d0d030e0693c2226413b52872acffd815f99f3f701b` |
| `tests/c/compression_kem.c` | `ccc134e69567899694737029acc3e6c0bdc292049acce4576d700648d062e1c5` |
| `tests/c/compression_sig.c` | `b97477e549d98c8262bcc702539ebb72cf9a97472241369a50d1aaadd7eef0e4` |
| `tests/c/diffusion_support.c` | `c7fabb6e23e96763cff33f2126da322404fd9a90c9bf882a7f8e0961fd425d42` |
| `tests/c/fuzz.c` | `f6d20a1d844ca0e4d7ccf54a27d0b14d4af22d3d4522630fed5c4c8323ffc0dd` |
| `tests/c/garde.c` | `50930a275b518b36a5a63edf1f4c48aeb5c56ab98335f4eec9891908a282dee7` |
| `tests/c/garde_test.c` | `84909ac34274d51460fd223197ab293abe75fe1729021a65cf3796ce4f5b06ce` |
| `tests/c/isd_comparaison.c` | `8a6933df5d2267711887c0ea59fd0be2946d6708d28c03bbc0a2a5aea75609fb` |
| `tests/c/isd_reel.c` | `1b1c6853cbded1d0b1c86ee38c33208a4f6ddeb9b900946436529d84fd729f12` |
| `tests/c/kem_distributions.c` | `ccd75e0606fdafcfd86e89032e4eb49fda6e76e07f6a321ff06d1bf6e5ec432b` |
| `tests/c/kem_valgrind.c` | `4000bfb3352ac1b94ff3fd336eb71142adcec13675a50b7da9dbb93bc945deba` |
| `tests/c/mini_brume.c` | `dc88028e62404b66c575cb2a28e07b46a6a89b1293f69bc3711bfe6f70f5e6f3` |
| `tests/c/noyau.c` | `4b6e7584b0f1fba466c11a9a034cda790167556d6e4c4ef3a6463526c1d263d4` |
| `tests/c/nuit_cryptanalyse.c` | `4a1fbc7c10efc14c234a8a77a1ace487b4d1ad12c0ff46caf650354fa362f56a` |
| `tests/c/nuit_isd.c` | `2c91530e47187ea9e68982b80b292a07a68cae37f4401670ec82b8f6179a1f3e` |
| `tests/c/nuit_kem_reel.c` | `19f0f62098944fce2b301ccbc26a9abe3087c4e9446e28f579b3e164e105aa24` |
| `tests/c/resultat.h` | `65186d1ad0cf9aa1e9b191277d2f73fffbfc58ef00120f841901bd0cf735d2b1` |
| `tests/c/rsd_attaques.c` | `e47a1c6af326c7804098bbb873f69eb2fc738b55eebb2ed1684c0d3d0f41d740` |
| `tests/c/sig_ct.c` | `17a9a1dde668cd44f84ebeb05da74c96e176c916110d79f39deb655d09e92920` |
| `tests/c/sig_flux.c` | `7bddabedc3d6e5c0ea2112dd3d8fa7a5b7f1095f43dc38848bc18e6f8073d382` |
| `tests/c/sig_valgrind.c` | `834f634ed3f1b0c5321fd693b345632f7970855b32a97b88c7fd1d0984d188d3` |
| `tests/c/simd_conformite.c` | `73c2b1507eb2d7a9ee162dcb7a884aaf72cfae10027c6e01d9931b5effa63603` |
| `tests/c/structure_miss.c` | `8064bb4d1267a2f41607723b98920d58b037c1c7ec2b284c006041e0378dc69a` |
| `tests/c/temps.c` | `f59b5aadb5b6d33dec9461bd80b172771d2d1150da9aca2d9234534a3d77d368` |
| `tests/c/trace_pc.c` | `97300089809ac8bb53d3fc3f183a4c7eff4a069e9737d9aecf58b683383f0741` |
| `tests/c/vole_kat.h` | `b72f26bc437c4685f5175cc3956a3b35540a5fa2f608de77b6d923dfc56cf256` |
| `tests/c/vole_params.c` | `f84f53c714832f392d63a593b3ee84ead5bc0a48f194683dabf4e57ebdf57f06` |
| `tests/c/vole_proto.c` | `1cfd017e4ea4d6ea0668e0b6eda8b9977b8c702450f7231248fc0b94edcd9777` |
| `tests/commun.py` | `4c42c8e3bb8ff345006777c6ffa1fe08a8cc78ec45181be2d5c044f3edef968e` |
| `tests/dp_cpsat.py` | `9f7efe1431e9a0e0286bb88c77cbaa6484689d7c974a8627ea9e578512013370` |
| `tests/dp_queue.py` | `fdad527d13321006d4a3cedbadb4fca77bfffeb3a3c865da4391481bcfe61425` |
| `tests/dp_sat.py` | `98b1fb72dba68d1acae98369747458819bdb837def7f054d4e30dc81b2aa8733` |
| `tests/empreintes.py` | `b774f1ed3a4c72df921746679a71618f37729101b1a13cf04356db681e0634f0` |
| `tests/noyau_c.py` | `8b2531d11172dd1a013c40044fa779b2d7d06f53c68bf6623a6981f47a275588` |
| `tests/nuit_brume.py` | `608bccf35ed1aca14db41d11a7f70fde026e6763b7f09d4ebdbce904921325ac` |
| `tests/pistes_monomiales.py` | `d3e71c04cd304e754967867f4a2d5fcaafbd646e41d2406ab2b53fcd3ee5f840` |
| `tests/run_all.py` | `f887fe2ab7fb4c95c7f07fc6235822418ed4a4afa2d8ee28f680a166b8650403` |
| `tests/test_aead.py` | `174b1d4eded90afb749947f1e7ead1470c838aba7b9797b4cf9da55e96fe23a7` |
| `tests/test_aead_modele.py` | `e663adb2d461585c2f492522edadfec7c804e2c381a1e77aa6c30c6299846c5c` |
| `tests/test_aead_parallele.py` | `3792c928a5c703c745049347d247a9e6dcd3bb216e37cf0405579fdb7bbdf44d` |
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
| `tests/test_c_kem_bruit.py` | `c70ef79bb3cd10fae0e9ad68c68e3a82c17cef3da38a578c05ea99ae9896ab18` |
| `tests/test_c_kem_valgrind.py` | `a0b9af2b9453a9376e2e645af4058d004b356fc399a089e64e2a24cbec1242ec` |
| `tests/test_c_sac.py` | `96f05eb652fdba3287255323133d71409753e1e086418bd13ae3f74cc60a0a7b` |
| `tests/test_c_sig_valgrind.py` | `ee36d0c92fc538fc368646917717ef35c4b99de3c25c6fd9837adeff88e1f3cc` |
| `tests/test_c_simd.py` | `72015fd5ef1f648516533f989ee6d91a0d4d2a5a7c760e8ae06233c8faafb357` |
| `tests/test_c_statistiques.py` | `87cef4429f1723a14889ac367b998896bc877747bd479763115753d323184683` |
| `tests/test_c_temps.py` | `e181a9fef9ffdb41cc4f6b08143d2151512c9ef9026326c561fdd2cd1748a937` |
| `tests/test_cycles.py` | `51a723218088e50988fcb480dd42515e366ccc360bf81bdc72e52a76c5861165` |
| `tests/test_diff_lin_empirique.py` | `4799c70ce678caa272a0607401c8c1b26c8519ee02e907a13c0d6d82627a94af` |
| `tests/test_diffusion_stats.py` | `c2cf152e8aa7f13f6aed5a806f1bce05af6b5c5bf14d613c6e5f8d02646d7a9c` |
| `tests/test_division_property.py` | `0ea52a7add42fd4b2ed8ef41cfba0a1b989511fe52994515a0b3a6358f5992ff` |
| `tests/test_dp_exact.py` | `ede53abeb2360a6c53150e5e2ac7f846a6d2d90cb93b7edb5ce5cf6e5fb37b7c` |
| `tests/test_dp_modele.py` | `604bd5b3453e496bd3337a7390d8aad81d7adff379f70b60255279c941e83b2b` |
| `tests/test_dp_tous_cubes.py` | `5d5f724895a1a4e820b0bcc4bcb08aa3377a79a59d7459b616a47f8b8dc89275` |
| `tests/test_dp_validation.py` | `656d51bb814ef190f95add9ba1cc8dd6bb0eeddb60e338baf8ee332305f5d368` |
| `tests/test_fonctionnel.py` | `f0e4a39ebf502c8ed392669e90f658e14731b082b17e4c04cba1aac4581af6ee` |
| `tests/test_hachage.py` | `11b615831c5b07fbf822ecffda9a46ef348bf31018e6ffbb70af5b7a39b3c61c` |
| `tests/test_hachage_arbre.py` | `d168614e2fb4148f7a2ea813087d51a26f33d811cc847d30415eb8b3810c5121` |
| `tests/test_hull.py` | `4a5fd66aec69e3c241951306459769ca1ff099f6eee719990eb1b416e4e01dab` |
| `tests/test_indiff_arbre.py` | `3eac302e51a333781abc0068589ea3d81b2ce1846547fdf8a06be0eb6d8be196` |
| `tests/test_integral_degre.py` | `faf0a3f4ebe36036b32f2ce9ccb9de4ba325717d89993b4549c34d6af24c6211` |
| `tests/test_isd_parametres.py` | `2a55c14d4cdcaabe27576b78007553949578b12a6834b3af583e9ac98e717c3c` |
| `tests/test_kem.py` | `83e96e05073e6ef27aab771f1c9fbed3b276a514cd18d1820d5086d89706ad1f` |
| `tests/test_mode_aead.py` | `f2ef9157de7302a6e86c67dbc9c68f8812079ffe6390426de60a67ad01d577d2` |
| `tests/test_robustesse.py` | `4cdd96f277111e518018058451042c265aa9e93da6908d96a2a47fe5f3ba9783` |
| `tests/test_sig.py` | `a693151ab9d3988c87007173bdfbaaa7263950d29008f3b9db83b2159e7fbb03` |
| `tests/test_sig_modele.py` | `90ce4393e48dd025bc0bffd6858914f8ae7fd8957992bdb5f960406f05369320` |
| `tests/test_symetries_invariants.py` | `44a97254544ed4ece405b6e84dae21184b842484ff8da1bb82a18327642252a0` |
| `tests/test_te.py` | `889c1dfaf9aad82478719bd734e95ae2be08d3ff606f641891be2c4d9da4cc45` |

## Certificats (pistes de division property)

| Fichier | SHA-256 |
|---|---|
| `resultats/pistes_division.json` | `494c340bc8e669378098f19fed72b49ecc00e11b10e23b65e7ccbb220fe17a6c` |
| `resultats/pistes_exactes.json` | `2c511cd9f6a5a0bed47188d92a5161218fb91f4ff4b49d0d37f65773f7349bfb` |

## Résultats de la batterie

| Fichier | SHA-256 |
|---|---|
| `resultats/SYNTHESE.md` | `654dd47bd8e0ba3537564b03ac3da165e46df124a8b654f6a8bc5e3675dd5108` |
| `resultats/aead.json` | `b91185ddf202b24c80d815a17efa9342e1e833cedd33d2524a2c353ec6dd8d7d` |
| `resultats/aead_modele.json` | `38def47f98b116cc7da599ffc3db66785158e4aff9a9665204f8285cf79ae962` |
| `resultats/aead_parallele.json` | `d428b94ff6becb56284d69fcf74801667c4005140cf1b2b4c4cadc5d18728e15` |
| `resultats/api_c.json` | `a6e07688dc0df3fb28ef606ddcbaf99500c9186d2068114fca5cc5389806ec58` |
| `resultats/banc_cryptanalyse.json` | `f2db4cd157152947fdd9701464503e80e982d94d23683a4ee3fc63ce696b006d` |
| `resultats/beam_trails.json` | `c25f4c31e407ebd70df0edf97926eb606cb87b48cb1c4d7ab002dae0d84edfe6` |
| `resultats/bench_c.json` | `f2e2ce15bdd8846a0299918dd86ed3bec59a34a0a80058b7960af98e7f563dad` |
| `resultats/bench_tailles.json` | `e247d79fc9975b776f60d070d59dcd0f01e7e7b021be7d9b94746bba8a71e5d4` |
| `resultats/branch_exact.json` | `cb8b463cbca6c10f59a33532f6bcb2d2d699cd0519ba6687a91d11a91838ca61` |
| `resultats/brume_algebre.json` | `2fba31a842c564b01e14959ab8973805e6f885355c16e57100233226689a55c1` |
| `resultats/brume_attaques.json` | `86b6f7fbff1b06591d894a1f6eb1c1a10d7bbe7837270a234c0bc7e8d3561329` |
| `resultats/c_cube_init.json` | `fa6cd415f544625ea053f444e2ade7aad33dff8f017d942e632fac8a695aa91a` |
| `resultats/c_degre.json` | `61a75ceb9b0498710adcd614823ca9fbcd1bb8236fdde8fda4f66d75ce164acb` |
| `resultats/c_diff_lin.json` | `b32482ded8dcac7b8901d777cc60ab3f6f322fd3c9384750fc47008b25a695ed` |
| `resultats/c_diff_lin_x4.json` | `5000755ba3699799516cd4e061e294f9d82296ba46bb6920637041941126537b` |
| `resultats/c_fuzz.json` | `0c4c0eef52395633eb33f1d76363f8584b8515b4da2a0cbbeb9bffa0d7c8e5a3` |
| `resultats/c_impl.json` | `9f4bd64545971f000e373a2e370afed19870d885c98a8fd0ebdd55ff622176c7` |
| `resultats/c_integral.json` | `fe17e47315c4fb3969e4b86977b234ed7416ff26ed6234d91d8504eda98b4157` |
| `resultats/c_integral_x8.json` | `886d2341ef7325edd1ecb465617f98c7cea2180ada2cc73b4140830cefdcef13` |
| `resultats/c_kem_bruit.json` | `e4fc711c9e2a3ea541f1c3a497f27225b15ca50440d2349311182379a88d0800` |
| `resultats/c_kem_bruit_x4.json` | `776cebd292199f6f376f7975ca4b903dc6e7c01ff0f119753d11545229097989` |
| `resultats/c_kem_valgrind.json` | `b9ec1bc5a3fd0c71bf23539ebf54afb120c26a4207456ab7e3718301fa07cb0f` |
| `resultats/c_sac.json` | `abaeea3551c2d705fc67a3adf0831e98f2667821e6dbfe03ab5ef3bbc3859582` |
| `resultats/c_sac_x4.json` | `591df87caff6c769a69a8445b2d1068bc64e5dd44d9661014f19288ee9bbff3f` |
| `resultats/c_sig_valgrind.json` | `0bc530416f6d361f1e523c8f22d70982e4ddaa1c6f2d67f88f9edb43357837b3` |
| `resultats/c_simd.json` | `1831c6a5c65f744ca2f8a037c1600e760b5f86faa6db8e08396449bd09aebf45` |
| `resultats/c_statistiques.json` | `e99ef8a5d938d026c1302c8f61c0b2feaad652026b46c6bcc7ef0419641220e4` |
| `resultats/c_statistiques_x4.json` | `cd06d13fc74fba027fffeeb6ffc592326eacba48922cd57a58b16bfad88d8610` |
| `resultats/c_temps.json` | `e668de7d06fe0ab5a223a4535c426cc289cac5bbe04e8b5c7513fbf7bf67e6f7` |
| `resultats/cache_trails.json` | `4833b63ca63002838b96bcdc17487a3dfd682868fde7d00bd3213e46b141cb14` |
| `resultats/compression_kem.json` | `ad2119229ebf21ea5907c8aeb4e62f7dcd1b35815b5b6aff087aecc3de248785` |
| `resultats/compression_sig.json` | `feee314a3c2e1aec4d1bfd5adb84f8a737c1de0e224c436a0b93e176e38c6bf8` |
| `resultats/cycles.json` | `1325f0c84f64a060da5fee19555a1949e11a011106b1c046d10de0ddc76b847d` |
| `resultats/diff_lin_empirique.json` | `5a55b998c883171db2422e9e6df2e86d9886ecfbdc093c8400bc39b6ea656a36` |
| `resultats/diffusion_stats.json` | `815bb71b5c1f6acd0f8ca8a9d0addd27d7cd3646b39052605622987f610d324d` |
| `resultats/diffusion_support.json` | `290d83404f63dfecfd311429ea6e1df23826703f091a89771abc125abd2254ea` |
| `resultats/division_property.json` | `df0ee81372305023144cbc21f8822484b922609095997d2af05b1bbef0c4a625` |
| `resultats/dp_exact.json` | `29b61eaea15241b5a2c85f19aa027fd3474f2b5acbf5af435738259de4f79e83` |
| `resultats/dp_modele.json` | `43b7e88054650f5bb9222963dcf91806d7df60188adadf0abbe8c279bb10a7d1` |
| `resultats/dp_tous_cubes.json` | `c8074279fe3b598b82c1c292f417149859deb37ad73ef8cee15e8d5ede1c7564` |
| `resultats/dp_validation.json` | `8d0497b43e5d55c10d9bedb273cafa133aebc85a58855ca931482fdd9e410ca5` |
| `resultats/fonctionnel.json` | `a4a6f4f43956f1c7db8754dd93f106e633e325eb97b31c48a3d1f77544c0ff7f` |
| `resultats/hachage.json` | `bf1f99c5dc6f8ca3d595abe4cebd66f684dfa25829afa403219d587d150e3719` |
| `resultats/hachage_arbre.json` | `2cb8a879895f7d1d510690761332cf0360e1aa8a65a2a8669cef1148af37bc2b` |
| `resultats/hull.json` | `90342c2b045a3233873297de0461a8962785c69086ccba82fff224999d83e43b` |
| `resultats/indiff_arbre.json` | `2d8bc1405130c7539c4849e1e2d6c1a20fd0a736a8d1eed71f421d8776959b8c` |
| `resultats/integral_degre.json` | `5f03cdcea50d8d2482c954b85bde8e947dcc8c4d311c8d34f1e440f39e6a0ca5` |
| `resultats/isd_comparaison.json` | `cbf2bd2e5de2cb5385abbe0bb2e1dc3c455f20e90738816e16b6a5f66f104d4e` |
| `resultats/isd_parametres.json` | `61f8e2a38294be88e8eb8ec376c6880206ad143d14f15334d449c0042bd2414e` |
| `resultats/isd_reel.json` | `ff79972f5125fd007c12cc27e1155d424384db95478ea00c87fce73a44e7f339` |
| `resultats/kem.json` | `8292f63aac9c62a4ab0d28b309263eecbbc234b573f0684a19defb85742dc05a` |
| `resultats/kem_distributions.json` | `77336568e1a31f89c0e2e0fdb54ce994d762a58884b672e6e59f9d16d02a9587` |
| `resultats/mini_brume.json` | `2a807e5bf9d6269dc6df991ca9c3c5f5b604fd3b5cf936caefea81b3d7c9d733` |
| `resultats/mini_brume_detail.json` | `39e5e08f96bf3e63aac0cd0fb896fe256478c0a0587e44c88d0aed3ae7f90cd4` |
| `resultats/mini_brume_instances.json` | `b2bccce1c1188a8fecfc2a7c0ac4594da4794d138c0f12a8a0e4fbbb3eaf4151` |
| `resultats/mode_aead.json` | `d1cdd256eb031796b28dd9c790a180aa411a63225dc7de0c0d82a7aa4053c389` |
| `resultats/nuit_brume.json` | `804c124be72272c4464aa3fcc46ed7f7c59f210c8d0dc9dc405b515d8bcc98cd` |
| `resultats/nuit_fuzz.json` | `d6a58a9b4cc40e06261bc284466b59edcea87aceb19d1c577f14d38de8806923` |
| `resultats/nuit_isd.json` | `c39287eaccab608dde73a885dafbfbf0eaf7473aafc08c76828ca4de77a3a334` |
| `resultats/nuit_kem_reel.json` | `b83f7c6ce5256ef581a145989e48adfe8c2c95897e5aff589eb94a7fe7596329` |
| `resultats/nuit_temps.json` | `4f289e467002a56beb4275bd9e6ad6005b65475ab39a915b799fa9c996ef2fa2` |
| `resultats/robustesse.json` | `ef6bf91ac3a0c017e4490820e916c32833a9987fe91d544078c289e0a5ee34ec` |
| `resultats/rsd_attaques.json` | `04bf7a4c7e2303487cc84b3f93250f908f7ed9ff7b5e9d9e6856910cc1d7f096` |
| `resultats/sig.json` | `88f65cc2940c27b19f93e57132fc0ac04fd55fd06ed42217a10407bb1974ac30` |
| `resultats/sig_flux.json` | `5406fec788e6a202a19688dbd28ebfbc88c882655c11a9a0501c57701ec1b854` |
| `resultats/sig_modele.json` | `141e049867c66019984468eb0ff0a4a5bad346b1966c1d48aebd608f184450bb` |
| `resultats/statiques.json` | `3a82c07a40ce053af6bb5815c193ae0a865099e1d7cbf907f604e0584193ea5f` |
| `resultats/structure_miss.json` | `792d62c718361c1fbbbfda9a320889fdec7dd8d414e2608cd2699483be50df7d` |
| `resultats/symetries_invariants.json` | `14c13d99a122f55bcdae93efb5e6e7abfb7d9c4e678822482983a13ac7d534a9` |
| `resultats/synthese.json` | `3b72eba83de4e5ba69ea0ab6465fd8288807b24782deebcfb77ef21f3929c741` |
| `resultats/te.json` | `19b3b92d061b07253c7b7dc732bc4d1169c01cdfc66036566ac47dc88ad4838c` |
| `resultats/trails.json` | `f149e63c675ec2061ffdd1d9240ae9a34a72b2b72d8f9f34f45180a3ec59797f` |
| `resultats/vole_params.json` | `30e65f8e34624898f81e0c2c512615eb9568226da2d185414e95c709ccc71973` |
| `resultats/vole_proto.json` | `bbc4640ddfd9663326ea95b9b0531d0699b6ef24a6c37c3df0f559c0e6dfca01` |
| `resultats/wide_trail.json` | `908b2ded5bf3ecfb84c1a3a4071b4d1fd8e5c6baa7bce91a6a89a56926ba3657` |

## Preuves et rapports

| Fichier | SHA-256 |
|---|---|
| `docs/AUDIT_EXTERNE.md` | `15181ffed3a873c321f66b349144a0030f07e45f021e088b030613a554ca0a31` |
| `docs/CAMPAGNE_24H.md` | `3f63cb78b53ae1150f403bd973f9cc8654c2da43bb5d63292d43e3c789771d07` |
| `docs/PISTES.md` | `b95e34b8fe5d145f3cd22d8a131f61ed86232e12de1993f079d3e7e311eb20c0` |
| `docs/PREUVES.md` | `9beb934e74f83102750ced9e5cf9823a649e00296ee34cb9456e426f0c450161` |
| `docs/RAPPORT_AUDIT.md` | `6006fdc094acdeb610ff4fa8161d4d738764d9bfc0c48e86b6062dccb5e42a71` |
| `docs/REVUE_CODE_DEPOT_C.md` | `def7d3b741d31e21a4efb31337fcbca59feac6c2357e1ad87a54fbdd0ec41cff` |
| `docs/REVUE_CODE_VOLE.md` | `4f9588e8227401492d2ad2b06c60a4411031922a0671096b9fa1a495d869f225` |
| `docs/guide.md` | `a43e2fd5c073431e6c0b6573e1817ec026ebb5e49ad30e01c7f2abb58a1afb90` |
| `docs/rapport-piste-compression.md` | `1d79705c40b5be919a7c0124543868c777a5994373a4da25d248baa75f40ccac` |
| `docs/rapport31codex.md` | `367dac368aa8582b826df979f3323ad822dd42b0252294d3956373283e181c60` |
