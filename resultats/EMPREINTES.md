# Empreintes SHA-256 — SILLAGE v0.6

Batterie : 616/616 contrôles, 44 tests.
Python 3.12.3, gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0.

## KAT

| Entrée | Sortie |
|---|---|
| `brume1024_hash(b'abc', 64)` | `062a5ef271ad9bd6447ba12a02771e2337adcc35a525103309ce4bcb4e28dbfe7dbd80b3941e1e836c3f10218cb4f84fd9909aed1bcb3c47d5c1e2e95f776916` |
| `brume1024_xof(b'abc', 64)` | `657f93a6eafa3bd4f65f35d032ffd5fb8484f404fe3f56beb450de5da35d53fc0a789eed4108ec185528314652741e90a83036f8e27d9e38bcb6f23eb2519dd3` |
| `BRUME-1024q AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')` | `2d1d2d247174820fa96ed225fa5d7592243da760bb1652e2db8b40a2e5d5f5bbc232f87aebf743` |
| `BRUME-1024qp AEAD(cle=00..3f, nonce=00..17, aad='kat', 'SILLAGE')` | `a763507b3aa82d81a862111dd678bf7303deeaabf61a5204598f76fce867807d323cd3eccdbfe9` |

## Sources Python

| Fichier | SHA-256 |
|---|---|
| `sillage/__init__.py` | `9b5567a31b316028f5e3d651113693fbf4b21c0e25d57f54a267c3d5d6b5ea09` |
| `sillage/demo.py` | `c440c6a3e2e495dcdd631c628cd188a9a7c4ff49d54478a4455ba0e46338afce` |
| `sillage/rapide.py` | `f704a689faab7e6e2c2bee4ad3ed719ad63c7699e78874f7e9ce104806a06dc8` |
| `sillage/sillage_c.py` | `0983e3c806523c050f39624034167b794524368b65e6eb7fab3a797250c1e813` |
| `sillage/sillage_common.py` | `e5dd1340fe088def8e9caea363ff4bfb9c8bc3589222b9eafd4a4763658baa59` |
| `sillage/sillage_kem.py` | `5ca543efd599051938b762ab902b685560b20ea9d219dd9746b43cb7cc2bccaf` |
| `sillage/sillage_sig.py` | `c3a66765be93150ce88242b20b56ad28d533cfbee794ef0e20dc983e2e4db112` |

## Sources C et en-têtes générés

| Fichier | SHA-256 |
|---|---|
| `sillage/c/Makefile` | `3989972893b8287de6a458eb227ed35a355fc87534f09394ea86e86cbf1ad987` |
| `sillage/c/bench.c` | `7f03bc8d0cb5ced8e0857ae6c8739a52643501c3263dbcd45c476f93f12f2069` |
| `sillage/c/brume1024.c` | `dd5861eee3ab6bc2e3f08ef1f7367c1eee5cd40e3dddede3e28d28d03ac004be` |
| `sillage/c/brume1024_bs.h` | `9d04e6e4d707144d16ccb7a463af9f840a9ace0966256c5ac169daea7db45a30` |
| `sillage/c/brume1024_lot.h` | `d169caa6b3f191cf8407bead92a6c830cbaf1aed54aa4d699c0e9de80f6f1f80` |
| `sillage/c/brume1024_portable.h` | `f602ea34cbed0279cd094378eaf418ee1ec1adfb034320d12bed22d4881bd192` |
| `sillage/c/brume1024_tables.h` | `ce89885c6626affbfdad4f2a07de9dd5385f3ec2835d1d329326912fe0a09c4a` |
| `sillage/c/commun.c` | `6494c3479457aaa65b8ecfc40465ddc09e566ec99909d06c5b891099aff36909` |
| `sillage/c/isd.c` | `b2885305a022218073c77181275d1d9cae3c327abe3025c4f0da0452d59eed50` |
| `sillage/c/kem.c` | `02af924eda3838923bcc2e3608648f9c8a872a5869425fede59d39cc98499f4a` |
| `sillage/c/sig.c` | `071f9d2449d6dc6e7d416e122f48b0f2957710fa9e880d7c7662ccfb11e66e70` |
| `sillage/c/sillage.h` | `9fb7bdb707069c08a6b53ce5fc0863d92673949ef2f44fc9eaadc551cc41d7e2` |
| `sillage/c/vole.c` | `88c2586dd60d3d89909dc590ea05da8e2445b8a5a5659babc9560ba652c85614` |

## Tests

| Fichier | SHA-256 |
|---|---|
| `tests/__init__.py` | `bc7d93e2923d07458b29793d8272372e5f66fd8cdbb31688205f6a17cb9b126d` |
| `tests/b1024_outils.py` | `35012eeb40d422dbc7c9cee08651808bba6e692ebb9821d314a65d1028323d17` |
| `tests/bench_c.py` | `2cf46f5e432628e58e9149d7f804cf746cc98863e1fefb9f78d2273d26e98cf9` |
| `tests/c/Makefile` | `b1ecccd5fab9c0f7539fb04bfb68b9e5de45f841ba88346eb6e2be5fe6344b8f` |
| `tests/c/brume1024.c` | `abcfa562aec6955c0ef5eb151c13d243344e4d02a47ee0569481577b42f0319f` |
| `tests/c/brume1024_api.c` | `ac03016ab77a738bde8a3ae49951ea7b75642973f7b7fa5d9100328d1cab2cdf` |
| `tests/c/compression_kem.c` | `768bd0e181c7db82feb087a6354e90d7a62c11075153e5bf760efb306f0ba201` |
| `tests/c/compression_sig.c` | `b97477e549d98c8262bcc702539ebb72cf9a97472241369a50d1aaadd7eef0e4` |
| `tests/c/ct1024.c` | `9d46ae566c48f045a0420ac7e50948c28a5cdefccf13abc76edae5300e411cfb` |
| `tests/c/fuzz.c` | `9dfc591890b729e853703560da4c5e4182fb4a86b44a8f0938bcd2c670ed0550` |
| `tests/c/garde.c` | `50930a275b518b36a5a63edf1f4c48aeb5c56ab98335f4eec9891908a282dee7` |
| `tests/c/garde_test.c` | `a250f2e8d513bb4e53b59d3446cde4f0c1a93ac508bd74b23061deaf4acdd323` |
| `tests/c/h1p_fourier.c` | `6f40edad0b61aa8e2350fd5df77814f4d4acb47c13a42fb828f2f762e283a52b` |
| `tests/c/isd_comparaison.c` | `8a6933df5d2267711887c0ea59fd0be2946d6708d28c03bbc0a2a5aea75609fb` |
| `tests/c/isd_reel.c` | `1b1c6853cbded1d0b1c86ee38c33208a4f6ddeb9b900946436529d84fd729f12` |
| `tests/c/kat_b1024.h` | `28d0923165ba7b5d251279b2dd9ed2bae18e4853d716a6f75def4d48f37732cb` |
| `tests/c/kem_distributions.c` | `ccd75e0606fdafcfd86e89032e4eb49fda6e76e07f6a321ff06d1bf6e5ec432b` |
| `tests/c/kem_rejet.c` | `095a5718b149e03d99139453a50d2d8625e531e7206de111cf8a98756e4db170` |
| `tests/c/kem_valgrind.c` | `4000bfb3352ac1b94ff3fd336eb71142adcec13675a50b7da9dbb93bc945deba` |
| `tests/c/noyau.c` | `4b6e7584b0f1fba466c11a9a034cda790167556d6e4c4ef3a6463526c1d263d4` |
| `tests/c/nuit_isd.c` | `c9cfe21532e0490e2db42a4d3a374c24299a9ffd8ee2347e209f12b9fe1479e9` |
| `tests/c/nuit_kem_reel.c` | `19f0f62098944fce2b301ccbc26a9abe3087c4e9446e28f579b3e164e105aa24` |
| `tests/c/resultat.h` | `65186d1ad0cf9aa1e9b191277d2f73fffbfc58ef00120f841901bd0cf735d2b1` |
| `tests/c/revue_c.c` | `f285a467bb7c66c71e2b6be0f06e0f7cebc5eb061baeadf5e45d239cd9d821cc` |
| `tests/c/rsd_attaques.c` | `25c48171966923668a2bbdbada1851acad930100ed08b20fe2a522525fb46351` |
| `tests/c/sig_ct.c` | `17a9a1dde668cd44f84ebeb05da74c96e176c916110d79f39deb655d09e92920` |
| `tests/c/sig_flux.c` | `b2f36ca2694e12b11b7800b59350d08b71f0d2f2257e5d34b7e3e4105aeac697` |
| `tests/c/sig_kz.c` | `dfa8cc225159292c25abd10cac39b4235f15aa68a579e5c3408f9dff5d043bf2` |
| `tests/c/sig_kz_commun.h` | `a35a29224c2983318d442d2aa378d06a3caa6c97dd330c7b83d70c3135daf25e` |
| `tests/c/sig_valgrind.c` | `834f634ed3f1b0c5321fd693b345632f7970855b32a97b88c7fd1d0984d188d3` |
| `tests/c/temps.c` | `b470a1e2c67044cb7705da020e928cd314be45e097d255cd990a0dc69087abcd` |
| `tests/c/temps1024.c` | `780223848ff677d3292c69dbb4a6d6ed3051eb05d49992aa4a61453d19095c27` |
| `tests/c/trace_pc.c` | `97300089809ac8bb53d3fc3f183a4c7eff4a069e9737d9aecf58b683383f0741` |
| `tests/commun.py` | `4c42c8e3bb8ff345006777c6ffa1fe08a8cc78ec45181be2d5c044f3edef968e` |
| `tests/couverture.py` | `817ad7c0cb8689f1cd90d346bc7469da0680dd5941e448d75cda263a6bb67aa4` |
| `tests/empreintes.py` | `afe5affe6567042d7d6441b02df06f065a70d306f2c2a3bbeb259c07a263a2da` |
| `tests/noyau_c.py` | `bbab194f6687532783bb3e1a7149a3cbb5c3a70aceab656c810b2435abe7ca66` |
| `tests/run_all.py` | `a2671c89216a9c7ab660c07e6e20d77cec4b5b96d375de4f45b31093ddec5934` |
| `tests/test_api_c.py` | `3e1e97a752ce95e5b7636e45874d26e0b25aafe93f94a968a2c8ff9260f9399e` |
| `tests/test_b1024_certificats.py` | `6670b125eb8aec9af6395918bf9c360ef947e99b3249a55d640575e6f550d69d` |
| `tests/test_b1024_etudes.py` | `2744c8c228823203a7814d0c3609a23156771cf3947ebe3e5880c7f283546829` |
| `tests/test_b1024_preuves.py` | `a774a1437a1e68714faf2ff409df099cafdf680e24b3ef9518f23dd1d5159eb9` |
| `tests/test_b1024_seconde_implementation.py` | `78816be90990147cc5a9f1645f86169d9b6b8813186e8e7b258a1dd111465602` |
| `tests/test_b1024_statistiques.py` | `dea5251440698887e0c95b3c407579c0a6f06dfe0b8644c8da3e3eb9b28ef1fe` |
| `tests/test_b1024_structure.py` | `015b898f57d60e474d55721660df3f9d9860fb2dbb5eb13ac80d1e765ba08482` |
| `tests/test_bornes_preuves.py` | `04ed4b93b36cb8a7ba323b1bd8dff1a2df8e57c0746fce7045a45b43cc31cfb9` |
| `tests/test_c_brume1024_valgrind.py` | `35d2f402da39dbaa3cf61a5bb69a0007a8edc1284ccc74e08a10f2b6d6edffcb` |
| `tests/test_c_fuzz.py` | `4fd95935c0f7be173c6b4defa8597a8b33f926f9cc325e2061b649be6c75c352` |
| `tests/test_c_impl.py` | `f9129131785886b6c163c7a0c17fd65c4b5676b613bdfbc0ec6b5dd68436789d` |
| `tests/test_c_kem_bruit.py` | `886ae7c06a634728bb73136ea20157d4a6255033d791fed0dadfd083eb26711b` |
| `tests/test_c_kem_valgrind.py` | `13e1e0757b40f9e78d6ee29a8c178ab195ec9d0c38ddc2a3d9572fcf5fcf6ed8` |
| `tests/test_c_limites.py` | `9098029446741e4cca82fc34ba16c7375cfc91a6a8bdbcba918250553fcff71c` |
| `tests/test_c_sig_valgrind.py` | `1e52bfe6e42f8e3d4afe9de79137d11ba72065b94cafb9f27025c5c26bf27b63` |
| `tests/test_c_temps.py` | `6730a7e00de8b5df30f5914e04dbafdef95735d6ed75b67f2908d4733c56d937` |
| `tests/test_c_vole_temps.py` | `5fe2a1c7cd51a6f696cdb46bf60f4e81ff0cdb9fe73438184909dcac653af937` |
| `tests/test_c_vole_valgrind.py` | `96d6fb20fd578fcac6145696ee297bf75fc760f133a88054a7b5188b3bf06ed7` |
| `tests/test_erreurs_api.py` | `711959fbe5b33c54d6768c14bf79d5d33d5cea9001c0fe1c0897c3db7113a8b8` |
| `tests/test_fonctionnel.py` | `3c4258998b45f75375bb11dac0c91167d6a3442722f272a0221038f6327f7928` |
| `tests/test_isd_parametres.py` | `c0589cdff1c51418f9d4a7f226566fd07aacf45b9e023d3d44881980cdd5d8f3` |
| `tests/test_kem.py` | `ee187d8c7c12f59a4f92fe237374b178497bc28ce770de30106427e3d77a4402` |
| `tests/test_kem_lemme3.py` | `280bb6618c924a247e5eac9d9c7fa46ca880bcefadb7f52343ff6379e9f6fb8e` |
| `tests/test_kem_theta.py` | `6007068e6a16a8c0a0c2fdbc934d3949458d66293bb22c69fc3a84374e5e0ebd` |
| `tests/test_robustesse.py` | `0fe645dd92c798eebc860237b4c10446e1c78af3e78ada27892c698791a1164e` |
| `tests/test_sig.py` | `53231c7da1e69fa5557f84f49923f59fa64a48264c6a365d5326b087d527e12c` |
| `tests/test_sig_hvzk.py` | `5755b92d4abe4d237c2edc1301d5385230e3c750778e8366c5ae8d7530acfbff` |
| `tests/test_sig_modele.py` | `db283b3a25e019fcc5a78bded7761efe1c8be6b3b86ff452c31f6272b8154880` |
| `tests/test_vole.py` | `65908ba8c5b82dabbba4ba3377c15919b32393755af63d8691a6faca57090006` |
| `tests/test_vole_kz.py` | `e0e832d24ebfec12fc254120ef45c3a6605a7a97e3e0bed1e0bad312cf81c4f8` |

## Outils de recherche BRUME-1024q (hors bibliothèque)

| Fichier | SHA-256 |
|---|---|
| `prototypes/brume_q/b1024/agregation2.c` | `19cdf3df1a84233be3824ea470380b7c2332699c5e30a6adb16d58b4998106d2` |
| `prototypes/brume_q/b1024/agregation34.c` | `9c224fc6ae4759fb7f0a65dc8835f218fd8f87d079bfe0b8367ea50114573021` |
| `prototypes/brume_q/b1024/algebrique1024.py` | `87f37ac6f65beffc3d7dbf725be291414c91d21d86c0cbe4bf6f0374020fb26a` |
| `prototypes/brume_q/b1024/b1024_bs.h` | `3dfb2ac753047ff8639eec3b127436a76ff1e7264e9fcdc564d8e749814eee12` |
| `prototypes/brume_q/b1024/b1024_lot.h` | `c31ecb44cde6c296c5fafc13e952df829c30559ae33161943f60a3c482a154e0` |
| `prototypes/brume_q/b1024/b1024_lot_var.h` | `30b7b57c49a077224fe5a7a8376f12c57c6fa204befba872a7e82b35725a96e1` |
| `prototypes/brume_q/b1024/b1024_portable.h` | `07914cf55f57912e99d034d027291ae883d903d01a69e346912012d46e6d412f` |
| `prototypes/brume_q/b1024/b1024_tables.h` | `a84aa8b37490a3b8c347d138601aa53f6296b9c7ff31514b6b0e7e8f192647fa` |
| `prototypes/brume_q/b1024/bench_comparatif.c` | `cc8c60bc07322d1f9b01e3b3dc5d4e1e75aed732bdbb565f2a59c49578627324` |
| `prototypes/brume_q/b1024/bench_lot.c` | `a0927ee875fc620c55588b9c680638e6e754988792dc206e3924d1194e385298` |
| `prototypes/brume_q/b1024/bench_tailles_1024q.c` | `1d5b91add17c2a743b59b4f1b00e3beaae108dd162dcbb9a664256b4f0e2bb0b` |
| `prototypes/brume_q/b1024/brume1024.c` | `c7550a0448fd3651e743ab7b882956469353c73b8bba72aa996afb133f31051e` |
| `prototypes/brume_q/b1024/campagne_aead.c` | `b18b8231632fcee96e8b109e9eb29a3218aff70a353984970e4de2827839bfe2` |
| `prototypes/brume_q/b1024/circuit_sbox.c` | `170b16e0f341313d9eff5b9822dc9349175648178406aea6896d0aa135b18daf` |
| `prototypes/brume_q/b1024/controle_portable.c` | `0810cce84ef64f92bce11da859ce9c996cb998d52e297e4c0ea73f2eec6c298a` |
| `prototypes/brume_q/b1024/cubes_degre.c` | `3aaac2e54939be3b39220f12e28ee9cab87081b493a5d9c0b603747d018018cf` |
| `prototypes/brume_q/b1024/dl_verif.c` | `d8e60568d223236926405125f3b649b0475d6a2de7232cc272b9b18ba1561e26` |
| `prototypes/brume_q/b1024/gen_b1024.c` | `f46ecbbdf652ab8244f7d941dbc2e07573f63b07dfc334b9f5e4e60aaaa566a7` |
| `prototypes/brume_q/b1024/gen_bitslice.c` | `9de5943ce8fe7ead6d7cc3caed05c6ed36d54b5112b5817d82be4ac262d1f642` |
| `prototypes/brume_q/b1024/gen_lot_variantes.c` | `43b83192355fc8e48212c254ac65906293e0e6cb08338122ce26dd9364365f6a` |
| `prototypes/brume_q/b1024/gf16.py` | `76be18b1ee2f6f7878455cdd13a59d4cbe7d50e4a28354f6018dc7337488cb12` |
| `prototypes/brume_q/b1024/invariants_quad1024.c` | `0f111dc1987c34e3fe8f330b580e8c99a170ac2298cc8dce98d2f83d29a5fd1e` |
| `prototypes/brume_q/b1024/kat_b1024.h` | `647bd80e29cea2c3870221436e9eca8e77de3eb9754ef40f24abfe8362eea612` |
| `prototypes/brume_q/b1024/mutants.c` | `c3a805f3a31ba89204b12292fbd38f88b46b2512c2bcf6936387d17804d64e11` |
| `prototypes/brume_q/b1024/rebond1024.py` | `91b742b998c0a387787e444d9cd621ee7f4aca990c3a24f1df1bb3794707febc` |
| `prototypes/brume_q/b1024/rebond_verif.c` | `ba46fae5a0e5516f3a51b1eb39b3b483a9ee2343a97e273c5958bcbd33cf7ac8` |
| `prototypes/brume_q/b1024/spec_ref.c` | `df89c0eef6417710801ac4807e67478ff7cda5824f3bd60ad931cd35f110d17e` |
| `prototypes/brume_q/b1024/stats1024.c` | `35b87106df339860d558a7da243d1514d0985746b698099b4fff3c585a0fadd2` |
| `prototypes/brume_q/b1024/structure1024.py` | `d7e0d6a7c567befdea3f3d38ebd554451fad405930ab3b60524197bca709cddf` |
| `prototypes/brume_q/b1024/trails1024.py` | `9f7da6a99b26bcfe0b03d22f76c3c6a28f46f763ba7fd39fb29deb3894e6f87e` |
| `prototypes/brume_q/b1024/tronquees1024.py` | `9875c0d8de6b43bf82443dcc77f290c6c98c9bd51a26617db806cc65de71f21b` |
| `prototypes/brume_q/b1024/tronquees_verif.c` | `b7db89086787ee0c939a8ac3e1db8bb116913a609c23158a7a3941f261b3aaee` |
| `prototypes/brume_q/b1024/verif_chemin3.py` | `846776076951dcd44f22c87e3c6f6523df5b12b6da2911e99abec1775e2921cf` |
| `prototypes/brume_q/sat/audit_c4_K28.py` | `cd230d5cc1636e639bd78aba2f5bb2893a337050a9a0540620cb06ae785d31e9` |
| `prototypes/brume_q/sat/c3_cnf.c` | `b34508ea937e526fb1776a44f0ec47b0376c31ac2161cff034af8ca170b9147e` |
| `prototypes/brume_q/sat/lrat_verif.c` | `2efead346cdfc09bd456138dcb2b12e4e567e7f5dad73194bb92ea80e7872165` |

## Certificats BRUME-1024q (C4 ≥ 28 : découpages et complétude)

| Fichier | SHA-256 |
|---|---|
| `prototypes/brume_q/sat/c4_K28/README.md` | `e8b221159459d38a60cfafeb98118757b4548aff2a78073dd71f3b6fda0eeadf` |
| `prototypes/brume_q/sat/c4_K28/chaine_P4.txt` | `51a324369c7be8e042336a24f7e4083c338117a2c184d382d89fab5c2d8b9074` |
| `prototypes/brume_q/sat/c4_K28/chaine_W2.txt` | `325624c71165907b8b55757c30a10a010171d413992107d080985befdfa05f46` |
| `prototypes/brume_q/sat/c4_K28/chaine_W3.txt` | `5b779eab495e40435bcbd2d18ff196ef3e5c3fc6906cca893f93afe2b3d325ae` |
| `prototypes/brume_q/sat/c4_K28/completude.cnf` | `b089409229f5f64a3e9235f488496dd0b76c38a13f7ba8933135a5eead9f99e0` |
| `prototypes/brume_q/sat/c4_K28/completude.txt` | `81c1c420891476df9fa934e5242c5febff41f0311c1fe0f056b2c6a4d965eb8f` |
| `prototypes/brume_q/sat/c4_K28/completude_P4.cnf` | `45ba37cbd69d9d24c9ab2045cd2f7d6158054e1408e7dfb4fd634f621097fff0` |
| `prototypes/brume_q/sat/c4_K28/completude_P4.txt` | `e424ebbc38d4846b116b9a9e978f4718dde07303ac8132159447434301a4ab4c` |
| `prototypes/brume_q/sat/c4_K28/completude_W2.cnf` | `93530a671f50df58d06b45c8d5661d57f0c1be0ca32b55d380da0fbbc47e247f` |
| `prototypes/brume_q/sat/c4_K28/completude_W2.txt` | `bb53e562e183e4a40356c1269965c265744d338eeea4a85e200e571836015fcc` |
| `prototypes/brume_q/sat/c4_K28/completude_W3.cnf` | `9d3df3557f1101beba0a82bd6b27e6d36a250dcdef3fef2b4bd57ec890964dc1` |
| `prototypes/brume_q/sat/c4_K28/completude_W3.txt` | `e424ebbc38d4846b116b9a9e978f4718dde07303ac8132159447434301a4ab4c` |
| `prototypes/brume_q/sat/c4_K28/cubes.txt` | `8f73742627ed3653c8709fb9eae227a0056b6eef81d62c6776ee949da516d0c0` |
| `prototypes/brume_q/sat/c4_K28/cubes_phase3.txt` | `30bb6fd3c9b600a46f5d93d87ad5e757ae193c5ac2d40577d49a89ddc886cc2a` |
| `prototypes/brume_q/sat/c4_K28/cubes_phase3b.txt` | `66cb8cf4db1d2f1e5fcc4ad6934bdc2aa9fa6bb2c21fc1c0f4c94d19cedea878` |
| `prototypes/brume_q/sat/c4_K28/cubes_phase3c.txt` | `3a578c91758cd0d504bcb313f4997557df2c094e030bb1a08e4e104dda708fd9` |
| `prototypes/brume_q/sat/c4_K28/cubes_phase4.txt` | `910c8a5bfddccf913341cfc608715d6a17b61bb21c49cc02a76c32e6e13d268e` |
| `prototypes/brume_q/sat/c4_K28/cubes_phase4c.txt` | `db68c269c1a9e0608dd79d0724409655eb0ee1533eac04352f4328723b66369a` |
| `prototypes/brume_q/sat/c4_K28/feuilles_prouvees.txt` | `b21efdcb7ac6ab456edd36a8de4c97d51a8197589d480ee2acf00db8ef7f5c87` |
| `prototypes/brume_q/sat/c4_K28/sous_cubes.txt` | `1c583d202ad7807680ee86ece09bd869a7b797478e85f4ec4ae8044a46251ef0` |
| `prototypes/brume_q/sat/c4_K28/verif.txt` | `cdd4c39e20c01f1f478dc8010e6a27a66ba1753c2756ff171fdde91eba0d879f` |

## Certificats v0.5 (BRUME-512, historique : pistes de division property)

| Fichier | SHA-256 |
|---|---|
| `resultats/pistes_division.json` | `b4c596d22d96a7df68964fbc07b0815c2645e9c64c6a139b6121ea25e61b2274` |
| `resultats/pistes_exactes.json` | `f3dc65dd67b646eb05edaa0d5b5a7688df5c77911cb2df1eac01b6d6c02ca00a` |

## Résultats de la batterie

| Fichier | SHA-256 |
|---|---|
| `resultats/SYNTHESE.md` | `4d73d38e58ca6f458572b760f738b6249d9b3430409a6a38b0f5dc96201a2b14` |
| `resultats/api_c.json` | `afc46d6be37c2fe7c7d62e18fb2daecf450a77dec3a7a51400921e6d4ab11383` |
| `resultats/b1024_certificats.json` | `d9fef4bf1cb83ee0d806ba580d8fa1093f37c5d35e5d1fe4e71e8cf58571be82` |
| `resultats/b1024_etudes.json` | `0c2390b1f8b4624fa97eef3161aca20ac1dde6a71694dfbd060a6951b39a38d5` |
| `resultats/b1024_preuves.json` | `d02c5014c1ce91394cfcdcca8ef7f1d43ac79c0f245773fe1228964ce80e3643` |
| `resultats/b1024_seconde_implementation.json` | `eaa7158f90ea9e37cfdedc0e61a91e14022dbdc58af2bf150daabf1fd45e9f6c` |
| `resultats/b1024_statistiques.json` | `9a6d87a57b5ef9d529c4480a610e6d57a5b55197f89584d75211bc74c75e1a67` |
| `resultats/b1024_structure.json` | `8ab5544588719f541fac02fd4de103df0380faaaad67803f15551d6dec4225c8` |
| `resultats/bornes_preuves.json` | `e310918b21cd343fe8858bccc793b1379baa41a7cb2a4e0d36998de5931f1717` |
| `resultats/brume1024.json` | `f82d43d07676e8a748fda685bb3260405bd048331d363b3e08f7386cb22cfb8c` |
| `resultats/brume1024_api.json` | `01bdfb431b62adedb6abf01f59647635a32710f165d95d8b8a8530bfff5eb5a1` |
| `resultats/brume1024_api_portable.json` | `ffc5410542286f3cc73bc983e36e43b74f794bedc752b592a7bb67cd64f5788b` |
| `resultats/c_brume1024_valgrind.json` | `ed900e06ed5ea84771c22488011d532edc4632fdb24c58a414a5cae320b3c098` |
| `resultats/c_fuzz.json` | `b7cc01078bb7a5fa767c413d0fa5607d2f7da72df4b35b39845d1914a391c1f8` |
| `resultats/c_impl.json` | `1d16d3ec6fcc240d827d22bbe3a38cc99272e2c8eb22ac66fd8905319a3928a9` |
| `resultats/c_kem_bruit.json` | `01cc24274eba61b26d6b464cfc7a87a699be667e54661846760039d3c934b142` |
| `resultats/c_kem_valgrind.json` | `b9ec1bc5a3fd0c71bf23539ebf54afb120c26a4207456ab7e3718301fa07cb0f` |
| `resultats/c_limites.json` | `ca964c6bdf37bb47bf93fc11925620f0a455934e5904013a1eea1d1217a630c6` |
| `resultats/c_sig_valgrind.json` | `0bc530416f6d361f1e523c8f22d70982e4ddaa1c6f2d67f88f9edb43357837b3` |
| `resultats/c_temps.json` | `919c7c23e512d21711f36b5d2b9187822b1873edb3ad182149d7b2ea68ec0874` |
| `resultats/c_vole_temps.json` | `cd57fe2ea649a6656b0605da4e8d4c183a8641e89b1abea4c38a1f228e40a5f5` |
| `resultats/c_vole_valgrind.json` | `3b933f5c95f881d81af0b2ecf92840adab33a566c6d69384ceb62e499003ebb3` |
| `resultats/compression_sig.json` | `feee314a3c2e1aec4d1bfd5adb84f8a737c1de0e224c436a0b93e176e38c6bf8` |
| `resultats/erreurs_api.json` | `32c31a6b348394f33eab114e9fcde4b6a6dacbb3cc4eb8cee93c8d6068158a72` |
| `resultats/fonctionnel.json` | `26e250e706d58117dc42046a6e88098905a624106189f7c98c8d3e30d7f5b954` |
| `resultats/h1p_fourier.json` | `0dec37c4f7dcb819f05149ec119af45fccbbedef48ac9bc748174f4d55e3c7a0` |
| `resultats/isd_comparaison.json` | `cbf2bd2e5de2cb5385abbe0bb2e1dc3c455f20e90738816e16b6a5f66f104d4e` |
| `resultats/isd_parametres.json` | `c303d6fae5743adb01ce5e26acfe07d6d1fa9f7035c6b0cf1a082a0cdabdf742` |
| `resultats/isd_reel.json` | `ff79972f5125fd007c12cc27e1155d424384db95478ea00c87fce73a44e7f339` |
| `resultats/kem.json` | `6f8fa6d1f5bae58d189752d8e2c0073582df56026dde835feeaad54cd303afc4` |
| `resultats/kem_distributions.json` | `8742fedb5f2d904ea720b56ff0cd1b6399e96a24bc6d482a5fb8e755ab69de4c` |
| `resultats/kem_lemme3.json` | `258c6094965b2f4971b09f4cde88638ccb322d6282b9c376cb589ace5c56eb17` |
| `resultats/kem_rejet.json` | `9d1fe243afc79cbb4dbfc0f91c8a53f26bada9380ad00ed7dab9b9f23db64e57` |
| `resultats/kem_theta.json` | `26bac377000e02e3de61d49cf57fc756118e482692d4fcff1df2805d91b0d511` |
| `resultats/revue_c.json` | `4ba04534bbc9821d8b1184407d492669946877f654f9271b024298a5bf78debf` |
| `resultats/robustesse.json` | `a278c2ab57cae674af6ebd0e42fcbf29b8d1aaae718f90bee2f4f20a13421e07` |
| `resultats/sig.json` | `31fb13accae55ea1665ea2f617c1b9e0db1666a7fc7a89592da4b89ec8af2416` |
| `resultats/sig_flux.json` | `455390b89e79417ec2bdf7f75b94de95c062883eaf20f07d6f748f6fd2dfe5bb` |
| `resultats/sig_hvzk.json` | `a846ba8e8591f97076296133107ba4b3d45505902ff3081fa5817c2050eecf0f` |
| `resultats/sig_kz.json` | `f46ab751ab9461b5690f01042698bd4acc185e6563173e3e880c3072b976b3a8` |
| `resultats/sig_modele.json` | `37a7f7c296af48dc161a927c7062f9933b3ce8431508c207d319d5389e0feb8f` |
| `resultats/temps1024.json` | `3c1c4eaf0a557be94fc1b3cc3c3f2b8a78ef336291bfc17fead6a0e720f8c519` |
| `resultats/vole.json` | `3cd4e052a16612b55e6ef3b8ab167bea16e99e3621944d5ab4a5c08f290ac1e4` |
| `resultats/vole_kz.json` | `313609643ad888a6b2c7cdfb3da2c4fc52407a70543c35b3d8359cfb219d5f59` |
| `resultats/vole_proto.json` | `b9ee9d430a8c385754e97fbd7a36eed0d43aeba3986b6af587579ce911ff821c` |

## Spécification, preuves et rapports

| Fichier | SHA-256 |
|---|---|
| `docs/AUDIT_EXTERNE.md` | `15181ffed3a873c321f66b349144a0030f07e45f021e088b030613a554ca0a31` |
| `docs/AUDIT_REPORT.md` | `1cee9b5b23dc9dfdaff1e588f15d310f94277b1e38f24c484cd53d31e6676450` |
| `docs/CAMPAIGN_24H.md` | `e2773b4e8aae053d0a6eea15c59050409f1950e9b0f4031b54c939344caa11d4` |
| `docs/DESIGN_NOTE.md` | `ade0afa112999029530930f6312ffe3df5cd65f9b6a827357326ff7bf560c29e` |
| `docs/GPU_CRYPTANALYSIS_PLAN.md` | `58ffa7a0da65ec8186eb16f8278d6a7030a1d6f23f6cee58780977489631db7a` |
| `docs/LEADS.md` | `e2a6ac832fa1890ea3a39e0e1033c6d910574351324b017582bd3c2baac1ee96` |
| `docs/MIGRATION_V06.md` | `44a0acc6dd6853bca6e9cc1bd379d84c37fc508f757ae732ab6108b01a6491ec` |
| `docs/PROOFS.md` | `77eb7eed62c49bfd48730636a32291229aa1dfd019d4eb6cdbcc9fffa0d32ab7` |
| `docs/README.md` | `6a5b5e83b0db75cde1e4d785bfd9b0ae647c51cc73dafdd4b8fdab559af152e9` |
| `docs/REVUE_CODE_DEPOT_C.md` | `9185183f7c008508342eae0f3ce3b19077c6bbe671645584c766337c88c7e2f1` |
| `docs/SPEC.md` | `59c31577b98164fd118b300db02aaa7614828d7ac1c0fa12fec695113de06f5a` |
| `docs/VOLE_CODE_REVIEW.md` | `6ac1e10eb0acb9392a80dcf50820734b20555713997b7f948ab76c59e4df4e1b` |
| `docs/brume1024/AEAD_SECURITY.md` | `5014af09dacb9ffad3eb29e7414af1097bbc6caeb535cb6630c45354f98f1bd6` |
| `docs/brume1024/ALGEBRIQUE.md` | `46b21249b45430295a5e429d11e79a9cd531208111546d2301004ee794ad1f2b` |
| `docs/brume1024/CM_VERIFICATION.md` | `a7d4adb5205c1862b5ffc3202c00bd9efd04928961af94c2c8a46fcdbf1f4717` |
| `docs/brume1024/DIFF_LIN.md` | `012bcd02221ba6d01eb8a80a2aeccfb26aec83cd2ac676695b4c83594da0920f` |
| `docs/brume1024/DOMAINS.md` | `0f96039cad7e3590531974c7ac4d58a72503cad4c51813d08f9ca88f0849b297` |
| `docs/brume1024/ETUDE_GROUPE_STRUCTURE.md` | `00e8dcae601f02f570e6469e35521edd1f3c521e47b06e853422eedea1222ab4` |
| `docs/brume1024/NIVEAU3.md` | `2abfdbc5b3a4195ea42d20916153ee411890fd5e15aaf3c4778a4894970c9818` |
| `docs/brume1024/README.md` | `47f1a9dfbc5a1384764fc4392e4a04b9a4ef55238787ca7fd8369286243b64c2` |
| `docs/brume1024/REBOND.md` | `4f34d00aa5932e2cd01179dc05317892521b9f6866d37b78dc659e1f63b36965` |
| `docs/brume1024/ROADMAP.md` | `22cc0e7bf7e905618885c2dbcd82692bfd5310390b92feb722d249693102f193` |
| `docs/brume1024/SPEC.md` | `7018c40b508358cbf6ef8eedeedf92879dfcd08f85e6a4da55ef54dc08c237ed` |
| `docs/brume1024/SPONGE_QROM.md` | `45f5ba8db62b572d7d7aa249d4accf22de1943bcd0402e136121b48a3ab886e4` |
| `docs/brume1024/V06_MODES.md` | `783bd37e7390023e627ea597858ea9d505c83d4c457b05cdea11eb16a20c647e` |
| `docs/brume1024/WIDTH_ANALYSIS.md` | `3145eab73934cccf76c022fc0823d87bcf8d3157a00fa9063b175513b7e794cd` |
| `docs/rapport-piste-compression.md` | `1d79705c40b5be919a7c0124543868c777a5994373a4da25d248baa75f40ccac` |
| `docs/rapport31codex.md` | `367dac368aa8582b826df979f3323ad822dd42b0252294d3956373283e181c60` |
