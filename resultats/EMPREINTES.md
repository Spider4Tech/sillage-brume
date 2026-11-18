# Empreintes SHA-256 — SILLAGE v0.6

Batterie : 570/570 contrôles, 46 tests.
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
| `sillage/demo.py` | `4322eca96c45acc7b6f2313defecf265b8c28438b16b4f904be366bcecb7b4ca` |
| `sillage/rapide.py` | `367c5fb9e64c83d05b1f4b6e6e5607f295b9581d6a945aa9cdcf605b7a3920e9` |
| `sillage/sillage_c.py` | `89d0126fcd0da0e37023472eb849d321a43222dc59e02a22122677f0c063c48e` |
| `sillage/sillage_common.py` | `e5dd1340fe088def8e9caea363ff4bfb9c8bc3589222b9eafd4a4763658baa59` |
| `sillage/sillage_kem.py` | `d18d415fda72c855518df0f4a21613bd78896ae5242b5a1ec1eed2c0d8e4b212` |
| `sillage/sillage_sig.py` | `c3a66765be93150ce88242b20b56ad28d533cfbee794ef0e20dc983e2e4db112` |

## Sources C et en-têtes générés

| Fichier | SHA-256 |
|---|---|
| `sillage/c/Makefile` | `3989972893b8287de6a458eb227ed35a355fc87534f09394ea86e86cbf1ad987` |
| `sillage/c/bench.c` | `d699c52852f13658fd0a294c9f012a51baea23f5156805e29de68c5c92c04039` |
| `sillage/c/brume1024.c` | `dd5861eee3ab6bc2e3f08ef1f7367c1eee5cd40e3dddede3e28d28d03ac004be` |
| `sillage/c/brume1024_bs.h` | `9d04e6e4d707144d16ccb7a463af9f840a9ace0966256c5ac169daea7db45a30` |
| `sillage/c/brume1024_lot.h` | `d169caa6b3f191cf8407bead92a6c830cbaf1aed54aa4d699c0e9de80f6f1f80` |
| `sillage/c/brume1024_portable.h` | `f602ea34cbed0279cd094378eaf418ee1ec1adfb034320d12bed22d4881bd192` |
| `sillage/c/brume1024_tables.h` | `ce89885c6626affbfdad4f2a07de9dd5385f3ec2835d1d329326912fe0a09c4a` |
| `sillage/c/commun.c` | `6494c3479457aaa65b8ecfc40465ddc09e566ec99909d06c5b891099aff36909` |
| `sillage/c/isd.c` | `b2885305a022218073c77181275d1d9cae3c327abe3025c4f0da0452d59eed50` |
| `sillage/c/kem.c` | `762e6de7246d24e89e87ead1394a85c58939cf29117d5163b64911a07889021c` |
| `sillage/c/sig.c` | `071f9d2449d6dc6e7d416e122f48b0f2957710fa9e880d7c7662ccfb11e66e70` |
| `sillage/c/sillage.h` | `3aea319d0adaa96ffe30f6abaf58898bcb0af029603da4c024c0a3c0d2510f6b` |
| `sillage/c/vole.c` | `af00126af36d1259e9cc3d122ee5295c0d743f0d32c43d72a719272d8ab41a4a` |

## Tests

| Fichier | SHA-256 |
|---|---|
| `tests/__init__.py` | `bc7d93e2923d07458b29793d8272372e5f66fd8cdbb31688205f6a17cb9b126d` |
| `tests/b1024_outils.py` | `35012eeb40d422dbc7c9cee08651808bba6e692ebb9821d314a65d1028323d17` |
| `tests/bench_c.py` | `c8d581a040b0907781e1cda6b8a15eeb9f8b4891c01ce8c483b1d5b506b6b895` |
| `tests/c/Makefile` | `b1ecccd5fab9c0f7539fb04bfb68b9e5de45f841ba88346eb6e2be5fe6344b8f` |
| `tests/c/brume1024.c` | `abcfa562aec6955c0ef5eb151c13d243344e4d02a47ee0569481577b42f0319f` |
| `tests/c/brume1024_api.c` | `f7b78c13130b94c753cb12021d5f2014eb7088e9dd5f9a84754f5f8e9c44e1db` |
| `tests/c/compression_kem.c` | `8b88a38f25f671d15c27284b29cecc43c3bad1c4a222c7bafc4a99d6dc2590bf` |
| `tests/c/compression_sig.c` | `b97477e549d98c8262bcc702539ebb72cf9a97472241369a50d1aaadd7eef0e4` |
| `tests/c/ct1024.c` | `9d46ae566c48f045a0420ac7e50948c28a5cdefccf13abc76edae5300e411cfb` |
| `tests/c/fuzz.c` | `af231d13a2b7782b2aad6c8724148dc12a44593b1780a5b849a68c22f69ef32c` |
| `tests/c/garde.c` | `50930a275b518b36a5a63edf1f4c48aeb5c56ab98335f4eec9891908a282dee7` |
| `tests/c/garde_test.c` | `a250f2e8d513bb4e53b59d3446cde4f0c1a93ac508bd74b23061deaf4acdd323` |
| `tests/c/h1p_fourier.c` | `841f91de92dbf40d1e9607d642f51fec27be341552b87c0ea4274875eab7cfc2` |
| `tests/c/isd_comparaison.c` | `8a6933df5d2267711887c0ea59fd0be2946d6708d28c03bbc0a2a5aea75609fb` |
| `tests/c/isd_reel.c` | `1b1c6853cbded1d0b1c86ee38c33208a4f6ddeb9b900946436529d84fd729f12` |
| `tests/c/kat_b1024.h` | `28d0923165ba7b5d251279b2dd9ed2bae18e4853d716a6f75def4d48f37732cb` |
| `tests/c/kem_distributions.c` | `21ef8a4b680eae27a2ec4960c38813352d722e2d27b444f5bb01d5746dfba0e7` |
| `tests/c/kem_rejet.c` | `5c6e6921061db48f5c4d1c368d5b766b0efc3bf9682f79fdcee537cc25e0a53d` |
| `tests/c/kem_valgrind.c` | `849eb6452a9bc97aa591134eec0aefe3daa78880d6166de5eae5a0afbfd0fda9` |
| `tests/c/noyau.c` | `4b6e7584b0f1fba466c11a9a034cda790167556d6e4c4ef3a6463526c1d263d4` |
| `tests/c/nuit_isd.c` | `c9cfe21532e0490e2db42a4d3a374c24299a9ffd8ee2347e209f12b9fe1479e9` |
| `tests/c/nuit_kem_reel.c` | `f4dee6d67bc2c3277fa8aae49b3489d53d4d808312c685a0385f891d071e22ef` |
| `tests/c/resultat.h` | `65186d1ad0cf9aa1e9b191277d2f73fffbfc58ef00120f841901bd0cf735d2b1` |
| `tests/c/revue_c.c` | `9b352c662cb94d091ec5e47f01a06690518a078a6080f3f2113ae9ae20f68a97` |
| `tests/c/rsd_attaques.c` | `f7e85bdca1a651e6e3ae579c8666c65432aaac7ad1788b25871c92a7fcb0aa49` |
| `tests/c/sig_ct.c` | `17a9a1dde668cd44f84ebeb05da74c96e176c916110d79f39deb655d09e92920` |
| `tests/c/sig_flux.c` | `b2f36ca2694e12b11b7800b59350d08b71f0d2f2257e5d34b7e3e4105aeac697` |
| `tests/c/sig_kz.c` | `dfa8cc225159292c25abd10cac39b4235f15aa68a579e5c3408f9dff5d043bf2` |
| `tests/c/sig_kz_commun.h` | `a35a29224c2983318d442d2aa378d06a3caa6c97dd330c7b83d70c3135daf25e` |
| `tests/c/sig_valgrind.c` | `834f634ed3f1b0c5321fd693b345632f7970855b32a97b88c7fd1d0984d188d3` |
| `tests/c/temps.c` | `834ce3e8ac2c8f4f3c4fb96c6c0205d0c356f9d111c370a329a240a92de6a859` |
| `tests/c/temps1024.c` | `780223848ff677d3292c69dbb4a6d6ed3051eb05d49992aa4a61453d19095c27` |
| `tests/c/trace_pc.c` | `97300089809ac8bb53d3fc3f183a4c7eff4a069e9737d9aecf58b683383f0741` |
| `tests/commun.py` | `4c42c8e3bb8ff345006777c6ffa1fe08a8cc78ec45181be2d5c044f3edef968e` |
| `tests/couverture.py` | `817ad7c0cb8689f1cd90d346bc7469da0680dd5941e448d75cda263a6bb67aa4` |
| `tests/empreintes.py` | `afe5affe6567042d7d6441b02df06f065a70d306f2c2a3bbeb259c07a263a2da` |
| `tests/gadget_ssb.py` | `5d6728f91e44568d5076d8a5d925efb115418fcaddc86a1b13c4ad153ab81fe4` |
| `tests/modele_portes.py` | `e08d69017e1938b8488c7c8fa43abea3fabd5775197cb8c5e4c3832a96be0c1e` |
| `tests/noyau_c.py` | `bbab194f6687532783bb3e1a7149a3cbb5c3a70aceab656c810b2435abe7ca66` |
| `tests/run_all.py` | `28150ab16dce1dc61a9c95094155a9647defc5205253366dbdb0cd6b38f38f15` |
| `tests/test_api_c.py` | `fb0bd14e1ae794d2e81f176e6e3380c414ccc98c33a60cd5a2ddbb2e102231df` |
| `tests/test_b1024_certificats.py` | `6670b125eb8aec9af6395918bf9c360ef947e99b3249a55d640575e6f550d69d` |
| `tests/test_b1024_etudes.py` | `2744c8c228823203a7814d0c3609a23156771cf3947ebe3e5880c7f283546829` |
| `tests/test_b1024_preuves.py` | `a774a1437a1e68714faf2ff409df099cafdf680e24b3ef9518f23dd1d5159eb9` |
| `tests/test_b1024_seconde_implementation.py` | `78816be90990147cc5a9f1645f86169d9b6b8813186e8e7b258a1dd111465602` |
| `tests/test_b1024_statistiques.py` | `dea5251440698887e0c95b3c407579c0a6f06dfe0b8644c8da3e3eb9b28ef1fe` |
| `tests/test_b1024_structure.py` | `015b898f57d60e474d55721660df3f9d9860fb2dbb5eb13ac80d1e765ba08482` |
| `tests/test_bornes_preuves.py` | `e6986bd72d7358823cbb5760057838aeac924af9005d3577e5ac8aab7a9e89f0` |
| `tests/test_c_brume1024_valgrind.py` | `35d2f402da39dbaa3cf61a5bb69a0007a8edc1284ccc74e08a10f2b6d6edffcb` |
| `tests/test_c_fuzz.py` | `4fd95935c0f7be173c6b4defa8597a8b33f926f9cc325e2061b649be6c75c352` |
| `tests/test_c_gadget_ssb.py` | `9370a80bf2ef8403bfe9ebaa10d0a2d2b245f86ae6cb51844121a343e37716ea` |
| `tests/test_c_impl.py` | `383761c88ba59ff692eb1dae1e0765c4f2ee08a3de69137a4b8696dcb150444f` |
| `tests/test_c_kem_bruit.py` | `5c9515ff8cf3cc7bff49167c1a80b34e15f5b87c25927c94e80e1c9fc5449472` |
| `tests/test_c_kem_valgrind.py` | `b9a07c42862732d89a1a376b7162e989fdd439be879bb12b672d4304a24e9fd0` |
| `tests/test_c_limites.py` | `d26b04b97ec7f1b55a479a2dee1e71f54589df84534438de859855d3f7eea48d` |
| `tests/test_c_sig_valgrind.py` | `1e52bfe6e42f8e3d4afe9de79137d11ba72065b94cafb9f27025c5c26bf27b63` |
| `tests/test_c_temps.py` | `5bceb630708af45edf109352a85ce59e416516773cd8dbf3c7ae91f7e912df2b` |
| `tests/test_c_vole_temps.py` | `5fe2a1c7cd51a6f696cdb46bf60f4e81ff0cdb9fe73438184909dcac653af937` |
| `tests/test_c_vole_valgrind.py` | `d638cbfa2a11cfaa19684c26f8ecb2f1a1bd2829a0f95abc095c446561be1a3f` |
| `tests/test_erreurs_api.py` | `109eacee7bd73304fa9ebf12b38e4e9c57558594e1670a8233346386835e782c` |
| `tests/test_fonctionnel.py` | `7dbec2bed40a1647d336578ae964867199fe6fbb8176e491b1486cb68a4604ea` |
| `tests/test_isd_parametres.py` | `8c7c8b187193968d5e2c3b25f34bf3c8ae705f25564e6c1ff5d2f586d7e9fad8` |
| `tests/test_kem.py` | `50e14c8fbf49156b98c275ee219cd99d85228ee843167f250b59dd935b1077f4` |
| `tests/test_kem_lemme3.py` | `5b8d4ef4b5bdadf19ee37cbe6c22985178a10ff04695161f430ec3ffe61319e8` |
| `tests/test_kem_theta.py` | `6007068e6a16a8c0a0c2fdbc934d3949458d66293bb22c69fc3a84374e5e0ebd` |
| `tests/test_modele_portes.py` | `427c13ffa9d798a92a595dbfa82f2e314d2376a34530cf6a862fb5cf9e5b55ab` |
| `tests/test_robustesse.py` | `0fe645dd92c798eebc860237b4c10446e1c78af3e78ada27892c698791a1164e` |
| `tests/test_sig.py` | `53231c7da1e69fa5557f84f49923f59fa64a48264c6a365d5326b087d527e12c` |
| `tests/test_sig_hvzk.py` | `5755b92d4abe4d237c2edc1301d5385230e3c750778e8366c5ae8d7530acfbff` |
| `tests/test_sig_modele.py` | `db283b3a25e019fcc5a78bded7761efe1c8be6b3b86ff452c31f6272b8154880` |
| `tests/test_vole.py` | `51f4412275ac07db10ff8023d295de94764161cd9fe596d198b9e75b4edd6502` |
| `tests/test_vole_kz.py` | `e0e832d24ebfec12fc254120ef45c3a6605a7a97e3e0bed1e0bad312cf81c4f8` |
| `tests/verifier_controles.py` | `abf7fabd005005810a579417fb8ae8c5996337d6c800ff697840023396337367` |

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
| `resultats/SYNTHESE.md` | `552ecb168b7640da0e302a2fec7916f812d471ee1614665c6f59b1aad67521b1` |
| `resultats/api_c.json` | `4990661e9feb1eb141b18c48d8988e408219c412c1c562808d0d3be42652ec86` |
| `resultats/b1024_certificats.json` | `d9fef4bf1cb83ee0d806ba580d8fa1093f37c5d35e5d1fe4e71e8cf58571be82` |
| `resultats/b1024_etudes.json` | `cfec82d1169d1204fb770fbb5ef62e9cec71a461be8fdfa8ad5817f3134d2efc` |
| `resultats/b1024_preuves.json` | `57fdcd8d76ac1dc7684a4f0f06da199b065fd153d52d73d411dc087dd5896872` |
| `resultats/b1024_seconde_implementation.json` | `18d850d588f501f97c07d7b6f3e4a9877d5674713bf74ce85aabd3c63fc36b1d` |
| `resultats/b1024_statistiques.json` | `0b877baf567a22fbae1bc5d892a861d6e1718e31c7bc55af52441c24b77988ac` |
| `resultats/b1024_structure.json` | `3f2086293dec575b05d39783e7ec97703f2c14a6599fdcb14663d359c1a8f9a6` |
| `resultats/bornes_preuves.json` | `fcb79cd3dccf59d0a925c970b2b7fd25531712bdb4e5a9665e3d8905f1340331` |
| `resultats/brume1024.json` | `84f652f7f33f87f2a75904d12fca5f68c627de275529a9847437f818b6942b9e` |
| `resultats/brume1024_api.json` | `10f78e61f61d6600d54bd9c7bbb174a6def2c6aa58a335e501abe4952fc1d40b` |
| `resultats/brume1024_api_portable.json` | `73c38fdf67f44e0969ce44e9817d10cdb3a8fbedb68ccf3474a5cb790a808c8a` |
| `resultats/c_brume1024_valgrind.json` | `ed900e06ed5ea84771c22488011d532edc4632fdb24c58a414a5cae320b3c098` |
| `resultats/c_fuzz.json` | `9f9e8082d3c789099b61b90aa37a7be04909923f27a52fbab9f442e0333da578` |
| `resultats/c_gadget_ssb.json` | `536973da1fcf2df5949421d77117525945faa1d82beffa06e369f76b3d293b71` |
| `resultats/c_impl.json` | `bc17b791257c1c153a81273e672fe48caf9022231f16399596266c092f45d44f` |
| `resultats/c_kem_bruit.json` | `204c920ac90e1f145756804902b495be3976d29ea4aceece7e18966871f71642` |
| `resultats/c_kem_valgrind.json` | `3c172333384109966e2568d2395d2c39a1933eb56ec33e5d773086fa42032371` |
| `resultats/c_limites.json` | `ca964c6bdf37bb47bf93fc11925620f0a455934e5904013a1eea1d1217a630c6` |
| `resultats/c_sig_valgrind.json` | `0bc530416f6d361f1e523c8f22d70982e4ddaa1c6f2d67f88f9edb43357837b3` |
| `resultats/c_temps.json` | `b38c24fc2dfec36ee4ce8893cb4ee63c7d1065ff907251db7f3d4539882eadac` |
| `resultats/c_vole_temps.json` | `d741acde97766afe4a6edc185fdb3562780bbd8e4fe9f400f4a30cffc2e86bf6` |
| `resultats/c_vole_valgrind.json` | `3bc56e663002ab3faedde029a2e60933f6e93a567670469366e5766fe3947294` |
| `resultats/compression_sig.json` | `feee314a3c2e1aec4d1bfd5adb84f8a737c1de0e224c436a0b93e176e38c6bf8` |
| `resultats/erreurs_api.json` | `32c31a6b348394f33eab114e9fcde4b6a6dacbb3cc4eb8cee93c8d6068158a72` |
| `resultats/fonctionnel.json` | `aa57f3c85eca039043210d70902570604e9cd217572fd1dd1b4ed45e70bc159a` |
| `resultats/h1p_fourier.json` | `9205cd20d6e60200b6539b4469608547ff1235f9af1c7f824f591f0436b58aa2` |
| `resultats/isd_comparaison.json` | `cbf2bd2e5de2cb5385abbe0bb2e1dc3c455f20e90738816e16b6a5f66f104d4e` |
| `resultats/isd_parametres.json` | `6cbfc58dc41e39c0372701b1e9de7b97fbd522d0ff3f6602066f7ba25746c83a` |
| `resultats/isd_reel.json` | `ff79972f5125fd007c12cc27e1155d424384db95478ea00c87fce73a44e7f339` |
| `resultats/kem.json` | `012a2785d59457f13c38d1c52a82862d5224bd366ff48495bf4172d01e58bd01` |
| `resultats/kem_distributions.json` | `544e36b939fb870a20cacc1994d4a554b8ef1a4be8213e60003a4572e3cea1a5` |
| `resultats/kem_lemme3.json` | `b48e270ee0e14394dcbe893ad9b66e232e2e62651a21b252942c0c2693f61103` |
| `resultats/kem_rejet.json` | `d3c961363722300d1e4c275307997d7b681144bd27bd030237080fedccfe5086` |
| `resultats/kem_theta.json` | `e6bae78b8027657768d0a113bd5a11de2fc375ca6ecf813208d980c59cf45270` |
| `resultats/modele_portes.json` | `bad171645659aec66117fbf71463ff7acff1b91da7fd27fd71fc3923eb9a0628` |
| `resultats/revue_c.json` | `a6e861a040338593f1f8e599d7c272627aed502ac34cada3401e1add13e3903a` |
| `resultats/robustesse.json` | `dfab83d486554675c964cd27d21ea9d5c95698e26a913d7bf329c0793bc7a45f` |
| `resultats/sig.json` | `afef773f6d9f3e8b17d1245096300c6f6f4ecaf4ca74117e9a9777852f58f53a` |
| `resultats/sig_flux.json` | `aa81d832374d60ba5e3e0076e607caea6198bfe5c1bcf312c7557844c7a32176` |
| `resultats/sig_hvzk.json` | `0a2b4f8f80891e825ee1f81d5d69a7a811f3de3a69d843701daf6a2f434fc876` |
| `resultats/sig_kz.json` | `f46ab751ab9461b5690f01042698bd4acc185e6563173e3e880c3072b976b3a8` |
| `resultats/sig_modele.json` | `3c93dc8fb6ced5d5e2c152a52969fc4dbd968f4c1f81132ace90d67ef0946f40` |
| `resultats/temps1024.json` | `3f79ec5e9fa8866aa39115f7b7cc6c9d58b5e8741f375400fc18525dcff61994` |
| `resultats/vole.json` | `41fe808be658714ca97152ff1ef27f5e2280cb696a2b4f1ef99f29eb5cb9dfa3` |
| `resultats/vole_kz.json` | `176db71bd18bfbc2d9248f7396c5b641be2d6dfeefec3cbd18f503610b9a39d9` |
| `resultats/vole_proto.json` | `c06306f0de9ba39624120ac0337ab8aa3976326bde8b03b6dfb35e0d4bdc8935` |

## Spécification, preuves et rapports

| Fichier | SHA-256 |
|---|---|
| `docs/AUDIT_EXTERNE.md` | `15181ffed3a873c321f66b349144a0030f07e45f021e088b030613a554ca0a31` |
| `docs/AUDIT_REPORT.md` | `c74512a68e6e78d18d9d548ce8bf65ae21c37f3829dba1268537204e785845eb` |
| `docs/CAMPAIGN_24H.md` | `e2773b4e8aae053d0a6eea15c59050409f1950e9b0f4031b54c939344caa11d4` |
| `docs/DESIGN_NOTE.md` | `ade0afa112999029530930f6312ffe3df5cd65f9b6a827357326ff7bf560c29e` |
| `docs/GPU_CRYPTANALYSIS_PLAN.md` | `58ffa7a0da65ec8186eb16f8278d6a7030a1d6f23f6cee58780977489631db7a` |
| `docs/LEADS.md` | `e2a6ac832fa1890ea3a39e0e1033c6d910574351324b017582bd3c2baac1ee96` |
| `docs/MIGRATION_V06.md` | `44a0acc6dd6853bca6e9cc1bd379d84c37fc508f757ae732ab6108b01a6491ec` |
| `docs/NIST_CATEGORIES.md` | `ecc5a52db2b2596a582d76f6077fb4def35cb8f4331e3204187beb3a752ebec2` |
| `docs/PROOFS.md` | `0e6bf826859a862d942bacdbbf89a217f0d97c5f54a285e75334c1f3abd34739` |
| `docs/README.md` | `ce85b9771cb28d2924191caea0a2c46d092441fb4712dfce9c245c1a2a8436bf` |
| `docs/REVUE_CODE_DEPOT_C.md` | `9185183f7c008508342eae0f3ce3b19077c6bbe671645584c766337c88c7e2f1` |
| `docs/SPEC.md` | `6266a37fb419949da74567239954d1355fc15da476e081dfb6b3c2338e9bf55f` |
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
