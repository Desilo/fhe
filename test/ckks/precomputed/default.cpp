#include "ckks/config.h"
#include "ckks/precomputed.h"
#include "common/test.h"
#include "engine/scheme_preset.h"

constexpr int64_t R = 1LL << 62;

TEST(CKKSPrecomputed, Sand) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 4);
  EXPECT_EQ(precomputed.coeff_count_, 8);
  EXPECT_EQ(precomputed.log_coeff_count_, 3);
  EXPECT_EQ(precomputed.chain_count_, 24);
  EXPECT_EQ(precomputed.prime_count_, 25);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 1099511627776);

  std::vector<uint64_t> post_permutation = {0, 4, 1, 5};
  EXPECT_EQ(precomputed.post_permutation_.size(), 8);
  expect_vector_equals(precomputed.post_permutation_, post_permutation, 4);

  std::vector<uint64_t> pre_permutation = {0, 2, 4, 6};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 8);
  expect_vector_equals(precomputed.pre_permutation_, pre_permutation, 4);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.70710678118654757, -0.70710678118654746),
      std::complex(0.0, -1.0),
      std::complex(-0.70710678118654746, -0.70710678118654757)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-9);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.70710678118654757, 0.70710678118654746),
      std::complex(0.0, 1.0),
      std::complex(-0.70710678118654746, 0.70710678118654757)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {
      1152921504606846097, 1099511627297, 1099511628769, 1099511627089,
      1099511629121,       1099511626321, 1099511630417, 1099511626049,
      1099511630561,       1099511625409, 1099511632913, 1099511625073,
      1099511632993,       1099511623633, 1099511633153, 1099511618209,
      1099511633201,       1099511616913, 1099511633377, 1099511616689,
      1099511633393,       1099511616481, 1099511633489, 1152921504606846577,
      1152921504606846097};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {
      2305843009213692194, 2199023254594, 2199023257538, 2199023254178,
      2199023258242,       2199023252642, 2199023260834, 2199023252098,
      2199023261122,       2199023250818, 2199023265826, 2199023250146,
      2199023265986,       2199023247266, 2199023266306, 2199023236418,
      2199023266402,       2199023233826, 2199023266754, 2199023233378,
      2199023266786,       2199023232962, 2199023266978, 2305843009213693154,
      2305843009213692194};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {
      576460752303423048, 549755813648, 549755814384, 549755813544,
      549755814560,       549755813160, 549755815208, 549755813024,
      549755815280,       549755812704, 549755816456, 549755812536,
      549755816496,       549755811816, 549755816576, 549755809104,
      549755816600,       549755808456, 549755816688, 549755808344,
      549755816696,       549755808240, 549755816744, 576460752303423288,
      576460752303423048};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {
      12362256,     1758435824,    1083845282257, 5187883248,   1060581411121,
      49284342000,  804781058881,  82413241328,   753894244561, 212185037808,
      30077564178,  315978926832,  1026670045971, 38285371679,  811166617331,
      816156377700, 743956649603,  718963785918,  487173351315, 914582250957,
      463011378371, 1065487628380, 315126866915,  2547216,      12362256};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {
      518093281364851599,  2862593532740565535, 3389065336791793631,
      1810625812868535375, 4576088067287840063, 1163442537919443279,
      25033121618100559,   2171258079147354431, 3463388700855846623,
      3947014878685193919, 534258077633389327,  3359057645690672239,
      3513592387824676959};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {
      576460752303423488, 251133952,  1098991010785, 360185856,
      1098806461761,      762839040,  1098126985809, 905445376,
      1098051488481,      1240989696, 1096818365457, 1417150464,
      1096776422497,      2172125184, 1096692536577, 5015863296,
      1096667370801,      5695340544, 1096575096289, 5812781056,
      1096566707697,      5921832960, 1096516376145, 576460752303423488,
      576460752303423488};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {
      412218553699309604, 753604283963634156, 309719362204639333,
      380101822316277589, 533199095251533384, 342888388547029265,
      685977839654643293, 989415754361,       337786523526,
      616630767247,       751409830250,       1096294094988,
      197934104926,       812253083602,       43375851060,
      666349746656,       163679848558,       504407542817,
      1065033656158,      949580098484,       91589064492,
      961251799070};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {
      466943664952202804, 810033116059816832, 619722409355312713,
      772819682290568508, 843202142402206764, 399317220643211941,
      740702950907536493, 287258543695,       901577522371,
      3217532309,         348101797047,       482880860050,
      761725103771,       110095872936,       1007922564277,
      149931530285,       34477972611,        595104085952,
      935831780211,       433161882113,       1056135777709,
      773545056337,       786382982512,       516367302558,
      570611565067};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  std::vector<int64_t> p_product_mult_r = {0,
                                           433488913086,
                                           358534190553,
                                           767004912687,
                                           550957804536,
                                           145595087825,
                                           867045197236,
                                           250581182594,
                                           285710085011,
                                           122499720452,
                                           804634198572,
                                           9197294517,
                                           1073847866732,
                                           403227685802,
                                           510347288299,
                                           116860179641,
                                           670510869883,
                                           262280258396,
                                           155679014826,
                                           859732706957,
                                           208627212746,
                                           405483958653,
                                           525588231818,
                                           1152921504606080497};
  expect_array_equals(precomputed.get_p_product_mult_r(0), p_product_mult_r);

  std::vector<std::vector<int64_t>> p_inverse_mult_r = {{0,
                                                         777071200216,
                                                         981839648607,
                                                         370931263550,
                                                         582774321441,
                                                         870016006470,
                                                         663347140256,
                                                         672326690560,
                                                         648441466553,
                                                         419443583747,
                                                         522502334526,
                                                         955981186444,
                                                         249336986702,
                                                         293882800911,
                                                         122651291386,
                                                         573144842651,
                                                         367716492528,
                                                         540696467831,
                                                         741718770525,
                                                         321290036649,
                                                         199016087801,
                                                         142090207575,
                                                         260691256776,
                                                         835868090839963765}};

  auto precomputed_pir = precomputed.get_p_inverse_mult_r(0);
  ASSERT_EQ(precomputed_pir.size(), 1);
  for (int p_index = 0; p_index < 1; p_index++) {
    expect_array_equals(precomputed_pir[p_index], p_inverse_mult_r[p_index]);
  }

  for (int moduli_id = 1; moduli_id <= 24; moduli_id++) {
    EXPECT_NE(precomputed.get_rescale_scale(moduli_id), nullptr);
  }
}

TEST(CKKSPrecomputed, Pebble) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 8);
  EXPECT_EQ(precomputed.coeff_count_, 16);
  EXPECT_EQ(precomputed.log_coeff_count_, 4);
  EXPECT_EQ(precomputed.chain_count_, 24);
  EXPECT_EQ(precomputed.prime_count_, 25);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 1099511627776);

  std::vector<uint64_t> post_permutation = {0, 8, 1, 9};
  EXPECT_EQ(precomputed.post_permutation_.size(), 16);
  expect_vector_equals(precomputed.post_permutation_, post_permutation, 4);

  std::vector<uint64_t> pre_permutation = {0, 2, 12, 14};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 16);
  expect_vector_equals(precomputed.pre_permutation_, pre_permutation, 4);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.92387953251128674, -0.38268343236508978),
      std::complex(0.70710678118654757, -0.70710678118654746),
      std::complex(0.38268343236508984, -0.92387953251128674)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-9);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.92387953251128674, 0.38268343236508978),
      std::complex(0.70710678118654757, 0.70710678118654746),
      std::complex(0.38268343236508984, 0.92387953251128674)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {
      1152921504606844513, 1099511627297, 1099511628769, 1099511626049,
      1099511631457,       1099511625409, 1099511631937, 1099511624993,
      1099511632993,       1099511621249, 1099511633153, 1099511616481,
      1099511633377,       1099511616193, 1099511635009, 1099511615681,
      1099511652257,       1099511615329, 1099511652769, 1099511614529,
      1099511652929,       1099511611873, 1099511653249, 1152921504606845473,
      1152921504606844513};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {
      2305843009213689026, 2199023254594, 2199023257538, 2199023252098,
      2199023262914,       2199023250818, 2199023263874, 2199023249986,
      2199023265986,       2199023242498, 2199023266306, 2199023232962,
      2199023266754,       2199023232386, 2199023270018, 2199023231362,
      2199023304514,       2199023230658, 2199023305538, 2199023229058,
      2199023305858,       2199023223746, 2199023306498, 2305843009213690946,
      2305843009213689026};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {
      576460752303422256, 549755813648, 549755814384, 549755813024,
      549755815728,       549755812704, 549755815968, 549755812496,
      549755816496,       549755810624, 549755816576, 549755808240,
      549755816688,       549755808096, 549755817504, 549755807840,
      549755826128,       549755807664, 549755826384, 549755807264,
      549755826464,       549755805936, 549755826624, 576460752303422736,
      576460752303422256};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {
      97061904,     1758435824,    1083845282257, 82413241328,   301484907601,
      212185037808, 1046331659378, 344873322992,  1026670045971, 50937277932,
      811166617331, 1065487628380, 487173351315,  675440320346,  542610316662,
      822061725975, 544497156742,  67857788756,   898598036820,  910091444111,
      468555374296, 579602020598,  522140451937,  36144144,      97061904};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {
      4038267892912411231, 2862593532740565535, 3389065336791793631,
      2171258079147354431, 444307878259911263,  3947014878685193919,
      1715736149394980927, 951745191521693983,  3513592387824676959,
      1766627105872127615, 1602030717758805247, 2205634226085449695,
      4348708994682524127};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {
      288230376151711744, 125566976,  1099251319777, 452722688,
      1098546679393,      620494848,  1098420850753, 729546752,
      1098144027745,      1711013888, 1098102084865, 2960916480,
      1098043364833,      3036413952, 1097615547457, 3170631680,
      1093094104993,      3262906368, 1092959887777, 3472621568,
      1092917944897,      4168876032, 1092834059137, 288230376151711744,
      288230376151711744};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {
      1120889322250572310, 853233588903768284,  498015480496202538,
      697459761672130565,  1095469082079527282, 293683139508317969,
      203032496445404166,  363209959860623689,  386450276390664007,
      697781461565252757,  33239088143045801,   1019516673416241098,
      671151095393758282,  432056396889708580,  311815866572129573,
      989415754361,        337786523526,        616630767247,
      751409830250,        1096294094988,       197934104926,
      812253083602};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {
      841105638034714940, 720865107717135933,  481770409213086231,
      133404831190603415, 1119682416463798712, 455140043041591756,
      766471228216180506, 789711544746220824,  949889008161440347,
      859238365098526544, 57452422527317231,   455461742934713948,
      654906024110641975, 299687915703076229,  32032182356272203,
      639940600893,       657113403667,        79574868544,
      1050713756379,      191942707294,        65291288161,
      25891987340,        207240733722,        287258543695,
      901577522371};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  std::vector<int64_t> p_product_mult_r = {0,
                                           549654355233,
                                           358735511187,
                                           871405264461,
                                           443928787610,
                                           889352673875,
                                           915889984342,
                                           1023053802743,
                                           550063016268,
                                           754819538617,
                                           1049566838475,
                                           130806610241,
                                           1083593092521,
                                           906381032804,
                                           639635465274,
                                           876464277608,
                                           700902675916,
                                           75209290538,
                                           31365913226,
                                           1092281829041,
                                           477234877386,
                                           234819811107,
                                           223000838857,
                                           1152921504601073953};
  expect_array_equals(precomputed.get_p_product_mult_r(0), p_product_mult_r);

  std::vector<std::vector<int64_t>> p_inverse_mult_r = {{0,
                                                         1058519755588,
                                                         650933137487,
                                                         402092264260,
                                                         990736062528,
                                                         109726767989,
                                                         311705038246,
                                                         712426780929,
                                                         1064809350138,
                                                         777241793866,
                                                         1014600849876,
                                                         922910463734,
                                                         59715098495,
                                                         601688814770,
                                                         254578292685,
                                                         898458903772,
                                                         235638867826,
                                                         812213963899,
                                                         290750718081,
                                                         272858150392,
                                                         843828019525,
                                                         1076704946725,
                                                         553250369041,
                                                         533226195880666025}};

  auto precomputed_pir = precomputed.get_p_inverse_mult_r(0);
  ASSERT_EQ(precomputed_pir.size(), 1);
  for (int p_index = 0; p_index < 1; p_index++) {
    expect_array_equals(precomputed_pir[p_index], p_inverse_mult_r[p_index]);
  }

  for (int moduli_id = 1; moduli_id <= 24; moduli_id++) {
    EXPECT_NE(precomputed.get_rescale_scale(moduli_id), nullptr);
  }
}

TEST(CKKSPrecomputed, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 4096);
  EXPECT_EQ(precomputed.coeff_count_, 8192);
  EXPECT_EQ(precomputed.log_coeff_count_, 13);
  EXPECT_EQ(precomputed.chain_count_, 4);
  EXPECT_EQ(precomputed.prime_count_, 5);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 1099511627776);

  std::vector<uint64_t> pre_permutation = {0, 2, 12, 62};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 8192);
  expect_array_equals(precomputed.get_pre_permutation(), pre_permutation);

  std::vector<uint64_t> post_permutation = {0, 4096, 1, 6105};
  EXPECT_EQ(precomputed.post_permutation_.size(), 8192);
  expect_array_equals(precomputed.get_post_permutation(), post_permutation);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.9999997058628822, -0.0007669903187427045),
      std::complex(0.9999988234517019, -0.0015339801862847655),
      std::complex(0.9999973527669782, -0.002300969151425805)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-9);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.9999997058628822, 0.0007669903187427045),
      std::complex(0.9999988234517019, 0.0015339801862847655),
      std::complex(0.9999973527669782, 0.002300969151425805)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {1152921504606748673, 1099511922689, 1099510890497,
                             1152921504606830593, 1152921504606748673};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {2305843009213497346, 2199023845378,
                                    2199021780994, 2305843009213661186,
                                    2305843009213497346};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {576460752303374336, 549755961344,
                                  549755445248, 576460752303415296,
                                  576460752303374336};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {154615676944, 333401010676, 198138004164,
                                    4294443024, 154615676944};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {4610736030717214719, 2835896587270782975,
                             4607231353240731647, 1080859512253956095,
                             4610736030717214719};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {562949953421312, 1099360927233,
                                              377486848, 562949953421312,
                                              562949953421312};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {445523564914844012, 1114543911831482092,
                               92957750393765587, 374223376506562498};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {1394161141106179, 1149279895586543456,
                                       66236548431759242, 473251796992050286};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  std::vector<int64_t> p_product_mult_r = {0, 325609241726, 51848050862,
                                           1152921499238449153};
  expect_array_equals(precomputed.get_p_product_mult_r(0), p_product_mult_r);

  std::vector<std::vector<int64_t>> p_inverse_mult_r = {
      {0, 715651658816, 292639282731, 461112306847390106}};
  auto precomputed_pir = precomputed.get_p_inverse_mult_r(0);
  ASSERT_EQ(precomputed_pir.size(), 1);
  for (int p_index = 0; p_index < 1; p_index++) {
    expect_array_equals(precomputed_pir[p_index], p_inverse_mult_r[p_index]);
  }

  std::vector<std::vector<int64_t>> rescale_scale = {
      {715651658816, 292639282731, 461112306847390106, 0},
      {872630686798, 968738560891204246, 402506552094018497},
      {949902557521525030, 846066770320173526},
      {691809197759391335}};
  for (int moduli_id = 0; moduli_id < 4; moduli_id++) {
    expect_array_equals(precomputed.get_rescale_scale(moduli_id + 1),
                        rescale_scale[moduli_id]);
  }
}

TEST(CKKSPrecomputed, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 8192);
  EXPECT_EQ(precomputed.coeff_count_, 16384);
  EXPECT_EQ(precomputed.log_coeff_count_, 14);
  EXPECT_EQ(precomputed.chain_count_, 9);
  EXPECT_EQ(precomputed.prime_count_, 10);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 1099511627776);

  std::vector<uint64_t> pre_permutation = {0, 2, 12, 62};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 16384);
  expect_array_equals(precomputed.get_pre_permutation(), pre_permutation);

  std::vector<uint64_t> post_permutation = {0, 8192, 1, 14297};
  EXPECT_EQ(precomputed.post_permutation_.size(), 16384);
  expect_array_equals(precomputed.get_post_permutation(), post_permutation);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.9999999264657179, -0.00038349518757139556),
      std::complex(0.9999997058628822, -0.0007669903187427045),
      std::complex(0.9999993381915255, -0.0011504853371138485)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-9);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.9999999264657179, 0.00038349518757139556),
      std::complex(0.9999997058628822, 0.0007669903187427045),
      std::complex(0.9999993381915255, 0.0011504853371138485)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {
      1152921504606683137, 1099510054913,      1099515691009, 1099508121601,
      1099515789313,       1099507695617,      1099516280833, 1099506515969,
      1152921504606748673, 1152921504606683137};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {
      2305843009213366274, 2199020109826,      2199031382018, 2199016243202,
      2199031578626,       2199015391234,      2199032561666, 2199013031938,
      2305843009213497346, 2305843009213366274};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {
      576460752303341568, 549755027456,      549757845504, 549754060800,
      549757894656,       549753847808,      549758140416, 549753257984,
      576460752303374336, 576460752303341568};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {
      429491486736, 1099486461964, 817983354026, 492971480121, 477121048931,
      77810628151,  896168319846,  180398350616, 154615676944, 429491486736};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {4607287945072574463, 4179339079808712703,
                             2807978957326909439, 348349274289504255,
                             1814899246592131071, 3188534173803741183,
                             2888757134567604223, 2181968988386492415,
                             4610736030717214719, 4607287945072574463};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {
      281474976710656, 402652928,      1098475503361, 897580800,
      1098450435841,   1006632704,     1098325098241, 1308622592,
      281474976710656, 281474976710656};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {1006865104779340474, 215526123826131610,
                               676069197320426198, 209917423119671486};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {633899199963091708, 12121763667306633,
                                       79693848525165847, 246908663542386600};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  std::vector<int64_t> p_product_mult_r = {0,
                                           515394437118,
                                           468729142595,
                                           961184056584,
                                           290506148978,
                                           113966742919,
                                           298797299447,
                                           343624374337,
                                           1152921478837207041};
  expect_array_equals(precomputed.get_p_product_mult_r(0), p_product_mult_r);

  std::vector<std::vector<int64_t>> p_inverse_mult_r = {
      {0, 909118082962, 708729882666, 471533895801, 544470590347, 570150293449,
       679780941540, 448629062455, 1152851135862571009}};
  auto precomputed_pir = precomputed.get_p_inverse_mult_r(0);
  ASSERT_EQ(precomputed_pir.size(), 1);
  for (int p_index = 0; p_index < 1; p_index++) {
    expect_array_equals(precomputed_pir[p_index], p_inverse_mult_r[p_index]);
  }

  for (int moduli_id = 1; moduli_id <= 9; moduli_id++) {
    EXPECT_NE(precomputed.get_rescale_scale(moduli_id), nullptr);
  }
}

TEST(CKKSPrecomputed, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 16384);
  EXPECT_EQ(precomputed.coeff_count_, 32768);
  EXPECT_EQ(precomputed.log_coeff_count_, 15);
  EXPECT_EQ(precomputed.chain_count_, 19);
  EXPECT_EQ(precomputed.prime_count_, 21);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 1099511627776);

  std::vector<uint64_t> pre_permutation = {0, 2, 12, 62};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 32768);
  expect_array_equals(precomputed.get_pre_permutation(), pre_permutation);

  std::vector<uint64_t> post_permutation = {0, 16384, 1, 22489};
  EXPECT_EQ(precomputed.post_permutation_.size(), 32768);
  expect_array_equals(precomputed.get_post_permutation(), post_permutation);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.9999999816164293, -0.0001917475973107033),
      std::complex(0.9999999264657179, -0.00038349518757139556),
      std::complex(0.9999998345478677, -0.0005752427637320661)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-9);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.9999999816164293, 0.0001917475973107033),
      std::complex(0.9999999264657179, 0.00038349518757139556),
      std::complex(0.9999998345478677, 0.0005752427637320661)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {
      1152921504598720513, 1099510054913,       1099515691009,
      1099507695617,       1099516280833,       1099506515969,
      1099520606209,       1099504549889,       1099523555329,
      1099503894529,       1099527946241,       1099503370241,
      1099529060353,       1099498258433,       1099531223041,
      1099469684737,       1099532009473,       1099468767233,
      1152921504606584833, 1152921504598720513, 1152921504597016577};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {
      2305843009197441026, 2199020109826,       2199031382018,
      2199015391234,       2199032561666,       2199013031938,
      2199041212418,       2199009099778,       2199047110658,
      2199007789058,       2199055892482,       2199006740482,
      2199058120706,       2198996516866,       2199062446082,
      2198939369474,       2199064018946,       2198937534466,
      2305843009213169666, 2305843009197441026, 2305843009194033154};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {
      576460752299360256, 549755027456, 549757845504,       549753847808,
      549758140416,       549753257984, 549760303104,       549752274944,
      549761777664,       549751947264, 549763973120,       549751685120,
      549764530176,       549749129216, 549765611520,       549734842368,
      549766004736,       549734383616, 576460752303292416, 576460752299360256,
      576460752298508288};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {
      1056630414245904, 1099486461964, 817983354026,  77810628151,
      896168319846,     180398350616,  962009779644,  283512112828,
      412181037527,     192926013,     1043800877917, 754920430386,
      651512778074,     85667719869,   388214139718,  720154666458,
      783663619422,     627571437648,  1099503239184, 1056630414245904,
      1546187911987216};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {
      4053173625208176639, 4179339079808712703, 2807978957326909439,
      3188534173803741183, 2888757134567604223, 2181968988386492415,
      3051390709799649279, 2251750816691257343, 1231593331112673279,
      1866683341924335615, 2281089493500493823, 3893294790464372735,
      2010554438443991039, 954585481141813247,  833627481153667071,
      4609927899292631039, 1073412722151325695, 1387524558280589311,
      1134907037377626111, 4053173625208176639, 1182098265410764799};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {
      140737488355328, 201326464,  1098995597185,   503316352,
      1098920689537,   654311296,  1098371366785,   905969536,
      1097996828545,   989855616,  1097439182721,   1056964480,
      1097297690497,   1711275904, 1097023029121,   5368708992,
      1096923152257,   5486149504, 140737488355328, 140737488355328,
      140737488355328};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {20347699716009612, 282006193726917038,
                               54652613579671190, 866211086935993210};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {995106542454238105, 560467250798583486,
                                       314961357560284854, 698276179080712024};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  std::vector<int64_t> p_product_mult_r = {0,
                                           309097725835,
                                           476588484902,
                                           874284243652,
                                           402980667375,
                                           1090430438424,
                                           258534581277,
                                           933147746644,
                                           582875343427,
                                           27369252825,
                                           611029823103,
                                           153646627099,
                                           244010957257,
                                           595320403995,
                                           664719990887,
                                           573659759951,
                                           1093086354610,
                                           153632463400,
                                           504102166975217596};
  expect_array_equals(precomputed.get_p_product_mult_r(0), p_product_mult_r);

  std::vector<std::vector<int64_t>> p_inverse_mult_r = {
      {886859989355008946, 551772387884,      211990157095,
       279593138667,       824625594918,      210673242430,
       790245758602,       124359840744,      425429106268,
       184942916252,       71617212907,       865433142367,
       869179566573,       299272577019,      207341181853,
       1017069806882,      43076894820,       4034418380,
       126347080170966984, 886859989355008946},
      {0, 168261833926, 402346525056, 868035923321, 578668671610, 538189080309,
       420278422998, 479445774595, 875653950899, 282183732590, 68296659248,
       1030988223868, 590763088305, 470888096002, 1071529221551, 1017938894605,
       939792576925, 1074595521573, 845475183638627397}};
  auto precomputed_pir = precomputed.get_p_inverse_mult_r(0);
  ASSERT_EQ(precomputed_pir.size(), 2);
  for (int p_index = 0; p_index < 2; p_index++) {
    expect_array_equals(precomputed_pir[p_index], p_inverse_mult_r[p_index]);
  }

  for (int moduli_id = 1; moduli_id <= 20; moduli_id++) {
    EXPECT_NE(precomputed.get_rescale_scale(moduli_id), nullptr);
  }
}

TEST(CKKSPrecomputed, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 32768);
  EXPECT_EQ(precomputed.coeff_count_, 65536);
  EXPECT_EQ(precomputed.log_coeff_count_, 16);
  EXPECT_EQ(precomputed.chain_count_, 38);
  EXPECT_EQ(precomputed.prime_count_, 42);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 1099511627776);

  std::vector<uint64_t> pre_permutation = {0, 2, 12, 62};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 65536);
  expect_array_equals(precomputed.get_pre_permutation(), pre_permutation);

  std::vector<uint64_t> post_permutation = {0, 32768, 1, 55257};
  EXPECT_EQ(precomputed.post_permutation_.size(), 65536);
  expect_array_equals(precomputed.get_post_permutation(), post_permutation);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.9999999954041073, -9.587379909597734e-05),
      std::complex(0.9999999816164293, -0.0001917475973107033),
      std::complex(0.9999999586369661, -0.0002876213937629265)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-9);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.9999999954041073, 9.587379909597734e-05),
      std::complex(0.9999999816164293, 0.0001917475973107033),
      std::complex(0.9999999586369661, 0.0002876213937629265)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {
      1152921504598720513, 1099510054913,       1099515691009,
      1099507695617,       1099516870657,       1099506515969,
      1099521458177,       1099503894529,       1099522375681,
      1099490000897,       1099523555329,       1099489607681,
      1099525128193,       1099486855169,       1099526176769,
      1099484889089,       1099529060353,       1099480956929,
      1099535220737,       1099469684737,       1099536138241,
      1099468767233,       1099537580033,       1099461820417,
      1099538104321,       1099457495041,       1099540725761,
      1099455004673,       1099540856833,       1099454218241,
      1099591974913,       1099453431809,       1099629723649,
      1099451465729,       1099630510081,       1099451072513,
      1099630903297,       1152921504606584833, 1152921504598720513,
      1152921504597016577, 1152921504595968001, 1152921504592822273};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {
      2305843009197441026, 2199020109826,       2199031382018,
      2199015391234,       2199033741314,       2199013031938,
      2199042916354,       2199007789058,       2199044751362,
      2198980001794,       2199047110658,       2198979215362,
      2199050256386,       2198973710338,       2199052353538,
      2198969778178,       2199058120706,       2198961913858,
      2199070441474,       2198939369474,       2199072276482,
      2198937534466,       2199075160066,       2198923640834,
      2199076208642,       2198914990082,       2199081451522,
      2198910009346,       2199081713666,       2198908436482,
      2199183949826,       2198906863618,       2199259447298,
      2198902931458,       2199261020162,       2198902145026,
      2199261806594,       2305843009213169666, 2305843009197441026,
      2305843009194033154, 2305843009191936002, 2305843009185644546};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {
      576460752299360256, 549755027456,       549757845504,
      549753847808,       549758435328,       549753257984,
      549760729088,       549751947264,       549761187840,
      549745000448,       549761777664,       549744803840,
      549762564096,       549743427584,       549763088384,
      549742444544,       549764530176,       549740478464,
      549767610368,       549734842368,       549768069120,
      549734383616,       549768790016,       549730910208,
      549769052160,       549728747520,       549770362880,
      549727502336,       549770428416,       549727109120,
      549795987456,       549726715904,       549814861824,
      549725732864,       549815255040,       549725536256,
      549815451648,       576460752303292416, 576460752299360256,
      576460752298508288, 576460752297984000, 576460752296411136};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {
      1056630414245904, 1099486461964,   817983354026,     77810628151,
      1055225011601,    180398350616,    424681123232,     192926013,
      441329738179,     667881415080,    412181037527,     830537258835,
      945980631463,     71495178776,     901328967597,     565081357992,
      651512778074,     270140303843,    776493190435,     720154666458,
      1088254444514,    627571437648,    309490669387,     332843631128,
      478250351288,     228243226091,    306633493257,     59471435355,
      309772725260,     1093643035236,   362355169641,     1073484774883,
      252047609225,     589705322537,    97297612693,      72532544999,
      863678499840,     1099503239184,   1056630414245904, 1546187911987216,
      1893633552810000, 3147076707811344};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {
      4053173625208176639, 4179339079808712703, 2807978957326909439,
      3188534173803741183, 3458738125546717183, 2181968988386492415,
      1411782945937948671, 1866683341924335615, 450245544819032063,
      4113571637154414591, 1231593331112673279, 1152437719468605439,
      556013392273211391,  1357222705031938047, 3924676501611347967,
      1872783587035054079, 2010554438443991039, 1494255474850922495,
      1872941916759785471, 4609927899292631039, 1303192428814401535,
      1387524558280589311, 3944480853522644991, 3600400028248047615,
      4556942915054862335, 3876921825330331647, 1998752641420361727,
      4608480941975797759, 4104177822174412799, 1095583553708883967,
      2364690641139138559, 1293651021444677631, 2573372450570633215,
      2907958786526937087, 3559474401744650239, 4193689012162265087,
      3282409377194835967, 1134907037377626111, 4053173625208176639,
      1182098265410764799, 263342226071486463,  389364675431235583};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {
      70368744177664, 100663232,      1099255644097,  251658176,
      1099181326273,  327155648,      1098892312513,  494927808,
      1098834509761,  1384120256,     1098760191937,  1409286080,
      1098661101505,  1585446848,     1098595041217,  1711275968,
      1098413375425,  1962934208,     1098025271233,  2684354496,
      1097967468481,  2743074752,     1097876635585,  3187670976,
      1097843605441,  3464495040,     1097678454721,  3623878592,
      1097670197185,  3674210240,     1094449758145,  3724541888,
      1092071587777,  3850371008,     1092022042561,  3875536832,
      1091997269953,  70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {20347699716009612, 282006193726917038,
                               54652613579671190, 866211086935993210};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {850178231243678074, 685101548658244679,
                                       1095268752430331346, 661600600025352636};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  EXPECT_NE(precomputed.get_p_product_mult_r(0), nullptr);
  EXPECT_EQ(precomputed.get_p_inverse_mult_r(0).size(), 4);

  for (int moduli_id = 1; moduli_id <= 41; moduli_id++) {
    EXPECT_NE(precomputed.get_rescale_scale(moduli_id), nullptr);
  }
}

TEST(CKKSPrecomputed, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 32768);
  EXPECT_EQ(precomputed.coeff_count_, 65536);
  EXPECT_EQ(precomputed.log_coeff_count_, 16);
  EXPECT_EQ(precomputed.chain_count_, 28);
  EXPECT_EQ(precomputed.prime_count_, 32);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 18014398509481984);

  std::vector<uint64_t> pre_permutation = {0, 2, 12, 62};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 65536);
  expect_array_equals(precomputed.get_pre_permutation(), pre_permutation);

  std::vector<uint64_t> post_permutation = {0, 32768, 1, 55257};
  EXPECT_EQ(precomputed.post_permutation_.size(), 65536);
  expect_array_equals(precomputed.get_post_permutation(), post_permutation);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.9999999954041073, -9.587379909597734e-05),
      std::complex(0.9999999816164293, -0.0001917475973107033),
      std::complex(0.9999999586369661, -0.0002876213937629265)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-9);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.9999999954041073, 9.587379909597734e-05),
      std::complex(0.9999999816164293, 0.0001917475973107033),
      std::complex(0.9999999586369661, 0.0002876213937629265)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {
      1152921504598720513, 18014398506729473,   18014398514987009,
      18014398505943041,   18014398516559873,   18014398496243713,
      18014398539104257,   18014398495457281,   18014398539497473,
      18014398479204353,   18014398539890689,   18014398452203521,
      18014398544084993,   18014398443552769,   18014398545788929,
      18014398438440961,   18014398546051073,   18014398434902017,
      18014398547623937,   18014398432018433,   18014398661394433,
      18014398431363073,   18014398665195521,   18014398431232001,
      18014398666899457,   18014398388371457,   18014398674239489,
      1152921504606584833, 1152921504598720513, 1152921504597016577,
      1152921504595968001, 1152921504592822273};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {
      2305843009197441026, 36028797013458946,   36028797029974018,
      36028797011886082,   36028797033119746,   36028796992487426,
      36028797078208514,   36028796990914562,   36028797078994946,
      36028796958408706,   36028797079781378,   36028796904407042,
      36028797088169986,   36028796887105538,   36028797091577858,
      36028796876881922,   36028797092102146,   36028796869804034,
      36028797095247874,   36028796864036866,   36028797322788866,
      36028796862726146,   36028797330391042,   36028796862464002,
      36028797333798914,   36028796776742914,   36028797348478978,
      2305843009213169666, 2305843009197441026, 2305843009194033154,
      2305843009191936002, 2305843009185644546};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {
      576460752299360256, 9007199253364736,   9007199257493504,
      9007199252971520,   9007199258279936,   9007199248121856,
      9007199269552128,   9007199247728640,   9007199269748736,
      9007199239602176,   9007199269945344,   9007199226101760,
      9007199272042496,   9007199221776384,   9007199272894464,
      9007199219220480,   9007199273025536,   9007199217451008,
      9007199273811968,   9007199216009216,   9007199330697216,
      9007199215681536,   9007199332597760,   9007199215616000,
      9007199333449728,   9007199194185728,   9007199337119744,
      576460752303292416, 576460752299360256, 576460752298508288,
      576460752297984000, 576460752296411136};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {
      1056630414245904,  10132738458714085, 4504320576389010,
      10132635464433619, 4504526052196170,  10131372427640195,
      4507387723576200,  10131270943309109, 10136934990934835,
      1122032333026041,  3883434832604,     10126275177271649,
      4384754822908,     1118300971385403,  10137683893611845,
      4495592451520584,  1130515181792511,  1117633686974709,
      10137896656366420, 1117437633538746,  1133057565636621,
      18005893547338056, 6674349270895,     10124585798117629,
      1132341744607194,  18004986768142224, 1131224704581183,
      1099503239184,     1056630414245904,  1546187911987216,
      1893633552810000,  3147076707811344};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {
      4053173625208176639, 2222518839782277119, 828632026152435711,
      1812686325888450559, 4107232763670429695, 4275992594329501695,
      1476303198808702975, 3866143587761258495, 3541180177437032447,
      1190285366409691135, 1170011213867778047, 1138381683042942975,
      1169738534988283903, 2808151305704570879, 4153252462102970367,
      3777976859829207039, 1473591579803254783, 3811238512495034367,
      1446452471735386111, 2356137402589904895, 3937838480566910975,
      2750100407460560895, 3596647395267969023, 1784057791805521919,
      607975487312101375,  1300383331078635519, 4298562407129808895,
      1134907037377626111, 4053173625208176639, 1182098265410764799,
      263342226071486463,  389364675431235583};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {
      70368744177664, 70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664, 70368744177664, 70368744177664,
      70368744177664, 70368744177664, 70368744177664, 70368744177664};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {20347699716009612, 282006193726917038,
                               54652613579671190, 866211086935993210};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {850178231243678074, 685101548658244679,
                                       1095268752430331346, 661600600025352636};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  EXPECT_NE(precomputed.get_p_product_mult_r(0), nullptr);
  EXPECT_EQ(precomputed.get_p_inverse_mult_r(0).size(), 4);

  for (int moduli_id = 1; moduli_id <= 31; moduli_id++) {
    EXPECT_NE(precomputed.get_rescale_scale(moduli_id), nullptr);
  }
}

TEST(CKKSPrecomputed, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.slot_count_, 65536);
  EXPECT_EQ(precomputed.coeff_count_, 131072);
  EXPECT_EQ(precomputed.log_coeff_count_, 17);
  EXPECT_EQ(precomputed.chain_count_, 79);
  EXPECT_EQ(precomputed.prime_count_, 85);

  EXPECT_EQ(precomputed.buffer_bit_length_, 62);
  EXPECT_EQ(precomputed.scale_, 1099511627776);

  std::vector<uint64_t> pre_permutation = {0, 2, 12, 62};
  EXPECT_EQ(precomputed.pre_permutation_.size(), 131072);
  expect_vector_equals(precomputed.pre_permutation_, pre_permutation, 4);

  std::vector<uint64_t> post_permutation = {0, 65536, 1, 120793};
  EXPECT_EQ(precomputed.post_permutation_.size(), 131072);
  expect_vector_equals(precomputed.post_permutation_, post_permutation, 4);

  std::vector<std::complex<double>> fft_twiddle_factor = {
      std::complex(1.0, -0.0),
      std::complex(0.999999998851027, -0.000047936899603),
      std::complex(0.999999995404107, -0.000095873799096),
      std::complex(0.999999989659241, -0.000143810698369)};
  expect_complex_vector_near(precomputed.fft_twiddle_factor_,
                             fft_twiddle_factor, 4, 1e-15);

  std::vector<std::complex<double>> ifft_twiddle_factor = {
      std::complex(1.0, 0.0),
      std::complex(0.999999998851027, 0.000047936899603),
      std::complex(0.999999995404107, 0.000095873799096),
      std::complex(0.999999989659241, 0.000143810698369)};
  expect_complex_vector_near(precomputed.ifft_twiddle_factor_,
                             ifft_twiddle_factor, 4, 1e-9);

  std::vector<uint64_t> q = {
      1152921504598720513, 1099510054913,       1099516870657,
      1099504549889,       1099522375681,       1099500617729,
      1099535220737,       1099461820417,       1099537580033,
      1099455004673,       1099579260929,       1099454218241,
      1099612028929,       1099453431809,       1099630903297,
      1099451072513,       1099633262593,       1099450810369,
      1099634311169,       1099394449409,       1099634835457,
      1099271766017,       1099641389057,       1099253415937,
      1099642699777,       1099237949441,       1099645321217,
      1099237687297,       1099697225729,       1099236114433,
      1100032245761,       1099234541569,       1100069732353,
      1099231395841,       1100072091649,       1099221958657,
      1100075499521,       1099180277761,       1100079431681,
      1098377592833,       1100082577409,       1098368679937,
      1100085460993,       1098367107073,       1100087296001,
      1098359242753,       1100087820289,       1098357932033,
      1101805387777,       1098357669889,       1101814300673,
      1098357145601,       1101819543553,       1098355310593,
      1101825310721,       1098354524161,       1101825835009,
      1098345873409,       1101828980737,       1097449340929,
      1101831602177,       1094883213313,       1101835272193,
      1094881902593,       1101837107201,       1094881640449,
      1101840777217,       1094880329729,       1101843398657,
      1094879543297,       1101845495809,       1094869057537,
      1106523979777,       1094867484673,       1108826914817,
      1094865911809,       1108861255681,       1094865387521,
      1152921504606584833, 1152921504598720513, 1152921504592429057,
      1152921504581419009, 1152921504580894721, 1152921504578273281,
      1152921504577748993};
  expect_array_equals(precomputed.get_q(0), q);

  std::vector<uint64_t> q_double = {
      2305843009197441026, 2199020109826,       2199033741314,
      2199009099778,       2199044751362,       2199001235458,
      2199070441474,       2198923640834,       2199075160066,
      2198910009346,       2199158521858,       2198908436482,
      2199224057858,       2198906863618,       2199261806594,
      2198902145026,       2199266525186,       2198901620738,
      2199268622338,       2198788898818,       2199269670914,
      2198543532034,       2199282778114,       2198506831874,
      2199285399554,       2198475898882,       2199290642434,
      2198475374594,       2199394451458,       2198472228866,
      2200064491522,       2198469083138,       2200139464706,
      2198462791682,       2200144183298,       2198443917314,
      2200150999042,       2198360555522,       2200158863362,
      2196755185666,       2200165154818,       2196737359874,
      2200170921986,       2196734214146,       2200174592002,
      2196718485506,       2200175640578,       2196715864066,
      2203610775554,       2196715339778,       2203628601346,
      2196714291202,       2203639087106,       2196710621186,
      2203650621442,       2196709048322,       2203651670018,
      2196691746818,       2203657961474,       2194898681858,
      2203663204354,       2189766426626,       2203670544386,
      2189763805186,       2203674214402,       2189763280898,
      2203681554434,       2189760659458,       2203686797314,
      2189759086594,       2203690991618,       2189738115074,
      2213047959554,       2189734969346,       2217653829634,
      2189731823618,       2217722511362,       2189730775042,
      2305843009213169666, 2305843009197441026, 2305843009184858114,
      2305843009162838018, 2305843009161789442, 2305843009156546562,
      2305843009155497986};
  expect_array_equals(precomputed.get_q_double(0), q_double);

  std::vector<uint64_t> q_half = {
      576460752299360256, 549755027456,       549758435328,
      549752274944,       549761187840,       549750308864,
      549767610368,       549730910208,       549768790016,
      549727502336,       549789630464,       549727109120,
      549806014464,       549726715904,       549815451648,
      549725536256,       549816631296,       549725405184,
      549817155584,       549697224704,       549817417728,
      549635883008,       549820694528,       549626707968,
      549821349888,       549618974720,       549822660608,
      549618843648,       549848612864,       549618057216,
      550016122880,       549617270784,       550034866176,
      549615697920,       550036045824,       549610979328,
      550037749760,       549590138880,       550039715840,
      549188796416,       550041288704,       549184339968,
      550042730496,       549183553536,       550043648000,
      549179621376,       550043910144,       549178966016,
      550902693888,       549178834944,       550907150336,
      549178572800,       550909771776,       549177655296,
      550912655360,       549177262080,       550912917504,
      549172936704,       550914490368,       548724670464,
      550915801088,       547441606656,       550917636096,
      547440951296,       550918553600,       547440820224,
      550920388608,       547440164864,       550921699328,
      547439771648,       550922747904,       547434528768,
      553261989888,       547433742336,       554413457408,
      547432955904,       554430627840,       547432693760,
      576460752303292416, 576460752299360256, 576460752296214528,
      576460752290709504, 576460752290447360, 576460752289136640,
      576460752288874496};
  expect_array_equals(precomputed.get_q_half(0), q_half);

  EXPECT_EQ(precomputed.r_, R);

  std::vector<int64_t> r_squared = {
      1056630414245904, 1099486461964,     1055225011601,     283512112828,
      441329738179,     964585921770,      776493190435,      332843631128,
      309490669387,     59471435355,       377189682292,      1093643035236,
      471125180103,     1073484774883,     863678499840,      72532544999,
      1097693507157,    941807337117,      42366266838,       375057740120,
      652553949017,     684173725712,      785205820575,      500080644029,
      443194140383,     1045999153383,     329512764302,      82197625207,
      164780955112,     272725674382,      215652355097,      636942783564,
      434560216600,     832323516135,      727242201821,      996466113564,
      356262603179,     108496109883,      148117390258,      745808402664,
      164342168082,     469171916613,      448037656540,      81634544533,
      879536788280,     105200728204,      650773380537,      767415559544,
      899073526373,     1092924846627,     569076071798,      632051613779,
      1070845843168,    267298725898,      646127692327,      394638647193,
      76719218036,      454343220641,      51912075632,       4099599250,
      680071652953,     155992426871,      275863455359,      273467368208,
      891723727478,     89355829290,       481943458603,      987724419449,
      1070780932386,    465834131331,      205870092989,      662561385521,
      826937670634,     660204446034,      163322681407,      862944448372,
      337074729236,     226646227673,      1099503239184,     1056630414245904,
      3326022212648976, 10345304092049424, 10776312633360400, 13063296735248400,
      13547081834692624};
  expect_array_equals(precomputed.get_r_squared(0), r_squared);

  std::vector<uint64_t> k = {
      4053173625208176639, 4179339079808712703, 3458738125546717183,
      2251750816691257343, 450245544819032063,  3890989956391763967,
      1872941916759785471, 3600400028248047615, 3944480853522644991,
      4608480941975797759, 3598306558226202623, 1095583553708883967,
      2854210071296737279, 1293651021444677631, 3282409377194835967,
      4193689012162265087, 4596892089597296639, 4607988360762359807,
      3443714398782226431, 2886588489493905407, 3875931045271961599,
      320769804060590079,  4288604353620344831, 3806423424475856895,
      3441585744279240703, 1078022772249067519, 990933480277278719,
      1996613541245485055, 3424319013731172351, 2175893310199300095,
      3331837716664418303, 3363974447881781247, 3453529670799327231,
      3001933306398507007, 1559378793240985599, 762769630086037503,
      2402223931325677567, 4501894284504465407, 1262866895516205055,
      587463289150636031,  3276897319698038783, 3305357351835402239,
      1778401165909950463, 3445874662985695231, 3127371709784522751,
      2130774368640303103, 3559113367251058687, 1245046215490142207,
      1512080003770613759, 3135953121431781375, 3921070672696049663,
      4431779526689685503, 2743976404957790207, 3797035243543986175,
      3437898809096011775, 2263992022090645503, 409053512218968063,
      2117796764164816895, 3853248397462994943, 3186920638431625215,
      1679364100893179903, 1636210736455745535, 3824049766682066943,
      381082410500751359,  771085239142055935,  612842213047009279,
      1150319443949387775, 2852503074762915839, 885899541855600639,
      1169878992932044799, 2461382056716533759, 3954930950961889279,
      2564273053852237823, 2643287521180516351, 3423521808211247103,
      1908099895900241919, 2656451713015742463, 317961165920534527,
      1134907037377626111, 4053173625208176639, 1603073590912352255,
      557799772211904511,  89398472929968127,   2503184936686321663,
      4340623348083195903};
  expect_array_equals(precomputed.get_k(0), k);

  std::vector<int64_t> coeff_count_inverse = {
      35184372088832, 50331616,       1099349098465,  226492384,
      1099178442721,  352321504,      1098780245985,  1593835488,
      1098707107809,  1811939296,     1097415000033,  1837105120,
      1096399192033,  1862270944,     1095814086625,  1937768416,
      1095740948449,  1946157024,     1095708442593,  3749707744,
      1095692189665,  7675576288,     1095489028065,  8262778848,
      1095448395745,  8757706720,     1095367131105,  8766095328,
      1093758091233,  8816426976,     1083372470241,  8866758624,
      1082210385889,  8967421920,     1082137247713,  9269411808,
      1082031603681,  10603200480,    1081909706721,  36289118176,
      1081812189153,  36574330848,    1081722798049,  36624662496,
      1081665912801,  36876320736,    1081649659873,  36918263776,
      1028405067745,  36926652384,    1028128767969,  36943429600,
      1027966238689,  37002149856,    1027787456481,  37027315680,
      1027771203553,  37304139744,    1027673685985,  65993179104,
      1027592421345,  148109262816,   1027478650849,  148151205856,
      1027421765601,  148159594464,   1027307995105,  148201537504,
      1027226730465,  148226703328,   1027161718753,  148562247648,
      882128715745,   148612579296,   810737729505,   148662910944,
      809673162721,   148679688160,   35184372088832, 35184372088832,
      35184372088832, 35184372088832, 35184372088832, 35184372088832,
      35184372088832};
  expect_array_equals(precomputed.get_coeff_count_inverse(0),
                      coeff_count_inverse);

  std::vector<int64_t> root = {20347699716009612, 282006193726917038,
                               54652613579671190, 866211086935993210};
  expect_array_equals(precomputed.get_root(0), root);

  std::vector<int64_t> root_inverse = {832727522214926820, 399763491689395446,
                                       210541676800684277, 544659551178863043};
  expect_array_equals(precomputed.get_root_inverse(0), root_inverse);

  EXPECT_NE(precomputed.get_p_product_mult_r(0), nullptr);
  EXPECT_EQ(precomputed.get_p_inverse_mult_r(0).size(), 6);

  for (int moduli_id = 1; moduli_id <= 84; moduli_id++) {
    EXPECT_NE(precomputed.get_rescale_scale(moduli_id), nullptr);
  }
}
