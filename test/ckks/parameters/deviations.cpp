#include <cstdio>
#include <limits>

#include "ckks/config.h"
#include "ckks/parameters.h"
#include "common/common.h"
#include "common/test.h"

TEST(Deviations, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      1.0000000034958401, 0.9999999914751774, 1.0000000008462204,
      0.9999999903395425, 1.0000000002638509, 0.9999999902520845,
      1.0000000000600511, 0.9999999913288897, 1.0000000005547978,
      0.9999999965093623, 1.0000000029995151, 0.9999999990413934,
      1.0000000041927710, 0.9999999999436116, 1.0000000025047484,
      0.9999999996816769, 1.0000000022428139, 0.9999999997980922,
      1.0000000011223165, 0.9999999999363354, 1.0000000008712959,
      1.0000000000000000, 1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      1.0000000008462204, 0.9999999903395425, 1.0000000002638509,
      0.9999999902520845, 1.0000000000600511, 0.9999999913288897,
      1.0000000005547978, 0.9999999965093623, 1.0000000029995151,
      0.9999999990413934, 1.0000000041927710, 0.9999999999436116,
      1.0000000025047484, 0.9999999996816769, 1.0000000022428139,
      0.9999999997980922, 1.0000000011223165, 0.9999999999363354,
      1.0000000008712959, 1.0000000000000000, 1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      0.9999999902520845, 1.0000000000600511, 0.9999999913288897,
      1.0000000005547978, 0.9999999965093623, 1.0000000029995151,
      0.9999999990413934, 1.0000000041927710, 0.9999999999436116,
      1.0000000025047484, 0.9999999996816769, 1.0000000022428139,
      0.9999999997980922, 1.0000000011223165, 0.9999999999363354,
      1.0000000008712959, 1.0000000000000000, 1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      1.0000000007628040, 0.9999999859177078, 1.0000000158353739,
      0.9999999958696105, 1.0000000206658064, 0.9999999990124224,
      1.0000000217715510, 0.9999999998854369, 1.0000000065210937,
      0.9999999927258696, 1.0000000014570147, 0.9999999904557646,
      1.0000000001182352, 0.9999999941228457, 1.0000000018062567,
      0.9999999983720046, 1.0000000029704097, 0.9999999993324309,
      1.0000000030140654, 0.9999999999363354, 1.0000000008712959,
      1.0000000000000000, 1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      1.0000000158353739, 0.9999999958696105, 1.0000000206658064,
      0.9999999990124224, 1.0000000217715510, 0.9999999998854369,
      1.0000000065210937, 0.9999999927258696, 1.0000000014570147,
      0.9999999904557646, 1.0000000001182352, 0.9999999941228457,
      1.0000000018062567, 0.9999999983720046, 1.0000000029704097,
      0.9999999993324309, 1.0000000030140654, 0.9999999999363354,
      1.0000000008712959, 1.0000000000000000, 1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      0.9999999990124224, 1.0000000217715510, 0.9999999998854369,
      1.0000000065210937, 0.9999999927258696, 1.0000000014570147,
      0.9999999904557646, 1.0000000001182352, 0.9999999941228457,
      1.0000000018062567, 0.9999999983720046, 1.0000000029704097,
      0.9999999993324309, 1.0000000030140654, 0.9999999999363354,
      1.0000000008712959, 1.0000000000000000, 1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {0.9999994635565939, 1.0000000000000000,
                                  1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {0.9999998811422509, 1.0000041725015607,
                                  0.9999985099633661, 1.0000030398744384,
                                  0.9999983310836313, 1.0000028610272693,
                                  1.0000000000000000, 1.0000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      0.999981114645662, 1.000009094148643, 0.999966399918780,
      1.000001021308555, 0.999988351301313, 1.000010030377770,
      0.999997504954312, 1.000013594015321, 0.999999763589582,
      1.000010729839760, 0.999998927570227, 1.000007629617834,
      0.999999165622522, 1.000003814740097, 0.999998331083631,
      1.000002861027269, 1.000000000000000, 1.000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      1.000064985405190, 0.999977415694365, 1.000096829389011,
      0.999993693810531, 1.000104254132422, 0.999999194025058,
      1.000072672278404, 0.999984119913946, 1.000018643386853,
      0.999957822757754, 1.000005375061592, 0.999953453959193,
      1.000000806425745, 0.999955103665406, 1.000001154491118,
      0.999961595786117, 1.000003089418690, 0.999963397677479,
      1.000003155951595, 0.999973682957690, 1.000002696020063,
      0.999977029282182, 1.000001746655205, 0.999978342752729,
      1.000001449742507, 0.999980697696739, 1.000001196743358,
      0.999980928827864, 1.000000239437908, 0.999993086370931,
      1.000005483846210, 0.999998092745215, 1.000003814740097,
      0.999998331083631, 1.000002861027269, 1.000000000000000,
      1.000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}

TEST(Deviations, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  auto infinity = std::numeric_limits<double>::infinity();
  std::vector<double> expected = {
      3.192079377725347e+282, 1.7790926807037262e+141, 4.2448298828199952e+70,
      2.0515991036122897e+35, 4.5390725511407085e+17,  670888082.3659023,
      25956.43752586633,      160.43139872575998,      12.692983024358231,
      3.547718857319983,      1.887522624389633,       1.368086425472737,
      1.172124142499243,      1.078089400851383,       1.040501680656063,
      1.018136597014936,      1.011154197064013,       1.004495488526094,
      1.004354708620804,      1.001120320500442,       1.002665464233739,
      1.000278780205399,      1.002238710125191,       1.000067559202908,
      1.002128118573051,      1.000012859036240,       1.002092605478476,
      0.999995378479820,      1.000521732064073,       0.999212470567621,
      1.000129518725664,      0.999023754342494,       1.000033401439010,
      0.998977178215741,      1.000007468305420,       0.998972331522061,
      1.000002182903852,      0.999699730039334,       1.000362615111517,
      0.999917790831921,      1.000468612541124,       0.999979349656609,
      1.000497262689803,      0.999996529357201,       1.000471763154426,
      0.999985216738241,      1.000161407449001,       0.999831532947653,
      1.000037346159457,      0.999769759261863,       1.000004068570072,
      0.999767191505725,      1.000001592436162,       0.999782643045098,
      1.000003360170672,      0.999895106800924,       1.000059126068856,
      0.999974247852813,      1.000097748640681,       0.999993795743514,
      1.000105377984825,      0.999999755892072,       1.000091192251589,
      0.999993379037738,      1.000058201304072,       0.999977600317832,
      1.000012403272082,      0.999960901806761,       1.000001907965839,
      0.999990940393499,      1.000005245304863,       0.999996185331383,
      1.000002861027269,      1.000000000000000,       1.000000000000000};
  auto deviations = parameters.get_deviations();
  std::vector<double> finite_deviations(deviations.begin() + 3,
                                        deviations.end());

  ASSERT_EQ(deviations.size(), expected.size() + 3);
  EXPECT_EQ(deviations[0], infinity);
  EXPECT_EQ(deviations[1], infinity);
  EXPECT_EQ(deviations[2], infinity);
  EXPECT_VECTOR_NEAR(finite_deviations, expected, 1e-15);
}

TEST(Deviations, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  std::vector<double> expected = {
      0.999999996482022, 0.999999991518026, 1.000000004497438,
      0.999999997904972, 1.000000007596324, 0.999999999461692,
      1.000000008163681, 0.999999999781749, 1.000000002008178,
      0.999999996864069, 1.000000000462027, 0.999999996287445,
      1.000000000159163, 0.999999996419775, 1.000000000130740,
      0.999999996885777, 1.000000000130911, 0.999999998384709,
      1.000000000858549, 0.999999999650747, 1.000000001469740,
      0.999999999999998, 1.000000000392902, 1.000000000000000,
      1.000000000305590, 1.000000000000000, 1.000000000000000};
  auto deviations = parameters.get_deviations();

  ASSERT_EQ(deviations.size(), expected.size());
  EXPECT_VECTOR_NEAR(deviations, expected, 1e-15);
}
