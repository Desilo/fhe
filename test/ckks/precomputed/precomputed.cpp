#include "ckks/precomputed.h"
#include "ckks/config.h"
#include "common/common.h"
#include "common/test.h"

TEST(CKKS, BackwardPaint3) {
  const auto paint = desilo::fhe::get_backward_paint(3);

  const std::vector<int> expected = {4, 5, 6, 7, 2, 3, 1};

  expect_vector_equals(paint, expected, 7);
}

TEST(CKKS, BackwardPaint4) {
  const auto paint = desilo::fhe::get_backward_paint(4);

  const std::vector<int> expected = {8, 9, 10, 11, 12, 13, 14, 15,
                                     4, 5, 6,  7,  2,  3,  1};

  expect_vector_equals(paint, expected, 15);
}

TEST(CKKSPrecomputed, IronToNormalizedDelta) {
  const auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.to_normalized_delta(0), 0);
  EXPECT_EQ(precomputed.to_normalized_delta(1), 1);
  EXPECT_EQ(precomputed.to_normalized_delta(2), 2);
  EXPECT_EQ(precomputed.to_normalized_delta(-1), 4095);
  EXPECT_EQ(precomputed.to_normalized_delta(-2), 4094);
}

TEST(CKKSPrecomputed, BronzeToNormalizedDelta) {
  const auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.to_normalized_delta(0), 0);
  EXPECT_EQ(precomputed.to_normalized_delta(1), 1);
  EXPECT_EQ(precomputed.to_normalized_delta(2), 2);
  EXPECT_EQ(precomputed.to_normalized_delta(-1), 8191);
  EXPECT_EQ(precomputed.to_normalized_delta(-2), 8190);
}

TEST(CKKSPrecomputed, SilverToNormalizedDelta) {
  const auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.to_normalized_delta(0), 0);
  EXPECT_EQ(precomputed.to_normalized_delta(1), 1);
  EXPECT_EQ(precomputed.to_normalized_delta(2), 2);
  EXPECT_EQ(precomputed.to_normalized_delta(-1), 16383);
  EXPECT_EQ(precomputed.to_normalized_delta(-2), 16382);
}

TEST(CKKSPrecomputed, GoldToNormalizedDelta) {
  const auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  EXPECT_EQ(precomputed.to_normalized_delta(0), 0);
  EXPECT_EQ(precomputed.to_normalized_delta(1), 1);
  EXPECT_EQ(precomputed.to_normalized_delta(2), 2);
  EXPECT_EQ(precomputed.to_normalized_delta(-1), 32767);
  EXPECT_EQ(precomputed.to_normalized_delta(-2), 32766);
}

TEST(LevelDownMultiplier, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);
  auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  ASSERT_EQ(parameters.get_full_level(), 2);

  std::vector<int64_t> expected_level_2_to_1 = {
      432341166181056512, 177036455934, 841627474949, 72053195991416832};
  const auto multiplier_level_2_to_1 =
      precomputed.make_level_down_multiplier(2, 1);

  EXPECT_VECTOR_EQUALS(multiplier_level_2_to_1->multiplier_,
                       expected_level_2_to_1);

  std::vector<int64_t> expected_level_2_to_0 = {
      432340934254395400, 531109367802, 305770294281, 72053157338939400};
  auto multiplier_level_2_to_0 = precomputed.make_level_down_multiplier(2, 0);

  EXPECT_VECTOR_EQUALS(multiplier_level_2_to_0->multiplier_,
                       expected_level_2_to_0);

  std::vector<int64_t> expected_level_1_to_0 = {354072911868, 573698884615,
                                                72053176665178116};
  auto multiplier_level_1_to_0 = precomputed.make_level_down_multiplier(1, 0);

  EXPECT_VECTOR_EQUALS(multiplier_level_1_to_0->multiplier_,
                       expected_level_1_to_0);

  delete multiplier_level_2_to_1;
  delete multiplier_level_2_to_0;
  delete multiplier_level_1_to_0;
}

TEST(LevelDownMultiplier, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);
  auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  ASSERT_EQ(parameters.get_full_level(), 7);

  std::vector<int64_t> expected_level_7_to_6 = {
      720571542332768256, 549752143871, 284229828810,
      870518583174,       774077837531, 1031445151564,
      1076202881339,      474518322776, 432341166181056512};
  auto multiplier_level_7_to_6 = precomputed.make_level_down_multiplier(7, 6);

  EXPECT_VECTOR_EQUALS(multiplier_level_7_to_6->multiplier_,
                       expected_level_7_to_6);

  std::vector<int64_t> expected_level_7_to_0 = {
      720571456687569396, 964097210094, 848174258240,
      925145406291,       797513304290, 468510959781,
      451598572569,       640264167657, 432341114794146292};
  auto multiplier_level_7_to_0 = precomputed.make_level_down_multiplier(7, 0);

  EXPECT_VECTOR_EQUALS(multiplier_level_7_to_0->multiplier_,
                       expected_level_7_to_0);

  std::vector<int64_t> expected_level_1_to_0 = {626421993121, 282466873258,
                                                432341140487404796};
  auto multiplier_level_1_to_0 = precomputed.make_level_down_multiplier(1, 0);

  EXPECT_VECTOR_EQUALS(multiplier_level_1_to_0->multiplier_,
                       expected_level_1_to_0);

  delete multiplier_level_7_to_6;
  delete multiplier_level_7_to_0;
  delete multiplier_level_1_to_0;
}

TEST(LevelDownMultiplier, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);
  auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  ASSERT_EQ(parameters.get_full_level(), 17);

  std::vector<int64_t> expected_level_17_to_16 = {
      1152917106804129762, 549752143871, 284229828810,       1031445151564,
      1076202881339,       474518322776, 475823786379,       214295116648,
      867469432485,        587249547767, 336397597288,       556516702366,
      342706964295,        864704782340, 624172410211,       822062356791,
      895694156324,        890076452395, 1152917106560335872};
  auto multiplier_level_17_to_16 =
      precomputed.make_level_down_multiplier(17, 16);

  EXPECT_VECTOR_EQUALS(multiplier_level_17_to_16->multiplier_,
                       expected_level_17_to_16);

  std::vector<int64_t> expected_level_17_to_0 = {
      1152242133611798478, 534714847300, 628687630702,       266144885515,
      738073759068,        700928325890, 1077451094679,      369583378603,
      504780479298,        972483194345, 379897561152,       953000369890,
      233043100105,        129518213378, 298425483415,       726017574110,
      706791738944,        536427678630, 1152895333311930348};
  auto multiplier_level_17_to_0 = precomputed.make_level_down_multiplier(17, 0);

  EXPECT_VECTOR_EQUALS(multiplier_level_17_to_0->multiplier_,
                       expected_level_17_to_0);

  std::vector<int64_t> expected_level_1_to_0 = {587148038519, 98714906594,
                                                1152906219885277368};
  auto multiplier_level_1_to_0 = precomputed.make_level_down_multiplier(1, 0);

  EXPECT_VECTOR_EQUALS(multiplier_level_1_to_0->multiplier_,
                       expected_level_1_to_0);

  delete multiplier_level_17_to_16;
  delete multiplier_level_17_to_0;
  delete multiplier_level_1_to_0;
}
