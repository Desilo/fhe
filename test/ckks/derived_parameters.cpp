#include "ckks/derived_parameters.h"
#include "ckks/precomputed.h"
#include "common/test.h"

TEST(CKKSDerivedParameters, IronQ0) {
  const uint64_t q = 1099511922689;
  const int64_t r = 1LL << 62;
  const int log_coeff_count = 13;
  const int coeff_count = 1 << log_coeff_count;
  const auto backward_paint = desilo::fhe::get_backward_paint(log_coeff_count);

  auto derived = desilo::fhe::CKKSDerivedParameters(
      q, r, log_coeff_count, coeff_count, backward_paint);

  EXPECT_EQ(derived.q_, q);
  EXPECT_EQ(derived.k_, 2835896587270782975);
  EXPECT_EQ(derived.q_double_, 2199023845378);
  EXPECT_EQ(derived.q_half_, 549755961344);

  EXPECT_EQ(derived.r_squared_, 333401010676);
  EXPECT_EQ(derived.coeff_count_inverse_, 1099360927233);
  expect_vector_equals(derived.root_,
                       {114895742913, 406428375928, 19220884517, 1042186274405},
                       4);
  expect_vector_equals(derived.root_inverse_,
                       {893896406426, 48860252429, 1006357924583, 333120521744},
                       4);
}

TEST(CKKSDerivedParameters, IronQ1) {
  const uint64_t q = 1099510890497;
  const int64_t r = 1LL << 62;
  const int log_coeff_count = 13;
  const int coeff_count = 1 << log_coeff_count;
  const auto backward_paint = desilo::fhe::get_backward_paint(log_coeff_count);

  auto derived = desilo::fhe::CKKSDerivedParameters(
      q, r, log_coeff_count, coeff_count, backward_paint);

  EXPECT_EQ(derived.q_, q);
  EXPECT_EQ(derived.k_, 4607231353240731647);
  EXPECT_EQ(derived.q_double_, 2199021780994);
  EXPECT_EQ(derived.q_half_, 549755445248);

  EXPECT_EQ(derived.r_squared_, 198138004164);
  EXPECT_EQ(derived.coeff_count_inverse_, 377486848);
  expect_vector_equals(
      derived.root_, {1097178449087, 620070522686, 659836463760, 170433894186},
      4);
  expect_vector_equals(derived.root_inverse_,
                       {512964584806, 423776469050, 755616018070, 39514764696},
                       4);
}

TEST(CKKSDerivedParameters, BronzeQ0) {
  const uint64_t q = 1099510054913;
  const int64_t r = 1LL << 62;
  const int log_coeff_count = 14;
  const int coeff_count = 1 << log_coeff_count;
  const auto backward_paint = desilo::fhe::get_backward_paint(log_coeff_count);

  auto derived = desilo::fhe::CKKSDerivedParameters(
      q, r, log_coeff_count, coeff_count, backward_paint);

  EXPECT_EQ(derived.q_, q);
  EXPECT_EQ(derived.k_, 4179339079808712703);
  EXPECT_EQ(derived.q_double_, 2199020109826);
  EXPECT_EQ(derived.q_half_, 549755027456);

  EXPECT_EQ(derived.r_squared_, 1099486461964);
  EXPECT_EQ(derived.coeff_count_inverse_, 402652928);
  expect_vector_equals(
      derived.root_, {1020560169870, 396732489779, 704925052878, 212645052244},
      4);
  expect_vector_equals(derived.root_inverse_,
                       {458280421675, 758315428071, 700276168656, 617152194231},
                       4);
}
