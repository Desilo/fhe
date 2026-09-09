#include "ckks/config.h"
#include "ckks/precomputed.h"
#include "common/common.h"
#include "common/test.h"

class PermutationParameters
    : public testing::TestWithParam<
          std::tuple<desilo::fhe::CKKSConfig, int, std::vector<int32_t>,
                     std::vector<int32_t>>> {};

INSTANTIATE_TEST_CASE_P(
    , PermutationParameters,
    testing::Values(
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("iron"), 1,
                        std::vector<int32_t>{0, 3277, 6554, 1639},
                        std::vector<int32_t>{1, 1, 1, -1}),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("iron"), 2,
                        std::vector<int32_t>{0, 7209, 6226, 5243},
                        std::vector<int32_t>{1, 1, -1, 1}),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("bronze"), 1,
                        std::vector<int32_t>{0, 3277, 6554, 9831},
                        std::vector<int32_t>{1, -1, 1, -1}),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("bronze"), 2,
                        std::vector<int32_t>{0, 7209, 14418, 5243},
                        std::vector<int32_t>{1, -1, 1, 1})),
    [](const testing::TestParamInfo<PermutationParameters::ParamType> &info) {
      const auto config = std::get<0>(info.param);
      return print_tier(config.log_coeff_count_) +
             print_delta(std::get<1>(info.param));
    });

TEST_P(PermutationParameters, Make) {
  auto [config, delta, permutation_, sign_] = GetParam();
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);
  const auto [permutation, sign] =
      precomputed.make_permutation_parameters(delta);

  ASSERT_EQ(permutation->values_.size(), precomputed.coeff_count_);
  ASSERT_EQ(permutation->values_.size(), precomputed.coeff_count_);

  expect_vector_equals(permutation->values_, permutation_, 4);
  expect_vector_equals(sign->values_, sign_, 4);

  delete permutation;
  delete sign;
}

TEST_P(PermutationParameters, CopyFrom) {
  auto [config, delta, permutation_, sign_] = GetParam();
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);
  const auto [permutation, sign] =
      precomputed.make_permutation_parameters(delta);

  ASSERT_EQ(permutation->values_.size(), precomputed.coeff_count_);
  ASSERT_EQ(permutation->values_.size(), precomputed.coeff_count_);

  expect_vector_equals(permutation->values_, permutation_, 4);
  expect_vector_equals(sign->values_, sign_, 4);

  const auto permutation_copy =
      new desilo::fhe::PermutationParameters(*permutation);

  ASSERT_EQ(permutation_copy->values_.size(), precomputed.coeff_count_);

  expect_vector_equals(permutation_copy->values_, permutation_, 4);

  ASSERT_NE(permutation->values_.data(), permutation_copy->values_.data());

  delete permutation;
  delete sign;
  delete permutation_copy;
}

class BitReversalPermutationParameters
    : public testing::TestWithParam<
          std::tuple<desilo::fhe::CKKSConfig, std::vector<int32_t>>> {};

INSTANTIATE_TEST_CASE_P(
    , BitReversalPermutationParameters,
    testing::Values(
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("iron"),
                        std::vector<int32_t>{0, 4096, 2048, 6144}),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("bronze"),
                        std::vector<int32_t>{0, 8192, 4096, 12288})),
    [](const testing::TestParamInfo<BitReversalPermutationParameters::ParamType>
           &info) {
      const auto config = std::get<0>(info.param);
      return print_tier(config.log_coeff_count_);
    });

TEST_P(BitReversalPermutationParameters, Make) {
  auto [config, permutation_] = GetParam();
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);
  const auto permutation = precomputed.make_bit_reversal_permutation_parameters(
      precomputed.coeff_count_);

  ASSERT_EQ(permutation->values_.size(), precomputed.coeff_count_);

  expect_vector_equals(permutation->values_, permutation_, 4);

  delete permutation;
}

class NTTPermutationParameters
    : public testing::TestWithParam<
          std::tuple<desilo::fhe::CKKSConfig, int, std::vector<int32_t>>> {};

INSTANTIATE_TEST_CASE_P(
    , NTTPermutationParameters,
    testing::Values(
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("iron"), 1,
                        std::vector<int32_t>{3276, 3277, 3278, 3279}),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("iron"), 2,
                        std::vector<int32_t>{1294, 1295, 1293, 1292}),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("bronze"), 1,
                        std::vector<int32_t>{6553, 6552, 6555, 6554}),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("bronze"), 2,
                        std::vector<int32_t>{2589, 2588, 2591, 2590})),
    [](const testing::TestParamInfo<NTTPermutationParameters::ParamType>
           &info) {
      const auto config = std::get<0>(info.param);
      return print_tier(config.log_coeff_count_) +
             print_delta(std::get<1>(info.param));
    });

TEST_P(NTTPermutationParameters, Make) {
  auto [config, delta, permutation_] = GetParam();
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);
  const auto permutation = precomputed.make_ntt_permutation_parameters(delta);

  ASSERT_EQ(permutation->values_.size(), precomputed.coeff_count_);

  expect_vector_equals(permutation->values_, permutation_, 4);

  delete permutation;
}
