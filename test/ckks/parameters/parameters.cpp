#include "ckks/parameters.h"
#include "ckks/config.h"
#include "common/common.h"
#include "common/test.h"

TEST(CKKSParameters, InvalidLogCoeffCount12) {
  auto config = desilo::fhe::CKKSConfig();
  config.log_coeff_count_ = 12;

  try {
    auto parameters = desilo::fhe::CKKSParameters(config);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("CKKS Parameters: unsupported config.", e.what());
  }
}

TEST(CKKSParameters, InvalidLogCoeffCount18) {
  auto config = desilo::fhe::CKKSConfig();
  config.log_coeff_count_ = 18;

  try {
    auto parameters = desilo::fhe::CKKSParameters(config);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("CKKS Parameters: unsupported config.", e.what());
  }
}

TEST(CKKSParameters, InvalidSpecialPrimeCount) {
  auto config = desilo::fhe::CKKSConfig();
  config.special_prime_count_ = 18;

  try {
    auto parameters = desilo::fhe::CKKSParameters(config);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("CKKS Parameters: unsupported config.", e.what());
  }
}

class CKKSConfigFromTier
    : public testing::TestWithParam<
          std::tuple<const std::string, int, int, int, int, int, int, int>> {};

INSTANTIATE_TEST_CASE_P(
    , CKKSConfigFromTier,
    testing::Values(std::make_tuple("iron", 13, 1, 2, 2, 4, 5, 2),
                    std::make_tuple("bronze", 14, 1, 7, 2, 9, 10, 7),
                    std::make_tuple("silver", 15, 2, 17, 3, 19, 21, 17),
                    std::make_tuple("gold", 16, 4, 36, 5, 38, 42, 36),
                    std::make_tuple("platinum", 17, 6, 77, 7, 79, 85, 77)));

TEST_P(CKKSConfigFromTier, ) {
  const auto [tier_name, log_coeff_count, special_prime_count,
              small_prime_count, large_prime_count, chain_count, prime_count,
              full_level] = GetParam();

  auto config = desilo::fhe::CKKSConfig::from_tier(tier_name);
  EXPECT_EQ(config.log_coeff_count_, log_coeff_count);
  EXPECT_EQ(config.special_prime_count_, special_prime_count);
  EXPECT_EQ(config.scheme_preset_,
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT);

  auto parameters = desilo::fhe::CKKSParameters(config);
  EXPECT_EQ(parameters.get_log_coeff_count(), log_coeff_count);
  EXPECT_EQ(parameters.get_special_prime_count(), special_prime_count);
  EXPECT_EQ(parameters.get_scheme_preset(),
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT);
  EXPECT_EQ(parameters.get_scale_bit_length(), 40);
  EXPECT_EQ(parameters.get_small_prime_bit_length(), 40);
  EXPECT_EQ(parameters.get_use_bootstrap(), false);
  EXPECT_EQ(parameters.get_use_one_more_level(), true);
  EXPECT_EQ(parameters.get_small_prime_count(), small_prime_count);
  EXPECT_EQ(parameters.get_large_prime_count(), large_prime_count);
  EXPECT_EQ(parameters.get_chain_count(), chain_count);
  EXPECT_EQ(parameters.get_prime_count(), prime_count);
  EXPECT_EQ(parameters.get_max_level(), full_level);
  EXPECT_EQ(parameters.get_max_key_switching_level(), full_level - 1);
  EXPECT_EQ(parameters.get_full_level(), full_level);
  for (int level = 0; level <= full_level; level++) {
    EXPECT_FALSE(parameters.has_flexible_chain(level));
    EXPECT_EQ(parameters.get_flexible_chain_scale_bit(level), 0);
  }
}

TEST(CKKSConfig, ConfigFromNotSupportedTier) {
  try {
    desilo::fhe::CKKSConfig::from_tier("diamond");
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("Not supported tier name.", e.what());
  }
}

class CKKSConfigFromMaxLevel
    : public testing::TestWithParam<std::tuple<int, int, int>> {};

INSTANTIATE_TEST_CASE_P(
    , CKKSConfigFromMaxLevel,
    testing::Values(std::make_tuple(0, 13, 1), std::make_tuple(1, 13, 1),
                    std::make_tuple(2, 13, 1), std::make_tuple(3, 14, 1),
                    std::make_tuple(4, 14, 1), std::make_tuple(5, 14, 1),
                    std::make_tuple(6, 14, 1), std::make_tuple(7, 14, 1),
                    std::make_tuple(8, 15, 2), std::make_tuple(9, 15, 2),
                    std::make_tuple(10, 15, 2), std::make_tuple(11, 15, 2),
                    std::make_tuple(12, 15, 2), std::make_tuple(13, 15, 2),
                    std::make_tuple(14, 15, 2), std::make_tuple(15, 15, 2),
                    std::make_tuple(16, 15, 2), std::make_tuple(17, 15, 2),
                    std::make_tuple(18, 16, 4), std::make_tuple(19, 16, 4),
                    std::make_tuple(20, 16, 4), std::make_tuple(21, 16, 4),
                    std::make_tuple(22, 16, 4), std::make_tuple(23, 16, 4),
                    std::make_tuple(24, 16, 4), std::make_tuple(25, 16, 4),
                    std::make_tuple(26, 16, 4), std::make_tuple(27, 16, 4),
                    std::make_tuple(28, 16, 4), std::make_tuple(29, 16, 4),
                    std::make_tuple(30, 16, 4), std::make_tuple(31, 16, 4),
                    std::make_tuple(32, 16, 4), std::make_tuple(33, 16, 4),
                    std::make_tuple(34, 16, 4), std::make_tuple(35, 16, 4),
                    std::make_tuple(36, 16, 4), std::make_tuple(37, 17, 6),
                    std::make_tuple(38, 17, 6), std::make_tuple(39, 17, 6),
                    std::make_tuple(40, 17, 6), std::make_tuple(41, 17, 6),
                    std::make_tuple(42, 17, 6), std::make_tuple(43, 17, 6),
                    std::make_tuple(44, 17, 6), std::make_tuple(45, 17, 6),
                    std::make_tuple(46, 17, 6), std::make_tuple(47, 17, 6),
                    std::make_tuple(48, 17, 6), std::make_tuple(49, 17, 6),
                    std::make_tuple(50, 17, 6), std::make_tuple(51, 17, 6),
                    std::make_tuple(52, 17, 6), std::make_tuple(53, 17, 6),
                    std::make_tuple(54, 17, 6), std::make_tuple(55, 17, 6),
                    std::make_tuple(56, 17, 6), std::make_tuple(57, 17, 6),
                    std::make_tuple(58, 17, 6), std::make_tuple(59, 17, 6),
                    std::make_tuple(60, 17, 6), std::make_tuple(61, 17, 6),
                    std::make_tuple(62, 17, 6), std::make_tuple(63, 17, 6),
                    std::make_tuple(64, 17, 6), std::make_tuple(65, 17, 6),
                    std::make_tuple(66, 17, 6), std::make_tuple(67, 17, 6),
                    std::make_tuple(68, 17, 6), std::make_tuple(69, 17, 6),
                    std::make_tuple(70, 17, 6), std::make_tuple(71, 17, 6),
                    std::make_tuple(72, 17, 6), std::make_tuple(73, 17, 6),
                    std::make_tuple(74, 17, 6), std::make_tuple(75, 17, 6),
                    std::make_tuple(76, 17, 6), std::make_tuple(77, 17, 6)));

TEST_P(CKKSConfigFromMaxLevel, ) {
  const auto [max_level, log_coeff_count, special_prime_count] = GetParam();

  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);

  EXPECT_EQ(config.log_coeff_count_, log_coeff_count);
  EXPECT_EQ(config.special_prime_count_, special_prime_count);
  EXPECT_EQ(config.max_level_, max_level);

  auto parameters = desilo::fhe::CKKSParameters(config);
  EXPECT_EQ(parameters.get_max_level(), max_level);

  if ((max_level == 2 && log_coeff_count == 13) ||
      (max_level == 7 && log_coeff_count == 14) ||
      (max_level == 17 && log_coeff_count == 15) ||
      (max_level == 36 && log_coeff_count == 16) ||
      (max_level == 77 && log_coeff_count == 17)) {
    EXPECT_EQ(parameters.get_max_key_switching_level(), max_level - 1);
  } else {
    EXPECT_EQ(parameters.get_max_key_switching_level(), max_level);
  }
}

TEST(CKKSConfig, ConfigFromMaxLevelNotSupportedMaxLevel) {
  try {
    desilo::fhe::CKKSConfig::from_max_level(10000);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("Not supported max level.", e.what());
  }
}

TEST(CKKSParameter, ForBootstrap) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();

  config.validate();

  EXPECT_EQ(config.log_coeff_count_, 16);
  EXPECT_EQ(config.special_prime_count_, 4);
  EXPECT_EQ(config.scheme_preset_,
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP);

  auto parameters = desilo::fhe::CKKSParameters(config);
  EXPECT_EQ(parameters.get_log_coeff_count(), 16);
  EXPECT_EQ(parameters.get_special_prime_count(), 4);
  EXPECT_EQ(parameters.get_scheme_preset(),
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP);
  EXPECT_EQ(parameters.get_scale_bit_length(), 54);
  EXPECT_EQ(parameters.get_small_prime_bit_length(), 54);
  EXPECT_EQ(parameters.get_use_bootstrap(), true);
  EXPECT_EQ(parameters.get_use_one_more_level(), true);
  EXPECT_EQ(parameters.get_small_prime_count(), 26);
  EXPECT_EQ(parameters.get_large_prime_count(), 5);
  EXPECT_EQ(parameters.get_chain_count(), 28);
  EXPECT_EQ(parameters.get_prime_count(), 32);
  EXPECT_EQ(parameters.get_max_level(), 26);
  EXPECT_EQ(parameters.get_max_key_switching_level(), 25);
  EXPECT_EQ(parameters.get_full_level(), 26);
  for (int level = 0; level <= 26; level++) {
    EXPECT_FALSE(parameters.has_flexible_chain(level));
    EXPECT_EQ(parameters.get_flexible_chain_scale_bit(level), 0);
  }
}
TEST(CKKSParameters, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 3);
  EXPECT_EQ(parameters.get_coeff_count(), 8);
  EXPECT_EQ(parameters.get_special_prime_count(), 1);

  std::vector<uint64_t> moduli = {
      1152921504606846097, 1099511627297, 1099511628769, 1099511627089,
      1099511629121,       1099511626321, 1099511630417, 1099511626049,
      1099511630561,       1099511625409, 1099511632913, 1099511625073,
      1099511632993,       1099511623633, 1099511633153, 1099511618209,
      1099511633201,       1099511616913, 1099511633377, 1099511616689,
      1099511633393,       1099511616481, 1099511633489, 1152921504606846577,
      1152921504606846097};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 22);
  EXPECT_EQ(parameters.get_moduli_id(1), 21);
  EXPECT_EQ(parameters.get_moduli_id(2), 20);
  EXPECT_EQ(parameters.get_moduli_id(3), 19);
  EXPECT_EQ(parameters.get_moduli_id(4), 18);
  EXPECT_EQ(parameters.get_moduli_id(5), 17);
  EXPECT_EQ(parameters.get_moduli_id(6), 16);
  EXPECT_EQ(parameters.get_moduli_id(7), 15);
  EXPECT_EQ(parameters.get_moduli_id(8), 14);
  EXPECT_EQ(parameters.get_moduli_id(9), 13);
  EXPECT_EQ(parameters.get_moduli_id(10), 12);
  EXPECT_EQ(parameters.get_moduli_id(11), 11);
  EXPECT_EQ(parameters.get_moduli_id(12), 10);
  EXPECT_EQ(parameters.get_moduli_id(13), 9);
  EXPECT_EQ(parameters.get_moduli_id(14), 8);
  EXPECT_EQ(parameters.get_moduli_id(15), 7);
  EXPECT_EQ(parameters.get_moduli_id(16), 6);
  EXPECT_EQ(parameters.get_moduli_id(17), 5);
  EXPECT_EQ(parameters.get_moduli_id(18), 4);
  EXPECT_EQ(parameters.get_moduli_id(19), 3);
  EXPECT_EQ(parameters.get_moduli_id(20), 2);
  EXPECT_EQ(parameters.get_moduli_id(21), 1);
  EXPECT_EQ(parameters.get_moduli_id(22), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 24);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(22, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(23, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 25);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 24);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(22, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(23, include_special), 2);
}

TEST(CKKSParameters, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 3);
  EXPECT_EQ(parameters.get_coeff_count(), 8);
  EXPECT_EQ(parameters.get_special_prime_count(), 2);

  std::vector<uint64_t> moduli = {
      1152921504606846097, 1099511627297,       1099511628769,
      1099511627089,       1099511629121,       1099511626321,
      1099511630417,       1099511626049,       1099511630561,
      1099511625409,       1099511632913,       1099511625073,
      1099511632993,       1099511623633,       1099511633153,
      1099511618209,       1099511633201,       1099511616913,
      1099511633377,       1099511616689,       1099511633393,
      1152921504606846577, 1152921504606846097, 1152921504606845777};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 20);
  EXPECT_EQ(parameters.get_moduli_id(1), 19);
  EXPECT_EQ(parameters.get_moduli_id(2), 18);
  EXPECT_EQ(parameters.get_moduli_id(3), 17);
  EXPECT_EQ(parameters.get_moduli_id(4), 16);
  EXPECT_EQ(parameters.get_moduli_id(5), 15);
  EXPECT_EQ(parameters.get_moduli_id(6), 14);
  EXPECT_EQ(parameters.get_moduli_id(7), 13);
  EXPECT_EQ(parameters.get_moduli_id(8), 12);
  EXPECT_EQ(parameters.get_moduli_id(9), 11);
  EXPECT_EQ(parameters.get_moduli_id(10), 10);
  EXPECT_EQ(parameters.get_moduli_id(11), 9);
  EXPECT_EQ(parameters.get_moduli_id(12), 8);
  EXPECT_EQ(parameters.get_moduli_id(13), 7);
  EXPECT_EQ(parameters.get_moduli_id(14), 6);
  EXPECT_EQ(parameters.get_moduli_id(15), 5);
  EXPECT_EQ(parameters.get_moduli_id(16), 4);
  EXPECT_EQ(parameters.get_moduli_id(17), 3);
  EXPECT_EQ(parameters.get_moduli_id(18), 2);
  EXPECT_EQ(parameters.get_moduli_id(19), 1);
  EXPECT_EQ(parameters.get_moduli_id(20), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 24);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 3);
}

TEST(CKKSParameters, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 3);
  EXPECT_EQ(parameters.get_coeff_count(), 8);
  EXPECT_EQ(parameters.get_special_prime_count(), 4);

  std::vector<uint64_t> moduli = {
      1152921504606846097, 1099511627297,       1099511628769,
      1099511627089,       1099511629121,       1099511626321,
      1099511630417,       1099511626049,       1099511630561,
      1099511625409,       1099511632913,       1099511625073,
      1099511632993,       1099511623633,       1099511633153,
      1099511618209,       1099511633201,       1099511616913,
      1152921504606846577, 1152921504606846097, 1152921504606845777,
      1152921504606845473, 1152921504606844913};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 17);
  EXPECT_EQ(parameters.get_moduli_id(1), 16);
  EXPECT_EQ(parameters.get_moduli_id(2), 15);
  EXPECT_EQ(parameters.get_moduli_id(3), 14);
  EXPECT_EQ(parameters.get_moduli_id(4), 13);
  EXPECT_EQ(parameters.get_moduli_id(5), 12);
  EXPECT_EQ(parameters.get_moduli_id(6), 11);
  EXPECT_EQ(parameters.get_moduli_id(7), 10);
  EXPECT_EQ(parameters.get_moduli_id(8), 9);
  EXPECT_EQ(parameters.get_moduli_id(9), 8);
  EXPECT_EQ(parameters.get_moduli_id(10), 7);
  EXPECT_EQ(parameters.get_moduli_id(11), 6);
  EXPECT_EQ(parameters.get_moduli_id(12), 5);
  EXPECT_EQ(parameters.get_moduli_id(13), 4);
  EXPECT_EQ(parameters.get_moduli_id(14), 3);
  EXPECT_EQ(parameters.get_moduli_id(15), 2);
  EXPECT_EQ(parameters.get_moduli_id(16), 1);
  EXPECT_EQ(parameters.get_moduli_id(17), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 5);
}

TEST(CKKSParameters, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 4);
  EXPECT_EQ(parameters.get_coeff_count(), 16);
  EXPECT_EQ(parameters.get_special_prime_count(), 1);

  std::vector<uint64_t> moduli = {
      1152921504606844513, 1099511627297, 1099511628769, 1099511626049,
      1099511631457,       1099511625409, 1099511631937, 1099511624993,
      1099511632993,       1099511621249, 1099511633153, 1099511616481,
      1099511633377,       1099511616193, 1099511635009, 1099511615681,
      1099511652257,       1099511615329, 1099511652769, 1099511614529,
      1099511652929,       1099511611873, 1099511653249, 1152921504606845473,
      1152921504606844513};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 22);
  EXPECT_EQ(parameters.get_moduli_id(1), 21);
  EXPECT_EQ(parameters.get_moduli_id(2), 20);
  EXPECT_EQ(parameters.get_moduli_id(3), 19);
  EXPECT_EQ(parameters.get_moduli_id(4), 18);
  EXPECT_EQ(parameters.get_moduli_id(5), 17);
  EXPECT_EQ(parameters.get_moduli_id(6), 16);
  EXPECT_EQ(parameters.get_moduli_id(7), 15);
  EXPECT_EQ(parameters.get_moduli_id(8), 14);
  EXPECT_EQ(parameters.get_moduli_id(9), 13);
  EXPECT_EQ(parameters.get_moduli_id(10), 12);
  EXPECT_EQ(parameters.get_moduli_id(11), 11);
  EXPECT_EQ(parameters.get_moduli_id(12), 10);
  EXPECT_EQ(parameters.get_moduli_id(13), 9);
  EXPECT_EQ(parameters.get_moduli_id(14), 8);
  EXPECT_EQ(parameters.get_moduli_id(15), 7);
  EXPECT_EQ(parameters.get_moduli_id(16), 6);
  EXPECT_EQ(parameters.get_moduli_id(17), 5);
  EXPECT_EQ(parameters.get_moduli_id(18), 4);
  EXPECT_EQ(parameters.get_moduli_id(19), 3);
  EXPECT_EQ(parameters.get_moduli_id(20), 2);
  EXPECT_EQ(parameters.get_moduli_id(21), 1);
  EXPECT_EQ(parameters.get_moduli_id(22), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 24);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(22, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(23, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 25);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 24);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(22, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(23, include_special), 2);
}

TEST(CKKSParameters, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 4);
  EXPECT_EQ(parameters.get_coeff_count(), 16);
  EXPECT_EQ(parameters.get_special_prime_count(), 2);

  std::vector<uint64_t> moduli = {
      1152921504606844513, 1099511627297,       1099511628769,
      1099511626049,       1099511631457,       1099511625409,
      1099511631937,       1099511624993,       1099511632993,
      1099511621249,       1099511633153,       1099511616481,
      1099511633377,       1099511616193,       1099511635009,
      1099511615681,       1099511652257,       1099511615329,
      1099511652769,       1099511614529,       1099511652929,
      1152921504606845473, 1152921504606844513, 1152921504606844417};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 20);
  EXPECT_EQ(parameters.get_moduli_id(1), 19);
  EXPECT_EQ(parameters.get_moduli_id(2), 18);
  EXPECT_EQ(parameters.get_moduli_id(3), 17);
  EXPECT_EQ(parameters.get_moduli_id(4), 16);
  EXPECT_EQ(parameters.get_moduli_id(5), 15);
  EXPECT_EQ(parameters.get_moduli_id(6), 14);
  EXPECT_EQ(parameters.get_moduli_id(7), 13);
  EXPECT_EQ(parameters.get_moduli_id(8), 12);
  EXPECT_EQ(parameters.get_moduli_id(9), 11);
  EXPECT_EQ(parameters.get_moduli_id(10), 10);
  EXPECT_EQ(parameters.get_moduli_id(11), 9);
  EXPECT_EQ(parameters.get_moduli_id(12), 8);
  EXPECT_EQ(parameters.get_moduli_id(13), 7);
  EXPECT_EQ(parameters.get_moduli_id(14), 6);
  EXPECT_EQ(parameters.get_moduli_id(15), 5);
  EXPECT_EQ(parameters.get_moduli_id(16), 4);
  EXPECT_EQ(parameters.get_moduli_id(17), 3);
  EXPECT_EQ(parameters.get_moduli_id(18), 2);
  EXPECT_EQ(parameters.get_moduli_id(19), 1);
  EXPECT_EQ(parameters.get_moduli_id(20), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 24);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(19, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(20, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(21, include_special), 3);
}

TEST(CKKSParameters, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 4);
  EXPECT_EQ(parameters.get_coeff_count(), 16);
  EXPECT_EQ(parameters.get_special_prime_count(), 4);

  std::vector<uint64_t> moduli = {
      1152921504606844513, 1099511627297,       1099511628769,
      1099511626049,       1099511631457,       1099511625409,
      1099511631937,       1099511624993,       1099511632993,
      1099511621249,       1099511633153,       1099511616481,
      1099511633377,       1099511616193,       1099511635009,
      1099511615681,       1099511652257,       1099511615329,
      1152921504606845473, 1152921504606844513, 1152921504606844417,
      1152921504606844289, 1152921504606843233};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 17);
  EXPECT_EQ(parameters.get_moduli_id(1), 16);
  EXPECT_EQ(parameters.get_moduli_id(2), 15);
  EXPECT_EQ(parameters.get_moduli_id(3), 14);
  EXPECT_EQ(parameters.get_moduli_id(4), 13);
  EXPECT_EQ(parameters.get_moduli_id(5), 12);
  EXPECT_EQ(parameters.get_moduli_id(6), 11);
  EXPECT_EQ(parameters.get_moduli_id(7), 10);
  EXPECT_EQ(parameters.get_moduli_id(8), 9);
  EXPECT_EQ(parameters.get_moduli_id(9), 8);
  EXPECT_EQ(parameters.get_moduli_id(10), 7);
  EXPECT_EQ(parameters.get_moduli_id(11), 6);
  EXPECT_EQ(parameters.get_moduli_id(12), 5);
  EXPECT_EQ(parameters.get_moduli_id(13), 4);
  EXPECT_EQ(parameters.get_moduli_id(14), 3);
  EXPECT_EQ(parameters.get_moduli_id(15), 2);
  EXPECT_EQ(parameters.get_moduli_id(16), 1);
  EXPECT_EQ(parameters.get_moduli_id(17), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 23);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 22);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 17);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 16);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 15);
  EXPECT_EQ(parameters.get_chain_count(9, include_special), 14);
  EXPECT_EQ(parameters.get_chain_count(10, include_special), 13);
  EXPECT_EQ(parameters.get_chain_count(11, include_special), 12);
  EXPECT_EQ(parameters.get_chain_count(12, include_special), 11);
  EXPECT_EQ(parameters.get_chain_count(13, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(14, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(15, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(16, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 5);
}

TEST(CKKSParameters, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 13);
  EXPECT_EQ(parameters.get_coeff_count(), 8192);
  EXPECT_EQ(parameters.get_log_slot_count(), 12);
  EXPECT_EQ(parameters.get_slot_count(), 4096);
  EXPECT_EQ(parameters.get_log_codec_coeff_count(), 13);
  EXPECT_EQ(parameters.get_codec_coeff_count(), 8192);
  EXPECT_EQ(parameters.get_special_prime_count(), 1);

  std::vector<uint64_t> moduli = {1152921504606748673, 1099511922689,
                                  1099510890497, 1152921504606830593,
                                  1152921504606748673};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 2);
  EXPECT_EQ(parameters.get_moduli_id(1), 1);
  EXPECT_EQ(parameters.get_moduli_id(2), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 2);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 3);
}

TEST(CKKSParameters, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 14);
  EXPECT_EQ(parameters.get_coeff_count(), 16384);
  EXPECT_EQ(parameters.get_log_slot_count(), 13);
  EXPECT_EQ(parameters.get_slot_count(), 8192);
  EXPECT_EQ(parameters.get_log_codec_coeff_count(), 14);
  EXPECT_EQ(parameters.get_codec_coeff_count(), 16384);
  EXPECT_EQ(parameters.get_special_prime_count(), 1);

  std::vector<uint64_t> moduli = {
      1152921504606683137, 1099510054913,      1099515691009, 1099508121601,
      1099515789313,       1099507695617,      1099516280833, 1099506515969,
      1152921504606748673, 1152921504606683137};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 7);
  EXPECT_EQ(parameters.get_moduli_id(1), 6);
  EXPECT_EQ(parameters.get_moduli_id(2), 5);
  EXPECT_EQ(parameters.get_moduli_id(3), 4);
  EXPECT_EQ(parameters.get_moduli_id(4), 3);
  EXPECT_EQ(parameters.get_moduli_id(5), 2);
  EXPECT_EQ(parameters.get_moduli_id(6), 1);
  EXPECT_EQ(parameters.get_moduli_id(7), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 10);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 9);
  EXPECT_EQ(parameters.get_chain_count(2, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(3, include_special), 7);
  EXPECT_EQ(parameters.get_chain_count(4, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(5, include_special), 5);
  EXPECT_EQ(parameters.get_chain_count(6, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(7, include_special), 3);
  EXPECT_EQ(parameters.get_chain_count(8, include_special), 2);
}

TEST(CKKSParameters, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 15);
  EXPECT_EQ(parameters.get_coeff_count(), 32768);
  EXPECT_EQ(parameters.get_log_slot_count(), 14);
  EXPECT_EQ(parameters.get_slot_count(), 16384);
  EXPECT_EQ(parameters.get_log_codec_coeff_count(), 15);
  EXPECT_EQ(parameters.get_codec_coeff_count(), 32768);
  EXPECT_EQ(parameters.get_special_prime_count(), 2);

  std::vector<uint64_t> moduli = {
      1152921504598720513, 1099510054913,       1099515691009,
      1099507695617,       1099516280833,       1099506515969,
      1099520606209,       1099504549889,       1099523555329,
      1099503894529,       1099527946241,       1099503370241,
      1099529060353,       1099498258433,       1099531223041,
      1099469684737,       1099532009473,       1099468767233,
      1152921504606584833, 1152921504598720513, 1152921504597016577};
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 17);
  EXPECT_EQ(parameters.get_moduli_id(1), 16);
  EXPECT_EQ(parameters.get_moduli_id(17), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 19);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 18);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 21);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 20);
  EXPECT_EQ(parameters.get_chain_count(17, include_special), 4);
  EXPECT_EQ(parameters.get_chain_count(18, include_special), 3);
}

TEST(CKKSParameters, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 16);
  EXPECT_EQ(parameters.get_coeff_count(), 65536);
  EXPECT_EQ(parameters.get_log_slot_count(), 15);
  EXPECT_EQ(parameters.get_slot_count(), 32768);
  EXPECT_EQ(parameters.get_log_codec_coeff_count(), 16);
  EXPECT_EQ(parameters.get_codec_coeff_count(), 65536);
  EXPECT_EQ(parameters.get_special_prime_count(), 4);

  std::vector<uint64_t> moduli = {
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
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 36);
  EXPECT_EQ(parameters.get_moduli_id(1), 35);
  EXPECT_EQ(parameters.get_moduli_id(36), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 38);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 37);
  EXPECT_EQ(parameters.get_chain_count(36, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(37, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 42);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 41);
  EXPECT_EQ(parameters.get_chain_count(36, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(37, include_special), 5);
}

TEST(CKKSParameters, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 17);
  EXPECT_EQ(parameters.get_coeff_count(), 131072);
  EXPECT_EQ(parameters.get_log_slot_count(), 16);
  EXPECT_EQ(parameters.get_slot_count(), 65536);
  EXPECT_EQ(parameters.get_log_codec_coeff_count(), 17);
  EXPECT_EQ(parameters.get_codec_coeff_count(), 131072);
  EXPECT_EQ(parameters.get_special_prime_count(), 6);

  std::vector<uint64_t> moduli = {
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
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 77);
  EXPECT_EQ(parameters.get_moduli_id(1), 76);
  EXPECT_EQ(parameters.get_moduli_id(77), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 79);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 78);
  EXPECT_EQ(parameters.get_chain_count(77, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(78, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 85);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 84);
  EXPECT_EQ(parameters.get_chain_count(77, include_special), 8);
  EXPECT_EQ(parameters.get_chain_count(78, include_special), 7);
}

TEST(CKKSParameters, GoldBootstrap) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_log_coeff_count(), 16);
  EXPECT_EQ(parameters.get_coeff_count(), 65536);
  EXPECT_EQ(parameters.get_log_slot_count(), 15);
  EXPECT_EQ(parameters.get_slot_count(), 32768);
  EXPECT_EQ(parameters.get_log_codec_coeff_count(), 16);
  EXPECT_EQ(parameters.get_codec_coeff_count(), 65536);
  EXPECT_EQ(parameters.get_special_prime_count(), 4);

  std::vector<uint64_t> moduli = {
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
  expect_vector_equals(parameters.get_moduli(0), moduli);

  EXPECT_EQ(parameters.get_moduli_id(0), 26);
  EXPECT_EQ(parameters.get_moduli_id(1), 25);
  EXPECT_EQ(parameters.get_moduli_id(26), 0);

  bool include_special = false;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 28);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 27);
  EXPECT_EQ(parameters.get_chain_count(26, include_special), 2);
  EXPECT_EQ(parameters.get_chain_count(27, include_special), 1);

  include_special = true;
  EXPECT_EQ(parameters.get_chain_count(0, include_special), 32);
  EXPECT_EQ(parameters.get_chain_count(1, include_special), 31);
  EXPECT_EQ(parameters.get_chain_count(26, include_special), 6);
  EXPECT_EQ(parameters.get_chain_count(27, include_special), 5);
}
class GetBasePrime : public testing::TestWithParam<
                         std::tuple<desilo::fhe::CKKSConfig, int64_t>> {};

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetBasePrime,
    testing::Values(
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("iron"),
                        1152921504606830593),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("bronze"),
                        1152921504606748673),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("silver"),
                        1152921504606584833),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("gold"),
                        1152921504606584833),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("platinum"),
                        1152921504606584833),
        std::make_tuple(desilo::fhe::CKKSConfig::for_bootstrap(),
                        1152921504606584833)),
    [](const testing::TestParamInfo<GetBasePrime::ParamType> &info) {
      const auto config = std::get<0>(info.param);
      return print_tier(config.log_coeff_count_) +
             print_scheme_preset(config.scheme_preset_);
    });

TEST_P(GetBasePrime, ) {
  const auto [config, base_prime] = GetParam();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(base_prime, parameters.get_base_prime());
}
