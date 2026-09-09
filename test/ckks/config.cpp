#include <gtest/gtest.h>

#include "ckks/config.h"
#include "common/common.h"

TEST(CKKSConfig, Valid) {
  desilo::fhe::CKKSConfig config;

  config.validate();
}

class FromMaxLevel : public testing::TestWithParam<std::tuple<int, int, int>> {
};

INSTANTIATE_TEST_CASE_P(
    CKKSConfig, FromMaxLevel,
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
                    std::make_tuple(76, 17, 6), std::make_tuple(77, 17, 6)),
    [](const testing::TestParamInfo<FromMaxLevel::ParamType> &info) {
      return print_level(std::get<0>(info.param));
    });

TEST_P(FromMaxLevel, ) {
  const auto [max_level, log_coeff_count, special_prime_count] = GetParam();

  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);

  EXPECT_EQ(config.max_level_, max_level);
  EXPECT_EQ(config.log_coeff_count_, log_coeff_count);
  EXPECT_EQ(config.special_prime_count_, special_prime_count);

  config.validate();
}

TEST_P(FromMaxLevel, WithSlotCount) {
  const auto [max_level, log_coeff_count, special_prime_count] = GetParam();
  const auto max_slot_count = 1 << (log_coeff_count - 1);

  for (int slot_count = 2; slot_count <= max_slot_count; slot_count++) {
    auto config = desilo::fhe::CKKSConfig::from_slot_count_and_max_level(
        slot_count, max_level);

    EXPECT_LT(1 << (config.log_slot_count_ - 1), slot_count);
    EXPECT_GE(1 << config.log_slot_count_, slot_count);
    EXPECT_EQ(config.max_level_, max_level);
    EXPECT_EQ(config.log_coeff_count_, log_coeff_count);
    EXPECT_EQ(config.special_prime_count_, special_prime_count);

    config.validate();
  }
}

TEST_P(FromMaxLevel, SlotCountTooSmall) {
  const auto [max_level, log_coeff_count, special_prime_count] = GetParam();

  try {
    int slot_count = 0;
    desilo::fhe::CKKSConfig::from_slot_count_and_max_level(slot_count,
                                                           max_level);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given slot count is too small.", e.what());
  }
}

TEST_P(FromMaxLevel, LogCoeffCountTooLarge) {
  const auto [max_level, log_coeff_count, special_prime_count] = GetParam();

  try {
    auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
    int slot_count = (1 << (config.log_coeff_count_ - 1)) + 1;
    desilo::fhe::CKKSConfig::from_slot_count_and_max_level(slot_count,
                                                           max_level);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given slot count is too large.", e.what());
  }
}

TEST(CKKSConfig, ForBootstrap) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();

  EXPECT_EQ(config.log_coeff_count_, 16);
  EXPECT_EQ(config.special_prime_count_, 4);
  EXPECT_EQ(config.scheme_preset_,
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP);

  config.validate();
}

TEST(CKKSConfig, ForSparseBootstrap) {
  const auto max_slot_count = 1 << 15;

  for (int slot_count = 2; slot_count <= max_slot_count; slot_count++) {
    auto config = desilo::fhe::CKKSConfig::for_sparse_bootstrap(slot_count);

    EXPECT_LT(1 << (config.log_slot_count_ - 1), slot_count);
    EXPECT_GE(1 << config.log_slot_count_, slot_count);
    EXPECT_EQ(config.log_coeff_count_, 16);
    EXPECT_EQ(config.special_prime_count_, 4);
    EXPECT_EQ(config.scheme_preset_,
              desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP);

    config.validate();
  }
}

TEST(CKKSConfig, ForSparseBootstrapSlotCountTooSmall) {
  try {
    int slot_count = 0;
    desilo::fhe::CKKSConfig::for_sparse_bootstrap(slot_count);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given slot count is too small.", e.what());
  }
}

TEST(CKKSConfig, ForSparseBootstrapLogCoeffCountTooLarge) {
  try {
    int slot_count = (1 << 15) + 1;
    desilo::fhe::CKKSConfig::for_sparse_bootstrap(slot_count);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given slot count is too large.", e.what());
  }
}

class GetSmallPrimeCount
    : public testing::TestWithParam<
          std::tuple<desilo::fhe::SchemePreset, int, int, int>> {};

INSTANTIATE_TEST_CASE_P(
    CKKSConfig, GetSmallPrimeCount,
    testing::Values(
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 13, 1,
                        2),
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 14, 1,
                        7),
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 15, 2,
                        17),
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 16, 4,
                        36),
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 17, 6,
                        77),
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP, 16, 4,
                        26),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST, 3, 1,
            22),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST, 3, 2,
            20),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST, 3, 4,
            17),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST, 4, 1,
            22),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST, 4, 2,
            20),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST, 4, 4,
            17),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST, 3, 1,
            16),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST, 3, 2,
            15),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST, 3, 4,
            12),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST, 4, 1,
            16),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST, 4, 2,
            15),
        std::make_tuple(
            desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST, 4, 4,
            12)),
    [](const testing::TestParamInfo<GetSmallPrimeCount::ParamType> &info) {
      std::string postfix = "";
      auto log_coeff_count = std::get<1>(info.param);
      if (log_coeff_count == 3 || log_coeff_count == 4) {
        postfix = std::to_string(std::get<2>(info.param)) + "SpecialPrimes";
      }

      return print_tier(std::get<1>(info.param)) +
             print_scheme_preset(std::get<0>(info.param)) + postfix;
    });

TEST_P(GetSmallPrimeCount, ) {
  const auto [scheme_preset, log_coeff_count, special_prime_count, expected] =
      GetParam();

  desilo::fhe::CKKSConfig config;
  config.scheme_preset_ = scheme_preset;
  config.log_coeff_count_ = log_coeff_count;
  config.special_prime_count_ = special_prime_count;

  EXPECT_EQ(config.get_small_prime_count(), expected);
}

class CKKSConfigScheme : public testing::TestWithParam<
                             std::tuple<desilo::fhe::SchemePreset, int, int>> {
};

INSTANTIATE_TEST_CASE_P(
    CKKSConfig, CKKSConfigScheme,
    testing::Values(
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 13, 17),
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP, 16,
                        16)));

TEST_P(CKKSConfigScheme, InvalidLogCoeffCount) {
  const auto [scheme_preset, min_log_coeff_count, max_log_coeff_count] =
      GetParam();
  desilo::fhe::CKKSConfig config;
  config.scheme_preset_ = scheme_preset;

  try {
    config.log_coeff_count_ = min_log_coeff_count - 1;
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log coefficient count is too small.", e.what());
  }

  try {
    config.log_coeff_count_ = max_log_coeff_count + 1;
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log coefficient count is too large.", e.what());
  }
}

TEST_P(CKKSConfigScheme, LogSlotCountTooSmall) {
  desilo::fhe::CKKSConfig config;
  const auto scheme_preset = GetParam();

  try {
    config.log_slot_count_ = -2;
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log slot count is too small.", e.what());
  }
}

TEST_P(CKKSConfigScheme, LogSlotCountTooLarge) {
  desilo::fhe::CKKSConfig config;
  const auto scheme_preset = GetParam();

  try {
    config.log_slot_count_ = config.log_coeff_count_;
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log slot count is too large.", e.what());
  }
}

class CKKSConfigEngineTestScheme
    : public testing::TestWithParam<desilo::fhe::SchemePreset> {};

INSTANTIATE_TEST_CASE_P(
    CKKSConfig, CKKSConfigEngineTestScheme,
    testing::Values(
        desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST,
        desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST));

TEST_P(CKKSConfigEngineTestScheme, InvalidLogCoeffCount) {
  desilo::fhe::CKKSConfig config;
  config.scheme_preset_ = GetParam();

  try {
    config.log_coeff_count_ = 2;
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log coefficient count is too small.", e.what());
  }

  try {
    config.log_coeff_count_ = 5;
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log coefficient count is too large.", e.what());
  }
}

TEST(CKKSConfig, SpecialPrimeCountTooSmall) {
  desilo::fhe::CKKSConfig config;
  config.special_prime_count_ = -1;

  try {
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given special prime count is too small.", e.what());
  }
}

TEST(CKKSConfig, SpecialPrimeCountTooLarge) {
  desilo::fhe::CKKSConfig config;
  config.special_prime_count_ = 17;

  try {
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given special prime count is too large.", e.what());
  }
}

TEST(CKKSConfig, LogCoeffCountNotSupportedBootstrap17) {
  desilo::fhe::CKKSConfig config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_coeff_count_ = 17;

  try {
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log coefficient count is too large.", e.what());
  }
}

TEST(CKKSConfig, MaxLevelTooSmall) {
  desilo::fhe::CKKSConfig config;
  config.max_level_ = -2;

  try {
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given max level is too small.", e.what());
  }
}

TEST(CKKSConfig, MaxLevelTooLarge) {
  desilo::fhe::CKKSConfig config;
  config.max_level_ = 78;

  try {
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given max level is too large.", e.what());
  }
}

TEST(CKKSConfig, CPUThreadCountTooLarge) {
  desilo::fhe::CKKSConfig config;
  config.processor_ = desilo::fhe::EngineProcessor::CPU;
  config.thread_count_ = 2;

  try {
    config.validate();
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given thread count is too large.", e.what());
  }
}
