#include <gtest/gtest.h>
#include <string>

#include "common/common.h"
#include "engine/engine.h"

TEST(Engine, CreateDefaultEngine) {
  const auto engine = desilo::fhe::create_default_engine();

  EXPECT_EQ(engine->get_slot_count(), 8192);
  EXPECT_EQ(engine->get_max_level(), 7);

  delete engine;
}

TEST(Engine, CreateDefaultCKKSCore) {
  const auto engine = desilo::fhe::create_default_engine("ckks");

  EXPECT_EQ(engine->get_slot_count(), 8192);
  EXPECT_EQ(engine->get_max_level(), 7);

  delete engine;
}

TEST(Engine, CreateIronCKKSCore) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto engine = desilo::fhe::create_ckks_engine(config);

  EXPECT_EQ(engine->get_slot_count(), 4096);
  EXPECT_EQ(engine->get_max_level(), 2);

  delete engine;
}

TEST(Engine, CreateNotSupportedScheme) {
  try {
    desilo::fhe::create_default_engine("abcd");
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given scheme is not supported.", e.what());
  }
}

TEST(Engine, CreateCKKSLogCoeffCountSmall) {
  desilo::fhe::CKKSConfig config;
  config.log_coeff_count_ = 12;

  try {
    desilo::fhe::create_ckks_engine(config);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log coefficient count is too small.", e.what());
  }
}

class EngineTestScheme
    : public testing::TestWithParam<desilo::fhe::SchemePreset> {};

INSTANTIATE_TEST_CASE_P(
    Engine, EngineTestScheme,
    testing::Values(
        desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST,
        desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST));

TEST_P(EngineTestScheme, CreateCKKSLogCoeffCountSmall) {
  desilo::fhe::CKKSConfig config;
  config.scheme_preset_ = GetParam();
  config.log_coeff_count_ = 2;

  try {
    desilo::fhe::create_ckks_engine(config);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("The given log coefficient count is too small.", e.what());
  }
}
