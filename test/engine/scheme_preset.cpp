#include <gtest/gtest.h>

#include "engine/scheme_preset.h"

TEST(SchemePreset, CKKS_40_60_DEFAULT) {
  auto preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;

  EXPECT_EQ(desilo::fhe::scheme_preset::get_scale_bit_length(preset), 40);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_small_prime_bit_length(preset), 40);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_large_prime_bit_length(preset), 60);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_bootstrap(preset), false);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_one_more_level(preset), true);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_engine_test(preset), false);
}

TEST(SchemePreset, CKKS_54_60_BOOTSTRAP) {
  auto preset = desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP;

  EXPECT_EQ(desilo::fhe::scheme_preset::get_scale_bit_length(preset), 54);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_small_prime_bit_length(preset), 54);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_large_prime_bit_length(preset), 60);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_bootstrap(preset), true);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_one_more_level(preset), true);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_engine_test(preset), false);
}

TEST(SchemePreset, CKKS_40_60_DEFAULT_ENGINE_TEST) {
  auto preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST;

  EXPECT_EQ(desilo::fhe::scheme_preset::get_scale_bit_length(preset), 40);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_small_prime_bit_length(preset), 40);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_large_prime_bit_length(preset), 60);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_bootstrap(preset), false);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_one_more_level(preset), true);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_engine_test(preset), true);
}

TEST(SchemePreset, CKKS_54_60_BOOTSTRAP_ENGINE_TEST) {
  auto preset = desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST;

  EXPECT_EQ(desilo::fhe::scheme_preset::get_scale_bit_length(preset), 54);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_small_prime_bit_length(preset), 54);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_large_prime_bit_length(preset), 60);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_bootstrap(preset), true);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_one_more_level(preset), true);
  EXPECT_EQ(desilo::fhe::scheme_preset::get_use_engine_test(preset), true);
}
