#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/parameters.h"

TEST(NextModuliIdAtRescale, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 22);

  for (int moduli_id = 0; moduli_id <= 22; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 20);

  for (int moduli_id = 0; moduli_id <= 20; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 17);

  for (int moduli_id = 0; moduli_id <= 17; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 22);

  for (int moduli_id = 0; moduli_id <= 22; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 20);

  for (int moduli_id = 0; moduli_id <= 20; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 17);

  for (int moduli_id = 0; moduli_id <= 17; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 2);

  for (int moduli_id = 0; moduli_id <= 2; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 7);

  for (int moduli_id = 0; moduli_id <= 7; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 17);

  for (int moduli_id = 0; moduli_id <= 17; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 36);

  for (int moduli_id = 0; moduli_id <= 36; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 77);

  for (int moduli_id = 0; moduli_id <= 77; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}

TEST(NextModuliIdAtRescale, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  ASSERT_EQ(parameters.get_full_level(), 26);

  for (int moduli_id = 0; moduli_id <= 26; moduli_id++) {
    auto next_moduli_id = parameters.get_next_moduli_id_at_rescale(moduli_id);
    EXPECT_EQ(next_moduli_id, moduli_id + 1);
  }
}
