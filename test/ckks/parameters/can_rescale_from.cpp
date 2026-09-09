#include <cmath>
#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/parameters.h"

TEST(CanRescaleFrom, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 22; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(23));
}

TEST(CanRescaleFrom, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 20; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(21));
}

TEST(CanRescaleFrom, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 17; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(18));
}

TEST(CanRescaleFrom, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 22; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(23));
}

TEST(CanRescaleFrom, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 20; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(21));
}

TEST(CanRescaleFrom, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 17; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(18));
}

TEST(CanRescaleFrom, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 2; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(3));
}

TEST(CanRescaleFrom, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 7; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(8));
}

TEST(CanRescaleFrom, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 17; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(18));
}

TEST(CanRescaleFrom, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 36; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(37));
}

TEST(CanRescaleFrom, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 77; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(78));
}

TEST(CanRescaleFrom, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 26; moduli_id++) {
    EXPECT_TRUE(parameters.can_rescale_from(moduli_id));
  }
  EXPECT_FALSE(parameters.can_rescale_from(27));
}
