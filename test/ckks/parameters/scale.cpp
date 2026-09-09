#include <cmath>
#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/parameters.h"

TEST(Scale, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 40));
}

TEST(Scale, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_scale(), std::pow(2, 54));
}
