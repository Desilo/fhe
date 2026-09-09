#include <cmath>
#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/parameters.h"

TEST(Level, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 22);
  EXPECT_EQ(parameters.get_level(1, true), 22);
  EXPECT_EQ(parameters.get_level(1, false), 21);
  EXPECT_EQ(parameters.get_level(2, true), 21);
  EXPECT_EQ(parameters.get_level(2, false), 20);
  EXPECT_EQ(parameters.get_level(21, true), 2);
  EXPECT_EQ(parameters.get_level(21, false), 1);
  EXPECT_EQ(parameters.get_level(22, true), 1);
  EXPECT_EQ(parameters.get_level(22, false), 0);
}

TEST(Level, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 20);
  EXPECT_EQ(parameters.get_level(1, true), 20);
  EXPECT_EQ(parameters.get_level(1, false), 19);
  EXPECT_EQ(parameters.get_level(2, true), 19);
  EXPECT_EQ(parameters.get_level(2, false), 18);
  EXPECT_EQ(parameters.get_level(19, true), 2);
  EXPECT_EQ(parameters.get_level(19, false), 1);
  EXPECT_EQ(parameters.get_level(20, true), 1);
  EXPECT_EQ(parameters.get_level(20, false), 0);
}

TEST(Level, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 17);
  EXPECT_EQ(parameters.get_level(1, true), 17);
  EXPECT_EQ(parameters.get_level(1, false), 16);
  EXPECT_EQ(parameters.get_level(2, true), 16);
  EXPECT_EQ(parameters.get_level(2, false), 15);
  EXPECT_EQ(parameters.get_level(16, true), 2);
  EXPECT_EQ(parameters.get_level(16, false), 1);
  EXPECT_EQ(parameters.get_level(17, true), 1);
  EXPECT_EQ(parameters.get_level(17, false), 0);
}

TEST(Level, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 22);
  EXPECT_EQ(parameters.get_level(1, true), 22);
  EXPECT_EQ(parameters.get_level(1, false), 21);
  EXPECT_EQ(parameters.get_level(2, true), 21);
  EXPECT_EQ(parameters.get_level(2, false), 20);
  EXPECT_EQ(parameters.get_level(21, true), 2);
  EXPECT_EQ(parameters.get_level(21, false), 1);
  EXPECT_EQ(parameters.get_level(22, true), 1);
  EXPECT_EQ(parameters.get_level(22, false), 0);
}

TEST(Level, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 20);
  EXPECT_EQ(parameters.get_level(1, true), 20);
  EXPECT_EQ(parameters.get_level(1, false), 19);
  EXPECT_EQ(parameters.get_level(2, true), 19);
  EXPECT_EQ(parameters.get_level(2, false), 18);
  EXPECT_EQ(parameters.get_level(19, true), 2);
  EXPECT_EQ(parameters.get_level(19, false), 1);
  EXPECT_EQ(parameters.get_level(20, true), 1);
  EXPECT_EQ(parameters.get_level(20, false), 0);
}

TEST(Level, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 17);
  EXPECT_EQ(parameters.get_level(1, true), 17);
  EXPECT_EQ(parameters.get_level(1, false), 16);
  EXPECT_EQ(parameters.get_level(2, true), 16);
  EXPECT_EQ(parameters.get_level(2, false), 15);
  EXPECT_EQ(parameters.get_level(16, true), 2);
  EXPECT_EQ(parameters.get_level(16, false), 1);
  EXPECT_EQ(parameters.get_level(17, true), 1);
  EXPECT_EQ(parameters.get_level(17, false), 0);
}

TEST(Level, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 2);
  EXPECT_EQ(parameters.get_level(1, true), 2);
  EXPECT_EQ(parameters.get_level(1, false), 1);
  EXPECT_EQ(parameters.get_level(2, true), 1);
  EXPECT_EQ(parameters.get_level(2, false), 0);
  EXPECT_EQ(parameters.get_level(3, true), 0);
}

TEST(Level, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 7);
  EXPECT_EQ(parameters.get_level(1, true), 7);
  EXPECT_EQ(parameters.get_level(1, false), 6);
  EXPECT_EQ(parameters.get_level(2, true), 6);
  EXPECT_EQ(parameters.get_level(2, false), 5);
  EXPECT_EQ(parameters.get_level(7, true), 1);
  EXPECT_EQ(parameters.get_level(7, false), 0);
  EXPECT_EQ(parameters.get_level(8, true), 0);
}

TEST(Level, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 17);
  EXPECT_EQ(parameters.get_level(1, true), 17);
  EXPECT_EQ(parameters.get_level(1, false), 16);
  EXPECT_EQ(parameters.get_level(2, true), 16);
  EXPECT_EQ(parameters.get_level(2, false), 15);
  EXPECT_EQ(parameters.get_level(17, true), 1);
  EXPECT_EQ(parameters.get_level(17, false), 0);
  EXPECT_EQ(parameters.get_level(18, true), 0);
}

TEST(Level, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 36);
  EXPECT_EQ(parameters.get_level(1, true), 36);
  EXPECT_EQ(parameters.get_level(1, false), 35);
  EXPECT_EQ(parameters.get_level(2, true), 35);
  EXPECT_EQ(parameters.get_level(2, false), 34);
  EXPECT_EQ(parameters.get_level(36, true), 1);
  EXPECT_EQ(parameters.get_level(36, false), 0);
  EXPECT_EQ(parameters.get_level(37, true), 0);
}

TEST(Level, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 77);
  EXPECT_EQ(parameters.get_level(1, true), 77);
  EXPECT_EQ(parameters.get_level(1, false), 76);
  EXPECT_EQ(parameters.get_level(2, true), 76);
  EXPECT_EQ(parameters.get_level(2, false), 75);
  EXPECT_EQ(parameters.get_level(77, true), 1);
  EXPECT_EQ(parameters.get_level(77, false), 0);
}

TEST(Level, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_level(0, false), 26);
  EXPECT_EQ(parameters.get_level(1, true), 26);
  EXPECT_EQ(parameters.get_level(1, false), 25);
  EXPECT_EQ(parameters.get_level(2, true), 25);
  EXPECT_EQ(parameters.get_level(2, false), 24);
  EXPECT_EQ(parameters.get_level(26, true), 1);
  EXPECT_EQ(parameters.get_level(26, false), 0);
}
