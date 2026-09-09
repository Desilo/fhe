#include <cmath>
#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/parameters.h"

TEST(ChainOffset, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 22), 22);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 22), 21);
  EXPECT_EQ(parameters.get_chain_offset(21, 22), 1);
  EXPECT_EQ(parameters.get_chain_offset(22, 22), 0);
}

TEST(ChainOffset, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 20), 20);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 20), 19);
  EXPECT_EQ(parameters.get_chain_offset(19, 20), 1);
  EXPECT_EQ(parameters.get_chain_offset(20, 20), 0);
}

TEST(ChainOffset, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 17), 17);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 17), 16);
  EXPECT_EQ(parameters.get_chain_offset(16, 17), 1);
  EXPECT_EQ(parameters.get_chain_offset(17, 17), 0);
}

TEST(ChainOffset, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 22), 22);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 22), 21);
  EXPECT_EQ(parameters.get_chain_offset(21, 22), 1);
  EXPECT_EQ(parameters.get_chain_offset(22, 22), 0);
}

TEST(ChainOffset, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 20), 20);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 20), 19);
  EXPECT_EQ(parameters.get_chain_offset(19, 20), 1);
  EXPECT_EQ(parameters.get_chain_offset(20, 20), 0);
}

TEST(ChainOffset, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 17), 17);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 17), 16);
  EXPECT_EQ(parameters.get_chain_offset(16, 17), 1);
  EXPECT_EQ(parameters.get_chain_offset(17, 17), 0);
}

TEST(ChainOffset, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 2), 2);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 2), 1);
  EXPECT_EQ(parameters.get_chain_offset(2, 2), 0);
}

TEST(ChainOffset, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 7), 7);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 7), 6);
  EXPECT_EQ(parameters.get_chain_offset(6, 7), 1);
  EXPECT_EQ(parameters.get_chain_offset(7, 7), 0);
}

TEST(ChainOffset, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 17), 17);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 17), 16);
  EXPECT_EQ(parameters.get_chain_offset(16, 17), 1);
  EXPECT_EQ(parameters.get_chain_offset(17, 17), 0);
}

TEST(ChainOffset, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 36), 36);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 36), 35);
  EXPECT_EQ(parameters.get_chain_offset(35, 36), 1);
  EXPECT_EQ(parameters.get_chain_offset(36, 36), 0);
}

TEST(ChainOffset, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 77), 77);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 77), 76);
  EXPECT_EQ(parameters.get_chain_offset(76, 77), 1);
  EXPECT_EQ(parameters.get_chain_offset(77, 77), 0);
}

TEST(ChainOffset, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  EXPECT_EQ(parameters.get_chain_offset(0, 0), 0);
  EXPECT_EQ(parameters.get_chain_offset(0, 1), 1);
  EXPECT_EQ(parameters.get_chain_offset(0, 26), 26);
  EXPECT_EQ(parameters.get_chain_offset(1, 1), 0);
  EXPECT_EQ(parameters.get_chain_offset(1, 26), 25);
  EXPECT_EQ(parameters.get_chain_offset(25, 26), 1);
  EXPECT_EQ(parameters.get_chain_offset(26, 26), 0);
}
