#include <cmath>
#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/parameters.h"

TEST(GetKeyModuliId, Sand1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 8; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Sand2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 18; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Sand4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("sand");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 37; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Pebble1) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 8; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Pebble2) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 2;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 18; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Pebble4) {
  auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
  config.special_prime_count_ = 4;
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 37; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 3; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Bronze) {
  auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 8; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Silver) {
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 18; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Gold) {
  auto config = desilo::fhe::CKKSConfig::from_tier("gold");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 37; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, Platinum) {
  auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 78; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}

TEST(GetKeyModuliId, BootstrapGold) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  const auto parameters = desilo::fhe::CKKSParameters(config);

  for (int moduli_id = 0; moduli_id <= 27; moduli_id++) {
    EXPECT_EQ(parameters.get_key_moduli_id(moduli_id), moduli_id);
    EXPECT_EQ(parameters.get_intt_moduli_id(moduli_id), moduli_id);
  }
}
