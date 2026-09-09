#include <gtest/gtest.h>
#include <map>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

#pragma once

#define BOOTSTRAP get_use_bootstrap(config_)
#define ONE_MORE_LEVEL get_use_one_more_level(config_)
#define FULL_LEVEL                                                             \
  ({                                                                           \
    auto parameters = desilo::fhe::CKKSParameters(config_);                    \
    parameters.get_full_level();                                               \
  })

#define DECRYPT_DUO(x)                                                         \
  ({                                                                           \
    desilo::fhe::UnitPlaintext *decrypted;                                     \
    decrypted = core.decrypt_duo(x, secret_key_);                              \
    decrypted;                                                                 \
  })

#define DECRYPT_TRIO(x)                                                        \
  ({                                                                           \
    desilo::fhe::UnitPlaintext *decrypted;                                     \
    decrypted = core.decrypt_trio(x, secret_key_);                             \
    decrypted;                                                                 \
  })

#define DELETE(x)                                                              \
  do {                                                                         \
    if (x != nullptr) {                                                        \
      delete x;                                                                \
      x = nullptr;                                                             \
    }                                                                          \
  } while (0)

#define DEFINE_TIER_TEST_CLASS_SP(tier, name, ...)                             \
  class tier##CKKSCore##name                                                   \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = tier_configs[#tier];                                           \
      auto core = desilo::fhe::CKKSCore(config_);                              \
      auto max_level = core.parameters_.get_max_level();                       \
                                                                               \
      secret_key_ = core.create_secret_key(max_level);                         \
      public_key_ = core.create_public_key(secret_key_, max_level);            \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(secret_key_1_);                                                   \
      DELETE(secret_key_2_);                                                   \
      DELETE(secret_key_3_);                                                   \
      DELETE(public_key_);                                                     \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSCore##name::config_ = {};                  \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_ = nullptr;         \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_1_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_2_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_3_ = nullptr;       \
  desilo::fhe::PublicKey *tier##CKKSCore##name::public_key_ = nullptr;

#define DEFINE_TIER_TEST_CLASS_SPC(tier, name, ...)                            \
  class tier##CKKSCore##name                                                   \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = tier_configs[#tier];                                           \
      auto core = desilo::fhe::CKKSCore(config_);                              \
      auto max_level = core.parameters_.get_max_level();                       \
                                                                               \
      secret_key_ = core.create_secret_key(max_level);                         \
      public_key_ = core.create_public_key(secret_key_, max_level);            \
      conjugation_key_ = core.create_conjugation_key(secret_key_, max_level);  \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(secret_key_1_);                                                   \
      DELETE(secret_key_2_);                                                   \
      DELETE(secret_key_3_);                                                   \
      DELETE(public_key_);                                                     \
      DELETE(conjugation_key_);                                                \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::ConjugationKey *conjugation_key_;                      \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSCore##name::config_ = {};                  \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_ = nullptr;         \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_1_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_2_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_3_ = nullptr;       \
  desilo::fhe::PublicKey *tier##CKKSCore##name::public_key_ = nullptr;         \
  desilo::fhe::ConjugationKey *tier##CKKSCore##name::conjugation_key_ = nullptr;

#define DEFINE_TIER_TEST_CLASS_SPF(tier, name, ...)                            \
  class tier##CKKSCore##name                                                   \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = tier_configs[#tier];                                           \
      auto core = desilo::fhe::CKKSCore(config_);                              \
      auto max_level = core.parameters_.get_max_level();                       \
                                                                               \
      secret_key_ = core.create_secret_key(max_level);                         \
      public_key_ = core.create_public_key(secret_key_, max_level);            \
      fixed_rotation_keys_[1] =                                                \
          core.create_fixed_rotation_key(secret_key_, max_level, 1);           \
      fixed_rotation_keys_[2] =                                                \
          core.create_fixed_rotation_key(secret_key_, max_level, 2);           \
      fixed_rotation_keys_[-4] =                                               \
          core.create_fixed_rotation_key(secret_key_, max_level, -4);          \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(secret_key_1_);                                                   \
      DELETE(secret_key_2_);                                                   \
      DELETE(secret_key_3_);                                                   \
      DELETE(public_key_);                                                     \
      DELETE(fixed_rotation_keys_[1]);                                         \
      DELETE(fixed_rotation_keys_[2]);                                         \
      DELETE(fixed_rotation_keys_[-4]);                                        \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static std::map<int, desilo::fhe::FixedRotationKey *>                      \
        fixed_rotation_keys_;                                                  \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSCore##name::config_ = {};                  \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_ = nullptr;         \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_1_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_2_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_3_ = nullptr;       \
  desilo::fhe::PublicKey *tier##CKKSCore##name::public_key_ = nullptr;         \
  std::map<int, desilo::fhe::FixedRotationKey *>                               \
      tier##CKKSCore##name::fixed_rotation_keys_ = {};

#define DEFINE_TIER_TEST_CLASS_SPR(tier, name, ...)                            \
  class tier##CKKSCore##name                                                   \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = tier_configs[#tier];                                           \
      auto core = desilo::fhe::CKKSCore(config_);                              \
      auto max_level = core.parameters_.get_max_level();                       \
                                                                               \
      secret_key_ = core.create_secret_key(max_level);                         \
      public_key_ = core.create_public_key(secret_key_, max_level);            \
      relinearization_key_ =                                                   \
          core.create_relinearization_key(secret_key_, max_level);             \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(secret_key_1_);                                                   \
      DELETE(secret_key_2_);                                                   \
      DELETE(secret_key_3_);                                                   \
      DELETE(public_key_);                                                     \
      DELETE(relinearization_key_);                                            \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::RelinearizationKey *relinearization_key_;              \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSCore##name::config_ = {};                  \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_ = nullptr;         \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_1_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_2_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_3_ = nullptr;       \
  desilo::fhe::PublicKey *tier##CKKSCore##name::public_key_ = nullptr;         \
  desilo::fhe::RelinearizationKey                                              \
      *tier##CKKSCore##name::relinearization_key_ = nullptr;

#define DEFINE_TIER_TEST_CLASS_SPE(tier, name, ...)                            \
  class tier##CKKSCore##name                                                   \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = tier_configs[#tier];                                           \
      auto core = desilo::fhe::CKKSCore(config_);                              \
      auto max_level = core.parameters_.get_max_level();                       \
                                                                               \
      secret_key_ = core.create_secret_key(max_level);                         \
      public_key_ = core.create_public_key(secret_key_, max_level);            \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(secret_key_1_);                                                   \
      DELETE(secret_key_2_);                                                   \
      DELETE(secret_key_3_);                                                   \
      DELETE(public_key_);                                                     \
      DELETE(relinearization_key_);                                            \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::RelinearizationKey *relinearization_key_;              \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSCore##name::config_ = {};                  \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_ = nullptr;         \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_1_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_2_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSCore##name::secret_key_3_ = nullptr;       \
  desilo::fhe::PublicKey *tier##CKKSCore##name::public_key_ = nullptr;         \
  desilo::fhe::RelinearizationKey                                              \
      *tier##CKKSCore##name::relinearization_key_ = nullptr;

#define INSTANTIATE_TIER_TEST(tier, name, level_start, level_end,              \
                              to_test_name, ...)                               \
  INSTANTIATE_TEST_CASE_P(                                                     \
      , tier##CKKSCore##name,                                                  \
      testing::Combine(testing::Range(level_start, level_end), __VA_ARGS__),   \
      [](const testing::TestParamInfo<tier##CKKSCore##name::ParamType>         \
             &info) { return to_test_name(info.param); });

#define SETUP_TIER_TEST_SP2_(                                                  \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SP(Iron, name, int, int);                             \
  DEFINE_TIER_TEST_CLASS_SP(IronSparse, name, int, int);                       \
  DEFINE_TIER_TEST_CLASS_SP(Bronze, name, int, int);                           \
  DEFINE_TIER_TEST_CLASS_SP(Silver, name, int, int);                           \
  DEFINE_TIER_TEST_CLASS_SP(Gold, name, int, int);                             \
  DEFINE_TIER_TEST_CLASS_SP(Platinum, name, int, int);                         \
  DEFINE_TIER_TEST_CLASS_SP(GoldBootstrap, name, int, int);                    \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SP3_(                                                  \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SP(Iron, name, int, int, int);                        \
  DEFINE_TIER_TEST_CLASS_SP(IronSparse, name, int, int, int);                  \
  DEFINE_TIER_TEST_CLASS_SP(Bronze, name, int, int, int);                      \
  DEFINE_TIER_TEST_CLASS_SP(Silver, name, int, int, int);                      \
  DEFINE_TIER_TEST_CLASS_SP(Gold, name, int, int, int);                        \
  DEFINE_TIER_TEST_CLASS_SP(Platinum, name, int, int, int);                    \
  DEFINE_TIER_TEST_CLASS_SP(GoldBootstrap, name, int, int, int);               \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SP4_(                                                  \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SP(Iron, name, int, int, int, int);                   \
  DEFINE_TIER_TEST_CLASS_SP(IronSparse, name, int, int, int, int);             \
  DEFINE_TIER_TEST_CLASS_SP(Bronze, name, int, int, int, int);                 \
  DEFINE_TIER_TEST_CLASS_SP(Silver, name, int, int, int, int);                 \
  DEFINE_TIER_TEST_CLASS_SP(Gold, name, int, int, int, int);                   \
  DEFINE_TIER_TEST_CLASS_SP(Platinum, name, int, int, int, int);               \
  DEFINE_TIER_TEST_CLASS_SP(GoldBootstrap, name, int, int, int, int);          \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SPC2_(                                                 \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SPC(Iron, name, int, int);                            \
  DEFINE_TIER_TEST_CLASS_SPC(IronSparse, name, int, int);                      \
  DEFINE_TIER_TEST_CLASS_SPC(Bronze, name, int, int);                          \
  DEFINE_TIER_TEST_CLASS_SPC(Silver, name, int, int);                          \
  DEFINE_TIER_TEST_CLASS_SPC(Gold, name, int, int);                            \
  DEFINE_TIER_TEST_CLASS_SPC(Platinum, name, int, int);                        \
  DEFINE_TIER_TEST_CLASS_SPC(GoldBootstrap, name, int, int);                   \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SPE2_(                                                 \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SPE(Iron, name, int, int);                            \
  DEFINE_TIER_TEST_CLASS_SPE(IronSparse, name, int, int);                      \
  DEFINE_TIER_TEST_CLASS_SPE(Bronze, name, int, int);                          \
  DEFINE_TIER_TEST_CLASS_SPE(Silver, name, int, int);                          \
  DEFINE_TIER_TEST_CLASS_SPE(Gold, name, int, int);                            \
  DEFINE_TIER_TEST_CLASS_SPE(Platinum, name, int, int);                        \
  DEFINE_TIER_TEST_CLASS_SPE(GoldBootstrap, name, int, int);                   \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SPE3_(                                                 \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SPE(Iron, name, int, int, int);                       \
  DEFINE_TIER_TEST_CLASS_SPE(IronSparse, name, int, int, int);                 \
  DEFINE_TIER_TEST_CLASS_SPE(Bronze, name, int, int, int);                     \
  DEFINE_TIER_TEST_CLASS_SPE(Silver, name, int, int, int);                     \
  DEFINE_TIER_TEST_CLASS_SPE(Gold, name, int, int, int);                       \
  DEFINE_TIER_TEST_CLASS_SPE(Platinum, name, int, int, int);                   \
  DEFINE_TIER_TEST_CLASS_SPE(GoldBootstrap, name, int, int, int);              \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SPE4_(                                                 \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SPE(Iron, name, int, int, int, int);                  \
  DEFINE_TIER_TEST_CLASS_SPE(IronSparse, name, int, int, int, int);            \
  DEFINE_TIER_TEST_CLASS_SPE(Bronze, name, int, int, int, int);                \
  DEFINE_TIER_TEST_CLASS_SPE(Silver, name, int, int, int, int);                \
  DEFINE_TIER_TEST_CLASS_SPE(Gold, name, int, int, int, int);                  \
  DEFINE_TIER_TEST_CLASS_SPE(Platinum, name, int, int, int, int);              \
  DEFINE_TIER_TEST_CLASS_SPE(GoldBootstrap, name, int, int, int, int);         \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SPF3_(                                                 \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SPF(Iron, name, int, int, int);                       \
  DEFINE_TIER_TEST_CLASS_SPF(IronSparse, name, int, int, int);                 \
  DEFINE_TIER_TEST_CLASS_SPF(Bronze, name, int, int, int);                     \
  DEFINE_TIER_TEST_CLASS_SPF(Silver, name, int, int, int);                     \
  DEFINE_TIER_TEST_CLASS_SPF(Gold, name, int, int, int);                       \
  DEFINE_TIER_TEST_CLASS_SPF(Platinum, name, int, int, int);                   \
  DEFINE_TIER_TEST_CLASS_SPF(GoldBootstrap, name, int, int, int);              \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define SETUP_TIER_TEST_SPR3_(                                                 \
    name, iron_level_start, iron_level_end, bronze_level_start,                \
    bronze_level_end, silver_level_start, silver_level_end, gold_level_start,  \
    gold_level_end, platinum_level_start, platinum_level_end,                  \
    bootstrap_gold_level_start, bootstrap_gold_level_end, to_test_name, ...)   \
  DEFINE_TIER_TEST_CLASS_SPR(Iron, name, int, int, int);                       \
  DEFINE_TIER_TEST_CLASS_SPR(IronSparse, name, int, int, int);                 \
  DEFINE_TIER_TEST_CLASS_SPR(Bronze, name, int, int, int);                     \
  DEFINE_TIER_TEST_CLASS_SPR(Silver, name, int, int, int);                     \
  DEFINE_TIER_TEST_CLASS_SPR(Gold, name, int, int, int);                       \
  DEFINE_TIER_TEST_CLASS_SPR(Platinum, name, int, int, int);                   \
  DEFINE_TIER_TEST_CLASS_SPR(GoldBootstrap, name, int, int, int);              \
  INSTANTIATE_TIER_TEST(Iron, name, iron_level_start, iron_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(IronSparse, name, iron_level_start, iron_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Bronze, name, bronze_level_start, bronze_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Silver, name, silver_level_start, silver_level_end,    \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Gold, name, gold_level_start, gold_level_end,          \
                        to_test_name, __VA_ARGS__);                            \
  INSTANTIATE_TIER_TEST(Platinum, name, platinum_level_start,                  \
                        platinum_level_end, to_test_name, __VA_ARGS__);        \
  INSTANTIATE_TIER_TEST(GoldBootstrap, name, bootstrap_gold_level_start,       \
                        bootstrap_gold_level_end, to_test_name, __VA_ARGS__);

#define TIER_TEST(fixture_name, test_name, test_body)                          \
  TEST_P(IronCKKSCore##fixture_name, test_name)                                \
  test_body;                                                                   \
  TEST_P(BronzeCKKSCore##fixture_name, test_name)                              \
  test_body;                                                                   \
  TEST_P(SilverCKKSCore##fixture_name, test_name)                              \
  test_body;                                                                   \
  TEST_P(GoldCKKSCore##fixture_name, test_name)                                \
  test_body;                                                                   \
  TEST_P(PlatinumCKKSCore##fixture_name, test_name)                            \
  test_body;                                                                   \
  TEST_P(GoldBootstrapCKKSCore##fixture_name, test_name)                       \
  test_body;                                                                   \
  TEST_P(IronSparseCKKSCore##fixture_name, test_name)                          \
  test_body;

#ifdef DESILO_FHE_LARGE_TEST
#define LEVELS_0_TO_MAX 0, 3, 0, 8, 0, 18, 32, 37, 71, 78, 19, 25
#else
#define LEVELS_0_TO_MAX 0, 3, 0, 8, 0, 18, 32, 37, 77, 78, 19, 25
#endif

#ifdef DESILO_FHE_LARGE_TEST
#define LEVELS_1_TO_MAX 1, 3, 1, 8, 1, 18, 32, 37, 71, 78, 19, 25
#else
#define LEVELS_1_TO_MAX 1, 3, 1, 8, 1, 18, 32, 37, 77, 78, 19, 25
#endif

#ifdef DESILO_FHE_LARGE_TEST
#define LEVELS_2_TO_MAX 2, 3, 2, 8, 2, 18, 32, 37, 71, 78, 19, 25
#else
#define LEVELS_2_TO_MAX 2, 3, 2, 8, 2, 18, 32, 37, 77, 78, 19, 25
#endif

#ifdef DESILO_FHE_LARGE_TEST
#define LEVELS_0_TO_MAX_MINUS_1 0, 2, 0, 7, 0, 17, 31, 36, 69, 77, 18, 24
#else
#define LEVELS_0_TO_MAX_MINUS_1 0, 2, 0, 7, 0, 17, 31, 36, 76, 77, 18, 24
#endif

#ifdef DESILO_FHE_LARGE_TEST
#define LEVELS_1_TO_MAX_MINUS_1 1, 2, 1, 7, 1, 17, 31, 36, 69, 77, 18, 24
#else
#define LEVELS_1_TO_MAX_MINUS_1 1, 2, 1, 7, 1, 17, 31, 36, 76, 77, 18, 24
#endif

#define SETUP_TIER_TEST_SP2(...) SETUP_TIER_TEST_SP2_(__VA_ARGS__)
#define SETUP_TIER_TEST_SP3(...) SETUP_TIER_TEST_SP3_(__VA_ARGS__)
#define SETUP_TIER_TEST_SP4(...) SETUP_TIER_TEST_SP4_(__VA_ARGS__)
#define SETUP_TIER_TEST_SPC2(...) SETUP_TIER_TEST_SPC2_(__VA_ARGS__)
#define SETUP_TIER_TEST_SPE2(...) SETUP_TIER_TEST_SPE2_(__VA_ARGS__)
#define SETUP_TIER_TEST_SPE3(...) SETUP_TIER_TEST_SPE3_(__VA_ARGS__)
#define SETUP_TIER_TEST_SPE4(...) SETUP_TIER_TEST_SPE4_(__VA_ARGS__)
#define SETUP_TIER_TEST_SPF3(...) SETUP_TIER_TEST_SPF3_(__VA_ARGS__)
#define SETUP_TIER_TEST_SPR3(...) SETUP_TIER_TEST_SPR3_(__VA_ARGS__)
