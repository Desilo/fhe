#include "ckks/config.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

#pragma once

#define ONE_MORE_LEVEL get_use_one_more_level(config_)
#define FULL_LEVEL                                                             \
  ({                                                                           \
    auto parameters = desilo::fhe::CKKSParameters(config_);                    \
    parameters.get_full_level();                                               \
  })

#define DECRYPT_UNIT(x)                                                        \
  ({                                                                           \
    std::vector<double> decrypted;                                             \
    decrypted = engine.decrypt(x, secret_key_);                                \
    decrypted;                                                                 \
  })

#define DECRYPT_UNIT_COMPLEX(x)                                                \
  ({                                                                           \
    std::vector<std::complex<double>> decrypted;                               \
    decrypted = engine.decrypt_complex(x, secret_key_);                        \
    decrypted;                                                                 \
  })

#define DECRYPT_UNIT_TRIO_COMPLEX(x)                                           \
  ({                                                                           \
    std::vector<std::complex<double>> decrypted;                               \
    decrypted = engine.decrypt_complex(x, secret_key_);                        \
    decrypted;                                                                 \
  })

#define DECRYPT_UNIT_TO_PLAINTEXT(x)                                           \
  ({                                                                           \
    desilo::fhe::UnitPlaintext *decrypted;                                     \
    decrypted = engine.decrypt_to_unit_plaintext(x, secret_key_);              \
    decrypted;                                                                 \
  })

#define DECRYPT(x)                                                             \
  ({                                                                           \
    std::vector<double> decrypted;                                             \
    decrypted = engine.decrypt(x, secret_key_);                                \
    decrypted;                                                                 \
  })

#define DECRYPT_COMPLEX(x)                                                     \
  ({                                                                           \
    std::vector<std::complex<double>> decrypted;                               \
    decrypted = engine.decrypt_complex(x, secret_key_);                        \
    decrypted;                                                                 \
  })

#define DECRYPT_TRIO_COMPLEX(x)                                                \
  ({                                                                           \
    std::vector<std::complex<double>> decrypted;                               \
    decrypted = engine.decrypt_complex(x, secret_key_);                        \
    decrypted;                                                                 \
  })

#define DECRYPT_TO_PLAINTEXT(x)                                                \
  ({                                                                           \
    desilo::fhe::Plaintext *decrypted;                                         \
    decrypted = engine.decrypt_to_plaintext(x, secret_key_);                   \
    decrypted;                                                                 \
  })

#define DELETE(x)                                                              \
  do {                                                                         \
    if (x != nullptr) {                                                        \
      delete x;                                                                \
      x = nullptr;                                                             \
    }                                                                          \
  } while (0)

#define DEFINE_ENGINE_TEST_CLASS_SP(tier, name, ...)                           \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
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
    static int max_level_;                                                     \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;                                  \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_1_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_2_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_3_ = nullptr;     \
  desilo::fhe::PublicKey *tier##CKKSEngine##name::public_key_ = nullptr;

#define DEFINE_ENGINE_TEST_CLASS_SPC(tier, name, ...)                          \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
      conjugation_key_ = engine.create_conjugation_key(secret_key_);           \
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
    static int max_level_;                                                     \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::ConjugationKey *conjugation_key_;                      \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;                                  \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_1_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_2_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_3_ = nullptr;     \
  desilo::fhe::PublicKey *tier##CKKSEngine##name::public_key_ = nullptr;       \
  desilo::fhe::ConjugationKey *tier##CKKSEngine##name::conjugation_key_ =      \
      nullptr;

#define DEFINE_ENGINE_TEST_CLASS_SPF(tier, name, ...)                          \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
      fixed_rotation_key_ =                                                    \
          engine.create_fixed_rotation_key(secret_key_, delta_);               \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(secret_key_1_);                                                   \
      DELETE(secret_key_2_);                                                   \
      DELETE(secret_key_3_);                                                   \
      DELETE(public_key_);                                                     \
      DELETE(fixed_rotation_key_);                                             \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static int max_level_;                                                     \
    static int delta_;                                                         \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::FixedRotationKey *fixed_rotation_key_;                 \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;                                  \
  int tier##CKKSEngine##name::delta_ = 3;                                      \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_1_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_2_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_3_ = nullptr;     \
  desilo::fhe::PublicKey *tier##CKKSEngine##name::public_key_ = nullptr;       \
  desilo::fhe::FixedRotationKey *tier##CKKSEngine##name::fixed_rotation_key_ = \
      nullptr;

#define DEFINE_ENGINE_TEST_CLASS_SPO(tier, name, ...)                          \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
      rotation_key_ = engine.create_rotation_key(secret_key_);                 \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(secret_key_1_);                                                   \
      DELETE(secret_key_2_);                                                   \
      DELETE(secret_key_3_);                                                   \
      DELETE(public_key_);                                                     \
      DELETE(rotation_key_);                                                   \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static int max_level_;                                                     \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::RotationKey *rotation_key_;                            \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;                                  \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_1_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_2_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_3_ = nullptr;     \
  desilo::fhe::PublicKey *tier##CKKSEngine##name::public_key_ = nullptr;       \
  desilo::fhe::RotationKey *tier##CKKSEngine##name::rotation_key_ = nullptr;

#define DEFINE_ENGINE_TEST_CLASS_SPE(tier, name, ...)                          \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
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
    static int max_level_;                                                     \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::RelinearizationKey *relinearization_key_;              \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;                                  \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_1_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_2_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_3_ = nullptr;     \
  desilo::fhe::PublicKey *tier##CKKSEngine##name::public_key_ = nullptr;       \
  desilo::fhe::RelinearizationKey                                              \
      *tier##CKKSEngine##name::relinearization_key_ = nullptr;

#define DEFINE_ENGINE_TEST_CLASS_SPR(tier, name, ...)                          \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
      relinearization_key_ = engine.create_relinearization_key(secret_key_);   \
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
    static int max_level_;                                                     \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::SecretKey *secret_key_1_;                              \
    static desilo::fhe::SecretKey *secret_key_2_;                              \
    static desilo::fhe::SecretKey *secret_key_3_;                              \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::RelinearizationKey *relinearization_key_;              \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;                                  \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_ = nullptr;       \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_1_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_2_ = nullptr;     \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_3_ = nullptr;     \
  desilo::fhe::PublicKey *tier##CKKSEngine##name::public_key_ = nullptr;       \
  desilo::fhe::RelinearizationKey                                              \
      *tier##CKKSEngine##name::relinearization_key_ = nullptr;

#define INSTANTIATE_ENGINE_TEST(tier, name, to_test_name, ...)                 \
  INSTANTIATE_TEST_CASE_P(                                                     \
      , tier##CKKSEngine##name, __VA_ARGS__,                                   \
      [](const testing::TestParamInfo<tier##CKKSEngine##name::ParamType>       \
             &info) { return to_test_name(info.param); });

#define SETUP_ENGINE_TEST_SP1(name, to_test_name, ...)                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, int);                               \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, int);                       \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, int);                               \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, int);                               \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_DEFAULT_ENGINE_TEST_SP1(name, to_test_name, ...)                 \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, int);                               \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, int);                       \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, int);                               \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, int);                               \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP2(name, to_test_name, ...)                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, int, int);                          \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, int, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, int, int);                    \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, int, int);                          \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, int, int);                          \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_DEFAULT_ENGINE_TEST_SP2(name, to_test_name, ...)                 \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, int, int);                          \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, int, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, int, int);                    \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, int, int);                          \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, int, int);                          \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP3(name, to_test_name, ...)                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, int, int, int);                     \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, int, int, int);             \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, int, int, int);               \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, int, int, int);                     \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, int, int, int);                     \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP11(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, int);                 \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, int);                         \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_DEFAULT_ENGINE_TEST_SP11(name, to_test_name, ...)                \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, int);                 \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, int);                         \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP21(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, int);           \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, int);             \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, int);                   \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_DEFAULT_ENGINE_TEST_SP21(name, to_test_name, ...)                \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, int);           \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, int);             \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, int);                   \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP22(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, std::tuple<int, int>);  \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool,                 \
                              std::tuple<int, int>);                           \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool,                   \
                              std::tuple<int, int>);                           \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, std::tuple<int, int>);  \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, std::tuple<int, int>);  \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP31(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, bool, int);             \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, bool, int);     \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, bool, int);       \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, bool, int);             \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, bool, int);             \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP41(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, bool, bool, int);       \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, bool, bool,     \
                              int);                                            \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, bool, bool, int); \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, bool, bool, int);       \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, bool, bool, int);       \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP43(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, bool, bool,             \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, bool, bool,     \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, bool, bool,       \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, bool, bool,             \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, bool, bool,             \
                              std::tuple<int, int, int>);                      \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP51(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, bool, bool, bool, int); \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, bool, bool,     \
                              bool, int);                                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, bool, bool, bool, \
                              int);                                            \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, bool, bool, bool, int); \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, bool, bool, bool, int); \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP53(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, bool, bool, bool,       \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, bool, bool,     \
                              bool, std::tuple<int, int, int>);                \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, bool, bool, bool, \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, bool, bool, bool,       \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, bool, bool, bool,       \
                              std::tuple<int, int, int>);                      \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SP63(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1, name, bool, bool, bool, bool, bool, bool, \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Pebble1Sparse, name, bool, bool, bool, bool,     \
                              bool, bool, std::tuple<int, int, int>);          \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand1Level2, name, bool, bool, bool, bool, bool, \
                              bool, std::tuple<int, int, int>);                \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand2, name, bool, bool, bool, bool, bool, bool, \
                              std::tuple<int, int, int>);                      \
  DEFINE_ENGINE_TEST_CLASS_SP(Sand4, name, bool, bool, bool, bool, bool, bool, \
                              std::tuple<int, int, int>);                      \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPC21(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand1, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPC(Pebble1Sparse, name, bool, bool, int);          \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand1Level2, name, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand2, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand4, name, bool, bool, int);                  \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPC31(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand1, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPC(Pebble1Sparse, name, bool, bool, bool, int);    \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand1Level2, name, bool, bool, bool, int);      \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand2, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPC(Sand4, name, bool, bool, bool, int);            \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE11(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, int);                        \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, int);                \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, int);                        \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, int);                        \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE2(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, int, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, int, int);                 \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, int, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, int, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, int, int);                         \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE21(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool, int);          \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, int);                  \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE22(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, std::tuple<int, int>); \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool,                \
                               std::tuple<int, int>);                          \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool,                  \
                               std::tuple<int, int>);                          \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, std::tuple<int, int>); \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, std::tuple<int, int>); \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE31(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool, bool, int);    \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool, bool, int);      \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, bool, int);            \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE41(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, bool, bool, int);      \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool, bool, bool,    \
                               int);                                           \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool, bool, bool,      \
                               int);                                           \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, bool, bool, int);      \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, bool, bool, int);      \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE43(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, bool, bool,            \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool, bool, bool,    \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, bool, bool,            \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, bool, bool,            \
                               std::tuple<int, int, int>);                     \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE51(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, bool, bool, bool,      \
                               int);                                           \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool, bool, bool,    \
                               bool, int);                                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool, bool, bool,      \
                               bool, int);                                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, bool, bool, bool,      \
                               int);                                           \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, bool, bool, bool,      \
                               int);                                           \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE53(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool, bool, bool,    \
                               bool, std::tuple<int, int, int>);               \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool, bool, bool,      \
                               bool, std::tuple<int, int, int>);               \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPE63(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1, name, bool, bool, bool, bool, bool,      \
                               bool, std::tuple<int, int, int>);               \
  DEFINE_ENGINE_TEST_CLASS_SPE(Pebble1Sparse, name, bool, bool, bool, bool,    \
                               bool, bool, std::tuple<int, int, int>);         \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand1Level2, name, bool, bool, bool, bool,      \
                               bool, bool, std::tuple<int, int, int>);         \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand2, name, bool, bool, bool, bool, bool,      \
                               bool, std::tuple<int, int, int>);               \
  DEFINE_ENGINE_TEST_CLASS_SPE(Sand4, name, bool, bool, bool, bool, bool,      \
                               bool, std::tuple<int, int, int>);               \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPF21(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand1, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPF(Pebble1Sparse, name, bool, bool, int);          \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand1Level2, name, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand2, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand4, name, bool, bool, int);                  \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPF31(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand1, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPF(Pebble1Sparse, name, bool, bool, bool, int);    \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand1Level2, name, bool, bool, bool, int);      \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand2, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPF(Sand4, name, bool, bool, bool, int);            \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPO1(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1, name, int);                              \
  DEFINE_ENGINE_TEST_CLASS_SPO(Pebble1Sparse, name, int);                      \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1Level2, name, int);                        \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand2, name, int);                              \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand4, name, int);                              \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPO2(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1, name, int, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SPO(Pebble1Sparse, name, int, int);                 \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1Level2, name, int, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand2, name, int, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand4, name, int, int);                         \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPO3(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1, name, int, int, int);                    \
  DEFINE_ENGINE_TEST_CLASS_SPO(Pebble1Sparse, name, int, int, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1Level2, name, int, int, int);              \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand2, name, int, int, int);                    \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand4, name, int, int, int);                    \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPO23(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1, name, bool, bool,                        \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Pebble1Sparse, name, bool, bool,                \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1Level2, name, bool, bool,                  \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand2, name, bool, bool,                        \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand4, name, bool, bool,                        \
                               std::tuple<int, int, int>);                     \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPO33(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1, name, bool, bool, bool,                  \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Pebble1Sparse, name, bool, bool, bool,          \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand1Level2, name, bool, bool, bool,            \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand2, name, bool, bool, bool,                  \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPO(Sand4, name, bool, bool, bool,                  \
                               std::tuple<int, int, int>);                     \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPR2(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1, name, int, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SPR(Pebble1Sparse, name, int, int);                 \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1Level2, name, int, int);                   \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand2, name, int, int);                         \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand4, name, int, int);                         \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPR3(name, to_test_name, ...)                        \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1, name, int, int, int);                    \
  DEFINE_ENGINE_TEST_CLASS_SPR(Pebble1Sparse, name, int, int, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1Level2, name, int, int, int);              \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand2, name, int, int, int);                    \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand4, name, int, int, int);                    \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPR21(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPR(Pebble1Sparse, name, bool, bool, int);          \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1Level2, name, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand2, name, bool, bool, int);                  \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand4, name, bool, bool, int);                  \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPR31(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPR(Pebble1Sparse, name, bool, bool, bool, int);    \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1Level2, name, bool, bool, bool, int);      \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand2, name, bool, bool, bool, int);            \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand4, name, bool, bool, bool, int);            \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPR43(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1, name, bool, bool, bool, bool,            \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPR(Pebble1Sparse, name, bool, bool, bool, bool,    \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1Level2, name, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand2, name, bool, bool, bool, bool,            \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand4, name, bool, bool, bool, bool,            \
                               std::tuple<int, int, int>);                     \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define SETUP_ENGINE_TEST_SPR53(name, to_test_name, ...)                       \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1, name, bool, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPR(Pebble1Sparse, name, bool, bool, bool, bool,    \
                               bool, std::tuple<int, int, int>);               \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand1Level2, name, bool, bool, bool, bool,      \
                               bool, std::tuple<int, int, int>);               \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand2, name, bool, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  DEFINE_ENGINE_TEST_CLASS_SPR(Sand4, name, bool, bool, bool, bool, bool,      \
                               std::tuple<int, int, int>);                     \
  INSTANTIATE_ENGINE_TEST(Sand1, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Pebble1Sparse, name, to_test_name, __VA_ARGS__);     \
  INSTANTIATE_ENGINE_TEST(Sand1Level2, name, to_test_name, __VA_ARGS__);       \
  INSTANTIATE_ENGINE_TEST(Sand2, name, to_test_name, __VA_ARGS__);             \
  INSTANTIATE_ENGINE_TEST(Sand4, name, to_test_name, __VA_ARGS__);

#define DEFAULT_ENGINE_TEST(fixture_name, test_name, test_body)                \
  TEST_P(Sand1CKKSEngine##fixture_name, test_name)                             \
  test_body;                                                                   \
  TEST_P(Pebble1SparseCKKSEngine##fixture_name, test_name)                     \
  test_body;                                                                   \
  TEST_P(Sand1Level2CKKSEngine##fixture_name, test_name)                       \
  test_body;                                                                   \
  TEST_P(Sand2CKKSEngine##fixture_name, test_name)                             \
  test_body;                                                                   \
  TEST_P(Sand4CKKSEngine##fixture_name, test_name)                             \
  test_body;

#define ALL_ENGINE_TEST(fixture_name, test_name, test_body)                    \
  DEFAULT_ENGINE_TEST(fixture_name, test_name, test_body)
