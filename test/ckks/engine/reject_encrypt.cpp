#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectEncrypt : public testing::TestWithParam<int> {
public:
  static void SetUpTestSuite() {
    engine_ = new desilo::fhe::CKKSEngine();

    const auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
    const auto log_slot_count = 13;
    const auto log_coeff_count = 14;
    const auto special_prime_count = 1;

    const auto bad_scheme_preset = desilo::fhe::SchemePreset::NONE;
    const auto bad_log_slot_count = 12;
    const auto bad_log_coeff_count = 13;
    const auto bad_special_prime_count = 2;

    unit_plaintext_ = get_dummy_flagged_unit_plaintext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count);
    rescaled_unit_plaintext_ = get_dummy_flagged_unit_plaintext(
        desilo::fhe::DataFlag::RESCALED, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count);

    plaintext_ = new desilo::fhe::Plaintext({unit_plaintext_});
    rescaled_plaintext_ =
        new desilo::fhe::Plaintext({rescaled_unit_plaintext_});

    incompatible_unit_plaintexts_ = {
        get_dummy_unit_plaintext(bad_scheme_preset, log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, bad_log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count,
                                 bad_log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count, log_coeff_count,
                                 bad_special_prime_count)};
    incompatible_plaintexts_ = {
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[0]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[1]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[2]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[3]}),
    };

    public_key_ = get_dummy_public_key(scheme_preset, log_slot_count,
                                       log_coeff_count, special_prime_count);
    level_0_public_key_ = get_dummy_public_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_public_keys_ = {
        get_dummy_public_key(bad_scheme_preset, log_slot_count, log_coeff_count,
                             special_prime_count),
        get_dummy_public_key(scheme_preset, bad_log_slot_count, log_coeff_count,
                             special_prime_count),
        get_dummy_public_key(scheme_preset, log_slot_count, bad_log_coeff_count,
                             special_prime_count),
        get_dummy_public_key(scheme_preset, log_slot_count, log_coeff_count,
                             bad_special_prime_count)};

    secret_key_ = get_dummy_secret_key(scheme_preset, log_slot_count,
                                       log_coeff_count, special_prime_count);
    level_0_secret_key_ = get_dummy_secret_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_secret_keys_ = {
        get_dummy_secret_key(bad_scheme_preset, log_slot_count, log_coeff_count,
                             special_prime_count),
        get_dummy_secret_key(scheme_preset, bad_log_slot_count, log_coeff_count,
                             special_prime_count),
        get_dummy_secret_key(scheme_preset, log_slot_count, bad_log_coeff_count,
                             special_prime_count),
        get_dummy_secret_key(scheme_preset, log_slot_count, log_coeff_count,
                             bad_special_prime_count)};
  }

  static void TearDownTestSuite() {
    delete engine_;
    delete plaintext_;
    delete rescaled_plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    delete public_key_;
    delete level_0_public_key_;
    for (auto public_key : incompatible_public_keys_) {
      delete public_key;
    }
    delete secret_key_;
    delete level_0_secret_key_;
    for (auto secret_key : incompatible_secret_keys_) {
      delete secret_key;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitPlaintext *unit_plaintext_;
  static desilo::fhe::UnitPlaintext *rescaled_unit_plaintext_;
  static desilo::fhe::Plaintext *plaintext_;
  static desilo::fhe::Plaintext *rescaled_plaintext_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
  static desilo::fhe::PublicKey *public_key_;
  static desilo::fhe::PublicKey *level_0_public_key_;
  static std::vector<desilo::fhe::PublicKey *> incompatible_public_keys_;
  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::SecretKey *level_0_secret_key_;
  static std::vector<desilo::fhe::SecretKey *> incompatible_secret_keys_;
};

desilo::fhe::CKKSEngine *RejectEncrypt::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectEncrypt::unit_plaintext_ = nullptr;
desilo::fhe::UnitPlaintext *RejectEncrypt::rescaled_unit_plaintext_ = nullptr;
desilo::fhe::Plaintext *RejectEncrypt::plaintext_ = nullptr;
desilo::fhe::Plaintext *RejectEncrypt::rescaled_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectEncrypt::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectEncrypt::incompatible_plaintexts_;
desilo::fhe::PublicKey *RejectEncrypt::public_key_ = nullptr;
desilo::fhe::PublicKey *RejectEncrypt::level_0_public_key_ = nullptr;
std::vector<desilo::fhe::PublicKey *> RejectEncrypt::incompatible_public_keys_;
desilo::fhe::SecretKey *RejectEncrypt::secret_key_ = nullptr;
desilo::fhe::SecretKey *RejectEncrypt::level_0_secret_key_ = nullptr;
std::vector<desilo::fhe::SecretKey *> RejectEncrypt::incompatible_secret_keys_;

INSTANTIATE_TEST_CASE_P(, RejectEncrypt, testing::Values(0, 1, 2, 3));

TEST_P(RejectEncrypt, UnitDouble_PublicKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  try {
    engine_->encrypt_unit(message, incompatible_public_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Encode Double Vector To Unit Ciphertext: the input public key is not "
        "compatible with this engine.",
        e.what());
  }
}

TEST_F(RejectEncrypt, UnitDouble_PublicKeyTooSmall) {
  std::vector<double> message;

  try {
    engine_->encrypt_unit(message, level_0_public_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Double Vector To Unit Ciphertext: the target level "
                 "cannot be reached with the provided keys.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, UnitDouble_MessageTooLong) {
  std::vector<double> message(engine_->get_slot_count() + 1);

  try {
    engine_->encrypt_unit(message, public_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Double Vector To Unit Ciphertext: the given input is "
                 "too long to be processed.",
                 e.what());
  }
}

#define TEST_UNIT_DOUBLE_WITH_LEVEL(message, public_key, level, error_message) \
  try {                                                                        \
    engine_->encrypt_unit(message, public_key, level);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Double Vector To Unit Ciphertext: " error_message,    \
                 e.what());                                                    \
  }

TEST_P(RejectEncrypt, UnitDoubleWithLevel_PublicKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];
  const int level = 0;

  TEST_UNIT_DOUBLE_WITH_LEVEL(
      message, incompatible_public_key, level,
      "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitDoubleWithLevel_MessageTooLong) {
  std::vector<double> message(engine_->get_slot_count() + 1);
  const int level = 0;

  TEST_UNIT_DOUBLE_WITH_LEVEL(message, public_key_, level,
                              "the given input is too long to be processed.");
}

TEST_F(RejectEncrypt, UnitDoubleWithLevel_LevelTooSmall) {
  std::vector<double> message;
  const int level = -1;

  TEST_UNIT_DOUBLE_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, UnitDoubleWithLevel_LevelTooLarge) {
  std::vector<double> message;
  const int level = engine_->get_max_level() + 1;

  TEST_UNIT_DOUBLE_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, UnitComplex_PublicKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  try {
    engine_->encrypt_unit(message, incompatible_public_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Complex Double Vector To Unit Ciphertext: the input "
                 "public key is not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, UnitComplex_PublicKeyTooSmall) {
  std::vector<std::complex<double>> message;

  try {
    engine_->encrypt_unit(message, level_0_public_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Complex Double Vector To Unit Ciphertext: the target "
                 "level cannot be reached with the provided keys.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, UnitComplex_MessageTooLong) {
  std::vector<std::complex<double>> message(engine_->get_slot_count() + 1);

  try {
    engine_->encrypt_unit(message, public_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Complex Double Vector To Unit Ciphertext: the given "
                 "input is too long to be processed.",
                 e.what());
  }
}

#define TEST_UNIT_COMPLEX_WITH_LEVEL(message, public_key, level,               \
                                     error_message)                            \
  try {                                                                        \
    engine_->encrypt_unit(message, public_key, level);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Encode Complex Double Vector To Unit Ciphertext: " error_message,     \
        e.what());                                                             \
  }

TEST_P(RejectEncrypt, UnitComplexWithLevel_PublicKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];
  const int level = 0;

  TEST_UNIT_COMPLEX_WITH_LEVEL(
      message, incompatible_public_key, level,
      "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitComplexWithLevel_MessageTooLong) {
  std::vector<std::complex<double>> message(engine_->get_slot_count() + 1);
  const int level = 0;

  TEST_UNIT_COMPLEX_WITH_LEVEL(message, public_key_, level,
                               "the given input is too long to be processed.");
}

TEST_F(RejectEncrypt, UnitComplexWithLevel_LevelTooSmall) {
  std::vector<std::complex<double>> message;
  const int level = -1;

  TEST_UNIT_COMPLEX_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, UnitComplexWithLevel_LevelTooLarge) {
  std::vector<std::complex<double>> message;
  const int level = engine_->get_max_level() + 1;

  TEST_UNIT_COMPLEX_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_UNIT_PLAINTEXT(unit_plaintext, public_key, error_message)         \
  try {                                                                        \
    engine_->encrypt_unit(unit_plaintext, public_key);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Unit Plaintext: " error_message, e.what());          \
  }

TEST_P(RejectEncrypt, UnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  TEST_UNIT_PLAINTEXT(
      incompatible_unit_plaintext, public_key_,
      "the input unit plaintext is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitPlaintext_UnitPlaintextRescaled) {
  TEST_UNIT_PLAINTEXT(rescaled_unit_plaintext_, public_key_,
                      "the input unit plaintext should not be rescaled.");
}

TEST_P(RejectEncrypt, UnitPlaintext_PublicKeyNotCompatible) {
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  TEST_UNIT_PLAINTEXT(
      unit_plaintext_, incompatible_public_key,
      "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitPlaintext_PublicKeyTooSmall) {
  TEST_UNIT_PLAINTEXT(
      unit_plaintext_, level_0_public_key_,
      "the level of the input unit plaintext is greater than that of the "
      "input public key.");
}

TEST_P(RejectEncrypt, Double_PublicKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_public_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Double Vector: the input public key is not "
                 "compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, Double_PublicKeyTooSmall) {
  std::vector<double> message;

  try {
    engine_->encrypt(message, level_0_public_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Double Vector: the target level cannot be reached "
                 "with the provided keys.",
                 e.what());
  }
}

#define TEST_DOUBLE_WITH_LEVEL(message, public_key, level, error_message)      \
  try {                                                                        \
    engine_->encrypt(message, public_key, level);                              \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Double Vector: " error_message, e.what());           \
  }

TEST_P(RejectEncrypt, DoubleWithLevel_PublicKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];
  const int level = 0;

  TEST_DOUBLE_WITH_LEVEL(
      message, incompatible_public_key, level,
      "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, DoubleWithLevel_LevelTooSmall) {
  std::vector<double> message;
  const int level = -1;

  TEST_DOUBLE_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, DoubleWithLevel_LevelTooLarge) {
  std::vector<double> message;
  const int level = engine_->get_max_level() + 1;

  TEST_DOUBLE_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, Complex_PublicKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_public_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Vector: the input public key is "
                 "not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, Complex_PublicKeyTooSmall) {
  std::vector<std::complex<double>> message;

  try {
    engine_->encrypt(message, level_0_public_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Vector: the target level cannot "
                 "be reached with the provided keys.",
                 e.what());
  }
}

#define TEST_COMPLEX_WITH_LEVEL(message, public_key, level, error_message)     \
  try {                                                                        \
    engine_->encrypt(message, public_key, level);                              \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Complex Double Vector: " error_message, e.what());   \
  }

TEST_P(RejectEncrypt, ComplexWithLevel_PublicKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];
  const int level = 0;

  TEST_COMPLEX_WITH_LEVEL(
      message, incompatible_public_key, level,
      "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, ComplexWithLevel_LevelTooSmall) {
  std::vector<std::complex<double>> message;
  const int level = -1;

  TEST_COMPLEX_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, CompelxWithLevel_LevelTooLarge) {
  std::vector<std::complex<double>> message;
  const int level = engine_->get_max_level() + 1;

  TEST_COMPLEX_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, DoubleBuffer_PublicKeyNotCompatible) {
  double *message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_public_key,
                     engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Double Buffer: the input public key is not "
                 "compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, DoubleBuffer_PublicKeyTooSmall) {
  double *message;

  try {
    engine_->encrypt(message, level_0_public_key_, engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Double Buffer: the target level cannot be reached "
                 "with the provided keys.",
                 e.what());
  }
}

#define TEST_DOUBLE_BUFFER_WITH_LEVEL(message, public_key, level,              \
                                      error_message)                           \
  try {                                                                        \
    engine_->encrypt(message, public_key, engine_->get_slot_count(), level);   \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Double Buffer: " error_message, e.what());           \
  }

TEST_P(RejectEncrypt, DoubleBufferWithLevel_PublicKeyNotCompatible) {
  double *message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];
  const int level = 0;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, incompatible_public_key, level,
      "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, DoubleBufferWithLevel_LevelTooSmall) {
  double *message;
  const int level = -1;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, DoubleBufferWithLevel_LevelTooLarge) {
  double *message;
  const int level = engine_->get_max_level() + 1;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, ComplexBuffer_PublicKeyNotCompatible) {
  std::complex<double> *message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_public_key,
                     engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Buffer: the input public key is "
                 "not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, ComplexBuffer_PublicKeyTooSmall) {
  std::complex<double> *message;

  try {
    engine_->encrypt(message, level_0_public_key_, engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Buffer: the target level cannot "
                 "be reached with the provided keys.",
                 e.what());
  }
}

#define TEST_COMPLEX_BUFFER_WITH_LEVEL(message, public_key, level,             \
                                       error_message)                          \
  try {                                                                        \
    engine_->encrypt(message, public_key, engine_->get_slot_count(), level);   \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Complex Double Buffer: " error_message, e.what());   \
  }

TEST_P(RejectEncrypt, ComplexBufferWithLevel_PublicKeyNotCompatible) {
  std::complex<double> *message;
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];
  const int level = 0;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, incompatible_public_key, level,
      "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, ComplexBufferWithLevel_LevelTooSmall) {
  std::complex<double> *message;
  const int level = -1;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, CompelxBufferWithLevel_LevelTooLarge) {
  std::complex<double> *message;
  const int level = engine_->get_max_level() + 1;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, public_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, DoubleBufferSecretKey_SecretKeyNotCompatible) {
  double *message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_secret_key,
                     engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Encrypt Double Buffer With Secret Key: the input secret key is not "
        "compatible with this engine.",
        e.what());
  }
}

TEST_F(RejectEncrypt, DoubleBufferSecretKey_SecretKeyTooSmall) {
  double *message;

  try {
    engine_->encrypt(message, level_0_secret_key_, engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Encrypt Double Buffer With Secret Key: the target level cannot "
        "be reached with the provided keys.",
        e.what());
  }
}

#define TEST_DOUBLE_BUFFER_SECRET_KEY_WITH_LEVEL(message, secret_key, level,   \
                                                 error_message)                \
  try {                                                                        \
    engine_->encrypt(message, secret_key, engine_->get_slot_count(), level);   \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Double Buffer With Secret Key: " error_message,      \
                 e.what());                                                    \
  }

TEST_P(RejectEncrypt, DoubleBufferSecretKeyWithLevel_SecretKeyNotCompatible) {
  double *message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  const int level = 0;

  TEST_DOUBLE_BUFFER_SECRET_KEY_WITH_LEVEL(
      message, incompatible_secret_key, level,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, DoubleBufferSecretKeyWithLevel_LevelTooSmall) {
  double *message;
  const int level = -1;

  TEST_DOUBLE_BUFFER_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, DoubleBufferSecretKeyWithLevel_LevelTooLarge) {
  double *message;
  const int level = engine_->get_max_level() + 1;

  TEST_DOUBLE_BUFFER_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, ComplexBufferSecretKey_SecretKeyNotCompatible) {
  std::complex<double> *message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_secret_key,
                     engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Buffer With Secret Key: the input "
                 "secret key is not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, ComplexBufferSecretKey_SecretKeyTooSmall) {
  std::complex<double> *message;

  try {
    engine_->encrypt(message, level_0_secret_key_, engine_->get_slot_count());
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Buffer With Secret Key: the target "
                 "level cannot be reached with the provided keys.",
                 e.what());
  }
}

#define TEST_COMPLEX_BUFFER_SECRET_KEY_WITH_LEVEL(message, secret_key, level,  \
                                                  error_message)               \
  try {                                                                        \
    engine_->encrypt(message, secret_key, engine_->get_slot_count(), level);   \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Encrypt Complex Double Buffer With Secret Key: " error_message,       \
        e.what());                                                             \
  }

TEST_P(RejectEncrypt, ComplexBufferSecretKeyWithLevel_SecretKeyNotCompatible) {
  std::complex<double> *message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  const int level = 0;

  TEST_COMPLEX_BUFFER_SECRET_KEY_WITH_LEVEL(
      message, incompatible_secret_key, level,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, ComplexBufferSecretKeyWithLevel_LevelTooSmall) {
  std::complex<double> *message;
  const int level = -1;

  TEST_COMPLEX_BUFFER_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, ComplexBufferSecretKeyWithLevel_LevelTooLarge) {
  std::complex<double> *message;
  const int level = engine_->get_max_level() + 1;

  TEST_COMPLEX_BUFFER_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_PLAINTEXT(plaintext, public_key, error_message)                   \
  try {                                                                        \
    engine_->encrypt(plaintext, public_key);                                   \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Plaintext: " error_message, e.what());               \
  }

TEST_P(RejectEncrypt, Plaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  TEST_PLAINTEXT(incompatible_plaintext, public_key_,
                 "the input plaintext is not compatible with this engine.");
}

TEST_F(RejectEncrypt, Plaintext_PlaintextRescaled) {
  TEST_PLAINTEXT(rescaled_plaintext_, public_key_,
                 "the input plaintext should not be rescaled.");
}

TEST_P(RejectEncrypt, Plaintext_PublicKeyNotCompatible) {
  auto incompatible_public_key = incompatible_public_keys_[GetParam()];

  TEST_PLAINTEXT(plaintext_, incompatible_public_key,
                 "the input public key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, Plaintext_PublicKeyTooSmall) {
  TEST_PLAINTEXT(plaintext_, level_0_public_key_,
                 "the level of the input plaintext is greater than "
                 "that of the input public key.");
}

TEST_P(RejectEncrypt, UnitDoubleSecretKey_SecretKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  try {
    engine_->encrypt_unit(message, incompatible_secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Double Vector To Unit Ciphertext With Secret Key: the "
                 "input secret key is not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, UnitDoubleSecretKey_SecretKeyTooSmall) {
  std::vector<double> message;

  try {
    engine_->encrypt_unit(message, level_0_secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Double Vector To Unit Ciphertext With Secret Key: the "
                 "target level cannot be reached with the provided keys.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, UnitDoubleSecretKey_MessageTooLong) {
  std::vector<double> message(engine_->get_slot_count() + 1);

  try {
    engine_->encrypt_unit(message, secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Double Vector To Unit Ciphertext With Secret Key: the "
                 "given input is too long to be processed.",
                 e.what());
  }
}

#define TEST_UNIT_DOUBLE_SECRET_KEY_WITH_LEVEL(message, secret_key, level,     \
                                               error_message)                  \
  try {                                                                        \
    engine_->encrypt_unit(message, secret_key, level);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Double Vector To Unit Ciphertext With Secret "        \
                 "Key: " error_message,                                        \
                 e.what());                                                    \
  }

TEST_P(RejectEncrypt, UnitDoubleSecretKeyWithLevel_SecretKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  const int level = 0;

  TEST_UNIT_DOUBLE_SECRET_KEY_WITH_LEVEL(
      message, incompatible_secret_key, level,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitDoubleSecretKeyWithLevel_MessageTooLong) {
  std::vector<double> message(engine_->get_slot_count() + 1);
  const int level = 0;

  TEST_UNIT_DOUBLE_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the given input is too long to be processed.");
}

TEST_F(RejectEncrypt, UnitDoubleSecretKeyWithLevel_LevelTooSmall) {
  std::vector<double> message;
  const int level = -1;

  TEST_UNIT_DOUBLE_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, UnitDoubleSecretKeyWithLevel_LevelTooLarge) {
  std::vector<double> message;
  const int level = engine_->get_max_level() + 1;

  TEST_UNIT_DOUBLE_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, UnitComplexSecretKey_SecretKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  try {
    engine_->encrypt_unit(message, incompatible_secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Encode Complex Double Vector To Unit Ciphertext With Secret "
        "Key: the input secret key is not compatible with this engine.",
        e.what());
  }
}

TEST_F(RejectEncrypt, UnitComplexSecretKey_SecretKeyTooSmall) {
  std::vector<std::complex<double>> message;

  try {
    engine_->encrypt_unit(message, level_0_secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Encode Complex Double Vector To Unit Ciphertext With Secret "
        "Key: the target level cannot be reached with the provided keys.",
        e.what());
  }
}

TEST_F(RejectEncrypt, UnitComplexSecretKey_MessageTooLong) {
  std::vector<std::complex<double>> message(engine_->get_slot_count() + 1);

  try {
    engine_->encrypt_unit(message, secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Complex Double Vector To Unit Ciphertext With Secret "
                 "Key: the given input is too long to be processed.",
                 e.what());
  }
}

#define TEST_UNIT_COMPLEX_SECRET_KEY_WITH_LEVEL(message, secret_key, level,    \
                                                error_message)                 \
  try {                                                                        \
    engine_->encrypt_unit(message, secret_key, level);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Encode Complex Double Vector To Unit Ciphertext With Secret "         \
        "Key: " error_message,                                                 \
        e.what());                                                             \
  }

TEST_P(RejectEncrypt, UnitComplexSecretKeyWithLevel_SecretKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  const int level = 0;

  TEST_UNIT_COMPLEX_SECRET_KEY_WITH_LEVEL(
      message, incompatible_secret_key, level,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitComplexSecretKeyWithLevel_MessageTooLong) {
  std::vector<std::complex<double>> message(engine_->get_slot_count() + 1);
  const int level = 0;

  TEST_UNIT_COMPLEX_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the given input is too long to be processed.");
}

TEST_F(RejectEncrypt, UnitComplexSecretKeyWithLevel_LevelTooSmall) {
  std::vector<std::complex<double>> message;
  const int level = -1;

  TEST_UNIT_COMPLEX_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, UnitComplexSecretKeyWithLevel_LevelTooLarge) {
  std::vector<std::complex<double>> message;
  const int level = engine_->get_max_level() + 1;

  TEST_UNIT_COMPLEX_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_UNIT_PLAINTEXT_SECRET_KEY(unit_plaintext, secret_key,             \
                                       error_message)                          \
  try {                                                                        \
    engine_->encrypt_unit(unit_plaintext, secret_key);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Unit Plaintext With Secret Key: " error_message,     \
                 e.what());                                                    \
  }

TEST_P(RejectEncrypt, UnitPlaintextWithSecretKey_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  TEST_UNIT_PLAINTEXT_SECRET_KEY(
      incompatible_unit_plaintext, secret_key_,
      "the input unit plaintext is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitPlaintextWithSecretKey_UnitPlaintextRescaled) {
  TEST_UNIT_PLAINTEXT_SECRET_KEY(
      rescaled_unit_plaintext_, secret_key_,
      "the input unit plaintext should not be rescaled.");
}

TEST_P(RejectEncrypt, UnitPlaintextWithSecretKey_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_UNIT_PLAINTEXT_SECRET_KEY(
      unit_plaintext_, incompatible_secret_key,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, UnitPlaintextWithSecretKey_SecretKeyTooSmall) {
  TEST_UNIT_PLAINTEXT_SECRET_KEY(
      unit_plaintext_, level_0_secret_key_,
      "the level of the input unit plaintext is greater than that of the "
      "input secret key.");
}

TEST_P(RejectEncrypt, DoubleSecretKey_SecretKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Encrypt Double Vector With Secret Key: the input secret key is not "
        "compatible with this engine.",
        e.what());
  }
}

TEST_F(RejectEncrypt, DoubleSecretKey_SecretKeyTooSmall) {
  std::vector<double> message;

  try {
    engine_->encrypt(message, level_0_secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Encrypt Double Vector With Secret Key: the target level cannot "
        "be reached with the provided keys.",
        e.what());
  }
}

#define TEST_DOUBLE_SECRET_KEY_WITH_LEVEL(message, secret_key, level,          \
                                          error_message)                       \
  try {                                                                        \
    engine_->encrypt(message, secret_key, level);                              \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Double Vector With Secret Key: " error_message,      \
                 e.what());                                                    \
  }

TEST_P(RejectEncrypt, DoubleSecretKeyWithLevel_SecretKeyNotCompatible) {
  std::vector<double> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  const int level = 0;

  TEST_DOUBLE_SECRET_KEY_WITH_LEVEL(
      message, incompatible_secret_key, level,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, DoubleSecretKeyWithLevel_LevelTooSmall) {
  std::vector<double> message;
  const int level = -1;

  TEST_DOUBLE_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, DoubleSecretKeyWithLevel_LevelTooLarge) {
  std::vector<double> message;
  const int level = engine_->get_max_level() + 1;

  TEST_DOUBLE_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_P(RejectEncrypt, ComplexSecretKey_SecretKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  try {
    engine_->encrypt(message, incompatible_secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Vector With Secret Key: the input "
                 "secret key is "
                 "not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectEncrypt, ComplexSecretKey_SecretKeyTooSmall) {
  std::vector<std::complex<double>> message;

  try {
    engine_->encrypt(message, level_0_secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encrypt Complex Double Vector With Secret Key: the target "
                 "level cannot "
                 "be reached with the provided keys.",
                 e.what());
  }
}

#define TEST_COMPLEX_SECRET_KEY_WITH_LEVEL(message, secret_key, level,         \
                                           error_message)                      \
  try {                                                                        \
    engine_->encrypt(message, secret_key, level);                              \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Encrypt Complex Double Vector With Secret Key: " error_message,       \
        e.what());                                                             \
  }

TEST_P(RejectEncrypt, ComplexSecretKeyWithLevel_SecretKeyNotCompatible) {
  std::vector<std::complex<double>> message;
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  const int level = 0;

  TEST_COMPLEX_SECRET_KEY_WITH_LEVEL(
      message, incompatible_secret_key, level,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, ComplexSecretKeyWithLevel_LevelTooSmall) {
  std::vector<std::complex<double>> message;
  const int level = -1;

  TEST_COMPLEX_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncrypt, ComplexSecretKeyWithLevel_LevelTooLarge) {
  std::vector<std::complex<double>> message;
  const int level = engine_->get_max_level() + 1;

  TEST_COMPLEX_SECRET_KEY_WITH_LEVEL(
      message, secret_key_, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_PLAINTEXT_SECRET_KEY(plaintext, secret_key, error_message)        \
  try {                                                                        \
    engine_->encrypt(plaintext, secret_key);                                   \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encrypt Plaintext With Secret Key: " error_message,          \
                 e.what());                                                    \
  }

TEST_P(RejectEncrypt, PlaintextWithSecretKey_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  TEST_PLAINTEXT_SECRET_KEY(
      incompatible_plaintext, secret_key_,
      "the input plaintext is not compatible with this engine.");
}

TEST_F(RejectEncrypt, PlaintextWithSecretKey_PlaintextRescaled) {
  TEST_PLAINTEXT_SECRET_KEY(rescaled_plaintext_, secret_key_,
                            "the input plaintext should not be rescaled.");
}

TEST_P(RejectEncrypt, PlaintextWithSecretKey_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_PLAINTEXT_SECRET_KEY(
      plaintext_, incompatible_secret_key,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectEncrypt, PlaintextWithSecretKey_SecretKeyTooSmall) {
  TEST_PLAINTEXT_SECRET_KEY(
      plaintext_, level_0_secret_key_,
      "the level of the input plaintext is greater than that of the "
      "input secret key.");
}
