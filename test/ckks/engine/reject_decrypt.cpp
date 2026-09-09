#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectDecrypt : public testing::TestWithParam<int> {
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

    duo_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    polynomial_1_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 4);
    level_0_rescaled_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::RESCALED, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2, 0);

    duo_ciphertext_ = new desilo::fhe::Ciphertext({duo_unit_ciphertext_});
    polynomial_1_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_1_unit_ciphertext_});
    polynomial_4_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_4_unit_ciphertext_});
    level_0_rescaled_ciphertext_ =
        new desilo::fhe::Ciphertext({level_0_rescaled_unit_ciphertext_});

    incompatible_unit_ciphertexts_ = {
        get_dummy_unit_ciphertext(bad_scheme_preset, log_slot_count,
                                  log_coeff_count, special_prime_count, 2),
        get_dummy_unit_ciphertext(scheme_preset, bad_log_slot_count,
                                  log_coeff_count, special_prime_count, 2),
        get_dummy_unit_ciphertext(scheme_preset, log_slot_count,
                                  bad_log_coeff_count, special_prime_count, 2),
        get_dummy_unit_ciphertext(scheme_preset, log_slot_count,
                                  log_coeff_count, bad_special_prime_count, 2)};
    incompatible_ciphertexts_ = {
        new desilo::fhe::Ciphertext({incompatible_unit_ciphertexts_[0]}),
        new desilo::fhe::Ciphertext({incompatible_unit_ciphertexts_[1]}),
        new desilo::fhe::Ciphertext({incompatible_unit_ciphertexts_[2]}),
        new desilo::fhe::Ciphertext({incompatible_unit_ciphertexts_[3]}),
    };

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
    delete duo_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete level_0_rescaled_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
    delete secret_key_;
    delete level_0_secret_key_;
    for (auto secret_key : incompatible_secret_keys_) {
      delete secret_key;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitCiphertext *duo_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *level_0_rescaled_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *level_0_rescaled_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::SecretKey *level_0_secret_key_;
  static std::vector<desilo::fhe::SecretKey *> incompatible_secret_keys_;
};

desilo::fhe::CKKSEngine *RejectDecrypt::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectDecrypt::duo_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectDecrypt::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectDecrypt::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectDecrypt::level_0_rescaled_unit_ciphertext_ =
    nullptr;
desilo::fhe::Ciphertext *RejectDecrypt::duo_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectDecrypt::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectDecrypt::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectDecrypt::level_0_rescaled_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectDecrypt::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *> RejectDecrypt::incompatible_ciphertexts_;
desilo::fhe::SecretKey *RejectDecrypt::secret_key_ = nullptr;
desilo::fhe::SecretKey *RejectDecrypt::level_0_secret_key_ = nullptr;
std::vector<desilo::fhe::SecretKey *> RejectDecrypt::incompatible_secret_keys_;

INSTANTIATE_TEST_CASE_P(, RejectDecrypt, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_DOUBLE(unit_ciphertext, secret_key, error_message)           \
  try {                                                                        \
    engine_->decrypt(unit_ciphertext, secret_key);                             \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Decrypt Unit Ciphertext To Double Vector: " error_message,   \
                 e.what());                                                    \
  }

TEST_P(RejectDecrypt, UnitDouble_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_DOUBLE(
      incompatible_unit_ciphertext, secret_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, UnitDouble_UnitCiphertextLevel0Rescaled) {
  TEST_UNIT_DOUBLE(
      level_0_rescaled_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, UnitDouble_UnitCiphertextTooSmall) {
  TEST_UNIT_DOUBLE(
      polynomial_1_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, UnitDouble_UnitCiphertextTooLarge) {
  TEST_UNIT_DOUBLE(
      polynomial_4_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, UnitDouble_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_UNIT_DOUBLE(duo_unit_ciphertext_, incompatible_secret_key,
                   "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, UnitDouble_SecretKeyTooSmall) {
  TEST_UNIT_DOUBLE(
      duo_unit_ciphertext_, level_0_secret_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input secret key.");
}

#define TEST_UNIT_COMPLEX(unit_ciphertext, secret_key, error_message)          \
  try {                                                                        \
    engine_->decrypt_complex(unit_ciphertext, secret_key);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Decrypt Unit Ciphertext To Complex Double Vector: " error_message,    \
        e.what());                                                             \
  }

TEST_P(RejectDecrypt, UnitComplex_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_COMPLEX(
      incompatible_unit_ciphertext, secret_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, UnitComplex_UnitCiphertextLevel0Rescaled) {
  TEST_UNIT_COMPLEX(
      level_0_rescaled_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, UnitComplex_UnitCiphertextTooSmall) {
  TEST_UNIT_COMPLEX(
      polynomial_1_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, UnitComplex_UnitCiphertextTooLarge) {
  TEST_UNIT_COMPLEX(
      polynomial_4_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, UnitComplex_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_UNIT_COMPLEX(duo_unit_ciphertext_, incompatible_secret_key,
                    "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, UnitComplex_SecretKeyTooSmall) {
  TEST_UNIT_COMPLEX(
      duo_unit_ciphertext_, level_0_secret_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input secret key.");
}

#define TEST_UNIT_PLAINTEXT(unit_ciphertext, secret_key, error_message)        \
  try {                                                                        \
    engine_->decrypt_to_unit_plaintext(unit_ciphertext, secret_key);           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Decrypt Unit Ciphertext To Unit Plaintext: " error_message,  \
                 e.what());                                                    \
  }

TEST_P(RejectDecrypt, UnitPlaintext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_PLAINTEXT(
      incompatible_unit_ciphertext, secret_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, UnitPlaintext_UnitCiphertextLevel0Rescaled) {
  TEST_UNIT_PLAINTEXT(
      level_0_rescaled_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, UnitPlaintext_UnitCiphertextTooSmall) {
  TEST_UNIT_PLAINTEXT(
      polynomial_1_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, UnitPlaintext_UnitCiphertextTooLarge) {
  TEST_UNIT_PLAINTEXT(
      polynomial_4_unit_ciphertext_, secret_key_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, UnitPlaintext_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_UNIT_PLAINTEXT(
      duo_unit_ciphertext_, incompatible_secret_key,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, UnitPlaintext_SecretKeyTooSmall) {
  TEST_UNIT_PLAINTEXT(
      duo_unit_ciphertext_, level_0_secret_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input secret key.");
}

#define TEST_DOUBLE(ciphertext, secret_key, error_message)                     \
  try {                                                                        \
    engine_->decrypt(ciphertext, secret_key);                                  \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Decrypt To Double Vector: " error_message, e.what());        \
  }

TEST_P(RejectDecrypt, Double_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_DOUBLE(incompatible_ciphertext, secret_key_,
              "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, Double_CiphertextLevel0Rescaled) {
  TEST_DOUBLE(level_0_rescaled_ciphertext_, secret_key_,
              "the input ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, Double_CiphertextTooSmall) {
  TEST_DOUBLE(polynomial_1_ciphertext_, secret_key_,
              "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, Double_CiphertextTooLarge) {
  TEST_DOUBLE(polynomial_4_ciphertext_, secret_key_,
              "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, Double_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_DOUBLE(duo_ciphertext_, incompatible_secret_key,
              "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, Double_SecretKeyTooSmall) {
  TEST_DOUBLE(duo_ciphertext_, level_0_secret_key_,
              "the level of the input ciphertext is greater than "
              "that of the input secret key.");
}

#define TEST_COMPLEX(ciphertext, secret_key, error_message)                    \
  try {                                                                        \
    engine_->decrypt_complex(ciphertext, secret_key);                          \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Decrypt To Complex Double Vector: " error_message,           \
                 e.what());                                                    \
  }

TEST_P(RejectDecrypt, Complex_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_COMPLEX(incompatible_ciphertext, secret_key_,
               "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, Complex_CiphertextLevel0Rescaled) {
  TEST_COMPLEX(level_0_rescaled_ciphertext_, secret_key_,
               "the input ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, Complex_CiphertextTooSmall) {
  TEST_COMPLEX(polynomial_1_ciphertext_, secret_key_,
               "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, Complex_CiphertextTooLarge) {
  TEST_COMPLEX(polynomial_4_ciphertext_, secret_key_,
               "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, Complex_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_COMPLEX(duo_ciphertext_, incompatible_secret_key,
               "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, Complex_SecretKeyTooSmall) {
  TEST_COMPLEX(duo_ciphertext_, level_0_secret_key_,
               "the level of the input ciphertext is greater than "
               "that of the input secret key.");
}

#define TEST_TO_DOUBLE_BUFFER(ciphertext, secret_key, error_message)           \
  try {                                                                        \
    double *output;                                                            \
    engine_->decrypt_to_buffer(ciphertext, output, secret_key);                \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Decrypt To Double Buffer: " error_message, e.what());        \
  }

TEST_P(RejectDecrypt, DoubleBuffer_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_TO_DOUBLE_BUFFER(
      incompatible_ciphertext, secret_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, DoubleBuffer_CiphertextLevel0Rescaled) {
  TEST_TO_DOUBLE_BUFFER(
      level_0_rescaled_ciphertext_, secret_key_,
      "the input ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, DoubleBuffer_CiphertextTooSmall) {
  TEST_TO_DOUBLE_BUFFER(
      polynomial_1_ciphertext_, secret_key_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, DoubleBuffer_CiphertextTooLarge) {
  TEST_TO_DOUBLE_BUFFER(
      polynomial_4_ciphertext_, secret_key_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, DoubleBuffer_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_TO_DOUBLE_BUFFER(
      duo_ciphertext_, incompatible_secret_key,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, DoubleBuffer_SecretKeyTooSmall) {
  TEST_TO_DOUBLE_BUFFER(duo_ciphertext_, level_0_secret_key_,
                        "the level of the input ciphertext is greater than "
                        "that of the input secret key.");
}

#define TEST_TO_COMPLEX_BUFFER(ciphertext, secret_key, error_message)          \
  try {                                                                        \
    std::complex<double> *output;                                              \
    engine_->decrypt_to_complex_buffer(ciphertext, output, secret_key);        \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Decrypt To Complex Double Buffer: " error_message,           \
                 e.what());                                                    \
  }

TEST_P(RejectDecrypt, ComplexBuffer_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_TO_COMPLEX_BUFFER(
      incompatible_ciphertext, secret_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, ComplexBuffer_CiphertextLevel0Rescaled) {
  TEST_TO_COMPLEX_BUFFER(
      level_0_rescaled_ciphertext_, secret_key_,
      "the input ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, ComplexBuffer_CiphertextTooSmall) {
  TEST_TO_COMPLEX_BUFFER(
      polynomial_1_ciphertext_, secret_key_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, ComplexBuffer_CiphertextTooLarge) {
  TEST_TO_COMPLEX_BUFFER(
      polynomial_4_ciphertext_, secret_key_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, ComplexBuffer_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_TO_COMPLEX_BUFFER(
      duo_ciphertext_, incompatible_secret_key,
      "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, ComplexBuffer_SecretKeyTooSmall) {
  TEST_TO_COMPLEX_BUFFER(duo_ciphertext_, level_0_secret_key_,
                         "the level of the input ciphertext is greater than "
                         "that of the input secret key.");
}

#define TEST_PLAINTEXT(ciphertext, secret_key, error_message)                  \
  try {                                                                        \
    engine_->decrypt_to_plaintext(ciphertext, secret_key);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Decrypt To Plaintext: " error_message, e.what());            \
  }

TEST_P(RejectDecrypt, Plaintext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_PLAINTEXT(incompatible_ciphertext, secret_key_,
                 "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectDecrypt, Plaintext_CiphertextLevel0Rescaled) {
  TEST_PLAINTEXT(level_0_rescaled_ciphertext_, secret_key_,
                 "the input ciphertext should not be rescaled at level 0.");
}

TEST_F(RejectDecrypt, Plaintext_CiphertextTooSmall) {
  TEST_PLAINTEXT(polynomial_1_ciphertext_, secret_key_,
                 "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectDecrypt, Plaintext_CiphertextTooLarge) {
  TEST_PLAINTEXT(polynomial_4_ciphertext_, secret_key_,
                 "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectDecrypt, Plaintext_SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];

  TEST_PLAINTEXT(duo_ciphertext_, incompatible_secret_key,
                 "the input secret key is not compatible with this engine.");
}

TEST_F(RejectDecrypt, Plaintext_SecretKeyTooSmall) {
  TEST_PLAINTEXT(duo_ciphertext_, level_0_secret_key_,
                 "the level of the input ciphertext is greater than that "
                 "of the input secret key.");
}
