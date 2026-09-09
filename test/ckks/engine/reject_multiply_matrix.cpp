#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectMultiplyMatrix : public testing::TestWithParam<int> {
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

    duo_intt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    polynomial_1_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 4);
    level_0_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2, 0);

    duo_intt_ciphertext_ =
        new desilo::fhe::Ciphertext({duo_intt_unit_ciphertext_});
    polynomial_1_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_1_unit_ciphertext_});
    polynomial_4_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_4_unit_ciphertext_});
    level_0_ciphertext_ =
        new desilo::fhe::Ciphertext({level_0_unit_ciphertext_});
    size_2_ciphertext_ = new desilo::fhe::Ciphertext(
        {get_dummy_unit_ciphertext(scheme_preset, log_slot_count,
                                   log_coeff_count, special_prime_count, 2),
         get_dummy_unit_ciphertext(scheme_preset, log_slot_count,
                                   log_coeff_count, special_prime_count, 2)});

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

    rotation_key_ = get_dummy_rotation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count);
    level_0_rotation_key_ = get_dummy_rotation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_rotation_keys_ = {
        get_dummy_rotation_key(bad_scheme_preset, log_slot_count,
                               log_coeff_count, special_prime_count),
        get_dummy_rotation_key(scheme_preset, bad_log_slot_count,
                               log_coeff_count, special_prime_count),
        get_dummy_rotation_key(scheme_preset, log_slot_count,
                               bad_log_coeff_count, special_prime_count),
        get_dummy_rotation_key(scheme_preset, log_slot_count, log_coeff_count,
                               bad_special_prime_count)};

    std::vector<desilo::fhe::Polynomial *> keys;
    int moduli_id = 0;
    int level = 7;
    int chain_count = 2;
    int coeff_count = 1 << log_coeff_count;
    int delta = 1;
  }

  static void TearDownTestSuite() {
    delete duo_intt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete level_0_ciphertext_;
    delete size_2_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
    delete rotation_key_;
    delete level_0_rotation_key_;
    for (auto rotation_key : incompatible_rotation_keys_) {
      delete rotation_key;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitCiphertext *duo_intt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *level_0_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *level_0_ciphertext_;
  static desilo::fhe::Ciphertext *size_2_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::RotationKey *rotation_key_;
  static desilo::fhe::RotationKey *level_0_rotation_key_;
  static std::vector<desilo::fhe::FixedRotationKey *>
      incompatible_fixed_rotation_keys_;
  static std::vector<desilo::fhe::RotationKey *> incompatible_rotation_keys_;
};

desilo::fhe::CKKSEngine *RejectMultiplyMatrix::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectMultiplyMatrix::duo_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext
    *RejectMultiplyMatrix::polynomial_1_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext
    *RejectMultiplyMatrix::polynomial_4_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectMultiplyMatrix::level_0_unit_ciphertext_ =
    nullptr;
desilo::fhe::Ciphertext *RejectMultiplyMatrix::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectMultiplyMatrix::polynomial_1_ciphertext_ =
    nullptr;
desilo::fhe::Ciphertext *RejectMultiplyMatrix::polynomial_4_ciphertext_ =
    nullptr;
desilo::fhe::Ciphertext *RejectMultiplyMatrix::level_0_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectMultiplyMatrix::size_2_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectMultiplyMatrix::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectMultiplyMatrix::incompatible_ciphertexts_;
std::vector<desilo::fhe::FixedRotationKey *>
    RejectMultiplyMatrix::incompatible_fixed_rotation_keys_;
desilo::fhe::RotationKey *RejectMultiplyMatrix::rotation_key_ = nullptr;
desilo::fhe::RotationKey *RejectMultiplyMatrix::level_0_rotation_key_ = nullptr;
std::vector<desilo::fhe::RotationKey *>
    RejectMultiplyMatrix::incompatible_rotation_keys_;

INSTANTIATE_TEST_CASE_P(, RejectMultiplyMatrix, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_DOUBLE(unit_ciphertext, rotation_key, error_message)         \
  double *matrix;                                                              \
  try {                                                                        \
    engine_->multiply_matrix(matrix, unit_ciphertext, rotation_key);           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Double Matrix And Unit Ciphertext: " error_message, \
                 e.what());                                                    \
  }                                                                            \
                                                                               \
  std::vector<double> matrix_vector;                                           \
  try {                                                                        \
    engine_->multiply_matrix(matrix_vector, unit_ciphertext, rotation_key);    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Multiply Double Matrix Vector And Unit Ciphertext: " error_message,   \
        e.what());                                                             \
  }

TEST_P(RejectMultiplyMatrix, UnitDouble_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_DOUBLE(
      incompatible_unit_ciphertext, rotation_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, UnitDouble_UnitCiphertextTooSmall) {
  TEST_UNIT_DOUBLE(polynomial_1_unit_ciphertext_, rotation_key_,
                   "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, UnitDouble_UnitCiphertextTooLarge) {
  TEST_UNIT_DOUBLE(polynomial_4_unit_ciphertext_, rotation_key_,
                   "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, UnitDouble_UnitCiphertextLevel0) {
  TEST_UNIT_DOUBLE(level_0_unit_ciphertext_, rotation_key_,
                   "the input unit ciphertext should have a positive level.");
}

TEST_P(RejectMultiplyMatrix, UnitDouble_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_UNIT_DOUBLE(
      duo_intt_unit_ciphertext_, incompatible_rotation_key,
      "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, UnitDouble_RotationKeyTooSmall) {
  TEST_UNIT_DOUBLE(
      duo_intt_unit_ciphertext_, level_0_rotation_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input rotation key.");
}

#define TEST_UNIT_COMPLEX(unit_ciphertext, rotation_key, error_message)        \
  std::complex<double> *matrix;                                                \
  try {                                                                        \
    engine_->multiply_matrix(matrix, unit_ciphertext, rotation_key);           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Multiply Complex Double Matrix And Unit Ciphertext: " error_message,  \
        e.what());                                                             \
  }                                                                            \
                                                                               \
  std::vector<std::complex<double>> matrix_vector;                             \
  try {                                                                        \
    engine_->multiply_matrix(matrix_vector, unit_ciphertext, rotation_key);    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Complex Double Matrix Vector And Unit "             \
                 "Ciphertext: " error_message,                                 \
                 e.what());                                                    \
  }

TEST_P(RejectMultiplyMatrix, UnitComplex_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_COMPLEX(
      incompatible_unit_ciphertext, rotation_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, UnitComplex_UnitCiphertextTooSmall) {
  TEST_UNIT_COMPLEX(polynomial_1_unit_ciphertext_, rotation_key_,
                    "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, UnitComplex_UnitCiphertextTooLarge) {
  TEST_UNIT_COMPLEX(polynomial_4_unit_ciphertext_, rotation_key_,
                    "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, UnitComplex_UnitCiphertextLevel0) {
  TEST_UNIT_COMPLEX(level_0_unit_ciphertext_, rotation_key_,
                    "the input unit ciphertext should have a positive level.");
}

TEST_P(RejectMultiplyMatrix, UnitComplex_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_UNIT_COMPLEX(
      duo_intt_unit_ciphertext_, incompatible_rotation_key,
      "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, UnitComplex_RotationKeyTooSmall) {
  TEST_UNIT_COMPLEX(
      duo_intt_unit_ciphertext_, level_0_rotation_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input rotation key.");
}

#define TEST_DOUBLE(ciphertext, rotation_key, error_message)                   \
  double *matrix;                                                              \
  try {                                                                        \
    engine_->multiply_matrix(matrix, ciphertext, rotation_key);                \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Double Matrix And Ciphertext: " error_message,      \
                 e.what());                                                    \
  }                                                                            \
                                                                               \
  std::vector<double> matrix_vector;                                           \
  try {                                                                        \
    engine_->multiply_matrix(matrix_vector, ciphertext, rotation_key);         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Multiply Double Matrix Vector And Ciphertext: " error_message,        \
        e.what());                                                             \
  }

TEST_P(RejectMultiplyMatrix, Double_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_DOUBLE(incompatible_ciphertext, rotation_key_,
              "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, Double_CiphertextTooSmall) {
  TEST_DOUBLE(polynomial_1_ciphertext_, rotation_key_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, Double_CiphertextTooLarge) {
  TEST_DOUBLE(polynomial_4_ciphertext_, rotation_key_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, Double_CiphertextLevel0) {
  TEST_DOUBLE(level_0_ciphertext_, rotation_key_,
              "the input ciphertext should have a positive level.");
}

TEST_P(RejectMultiplyMatrix, Double_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_DOUBLE(duo_intt_ciphertext_, incompatible_rotation_key,
              "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, Double_RotationKeyTooSmall) {
  TEST_DOUBLE(duo_intt_ciphertext_, level_0_rotation_key_,
              "the level of the input ciphertext is greater than that of the "
              "input rotation key.");
}

#define TEST_COMPLEX_DOUBLE(ciphertext, rotation_key, error_message)           \
  std::complex<double> *matrix;                                                \
  try {                                                                        \
    engine_->multiply_matrix(matrix, ciphertext, rotation_key);                \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Multiply Complex Double Matrix And Ciphertext: " error_message,       \
        e.what());                                                             \
  }                                                                            \
                                                                               \
  std::vector<std::complex<double>> matrix_vector;                             \
  try {                                                                        \
    engine_->multiply_matrix(matrix_vector, ciphertext, rotation_key);         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Complex Double Matrix Vector And "                  \
                 "Ciphertext: " error_message,                                 \
                 e.what());                                                    \
  }

TEST_P(RejectMultiplyMatrix, ComplexDouble_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_COMPLEX_DOUBLE(
      incompatible_ciphertext, rotation_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, ComplexDouble_CiphertextTooSmall) {
  TEST_COMPLEX_DOUBLE(polynomial_1_ciphertext_, rotation_key_,
                      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, ComplexDouble_CiphertextTooLarge) {
  TEST_COMPLEX_DOUBLE(polynomial_4_ciphertext_, rotation_key_,
                      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiplyMatrix, ComplexDouble_CiphertextLevel0) {
  TEST_COMPLEX_DOUBLE(level_0_ciphertext_, rotation_key_,
                      "the input ciphertext should have a positive level.");
}

TEST_P(RejectMultiplyMatrix, ComplexDouble_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_COMPLEX_DOUBLE(
      duo_intt_ciphertext_, incompatible_rotation_key,
      "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectMultiplyMatrix, ComplexDouble_RotationKeyTooSmall) {
  TEST_COMPLEX_DOUBLE(
      duo_intt_ciphertext_, level_0_rotation_key_,
      "the level of the input ciphertext is greater than that of the "
      "input rotation key.");
}
