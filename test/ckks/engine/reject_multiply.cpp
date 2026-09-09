#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectMultiply : public testing::TestWithParam<int> {
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
    level_0_unit_plaintext_ = get_dummy_flagged_unit_plaintext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 0);
    incompatible_unit_plaintexts_ = {
        get_dummy_unit_plaintext(bad_scheme_preset, log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, bad_log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count,
                                 bad_log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count, log_coeff_count,
                                 bad_special_prime_count)};

    plaintext_ = new desilo::fhe::Plaintext({unit_plaintext_});
    level_0_plaintext_ = new desilo::fhe::Plaintext({level_0_unit_plaintext_});
    incompatible_plaintexts_ = {
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[0]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[1]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[2]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[3]}),
    };

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

    relinearization_key_ = get_dummy_relinearization_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count);
    level_0_relinearization_key_ = get_dummy_relinearization_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_relinearization_keys_ = {
        get_dummy_relinearization_key(bad_scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count),
        get_dummy_relinearization_key(scheme_preset, bad_log_slot_count,
                                      log_coeff_count, special_prime_count),
        get_dummy_relinearization_key(scheme_preset, log_slot_count,
                                      bad_log_coeff_count, special_prime_count),
        get_dummy_relinearization_key(scheme_preset, log_slot_count,
                                      log_coeff_count,
                                      bad_special_prime_count)};

    std::vector<desilo::fhe::Polynomial *> keys;
    int moduli_id = 0;
    int level = 7;
    int chain_count = 2;
    int coeff_count = 1 << log_coeff_count;
  }

  static void TearDownTestSuite() {
    delete plaintext_;
    delete level_0_plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    delete duo_intt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete level_0_ciphertext_;
    delete size_2_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
    delete relinearization_key_;
    delete level_0_relinearization_key_;
    for (auto relinearization_key : incompatible_relinearization_keys_) {
      delete relinearization_key;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitPlaintext *unit_plaintext_;
  static desilo::fhe::UnitPlaintext *level_0_unit_plaintext_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static desilo::fhe::Plaintext *plaintext_;
  static desilo::fhe::Plaintext *level_0_plaintext_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
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
  static desilo::fhe::RelinearizationKey *relinearization_key_;
  static desilo::fhe::RelinearizationKey *level_0_relinearization_key_;
  static std::vector<desilo::fhe::RelinearizationKey *>
      incompatible_relinearization_keys_;
};

desilo::fhe::CKKSEngine *RejectMultiply::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectMultiply::unit_plaintext_ = nullptr;
desilo::fhe::UnitPlaintext *RejectMultiply::level_0_unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectMultiply::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectMultiply::incompatible_plaintexts_;
desilo::fhe::Plaintext *RejectMultiply::plaintext_ = nullptr;
desilo::fhe::Plaintext *RejectMultiply::level_0_plaintext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectMultiply::duo_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectMultiply::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectMultiply::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectMultiply::level_0_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectMultiply::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectMultiply::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectMultiply::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectMultiply::level_0_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectMultiply::size_2_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectMultiply::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectMultiply::incompatible_ciphertexts_;
desilo::fhe::RelinearizationKey *RejectMultiply::relinearization_key_ = nullptr;
desilo::fhe::RelinearizationKey *RejectMultiply::level_0_relinearization_key_ =
    nullptr;
std::vector<desilo::fhe::RelinearizationKey *>
    RejectMultiply::incompatible_relinearization_keys_;

INSTANTIATE_TEST_CASE_P(, RejectMultiply, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_CIPHERTEXTS(unit_ciphertext1, unit_ciphertext2,              \
                              error_message)                                   \
  try {                                                                        \
    engine_->multiply(unit_ciphertext1, unit_ciphertext2);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Unit Ciphertexts: " error_message, e.what());       \
  }

TEST_P(RejectMultiply, UnitCiphertexts_UnitCiphertext1NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXTS(
      incompatible_unit_ciphertext, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitCiphertexts_UnitCiphertext1TooSmall) {
  TEST_UNIT_CIPHERTEXTS(
      polynomial_1_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertexts_UnitCiphertext1TooLarge) {
  TEST_UNIT_CIPHERTEXTS(
      polynomial_4_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertexts_UnitCiphertext1Level0) {
  TEST_UNIT_CIPHERTEXTS(
      level_0_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext should have a positive level.");
}

TEST_P(RejectMultiply, UnitCiphertexts_UnitCiphertext2NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXTS(
      duo_intt_unit_ciphertext_, incompatible_unit_ciphertext,
      "the second input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitCiphertexts_UnitCiphertext2TooSmall) {
  TEST_UNIT_CIPHERTEXTS(
      duo_intt_unit_ciphertext_, polynomial_1_unit_ciphertext_,
      "the second input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertexts_UnitCiphertext2TooLarge) {
  TEST_UNIT_CIPHERTEXTS(
      duo_intt_unit_ciphertext_, polynomial_4_unit_ciphertext_,
      "the second input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertexts_UnitCiphertext2Level0) {
  TEST_UNIT_CIPHERTEXTS(
      duo_intt_unit_ciphertext_, level_0_unit_ciphertext_,
      "the second input unit ciphertext should have a positive level.");
}

#define TEST_UNIT_WITH_KEY(unit_ciphertext1, unit_ciphertext2,                 \
                           relinearization_key, error_message)                 \
  try {                                                                        \
    engine_->multiply(unit_ciphertext1, unit_ciphertext2,                      \
                      relinearization_key);                                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Unit Ciphertexts Then Relinearize: " error_message, \
                 e.what());                                                    \
  }

TEST_P(RejectMultiply,
       UnitCiphertextsThenRelinearize_UnitCiphertext1NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_WITH_KEY(
      incompatible_unit_ciphertext, duo_intt_unit_ciphertext_,
      relinearization_key_,
      "the first input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitCiphertextsThenRelinearize_UnitCiphertext1TooSmall) {
  TEST_UNIT_WITH_KEY(
      polynomial_1_unit_ciphertext_, duo_intt_unit_ciphertext_,
      relinearization_key_,
      "the first input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertextsThenRelinearize_UnitCiphertext1TooLarge) {
  TEST_UNIT_WITH_KEY(
      polynomial_4_unit_ciphertext_, duo_intt_unit_ciphertext_,
      relinearization_key_,
      "the first input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertextsThenRelinearize_UnitCiphertext1Level0) {
  TEST_UNIT_WITH_KEY(
      level_0_unit_ciphertext_, duo_intt_unit_ciphertext_, relinearization_key_,
      "the first input unit ciphertext should have a positive level.");
}

TEST_P(RejectMultiply,
       UnitCiphertextsThenRelinearize_UnitCiphertext2NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, incompatible_unit_ciphertext,
      relinearization_key_,
      "the second input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitCiphertextsThenRelinearize_UnitCiphertext2TooSmall) {
  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, polynomial_1_unit_ciphertext_,
      relinearization_key_,
      "the second input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertextsThenRelinearize_UnitCiphertext2TooLarge) {
  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, polynomial_4_unit_ciphertext_,
      relinearization_key_,
      "the second input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertextsThenRelinearize_UnitCiphertext2Level0) {
  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, level_0_unit_ciphertext_, relinearization_key_,
      "the second input unit ciphertext should have a positive level.");
}

TEST_P(RejectMultiply,
       UnitCiphertextsThenRelinearize_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, duo_intt_unit_ciphertext_,
      incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectMultiply,
       UnitCiphertextsThenRelinearize_RelinearizationKeyTooSmall) {
  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, duo_intt_unit_ciphertext_,
      level_0_relinearization_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input relinearization key.");
}

#define TEST_UNIT_SQUARE(unit_ciphertext, error_message)                       \
  try {                                                                        \
    engine_->square(unit_ciphertext);                                          \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Square Unit Ciphertext: " error_message, e.what());          \
  }

TEST_P(RejectMultiply, UnitSquare_NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_SQUARE(
      incompatible_unit_ciphertext,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitSquare_TooSmall) {
  TEST_UNIT_SQUARE(polynomial_1_unit_ciphertext_,
                   "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitSquare_TooLarge) {
  TEST_UNIT_SQUARE(polynomial_4_unit_ciphertext_,
                   "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitSquare_Level0) {
  TEST_UNIT_SQUARE(level_0_unit_ciphertext_,
                   "the input unit ciphertext should have a positive level.");
}

#define TEST_UNIT_SQUARE_WITH_KEY(unit_ciphertext, relinearization_key,        \
                                  error_message)                               \
  try {                                                                        \
    engine_->square(unit_ciphertext, relinearization_key);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Square Unit Ciphertext Then Relinearize: " error_message,    \
                 e.what());                                                    \
  }

TEST_P(RejectMultiply, UnitSquareThenRelinearize_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_SQUARE_WITH_KEY(
      incompatible_unit_ciphertext, relinearization_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitSquareThenRelinearize_UnitCiphertextTooSmall) {
  TEST_UNIT_SQUARE_WITH_KEY(
      polynomial_1_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitSquareThenRelinearize_UnitCiphertextTooLarge) {
  TEST_UNIT_SQUARE_WITH_KEY(
      polynomial_4_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, UnitSquare_UnitCiphertextLevel0) {
  TEST_UNIT_SQUARE_WITH_KEY(
      level_0_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have a positive level.");
}

TEST_P(RejectMultiply,
       UnitSquareThenRelinearize_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_SQUARE_WITH_KEY(
      duo_intt_unit_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitSquareThenRelinearize_RelinearizationKeyTooSmall) {
  TEST_UNIT_SQUARE_WITH_KEY(
      duo_intt_unit_ciphertext_, level_0_relinearization_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input relinearization key.");
}

#define TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(unit_ciphertext, unit_plaintext,   \
                                            error_message)                     \
  {                                                                            \
    try {                                                                      \
      engine_->multiply(unit_ciphertext, unit_plaintext);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Unit Ciphertext And Unit Plaintext: " error_message,       \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(unit_plaintext, unit_ciphertext);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Unit Plaintext And Unit Ciphertext: " error_message,       \
          e.what());                                                           \
    }                                                                          \
  }

TEST_P(RejectMultiply,
       UnitCiphertextUnitPlaintext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      incompatible_unit_ciphertext, unit_plaintext_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitCiphertextUnitPlaintext_UnitCiphertextTooSmall) {
  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      polynomial_1_unit_ciphertext_, unit_plaintext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertextUnitPlaintext_UnitCiphertextTooLarge) {
  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      polynomial_4_unit_ciphertext_, unit_plaintext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectMultiply, UnitCiphertextUnitPlaintext_UnitCiphertextLevel0) {
  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      level_0_unit_ciphertext_, unit_plaintext_,
      "the input unit ciphertext should have a positive level.");
}

TEST_P(RejectMultiply, UnitCiphertextUnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      duo_intt_unit_ciphertext_, incompatible_unit_plaintext,
      "the input unit plaintext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitCiphertextUnitPlaintext_UnitPlaintextLevel0) {
  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      duo_intt_unit_ciphertext_, level_0_unit_plaintext_,
      "the input unit plaintext should have a positive level.");
}

#define TEST_UNIT_CIPHERTEXT_DOUBLE(unit_ciphertext, error_message)            \
  {                                                                            \
    std::vector<double> double_message;                                        \
                                                                               \
    try {                                                                      \
      engine_->multiply(unit_ciphertext, double_message);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Unit Ciphertext And Double Vector: " error_message,        \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(double_message, unit_ciphertext);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Double Vector And Unit Ciphertext: " error_message,        \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    std::vector<std::complex<double>> complex_message;                         \
                                                                               \
    try {                                                                      \
      engine_->multiply(unit_ciphertext, complex_message);                     \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Unit Ciphertext And Complex Double "              \
                   "Vector: " error_message,                                   \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(complex_message, unit_ciphertext);                     \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Complex Double Vector And Unit "                  \
                   "Ciphertext: " error_message,                               \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    double double_value;                                                       \
                                                                               \
    try {                                                                      \
      engine_->multiply(unit_ciphertext, double_value);                        \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Unit Ciphertext And Double Scalar: " error_message,        \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(double_value, unit_ciphertext);                        \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Double Scalar And Unit Ciphertext: " error_message,        \
          e.what());                                                           \
    }                                                                          \
  }

#define TEST_UNIT_CIPHERTEXT(unit_ciphertext, error_message)                   \
  {                                                                            \
    TEST_UNIT_CIPHERTEXT_DOUBLE(unit_ciphertext, error_message);               \
                                                                               \
    int64_t integer_value;                                                     \
                                                                               \
    try {                                                                      \
      engine_->multiply(unit_ciphertext, integer_value);                       \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Unit Ciphertext And Integer Scalar: " error_message,       \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(integer_value, unit_ciphertext);                       \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Integer Scalar And Unit Ciphertext: " error_message,       \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply_imaginary(unit_ciphertext, integer_value);             \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Unit Ciphertext And Imaginary Integer "           \
                   "Scalar: " error_message,                                   \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply_imaginary(integer_value, unit_ciphertext);             \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Imaginary Integer Scalar And "                    \
                   "Unit Ciphertext: " error_message,                          \
                   e.what());                                                  \
    }                                                                          \
  }

TEST_P(RejectMultiply, UnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT(
      incompatible_unit_ciphertext,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, UnitCiphertext_UnitCiphertextLevel0) {
  TEST_UNIT_CIPHERTEXT_DOUBLE(
      level_0_unit_ciphertext_,
      "the input unit ciphertext should have a positive level.");
}

TEST_F(RejectMultiply, UnitCiphertext_MessageTooLong) {
  auto unit_ciphertext = duo_intt_unit_ciphertext_;
  std::vector<double> double_message(10000);

  try {
    engine_->multiply(unit_ciphertext, double_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Unit Ciphertext And Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(double_message, unit_ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Double Vector And Unit Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  std::vector<std::complex<double>> complex_message(10000);

  try {
    engine_->multiply(unit_ciphertext, complex_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Unit Ciphertext And Complex Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(complex_message, unit_ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Complex Double Vector And Unit Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }
}

#define TEST_CIPHERTEXTS(ciphertext1, ciphertext2, error_message)              \
  try {                                                                        \
    engine_->multiply(ciphertext1, ciphertext2);                               \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Ciphertexts: " error_message, e.what());            \
  }

TEST_P(RejectMultiply, Ciphertexts_Ciphertext1NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXTS(
      incompatible_ciphertext, duo_intt_ciphertext_,
      "the first input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, Ciphertexts_Ciphertext1TooSmall) {
  TEST_CIPHERTEXTS(polynomial_1_ciphertext_, duo_intt_ciphertext_,
                   "the first input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, Ciphertexts_Ciphertext1TooLarge) {
  TEST_CIPHERTEXTS(polynomial_4_ciphertext_, duo_intt_ciphertext_,
                   "the first input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, Ciphertexts_UnitCiphertext1Level0) {
  TEST_CIPHERTEXTS(level_0_ciphertext_, duo_intt_ciphertext_,
                   "the first input ciphertext should have a positive level.");
}

TEST_P(RejectMultiply, Ciphertexts_Ciphertext2NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXTS(
      duo_intt_ciphertext_, incompatible_ciphertext,
      "the second input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, Ciphertexts_Ciphertext2TooSmall) {
  TEST_CIPHERTEXTS(duo_intt_ciphertext_, polynomial_1_ciphertext_,
                   "the second input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, Ciphertexts_Ciphertext2TooLarge) {
  TEST_CIPHERTEXTS(duo_intt_ciphertext_, polynomial_4_ciphertext_,
                   "the second input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, Ciphertexts_Ciphertext2Level0) {
  TEST_CIPHERTEXTS(duo_intt_ciphertext_, level_0_ciphertext_,
                   "the second input ciphertext should have a positive level.");
}

#define TEST_WITH_KEY(ciphertext1, ciphertext2, relinearization_key,           \
                      error_message)                                           \
  try {                                                                        \
    engine_->multiply(ciphertext1, ciphertext2, relinearization_key);          \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Multiply Ciphertexts Then Relinearize: " error_message,      \
                 e.what());                                                    \
  }

TEST_P(RejectMultiply, CiphertextsThenRelinearize_Ciphertext1NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_WITH_KEY(
      incompatible_ciphertext, duo_intt_ciphertext_, relinearization_key_,
      "the first input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, CiphertextsThenRelinearize_Ciphertext1TooSmall) {
  TEST_WITH_KEY(polynomial_1_ciphertext_, duo_intt_ciphertext_,
                relinearization_key_,
                "the first input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, CiphertextsThenRelinearize_Ciphertext1TooLarge) {
  TEST_WITH_KEY(polynomial_4_ciphertext_, duo_intt_ciphertext_,
                relinearization_key_,
                "the first input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, CiphertextsThenRelinearize_Ciphertext1Level0) {
  TEST_WITH_KEY(level_0_ciphertext_, duo_intt_ciphertext_, relinearization_key_,
                "the first input ciphertext should have a positive level.");
}

TEST_P(RejectMultiply, CiphertextsThenRelinearize_Ciphertext2NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_WITH_KEY(
      duo_intt_ciphertext_, incompatible_ciphertext, relinearization_key_,
      "the second input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, CiphertextsThenRelinearize_Ciphertext2TooSmall) {
  TEST_WITH_KEY(duo_intt_ciphertext_, polynomial_1_ciphertext_,
                relinearization_key_,
                "the second input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, CiphertextsThenRelinearize_Ciphertext2TooLarge) {
  TEST_WITH_KEY(duo_intt_ciphertext_, polynomial_4_ciphertext_,
                relinearization_key_,
                "the second input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, CiphertextsThenRelinearize_Ciphertext2Level0) {
  TEST_WITH_KEY(duo_intt_ciphertext_, level_0_ciphertext_, relinearization_key_,
                "the second input ciphertext should have a positive level.");
}

TEST_P(RejectMultiply,
       CiphertextsThenRelinearize_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_WITH_KEY(
      duo_intt_ciphertext_, duo_intt_ciphertext_,
      incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectMultiply, CiphertextsThenRelinearize_RelinearizationKeyTooSmall) {
  TEST_WITH_KEY(duo_intt_ciphertext_, duo_intt_ciphertext_,
                level_0_relinearization_key_,
                "the level of the input ciphertext is greater than that of the "
                "input relinearization key.");
}

#define TEST_SQUARE(ciphertext, error_message)                                 \
  try {                                                                        \
    engine_->square(ciphertext);                                               \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Square Ciphertext: " error_message, e.what());               \
  }

TEST_P(RejectMultiply, Square_NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_SQUARE(incompatible_ciphertext,
              "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, Square_TooSmall) {
  TEST_SQUARE(polynomial_1_ciphertext_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, Square_TooLarge) {
  TEST_SQUARE(polynomial_4_ciphertext_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, Square_Level0) {
  TEST_SQUARE(level_0_ciphertext_,
              "the input ciphertext should have a positive level.");
}

#define TEST_SQUARE_WITH_KEY(ciphertext, relinearization_key, error_message)   \
  try {                                                                        \
    engine_->square(ciphertext, relinearization_key);                          \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Square Ciphertext Then Relinearize: " error_message,         \
                 e.what());                                                    \
  }

TEST_P(RejectMultiply, SquareThenRelinearize_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_SQUARE_WITH_KEY(
      incompatible_ciphertext, relinearization_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, SquareThenRelinearize_CiphertextTooSmall) {
  TEST_SQUARE_WITH_KEY(polynomial_1_ciphertext_, relinearization_key_,
                       "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectMultiply, SquareThenRelinearize_CiphertextTooLarge) {
  TEST_SQUARE_WITH_KEY(polynomial_4_ciphertext_, relinearization_key_,
                       "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectMultiply, SquareThenRelinearize_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_SQUARE_WITH_KEY(
      duo_intt_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectMultiply, SquareThenRelinearize_RelinearizationKeyTooSmall) {
  TEST_SQUARE_WITH_KEY(duo_intt_ciphertext_, level_0_relinearization_key_,
                       "the level of the input ciphertext is greater than "
                       "that of the input relinearization key.");
}

#define TEST_CIPHERTEXT_PLAINTEXT(ciphertext, plaintext, error_message)        \
  {                                                                            \
    try {                                                                      \
      engine_->multiply(ciphertext, plaintext);                                \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Plaintext: " error_message,        \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(plaintext, ciphertext);                                \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Plaintext And Ciphertext: " error_message,        \
                   e.what());                                                  \
    }                                                                          \
  }

TEST_P(RejectMultiply, CiphertextPlaintext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXT_PLAINTEXT(
      incompatible_ciphertext, plaintext_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, CiphertextPlaintext_CiphertextTooSmall) {
  TEST_CIPHERTEXT_PLAINTEXT(
      polynomial_1_ciphertext_, plaintext_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectMultiply, CiphertextPlaintext_CiphertextTooLarge) {
  TEST_CIPHERTEXT_PLAINTEXT(
      polynomial_4_ciphertext_, plaintext_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectMultiply, CiphertextPlaintext_CiphertextLevel0) {
  TEST_CIPHERTEXT_PLAINTEXT(
      level_0_ciphertext_, plaintext_,
      "the input ciphertext should have a positive level.");
}

TEST_P(RejectMultiply, CiphertextPlaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  TEST_CIPHERTEXT_PLAINTEXT(
      duo_intt_ciphertext_, incompatible_plaintext,
      "the input plaintext is not compatible with this engine.");
}

TEST_F(RejectMultiply, CiphertextPlaintext_PlaintextLevel0) {
  TEST_CIPHERTEXT_PLAINTEXT(
      duo_intt_ciphertext_, level_0_plaintext_,
      "the input plaintext should have a positive level.");
}

TEST_F(RejectMultiply, CiphertextPlaintext_MatchCKKSSize) {
  TEST_CIPHERTEXT_PLAINTEXT(size_2_ciphertext_, plaintext_,
                            "the size of the input ciphertext "
                            "and plaintext does not match.");
}

#define TEST_CIPHERTEXT_DOUBLE(ciphertext, error_message)                      \
  {                                                                            \
    std::vector<double> double_message;                                        \
                                                                               \
    try {                                                                      \
      engine_->multiply(ciphertext, double_message);                           \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Double Vector: " error_message,    \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(double_message, ciphertext);                           \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Double Vector And Ciphertext: " error_message,    \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    std::vector<std::complex<double>> complex_message;                         \
                                                                               \
    try {                                                                      \
      engine_->multiply(ciphertext, complex_message);                          \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Complex Double "                   \
                   "Vector: " error_message,                                   \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(complex_message, ciphertext);                          \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Complex Double Vector And Ciphertext: " error_message,     \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    double *double_buffer;                                                     \
    int buffer_size = engine_->get_slot_count();                               \
                                                                               \
    try {                                                                      \
      engine_->multiply(ciphertext, double_buffer, buffer_size);               \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Double Buffer: " error_message,    \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(double_buffer, ciphertext, buffer_size);               \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Double Buffer And Ciphertext: " error_message,    \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    std::complex<double> *complex_buffer;                                      \
                                                                               \
    try {                                                                      \
      engine_->multiply(ciphertext, complex_buffer, buffer_size);              \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Complex Double "                   \
                   "Buffer: " error_message,                                   \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(complex_buffer, ciphertext, buffer_size);              \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Multiply Complex Double Buffer And Ciphertext: " error_message,     \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    double double_value;                                                       \
                                                                               \
    try {                                                                      \
      engine_->multiply(ciphertext, double_value);                             \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Double Scalar: " error_message,    \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(double_value, ciphertext);                             \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Double Scalar And Ciphertext: " error_message,    \
                   e.what());                                                  \
    }                                                                          \
  }

#define TEST_CIPHERTEXT(ciphertext, error_message)                             \
  {                                                                            \
    TEST_CIPHERTEXT_DOUBLE(ciphertext, error_message);                         \
                                                                               \
    int64_t integer_value;                                                     \
                                                                               \
    try {                                                                      \
      engine_->multiply(ciphertext, integer_value);                            \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Integer Scalar: " error_message,   \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply(integer_value, ciphertext);                            \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Integer Scalar And Ciphertext: " error_message,   \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply_imaginary(ciphertext, integer_value);                  \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Ciphertext And Imaginary Integer "                \
                   "Scalar: " error_message,                                   \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->multiply_imaginary(integer_value, ciphertext);                  \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Multiply Imaginary Integer Scalar And "                    \
                   "Ciphertext: " error_message,                               \
                   e.what());                                                  \
    }                                                                          \
  }

TEST_P(RejectMultiply, Ciphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXT(incompatible_ciphertext,
                  "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectMultiply, Ciphertext_CiphertextLevel0) {
  TEST_CIPHERTEXT_DOUBLE(level_0_ciphertext_,
                         "the input ciphertext should have a positive level.");
}

TEST_F(RejectMultiply, Ciphertext_MessageTooShort) {
  auto ciphertext = duo_intt_ciphertext_;
  std::vector<double> double_message;

  try {
    engine_->multiply(ciphertext, double_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Double Vector: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(double_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Double Vector And Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  std::vector<std::complex<double>> complex_message;

  try {
    engine_->multiply(ciphertext, complex_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Complex Double Vector: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(complex_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Complex Double Vector And Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  double *double_buffer;
  int buffer_size = 0;

  try {
    engine_->multiply(ciphertext, double_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Double Buffer: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(double_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Double Buffer And Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  std::complex<double> *complex_buffer;

  try {
    engine_->multiply(ciphertext, complex_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Complex Double Buffer: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(complex_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Complex Double Buffer And Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }
}

TEST_F(RejectMultiply, Ciphertext_MessageTooLong) {
  auto ciphertext = duo_intt_ciphertext_;
  std::vector<double> double_message(10000);

  try {
    engine_->multiply(ciphertext, double_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(double_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Double Vector And Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  std::vector<std::complex<double>> complex_message(10000);

  try {
    engine_->multiply(ciphertext, complex_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Complex Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(complex_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Complex Double Vector And Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  int buffer_size = 10000;
  double double_buffer[buffer_size];

  try {
    engine_->multiply(ciphertext, double_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Double Buffer: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(double_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Double Buffer And Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  std::complex<double> complex_buffer[buffer_size];

  try {
    engine_->multiply(ciphertext, complex_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Ciphertext And Complex Double Buffer: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->multiply(complex_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Multiply Complex Double Buffer And Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }
}
