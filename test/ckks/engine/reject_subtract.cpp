#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectSubtract : public testing::TestWithParam<int> {
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
    incompatible_plaintexts_ = {
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[0]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[1]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[2]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[3]}),
    };

    duo_intt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    trio_intt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 3);
    polynomial_1_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 4);
    rescaled_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::RESCALED, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    duo_ntt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NTT_FORM, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    scaled_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2, 7, 2.0);
    level_0_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2, 0);

    duo_intt_ciphertext_ =
        new desilo::fhe::Ciphertext({duo_intt_unit_ciphertext_});
    polynomial_1_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_1_unit_ciphertext_});
    polynomial_4_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_4_unit_ciphertext_});
    rescaled_ciphertext_ =
        new desilo::fhe::Ciphertext({rescaled_unit_ciphertext_});
    duo_ntt_ciphertext_ =
        new desilo::fhe::Ciphertext({duo_ntt_unit_ciphertext_});
    trio_intt_ciphertext_ =
        new desilo::fhe::Ciphertext({trio_intt_unit_ciphertext_});
    scaled_ciphertext_ = new desilo::fhe::Ciphertext({scaled_unit_ciphertext_});
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
  }

  static void TearDownTestSuite() {
    delete plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    delete duo_intt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete scaled_ciphertext_;
    delete size_2_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitPlaintext *unit_plaintext_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static desilo::fhe::Plaintext *plaintext_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
  static desilo::fhe::UnitCiphertext *duo_intt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *rescaled_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *duo_ntt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *trio_intt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *scaled_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *level_0_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *rescaled_ciphertext_;
  static desilo::fhe::Ciphertext *duo_ntt_ciphertext_;
  static desilo::fhe::Ciphertext *trio_intt_ciphertext_;
  static desilo::fhe::Ciphertext *scaled_ciphertext_;
  static desilo::fhe::Ciphertext *level_0_ciphertext_;
  static desilo::fhe::Ciphertext *size_2_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
};

desilo::fhe::CKKSEngine *RejectSubtract::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectSubtract::unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectSubtract::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectSubtract::incompatible_plaintexts_;
desilo::fhe::Plaintext *RejectSubtract::plaintext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::duo_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::rescaled_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::duo_ntt_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::trio_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::scaled_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSubtract::level_0_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::rescaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::duo_ntt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::trio_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::scaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::level_0_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSubtract::size_2_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectSubtract::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectSubtract::incompatible_ciphertexts_;

INSTANTIATE_TEST_CASE_P(, RejectSubtract, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_CIPHERTEXTS(unit_ciphertext1, unit_ciphertext2,              \
                              error_message)                                   \
  try {                                                                        \
    engine_->subtract(unit_ciphertext1, unit_ciphertext2);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Subtract Unit Ciphertexts: " error_message, e.what());       \
  }

TEST_P(RejectSubtract, UnitCiphertexts_UnitCiphertext1NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXTS(
      incompatible_unit_ciphertext, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, UnitCiphertexts_UnitCiphertext1TooSmall) {
  TEST_UNIT_CIPHERTEXTS(
      polynomial_1_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract, UnitCiphertexts_UnitCiphertext1TooLarge) {
  TEST_UNIT_CIPHERTEXTS(
      polynomial_4_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectSubtract, UnitCiphertexts_UnitCiphertext2NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXTS(
      duo_intt_unit_ciphertext_, incompatible_unit_ciphertext,
      "the second input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, UnitCiphertexts_UnitCiphertext2TooSmall) {
  TEST_UNIT_CIPHERTEXTS(
      duo_intt_unit_ciphertext_, polynomial_1_unit_ciphertext_,
      "the second input unit ciphertext should have either 2 or 3 "
      "polynomials.");
}

TEST_F(RejectSubtract, UnitCiphertexts_UnitCiphertext2TooLarge) {
  TEST_UNIT_CIPHERTEXTS(
      duo_intt_unit_ciphertext_, polynomial_4_unit_ciphertext_,
      "the second input unit ciphertext should have either 2 or 3 "
      "polynomials.");
}

TEST_F(RejectSubtract, UnitCiphertexts_MatchCKKSScale) {
  TEST_UNIT_CIPHERTEXTS(
      scaled_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the ckks scale of the input unit ciphertexts does not match.");
}

#define TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(unit_ciphertext, unit_plaintext,   \
                                            error_message)                     \
  {                                                                            \
    try {                                                                      \
      engine_->subtract(unit_ciphertext, unit_plaintext);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Unit Ciphertext By Unit Plaintext: " error_message,        \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(unit_plaintext, unit_ciphertext);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Unit Plaintext By Unit Ciphertext: " error_message,        \
          e.what());                                                           \
    }                                                                          \
  }

TEST_P(RejectSubtract,
       UnitCiphertextUnitPlaintext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      incompatible_unit_ciphertext, unit_plaintext_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, UnitCiphertextUnitPlaintext_UnitCiphertextTooSmall) {
  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      polynomial_1_unit_ciphertext_, unit_plaintext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract, UnitCiphertextUnitPlaintext_UnitCiphertextTooLarge) {
  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      polynomial_4_unit_ciphertext_, unit_plaintext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectSubtract, UnitCiphertextUnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      duo_intt_unit_ciphertext_, incompatible_unit_plaintext,
      "the input unit plaintext is not compatible with this engine.");
}

TEST_F(RejectSubtract, UnitCiphertextUnitPlaintext_MatchCKKSScale) {
  TEST_UNIT_CIPHERTEXT_UNIT_PLAINTEXT(
      scaled_unit_ciphertext_, unit_plaintext_,
      "the ckks scale of the input unit ciphertext and "
      "unit plaintext does not match.");
}

#define TEST_UNIT_CIPHERTEXT(unit_ciphertext, error_message)                   \
  {                                                                            \
    std::vector<double> double_message;                                        \
                                                                               \
    try {                                                                      \
      engine_->subtract(unit_ciphertext, double_message);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Unit Ciphertext By Double Vector: " error_message,         \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(double_message, unit_ciphertext);                      \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Double Vector By Unit Ciphertext: " error_message,         \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    std::vector<std::complex<double>> complex_message;                         \
                                                                               \
    try {                                                                      \
      engine_->subtract(unit_ciphertext, complex_message);                     \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Unit Ciphertext By Complex Double Vector: " error_message, \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(complex_message, unit_ciphertext);                     \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Complex Double Vector By Unit Ciphertext: " error_message, \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    double value;                                                              \
                                                                               \
    try {                                                                      \
      engine_->subtract(unit_ciphertext, value);                               \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Unit Ciphertext By Double Scalar: " error_message,         \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(value, unit_ciphertext);                               \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Double Scalar By Unit Ciphertext: " error_message,         \
          e.what());                                                           \
    }                                                                          \
  }

TEST_P(RejectSubtract, UnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT(
      incompatible_unit_ciphertext,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, UnitCiphertext_MessageTooLong) {
  auto unit_ciphertext = duo_intt_unit_ciphertext_;
  std::vector<double> double_message(10000);

  try {
    engine_->subtract(unit_ciphertext, double_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Unit Ciphertext By Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(double_message, unit_ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Double Vector By Unit Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  std::vector<std::complex<double>> complex_message(10000);

  try {
    engine_->subtract(unit_ciphertext, complex_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Unit Ciphertext By Complex Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(complex_message, unit_ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Complex Double Vector By Unit Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }
}

#define TEST_UNIT_CIPHERTEXTS_INPLACE(unit_ciphertext1, unit_ciphertext2,      \
                                      error_message)                           \
  try {                                                                        \
    engine_->subtract_inplace(unit_ciphertext1, unit_ciphertext2);             \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Subtract Inplace Unit Ciphertexts: " error_message,          \
                 e.what());                                                    \
  }

TEST_P(RejectSubtract, UnitCiphertextsInplace_UnitCiphertext1NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXTS_INPLACE(
      incompatible_unit_ciphertext, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_UnitCiphertext1TooSmall) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      polynomial_1_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_UnitCiphertext1TooLarge) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      polynomial_4_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the first input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract,
       UnitCiphertextsInplace_UnitCiphertext1TrioUnitCiphertext2Duo) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      trio_intt_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the polynomial count of the input unit ciphertexts does not match.");
}

TEST_P(RejectSubtract, UnitCiphertextsInplace_UnitCiphertext2NotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXTS_INPLACE(
      duo_intt_unit_ciphertext_, incompatible_unit_ciphertext,
      "the second input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_UnitCiphertext2TooSmall) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      duo_intt_unit_ciphertext_, polynomial_1_unit_ciphertext_,
      "the second input unit ciphertext should have either 2 or 3 "
      "polynomials.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_UnitCiphertext2TooLarge) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      duo_intt_unit_ciphertext_, polynomial_4_unit_ciphertext_,
      "the second input unit ciphertext should have either 2 or 3 "
      "polynomials.");
}

TEST_F(RejectSubtract,
       UnitCiphertextsInplace_UnitCiphertext1DuoUnitCiphertext2Trio) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      duo_intt_unit_ciphertext_, trio_intt_unit_ciphertext_,
      "the polynomial count of the input unit ciphertexts does not match.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_MatchCKKSScale) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      scaled_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the ckks scale of the input unit ciphertexts does not match.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_MatchLevel) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      level_0_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the level of the input unit ciphertexts does not match.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_MatchNTT) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      duo_ntt_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the NTT state of the input unit ciphertexts does not match.");
}

TEST_F(RejectSubtract, UnitCiphertextsInplace_MatchRescaled) {
  TEST_UNIT_CIPHERTEXTS_INPLACE(
      rescaled_unit_ciphertext_, duo_intt_unit_ciphertext_,
      "the rescaled state of the input unit ciphertexts does not match.");
}

#define TEST_CIPHERTEXTS(ciphertext1, ciphertext2, error_message)              \
  try {                                                                        \
    engine_->subtract(ciphertext1, ciphertext2);                               \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Subtract Ciphertexts: " error_message, e.what());            \
  }

TEST_P(RejectSubtract, Ciphertexts_Ciphertext1NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXTS(
      incompatible_ciphertext, duo_intt_ciphertext_,
      "the first input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, Ciphertexts_Ciphertext1TooSmall) {
  TEST_CIPHERTEXTS(
      polynomial_1_ciphertext_, duo_intt_ciphertext_,
      "the first input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract, Ciphertexts_Ciphertext1TooLarge) {
  TEST_CIPHERTEXTS(
      polynomial_4_ciphertext_, duo_intt_ciphertext_,
      "the first input ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectSubtract, Ciphertexts_Ciphertext2NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXTS(
      duo_intt_ciphertext_, incompatible_ciphertext,
      "the second input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, Ciphertexts_Ciphertext2TooSmall) {
  TEST_CIPHERTEXTS(duo_intt_ciphertext_, polynomial_1_ciphertext_,
                   "the second input ciphertext should have either 2 "
                   "or 3 polynomials.");
}

TEST_F(RejectSubtract, Ciphertexts_Ciphertext2TooLarge) {
  TEST_CIPHERTEXTS(duo_intt_ciphertext_, polynomial_4_ciphertext_,
                   "the second input ciphertext should have either 2 "
                   "or 3 polynomials.");
}

TEST_F(RejectSubtract, Ciphertexts_MatchCKKSScale) {
  TEST_CIPHERTEXTS(scaled_ciphertext_, duo_intt_ciphertext_,
                   "the ckks scale of the input ciphertexts does not match.");
}

TEST_F(RejectSubtract, Ciphertexts_MatchSize) {
  TEST_CIPHERTEXTS(size_2_ciphertext_, duo_intt_ciphertext_,
                   "the size of the input ciphertexts does not match.");
}

#define TEST_CIPHERTEXT_PLAINTEXT(ciphertext, plaintext, error_message)        \
  {                                                                            \
    try {                                                                      \
      engine_->subtract(ciphertext, plaintext);                                \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Ciphertext By Plaintext: " error_message,         \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(plaintext, ciphertext);                                \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Plaintext By Ciphertext: " error_message,         \
                   e.what());                                                  \
    }                                                                          \
  }

TEST_P(RejectSubtract, CiphertextPlaintext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXT_PLAINTEXT(
      incompatible_ciphertext, plaintext_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, CiphertextPlaintext_CiphertextTooSmall) {
  TEST_CIPHERTEXT_PLAINTEXT(
      polynomial_1_ciphertext_, plaintext_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract, CiphertextPlaintext_CiphertextTooLarge) {
  TEST_CIPHERTEXT_PLAINTEXT(
      polynomial_4_ciphertext_, plaintext_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_P(RejectSubtract, CiphertextPlaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  TEST_CIPHERTEXT_PLAINTEXT(
      duo_intt_ciphertext_, incompatible_plaintext,
      "the input plaintext is not compatible with this engine.");
}

TEST_F(RejectSubtract, CiphertextPlaintext_MatchCKKSScale) {
  TEST_CIPHERTEXT_PLAINTEXT(
      scaled_ciphertext_, plaintext_,
      "the ckks scale of the input ciphertext and plaintext does not "
      "match.");
}

TEST_F(RejectSubtract, CiphertextPlaintext_MatchCKKSSize) {
  TEST_CIPHERTEXT_PLAINTEXT(size_2_ciphertext_, plaintext_,
                            "the size of the input ciphertext "
                            "and plaintext does not match.");
}

#define TEST_CIPHERTEXT(ciphertext, error_message)                             \
  {                                                                            \
    std::vector<double> double_message;                                        \
                                                                               \
    try {                                                                      \
      engine_->subtract(ciphertext, double_message);                           \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Ciphertext By Double Vector: " error_message,     \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(double_message, ciphertext);                           \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Double Vector By Ciphertext: " error_message,     \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    std::vector<std::complex<double>> complex_message;                         \
                                                                               \
    try {                                                                      \
      engine_->subtract(ciphertext, complex_message);                          \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Ciphertext By Complex Double Vector: " error_message,      \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(complex_message, ciphertext);                          \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Complex Double Vector By Ciphertext: " error_message,      \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    double *double_buffer;                                                     \
    int buffer_size = engine_->get_slot_count();                               \
                                                                               \
    try {                                                                      \
      engine_->subtract(ciphertext, double_buffer, buffer_size);               \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Ciphertext By Double Buffer: " error_message,     \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(double_buffer, ciphertext, buffer_size);               \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Double Buffer By Ciphertext: " error_message,     \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    std::complex<double> *complex_buffer;                                      \
                                                                               \
    try {                                                                      \
      engine_->subtract(ciphertext, complex_buffer, buffer_size);              \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Ciphertext By Complex Double Buffer: " error_message,      \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(complex_buffer, ciphertext, buffer_size);              \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ(                                                            \
          "Subtract Complex Double Buffer By Ciphertext: " error_message,      \
          e.what());                                                           \
    }                                                                          \
                                                                               \
    double value;                                                              \
                                                                               \
    try {                                                                      \
      engine_->subtract(ciphertext, value);                                    \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Ciphertext By Double Scalar: " error_message,     \
                   e.what());                                                  \
    }                                                                          \
                                                                               \
    try {                                                                      \
      engine_->subtract(value, ciphertext);                                    \
      FAIL();                                                                  \
    } catch (std::runtime_error & e) {                                         \
      EXPECT_STREQ("Subtract Double Scalar By Ciphertext: " error_message,     \
                   e.what());                                                  \
    }                                                                          \
  }

TEST_P(RejectSubtract, Ciphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXT(incompatible_ciphertext,
                  "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, Ciphertext_MessageTooShort) {
  auto ciphertext = size_2_ciphertext_;
  std::vector<double> double_message;

  try {
    engine_->subtract(ciphertext, double_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Double Vector: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(double_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Double Vector By Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  std::vector<std::complex<double>> complex_message;

  try {
    engine_->subtract(ciphertext, complex_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Complex Double Vector: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(complex_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Complex Double Vector By Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  double *double_buffer;
  int buffer_size = 0;

  try {
    engine_->subtract(ciphertext, double_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Double Buffer: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(double_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Double Buffer By Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  std::complex<double> *complex_buffer;

  try {
    engine_->subtract(ciphertext, complex_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Complex Double Buffer: "
                 "the given input is too short to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(complex_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Complex Double Buffer By Ciphertext: "
                 "the given input is too short to be processed.",
                 e.what());
  }
}

TEST_F(RejectSubtract, Ciphertext_MessageTooLong) {
  auto ciphertext = duo_intt_ciphertext_;
  std::vector<double> double_message(10000);

  try {
    engine_->subtract(ciphertext, double_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(double_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Double Vector By Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  std::vector<std::complex<double>> complex_message(10000);

  try {
    engine_->subtract(ciphertext, complex_message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Complex Double Vector: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(complex_message, ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Complex Double Vector By Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  int buffer_size = 10000;
  double double_buffer[buffer_size];

  try {
    engine_->subtract(ciphertext, double_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Double Buffer: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(double_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Double Buffer By Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  std::complex<double> complex_buffer[buffer_size];

  try {
    engine_->subtract(ciphertext, complex_buffer, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Ciphertext By Complex Double Buffer: "
                 "the given input is too long to be processed.",
                 e.what());
  }

  try {
    engine_->subtract(complex_buffer, ciphertext, buffer_size);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Subtract Complex Double Buffer By Ciphertext: "
                 "the given input is too long to be processed.",
                 e.what());
  }
}

#define TEST_CIPHERTEXTS_INPLACE(ciphertext1, ciphertext2, error_message)      \
  try {                                                                        \
    engine_->subtract_inplace(ciphertext1, ciphertext2);                       \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Subtract Inplace Ciphertexts: " error_message, e.what());    \
  }

TEST_P(RejectSubtract, CiphertextsInplace_Ciphertext1NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXTS_INPLACE(
      incompatible_ciphertext, duo_intt_ciphertext_,
      "the first input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, CiphertextsInplace_Ciphertext1TooSmall) {
  TEST_CIPHERTEXTS_INPLACE(
      polynomial_1_ciphertext_, duo_intt_ciphertext_,
      "the first input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract, CiphertextsInplace_Ciphertext1TooLarge) {
  TEST_CIPHERTEXTS_INPLACE(
      polynomial_4_ciphertext_, duo_intt_ciphertext_,
      "the first input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectSubtract, CiphertextsInplace_Ciphertext1TrioCiphertext2Duo) {
  TEST_CIPHERTEXTS_INPLACE(
      trio_intt_ciphertext_, duo_intt_ciphertext_,
      "the polynomial count of the input ciphertexts does not match.");
}

TEST_P(RejectSubtract, CiphertextsInplace_Ciphertext2NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXTS_INPLACE(
      duo_intt_ciphertext_, incompatible_ciphertext,
      "the second input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSubtract, CiphertextsInplace_Ciphertext2TooSmall) {
  TEST_CIPHERTEXTS_INPLACE(
      duo_intt_ciphertext_, polynomial_1_ciphertext_,
      "the second input ciphertext should have either 2 or 3 "
      "polynomials.");
}

TEST_F(RejectSubtract, CiphertextsInplace_Ciphertext2TooLarge) {
  TEST_CIPHERTEXTS_INPLACE(
      duo_intt_ciphertext_, polynomial_4_ciphertext_,
      "the second input ciphertext should have either 2 or 3 "
      "polynomials.");
}

TEST_F(RejectSubtract, CiphertextsInplace_Ciphertext1DuoCiphertext2Trio) {
  TEST_CIPHERTEXTS_INPLACE(
      duo_intt_ciphertext_, trio_intt_ciphertext_,
      "the polynomial count of the input ciphertexts does not match.");
}

TEST_F(RejectSubtract, CiphertextsInplace_MatchCKKSScale) {
  TEST_CIPHERTEXTS_INPLACE(
      scaled_ciphertext_, duo_intt_ciphertext_,
      "the ckks scale of the input ciphertexts does not match.");
}

TEST_F(RejectSubtract, CiphertextsInplace_MatchLevel) {
  TEST_CIPHERTEXTS_INPLACE(
      level_0_ciphertext_, duo_intt_ciphertext_,
      "the level of the input ciphertexts does not match.");
}

TEST_F(RejectSubtract, CiphertextsInplace_MatchNTT) {
  TEST_CIPHERTEXTS_INPLACE(
      duo_ntt_ciphertext_, duo_intt_ciphertext_,
      "the NTT state of the input ciphertexts does not match.");
}

TEST_F(RejectSubtract, CiphertextsInplace_MatchRescaled) {
  TEST_CIPHERTEXTS_INPLACE(
      rescaled_ciphertext_, duo_intt_ciphertext_,
      "the rescaled state of the input ciphertexts does not match.");
}
