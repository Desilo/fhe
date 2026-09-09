#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectRescale : public testing::TestWithParam<int> {
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

    level_0_unit_plaintext_ = get_dummy_unit_plaintext(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_unit_plaintexts_ = {
        get_dummy_unit_plaintext(bad_scheme_preset, log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, bad_log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count,
                                 bad_log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count, log_coeff_count,
                                 bad_special_prime_count)};
    level_0_plaintext_ = new desilo::fhe::Plaintext({level_0_unit_plaintext_});
    incompatible_plaintexts_ = {
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[0]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[1]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[2]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[3]}),
    };

    polynomial_1_unit_ciphertext_ = get_dummy_unit_ciphertext(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_unit_ciphertext(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 4);
    level_0_unit_ciphertext_ =
        get_dummy_unit_ciphertext(scheme_preset, log_slot_count,
                                  log_coeff_count, special_prime_count, 2, 0);

    polynomial_1_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_1_unit_ciphertext_});
    polynomial_4_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_4_unit_ciphertext_});
    level_0_ciphertext_ =
        new desilo::fhe::Ciphertext({level_0_unit_ciphertext_});

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
    delete level_0_plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete level_0_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitPlaintext *level_0_unit_plaintext_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static desilo::fhe::Plaintext *level_0_plaintext_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *level_0_unit_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *level_0_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
};

desilo::fhe::CKKSEngine *RejectRescale::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectRescale::level_0_unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectRescale::incompatible_unit_plaintexts_;
desilo::fhe::Plaintext *RejectRescale::level_0_plaintext_ = nullptr;
std::vector<desilo::fhe::Plaintext *> RejectRescale::incompatible_plaintexts_;
desilo::fhe::UnitCiphertext *RejectRescale::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectRescale::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectRescale::level_0_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRescale::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRescale::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRescale::level_0_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectRescale::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *> RejectRescale::incompatible_ciphertexts_;

INSTANTIATE_TEST_CASE_P(, RejectRescale, testing::Values(0, 1, 2, 3));

TEST_F(RejectRescale, UnitPlaintextLevel0) {
  try {
    engine_->rescale(level_0_unit_plaintext_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Rescale Unit Plaintext: the input unit plaintext should have a "
        "positive level.",
        e.what());
  }
}

TEST_P(RejectRescale, UnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  try {
    engine_->rescale(incompatible_unit_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Rescale Unit Plaintext: the input unit plaintext is not compatible "
        "with this engine.",
        e.what());
  }
}

#define TEST_RESCALE_UNIT(unit_ciphertext, error_message)                      \
  try {                                                                        \
    engine_->rescale(unit_ciphertext);                                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Rescale Unit Ciphertext: " error_message, e.what());         \
  }

TEST_P(RejectRescale, UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_RESCALE_UNIT(
      incompatible_unit_ciphertext,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectRescale, UnitCiphertextTooSmall) {
  TEST_RESCALE_UNIT(
      polynomial_1_unit_ciphertext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectRescale, UnitCiphertextTooLarge) {
  TEST_RESCALE_UNIT(
      polynomial_4_unit_ciphertext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectRescale, UnitCiphertextLevel0) {
  TEST_RESCALE_UNIT(level_0_unit_ciphertext_,
                    "the input unit ciphertext should have a positive level.");
}

TEST_F(RejectRescale, PlaintextLevel0) {
  try {
    engine_->rescale(level_0_plaintext_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Rescale Plaintext: the input plaintext should have a positive level.",
        e.what());
  }
}

TEST_P(RejectRescale, Plaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  try {
    engine_->rescale(incompatible_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Rescale Plaintext: the input plaintext is not "
                 "compatible with this engine.",
                 e.what());
  }
}

#define TEST_RESCALE(ciphertext, error_message)                                \
  try {                                                                        \
    engine_->rescale(ciphertext);                                              \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Rescale Ciphertext: " error_message, e.what());              \
  }

TEST_P(RejectRescale, CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_RESCALE(incompatible_ciphertext,
               "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectRescale, CiphertextTooSmall) {
  TEST_RESCALE(polynomial_1_ciphertext_,
               "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectRescale, CiphertextTooLarge) {
  TEST_RESCALE(polynomial_4_ciphertext_,
               "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectRescale, CiphertextLevel0) {
  TEST_RESCALE(level_0_ciphertext_,
               "the input ciphertext should have a positive level.");
}
