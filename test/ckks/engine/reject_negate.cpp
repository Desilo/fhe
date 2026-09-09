#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectNegate : public testing::TestWithParam<int> {
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

    polynomial_1_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 4);

    polynomial_1_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_1_unit_ciphertext_});
    polynomial_4_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_4_unit_ciphertext_});

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
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
};

desilo::fhe::CKKSEngine *RejectNegate::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectNegate::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectNegate::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::Ciphertext *RejectNegate::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectNegate::polynomial_4_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectNegate::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *> RejectNegate::incompatible_ciphertexts_;

INSTANTIATE_TEST_CASE_P(, RejectNegate, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_CIPHERTEXT(unit_ciphertext, error_message)                   \
  try {                                                                        \
    engine_->negate(unit_ciphertext);                                          \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Negate Unit Ciphertext: " error_message, e.what());          \
  }

TEST_P(RejectNegate, UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT(
      incompatible_unit_ciphertext,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectNegate, UnitCiphertextTooSmall) {
  TEST_UNIT_CIPHERTEXT(
      polynomial_1_unit_ciphertext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectNegate, UnitCiphertextTooLarge) {
  TEST_UNIT_CIPHERTEXT(
      polynomial_4_unit_ciphertext_,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

#define TEST_CIPHERTEXT(ciphertext, error_message)                             \
  try {                                                                        \
    engine_->negate(ciphertext);                                               \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Negate Ciphertext: " error_message, e.what());               \
  }

TEST_P(RejectNegate, CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXT(incompatible_ciphertext,
                  "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectNegate, CiphertextTooSmall) {
  TEST_CIPHERTEXT(
      polynomial_1_ciphertext_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectNegate, CiphertextTooLarge) {
  TEST_CIPHERTEXT(
      polynomial_4_ciphertext_,
      "the input ciphertext should have either 2 or 3 polynomials.");
}
