#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectStack : public testing::TestWithParam<int> {
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
    rescaled_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::RESCALED, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    duo_ntt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NTT_FORM, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
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
    delete duo_intt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete rescaled_ciphertext_;
    delete duo_ntt_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitCiphertext *duo_intt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *rescaled_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *duo_ntt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *level_0_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *rescaled_ciphertext_;
  static desilo::fhe::Ciphertext *duo_ntt_ciphertext_;
  static desilo::fhe::Ciphertext *level_0_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
};

desilo::fhe::CKKSEngine *RejectStack::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectStack::duo_intt_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectStack::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectStack::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectStack::rescaled_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectStack::duo_ntt_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectStack::level_0_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectStack::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectStack::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectStack::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectStack::rescaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectStack::duo_ntt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectStack::level_0_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectStack::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *> RejectStack::incompatible_ciphertexts_;

INSTANTIATE_TEST_CASE_P(, RejectStack, testing::Values(0, 1, 2, 3));

#define TEST_VSTACK(ciphertext_1, ciphertext_2, error_message)                 \
  try {                                                                        \
    std::vector<desilo::fhe::Ciphertext *> ciphertexts{ciphertext_1,           \
                                                       ciphertext_2};          \
    engine_->stack_by_row(ciphertexts);                                        \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Stack Ciphertexts Vertically: " error_message, e.what());    \
  }

TEST_P(RejectStack, VStack_Ciphertext1NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_VSTACK(incompatible_ciphertext, duo_intt_ciphertext_,
              "the first input ciphertext is not compatible with this engine.");
}

TEST_P(RejectStack, VStack_Ciphertext2NotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_VSTACK(
      duo_intt_ciphertext_, incompatible_ciphertext,
      "the second input ciphertext is not compatible with this engine.");
}

TEST_F(RejectStack, VStack_LevelMismatch) {
  TEST_VSTACK(duo_intt_ciphertext_, level_0_ciphertext_,
              "the level of the input ciphertexts does not match.");
}

TEST_F(RejectStack, VStack_NTTMismatch) {
  TEST_VSTACK(duo_intt_ciphertext_, duo_ntt_ciphertext_,
              "the NTT state of the input ciphertexts does not match.");
}

TEST_F(RejectStack, VStack_RescaledMismatch) {
  TEST_VSTACK(duo_intt_ciphertext_, rescaled_ciphertext_,
              "the rescaled state of the input ciphertexts does not match.");
}

TEST_F(RejectStack, VStack_EmptyInput) {
  try {
    std::vector<desilo::fhe::Ciphertext *> ciphertexts{};
    engine_->stack_by_row(ciphertexts);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Stack Ciphertexts Vertically: "
                 "the input ciphertext vector is empty.",
                 e.what());
  }
}
