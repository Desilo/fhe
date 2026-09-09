#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectINTT : public testing::TestWithParam<int> {
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
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
};

desilo::fhe::CKKSEngine *RejectINTT::engine_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectINTT::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectINTT::incompatible_plaintexts_;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectINTT::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *> RejectINTT::incompatible_ciphertexts_;

INSTANTIATE_TEST_CASE_P(, RejectINTT, testing::Values(0, 1, 2, 3));

TEST_P(RejectINTT, UnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  try {
    engine_->intt(incompatible_unit_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "INTT Unit Plaintext: the input unit plaintext is not compatible with "
        "this engine.",
        e.what());
  }
}

TEST_P(RejectINTT, UnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  try {
    engine_->intt(incompatible_unit_ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "INTT Unit Ciphertext: the input unit ciphertext is not compatible "
        "with this engine.",
        e.what());
  }
}

TEST_P(RejectINTT, Plaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  try {
    engine_->intt(incompatible_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("INTT Plaintext: the input plaintext is not "
                 "compatible with this engine.",
                 e.what());
  }
}

TEST_P(RejectINTT, Ciphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  try {
    engine_->intt(incompatible_ciphertext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("INTT Ciphertext: the input ciphertext is not "
                 "compatible with this engine.",
                 e.what());
  }
}
