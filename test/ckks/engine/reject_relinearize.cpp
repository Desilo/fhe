#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectRelinearize : public testing::TestWithParam<int> {
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

    trio_ntt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NTT_FORM, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 3);
    polynomial_1_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 4);

    trio_ntt_ciphertext_ =
        new desilo::fhe::Ciphertext({trio_ntt_unit_ciphertext_});
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
    delete trio_ntt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
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
  static desilo::fhe::UnitCiphertext *trio_ntt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::Ciphertext *trio_ntt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::RelinearizationKey *relinearization_key_;
  static desilo::fhe::RelinearizationKey *level_0_relinearization_key_;
  static std::vector<desilo::fhe::RelinearizationKey *>
      incompatible_relinearization_keys_;
};

desilo::fhe::CKKSEngine *RejectRelinearize::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectRelinearize::trio_ntt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectRelinearize::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectRelinearize::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::Ciphertext *RejectRelinearize::trio_ntt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRelinearize::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRelinearize::polynomial_4_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectRelinearize::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectRelinearize::incompatible_ciphertexts_;
desilo::fhe::RelinearizationKey *RejectRelinearize::relinearization_key_ =
    nullptr;
desilo::fhe::RelinearizationKey
    *RejectRelinearize::level_0_relinearization_key_ = nullptr;
std::vector<desilo::fhe::RelinearizationKey *>
    RejectRelinearize::incompatible_relinearization_keys_;

INSTANTIATE_TEST_CASE_P(, RejectRelinearize, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_CIPHERTEXT(unit_ciphertext, relinearization_key,             \
                             error_message)                                    \
  try {                                                                        \
    engine_->relinearize(unit_ciphertext, relinearization_key);                \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Relinearize Unit Ciphertext: " error_message, e.what());     \
  }

TEST_P(RejectRelinearize, UnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT(
      incompatible_unit_ciphertext, relinearization_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectRelinearize, UnitCiphertext_UnitCiphertextTooSmall) {
  TEST_UNIT_CIPHERTEXT(polynomial_1_unit_ciphertext_, relinearization_key_,
                       "the input unit ciphertext should have 3 polynomials.");
}

TEST_F(RejectRelinearize, UnitCiphertext_UnitCiphertextTooLarge) {
  TEST_UNIT_CIPHERTEXT(polynomial_4_unit_ciphertext_, relinearization_key_,
                       "the input unit ciphertext should have 3 polynomials.");
}

TEST_P(RejectRelinearize, UnitCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_CIPHERTEXT(
      trio_ntt_unit_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectRelinearize, UnitCiphertext_RelinearizationKeyTooSmall) {
  TEST_UNIT_CIPHERTEXT(
      trio_ntt_unit_ciphertext_, level_0_relinearization_key_,
      "the level of the input unit ciphertext is greater than that of "
      "the input relinearization key.");
}

#define TEST_CIPHERTEXT(ciphertext, relinearization_key, error_message)        \
  try {                                                                        \
    engine_->relinearize(ciphertext, relinearization_key);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Relinearize Ciphertext: " error_message, e.what());          \
  }

TEST_P(RejectRelinearize, Ciphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXT(incompatible_ciphertext, relinearization_key_,
                  "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectRelinearize, Ciphertext_CiphertextTooSmall) {
  TEST_CIPHERTEXT(polynomial_1_ciphertext_, relinearization_key_,
                  "the input ciphertext should have 3 polynomials.");
}

TEST_F(RejectRelinearize, Ciphertext_CiphertextTooLarge) {
  TEST_CIPHERTEXT(polynomial_4_ciphertext_, relinearization_key_,
                  "the input ciphertext should have 3 polynomials.");
}

TEST_P(RejectRelinearize, Ciphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_CIPHERTEXT(
      trio_ntt_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectRelinearize, Ciphertext_RelinearizationKeyTooSmall) {
  TEST_CIPHERTEXT(
      trio_ntt_ciphertext_, level_0_relinearization_key_,
      "the level of the input ciphertext is greater than that of the "
      "input relinearization key.");
}
