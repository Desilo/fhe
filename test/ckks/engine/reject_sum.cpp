#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectSum : public testing::TestWithParam<int> {
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

    int delta = 1;
    fixed_rotation_key_ = get_dummy_fixed_rotation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count,
        delta);
    level_0_fixed_rotation_key_ = get_dummy_fixed_rotation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count,
        delta, 0);
    incompatible_fixed_rotation_keys_ = {
        get_dummy_fixed_rotation_key(bad_scheme_preset, log_slot_count,
                                     log_coeff_count, special_prime_count,
                                     delta),
        get_dummy_fixed_rotation_key(scheme_preset, bad_log_slot_count,
                                     log_coeff_count, special_prime_count,
                                     delta),
        get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                     bad_log_coeff_count, special_prime_count,
                                     delta),
        get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                     log_coeff_count, bad_special_prime_count,
                                     delta)};

    std::vector<desilo::fhe::FixedRotationKey *> fixed_rotation_keys{
        fixed_rotation_key_};
    rotation_key_ = new desilo::fhe::RotationKey(fixed_rotation_keys);
    fixed_rotation_keys = {level_0_fixed_rotation_key_};
    level_0_rotation_key_ = new desilo::fhe::RotationKey(fixed_rotation_keys);
    incompatible_rotation_keys_ = {};
    for (int index = 0; index < incompatible_fixed_rotation_keys_.size();
         index++) {
      fixed_rotation_keys = {incompatible_fixed_rotation_keys_[index]};
      incompatible_rotation_keys_.push_back(
          new desilo::fhe::RotationKey(fixed_rotation_keys));
    }

    std::vector<desilo::fhe::Polynomial *> keys;
    int moduli_id = 0;
    int level = 7;
    int chain_count = 2;
    int coeff_count = 1 << log_coeff_count;
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
  static desilo::fhe::UnitCiphertext *rescaled_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *duo_ntt_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *rescaled_ciphertext_;
  static desilo::fhe::Ciphertext *duo_ntt_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::FixedRotationKey *fixed_rotation_key_;
  static desilo::fhe::FixedRotationKey *level_0_fixed_rotation_key_;
  static std::vector<desilo::fhe::FixedRotationKey *>
      incompatible_fixed_rotation_keys_;
  static desilo::fhe::RotationKey *rotation_key_;
  static desilo::fhe::RotationKey *level_0_rotation_key_;
  static std::vector<desilo::fhe::RotationKey *> incompatible_rotation_keys_;
};

desilo::fhe::CKKSEngine *RejectSum::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSum::duo_intt_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSum::polynomial_1_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSum::polynomial_4_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSum::rescaled_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectSum::duo_ntt_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSum::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSum::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSum::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSum::rescaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectSum::duo_ntt_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectSum::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *> RejectSum::incompatible_ciphertexts_;
desilo::fhe::FixedRotationKey *RejectSum::fixed_rotation_key_ = nullptr;
desilo::fhe::FixedRotationKey *RejectSum::level_0_fixed_rotation_key_ = nullptr;
std::vector<desilo::fhe::FixedRotationKey *>
    RejectSum::incompatible_fixed_rotation_keys_;
desilo::fhe::RotationKey *RejectSum::rotation_key_ = nullptr;
desilo::fhe::RotationKey *RejectSum::level_0_rotation_key_ = nullptr;
std::vector<desilo::fhe::RotationKey *> RejectSum::incompatible_rotation_keys_;

INSTANTIATE_TEST_CASE_P(, RejectSum, testing::Values(0, 1, 2, 3));

#define TEST_1D_ROW(ciphertext, rotation_key, error_message)                   \
  try {                                                                        \
    engine_->sum_1d_by_row(ciphertext, rotation_key);                          \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Sum Ciphertext Along Axis 1: " error_message, e.what());     \
  }

TEST_P(RejectSum, Row_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_1D_ROW(incompatible_ciphertext, rotation_key_,
              "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSum, Row_CiphertextTooSmall) {
  TEST_1D_ROW(polynomial_1_ciphertext_, rotation_key_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectSum, Row_CiphertextTooLarge) {
  TEST_1D_ROW(polynomial_4_ciphertext_, rotation_key_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectSum, Row_CiphertextNTT) {
  TEST_1D_ROW(duo_ntt_ciphertext_, rotation_key_,
              "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectSum, Row_CiphertextRescaled) {
  TEST_1D_ROW(rescaled_ciphertext_, rotation_key_,
              "the input ciphertext should not be rescaled.");
}

TEST_P(RejectSum, Row_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_1D_ROW(duo_intt_ciphertext_, incompatible_rotation_key,
              "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectSum, Row_RotationKeyTooSmall) {
  TEST_1D_ROW(duo_intt_ciphertext_, level_0_rotation_key_,
              "the level of the input ciphertext is greater than that of the "
              "input rotation key.");
}

#define TEST_1D_COLUMN(ciphertext, error_message)                              \
  try {                                                                        \
    engine_->sum_1d_by_column(ciphertext);                                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Sum Ciphertext Along Axis 0: " error_message, e.what());     \
  }

TEST_P(RejectSum, Column_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_1D_COLUMN(incompatible_ciphertext,
                 "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSum, Column_CiphertextTooSmall) {
  TEST_1D_COLUMN(polynomial_1_ciphertext_,
                 "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectSum, Column_CiphertextTooLarge) {
  TEST_1D_COLUMN(polynomial_4_ciphertext_,
                 "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectSum, Column_CiphertextNTT) {
  TEST_1D_COLUMN(duo_ntt_ciphertext_,
                 "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectSum, Column_CiphertextRescaled) {
  TEST_1D_COLUMN(rescaled_ciphertext_,
                 "the input ciphertext should not be rescaled.");
}

#define TEST_2D(ciphertext, rotation_key, error_message)                       \
  try {                                                                        \
    engine_->sum_2d(ciphertext, rotation_key);                                 \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Sum Ciphertext Along All Axes: " error_message, e.what());   \
  }

TEST_P(RejectSum, 2D_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_2D(incompatible_ciphertext, rotation_key_,
          "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectSum, 2D_CiphertextTooSmall) {
  TEST_2D(polynomial_1_ciphertext_, rotation_key_,
          "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectSum, 2D_CiphertextTooLarge) {
  TEST_2D(polynomial_4_ciphertext_, rotation_key_,
          "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectSum, 2D_CiphertextNTT) {
  TEST_2D(duo_ntt_ciphertext_, rotation_key_,
          "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectSum, 2D_CiphertextRescaled) {
  TEST_2D(rescaled_ciphertext_, rotation_key_,
          "the input ciphertext should not be rescaled.");
}

TEST_P(RejectSum, 2D_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_2D(duo_intt_ciphertext_, incompatible_rotation_key,
          "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectSum, 2D_RotationKeyTooSmall) {
  TEST_2D(duo_intt_ciphertext_, level_0_rotation_key_,
          "the level of the input ciphertext is greater than that of the input "
          "rotation key.");
}
