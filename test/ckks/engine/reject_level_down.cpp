#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectLevelDown : public testing::TestWithParam<int> {
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

    unit_plaintext_ = get_dummy_unit_plaintext(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count);
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

    unit_ciphertext_ = get_dummy_unit_ciphertext(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 2);
    polynomial_1_unit_ciphertext_ = get_dummy_unit_ciphertext(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_unit_ciphertext(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 4);

    ciphertext_ = new desilo::fhe::Ciphertext({unit_ciphertext_});
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
    delete plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    delete ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
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
  static desilo::fhe::UnitCiphertext *unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::Ciphertext *ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
};

desilo::fhe::CKKSEngine *RejectLevelDown::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectLevelDown::unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectLevelDown::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectLevelDown::incompatible_plaintexts_;
desilo::fhe::UnitCiphertext *RejectLevelDown::unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectLevelDown::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectLevelDown::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::Plaintext *RejectLevelDown::plaintext_ = nullptr;
desilo::fhe::Ciphertext *RejectLevelDown::ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectLevelDown::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectLevelDown::polynomial_4_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectLevelDown::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectLevelDown::incompatible_ciphertexts_;

INSTANTIATE_TEST_CASE_P(, RejectLevelDown, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_PLAINTEXT(unit_plaintext, level, error_message)              \
  try {                                                                        \
    engine_->level_down(unit_plaintext, level);                                \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Level Down Unit Plaintext: " error_message, e.what());       \
  }

TEST_P(RejectLevelDown, UnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];
  int level = 0;

  TEST_UNIT_PLAINTEXT(
      incompatible_unit_plaintext, level,
      "the input unit plaintext is not compatible with this engine.");
}

TEST_F(RejectLevelDown, UnitPlaintext_LevelTooSmall) {
  const int level = -1;

  TEST_UNIT_PLAINTEXT(unit_plaintext_, level,
                      "the target level cannot be reached.");
}

TEST_F(RejectLevelDown, UnitPlaintext_LevelTooLarge) {
  const int level = engine_->get_max_level() + 1;

  TEST_UNIT_PLAINTEXT(unit_plaintext_, level,
                      "the target level cannot be reached.");
}

#define TEST_UNIT_CIPHERTEXT(unit_ciphertext, level, error_message)            \
  try {                                                                        \
    engine_->level_down(unit_ciphertext, level);                               \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Level Down Unit Ciphertext: " error_message, e.what());      \
  }

TEST_P(RejectLevelDown, UnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];
  int level = 0;

  TEST_UNIT_CIPHERTEXT(
      incompatible_unit_ciphertext, level,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectLevelDown, UnitCiphertextTooSmall) {
  int level = 0;

  TEST_UNIT_CIPHERTEXT(
      polynomial_1_unit_ciphertext_, level,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectLevelDown, UnitCiphertextTooLarge) {
  int level = 0;

  TEST_UNIT_CIPHERTEXT(
      polynomial_4_unit_ciphertext_, level,
      "the input unit ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectLevelDown, UnitCiphertext_LevelTooSmall) {
  const int level = -1;

  TEST_UNIT_CIPHERTEXT(unit_ciphertext_, level,
                       "the target level cannot be reached.");
}

TEST_F(RejectLevelDown, UnitCiphertext_LevelTooLarge) {
  const int level = engine_->get_max_level() + 1;

  TEST_UNIT_CIPHERTEXT(unit_ciphertext_, level,
                       "the target level cannot be reached.");
}

#define TEST_PLAINTEXT(plaintext, level, error_message)                        \
  try {                                                                        \
    engine_->level_down(plaintext, level);                                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Level Down Plaintext: " error_message, e.what());            \
  }

TEST_P(RejectLevelDown, Plaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];
  int level = 0;

  TEST_PLAINTEXT(incompatible_plaintext, level,
                 "the input plaintext is not compatible with this engine.");
}

TEST_F(RejectLevelDown, Plaintext_LevelTooSmall) {
  const int level = -1;

  TEST_PLAINTEXT(plaintext_, level, "the target level cannot be reached.");
}

TEST_F(RejectLevelDown, Plaintext_LevelTooLarge) {
  const int level = engine_->get_max_level() + 1;

  TEST_PLAINTEXT(plaintext_, level, "the target level cannot be reached.");
}

#define TEST_CIPHERTEXT(ciphertext, level, error_message)                      \
  try {                                                                        \
    engine_->level_down(ciphertext, level);                                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Level Down Ciphertext: " error_message, e.what());           \
  }

TEST_P(RejectLevelDown, Ciphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];
  int level = 0;

  TEST_CIPHERTEXT(incompatible_ciphertext, level,
                  "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectLevelDown, CiphertextTooSmall) {
  int level = 0;

  TEST_CIPHERTEXT(
      polynomial_1_ciphertext_, level,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectLevelDown, CiphertextTooLarge) {
  int level = 0;

  TEST_CIPHERTEXT(
      polynomial_4_ciphertext_, level,
      "the input ciphertext should have either 2 or 3 polynomials.");
}

TEST_F(RejectLevelDown, Ciphertext_LevelTooSmall) {
  const int level = -1;

  TEST_CIPHERTEXT(ciphertext_, level, "the target level cannot be reached.");
}

TEST_F(RejectLevelDown, Ciphertext_LevelTooLarge) {
  const int level = engine_->get_max_level() + 1;

  TEST_CIPHERTEXT(ciphertext_, level, "the target level cannot be reached.");
}
