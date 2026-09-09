#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectRotate : public testing::TestWithParam<int> {
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
    rescaled_unit_plaintext_ = get_dummy_flagged_unit_plaintext(
        desilo::fhe::DataFlag::RESCALED, scheme_preset, log_slot_count,
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
    rescaled_plaintext_ =
        new desilo::fhe::Plaintext({rescaled_unit_plaintext_});
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
    delete plaintext_;
    delete rescaled_plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
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
  static desilo::fhe::UnitPlaintext *unit_plaintext_;
  static desilo::fhe::UnitPlaintext *rescaled_unit_plaintext_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static desilo::fhe::Plaintext *plaintext_;
  static desilo::fhe::Plaintext *rescaled_plaintext_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
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

desilo::fhe::CKKSEngine *RejectRotate::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectRotate::unit_plaintext_ = nullptr;
desilo::fhe::UnitPlaintext *RejectRotate::rescaled_unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectRotate::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectRotate::incompatible_plaintexts_;
desilo::fhe::Plaintext *RejectRotate::plaintext_ = nullptr;
desilo::fhe::Plaintext *RejectRotate::rescaled_plaintext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectRotate::duo_intt_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectRotate::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectRotate::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectRotate::rescaled_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectRotate::duo_ntt_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRotate::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRotate::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRotate::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRotate::rescaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectRotate::duo_ntt_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectRotate::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *> RejectRotate::incompatible_ciphertexts_;
desilo::fhe::FixedRotationKey *RejectRotate::fixed_rotation_key_ = nullptr;
desilo::fhe::FixedRotationKey *RejectRotate::level_0_fixed_rotation_key_ =
    nullptr;
std::vector<desilo::fhe::FixedRotationKey *>
    RejectRotate::incompatible_fixed_rotation_keys_;
desilo::fhe::RotationKey *RejectRotate::rotation_key_ = nullptr;
desilo::fhe::RotationKey *RejectRotate::level_0_rotation_key_ = nullptr;
std::vector<desilo::fhe::RotationKey *>
    RejectRotate::incompatible_rotation_keys_;

INSTANTIATE_TEST_CASE_P(, RejectRotate, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_PLAINTEXT(unit_plaintext, error_message)                     \
  try {                                                                        \
    int delta = 1;                                                             \
    engine_->rotate(unit_plaintext, delta);                                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Rotate Unit Plaintext: " error_message, e.what());           \
  }

TEST_P(RejectRotate, UnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  TEST_UNIT_PLAINTEXT(
      incompatible_unit_plaintext,
      "the input unit plaintext is not compatible with this engine.");
}

#define TEST_UNIT_FIXED(unit_ciphertext, fixed_rotation_key, error_message)    \
  try {                                                                        \
    engine_->rotate(unit_ciphertext, fixed_rotation_key);                      \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Rotate Unit Ciphertext With Fixed Rotation Key: " error_message,      \
        e.what());                                                             \
  }

TEST_P(RejectRotate, UnitFixed_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_FIXED(
      incompatible_unit_ciphertext, fixed_rotation_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectRotate, UnitFixed_UnitCiphertextTooSmall) {
  TEST_UNIT_FIXED(polynomial_1_unit_ciphertext_, fixed_rotation_key_,
                  "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectRotate, UnitFixed_UnitCiphertextTooLarge) {
  TEST_UNIT_FIXED(polynomial_4_unit_ciphertext_, fixed_rotation_key_,
                  "the input unit ciphertext should have 2 polynomials.");
}

TEST_P(RejectRotate, UnitFixed_FixedRotationKeyNotCompatible) {
  auto incompatible_fixed_rotation_key =
      incompatible_fixed_rotation_keys_[GetParam()];

  TEST_UNIT_FIXED(
      duo_intt_unit_ciphertext_, incompatible_fixed_rotation_key,
      "the input fixed rotation key is not compatible with this engine.");
}

TEST_F(RejectRotate, UnitFixed_FixedRotationKeyTooSmall) {
  TEST_UNIT_FIXED(
      duo_intt_unit_ciphertext_, level_0_fixed_rotation_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input fixed rotation key.");
}

#define TEST_UNIT_GENERAL(unit_ciphertext, rotation_key, error_message)        \
  try {                                                                        \
    int delta = 1;                                                             \
    engine_->rotate(unit_ciphertext, rotation_key, delta);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Rotate Unit Ciphertext With Rotation Key: " error_message,   \
                 e.what());                                                    \
  }

TEST_P(RejectRotate, UnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_GENERAL(
      incompatible_unit_ciphertext, rotation_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectRotate, UnitCiphertext_UnitCiphertextTooSmall) {
  TEST_UNIT_GENERAL(polynomial_1_unit_ciphertext_, rotation_key_,
                    "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectRotate, UnitCiphertext_UnitCiphertextTooLarge) {
  TEST_UNIT_GENERAL(polynomial_4_unit_ciphertext_, rotation_key_,
                    "the input unit ciphertext should have 2 polynomials.");
}

TEST_P(RejectRotate, UnitCiphertext_FixedRotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_UNIT_GENERAL(
      duo_intt_unit_ciphertext_, incompatible_rotation_key,
      "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectRotate, UnitCiphertext_FixedRotationKeyTooSmall) {
  TEST_UNIT_GENERAL(
      duo_intt_unit_ciphertext_, level_0_rotation_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input rotation key.");
}

#define TEST_PLAINTEXT(plaintext, error_message)                               \
  try {                                                                        \
    int delta = 1;                                                             \
    engine_->rotate(plaintext, delta);                                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Rotate Plaintext: " error_message, e.what());                \
  }

TEST_P(RejectRotate, Plaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  TEST_PLAINTEXT(incompatible_plaintext,
                 "the input plaintext is not compatible with this engine.");
}

#define TEST_FIXED(ciphertext, fixed_rotation_key, error_message)              \
  try {                                                                        \
    engine_->rotate(ciphertext, fixed_rotation_key);                           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Rotate Ciphertext With Fixed Rotation Key: " error_message,  \
                 e.what());                                                    \
  }

TEST_P(RejectRotate, Fixed_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_FIXED(incompatible_ciphertext, fixed_rotation_key_,
             "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectRotate, Fixed_CiphertextTooSmall) {
  TEST_FIXED(polynomial_1_ciphertext_, fixed_rotation_key_,
             "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectRotate, Fixed_CiphertextTooLarge) {
  TEST_FIXED(polynomial_4_ciphertext_, fixed_rotation_key_,
             "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectRotate, Fixed_FixedRotationKeyNotCompatible) {
  auto incompatible_fixed_rotation_key =
      incompatible_fixed_rotation_keys_[GetParam()];

  TEST_FIXED(
      duo_intt_ciphertext_, incompatible_fixed_rotation_key,
      "the input fixed rotation key is not compatible with this engine.");
}

TEST_F(RejectRotate, Fixed_FixedRotationKeyTooSmall) {
  TEST_FIXED(duo_intt_ciphertext_, level_0_fixed_rotation_key_,
             "the level of the input ciphertext is greater than that "
             "of the input fixed rotation key.");
}

#define TEST_GENERAL(ciphertext, rotation_key, error_message)                  \
  try {                                                                        \
    int delta = 1;                                                             \
    engine_->rotate(ciphertext, rotation_key, delta);                          \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Rotate Ciphertext With Rotation Key: " error_message,        \
                 e.what());                                                    \
  }

TEST_P(RejectRotate, Ciphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_GENERAL(incompatible_ciphertext, rotation_key_,
               "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectRotate, Ciphertext_CiphertextTooSmall) {
  TEST_GENERAL(polynomial_1_ciphertext_, rotation_key_,
               "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectRotate, Ciphertext_CiphertextTooLarge) {
  TEST_GENERAL(polynomial_4_ciphertext_, rotation_key_,
               "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectRotate, Ciphertext_FixedRotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_GENERAL(duo_intt_ciphertext_, incompatible_rotation_key,
               "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectRotate, Ciphertext_FixedRotationKeyTooSmall) {
  TEST_GENERAL(duo_intt_ciphertext_, level_0_rotation_key_,
               "the level of the input ciphertext is greater than that of "
               "the input rotation key.");
}

#define TEST_BATCH_FIXED(ciphertext, fixed_rotation_keys, error_message)       \
  try {                                                                        \
    engine_->rotate_batch(ciphertext, fixed_rotation_keys);                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Batch Rotate Ciphertext With Fixed Rotation Keys: " error_message,    \
        e.what());                                                             \
  }

TEST_P(RejectRotate, BatchFixed_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_BATCH_FIXED(incompatible_ciphertext, {fixed_rotation_key_},
                   "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectRotate, BatchFixed_CiphertextTooSmall) {
  TEST_BATCH_FIXED(polynomial_1_ciphertext_, {fixed_rotation_key_},
                   "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectRotate, BatchFixed_CiphertextTooLarge) {
  TEST_BATCH_FIXED(polynomial_4_ciphertext_, {fixed_rotation_key_},
                   "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectRotate, BatchFixed_FixedRotationKeyNotCompatible) {
  auto incompatible_fixed_rotation_key =
      incompatible_fixed_rotation_keys_[GetParam()];

  TEST_BATCH_FIXED(
      duo_intt_ciphertext_, {incompatible_fixed_rotation_key},
      "the input fixed rotation key is not compatible with this engine.");
}

TEST_P(RejectRotate, BatchFixed_FixedRotationKey1NotCompatible) {
  auto incompatible_fixed_rotation_key =
      incompatible_fixed_rotation_keys_[GetParam()];
  std::vector fixed_rotation_keys = {incompatible_fixed_rotation_key,
                                     fixed_rotation_key_};

  TEST_BATCH_FIXED(
      duo_intt_ciphertext_, fixed_rotation_keys,
      "the first input fixed rotation key is not compatible with this engine.");
}

TEST_P(RejectRotate, BatchFixed_FixedRotationKey2NotCompatible) {
  auto incompatible_fixed_rotation_key =
      incompatible_fixed_rotation_keys_[GetParam()];
  std::vector fixed_rotation_keys = {fixed_rotation_key_,
                                     incompatible_fixed_rotation_key};

  TEST_BATCH_FIXED(duo_intt_ciphertext_, fixed_rotation_keys,
                   "the second input fixed rotation key is not compatible with "
                   "this engine.");
}

TEST_F(RejectRotate, BatchFixed_FixedRotationKeyTooSmall) {
  TEST_BATCH_FIXED(duo_intt_ciphertext_, {level_0_fixed_rotation_key_},
                   "the level of the input ciphertext is greater than that of "
                   "the input fixed rotation key.");
}

TEST_F(RejectRotate, BatchFixed_FixedRotationKey1TooSmall) {
  std::vector fixed_rotation_keys = {level_0_fixed_rotation_key_,
                                     fixed_rotation_key_};

  TEST_BATCH_FIXED(duo_intt_ciphertext_, fixed_rotation_keys,
                   "the level of the input ciphertext is greater than that of "
                   "the first input fixed rotation key.");
}

TEST_F(RejectRotate, BatchFixed_FixedRotationKey2TooSmall) {
  std::vector fixed_rotation_keys = {fixed_rotation_key_,
                                     level_0_fixed_rotation_key_};

  TEST_BATCH_FIXED(duo_intt_ciphertext_, fixed_rotation_keys,
                   "the level of the input ciphertext is greater than that of "
                   "the second input fixed rotation key.");
}

TEST_F(RejectRotate, BatchFixed_FixedRotationKeysEmpty) {
  TEST_BATCH_FIXED(duo_intt_ciphertext_, {},
                   "the input fixed rotation key vector is empty.");
}

#define TEST_BATCH(ciphertext, rotation_key, error_message)                    \
  try {                                                                        \
    int delta = 1;                                                             \
    engine_->rotate_batch(ciphertext, rotation_key, {delta});                  \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Batch Rotate Ciphertext With Rotation Key: " error_message,  \
                 e.what());                                                    \
  }

TEST_P(RejectRotate, Batch_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_BATCH(incompatible_ciphertext, rotation_key_,
             "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectRotate, Batch_CiphertextTooSmall) {
  TEST_BATCH(polynomial_1_ciphertext_, rotation_key_,
             "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectRotate, Batch_CiphertextTooLarge) {
  TEST_BATCH(polynomial_4_ciphertext_, rotation_key_,
             "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectRotate, Batch_FixedRotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_BATCH(duo_intt_ciphertext_, incompatible_rotation_key,
             "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectRotate, Batch_FixedRotationKeyTooSmall) {
  TEST_BATCH(duo_intt_ciphertext_, level_0_rotation_key_,
             "the level of the input ciphertext is greater than that of "
             "the input rotation key.");
}

TEST_F(RejectRotate, Batch_FixedDeltasEmpty) {
  try {
    engine_->rotate_batch(duo_intt_ciphertext_, rotation_key_, {});
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Batch Rotate Ciphertext With Rotation Key: the input delta "
                 "vector is empty.",
                 e.what());
  }
}
