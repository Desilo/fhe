#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectConjugate : public testing::TestWithParam<int> {
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
    polynomial_1_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 1);
    polynomial_4_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 4);

    duo_intt_ciphertext_ =
        new desilo::fhe::Ciphertext({duo_intt_unit_ciphertext_});
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

    conjugation_key_ = get_dummy_conjugation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count);
    level_0_conjugation_key_ = get_dummy_conjugation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_conjugation_keys_ = {
        get_dummy_conjugation_key(bad_scheme_preset, log_slot_count,
                                  log_coeff_count, special_prime_count),
        get_dummy_conjugation_key(scheme_preset, bad_log_slot_count,
                                  log_coeff_count, special_prime_count),
        get_dummy_conjugation_key(scheme_preset, log_slot_count,
                                  bad_log_coeff_count, special_prime_count),
        get_dummy_conjugation_key(scheme_preset, log_slot_count,
                                  log_coeff_count, bad_special_prime_count)};

    std::vector<desilo::fhe::Polynomial *> keys;
    int moduli_id = 0;
    int level = 7;
    int chain_count = 2;
    int coeff_count = 1 << log_coeff_count;
  }

  static void TearDownTestSuite() {
    delete plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    delete duo_intt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
    delete conjugation_key_;
    delete level_0_conjugation_key_;
    for (auto conjugation_key : incompatible_conjugation_keys_) {
      delete conjugation_key;
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
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::ConjugationKey *conjugation_key_;
  static desilo::fhe::ConjugationKey *level_0_conjugation_key_;
  static std::vector<desilo::fhe::ConjugationKey *>
      incompatible_conjugation_keys_;
};

desilo::fhe::CKKSEngine *RejectConjugate::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectConjugate::unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectConjugate::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectConjugate::incompatible_plaintexts_;
desilo::fhe::Plaintext *RejectConjugate::plaintext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectConjugate::duo_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectConjugate::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectConjugate::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::Ciphertext *RejectConjugate::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectConjugate::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectConjugate::polynomial_4_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectConjugate::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectConjugate::incompatible_ciphertexts_;
desilo::fhe::ConjugationKey *RejectConjugate::conjugation_key_ = nullptr;
desilo::fhe::ConjugationKey *RejectConjugate::level_0_conjugation_key_ =
    nullptr;
std::vector<desilo::fhe::ConjugationKey *>
    RejectConjugate::incompatible_conjugation_keys_;

INSTANTIATE_TEST_CASE_P(, RejectConjugate, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_PLAINTEXT(unit_plaintext, error_message)                     \
  try {                                                                        \
    engine_->conjugate(unit_plaintext);                                        \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Conjugate Unit Plaintext: " error_message, e.what());        \
  }

TEST_P(RejectConjugate, UnitPlaintext_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  TEST_UNIT_PLAINTEXT(
      incompatible_unit_plaintext,
      "the input unit plaintext is not compatible with this engine.");
}

#define TEST_UNIT_CIPHERTEXT(unit_ciphertext, conjugation_key, error_message)  \
  try {                                                                        \
    engine_->conjugate(unit_ciphertext, conjugation_key);                      \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Conjugate Unit Ciphertext: " error_message, e.what());       \
  }

TEST_P(RejectConjugate, UnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_CIPHERTEXT(
      incompatible_unit_ciphertext, conjugation_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectConjugate, UnitCiphertext_UnitCiphertextTooSmall) {
  TEST_UNIT_CIPHERTEXT(polynomial_1_unit_ciphertext_, conjugation_key_,
                       "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectConjugate, UnitCiphertext_UnitCiphertextTooLarge) {
  TEST_UNIT_CIPHERTEXT(polynomial_4_unit_ciphertext_, conjugation_key_,
                       "the input unit ciphertext should have 2 polynomials.");
}

TEST_P(RejectConjugate, UnitCiphertext_ConjugationKeyNotCompatible) {
  auto incompatible_conjugation_key =
      incompatible_conjugation_keys_[GetParam()];

  TEST_UNIT_CIPHERTEXT(
      duo_intt_unit_ciphertext_, incompatible_conjugation_key,
      "the input conjugation key is not compatible with this engine.");
}

TEST_F(RejectConjugate, UnitCiphertext_ConjugationKeyTooSmall) {
  TEST_UNIT_CIPHERTEXT(
      duo_intt_unit_ciphertext_, level_0_conjugation_key_,
      "the level of the input unit ciphertext is greater than that of "
      "the input conjugation key.");
}

#define TEST_PLAINTEXT(plaintext, error_message)                               \
  try {                                                                        \
    engine_->conjugate(plaintext);                                             \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Conjugate Plaintext: " error_message, e.what());             \
  }

TEST_P(RejectConjugate, Plaintext_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  TEST_PLAINTEXT(incompatible_plaintext,
                 "the input plaintext is not compatible with this engine.");
}

#define TEST_CIPHERTEXT(ciphertext, conjugation_key, error_message)            \
  try {                                                                        \
    engine_->conjugate(ciphertext, conjugation_key);                           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Conjugate Ciphertext: " error_message, e.what());            \
  }

TEST_P(RejectConjugate, Ciphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CIPHERTEXT(incompatible_ciphertext, conjugation_key_,
                  "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectConjugate, Ciphertext_CiphertextTooSmall) {
  TEST_CIPHERTEXT(polynomial_1_ciphertext_, conjugation_key_,
                  "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectConjugate, Ciphertext_CiphertextTooLarge) {
  TEST_CIPHERTEXT(polynomial_4_ciphertext_, conjugation_key_,
                  "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectConjugate, Ciphertext_ConjugationKeyNotCompatible) {
  auto incompatible_conjugation_key =
      incompatible_conjugation_keys_[GetParam()];

  TEST_CIPHERTEXT(
      duo_intt_ciphertext_, incompatible_conjugation_key,
      "the input conjugation key is not compatible with this engine.");
}

TEST_F(RejectConjugate, Ciphertext_ConjugationKeyTooSmall) {
  TEST_CIPHERTEXT(duo_intt_ciphertext_, level_0_conjugation_key_,
                  "the level of the input ciphertext is greater than that of "
                  "the input conjugation key.");
}
