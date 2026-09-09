#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectAdvanced : public testing::TestWithParam<int> {
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
    level_0_unit_plaintext_ = get_dummy_flagged_unit_plaintext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 0);
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
    level_0_plaintext_ = new desilo::fhe::Plaintext({level_0_unit_plaintext_});
    incompatible_plaintexts_ = {
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[0]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[1]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[2]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[3]}),
    };

    duo_intt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    trio_ntt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NTT_FORM, scheme_preset, log_slot_count,
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
    trio_intt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 3);
    scaled_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2, 7, 2.0);
    level_0_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2, 0);

    duo_intt_ciphertext_ =
        new desilo::fhe::Ciphertext({duo_intt_unit_ciphertext_});
    trio_ntt_ciphertext_ =
        new desilo::fhe::Ciphertext({trio_ntt_unit_ciphertext_});
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
    delete plaintext_;
    delete rescaled_plaintext_;
    delete level_0_plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
    delete duo_intt_ciphertext_;
    delete trio_ntt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete rescaled_ciphertext_;
    delete duo_ntt_ciphertext_;
    delete trio_intt_ciphertext_;
    delete scaled_ciphertext_;
    delete level_0_ciphertext_;
    delete size_2_ciphertext_;
    delete long_ciphertext_;
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
  static desilo::fhe::UnitPlaintext *unit_plaintext_;
  static desilo::fhe::UnitPlaintext *rescaled_unit_plaintext_;
  static desilo::fhe::UnitPlaintext *level_0_unit_plaintext_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static desilo::fhe::Plaintext *plaintext_;
  static desilo::fhe::Plaintext *rescaled_plaintext_;
  static desilo::fhe::Plaintext *level_0_plaintext_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
  static desilo::fhe::UnitCiphertext *duo_intt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *trio_ntt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *rescaled_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *duo_ntt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *trio_intt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *scaled_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *level_0_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *trio_ntt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *rescaled_ciphertext_;
  static desilo::fhe::Ciphertext *duo_ntt_ciphertext_;
  static desilo::fhe::Ciphertext *trio_intt_ciphertext_;
  static desilo::fhe::Ciphertext *scaled_ciphertext_;
  static desilo::fhe::Ciphertext *level_0_ciphertext_;
  static desilo::fhe::Ciphertext *size_2_ciphertext_;
  static desilo::fhe::Ciphertext *long_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::RelinearizationKey *relinearization_key_;
  static desilo::fhe::RelinearizationKey *level_0_relinearization_key_;
  static std::vector<desilo::fhe::RelinearizationKey *>
      incompatible_relinearization_keys_;
};

desilo::fhe::CKKSEngine *RejectAdvanced::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectAdvanced::unit_plaintext_ = nullptr;
desilo::fhe::UnitPlaintext *RejectAdvanced::rescaled_unit_plaintext_ = nullptr;
desilo::fhe::UnitPlaintext *RejectAdvanced::level_0_unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectAdvanced::incompatible_unit_plaintexts_;
std::vector<desilo::fhe::Plaintext *> RejectAdvanced::incompatible_plaintexts_;
desilo::fhe::Plaintext *RejectAdvanced::plaintext_ = nullptr;
desilo::fhe::Plaintext *RejectAdvanced::rescaled_plaintext_ = nullptr;
desilo::fhe::Plaintext *RejectAdvanced::level_0_plaintext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::duo_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::trio_ntt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::rescaled_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::duo_ntt_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::trio_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::scaled_unit_ciphertext_ = nullptr;
desilo::fhe::UnitCiphertext *RejectAdvanced::level_0_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::trio_ntt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::rescaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::duo_ntt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::trio_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::scaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::level_0_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::size_2_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectAdvanced::long_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectAdvanced::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectAdvanced::incompatible_ciphertexts_;
desilo::fhe::RelinearizationKey *RejectAdvanced::relinearization_key_ = nullptr;
desilo::fhe::RelinearizationKey *RejectAdvanced::level_0_relinearization_key_ =
    nullptr;
std::vector<desilo::fhe::RelinearizationKey *>
    RejectAdvanced::incompatible_relinearization_keys_;

INSTANTIATE_TEST_CASE_P(, RejectAdvanced, testing::Values(0, 1, 2, 3));

#define TEST_UNIT_WITH_KEY_BASIS(unit_ciphertext, relinearization_key,         \
                                 error_message)                                \
  int max_power = 2;                                                           \
  try {                                                                        \
    engine_->make_power_basis(unit_ciphertext, max_power,                      \
                              relinearization_key);                            \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Make Power Basis With Unit Ciphertext: " error_message,      \
                 e.what());                                                    \
  }

TEST_P(RejectAdvanced,
       MakePowerBasisUnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_WITH_KEY_BASIS(
      incompatible_unit_ciphertext, relinearization_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, MakePowerBasisUnitCiphertext_UnitCiphertextDuoNTT) {
  TEST_UNIT_WITH_KEY_BASIS(
      duo_ntt_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, MakePowerBasisUnitCiphertext_UnitCiphertextTrioINTT) {
  TEST_UNIT_WITH_KEY_BASIS(
      trio_intt_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakePowerBasisUnitCiphertext_UnitCiphertextRescaled) {
  TEST_UNIT_WITH_KEY_BASIS(rescaled_unit_ciphertext_, relinearization_key_,
                           "the input unit ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, MakePowerBasisUnitCiphertext_UnitCiphertextTooSmall) {
  TEST_UNIT_WITH_KEY_BASIS(
      polynomial_1_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakePowerBasisUnitCiphertext_UnitCiphertextTooLarge) {
  TEST_UNIT_WITH_KEY_BASIS(
      polynomial_4_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakePowerBasisUnitCiphertext_UnitCiphertextLevel0) {
  TEST_UNIT_WITH_KEY_BASIS(
      level_0_unit_ciphertext_, relinearization_key_,
      "the level of the input unit ciphertext is less than the target level.");
}

TEST_P(RejectAdvanced,
       MakePowerBasisUnitCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_WITH_KEY_BASIS(
      duo_intt_unit_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       MakePowerBasisUnitCiphertext_RelinearizationKeyTooSmall) {
  TEST_UNIT_WITH_KEY_BASIS(
      duo_intt_unit_ciphertext_, level_0_relinearization_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input relinearization key.");
}

#define TEST_WITH_KEY_BASIS(ciphertext, relinearization_key, error_message)    \
  int max_power = 2;                                                           \
  try {                                                                        \
    engine_->make_power_basis(ciphertext, max_power, relinearization_key);     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Make Power Basis With Ciphertext: " error_message,           \
                 e.what());                                                    \
  }

TEST_P(RejectAdvanced, MakePowerBasisCiphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_WITH_KEY_BASIS(
      incompatible_ciphertext, relinearization_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, MakePowerBasisCiphertext_CiphertextDuoNTT) {
  TEST_WITH_KEY_BASIS(duo_ntt_ciphertext_, relinearization_key_,
                      "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, MakePowerBasisCiphertext_CiphertextTrioINTT) {
  TEST_WITH_KEY_BASIS(trio_intt_ciphertext_, relinearization_key_,
                      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakePowerBasisCiphertext_CiphertextRescaled) {
  TEST_WITH_KEY_BASIS(rescaled_ciphertext_, relinearization_key_,
                      "the input ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, MakePowerBasisCiphertext_CiphertextTooSmall) {
  TEST_WITH_KEY_BASIS(polynomial_1_ciphertext_, relinearization_key_,
                      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakePowerBasisCiphertext_CiphertextTooLarge) {
  TEST_WITH_KEY_BASIS(polynomial_4_ciphertext_, relinearization_key_,
                      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakePowerBasisCiphertext_CiphertextLevel0) {
  TEST_WITH_KEY_BASIS(
      level_0_ciphertext_, relinearization_key_,
      "the level of the input ciphertext is less than the target level.");
}

TEST_P(RejectAdvanced,
       MakePowerBasisCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_WITH_KEY_BASIS(
      duo_intt_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced, MakePowerBasisCiphertext_RelinearizationKeyTooSmall) {
  TEST_WITH_KEY_BASIS(
      duo_intt_ciphertext_, level_0_relinearization_key_,
      "the level of the input ciphertext is greater than that of the "
      "input relinearization key.");
}

#define TEST_UNIT_WITH_KEY_CHEBYSHEV_BASIS(unit_ciphertext,                    \
                                           relinearization_key, error_message) \
  int max_power = 2;                                                           \
  try {                                                                        \
    engine_->make_chebyshev_basis(unit_ciphertext, max_power,                  \
                                  relinearization_key);                        \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Make Chebyshev Basis With Unit Ciphertext: " error_message,  \
                 e.what());                                                    \
  }

TEST_P(RejectAdvanced,
       MakeChebyshevBasisUnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_WITH_KEY_BASIS(
      incompatible_unit_ciphertext, relinearization_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisUnitCiphertext_UnitCiphertextDuoNTT) {
  TEST_UNIT_WITH_KEY_BASIS(
      duo_ntt_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced,
       MakeChebyshevBasisUnitCiphertext_UnitCiphertextTrioINTT) {
  TEST_UNIT_WITH_KEY_BASIS(
      trio_intt_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       MakeChebyshevBasisUnitCiphertext_UnitCiphertextRescaled) {
  TEST_UNIT_WITH_KEY_BASIS(rescaled_unit_ciphertext_, relinearization_key_,
                           "the input unit ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced,
       MakeChebyshevBasisUnitCiphertext_UnitCiphertextTooSmall) {
  TEST_UNIT_WITH_KEY_BASIS(
      polynomial_1_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       MakeChebyshevBasisUnitCiphertext_UnitCiphertextTooLarge) {
  TEST_UNIT_WITH_KEY_BASIS(
      polynomial_4_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisUnitCiphertext_UnitCiphertextLevel0) {
  TEST_UNIT_WITH_KEY_BASIS(
      level_0_unit_ciphertext_, relinearization_key_,
      "the level of the input unit ciphertext is less than the target level.");
}

TEST_P(RejectAdvanced,
       MakeChebyshevBasisUnitCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_WITH_KEY_BASIS(
      duo_intt_unit_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       MakeChebyshevBasisUnitCiphertext_RelinearizationKeyTooSmall) {
  TEST_UNIT_WITH_KEY_BASIS(
      duo_intt_unit_ciphertext_, level_0_relinearization_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input relinearization key.");
}

#define TEST_WITH_KEY_CHEBYSHEV_BASIS(ciphertext, relinearization_key,         \
                                      error_message)                           \
  int max_power = 2;                                                           \
  try {                                                                        \
    engine_->make_chebyshev_basis(ciphertext, max_power, relinearization_key); \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Make Chebyshev Basis With Ciphertext: " error_message,       \
                 e.what());                                                    \
  }

TEST_P(RejectAdvanced, MakeChebyshevBasisCiphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      incompatible_ciphertext, relinearization_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisCiphertext_CiphertextDuoNTT) {
  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      duo_ntt_ciphertext_, relinearization_key_,
      "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisCiphertext_CiphertextTrioINTT) {
  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      trio_intt_ciphertext_, relinearization_key_,
      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisCiphertext_CiphertextRescaled) {
  TEST_WITH_KEY_CHEBYSHEV_BASIS(rescaled_ciphertext_, relinearization_key_,
                                "the input ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisCiphertext_CiphertextTooSmall) {
  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      polynomial_1_ciphertext_, relinearization_key_,
      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisCiphertext_CiphertextTooLarge) {
  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      polynomial_4_ciphertext_, relinearization_key_,
      "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, MakeChebyshevBasisCiphertext_CiphertextLevel0) {
  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      level_0_ciphertext_, relinearization_key_,
      "the level of the input ciphertext is less than the target level.");
}

TEST_P(RejectAdvanced,
       MakeChebyshevBasisCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      duo_intt_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       MakeChebyshevBasisCiphertext_RelinearizationKeyTooSmall) {
  TEST_WITH_KEY_CHEBYSHEV_BASIS(
      duo_intt_ciphertext_, level_0_relinearization_key_,
      "the level of the input ciphertext is greater than that of the "
      "input relinearization key.");
}

#define TEST_UNIT_CIPHERTEXTS(unit_ciphertexts, error_message)                 \
  try {                                                                        \
    std::vector<int64_t> integer_weights(3, 1);                                \
                                                                               \
    engine_->weighted_sum(unit_ciphertexts, integer_weights);                  \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Weighted Sum Unit Ciphertexts: " error_message, e.what());   \
  }                                                                            \
                                                                               \
  try {                                                                        \
    std::vector<double> double_weights(3, 1.5);                                \
                                                                               \
    engine_->weighted_sum(unit_ciphertexts, double_weights);                   \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Weighted Sum Unit Ciphertexts: " error_message, e.what());   \
  }

TEST_P(RejectAdvanced,
       WeightedSumUnitCiphertext_FirstUnitCiphertextNotCompatible) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      incompatible_unit_ciphertexts_[GetParam()],
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the first input unit ciphertext is not compatible with this engine.");
}

TEST_P(RejectAdvanced,
       WeightedSumUnitCiphertext_SecondUnitCiphertextNotCompatible) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      incompatible_unit_ciphertexts_[GetParam()],
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the second input unit ciphertext is not compatible with this engine.");
}

TEST_P(RejectAdvanced,
       WeightedSumUnitCiphertext_ThirdUnitCiphertextNotCompatible) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      incompatible_unit_ciphertexts_[GetParam()],
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the third input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_FirstUnitCiphertextDuoNTT) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_ntt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the first input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_SecondUnitCiphertextDuoNTT) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_ntt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the second input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_ThirdUnitCiphertextDuoNTT) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_ntt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the third input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_FirstUnitCiphertextTrioINTT) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      trio_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the first input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_SecondUnitCiphertextTrioINTT) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      trio_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the second input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_ThirdUnitCiphertextTrioINTT) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      trio_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the third input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_FirstUnitCiphertextRescaled) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      rescaled_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the first input unit ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_SecondUnitCiphertextRescaled) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      rescaled_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the second input unit ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_ThirdUnitCiphertextRescaled) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      rescaled_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the third input unit ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_FirstUnitCiphertextTooSmall) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      polynomial_1_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the first input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_SecondUnitCiphertextTooSmall) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      polynomial_1_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the second input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_ThirdUnitCiphertextTooSmall) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      polynomial_1_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the third input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_FirstUnitCiphertextTooLarge) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      polynomial_4_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the first input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_SecondUnitCiphertextTooLarge) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      polynomial_4_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the second input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_ThirdUnitCiphertextTooLarge) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      polynomial_4_unit_ciphertext_,
  };
  TEST_UNIT_CIPHERTEXTS(
      unit_ciphertexts,
      "the third input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       WeightedSumUnitCiphertext_FirstUnitCiphertextDoubleCoefficientsLevel0) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      level_0_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  try {
    std::vector<double> double_weights(3, 1.5);

    engine_->weighted_sum(unit_ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Unit Ciphertexts: the first input unit "
                 "ciphertext should have a positive level.",
                 e.what());
  }
}

TEST_F(RejectAdvanced,
       WeightedSumUnitCiphertext_SecondUnitCiphertextDoubleCoefficientsLevel0) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      level_0_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  try {
    std::vector<double> double_weights(3, 1.5);

    engine_->weighted_sum(unit_ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Unit Ciphertexts: the second input unit "
                 "ciphertext should have a positive level.",
                 e.what());
  }
}

TEST_F(RejectAdvanced,
       WeightedSumUnitCiphertext_ThirdUnitCiphertextDoubleCoefficientsLevel0) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      level_0_unit_ciphertext_,
  };
  try {
    std::vector<double> double_weights(3, 1.5);

    engine_->weighted_sum(unit_ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Unit Ciphertexts: the third input unit "
                 "ciphertext should have a positive level.",
                 e.what());
  }
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_CoefficientsTooShort) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  try {
    std::vector<int64_t> integer_weights{};

    engine_->weighted_sum(unit_ciphertexts, integer_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Weighted Sum Unit Ciphertexts: the input weight is too short.",
        e.what());
  }

  try {
    std::vector<double> double_weights{};

    engine_->weighted_sum(unit_ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Weighted Sum Unit Ciphertexts: the input weight is too short.",
        e.what());
  }
}

TEST_F(RejectAdvanced, WeightedSumUnitCiphertext_ConstantCoefficients) {
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts = {
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
      duo_intt_unit_ciphertext_,
  };
  try {
    std::vector<int64_t> integer_weights{2, 0, 0};

    engine_->weighted_sum(unit_ciphertexts, integer_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Unit Ciphertexts: the input weights have only a "
                 "constant weight.",
                 e.what());
  }

  try {
    std::vector<double> double_weights{2.5, 0.0, 0.0};

    engine_->weighted_sum(unit_ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Unit Ciphertexts: the input weights have only a "
                 "constant weight.",
                 e.what());
  }
}

#define TEXT_CIPHERTEXTS(ciphertexts, error_message)                           \
  try {                                                                        \
    std::vector<int64_t> integer_weights(3, 1);                                \
                                                                               \
    engine_->weighted_sum(ciphertexts, integer_weights);                       \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Weighted Sum Ciphertexts: " error_message, e.what());        \
  }                                                                            \
                                                                               \
  try {                                                                        \
    std::vector<double> double_weights(3, 1.5);                                \
                                                                               \
    engine_->weighted_sum(ciphertexts, double_weights);                        \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Weighted Sum Ciphertexts: " error_message, e.what());        \
  }

TEST_P(RejectAdvanced, WeightedSumCiphertext_FirstCiphertextNotCompatible) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      incompatible_ciphertexts_[GetParam()],
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(
      ciphertexts,
      "the first input ciphertext is not compatible with this engine.");
}

TEST_P(RejectAdvanced, WeightedSumCiphertext_SecondCiphertextNotCompatible) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      incompatible_ciphertexts_[GetParam()],
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(
      ciphertexts,
      "the second input ciphertext is not compatible with this engine.");
}

TEST_P(RejectAdvanced, WeightedSumCiphertext_ThirdCiphertextNotCompatible) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      incompatible_ciphertexts_[GetParam()],
  };
  TEXT_CIPHERTEXTS(
      ciphertexts,
      "the third input ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_FirstCiphertextDuoNTT) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_ntt_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the first input ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_SecondCiphertextDuoNTT) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_ntt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the second input ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_ThirdCiphertextDuoNTT) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      duo_ntt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the third input ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_FirstCiphertextTrioINTT) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      trio_intt_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the first input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_SecondCiphertextTrioINTT) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      trio_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the second input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_ThirdCiphertextTrioINTT) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      trio_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the third input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_FirstCiphertextRescaled) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      rescaled_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the first input ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_SecondCiphertextRescaled) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      rescaled_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the second input ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_ThirdCiphertextRescaled) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      rescaled_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the third input ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_FirstCiphertextTooSmall) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      polynomial_1_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the first input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_SecondCiphertextTooSmall) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      polynomial_1_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the second input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_ThirdCiphertextTooSmall) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      polynomial_1_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the third input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_FirstCiphertextTooLarge) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      polynomial_4_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the first input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_SecondCiphertextTooLarge) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      polynomial_4_ciphertext_,
      duo_intt_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the second input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_ThirdCiphertextTooLarge) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      polynomial_4_ciphertext_,
  };
  TEXT_CIPHERTEXTS(ciphertexts,
                   "the third input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       WeightedSumCiphertext_FirstCiphertextDoubleCoefficientsLevel0) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      level_0_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  try {
    std::vector<double> double_weights(3, 1.5);

    engine_->weighted_sum(ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Ciphertexts: the first input ciphertext should "
                 "have a positive level.",
                 e.what());
  }
}

TEST_F(RejectAdvanced,
       WeightedSumCiphertext_SecondCiphertextDoubleCoefficientsLevel0) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      level_0_ciphertext_,
      duo_intt_ciphertext_,
  };
  try {
    std::vector<double> double_weights(3, 1.5);

    engine_->weighted_sum(ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Ciphertexts: the second input ciphertext should "
                 "have a positive level.",
                 e.what());
  }
}

TEST_F(RejectAdvanced,
       WeightedSumCiphertext_ThirdCiphertextDoubleCoefficientsLevel0) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      level_0_ciphertext_,
  };
  try {
    std::vector<double> double_weights(3, 1.5);

    engine_->weighted_sum(ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Ciphertexts: the third input ciphertext should "
                 "have a positive level.",
                 e.what());
  }
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_CoefficientsTooShort) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  try {
    std::vector<int64_t> integer_weights{};

    engine_->weighted_sum(ciphertexts, integer_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Ciphertexts: the input weight is too short.",
                 e.what());
  }

  try {
    std::vector<double> double_weights{};

    engine_->weighted_sum(ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Ciphertexts: the input weight is too short.",
                 e.what());
  }
}

TEST_F(RejectAdvanced, WeightedSumCiphertext_ConstantCoefficients) {
  std::vector<desilo::fhe::Ciphertext *> ciphertexts = {
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
      duo_intt_ciphertext_,
  };
  try {
    std::vector<int64_t> integer_weights{2, 0, 0};

    engine_->weighted_sum(ciphertexts, integer_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Ciphertexts: the input weights have only a "
                 "constant weight.",
                 e.what());
  }

  try {
    std::vector<double> double_weights{2.5, 0.0, 0.0};

    engine_->weighted_sum(ciphertexts, double_weights);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Weighted Sum Ciphertexts: the input weights have only a "
                 "constant weight.",
                 e.what());
  }
}

#define TEST_UNIT_WITH_KEY(unit_ciphertext, relinearization_key,               \
                           error_message)                                      \
  try {                                                                        \
    std::vector<int64_t> integer_coefficients(5, 1);                           \
                                                                               \
    engine_->evaluate_polynomial(unit_ciphertext, integer_coefficients,        \
                                 relinearization_key);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Evaluate Polynomial With Unit Ciphertext: " error_message,   \
                 e.what());                                                    \
  }                                                                            \
                                                                               \
  try {                                                                        \
    std::vector<double> double_coefficients(5, 1.5);                           \
                                                                               \
    engine_->evaluate_polynomial(unit_ciphertext, double_coefficients,         \
                                 relinearization_key);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Evaluate Polynomial With Unit Ciphertext: " error_message,   \
                 e.what());                                                    \
  }

TEST_P(RejectAdvanced,
       EvaluatePolynomialUnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_WITH_KEY(
      incompatible_unit_ciphertext, relinearization_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialUnitCiphertext_UnitCiphertextDuoNTT) {
  TEST_UNIT_WITH_KEY(duo_ntt_unit_ciphertext_, relinearization_key_,
                     "the input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced,
       EvaluatePolynomialUnitCiphertext_UnitCiphertextTrioINTT) {
  TEST_UNIT_WITH_KEY(trio_intt_unit_ciphertext_, relinearization_key_,
                     "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       EvaluatePolynomialUnitCiphertext_UnitCiphertextRescaled) {
  TEST_UNIT_WITH_KEY(rescaled_unit_ciphertext_, relinearization_key_,
                     "the input unit ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced,
       EvaluatePolynomialUnitCiphertext_UnitCiphertextTooSmall) {
  TEST_UNIT_WITH_KEY(polynomial_1_unit_ciphertext_, relinearization_key_,
                     "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       EvaluatePolynomialUnitCiphertext_UnitCiphertextTooLarge) {
  TEST_UNIT_WITH_KEY(polynomial_4_unit_ciphertext_, relinearization_key_,
                     "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialUnitCiphertext_UnitCiphertextLevel0) {
  TEST_UNIT_WITH_KEY(
      level_0_unit_ciphertext_, relinearization_key_,
      "the level of the input unit ciphertext is less than the target level.");
}

TEST_P(RejectAdvanced,
       EvaluatePolynomialUnitCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       EvaluatePolynomialUnitCiphertext_RelinearizationKeyTooSmall) {
  TEST_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, level_0_relinearization_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input relinearization key.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialUnitCiphertext_CoefficientsTooShort) {
  try {
    std::vector<int64_t> integer_coefficients{};

    engine_->evaluate_polynomial(duo_intt_unit_ciphertext_,
                                 integer_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Unit Ciphertext: the input "
                 "coefficient is too short.",
                 e.what());
  }

  try {
    std::vector<double> double_coefficients{};

    engine_->evaluate_polynomial(duo_intt_unit_ciphertext_, double_coefficients,
                                 relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Unit Ciphertext: the input "
                 "coefficient is too short.",
                 e.what());
  }
}

TEST_F(RejectAdvanced, EvaluatePolynomialUnitCiphertext_ConstantCoefficients) {
  try {
    std::vector<int64_t> integer_coefficients{2, 0, 0};

    engine_->evaluate_polynomial(duo_intt_unit_ciphertext_,
                                 integer_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Unit Ciphertext: the input "
                 "coefficients have only a constant coefficient.",
                 e.what());
  }

  try {
    std::vector<double> double_coefficients{2.5, 0.0, 0.0};

    engine_->evaluate_polynomial(duo_intt_unit_ciphertext_, double_coefficients,
                                 relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Unit Ciphertext: the input "
                 "coefficients have only a constant coefficient.",
                 e.what());
  }
}

#define TEST_WITH_KEY(ciphertext, relinearization_key, error_message)          \
  try {                                                                        \
    std::vector<int64_t> integer_coefficients(5, 1);                           \
                                                                               \
    engine_->evaluate_polynomial(ciphertext, integer_coefficients,             \
                                 relinearization_key);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Evaluate Polynomial With Ciphertext: " error_message,        \
                 e.what());                                                    \
  }                                                                            \
                                                                               \
  try {                                                                        \
    std::vector<double> double_coefficients(5, 1.5);                           \
                                                                               \
    engine_->evaluate_polynomial(ciphertext, double_coefficients,              \
                                 relinearization_key);                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Evaluate Polynomial With Ciphertext: " error_message,        \
                 e.what());                                                    \
  }

TEST_P(RejectAdvanced, EvaluatePolynomialCiphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_WITH_KEY(incompatible_ciphertext, relinearization_key_,
                "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_CiphertextDuoNTT) {
  TEST_WITH_KEY(duo_ntt_ciphertext_, relinearization_key_,
                "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_CiphertextTrioINTT) {
  TEST_WITH_KEY(trio_intt_ciphertext_, relinearization_key_,
                "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_CiphertextRescaled) {
  TEST_WITH_KEY(rescaled_ciphertext_, relinearization_key_,
                "the input ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_CiphertextTooSmall) {
  TEST_WITH_KEY(polynomial_1_ciphertext_, relinearization_key_,
                "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_CiphertextTooLarge) {
  TEST_WITH_KEY(polynomial_4_ciphertext_, relinearization_key_,
                "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_CiphertextLevel0) {
  TEST_WITH_KEY(
      level_0_ciphertext_, relinearization_key_,
      "the level of the input ciphertext is less than the target level.");
}

TEST_P(RejectAdvanced,
       EvaluatePolynomialCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_WITH_KEY(
      duo_intt_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       EvaluatePolynomialCiphertext_RelinearizationKeyTooSmall) {
  TEST_WITH_KEY(duo_intt_ciphertext_, level_0_relinearization_key_,
                "the level of the input ciphertext is greater than that of the "
                "input relinearization key.");
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_CoefficientsTooShort) {
  try {
    std::vector<int64_t> integer_coefficients{};

    engine_->evaluate_polynomial(duo_intt_ciphertext_, integer_coefficients,
                                 relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Ciphertext: the input "
                 "coefficient is too short.",
                 e.what());
  }

  try {
    std::vector<double> double_coefficients{};

    engine_->evaluate_polynomial(duo_intt_ciphertext_, double_coefficients,
                                 relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Ciphertext: the input "
                 "coefficient is too short.",
                 e.what());
  }
}

TEST_F(RejectAdvanced, EvaluatePolynomialCiphertext_ConstantCoefficients) {
  try {
    std::vector<int64_t> integer_coefficients{2, 0, 0};

    engine_->evaluate_polynomial(duo_intt_ciphertext_, integer_coefficients,
                                 relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Ciphertext: the input "
                 "coefficients have only a constant coefficient.",
                 e.what());
  }

  try {
    std::vector<double> double_coefficients{2.5, 0.0, 0.0};

    engine_->evaluate_polynomial(duo_intt_ciphertext_, double_coefficients,
                                 relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Polynomial With Ciphertext: the input "
                 "coefficients have only a constant coefficient.",
                 e.what());
  }
}

#define TEST_CHEBYSHEV_UNIT_WITH_KEY(unit_ciphertext, relinearization_key,     \
                                     error_message)                            \
  try {                                                                        \
    std::vector<int64_t> integer_coefficients(5, 1);                           \
                                                                               \
    engine_->evaluate_chebyshev_polynomial(                                    \
        unit_ciphertext, integer_coefficients, relinearization_key);           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Evaluate Chebyshev Polynomial With Unit Ciphertext: " error_message,  \
        e.what());                                                             \
  }                                                                            \
                                                                               \
  try {                                                                        \
    std::vector<double> double_coefficients(5, 1.5);                           \
                                                                               \
    engine_->evaluate_chebyshev_polynomial(                                    \
        unit_ciphertext, double_coefficients, relinearization_key);            \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Evaluate Chebyshev Polynomial With Unit Ciphertext: " error_message,  \
        e.what());                                                             \
  }

TEST_P(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      incompatible_unit_ciphertext, relinearization_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_UnitCiphertextDuoNTT) {
  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      duo_ntt_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_UnitCiphertextTrioINTT) {
  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      trio_intt_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_UnitCiphertextRescaled) {
  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      rescaled_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_UnitCiphertextTooSmall) {
  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      polynomial_1_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_UnitCiphertextTooLarge) {
  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      polynomial_4_unit_ciphertext_, relinearization_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_UnitCiphertextLevel0) {
  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      level_0_unit_ciphertext_, relinearization_key_,
      "the level of the input unit ciphertext is less than the target level.");
}

TEST_P(
    RejectAdvanced,
    EvaluateChebyshevPolynomialUnitCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_RelinearizationKeyTooSmall) {
  TEST_CHEBYSHEV_UNIT_WITH_KEY(
      duo_intt_unit_ciphertext_, level_0_relinearization_key_,
      "the level of the input unit ciphertext is greater than that of the "
      "input relinearization key.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_CoefficientsTooShort) {
  try {
    std::vector<int64_t> integer_coefficients{};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_unit_ciphertext_, integer_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Evaluate Chebyshev Polynomial With Unit Ciphertext: the input "
        "coefficient is too short.",
        e.what());
  }

  try {
    std::vector<double> double_coefficients{};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_unit_ciphertext_, double_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Evaluate Chebyshev Polynomial With Unit Ciphertext: the input "
        "coefficient is too short.",
        e.what());
  }
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialUnitCiphertext_ConstantCoefficients) {
  try {
    std::vector<int64_t> integer_coefficients{2, 0, 0};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_unit_ciphertext_, integer_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Evaluate Chebyshev Polynomial With Unit Ciphertext: the input "
        "coefficients have only a constant coefficient.",
        e.what());
  }

  try {
    std::vector<double> double_coefficients{2.5, 0.0, 0.0};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_unit_ciphertext_, double_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Evaluate Chebyshev Polynomial With Unit Ciphertext: the input "
        "coefficients have only a constant coefficient.",
        e.what());
  }
}

#define TEST_CHEBYSHEV_WITH_KEY(ciphertext, relinearization_key,               \
                                error_message)                                 \
  try {                                                                        \
    std::vector<int64_t> integer_coefficients(5, 1);                           \
                                                                               \
    engine_->evaluate_chebyshev_polynomial(ciphertext, integer_coefficients,   \
                                           relinearization_key);               \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Evaluate Chebyshev Polynomial With Ciphertext: " error_message,       \
        e.what());                                                             \
  }                                                                            \
                                                                               \
  try {                                                                        \
    std::vector<double> double_coefficients(5, 1.5);                           \
                                                                               \
    engine_->evaluate_chebyshev_polynomial(ciphertext, double_coefficients,    \
                                           relinearization_key);               \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Evaluate Chebyshev Polynomial With Ciphertext: " error_message,       \
        e.what());                                                             \
  }

TEST_P(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_CHEBYSHEV_WITH_KEY(
      incompatible_ciphertext, relinearization_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectAdvanced, EvaluateChebyshevPolynomialCiphertext_CiphertextDuoNTT) {
  TEST_CHEBYSHEV_WITH_KEY(duo_ntt_ciphertext_, relinearization_key_,
                          "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_CiphertextTrioINTT) {
  TEST_CHEBYSHEV_WITH_KEY(trio_intt_ciphertext_, relinearization_key_,
                          "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_CiphertextRescaled) {
  TEST_CHEBYSHEV_WITH_KEY(rescaled_ciphertext_, relinearization_key_,
                          "the input ciphertext should not be rescaled.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_CiphertextTooSmall) {
  TEST_CHEBYSHEV_WITH_KEY(polynomial_1_ciphertext_, relinearization_key_,
                          "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_CiphertextTooLarge) {
  TEST_CHEBYSHEV_WITH_KEY(polynomial_4_ciphertext_, relinearization_key_,
                          "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectAdvanced, EvaluateChebyshevPolynomialCiphertext_CiphertextLevel0) {
  TEST_CHEBYSHEV_WITH_KEY(
      level_0_ciphertext_, relinearization_key_,
      "the level of the input ciphertext is less than the target level.");
}

TEST_P(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_CHEBYSHEV_WITH_KEY(
      duo_intt_ciphertext_, incompatible_relinearization_key,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_RelinearizationKeyTooSmall) {
  TEST_CHEBYSHEV_WITH_KEY(
      duo_intt_ciphertext_, level_0_relinearization_key_,
      "the level of the input ciphertext is greater than that of the "
      "input relinearization key.");
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_CoefficientsTooShort) {
  try {
    std::vector<int64_t> integer_coefficients{};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_ciphertext_, integer_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Chebyshev Polynomial With Ciphertext: the input "
                 "coefficient is too short.",
                 e.what());
  }

  try {
    std::vector<double> double_coefficients{};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_ciphertext_, double_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Chebyshev Polynomial With Ciphertext: the input "
                 "coefficient is too short.",
                 e.what());
  }
}

TEST_F(RejectAdvanced,
       EvaluateChebyshevPolynomialCiphertext_ConstantCoefficients) {
  try {
    std::vector<int64_t> integer_coefficients{2, 0, 0};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_ciphertext_, integer_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Chebyshev Polynomial With Ciphertext: the input "
                 "coefficients have only a constant coefficient.",
                 e.what());
  }

  try {
    std::vector<double> double_coefficients{2.5, 0.0, 0.0};

    engine_->evaluate_chebyshev_polynomial(
        duo_intt_ciphertext_, double_coefficients, relinearization_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Evaluate Chebyshev Polynomial With Ciphertext: the input "
                 "coefficients have only a constant coefficient.",
                 e.what());
  }
}
