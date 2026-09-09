#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectModRaise : public testing::TestWithParam<int> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::for_bootstrap();
    engine_ = new desilo::fhe::CKKSEngine(config);

    const auto scheme_preset = config.scheme_preset_;
    const auto log_slot_count = 15;
    const auto log_coeff_count = 16;
    const auto special_prime_count = 4;

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
    duo_ntt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NTT_FORM, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);

    duo_intt_ciphertext_ =
        new desilo::fhe::Ciphertext({duo_intt_unit_ciphertext_});
    polynomial_1_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_1_unit_ciphertext_});
    polynomial_4_ciphertext_ =
        new desilo::fhe::Ciphertext({polynomial_4_unit_ciphertext_});
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

    int stage_count = 3;
    int inner_loop_shift = 0;
    std::vector<std::pair<desilo::fhe::FixedRotationKey *,
                          desilo::fhe::PermutationParameters *>>
        rotation_contexts;
    std::vector<desilo::fhe::PlainMatrix *> coeff_to_slot_stages = {
        new desilo::fhe::PlainMatrix(), new desilo::fhe::PlainMatrix(),
        new desilo::fhe::PlainMatrix()};
    std::vector<desilo::fhe::PlainMatrix *> slot_to_coeff_stages = {
        new desilo::fhe::PlainMatrix(), new desilo::fhe::PlainMatrix(),
        new desilo::fhe::PlainMatrix()};
    desilo::fhe::KeySwitchingKey *to_sparse = get_dummy_key_switching_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    desilo::fhe::KeySwitchingKey *to_dense =
        get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count, 25);

    small_bootstrap_key_ =
        new desilo::fhe::SmallBootstrapKey(to_sparse, to_dense);

    bootstrap_key_ = new desilo::fhe::BootstrapKey(
        stage_count, inner_loop_shift, rotation_contexts, coeff_to_slot_stages,
        slot_to_coeff_stages, small_bootstrap_key_);

    std::vector<desilo::fhe::KeySwitchingKey *> incompatible_to_sparses = {
        get_dummy_key_switching_key(bad_scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count, 0),
        get_dummy_key_switching_key(scheme_preset, bad_log_slot_count,
                                    log_coeff_count, special_prime_count, 0),
        get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                    bad_log_coeff_count, special_prime_count,
                                    0),
        get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                    log_coeff_count, bad_special_prime_count,
                                    0)};

    std::vector<desilo::fhe::KeySwitchingKey *> incompatible_to_denses = {
        get_dummy_key_switching_key(bad_scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count, 25),
        get_dummy_key_switching_key(scheme_preset, bad_log_slot_count,
                                    log_coeff_count, special_prime_count, 25),
        get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                    bad_log_coeff_count, special_prime_count,
                                    25),
        get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                    log_coeff_count, bad_special_prime_count,
                                    25)};

    for (int index = 0; index < incompatible_to_sparses.size(); index++) {
      incompatible_to_sparse_small_bootstrap_keys_.push_back(
          new desilo::fhe::SmallBootstrapKey(
              incompatible_to_sparses[index],
              get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                          log_coeff_count, special_prime_count,
                                          25)));
    }

    for (int index = 0; index < incompatible_to_denses.size(); index++) {
      incompatible_to_dense_small_bootstrap_keys_.push_back(
          new desilo::fhe::SmallBootstrapKey(
              get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                          log_coeff_count, special_prime_count,
                                          0),
              incompatible_to_denses[index]));
    }

    for (int index = 0; index < incompatible_to_sparses.size(); index++) {
      rotation_contexts = {};
      coeff_to_slot_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      slot_to_coeff_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};

      incompatible_to_sparse_bootstrap_keys_.push_back(
          new desilo::fhe::BootstrapKey(
              stage_count, inner_loop_shift, rotation_contexts,
              coeff_to_slot_stages, slot_to_coeff_stages,
              incompatible_to_sparse_small_bootstrap_keys_[index]));
    }

    for (int index = 0; index < incompatible_to_denses.size(); index++) {
      rotation_contexts = {};
      coeff_to_slot_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      slot_to_coeff_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};

      incompatible_to_dense_bootstrap_keys_.push_back(
          new desilo::fhe::BootstrapKey(
              stage_count, inner_loop_shift, rotation_contexts,
              coeff_to_slot_stages, slot_to_coeff_stages,
              incompatible_to_dense_small_bootstrap_keys_[index]));
    }

    int delta = 1;
    std::vector<desilo::fhe::FixedRotationKey *>
        incompatible_fixed_rotation_keys = {
            get_dummy_fixed_rotation_key(bad_scheme_preset, log_slot_count,
                                         log_coeff_count, special_prime_count,
                                         delta),
            get_dummy_fixed_rotation_key(scheme_preset, bad_log_slot_count,
                                         log_coeff_count, special_prime_count,
                                         delta),
            get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                         bad_log_coeff_count,
                                         special_prime_count, delta),
            get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                         log_coeff_count,
                                         bad_special_prime_count, delta)};

    for (int index = 0; index < incompatible_fixed_rotation_keys.size();
         index++) {
      rotation_contexts = {{incompatible_fixed_rotation_keys[index],
                            new desilo::fhe::PermutationParameters()}};
      coeff_to_slot_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      slot_to_coeff_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      desilo::fhe::KeySwitchingKey *to_sparse =
          get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count, 0);
      desilo::fhe::KeySwitchingKey *to_dense =
          get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count, 25);
      auto small_bootstrap_key =
          new desilo::fhe::SmallBootstrapKey(to_sparse, to_dense);

      incompatible_fixed_rotation_key_bootstrap_keys_.push_back(
          new desilo::fhe::BootstrapKey(
              stage_count, inner_loop_shift, rotation_contexts,
              coeff_to_slot_stages, slot_to_coeff_stages, small_bootstrap_key));
    }

    std::vector<desilo::fhe::UnitPlaintext *> incompatible_unit_plaintexts = {
        get_dummy_unit_plaintext(bad_scheme_preset, log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, bad_log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count,
                                 bad_log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count, log_coeff_count,
                                 bad_special_prime_count),
    };

    for (int index = 0; index < incompatible_unit_plaintexts.size(); index++) {
      rotation_contexts = {};
      coeff_to_slot_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      slot_to_coeff_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      desilo::fhe::KeySwitchingKey *to_sparse =
          get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count, 0);
      desilo::fhe::KeySwitchingKey *to_dense =
          get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count, 25);
      auto small_bootstrap_key =
          new desilo::fhe::SmallBootstrapKey(to_sparse, to_dense);

      coeff_to_slot_stages[0]->encoded_diagonals_[0] = {};
      coeff_to_slot_stages[0]->encoded_diagonals_[0][0] =
          incompatible_unit_plaintexts[index];

      incompatible_coeff_to_slot_bootstrap_keys_.push_back(
          new desilo::fhe::BootstrapKey(
              stage_count, inner_loop_shift, rotation_contexts,
              coeff_to_slot_stages, slot_to_coeff_stages, small_bootstrap_key));
    }

    incompatible_unit_plaintexts = {
        get_dummy_unit_plaintext(bad_scheme_preset, log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, bad_log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count,
                                 bad_log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count, log_coeff_count,
                                 bad_special_prime_count),
    };

    for (int index = 0; index < incompatible_unit_plaintexts.size(); index++) {
      rotation_contexts = {};
      coeff_to_slot_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      slot_to_coeff_stages = {new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix(),
                              new desilo::fhe::PlainMatrix()};
      desilo::fhe::KeySwitchingKey *to_sparse =
          get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count, 0);
      desilo::fhe::KeySwitchingKey *to_dense =
          get_dummy_key_switching_key(scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count, 25);
      auto small_bootstrap_key =
          new desilo::fhe::SmallBootstrapKey(to_sparse, to_dense);

      slot_to_coeff_stages[0]->encoded_diagonals_[0] = {};
      slot_to_coeff_stages[0]->encoded_diagonals_[0][0] =
          incompatible_unit_plaintexts[index];

      incompatible_slot_to_coeff_bootstrap_keys_.push_back(
          new desilo::fhe::BootstrapKey(
              stage_count, inner_loop_shift, rotation_contexts,
              coeff_to_slot_stages, slot_to_coeff_stages, small_bootstrap_key));
    }
  }

  static void TearDownTestSuite() {
    delete duo_intt_ciphertext_;
    delete polynomial_1_ciphertext_;
    delete polynomial_4_ciphertext_;
    delete duo_ntt_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
    delete bootstrap_key_;
    for (auto bootstrap_key : incompatible_to_sparse_bootstrap_keys_) {
      delete bootstrap_key;
    }
    for (auto bootstrap_key : incompatible_to_dense_bootstrap_keys_) {
      delete bootstrap_key;
    }
    for (auto bootstrap_key : incompatible_fixed_rotation_key_bootstrap_keys_) {
      delete bootstrap_key;
    }
    for (auto bootstrap_key : incompatible_coeff_to_slot_bootstrap_keys_) {
      delete bootstrap_key;
    }
    for (auto bootstrap_key : incompatible_slot_to_coeff_bootstrap_keys_) {
      delete bootstrap_key;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitCiphertext *duo_intt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_1_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *polynomial_4_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *duo_ntt_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *duo_ntt_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::SmallBootstrapKey *small_bootstrap_key_;
  static std::vector<desilo::fhe::SmallBootstrapKey *>
      incompatible_to_sparse_small_bootstrap_keys_;
  static std::vector<desilo::fhe::SmallBootstrapKey *>
      incompatible_to_dense_small_bootstrap_keys_;
  static desilo::fhe::BootstrapKey *bootstrap_key_;
  static std::vector<desilo::fhe::BootstrapKey *>
      incompatible_to_sparse_bootstrap_keys_;
  static std::vector<desilo::fhe::BootstrapKey *>
      incompatible_to_dense_bootstrap_keys_;
  static std::vector<desilo::fhe::BootstrapKey *>
      incompatible_fixed_rotation_key_bootstrap_keys_;
  static std::vector<desilo::fhe::BootstrapKey *>
      incompatible_coeff_to_slot_bootstrap_keys_;
  static std::vector<desilo::fhe::BootstrapKey *>
      incompatible_slot_to_coeff_bootstrap_keys_;
};

desilo::fhe::CKKSEngine *RejectModRaise::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectModRaise::duo_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectModRaise::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectModRaise::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectModRaise::duo_ntt_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectModRaise::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectModRaise::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectModRaise::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectModRaise::duo_ntt_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectModRaise::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectModRaise::incompatible_ciphertexts_;
desilo::fhe::SmallBootstrapKey *RejectModRaise::small_bootstrap_key_ = nullptr;
std::vector<desilo::fhe::SmallBootstrapKey *>
    RejectModRaise::incompatible_to_sparse_small_bootstrap_keys_;
std::vector<desilo::fhe::SmallBootstrapKey *>
    RejectModRaise::incompatible_to_dense_small_bootstrap_keys_;
desilo::fhe::BootstrapKey *RejectModRaise::bootstrap_key_ = nullptr;
std::vector<desilo::fhe::BootstrapKey *>
    RejectModRaise::incompatible_to_sparse_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectModRaise::incompatible_to_dense_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectModRaise::incompatible_fixed_rotation_key_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectModRaise::incompatible_coeff_to_slot_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectModRaise::incompatible_slot_to_coeff_bootstrap_keys_;

INSTANTIATE_TEST_CASE_P(, RejectModRaise, testing::Values(0, 1, 2, 3));

#define TEST_SMALL(ciphertext, small_bootstrap_key, error_message)             \
  try {                                                                        \
    engine_->mod_raise(ciphertext, small_bootstrap_key);                       \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Mod Raise With Small Bootstrap Key: " error_message,         \
                 e.what());                                                    \
  }

TEST_F(RejectModRaise, Small_EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    engine.mod_raise(duo_intt_ciphertext_, small_bootstrap_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Mod Raise With Small Bootstrap Key: this engine does not "
                 "support the bootstrap operation.",
                 e.what());
  }
}

TEST_P(RejectModRaise, Small_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_SMALL(incompatible_ciphertext, small_bootstrap_key_,
             "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectModRaise, Small_CiphertextNTT) {
  TEST_SMALL(duo_ntt_ciphertext_, small_bootstrap_key_,
             "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectModRaise, Small_CiphertextTooSmall) {
  TEST_SMALL(polynomial_1_ciphertext_, small_bootstrap_key_,
             "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectModRaise, Small_CiphertextTooLarge) {
  TEST_SMALL(polynomial_4_ciphertext_, small_bootstrap_key_,
             "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectModRaise, Small_SmallBootstrapKeyNotCompatibleSwitchKeyToSparse) {
  auto incompatible_small_bootstrap_key =
      incompatible_to_sparse_small_bootstrap_keys_[GetParam()];

  TEST_SMALL(
      duo_intt_ciphertext_, incompatible_small_bootstrap_key,
      "the input small bootstrap key is not compatible with this engine.");
}

TEST_P(RejectModRaise,
       Small_SmallBootstrapKeyNotCompatibleSwitchKeyBackToDense) {
  auto incompatible_small_bootstrap_key =
      incompatible_to_dense_small_bootstrap_keys_[GetParam()];

  TEST_SMALL(
      duo_intt_ciphertext_, incompatible_small_bootstrap_key,
      "the input small bootstrap key is not compatible with this engine.");
}

#define TEST_MEDIUM(ciphertext, bootstrap_key, error_message)                  \
  try {                                                                        \
    engine_->mod_raise(ciphertext, bootstrap_key);                             \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Mod Raise With Bootstrap Key: " error_message, e.what());    \
  }

TEST_F(RejectModRaise, Medium_EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    engine.mod_raise(duo_intt_ciphertext_, bootstrap_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Mod Raise With Bootstrap Key: this engine does not support "
                 "the bootstrap operation.",
                 e.what());
  }
}

TEST_P(RejectModRaise, Medium_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_MEDIUM(incompatible_ciphertext, bootstrap_key_,
              "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectModRaise, Medium_CiphertextNTT) {
  TEST_MEDIUM(duo_ntt_ciphertext_, bootstrap_key_,
              "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectModRaise, Medium_CiphertextTooSmall) {
  TEST_MEDIUM(polynomial_1_ciphertext_, bootstrap_key_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectModRaise, Medium_CiphertextTooLarge) {
  TEST_MEDIUM(polynomial_4_ciphertext_, bootstrap_key_,
              "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectModRaise, Medium_BootstrapKeyNotCompatibleFixedRotationKey) {
  auto incompatible_bootstrap_key =
      incompatible_fixed_rotation_key_bootstrap_keys_[GetParam()];

  TEST_MEDIUM(duo_intt_ciphertext_, incompatible_bootstrap_key,
              "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectModRaise,
       Medium_BootstrapKeyNotCompatibleCoeffToSlotEncodedTwiddle) {
  auto incompatible_bootstrap_key =
      incompatible_coeff_to_slot_bootstrap_keys_[GetParam()];

  TEST_MEDIUM(duo_intt_ciphertext_, incompatible_bootstrap_key,
              "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectModRaise,
       Medium_BootstrapKeyNotCompatibleSlotToCoeffEncodedTwiddle) {
  auto incompatible_bootstrap_key =
      incompatible_slot_to_coeff_bootstrap_keys_[GetParam()];

  TEST_MEDIUM(duo_intt_ciphertext_, incompatible_bootstrap_key,
              "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectModRaise, Medium_BootstrapKeyNotCompatibleSwitchKeyToSparse) {
  auto incompatible_bootstrap_key =
      incompatible_to_sparse_bootstrap_keys_[GetParam()];

  TEST_MEDIUM(duo_intt_ciphertext_, incompatible_bootstrap_key,
              "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectModRaise, Medium_BootstrapKeyNotCompatibleSwitchKeyBackToDense) {
  auto incompatible_bootstrap_key =
      incompatible_to_dense_bootstrap_keys_[GetParam()];

  TEST_MEDIUM(duo_intt_ciphertext_, incompatible_bootstrap_key,
              "the input bootstrap key is not compatible with this engine.");
}
