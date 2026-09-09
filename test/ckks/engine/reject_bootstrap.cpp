#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectBootstrap : public testing::TestWithParam<int> {
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
    rescaled_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::RESCALED, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    duo_ntt_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NTT_FORM, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2);
    scaled_unit_ciphertext_ = get_dummy_flagged_unit_ciphertext(
        desilo::fhe::DataFlag::NONE, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count, 2, 7, 2.0);

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
    scaled_ciphertext_ = new desilo::fhe::Ciphertext({scaled_unit_ciphertext_});

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

    int key_level = 22;
    relinearization_key_ = get_dummy_relinearization_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count,
        key_level);
    level_0_relinearization_key_ = get_dummy_relinearization_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_relinearization_keys_ = {
        get_dummy_relinearization_key(bad_scheme_preset, log_slot_count,
                                      log_coeff_count, special_prime_count,
                                      key_level),
        get_dummy_relinearization_key(scheme_preset, bad_log_slot_count,
                                      log_coeff_count, special_prime_count,
                                      key_level),
        get_dummy_relinearization_key(scheme_preset, log_slot_count,
                                      bad_log_coeff_count, special_prime_count,
                                      key_level),
        get_dummy_relinearization_key(scheme_preset, log_slot_count,
                                      log_coeff_count, bad_special_prime_count,
                                      key_level)};

    conjugation_key_ = get_dummy_conjugation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count,
        key_level);
    level_0_conjugation_key_ = get_dummy_conjugation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_conjugation_keys_ = {
        get_dummy_conjugation_key(bad_scheme_preset, log_slot_count,
                                  log_coeff_count, special_prime_count,
                                  key_level),
        get_dummy_conjugation_key(scheme_preset, bad_log_slot_count,
                                  log_coeff_count, special_prime_count,
                                  key_level),
        get_dummy_conjugation_key(scheme_preset, log_slot_count,
                                  bad_log_coeff_count, special_prime_count,
                                  key_level),
        get_dummy_conjugation_key(scheme_preset, log_slot_count,
                                  log_coeff_count, bad_special_prime_count,
                                  key_level)};

    int delta = 1;
    fixed_rotation_key_ = get_dummy_fixed_rotation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count,
        delta, key_level + 3);
    level_0_fixed_rotation_key_ = get_dummy_fixed_rotation_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count,
        delta, 0);
    incompatible_fixed_rotation_keys_ = {
        get_dummy_fixed_rotation_key(bad_scheme_preset, log_slot_count,
                                     log_coeff_count, special_prime_count,
                                     delta, key_level),
        get_dummy_fixed_rotation_key(scheme_preset, bad_log_slot_count,
                                     log_coeff_count, special_prime_count,
                                     delta, key_level),
        get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                     bad_log_coeff_count, special_prime_count,
                                     delta, key_level),
        get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                     log_coeff_count, bad_special_prime_count,
                                     delta, key_level)};

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

    std::vector<desilo::fhe::FixedRotationKey *>
        incompatible_fixed_rotation_keys = {
            get_dummy_fixed_rotation_key(bad_scheme_preset, log_slot_count,
                                         log_coeff_count, special_prime_count,
                                         delta, 25),
            get_dummy_fixed_rotation_key(scheme_preset, bad_log_slot_count,
                                         log_coeff_count, special_prime_count,
                                         delta, 25),
            get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                         bad_log_coeff_count,
                                         special_prime_count, delta, 25),
            get_dummy_fixed_rotation_key(scheme_preset, log_slot_count,
                                         log_coeff_count,
                                         bad_special_prime_count, delta, 25)};

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
    delete rescaled_ciphertext_;
    delete duo_ntt_ciphertext_;
    delete scaled_ciphertext_;
    for (auto ciphertext : incompatible_ciphertexts_) {
      delete ciphertext;
    }
    delete relinearization_key_;
    delete level_0_relinearization_key_;
    for (auto relinearization_key : incompatible_relinearization_keys_) {
      delete relinearization_key;
    }
    delete conjugation_key_;
    delete level_0_conjugation_key_;
    for (auto conjugation_key : incompatible_conjugation_keys_) {
      delete conjugation_key;
    }
    delete rotation_key_;
    delete level_0_rotation_key_;
    for (auto rotation_key : incompatible_rotation_keys_) {
      delete rotation_key;
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
  static desilo::fhe::UnitCiphertext *rescaled_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *duo_ntt_unit_ciphertext_;
  static desilo::fhe::UnitCiphertext *scaled_unit_ciphertext_;
  static desilo::fhe::Ciphertext *duo_intt_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_1_ciphertext_;
  static desilo::fhe::Ciphertext *polynomial_4_ciphertext_;
  static desilo::fhe::Ciphertext *rescaled_ciphertext_;
  static desilo::fhe::Ciphertext *duo_ntt_ciphertext_;
  static desilo::fhe::Ciphertext *scaled_ciphertext_;
  static std::vector<desilo::fhe::UnitCiphertext *>
      incompatible_unit_ciphertexts_;
  static std::vector<desilo::fhe::Ciphertext *> incompatible_ciphertexts_;
  static desilo::fhe::RelinearizationKey *relinearization_key_;
  static desilo::fhe::RelinearizationKey *level_0_relinearization_key_;
  static std::vector<desilo::fhe::RelinearizationKey *>
      incompatible_relinearization_keys_;
  static desilo::fhe::ConjugationKey *conjugation_key_;
  static desilo::fhe::ConjugationKey *level_0_conjugation_key_;
  static std::vector<desilo::fhe::ConjugationKey *>
      incompatible_conjugation_keys_;
  static desilo::fhe::FixedRotationKey *fixed_rotation_key_;
  static desilo::fhe::FixedRotationKey *level_0_fixed_rotation_key_;
  static std::vector<desilo::fhe::FixedRotationKey *>
      incompatible_fixed_rotation_keys_;
  static desilo::fhe::RotationKey *rotation_key_;
  static desilo::fhe::RotationKey *level_0_rotation_key_;
  static std::vector<desilo::fhe::RotationKey *> incompatible_rotation_keys_;
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

desilo::fhe::CKKSEngine *RejectBootstrap::engine_ = nullptr;
desilo::fhe::UnitCiphertext *RejectBootstrap::duo_intt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectBootstrap::polynomial_1_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectBootstrap::polynomial_4_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectBootstrap::rescaled_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectBootstrap::duo_ntt_unit_ciphertext_ =
    nullptr;
desilo::fhe::UnitCiphertext *RejectBootstrap::scaled_unit_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectBootstrap::duo_intt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectBootstrap::polynomial_1_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectBootstrap::polynomial_4_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectBootstrap::rescaled_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectBootstrap::duo_ntt_ciphertext_ = nullptr;
desilo::fhe::Ciphertext *RejectBootstrap::scaled_ciphertext_ = nullptr;
std::vector<desilo::fhe::UnitCiphertext *>
    RejectBootstrap::incompatible_unit_ciphertexts_;
std::vector<desilo::fhe::Ciphertext *>
    RejectBootstrap::incompatible_ciphertexts_;
desilo::fhe::RelinearizationKey *RejectBootstrap::relinearization_key_ =
    nullptr;
desilo::fhe::RelinearizationKey *RejectBootstrap::level_0_relinearization_key_ =
    nullptr;
std::vector<desilo::fhe::RelinearizationKey *>
    RejectBootstrap::incompatible_relinearization_keys_;
desilo::fhe::ConjugationKey *RejectBootstrap::conjugation_key_ = nullptr;
desilo::fhe::ConjugationKey *RejectBootstrap::level_0_conjugation_key_ =
    nullptr;
std::vector<desilo::fhe::ConjugationKey *>
    RejectBootstrap::incompatible_conjugation_keys_;
desilo::fhe::FixedRotationKey *RejectBootstrap::fixed_rotation_key_ = nullptr;
desilo::fhe::FixedRotationKey *RejectBootstrap::level_0_fixed_rotation_key_ =
    nullptr;
std::vector<desilo::fhe::FixedRotationKey *>
    RejectBootstrap::incompatible_fixed_rotation_keys_;
desilo::fhe::RotationKey *RejectBootstrap::rotation_key_ = nullptr;
desilo::fhe::RotationKey *RejectBootstrap::level_0_rotation_key_ = nullptr;
std::vector<desilo::fhe::RotationKey *>
    RejectBootstrap::incompatible_rotation_keys_;
desilo::fhe::SmallBootstrapKey *RejectBootstrap::small_bootstrap_key_ = nullptr;
std::vector<desilo::fhe::SmallBootstrapKey *>
    RejectBootstrap::incompatible_to_sparse_small_bootstrap_keys_;
std::vector<desilo::fhe::SmallBootstrapKey *>
    RejectBootstrap::incompatible_to_dense_small_bootstrap_keys_;
desilo::fhe::BootstrapKey *RejectBootstrap::bootstrap_key_ = nullptr;
std::vector<desilo::fhe::BootstrapKey *>
    RejectBootstrap::incompatible_to_sparse_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectBootstrap::incompatible_to_dense_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectBootstrap::incompatible_fixed_rotation_key_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectBootstrap::incompatible_coeff_to_slot_bootstrap_keys_;
std::vector<desilo::fhe::BootstrapKey *>
    RejectBootstrap::incompatible_slot_to_coeff_bootstrap_keys_;

INSTANTIATE_TEST_CASE_P(, RejectBootstrap, testing::Values(0, 1, 2));

#define TEST_UNIT_WITH_ROTATION_KEY(unit_ciphertext, relinearization_key,      \
                                    conjugation_key, rotation_key,             \
                                    small_bootstrap_key, error_message)        \
  try {                                                                        \
    engine_->bootstrap(unit_ciphertext, relinearization_key, conjugation_key,  \
                       rotation_key, small_bootstrap_key);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Bootstrap Unit Ciphertext With Rotation Key: " error_message,         \
        e.what());                                                             \
  }

TEST_F(RejectBootstrap, UnitWithRotationKey_EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    engine.bootstrap(duo_intt_unit_ciphertext_, relinearization_key_,
                     conjugation_key_, rotation_key_, small_bootstrap_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Bootstrap Unit Ciphertext With Rotation Key: this engine does not "
        "support the bootstrap operation.",
        e.what());
  }
}

TEST_P(RejectBootstrap, UnitWithRotationKey_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_WITH_ROTATION_KEY(
      incompatible_unit_ciphertext, relinearization_key_, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithRotationKey_UnitCiphertextNTT) {
  TEST_UNIT_WITH_ROTATION_KEY(
      duo_ntt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectBootstrap, UnitWithRotationKey_UnitCiphertextTooSmall) {
  TEST_UNIT_WITH_ROTATION_KEY(
      polynomial_1_unit_ciphertext_, relinearization_key_, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectBootstrap, UnitWithRotationKey_UnitCiphertextTooLarge) {
  TEST_UNIT_WITH_ROTATION_KEY(
      polynomial_4_unit_ciphertext_, relinearization_key_, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the input unit ciphertext should have 2 polynomials.");
}

TEST_P(RejectBootstrap, UnitWithRotationKey_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, incompatible_relinearization_key,
      conjugation_key_, rotation_key_, small_bootstrap_key_,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithRotationKey_RelinearizationKeyTooSmall) {
  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, level_0_relinearization_key_, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the level of the input relinearization key is too low.");
}

TEST_P(RejectBootstrap, UnitWithRotationKey_ConjugationKeyNotCompatible) {
  auto incompatible_conjugation_key =
      incompatible_conjugation_keys_[GetParam()];

  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_,
      incompatible_conjugation_key, rotation_key_, small_bootstrap_key_,
      "the input conjugation key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithRotationKey_ConjugationKeyTooSmall) {
  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, level_0_conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the level of the input conjugation key is too low.");
}

TEST_P(RejectBootstrap, UnitWithRotationKey_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_rotation_key, small_bootstrap_key_,
      "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithRotationKey_RotationKeyTooSmall) {
  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      level_0_rotation_key_, small_bootstrap_key_,
      "the level of the input rotation key is too low.");
}

TEST_P(RejectBootstrap,
       UnitWithRotationKey_SmallBootstrapKeyNotCompatibleSwitchKeyToSparse) {
  auto incompatible_small_bootstrap_key =
      incompatible_to_sparse_small_bootstrap_keys_[GetParam()];

  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      rotation_key_, incompatible_small_bootstrap_key,
      "the input small bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       UnitWithRotationKey_SmallBootstrapKeyNotCompatibleSwitchKeyBackToDense) {
  auto incompatible_small_bootstrap_key =
      incompatible_to_dense_small_bootstrap_keys_[GetParam()];

  TEST_UNIT_WITH_ROTATION_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      rotation_key_, incompatible_small_bootstrap_key,
      "the input small bootstrap key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithRotationKey_InvalidStageCount) {
  try {
    int stage_count = 6;
    engine_->bootstrap(duo_intt_unit_ciphertext_, relinearization_key_,
                       conjugation_key_, rotation_key_, small_bootstrap_key_,
                       stage_count);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Bootstrap Unit Ciphertext With Rotation Key: invalid stage count.",
        e.what());
  }
}

#define TEST_UNIT_WITH_BOOTSTRAP_KEY(unit_ciphertext, relinearization_key,     \
                                     conjugation_key, bootstrap_key,           \
                                     error_message)                            \
  try {                                                                        \
    engine_->bootstrap(unit_ciphertext, relinearization_key, conjugation_key,  \
                       bootstrap_key);                                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Bootstrap Unit Ciphertext With Bootstrap Key: " error_message,        \
        e.what());                                                             \
  }

TEST_F(RejectBootstrap, UnitWithBootstrapKey_EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    engine.bootstrap(duo_intt_unit_ciphertext_, relinearization_key_,
                     conjugation_key_, bootstrap_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Bootstrap Unit Ciphertext With Bootstrap Key: this engine does "
        "not support the bootstrap operation.",
        e.what());
  }
}

TEST_P(RejectBootstrap, UnitWithBootstrapKey_UnitCiphertextNotCompatible) {
  auto incompatible_unit_ciphertext =
      incompatible_unit_ciphertexts_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      incompatible_unit_ciphertext, relinearization_key_, conjugation_key_,
      bootstrap_key_,
      "the input unit ciphertext is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithBootstrapKey_UnitCiphertextNTT) {
  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_ntt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      bootstrap_key_, "the input unit ciphertext should not be in NTT form.");
}

TEST_F(RejectBootstrap, UnitWithBootstrapKey_UnitCiphertextTooSmall) {
  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      polynomial_1_unit_ciphertext_, relinearization_key_, conjugation_key_,
      bootstrap_key_, "the input unit ciphertext should have 2 polynomials.");
}

TEST_F(RejectBootstrap, UnitWithBootstrapKey_UnitCiphertextTooLarge) {
  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      polynomial_4_unit_ciphertext_, relinearization_key_, conjugation_key_,
      bootstrap_key_, "the input unit ciphertext should have 2 polynomials.");
}

TEST_P(RejectBootstrap, UnitWithBootstrapKey_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, incompatible_relinearization_key,
      conjugation_key_, bootstrap_key_,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithBootstrapKey_RelinearizationKeyTooSmall) {
  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, level_0_relinearization_key_, conjugation_key_,
      bootstrap_key_, "the level of the input relinearization key is too low.");
}

TEST_P(RejectBootstrap, UnitWithBootstrapKey_ConjugationKeyNotCompatible) {
  auto incompatible_conjugation_key =
      incompatible_conjugation_keys_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_,
      incompatible_conjugation_key, bootstrap_key_,
      "the input conjugation key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, UnitWithBootstrapKey_ConjugationKeyTooSmall) {
  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, level_0_conjugation_key_,
      bootstrap_key_, "the level of the input conjugation key is too low.");
}

TEST_P(RejectBootstrap,
       UnitWithBootstrapKey_BootstrapKeyNotCompatibleFixedRotationKey) {
  auto incompatible_bootstrap_key =
      incompatible_fixed_rotation_key_bootstrap_keys_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(
    RejectBootstrap,
    UnitWithBootstrapKey_BootstrapKeyNotCompatibleCoeffToSlotEncodedTwiddle) {
  auto incompatible_bootstrap_key =
      incompatible_coeff_to_slot_bootstrap_keys_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(
    RejectBootstrap,
    UnitWithBootstrapKey_BootstrapKeyNotCompatibleSlotToCoeffEncodedTwiddle) {
  auto incompatible_bootstrap_key =
      incompatible_slot_to_coeff_bootstrap_keys_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       UnitWithBootstrapKey_BootstrapKeyNotCompatibleSwitchKeyToSparse) {
  auto incompatible_bootstrap_key =
      incompatible_to_sparse_bootstrap_keys_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       UnitWithBootstrapKey_BootstrapKeyNotCompatibleSwitchKeyBackToDense) {
  auto incompatible_bootstrap_key =
      incompatible_to_dense_bootstrap_keys_[GetParam()];

  TEST_UNIT_WITH_BOOTSTRAP_KEY(
      duo_intt_unit_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

#define TEST_WITH_ROTATION_KEY(ciphertext, relinearization_key,                \
                               conjugation_key, rotation_key,                  \
                               small_bootstrap_key, error_message)             \
  try {                                                                        \
    engine_->bootstrap(ciphertext, relinearization_key, conjugation_key,       \
                       rotation_key, small_bootstrap_key);                     \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Bootstrap Ciphertext With Rotation Key: " error_message,     \
                 e.what());                                                    \
  }

TEST_F(RejectBootstrap, WithRotationKey_EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    engine.bootstrap(duo_intt_ciphertext_, relinearization_key_,
                     conjugation_key_, rotation_key_, small_bootstrap_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Bootstrap Ciphertext With Rotation Key: this engine "
                 "does not support the bootstrap operation.",
                 e.what());
  }
}

TEST_P(RejectBootstrap, WithRotationKey_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_WITH_ROTATION_KEY(
      incompatible_ciphertext, relinearization_key_, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithRotationKey_CiphertextNTT) {
  TEST_WITH_ROTATION_KEY(duo_ntt_ciphertext_, relinearization_key_,
                         conjugation_key_, rotation_key_, small_bootstrap_key_,
                         "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectBootstrap, WithRotationKey_CiphertextTooSmall) {
  TEST_WITH_ROTATION_KEY(polynomial_1_ciphertext_, relinearization_key_,
                         conjugation_key_, rotation_key_, small_bootstrap_key_,
                         "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectBootstrap, WithRotationKey_CiphertextTooLarge) {
  TEST_WITH_ROTATION_KEY(polynomial_4_ciphertext_, relinearization_key_,
                         conjugation_key_, rotation_key_, small_bootstrap_key_,
                         "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectBootstrap, WithRotationKey_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_WITH_ROTATION_KEY(
      duo_intt_ciphertext_, incompatible_relinearization_key, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithRotationKey_RelinearizationKeyTooSmall) {
  TEST_WITH_ROTATION_KEY(
      duo_intt_ciphertext_, level_0_relinearization_key_, conjugation_key_,
      rotation_key_, small_bootstrap_key_,
      "the level of the input relinearization key is too low.");
}

TEST_P(RejectBootstrap, WithRotationKey_ConjugationKeyNotCompatible) {
  auto incompatible_conjugation_key =
      incompatible_conjugation_keys_[GetParam()];

  TEST_WITH_ROTATION_KEY(
      duo_intt_ciphertext_, relinearization_key_, incompatible_conjugation_key,
      rotation_key_, small_bootstrap_key_,
      "the input conjugation key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithRotationKey_ConjugationKeyTooSmall) {
  TEST_WITH_ROTATION_KEY(duo_intt_ciphertext_, relinearization_key_,
                         level_0_conjugation_key_, rotation_key_,
                         small_bootstrap_key_,
                         "the level of the input conjugation key is too low.");
}

TEST_P(RejectBootstrap, WithRotationKey_RotationKeyNotCompatible) {
  auto incompatible_rotation_key = incompatible_rotation_keys_[GetParam()];

  TEST_WITH_ROTATION_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_rotation_key, small_bootstrap_key_,
      "the input rotation key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithRotationKey_RotationKeyTooSmall) {
  TEST_WITH_ROTATION_KEY(duo_intt_ciphertext_, relinearization_key_,
                         conjugation_key_, level_0_rotation_key_,
                         small_bootstrap_key_,
                         "the level of the input rotation key is too low.");
}

TEST_P(RejectBootstrap,
       WithRotationKey_SmallBootstrapKeyNotCompatibleSwitchKeyToSparse) {
  auto incompatible_small_bootstrap_key =
      incompatible_to_sparse_small_bootstrap_keys_[GetParam()];

  TEST_WITH_ROTATION_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      rotation_key_, incompatible_small_bootstrap_key,
      "the input small bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       WithRotationKey_SmallBootstrapKeyNotCompatibleSwitchKeyBackToDense) {
  auto incompatible_small_bootstrap_key =
      incompatible_to_dense_small_bootstrap_keys_[GetParam()];

  TEST_WITH_ROTATION_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      rotation_key_, incompatible_small_bootstrap_key,
      "the input small bootstrap key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithRotationKey_InvalidStageCount) {
  try {
    int stage_count = 6;
    engine_->bootstrap(duo_intt_ciphertext_, relinearization_key_,
                       conjugation_key_, rotation_key_, small_bootstrap_key_,
                       stage_count);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Bootstrap Ciphertext With Rotation Key: invalid stage count.",
                 e.what());
  }
}

#define TEST_WITH_BOOTSTRAP_KEY(ciphertext, relinearization_key,               \
                                conjugation_key, bootstrap_key, error_message) \
  try {                                                                        \
    engine_->bootstrap(ciphertext, relinearization_key, conjugation_key,       \
                       bootstrap_key);                                         \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Bootstrap Ciphertext With Bootstrap Key: " error_message,    \
                 e.what());                                                    \
  }

TEST_F(RejectBootstrap, WithBootstrapKey_EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    engine.bootstrap(duo_intt_ciphertext_, relinearization_key_,
                     conjugation_key_, bootstrap_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Bootstrap Ciphertext With Bootstrap Key: this engine "
                 "does not support the bootstrap operation.",
                 e.what());
  }
}

TEST_P(RejectBootstrap, WithBootstrapKey_CiphertextNotCompatible) {
  auto incompatible_ciphertext = incompatible_ciphertexts_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      incompatible_ciphertext, relinearization_key_, conjugation_key_,
      bootstrap_key_,
      "the input ciphertext is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithBootstrapKey_CiphertextNTT) {
  TEST_WITH_BOOTSTRAP_KEY(duo_ntt_ciphertext_, relinearization_key_,
                          conjugation_key_, bootstrap_key_,
                          "the input ciphertext should not be in NTT form.");
}

TEST_F(RejectBootstrap, WithBootstrapKey_CiphertextTooSmall) {
  TEST_WITH_BOOTSTRAP_KEY(polynomial_1_ciphertext_, relinearization_key_,
                          conjugation_key_, bootstrap_key_,
                          "the input ciphertext should have 2 polynomials.");
}

TEST_F(RejectBootstrap, WithBootstrapKey_CiphertextTooLarge) {
  TEST_WITH_BOOTSTRAP_KEY(polynomial_4_ciphertext_, relinearization_key_,
                          conjugation_key_, bootstrap_key_,
                          "the input ciphertext should have 2 polynomials.");
}

TEST_P(RejectBootstrap, WithBootstrapKey_RelinearizationKeyNotCompatible) {
  auto incompatible_relinearization_key =
      incompatible_relinearization_keys_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, incompatible_relinearization_key, conjugation_key_,
      bootstrap_key_,
      "the input relinearization key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithBootstrapKey_RelinearizationKeyTooSmall) {
  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, level_0_relinearization_key_, conjugation_key_,
      bootstrap_key_, "the level of the input relinearization key is too low.");
}

TEST_P(RejectBootstrap, WithBootstrapKey_ConjugationKeyNotCompatible) {
  auto incompatible_conjugation_key =
      incompatible_conjugation_keys_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, relinearization_key_, incompatible_conjugation_key,
      bootstrap_key_,
      "the input conjugation key is not compatible with this engine.");
}

TEST_F(RejectBootstrap, WithBootstrapKey_ConjugationKeyTooSmall) {
  TEST_WITH_BOOTSTRAP_KEY(duo_intt_ciphertext_, relinearization_key_,
                          level_0_conjugation_key_, bootstrap_key_,
                          "the level of the input conjugation key is too low.");
}

TEST_P(RejectBootstrap,
       WithBootstrapKey_BootstrapKeyNotCompatibleFixedRotationKey) {
  auto incompatible_bootstrap_key =
      incompatible_fixed_rotation_key_bootstrap_keys_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       WithBootstrapKey_BootstrapKeyNotCompatibleCoeffToSlotEncodedTwiddle) {
  auto incompatible_bootstrap_key =
      incompatible_coeff_to_slot_bootstrap_keys_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       WithBootstrapKey_BootstrapKeyNotCompatibleSlotToCoeffEncodedTwiddle) {
  auto incompatible_bootstrap_key =
      incompatible_slot_to_coeff_bootstrap_keys_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       WithBootstrapKey_BootstrapKeyNotCompatibleSwitchKeyToSparse) {
  auto incompatible_bootstrap_key =
      incompatible_to_sparse_bootstrap_keys_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}

TEST_P(RejectBootstrap,
       WithBootstrapKey_BootstrapKeyNotCompatibleSwitchKeyBackToDense) {
  auto incompatible_bootstrap_key =
      incompatible_to_dense_bootstrap_keys_[GetParam()];

  TEST_WITH_BOOTSTRAP_KEY(
      duo_intt_ciphertext_, relinearization_key_, conjugation_key_,
      incompatible_bootstrap_key,
      "the input bootstrap key is not compatible with this engine.");
}
