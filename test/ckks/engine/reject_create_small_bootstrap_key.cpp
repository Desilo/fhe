#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"

class RejectCreateSmallBootstrapKey : public testing::TestWithParam<int> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::for_bootstrap();
    engine_ = new desilo::fhe::CKKSEngine(config);

    const auto scheme_preset = config.scheme_preset_;
    const auto log_slot_count = 15;
    const auto log_coeff_count = 16;
    const auto special_prime_count = 4;

    const auto bad_scheme_preset = desilo::fhe::SchemePreset::NONE;
    const auto bad_log_slot_count = 12;
    const auto bad_log_coeff_count = 13;
    const auto bad_special_prime_count = 2;

    secret_key_ =
        get_dummy_secret_key(scheme_preset, log_slot_count, log_coeff_count,
                             special_prime_count, 25);
    level_0_secret_key_ = get_dummy_secret_key(
        scheme_preset, log_slot_count, log_coeff_count, special_prime_count, 0);
    incompatible_secret_keys_ = {
        get_dummy_secret_key(bad_scheme_preset, log_slot_count, log_coeff_count,
                             special_prime_count),
        get_dummy_secret_key(scheme_preset, bad_log_slot_count, log_coeff_count,
                             special_prime_count),
        get_dummy_secret_key(scheme_preset, log_slot_count, bad_log_coeff_count,
                             special_prime_count),
        get_dummy_secret_key(scheme_preset, log_slot_count, log_coeff_count,
                             bad_special_prime_count)};
  }

  static void TearDownTestSuite() {
    delete engine_;
    delete secret_key_;
    delete level_0_secret_key_;
    for (auto secret_key : incompatible_secret_keys_) {
      delete secret_key;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::SecretKey *level_0_secret_key_;
  static std::vector<desilo::fhe::SecretKey *> incompatible_secret_keys_;
};

desilo::fhe::CKKSEngine *RejectCreateSmallBootstrapKey::engine_ = nullptr;
desilo::fhe::SecretKey *RejectCreateSmallBootstrapKey::secret_key_ = nullptr;
desilo::fhe::SecretKey *RejectCreateSmallBootstrapKey::level_0_secret_key_ =
    nullptr;
std::vector<desilo::fhe::SecretKey *>
    RejectCreateSmallBootstrapKey::incompatible_secret_keys_;

INSTANTIATE_TEST_CASE_P(, RejectCreateSmallBootstrapKey, testing::Range(0, 4));

TEST_F(RejectCreateSmallBootstrapKey, EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    engine.create_small_bootstrap_key(secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Small Bootstrap Key: this engine does not support the "
                 "bootstrap operation.",
                 e.what());
  }
}

TEST_F(RejectCreateSmallBootstrapKey, SecretKeyTooSmall) {
  try {
    engine_->create_small_bootstrap_key(level_0_secret_key_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Small Bootstrap Key: the target level cannot be "
                 "reached with the provided keys.",
                 e.what());
  }
}

TEST_P(RejectCreateSmallBootstrapKey, SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  try {
    engine_->create_small_bootstrap_key(incompatible_secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Small Bootstrap Key: the input secret key is not "
                 "compatible with this engine.",
                 e.what());
  }
}
