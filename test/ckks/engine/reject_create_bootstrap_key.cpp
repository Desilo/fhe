#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"

class RejectCreateBootstrapKey : public testing::TestWithParam<int> {
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
    sparse_secret_key_ = get_dummy_secret_key(scheme_preset, 5, log_coeff_count,
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
    delete sparse_secret_key_;
    delete level_0_secret_key_;
    for (auto secret_key : incompatible_secret_keys_) {
      delete secret_key;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::SecretKey *sparse_secret_key_;
  static desilo::fhe::SecretKey *level_0_secret_key_;
  static std::vector<desilo::fhe::SecretKey *> incompatible_secret_keys_;
};

desilo::fhe::CKKSEngine *RejectCreateBootstrapKey::engine_ = nullptr;
desilo::fhe::SecretKey *RejectCreateBootstrapKey::secret_key_ = nullptr;
desilo::fhe::SecretKey *RejectCreateBootstrapKey::level_0_secret_key_ = nullptr;
desilo::fhe::SecretKey *RejectCreateBootstrapKey::sparse_secret_key_ = nullptr;
std::vector<desilo::fhe::SecretKey *>
    RejectCreateBootstrapKey::incompatible_secret_keys_;

INSTANTIATE_TEST_CASE_P(, RejectCreateBootstrapKey, testing::Range(0, 4));

TEST_F(RejectCreateBootstrapKey, EngineNotBootstrap) {
  auto engine = desilo::fhe::CKKSEngine();
  try {
    int stage_count = 3;
    engine.create_bootstrap_key(secret_key_, stage_count, "medium");
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Bootstrap Key: this engine does not support the "
                 "bootstrap operation.",
                 e.what());
  }
}

TEST_F(RejectCreateBootstrapKey, SecretKeyTooSmall) {
  try {
    int stage_count = 3;
    engine_->create_bootstrap_key(level_0_secret_key_, stage_count, "medium");
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Bootstrap Key: the target level cannot be reached "
                 "with the provided keys.",
                 e.what());
  }
}

TEST_P(RejectCreateBootstrapKey, SecretKeyNotCompatible) {
  auto incompatible_secret_key = incompatible_secret_keys_[GetParam()];
  try {
    int stage_count = 3;
    engine_->create_bootstrap_key(incompatible_secret_key, stage_count,
                                  "medium");
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Bootstrap Key: the input secret key is not compatible "
                 "with this engine.",
                 e.what());
  }
}

TEST_F(RejectCreateBootstrapKey, InvalidStageCount) {
  try {
    int stage_count = 6;
    engine_->create_bootstrap_key(secret_key_, stage_count, "medium");
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Bootstrap Key: invalid stage count.", e.what());
  }
}

TEST_F(RejectCreateBootstrapKey, SparseMedium_InvalidStageCount) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_slot_count_ = 5;
  auto engine = desilo::fhe::CKKSEngine(config);

  try {
    int stage_count = 3;
    engine.create_bootstrap_key(sparse_secret_key_, stage_count, "medium");
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Bootstrap Key: invalid stage count.", e.what());
  }
}

TEST_F(RejectCreateBootstrapKey, SparseLarge_InvalidStageCount) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_slot_count_ = 5;
  auto engine = desilo::fhe::CKKSEngine(config);

  try {
    int stage_count = 2;
    engine.create_bootstrap_key(sparse_secret_key_, stage_count, "large");
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Bootstrap Key: invalid stage count.", e.what());
  }
}

TEST_F(RejectCreateBootstrapKey, InvalidSize) {
  try {
    int stage_count = 3;
    engine_->create_bootstrap_key(secret_key_, stage_count, "small");
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Bootstrap Key: invalid size.", e.what());
  }
}
