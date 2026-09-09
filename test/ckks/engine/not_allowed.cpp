#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

const auto log_slot_count = 13;
const auto log_coeff_count = 14;
const auto special_prime_count = 1;
const auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;

class NotAllowed : public testing::Test,
                   public ::testing::WithParamInterface<int> {
public:
  static void SetUpTestSuite() {
    engine_ = new desilo::fhe::CKKSEngine(tier_configs["Sand1"]);
    secret_key_ = engine_->create_secret_key();
    public_key_ = engine_->create_public_key(secret_key_);
    undersized_secret_key_ = engine_->create_secret_key(1);
  }

  static void TearDownTestSuite() {
    delete engine_;
    delete secret_key_;
    delete public_key_;
    delete undersized_secret_key_;
    engine_ = nullptr;
    secret_key_ = nullptr;
    public_key_ = nullptr;
    undersized_secret_key_ = nullptr;
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::PublicKey *public_key_;
  static desilo::fhe::SecretKey *undersized_secret_key_;
};

desilo::fhe::CKKSEngine *NotAllowed::engine_ = nullptr;
desilo::fhe::SecretKey *NotAllowed::secret_key_ = nullptr;
desilo::fhe::PublicKey *NotAllowed::public_key_ = nullptr;
desilo::fhe::SecretKey *NotAllowed::undersized_secret_key_ = nullptr;

INSTANTIATE_TEST_SUITE_P(
    , NotAllowed, testing::Values(-1, 7, 8),
    [](const testing::TestParamInfo<NotAllowed::ParamType> &info) {
      return print_level(info.param);
    });

TEST_P(NotAllowed, LevelOfCreatePublicKey) {
  int level = GetParam();

  if (level == 7) {
    GTEST_SKIP() << "7 is valid";
  }

  try {
    engine_->create_public_key(secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Public Key: the target level cannot be reached "
                 "with the current engine parameters.",
                 e.what());
  }
}

TEST_F(NotAllowed, LevelOfCreatePublicKeyUndersizedSecretKey) {
  int level = engine_->get_max_level();

  try {
    engine_->create_public_key(undersized_secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Public Key: the target level cannot be reached with "
                 "the provided keys.",
                 e.what());
  }
}

TEST_P(NotAllowed, LevelOfCreateRelinearizationKey) {
  int level = GetParam();

  try {
    engine_->create_relinearization_key(secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Create Relinearization Key: the target level cannot be reached "
        "with the current engine parameters.",
        e.what());
  }
}

TEST_F(NotAllowed, LevelOfCreateRelinearizationKeyUndersizedSecretKey) {
  int level = engine_->get_max_level();

  try {
    engine_->create_relinearization_key(undersized_secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Create Relinearization Key: the target level cannot be reached with "
        "the provided keys.",
        e.what());
  }
}

TEST_P(NotAllowed, LevelOfCreateConjugationKey) {
  int level = GetParam();

  try {
    engine_->create_conjugation_key(secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Conjugation Key: the target level cannot be reached "
                 "with the current engine parameters.",
                 e.what());
  }
}

TEST_F(NotAllowed, LevelOfCreateConjugationKeyUndersizedSecretKey) {
  int level = engine_->get_max_level();

  try {
    engine_->create_conjugation_key(undersized_secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Create Conjugation Key: the target level cannot be reached with "
        "the provided keys.",
        e.what());
  }
}

TEST_P(NotAllowed, LevelOfCreateFixedRotationKey) {
  int level = GetParam();
  int delta = 1;

  try {
    engine_->create_fixed_rotation_key(secret_key_, delta, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Create Fixed Rotation Key: the target level cannot be reached "
        "with the current engine parameters.",
        e.what());
  }
}

TEST_F(NotAllowed, LevelOfCreateFixedRotationKeyUndersizedSecretKey) {
  int level = engine_->get_max_level();
  int delta = 1;

  try {
    engine_->create_fixed_rotation_key(undersized_secret_key_, delta, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ(
        "Create Fixed Rotation Key: the target level cannot be reached with "
        "the provided keys.",
        e.what());
  }
}

TEST_P(NotAllowed, LevelOfCreateRotationKey) {
  int level = GetParam();

  try {
    engine_->create_rotation_key(secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Rotation Key: the target level cannot be reached "
                 "with the current engine parameters.",
                 e.what());
  }
}

TEST_F(NotAllowed, LevelOfCreateRotationKeyUndersizedSecretKey) {
  int level = engine_->get_max_level();

  try {
    engine_->create_rotation_key(undersized_secret_key_, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Rotation Key: the target level cannot be reached with "
                 "the provided keys.",
                 e.what());
  }
}
