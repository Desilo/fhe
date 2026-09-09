#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"

class RejectCreateSecretKey : public testing::Test {
public:
  static void SetUpTestSuite() { engine_ = new desilo::fhe::CKKSEngine(); }

  static void TearDownTestSuite() { delete engine_; }

  static desilo::fhe::CKKSEngine *engine_;
};

desilo::fhe::CKKSEngine *RejectCreateSecretKey::engine_ = nullptr;

TEST_F(RejectCreateSecretKey, WithLevel_LevelTooSmall) {
  int level = -1;
  try {
    engine_->create_secret_key(level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Secret Key: the target level cannot be reached with "
                 "the current engine parameters.",
                 e.what());
  }
}

TEST_F(RejectCreateSecretKey, WithLevel_LevelTooLarge) {
  int level = 8;
  try {
    engine_->create_secret_key(level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Secret Key: the target level cannot be reached with "
                 "the current engine parameters.",
                 e.what());
  }
}

TEST_F(RejectCreateSecretKey, Custom_SecretTooLong) {
  std::vector<int64_t> secret(engine_->get_slot_count() * 2 + 1);
  try {
    engine_->create_secret_key(secret);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Custom Secret Key: the given input is too long to be "
                 "processed.",
                 e.what());
  }
}

TEST_F(RejectCreateSecretKey, CustomWithLevel_SecretTooLong) {
  std::vector<int64_t> secret(engine_->get_slot_count() * 2 + 1);
  int level = 0;
  try {
    engine_->create_secret_key(secret, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Custom Secret Key: the given input is too long to be "
                 "processed.",
                 e.what());
  }
}

TEST_F(RejectCreateSecretKey, CustomWithLevel_LevelTooSmall) {
  std::vector<int64_t> secret(engine_->get_slot_count() * 2);
  int level = -1;
  try {
    engine_->create_secret_key(secret, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Custom Secret Key: the target level cannot be reached "
                 "with the current engine parameters.",
                 e.what());
  }
}

TEST_F(RejectCreateSecretKey, CustomWithLevel_LevelTooLarge) {
  std::vector<int64_t> secret(engine_->get_slot_count() * 2);
  int level = 8;
  try {
    engine_->create_secret_key(secret, level);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Custom Secret Key: the target level cannot be reached "
                 "with the current engine parameters.",
                 e.what());
  }
}
