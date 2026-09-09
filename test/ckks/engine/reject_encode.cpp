#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectEncode : public testing::Test {
public:
  static void SetUpTestSuite() { engine_ = new desilo::fhe::CKKSEngine(); }

  static void TearDownTestSuite() { delete engine_; }

  static desilo::fhe::CKKSEngine *engine_;
};

desilo::fhe::CKKSEngine *RejectEncode::engine_ = nullptr;

TEST_F(RejectEncode, UnitDouble_MessageTooLong) {
  std::vector<double> message(engine_->get_slot_count() + 1);

  try {
    engine_->encode_unit(message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Double Vector To Unit Plaintext: the given input is "
                 "too long to be processed.",
                 e.what());
  }
}

#define TEST_UNIT_DOUBLE_WITH_LEVEL(message, level, error_message)             \
  try {                                                                        \
    engine_->encode_unit(message, level);                                      \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Double Vector To Unit Plaintext: " error_message,     \
                 e.what());                                                    \
  }

TEST_F(RejectEncode, UnitDoubleWithLevel_MessageTooLong) {
  std::vector<double> message(engine_->get_slot_count() + 1);
  int level = 0;

  TEST_UNIT_DOUBLE_WITH_LEVEL(message, level,
                              "the given input is too long to be processed.");
}

TEST_F(RejectEncode, UnitDoubleWithLevel_LevelTooSmall) {
  std::vector<double> message;
  int level = -1;

  TEST_UNIT_DOUBLE_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncode, UnitDoubleWithLevel_LevelTooLarge) {
  std::vector<double> message;
  int level = 8;

  TEST_UNIT_DOUBLE_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncode, UnitComplex_MessageTooLong) {
  std::vector<std::complex<double>> message(engine_->get_slot_count() + 1);

  try {
    engine_->encode_unit(message);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Encode Complex Double Vector To Unit Plaintext: the given "
                 "input is too long to be processed.",
                 e.what());
  }
}

#define TEST_UNIT_COMPLEX_WITH_LEVEL(message, level, error_message)            \
  try {                                                                        \
    engine_->encode_unit(message, level);                                      \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ(                                                              \
        "Encode Complex Double Vector To Unit Plaintext: " error_message,      \
        e.what());                                                             \
  }

TEST_F(RejectEncode, UnitComplexWithLevel_MessageTooLong) {
  std::vector<std::complex<double>> message(engine_->get_slot_count() + 1);
  int level = 0;

  TEST_UNIT_COMPLEX_WITH_LEVEL(message, level,
                               "the given input is too long to be processed.");
}

TEST_F(RejectEncode, UnitComplexWithLevel_LevelTooSmall) {
  std::vector<std::complex<double>> message;
  int level = -1;

  TEST_UNIT_COMPLEX_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncode, UnitComplexWithLevel_LevelTooLarge) {
  std::vector<std::complex<double>> message;
  int level = 8;

  TEST_UNIT_COMPLEX_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_DOUBLE_WITH_LEVEL(message, level, error_message)                  \
  try {                                                                        \
    engine_->encode(message, level);                                           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Double Vector: " error_message, e.what());            \
  }

TEST_F(RejectEncode, DoubleWithLevel_LevelTooSmall) {
  std::vector<double> message;
  int level = -1;

  TEST_DOUBLE_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncode, DoubleWithLevel_LevelTooLarge) {
  std::vector<double> message;
  int level = 8;

  TEST_DOUBLE_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_COMPLEX_WITH_LEVEL(message, level, error_message)                 \
  try {                                                                        \
    engine_->encode(message, level);                                           \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Complex Double Vector: " error_message, e.what());    \
  }

TEST_F(RejectEncode, ComplexWithLevel_LevelTooSmall) {
  std::vector<std::complex<double>> message;
  int level = -1;

  TEST_COMPLEX_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncode, ComplexWithLevel_LevelTooLarge) {
  std::vector<std::complex<double>> message;
  int level = 8;

  TEST_COMPLEX_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_DOUBLE_BUFFER_WITH_LEVEL(message, level, error_message)           \
  try {                                                                        \
    engine_->encode(message, engine_->get_slot_count(), level);                \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Double Buffer: " error_message, e.what());            \
  }

TEST_F(RejectEncode, DoubleBufferWithLevel_LevelTooSmall) {
  double *message;
  int level = -1;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncode, DoubleBufferWithLevel_LevelTooLarge) {
  double *message;
  int level = 8;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_COMPLEX_BUFFER_WITH_LEVEL(message, level, error_message)          \
  try {                                                                        \
    engine_->encode(message, engine_->get_slot_count(), level);                \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Complex Double Buffer: " error_message, e.what());    \
  }

TEST_F(RejectEncode, ComplexBufferWithLevel_LevelTooSmall) {
  std::complex<double> *message;
  int level = -1;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncode, ComplexBufferWithLevel_LevelTooLarge) {
  std::complex<double> *message;
  int level = 8;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, level,
      "the target level cannot be reached with the current engine parameters.");
}
