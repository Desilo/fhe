#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectEncodeMatrix : public testing::Test {
public:
  static void SetUpTestSuite() { engine_ = new desilo::fhe::CKKSEngine(); }

  static void TearDownTestSuite() { delete engine_; }

  static desilo::fhe::CKKSEngine *engine_;
};

desilo::fhe::CKKSEngine *RejectEncodeMatrix::engine_ = nullptr;

#define TEST_DOUBLE_WITH_LEVEL(message, level, error_message)                  \
  try {                                                                        \
    engine_->encode_matrix(message, level);                                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Double Matrix Vector: " error_message, e.what());     \
  }

TEST_F(RejectEncodeMatrix, DoubleWithLevel_LevelTooSmall) {
  auto slot_count = engine_->get_slot_count();
  std::vector<double> message(slot_count * slot_count);

  TEST_DOUBLE_WITH_LEVEL(
      message, -1,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, DoubleWithLevel_LevelTooLarge) {
  auto slot_count = engine_->get_slot_count();
  std::vector<double> message(slot_count * slot_count);

  TEST_DOUBLE_WITH_LEVEL(
      message, 8,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, DoubleWithLevel_OneMoreLevel) {
  auto slot_count = engine_->get_slot_count();
  std::vector<double> message(slot_count * slot_count);

  TEST_DOUBLE_WITH_LEVEL(
      message, 7,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, DoubleWithLevel_InvalidMatrixSize) {
  std::vector<double> message;

  TEST_DOUBLE_WITH_LEVEL(
      message, 6, "the given matrix is not compatible with this engine.");
}

#define TEST_COMPLEX_WITH_LEVEL(message, level, error_message)                 \
  try {                                                                        \
    engine_->encode_matrix(message, level);                                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Complex Double Matrix Vector: " error_message,        \
                 e.what());                                                    \
  }

TEST_F(RejectEncodeMatrix, ComplexWithLevel_LevelTooSmall) {
  auto slot_count = engine_->get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slot_count);

  TEST_COMPLEX_WITH_LEVEL(
      message, -1,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, ComplexWithLevel_LevelTooLarge) {
  auto slot_count = engine_->get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slot_count);

  TEST_COMPLEX_WITH_LEVEL(
      message, 8,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, ComplexWithLevel_OneMoreLevel) {
  auto slot_count = engine_->get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slot_count);

  TEST_COMPLEX_WITH_LEVEL(
      message, 7,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, ComplexWithLevel_InvalidMatrixSize) {
  std::vector<std::complex<double>> message;

  TEST_COMPLEX_WITH_LEVEL(
      message, 6, "the given matrix is not compatible with this engine.");
}

#define TEST_DOUBLE_BUFFER_WITH_LEVEL(message, level, error_message)           \
  try {                                                                        \
    engine_->encode_matrix(message, level);                                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Double Matrix Buffer: " error_message, e.what());     \
  }

TEST_F(RejectEncodeMatrix, DoubleBufferWithLevel_LevelTooSmall) {
  double *message;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, -1,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, DoubleBufferWithLevel_LevelTooLarge) {
  double *message;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, 8,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, DoubleBufferWithLevel_OneMoreLevel) {
  double *message;

  TEST_DOUBLE_BUFFER_WITH_LEVEL(
      message, 7,
      "the target level cannot be reached with the current engine parameters.");
}

#define TEST_COMPLEX_BUFFER_WITH_LEVEL(message, level, error_message)          \
  try {                                                                        \
    engine_->encode_matrix(message, level);                                    \
    FAIL();                                                                    \
  } catch (std::runtime_error & e) {                                           \
    EXPECT_STREQ("Encode Complex Double Matrix Buffer: " error_message,        \
                 e.what());                                                    \
  }

TEST_F(RejectEncodeMatrix, ComplexBufferWithLevel_LevelTooSmall) {
  std::complex<double> *message;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, -1,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, ComplexBufferWithLevel_LevelTooLarge) {
  std::complex<double> *message;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, 8,
      "the target level cannot be reached with the current engine parameters.");
}

TEST_F(RejectEncodeMatrix, ComplexBufferWithLevel_OneMoreLevel) {
  std::complex<double> *message;

  TEST_COMPLEX_BUFFER_WITH_LEVEL(
      message, 7,
      "the target level cannot be reached with the current engine parameters.");
}
