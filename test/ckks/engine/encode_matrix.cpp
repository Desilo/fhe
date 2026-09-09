#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"
#include "common/test.h"
#include "operation/bootstrap.h"

using namespace std::complex_literals;

#define LOG_SLOT_COUNT 3

#define DEFINE_ENCODE_MATRIX_TEST_CLASS(tier, name, ...)                       \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      config_.log_slot_count_ = LOG_SLOT_COUNT;                                \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {}                                         \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static int max_level_;                                                     \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;

#define SETUP_ENCODE_MATRIX_TEST(name, to_test_name, ...)                      \
  DEFINE_ENCODE_MATRIX_TEST_CLASS(Sand, name, int);                            \
  DEFINE_ENCODE_MATRIX_TEST_CLASS(Bronze, name, int);                          \
  DEFINE_ENCODE_MATRIX_TEST_CLASS(Silver, name, int);                          \
  DEFINE_ENCODE_MATRIX_TEST_CLASS(Gold, name, int);                            \
  INSTANTIATE_ENGINE_TEST(Sand, name, to_test_name, __VA_ARGS__);              \
  INSTANTIATE_ENGINE_TEST(Bronze, name, to_test_name, __VA_ARGS__);            \
  INSTANTIATE_ENGINE_TEST(Silver, name, to_test_name, __VA_ARGS__);            \
  INSTANTIATE_ENGINE_TEST(Gold, name, to_test_name, __VA_ARGS__);

#define ENCODE_MATRIX_TEST(fixture_name, test_name, test_body)                 \
  TEST_P(SandCKKSEngine##fixture_name, test_name)                              \
  test_body;                                                                   \
  TEST_P(BronzeCKKSEngine##fixture_name, test_name)                            \
  test_body;                                                                   \
  TEST_P(SilverCKKSEngine##fixture_name, test_name)                            \
  test_body;                                                                   \
  TEST_P(GoldCKKSEngine##fixture_name, test_name)                              \
  test_body;

// clang-format off

std::vector<double> matrix_double = {
     1,  2,  3,  4,  5,  6,  7,  8,
     9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56,
    57, 58, 59, 60, 61, 62, 63, 64};

std::vector<double> expected_encoded_matrix_double = {
    33, 42, 51, 60,  5, 14, 23, 32,
    40, 41, 50, 59,  4, 13, 22, 31,
    39, 48, 49, 58,  3, 12, 21, 30,
    38, 47, 56, 57,  2, 11, 20, 29,
     1, 10, 19, 28, 37, 46, 55, 64,
     8,  9, 18, 27, 36, 45, 54, 63,
     7, 16, 17, 26, 35, 44, 53, 62,
     6, 15, 24, 25, 34, 43, 52, 61};

std::vector<std::complex<double>> matrix_complex = {
      0.0 +   1.0i,   2.0 +   3.0i,   4.0 +   5.0i,   6.0 +   7.0i,
      8.0 +   9.0i,  10.0 +  11.0i,  12.0 +  13.0i,  14.0 +  15.0i,
     16.0 +  17.0i,  18.0 +  19.0i,  20.0 +  21.0i,  22.0 +  23.0i,
     24.0 +  25.0i,  26.0 +  27.0i,  28.0 +  29.0i,  30.0 +  31.0i,
     32.0 +  33.0i,  34.0 +  35.0i,  36.0 +  37.0i,  38.0 +  39.0i,
     40.0 +  41.0i,  42.0 +  43.0i,  44.0 +  45.0i,  46.0 +  47.0i,
     48.0 +  49.0i,  50.0 +  51.0i,  52.0 +  53.0i,  54.0 +  55.0i,
     56.0 +  57.0i,  58.0 +  59.0i,  60.0 +  61.0i,  62.0 +  63.0i,
     64.0 +  65.0i,  66.0 +  67.0i,  68.0 +  69.0i,  70.0 +  71.0i,
     72.0 +  73.0i,  74.0 +  75.0i,  76.0 +  77.0i,  78.0 +  79.0i,
     80.0 +  81.0i,  82.0 +  83.0i,  84.0 +  85.0i,  86.0 +  87.0i,
     88.0 +  89.0i,  90.0 +  91.0i,  92.0 +  93.0i,  94.0 +  95.0i,
     96.0 +  97.0i,  98.0 +  99.0i, 100.0 + 101.0i, 102.0 + 103.0i,
    104.0 + 105.0i, 106.0 + 107.0i, 108.0 + 109.0i, 110.0 + 111.0i,
    112.0 + 113.0i, 114.0 + 115.0i, 116.0 + 117.0i, 118.0 + 119.0i,
    120.0 + 121.0i, 122.0 + 123.0i, 124.0 + 125.0i, 126.0 + 127.0i
};

std::vector<std::complex<double>> expected_encoded_matrix_complex = {
     64.0 + 65.0i, 82.0 + 83.0i, 100.0 + 101.0i, 118.0 + 119.0i,
      8.0 +  9.0i, 26.0 + 27.0i,  44.0 +  45.0i,  62.0 +  63.0i,
     78.0 + 79.0i, 80.0 + 81.0i,  98.0 +  99.0i, 116.0 + 117.0i,
      6.0 +  7.0i, 24.0 + 25.0i,  42.0 +  43.0i,  60.0 +  61.0i,
     76.0 + 77.0i, 94.0 + 95.0i,  96.0 +  97.0i, 114.0 + 115.0i,
      4.0 +  5.0i, 22.0 + 23.0i,  40.0 +  41.0i,  58.0 +  59.0i,
     74.0 + 75.0i, 92.0 + 93.0i, 110.0 + 111.0i, 112.0 + 113.0i,
      2.0 +  3.0i, 20.0 + 21.0i,  38.0 +  39.0i,  56.0 +  57.0i,
      0.0 +  1.0i, 18.0 + 19.0i,  36.0 +  37.0i,  54.0 +  55.0i,
     72.0 + 73.0i, 90.0 + 91.0i, 108.0 + 109.0i, 126.0 + 127.0i,
     14.0 + 15.0i, 16.0 + 17.0i,  34.0 +  35.0i,  52.0 +  53.0i,
     70.0 + 71.0i, 88.0 + 89.0i, 106.0 + 107.0i, 124.0 + 125.0i,
     12.0 + 13.0i, 30.0 + 31.0i,  32.0 +  33.0i,  50.0 +  51.0i,
     68.0 + 69.0i, 86.0 + 87.0i, 104.0 + 105.0i, 122.0 + 123.0i,
     10.0 + 11.0i, 28.0 + 29.0i,  46.0 +  47.0i,  48.0 +  49.0i,
     66.0 + 67.0i, 84.0 + 85.0i, 102.0 + 103.0i, 120.0 + 121.0i
};

// clang-format on

SETUP_ENCODE_MATRIX_TEST(
    EncodeMatrix,
    [](const std::tuple<int> &param) {
      return print_process_type(std::get<0>(param));
    },
    PROCESS_TEST);

ENCODE_MATRIX_TEST(EncodeMatrix, Double, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_double.data());
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      EXPECT_EQ(diagonal->level(), engine.get_max_level() - 1);
      EXPECT_EQ(diagonal->flag(), desilo::fhe::DataFlag::INCLUDE_SPECIAL);

      auto decoded = engine.decode_unit(diagonal);

      expect_array_near(
          decoded.data(),
          &expected_encoded_matrix_double.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})

ENCODE_MATRIX_TEST(EncodeMatrix, DoubleLeveled, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  auto level = engine.get_max_level() - 1;
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_double.data(), level);
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      EXPECT_EQ(diagonal->level(), level);
      EXPECT_EQ(diagonal->flag(), desilo::fhe::DataFlag::INCLUDE_SPECIAL);

      auto decoded = engine.decode_unit(diagonal);

      expect_array_near(
          decoded.data(),
          &expected_encoded_matrix_double.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})

ENCODE_MATRIX_TEST(EncodeMatrix, DoubleVector, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_double);
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      EXPECT_EQ(diagonal->level(), engine.get_max_level() - 1);
      EXPECT_EQ(diagonal->flag(), desilo::fhe::DataFlag::INCLUDE_SPECIAL);

      auto decoded = engine.decode_unit(diagonal);

      expect_array_near(
          decoded.data(),
          &expected_encoded_matrix_double.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})

ENCODE_MATRIX_TEST(EncodeMatrix, DoubleVectorLeveled, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  auto level = engine.get_max_level() - 2;
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_double, level);
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      EXPECT_EQ(diagonal->level(), level);
      EXPECT_EQ(diagonal->flag(), desilo::fhe::DataFlag::INCLUDE_SPECIAL);

      auto decoded = engine.decode_unit(diagonal);

      expect_array_near(
          decoded.data(),
          &expected_encoded_matrix_double.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})

ENCODE_MATRIX_TEST(EncodeMatrix, ComplexDouble, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_complex.data());
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      auto flag = desilo::fhe::DataFlag::COMPLEX |
                  desilo::fhe::DataFlag::INCLUDE_SPECIAL;
      EXPECT_EQ(diagonal->level(), engine.get_max_level() - 1);
      EXPECT_EQ(diagonal->flag(), flag);

      auto decoded = engine.decode_complex_unit_plaintext(diagonal);

      expect_complex_array_near(
          decoded.data(),
          &expected_encoded_matrix_complex.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})

ENCODE_MATRIX_TEST(EncodeMatrix, ComplexDoubleLeveled, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  auto level = engine.get_max_level() - 2;
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_complex.data(), level);
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      auto flag = desilo::fhe::DataFlag::COMPLEX |
                  desilo::fhe::DataFlag::INCLUDE_SPECIAL;
      EXPECT_EQ(diagonal->level(), level);
      EXPECT_EQ(diagonal->flag(), flag);

      auto decoded = engine.decode_complex_unit_plaintext(diagonal);

      expect_complex_array_near(
          decoded.data(),
          &expected_encoded_matrix_complex.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})

ENCODE_MATRIX_TEST(EncodeMatrix, ComplexDoubleVector, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_complex);
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      auto flag = desilo::fhe::DataFlag::COMPLEX |
                  desilo::fhe::DataFlag::INCLUDE_SPECIAL;
      EXPECT_EQ(diagonal->level(), engine.get_max_level() - 1);
      EXPECT_EQ(diagonal->flag(), flag);

      auto decoded = engine.decode_complex_unit_plaintext(diagonal);

      expect_complex_array_near(
          decoded.data(),
          &expected_encoded_matrix_complex.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})

ENCODE_MATRIX_TEST(EncodeMatrix, ComplexDoubleVectorLeveled, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();
  auto level = engine.get_max_level() - 2;
  const auto loop_count = desilo::fhe::get_stage_loop_counts(slot_count, 0);
  const auto inner_loop_count = loop_count.first;
  const auto outer_loop_count = loop_count.second;

  const auto encoded = engine.encode_matrix(matrix_complex, level);
  auto diagonals = encoded->encoded_diagonals_;

  for (auto i = 0; i < outer_loop_count; i++) {
    for (auto j = 0; j < inner_loop_count; j++) {
      const auto index = i * inner_loop_count + j;
      auto diagonal = diagonals[i][j];

      auto flag = desilo::fhe::DataFlag::COMPLEX |
                  desilo::fhe::DataFlag::INCLUDE_SPECIAL;
      EXPECT_EQ(diagonal->level(), level);
      EXPECT_EQ(diagonal->flag(), flag);

      auto decoded = engine.decode_complex_unit_plaintext(diagonal);

      expect_complex_array_near(
          decoded.data(),
          &expected_encoded_matrix_complex.data()[index * slot_count],
          slot_count, 1e-9);
    }
  }

  delete encoded;
})
