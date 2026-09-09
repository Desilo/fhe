#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"
#include "common/test.h"

using namespace std::complex_literals;

#define LOG_SLOT_COUNT 3

#define DEFINE_MULTIPLY_MATRIX_TEST_CLASS(tier, name, ...)                     \
  class tier##CKKSEngine##name                                                 \
      : public testing::TestWithParam<std::tuple<__VA_ARGS__>> {               \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      config_ = test_configs[#tier];                                           \
      config_.log_slot_count_ = LOG_SLOT_COUNT;                                \
      max_level_ = config_.max_level_;                                         \
      auto engine = desilo::fhe::CKKSEngine(config_);                          \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
      rotation_key_ = engine.create_rotation_key(secret_key_);                 \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      DELETE(secret_key_);                                                     \
      DELETE(public_key_);                                                     \
      DELETE(rotation_key_);                                                   \
    }                                                                          \
                                                                               \
    static desilo::fhe::CKKSConfig config_;                                    \
    static int max_level_;                                                     \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::RotationKey *rotation_key_;                            \
  };                                                                           \
                                                                               \
  desilo::fhe::CKKSConfig tier##CKKSEngine##name::config_ = {};                \
  int tier##CKKSEngine##name::max_level_ = 0;                                  \
  desilo::fhe::SecretKey *tier##CKKSEngine##name::secret_key_ = nullptr;       \
  desilo::fhe::PublicKey *tier##CKKSEngine##name::public_key_ = nullptr;       \
  desilo::fhe::RotationKey *tier##CKKSEngine##name::rotation_key_ = nullptr;

#define SETUP_MULTIPLY_MATRIX_TEST(name, to_test_name, ...)                    \
  DEFINE_MULTIPLY_MATRIX_TEST_CLASS(Sand, name, int);                          \
  DEFINE_MULTIPLY_MATRIX_TEST_CLASS(Bronze, name, int);                        \
  DEFINE_MULTIPLY_MATRIX_TEST_CLASS(Silver, name, int);                        \
  DEFINE_MULTIPLY_MATRIX_TEST_CLASS(Gold, name, int);                          \
  INSTANTIATE_ENGINE_TEST(Sand, name, to_test_name, __VA_ARGS__);              \
  INSTANTIATE_ENGINE_TEST(Bronze, name, to_test_name, __VA_ARGS__);            \
  INSTANTIATE_ENGINE_TEST(Silver, name, to_test_name, __VA_ARGS__);            \
  INSTANTIATE_ENGINE_TEST(Gold, name, to_test_name, __VA_ARGS__);

#define MULTIPLY_MATRIX_TEST(fixture_name, test_name, test_body)               \
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

// clang-format on

std::vector<double> message_double = {1, 2, 3, 4, 5, 6, 7, 8};
std::vector<double> expected_double = {204,  492,  780,  1068,
                                       1356, 1644, 1932, 2220};
std::vector<std::complex<double>> message_complex = {
    0.0 + 1.0i, 2.0 + 3.0i,   4.0 + 5.0i,   6.0 + 7.0i,
    8.0 + 9.0i, 10.0 + 11.0i, 12.0 + 13.0i, 14.0 + 15.0i};
std::vector<std::complex<double>> expected_complex = {
    -120.0 + 1232.0i, -248.0 + 3152.0i,  -376.0 + 5072.0i,  -504.0 + 6992.0i,
    -632.0 + 8912.0i, -760.0 + 10832.0i, -888.0 + 12752.0i, -1016.0 + 14672.0i};

int slice_count = 2;
std::vector<double> long_message_double = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
};
std::vector<double> long_expected_double = {204,  492,  780,  1068, 1356, 1644,
                                            1932, 2220, 492,  1292, 2092, 2892,
                                            3692, 4492, 5292, 6092};

SETUP_MULTIPLY_MATRIX_TEST(
    MultiplyMatrix,
    [](const std::tuple<int> &param) {
      return print_process_type(std::get<0>(param));
    },
    PROCESS_TEST);

MULTIPLY_MATRIX_TEST(MultiplyMatrix, DoubleMatrixUnitCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto unit_ciphertext = engine.encrypt_unit(message_double, public_key_);

  const auto multiplied = engine.multiply_matrix(
      matrix_double.data(), unit_ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_double[i], decrypted[i], 1e-6);
  };

  delete unit_ciphertext;
  delete multiplied;
})

MULTIPLY_MATRIX_TEST(MultiplyMatrix, DoubleMatrixVectorUnitCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto unit_ciphertext = engine.encrypt_unit(message_double, public_key_);

  const auto multiplied =
      engine.multiply_matrix(matrix_double, unit_ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_double[i], decrypted[i], 1e-6);
  };

  delete unit_ciphertext;
  delete multiplied;
})

MULTIPLY_MATRIX_TEST(MultiplyMatrix, ComplexDoubleMatrixUnitCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto unit_ciphertext =
      engine.encrypt_unit(message_complex, public_key_);

  const auto multiplied = engine.multiply_matrix(
      matrix_complex.data(), unit_ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt_complex(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_complex[i].real(), decrypted[i].real(), 1e-6);
    ASSERT_NEAR(expected_complex[i].imag(), decrypted[i].imag(), 1e-6);
  };

  delete unit_ciphertext;
  delete multiplied;
})

MULTIPLY_MATRIX_TEST(MultiplyMatrix, ComplexDoubleMatrixVectorUnitCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto unit_ciphertext =
      engine.encrypt_unit(message_complex, public_key_);

  const auto multiplied =
      engine.multiply_matrix(matrix_complex, unit_ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt_complex(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_complex[i].real(), decrypted[i].real(), 1e-6);
    ASSERT_NEAR(expected_complex[i].imag(), decrypted[i].imag(), 1e-6);
  };

  delete unit_ciphertext;
  delete multiplied;
})

MULTIPLY_MATRIX_TEST(MultiplyMatrix, DoubleMatrixCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto ciphertext = engine.encrypt(message_double, public_key_);

  const auto multiplied =
      engine.multiply_matrix(matrix_double.data(), ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_double[i], decrypted[i], 1e-6);
  };

  delete ciphertext;
  delete multiplied;
})

MULTIPLY_MATRIX_TEST(MultiplyMatrix, DoubleMatrixVectorCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto ciphertext = engine.encrypt(message_double, public_key_);

  const auto multiplied =
      engine.multiply_matrix(matrix_double, ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_double[i], decrypted[i], 1e-6);
  };

  delete ciphertext;
  delete multiplied;
})

MULTIPLY_MATRIX_TEST(MultiplyMatrix, ComplexDoubleMatrixCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto ciphertext = engine.encrypt(message_complex, public_key_);

  const auto multiplied =
      engine.multiply_matrix(matrix_complex.data(), ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt_complex(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_complex[i].real(), decrypted[i].real(), 1e-6);
    ASSERT_NEAR(expected_complex[i].imag(), decrypted[i].imag(), 1e-6);
  };

  delete ciphertext;
  delete multiplied;
})

MULTIPLY_MATRIX_TEST(MultiplyMatrix, ComplexDoubleMatrixVectorCiphertext, {
  const auto process_type = std::get<0>(GetParam());
  set_process_type(config_, process_type);
  auto engine = desilo::fhe::CKKSEngine(config_);
  auto slot_count = engine.get_slot_count();

  const auto ciphertext = engine.encrypt(message_complex, public_key_);

  const auto multiplied =
      engine.multiply_matrix(matrix_complex, ciphertext, rotation_key_);
  const auto decrypted = engine.decrypt_complex(multiplied, secret_key_);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected_complex[i].real(), decrypted[i].real(), 1e-6);
    ASSERT_NEAR(expected_complex[i].imag(), decrypted[i].imag(), 1e-6);
  };

  delete ciphertext;
  delete multiplied;
})
