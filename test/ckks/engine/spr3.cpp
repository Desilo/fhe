#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPR3(
    MakeBasisSPR3,
    [](const std::tuple<int, int, int> &param) {
      return print_level_depth(std::get<0>(param)) + "And" +
             print_max_power(std::get<1>(param)) +
             print_slice_count(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(0, 1),

        testing::Values(4, 5, 6, 7, 8),

        testing::Values(1, 2)));

const int expected_level_use[8]{0, 1, 2, 2, 3, 3, 3, 3};

ALL_ENGINE_TEST(MakeBasisSPR3, PowerBasisCiphertext, {
  const auto levels = GetParam();
  const auto level = max_level_ - std::get<0>(levels);
  const auto max_power = std::get<1>(levels);
  const auto slice_count = std::get<2>(GetParam());

  if (level < std::ceil(std::log2(max_power))) {
    GTEST_SKIP() << "Impossible Max Power.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  std::vector<std::complex<double>> message(slot_count * slice_count,
                                            std::complex<double>(2, 2));

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto power_basis =
      engine.make_power_basis(ciphertext, max_power, relinearization_key_);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  for (int power_index = 0; power_index < max_power; power_index++) {
    const auto product = power_basis[power_index];
    const auto decrypted = DECRYPT_COMPLEX(product);

    EXPECT_EQ(product->level(), level - expected_level_use[power_index]);
    EXPECT_EQ(product->flag(), flag);
    EXPECT_EQ(product->polynomial_count(), 2);

    for (int i = 0; i < message.size(); i++) {
      const auto expected = std::pow(message[i], power_index + 1);

      ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-3);
      ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-3);
    }
  }

  for (auto &basis : power_basis) {
    delete basis;
  }

  delete ciphertext;
})

std::vector<std::vector<std::complex<double>>> chebyshev_expected{

    {std::complex<double>(1, 1), std::complex<double>(-1, 4),
     std::complex<double>(-11, 5), std::complex<double>(-31, -16),
     std::complex<double>(-19, -99), std::complex<double>(191, -220),
     std::complex<double>(841, 41), std::complex<double>(1409, 1984)},

    {std::complex<double>(2, 2), std::complex<double>(-1, 16),
     std::complex<double>(-70, 58), std::complex<double>(-511, -64),
     std::complex<double>(-1718, -2358), std::complex<double>(3071, -16240),
     std::complex<double>(78962, -50318),
     std::complex<double>(514049, 130816)}};

ALL_ENGINE_TEST(MakeBasisSPR3, ChebyshevBasisCiphertextOnes, {
  const auto levels = GetParam();
  const auto level = max_level_ - std::get<0>(levels);
  const auto max_power = std::get<1>(levels);
  const auto slice_count = std::get<2>(GetParam());

  if (level < std::ceil(std::log2(max_power))) {
    GTEST_SKIP() << "Impossible Max Power.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  std::vector<std::complex<double>> message(slot_count * slice_count,
                                            std::complex<double>(1, 1));

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto chebyshev_basis =
      engine.make_chebyshev_basis(ciphertext, max_power, relinearization_key_);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  for (int power_index = 0; power_index < max_power; power_index++) {
    const auto product = chebyshev_basis[power_index];
    const auto decrypted = DECRYPT_COMPLEX(product);

    EXPECT_EQ(product->level(), level - expected_level_use[power_index]);
    EXPECT_EQ(product->flag(), flag);
    EXPECT_EQ(product->polynomial_count(), 2);

    for (int i = 0; i < message.size(); i++) {

      ASSERT_NEAR(chebyshev_expected[0][power_index].real(),
                  decrypted[i].real(), 1e-3);
      ASSERT_NEAR(chebyshev_expected[0][power_index].imag(),
                  decrypted[i].imag(), 1e-3);
    }
  }

  for (auto &basis : chebyshev_basis) {
    delete basis;
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(MakeBasisSPR3, ChebyshevBasisCiphertextTwos, {
  const auto levels = GetParam();
  const auto level = max_level_ - std::get<0>(levels);
  const auto max_power = std::get<1>(levels);
  const auto slice_count = std::get<2>(GetParam());

  if (level < std::ceil(std::log2(max_power))) {
    GTEST_SKIP() << "Impossible Max Power.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  std::vector<std::complex<double>> message(slot_count * slice_count,
                                            std::complex<double>(2, 2));

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto chebyshev_basis =
      engine.make_chebyshev_basis(ciphertext, max_power, relinearization_key_);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  for (int power_index = 0; power_index < max_power; power_index++) {
    const auto product = chebyshev_basis[power_index];
    const auto decrypted = DECRYPT_COMPLEX(product);

    EXPECT_EQ(product->level(), level - expected_level_use[power_index]);
    EXPECT_EQ(product->flag(), flag);
    EXPECT_EQ(product->polynomial_count(), 2);

    for (int i = 0; i < message.size(); i++) {

      ASSERT_NEAR(chebyshev_expected[1][power_index].real(),
                  decrypted[i].real(), 1e-3);
      ASSERT_NEAR(chebyshev_expected[1][power_index].imag(),
                  decrypted[i].imag(), 1e-3);
    }
  }

  for (auto &basis : chebyshev_basis) {
    delete basis;
  }

  delete ciphertext;
})

SETUP_ENGINE_TEST_SPR3(
    EvaluatePolynomialSPR3,
    [](const std::tuple<int, int, int> &param) {
      return print_level_depth(std::get<0>(param)) + "And" +
             print_polynomial(std::get<1>(param)) +
             print_slice_count(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(0, 1),

        testing::Values(0, 1, 2, 3, 4, 5),

        testing::Values(1, 2)));

std::vector<std::vector<int64_t>> int_coefficients{
    {1, 2, 3, 4, 5, 6, 7, 8, 9},
    {9, 8, 7, 6, 5, 4, 3, 2, 1},
    {-1, 1, -2, 2, -3, 3, -4, 4, -5},
    {1, 2, 3},
    {9, 8, 7},
    {-1, 1, -2}};

const std::complex<double> expected_int_value[6]{
    std::complex<double>(43909, -12452), std::complex<double>(5241, -3928),
    std::complex<double>(-16607, -2414), std::complex<double>(5, 28),
    std::complex<double>(25, 72),        std::complex<double>(1, -14)};

ALL_ENGINE_TEST(EvaluatePolynomialSPR3, CiphertextIntPolynomial, {
  const auto levels = GetParam();
  const auto level = max_level_ - std::get<0>(levels);
  const auto polynomial_type = std::get<1>(levels);
  const auto slice_count = std::get<2>(GetParam());
  std::vector<int64_t> coefficients = int_coefficients[polynomial_type];

  auto required_level = 1;
  if (polynomial_type < 3) {
    required_level = 3;
  }

  if (level < required_level) {
    GTEST_SKIP() << "Not enough level for polynomial evaluation.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  std::vector<std::complex<double>> message(slot_count * slice_count,
                                            std::complex<double>(2, 2));

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto polynomial = engine.evaluate_polynomial(ciphertext, coefficients,
                                                     relinearization_key_);

  const auto decrypted = DECRYPT_COMPLEX(polynomial);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto threshold = 1e-4;
  if (polynomial_type < 3) {

    threshold = 1e-2;
  }

  EXPECT_EQ(polynomial->level(), level - required_level);
  EXPECT_EQ(polynomial->flag(), flag);
  EXPECT_EQ(polynomial->polynomial_count(), 2);

  const auto expected = expected_int_value[polynomial_type];
  for (int i = 0; i < message.size(); i++) {
    ASSERT_NEAR(expected.real(), decrypted[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), threshold);
  }

  delete ciphertext;
  delete polynomial;
})

std::vector<std::vector<double>> double_coefficients{
    {1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5},
    {9.5, 8.5, 7.5, 6.5, 5.5, 4.5, 3.5, 2.5, 1.5},
    {-1.5, 1.5, -2.5, 2.5, -3.5, 3.5, -4.5, 4.5, -5.5},
    {1.5, 2.5, 3.5},
    {9.5, 8.5, 7.5},
    {-1.5, 1.5, -2.5}};

const std::complex<double> expected_double_value[6]{
    std::complex<double>(46366.5, -13271), std::complex<double>(7698.5, -4747),
    std::complex<double>(-18182.5, -2729), std::complex<double>(6.5, 33),
    std::complex<double>(26.5, 77),        std::complex<double>(1.5, -17)};

ALL_ENGINE_TEST(EvaluatePolynomialSPR3, CiphertextDoublePolynomial, {
  const auto levels = GetParam();
  const auto level = max_level_ - std::get<0>(levels);
  const auto polynomial_type = std::get<1>(levels);
  const auto slice_count = std::get<2>(GetParam());
  std::vector<double> coefficients = double_coefficients[polynomial_type];

  auto required_level = 2;
  if (polynomial_type < 3) {
    required_level = 4;
  }

  if (level < required_level) {
    GTEST_SKIP() << "Not enough level for polynomial evaluation.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  std::vector<std::complex<double>> message(slot_count * slice_count,
                                            std::complex<double>(2, 2));

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto polynomial = engine.evaluate_polynomial(ciphertext, coefficients,
                                                     relinearization_key_);

  const auto decrypted = DECRYPT_COMPLEX(polynomial);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(polynomial->level(), level - required_level);
  EXPECT_EQ(polynomial->flag(), flag);
  EXPECT_EQ(polynomial->polynomial_count(), 2);

  auto threshold = 1e-4;
  if (polynomial_type < 3) {

    threshold = 1e-2;
  }

  const auto expected = expected_double_value[polynomial_type];
  for (int i = 0; i < message.size(); i++) {
    ASSERT_NEAR(expected.real(), decrypted[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), threshold);
  }

  delete ciphertext;
  delete polynomial;
})

const std::complex<double> expected_chebyshev_int_value[6]{
    std::complex<double>(5266493, 646936),
    std::complex<double>(671357, -27816),
    std::complex<double>(-2270439, -797188),
    std::complex<double>(2, 52),
    std::complex<double>(18, 128),
    std::complex<double>(3, -30)};

ALL_ENGINE_TEST(EvaluatePolynomialSPR3, CiphertextIntChebyshevPolynomial, {
  const auto levels = GetParam();
  const auto level = max_level_ - std::get<0>(levels);
  const auto polynomial_type = std::get<1>(levels);
  const auto slice_count = std::get<2>(GetParam());
  std::vector<int64_t> coefficients = int_coefficients[polynomial_type];

  auto required_level = 1;
  if (polynomial_type < 3) {
    required_level = 3;
  }

  if (level < required_level) {
    GTEST_SKIP() << "Not enough level for polynomial evaluation.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  std::vector<std::complex<double>> message(slot_count * slice_count,
                                            std::complex<double>(2, 2));

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto polynomial = engine.evaluate_chebyshev_polynomial(
      ciphertext, coefficients, relinearization_key_);

  const auto decrypted = DECRYPT_COMPLEX(polynomial);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto threshold = 1e-4;
  if (polynomial_type < 3) {

    threshold = 1e-2;
  }

  EXPECT_EQ(polynomial->level(), level - required_level);
  EXPECT_EQ(polynomial->flag(), flag);
  EXPECT_EQ(polynomial->polynomial_count(), 2);

  const auto expected = expected_chebyshev_int_value[polynomial_type];
  for (int i = 0; i < message.size(); i++) {
    ASSERT_NEAR(expected.real(), decrypted[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), threshold);
  }

  delete ciphertext;
  delete polynomial;
})

const std::complex<double> expected_chebyshev_double_value[6]{
    std::complex<double>(5563385.5, 677892),
    std::complex<double>(968249.5, 3140),
    std::complex<double>(-2490155.5, -880760),
    std::complex<double>(3, 61),
    std::complex<double>(19, 137),
    std::complex<double>(4, -37)};

ALL_ENGINE_TEST(EvaluatePolynomialSPR3, CiphertextDoubleChebyshevPolynomial, {
  const auto levels = GetParam();
  const auto level = max_level_ - std::get<0>(levels);
  const auto polynomial_type = std::get<1>(levels);
  const auto slice_count = std::get<2>(GetParam());
  std::vector<double> coefficients = double_coefficients[polynomial_type];

  auto required_level = 2;
  if (polynomial_type < 3) {
    required_level = 4;
  }

  if (level < required_level) {
    GTEST_SKIP() << "Not enough level for polynomial evaluation.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  std::vector<std::complex<double>> message(slot_count * slice_count,
                                            std::complex<double>(2, 2));

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto polynomial = engine.evaluate_chebyshev_polynomial(
      ciphertext, coefficients, relinearization_key_);

  const auto decrypted = DECRYPT_COMPLEX(polynomial);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(polynomial->level(), level - required_level);
  EXPECT_EQ(polynomial->flag(), flag);
  EXPECT_EQ(polynomial->polynomial_count(), 2);

  auto threshold = 1e-4;
  if (polynomial_type < 3) {

    threshold = 1e-2;
  }

  const auto expected = expected_chebyshev_double_value[polynomial_type];
  for (int i = 0; i < message.size(); i++) {
    ASSERT_NEAR(expected.real(), decrypted[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), threshold);
  }

  delete ciphertext;
  delete polynomial;
})
