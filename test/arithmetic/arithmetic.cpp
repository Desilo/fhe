#include <cstdint>

#include "arithmetic/arithmetic.h"
#include "common/common.h"
#include "common/test.h"
#include "parameter/decode.h"

TEST(Arithmetic, ModulusInvertSmall) {
  int64_t x = 2;
  int64_t y;

  int64_t modulus = 7;

  y = desilo::fhe::modulus_invert(x, modulus);
  int64_t expected = 4;

  EXPECT_EQ(1, (x * expected) % modulus);
  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusInvertBig) {
  int64_t x = 3;
  int64_t y;

  int64_t modulus = 1152921504606748673;

  y = desilo::fhe::modulus_invert(x, modulus);
  int64_t expected = 384307168202249558;

  EXPECT_EQ(1, modulus_multiply_128(x, expected, modulus));
  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusInvertNotExist) {
  int64_t x = 2;
  int64_t y;

  int64_t modulus = 4;

  y = desilo::fhe::modulus_invert(x, modulus);
  int64_t expected = 0;

  EXPECT_NE(1, (x * expected) % modulus);
  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusMultiplySmall) {
  int64_t x1 = 2;
  int64_t x2 = 4;
  int64_t y;

  int64_t modulus = 7;

  y = desilo::fhe::modulus_multiply(x1, x2, modulus);
  int64_t expected = 1;

  EXPECT_EQ(expected, (x1 * x2) % modulus);
  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusMultiplyBig) {
  int64_t x1 = 1099511627777;
  int64_t x2 = 2199023255553;
  int64_t y;

  int64_t modulus = 1152921504606748673;

  y = desilo::fhe::modulus_multiply(x1, x2, modulus);
  int64_t expected = 3504691216385;

  EXPECT_EQ(expected, modulus_multiply_128(x1, x2, modulus));
  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusPowerSmall) {
  int64_t base = 2;
  int64_t exponent = 4;
  int64_t y;

  int64_t modulus = 7;

  y = desilo::fhe::modulus_power(base, exponent, modulus);
  int64_t expected = 2;

  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusPowerBig) {
  int64_t base = 1099511627777;
  int64_t exponent = 17;
  int64_t y;

  int64_t modulus = 1152921504606748673;

  y = desilo::fhe::modulus_power(base, exponent, modulus);
  int64_t expected = 26116327820310390;

  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusPowerSmallUnsigned) {
  uint64_t base = 2;
  uint64_t exponent = 4;
  uint64_t y;

  uint64_t modulus = 7;

  y = desilo::fhe::modulus_power(base, exponent, modulus);
  uint64_t expected = 2;

  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ModulusPowerBigUnsigned) {
  uint64_t base = 1099511627777;
  uint64_t exponent = 17;
  uint64_t y;

  uint64_t modulus = 1152921504606748673;

  y = desilo::fhe::modulus_power(base, exponent, modulus);
  uint64_t expected = 26116327820310390;

  EXPECT_EQ(y, expected);
}

TEST(Arithmetic, ScaleModulo) {
  double x = 1 << 26;
  int64_t y[3];

  int64_t scale = 1099511627776;
  double deviation = 1.1;
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  int chain_count = 3;

  desilo::fhe::scale_modulo(y, x, scale, deviation, q, chain_count);
  int64_t expected[3]{878609431550, 468576304236, 7128353785846163};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, ScaleEnterModulo) {
  double x = 1 << 26;
  int64_t y[3];

  int64_t scale = 1099511627776;
  double deviation = 1.1;
  int64_t r = 4611686018427387904;
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  int chain_count = 3;

  desilo::fhe::scale_enter_modulo(y, x, scale, deviation, r, q, chain_count);
  int64_t expected[3]{73748015275, 277266436069, 446906820893360882};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, FindRootSmallMoudulusPrime) {

  int64_t modulus_prime = 17;
  int coeff_count = 4;
  int coeff_count_double = coeff_count * 2;
  int64_t root;

  root = desilo::fhe::find_root(modulus_prime, coeff_count);
  int64_t expected = 9;
  std::vector<int64_t> root_power_series;

  int64_t power_of_root = 1;
  for (auto coeff_index = 0; coeff_index < coeff_count_double; coeff_index++) {
    power_of_root *= root;
    power_of_root %= modulus_prime;

    for (auto power_index = 0; power_index < coeff_index; power_index++) {
      EXPECT_NE(power_of_root, root_power_series[power_index]);
    }

    root_power_series.push_back(power_of_root);
  }

  EXPECT_EQ(1, power_of_root);
  EXPECT_EQ(root, expected);
}

TEST(Arithmetic, FindCyclicRootSmallMoudulusPrime) {

  int64_t modulus_prime = 241;
  int coeff_count = 5;
  int64_t root;

  root = desilo::fhe::find_cyclic_root(modulus_prime, coeff_count);
  int64_t expected = 87;
  std::set<int64_t> root_power_series;

  int64_t power_of_root = 1;
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    power_of_root *= root;
    power_of_root %= modulus_prime;

    EXPECT_EQ(root_power_series.size(), coeff_index);
    EXPECT_EQ(root_power_series.find(power_of_root), root_power_series.end());

    root_power_series.insert(power_of_root);
  }

  EXPECT_EQ(1, power_of_root);
  EXPECT_EQ(root, expected);
}

TEST(Arithmetic, FindGenerator) {
  int64_t prime = 17;
  int64_t root;

  root = desilo::fhe::find_generator(prime);
  int64_t expected = 3;
  std::set<int64_t> root_power_series;

  int64_t power_of_root = 1;
  for (auto prime_index = 0; prime_index < prime - 1; prime_index++) {
    power_of_root *= root;
    power_of_root %= prime;

    EXPECT_EQ(root_power_series.size(), prime_index);
    EXPECT_EQ(root_power_series.find(power_of_root), root_power_series.end());

    root_power_series.insert(power_of_root);
  }

  EXPECT_EQ(1, power_of_root);
  EXPECT_EQ(root, expected);
}

class FindRootBigModulusPrime
    : public ::testing::TestWithParam<std::tuple<int64_t, int64_t>> {};

INSTANTIATE_TEST_SUITE_P(
    FindRootBigModulusPrime, FindRootBigModulusPrime,

    ::testing::Values(std::make_tuple(1099511653249, 474586663331),
                      std::make_tuple(1099503452161, 330755234587),
                      std::make_tuple(1152921504606748673, 1715157987554227)));

TEST_P(FindRootBigModulusPrime, ) {

  const auto [modulus_prime, expected] = GetParam();
  int coeff_count = 4;
  int coeff_count_double = coeff_count * 2;
  int64_t root;

  root = desilo::fhe::find_root(modulus_prime, coeff_count);
  std::vector<int64_t> root_power_series;

  int64_t power_of_root = 1;
  for (auto coeff_index = 0; coeff_index < coeff_count_double; coeff_index++) {
    power_of_root = modulus_multiply_128(power_of_root, root, modulus_prime);

    for (auto power_index = 0; power_index < coeff_index; power_index++) {
      EXPECT_NE(power_of_root, root_power_series[power_index]);
    }

    root_power_series.push_back(power_of_root);
  }

  EXPECT_EQ(1, power_of_root);
  EXPECT_EQ(root, expected);
}

TEST(Arithmetic, GetPowerSeriesSmall) {
  int64_t root = 9;
  int64_t modulus_prime = 17;
  int coeff_count = 4;

  std::vector<int64_t> power_series =
      desilo::fhe::get_power_series(root, modulus_prime, coeff_count);
  int64_t expected[4]{1, 9, 13, 15};

  int64_t power_of_root = 1;
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(expected[coeff_index], power_of_root);
    EXPECT_EQ(power_series[coeff_index], expected[coeff_index]);

    power_of_root *= root;
    power_of_root %= modulus_prime;
  }
}

TEST(Arithmetic, GetPowerSeriesBig) {
  int64_t root = 1715157987554227;
  int64_t modulus_prime = 1152921504606748673;
  int coeff_count = 4;

  std::vector<int64_t> power_series =
      desilo::fhe::get_power_series(root, modulus_prime, coeff_count);
  int64_t expected[4]{1, 1715157987554227, 53176988319565295,
                      365537328503629452};

  int64_t power_of_root = 1;
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(expected[coeff_index], power_of_root);
    EXPECT_EQ(power_series[coeff_index], expected[coeff_index]);

    power_of_root = modulus_multiply_128(power_of_root, root, modulus_prime);
  }
}

TEST(Arithmetic, CalculateKSmall) {
  int64_t r = 8;
  int64_t modulus_prime = 17;

  uint64_t k = desilo::fhe::calculate_k(r, modulus_prime);
  uint64_t expected = 7;

  EXPECT_EQ(expected, (r * desilo::fhe::modulus_invert(r, modulus_prime) - 1) /
                          modulus_prime);
  EXPECT_EQ(k, expected);
}

TEST(Arithmetic, CalculateKBig) {
  int64_t one = 1;
  int64_t r = one << 60;
  int64_t modulus_prime = 1152921504606748673;

  uint64_t k = desilo::fhe::calculate_k(r, modulus_prime);
  uint64_t expected = 1151971516896673791;

  EXPECT_EQ(static_cast<uint128_t>(expected),
            (static_cast<uint128_t>(r) *
                 static_cast<uint128_t>(
                     desilo::fhe::modulus_invert(r, modulus_prime)) -
             static_cast<uint128_t>(1)) /
                static_cast<uint128_t>(modulus_prime));
  EXPECT_EQ(k, expected);
}

TEST(Arithmetic, RNSToDoubleSmall) {

  MAKE_2D_ARRAY(2, 3, x, 0, 1, 2, 6, 0, 1);
  double y[3]{};

  std::vector<uint64_t> q{3, 7};

  const int chain_count = 2;
  const int coeff_count = 3;
  const int coeff_start = 0;
  const int coeff_end = 3;

  auto q_product = desilo::fhe::BigInt(3 * 7);
  auto q_product_half = q_product / 2;
  auto rns_reverser = std::vector<desilo::fhe::BigInt>{desilo::fhe::BigInt(7),
                                                       desilo::fhe::BigInt(15)};
  auto r_minus_k_product = 3513665537849438403;

  desilo::fhe::rns_to_double(x, y, q.data(), q_product, q_product_half,
                             rns_reverser.data(), r_minus_k_product,
                             chain_count, coeff_count, coeff_start, coeff_end);

  double expected[3]{6.0, 7.0, 8.0};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, RNSToDoubleSmallShiftedStart) {

  MAKE_2D_ARRAY(2, 3, x, 0, 1, 2, 6, 0, 1);
  double y[3]{};

  std::vector<uint64_t> q{3, 7};
  std::vector<uint64_t> k{1537228672809129301, 1317624576693539401};

  const int chain_count = 2;
  const int coeff_count = 3;
  const int coeff_start = 1;
  const int coeff_end = 3;

  auto q_product = desilo::fhe::BigInt(3 * 7);
  auto q_product_half = q_product / 2;
  auto rns_reverser = std::vector<desilo::fhe::BigInt>{desilo::fhe::BigInt(7),
                                                       desilo::fhe::BigInt(15)};
  auto r_minus_k_product = 3513665537849438403;

  desilo::fhe::rns_to_double(x, y, q.data(), q_product, q_product_half,
                             rns_reverser.data(), r_minus_k_product,
                             chain_count, coeff_count, coeff_start, coeff_end);

  double expected[3]{0.0, 7.0, 8.0};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, RnsToDoubleBig) {
  const int chain_count = 2;
  const int coeff_count = 3;

  MAKE_2D_ARRAY(2, 3, x, 6, 7, 8, 6, 7, 8);
  double y[3]{};

  uint64_t q[2]{1152921504606584833, 1152921504605962241};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[2]{desilo::fhe::calculate_k(r, q[1]),
                desilo::fhe::calculate_k(r, q[2])};
  auto decode_parameters = desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto q_product = decode_parameters.q_product_;
  auto rns_reverser = decode_parameters.rns_reverser_;
  auto r_minus_k_product = decode_parameters.r_minus_k_product_;

  const int coeff_start = 0;
  const int coeff_end = 3;

  desilo::fhe::rns_to_double_with_power_of_two(
      x, y, q, q_product, rns_reverser.data(), r_minus_k_product, chain_count,
      coeff_count, coeff_start, coeff_end);

  double expected[3]{6.0, 7.0, 8.0};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, RnsToDoubleWithPowerOfTwoSmall) {
  const int chain_count = 3;
  const int coeff_count = 3;

  MAKE_2D_ARRAY(3, 3, x, 2, 3, 0, 0, 1, 2, 6, 0, 1);
  double y[3]{};

  uint64_t q[3]{4, 3, 7};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[3]{0, desilo::fhe::calculate_k(r, q[1]),
                desilo::fhe::calculate_k(r, q[2])};
  auto decode_parameters = desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto q_product = decode_parameters.q_product_;
  auto rns_reverser = decode_parameters.rns_reverser_;
  auto r_minus_k_product = decode_parameters.r_minus_k_product_;

  const int coeff_start = 0;
  const int coeff_end = 3;

  desilo::fhe::rns_to_double_with_power_of_two(
      x, y, q, q_product, rns_reverser.data(), r_minus_k_product, chain_count,
      coeff_count, coeff_start, coeff_end);

  double expected[3]{6.0, 7.0, 8.0};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, RnsToDoubleWithPowerOfTwoSmallWithShiftedStart) {
  const int chain_count = 3;
  const int coeff_count = 3;

  MAKE_2D_ARRAY(3, 3, x, 2, 3, 0, 0, 1, 2, 6, 0, 1);
  double y[3]{};

  uint64_t q[3]{4, 3, 7};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[3]{0, desilo::fhe::calculate_k(r, q[1]),
                desilo::fhe::calculate_k(r, q[2])};
  auto decode_parameters = desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto q_product = decode_parameters.q_product_;
  auto rns_reverser = decode_parameters.rns_reverser_;
  auto r_minus_k_product = decode_parameters.r_minus_k_product_;

  const int coeff_start = 1;
  const int coeff_end = 3;

  desilo::fhe::rns_to_double_with_power_of_two(
      x, y, q, q_product, rns_reverser.data(), r_minus_k_product, chain_count,
      coeff_count, coeff_start, coeff_end);

  double expected[3]{0.0, 7.0, 8.0};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, RnsToDoubleWithPowerOfTwoBig) {
  const int chain_count = 3;
  const int coeff_count = 3;

  MAKE_2D_ARRAY(3, 3, x, 6, 7, 8, 6, 7, 8, 6, 7, 8);
  double y[3]{};

  uint64_t q[3]{UINT64_C(1) << 60, 1152921504606584833, 1152921504605962241};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[3]{0, desilo::fhe::calculate_k(r, q[1]),
                desilo::fhe::calculate_k(r, q[2])};
  auto decode_parameters = desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto q_product = decode_parameters.q_product_;
  auto rns_reverser = decode_parameters.rns_reverser_;
  auto r_minus_k_product = decode_parameters.r_minus_k_product_;

  const int coeff_start = 0;
  const int coeff_end = 3;

  desilo::fhe::rns_to_double_with_power_of_two(
      x, y, q, q_product, rns_reverser.data(), r_minus_k_product, chain_count,
      coeff_count, coeff_start, coeff_end);

  double expected[3]{6.0, 7.0, 8.0};

  expect_array_equals(y, expected, 3);
}

TEST(Arithmetic, DoubleToRNSmall) {

  double x[3]{8.0, 9.0, 10.0};
  MAKE_2D_ARRAY(2, 3, y);

  uint64_t q[2]{5, 7};

  const int chain_count = 2;
  const int coeff_count = 3;
  const int coeff_start = 0;

  desilo::fhe::double_to_rns(x, y, q, chain_count, coeff_count, coeff_start,
                             coeff_count);

  MAKE_2D_ARRAY(2, 3, expected, 3, 4, 0, 1, 2, 3);

  expect_2d_array_equals(y, expected, 2, 3);
}

TEST(Arithmetic, DoubleToRNSmallShiftedStart) {

  double x[3]{8.0, 9.0, 10.0};
  MAKE_2D_ARRAY(2, 3, y);

  uint64_t q[2]{5, 7};

  const int chain_count = 2;
  const int coeff_count = 3;
  const int coeff_start = 1;
  const int coeff_end = 2;

  desilo::fhe::double_to_rns(x, y, q, chain_count, coeff_count, coeff_start,
                             coeff_end);

  MAKE_2D_ARRAY(2, 3, expected, 0, 4, 0, 0, 2, 0);

  expect_2d_array_equals(y, expected, 2, 3);
}

TEST(Arithmetic, DoubleToRNSToDoubleBig) {
  double x[1]{(double)1152921504606748674L};
  MAKE_2D_ARRAY(2, 1, rns);
  double y[1];

  uint64_t q[2]{1099506515969, 1152921504606748673};

  const int chain_count = 2;
  const int coeff_count = 1;
  const int coeff_start = 0;
  const int coeff_end = 1;

  desilo::fhe::double_to_rns(x, rns, q, chain_count, coeff_count, coeff_start,
                             coeff_end);

  auto q_product = desilo::fhe::BigInt({1044836715567546369, 68719157248});
  auto q_product_half = q_product / 2;
  auto rns_reverser = std::vector<desilo::fhe::BigInt>{
      desilo::fhe::BigInt({14948726076072858941ULL, 24956946771}),
      desilo::fhe::BigInt({4542854713204239045, 43762210476})};
  auto r_minus_k_product = 4282651411775258623;

  desilo::fhe::rns_to_double(rns, y, q, q_product, q_product_half,
                             rns_reverser.data(), r_minus_k_product,
                             chain_count, coeff_count, coeff_start, coeff_end);

  expect_array_near(y, x, 1, 1 << 5);
}

TEST(Arithmetic, PositiveModulo1) {
  EXPECT_EQ(desilo::fhe::positive_modulo(1, 3), 1);
}

TEST(Arithmetic, PositiveModulo4) {
  EXPECT_EQ(desilo::fhe::positive_modulo(4, 3), 1);
}

TEST(Arithmetic, PositiveModuloMinus1) {
  EXPECT_EQ(desilo::fhe::positive_modulo(-1, 3), 2);
}

TEST(Arithmetic, PositiveModuloMinus4) {
  EXPECT_EQ(desilo::fhe::positive_modulo(-4, 3), 2);
}
