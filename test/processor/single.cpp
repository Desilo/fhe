#include "processor/single.h"
#include "common/common.h"
#include "common/test.h"
#include "data/polynomial.h"

using namespace std::complex_literals;

TEST(SingleProcessor, MontEnter) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);
  single_processor.mont_enter(x, y, r_squared, q, k, chain_count, coeff_count,
                              x_offset, y_offset);

  int64_t expected[6]{274957467666, 549914935332, 550039715782,
                      381943730,    1966060,      2359272};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[2];

  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter(x, y, r_squared, q, k, chain_count, coeff_count,
                              x_offset, y_offset);

  int64_t expected[6]{0, 0, 550039715782, 381943730, 1966060, 2359272};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterWithReducedCoeffCount) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 1;
  const int reduced_coeff_count = 2;

  auto x = MAKE_REDUCED_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_REDUCED_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter(x, y, r_squared, q, k, chain_count,
                              reduced_coeff_count, x_offset, y_offset);

  int64_t expected[6]{274957467666, 549914935332, 550039715782,
                      381943730,    1966060,      2359272};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontMult) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(2, 2, 2, 2, 2, 2);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 0;
  const int x2_offset = 0;

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_mult(x1, x2, y, q, k, chain_count, x1_offset,
                             x2_offset);

  int64_t expected[6]{277956291297, 555912582594,        922304131616,
                      863236670165, 1150546535331315913, 1150071541476229361};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontMultWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(2, 2, 2, 2, 2, 2);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 1;
  const int x2_offset = 1;
  chain_count -= x1_offset;

  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_mult(x1, x2, y, q, k, chain_count, x1_offset,
                             x2_offset);

  int64_t expected[6]{922304131616,
                      863236670165,
                      1150546535331315913,
                      1150071541476229361,
                      0,
                      0};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, Reduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.reduce_2q_to_q(x, y, q, chain_count);

  int64_t expected[6]{1, 2, 3, 4, 5, 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MakeSigned) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 1099516280831, 3, 1099506515965, 5,
                           1152921504606748667);
  auto y = MAKE_POLYNOMIAL();

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t q_half[3]{549758140416, 549753257984, 576460752303374336};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.make_signed(x, y, q, q_half, chain_count, coeff_count);

  int64_t expected[6]{1, -2, 3, -4, 5, -6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MakeSignedWithReducedCoeffCount) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 1;
  const int reduced_coeff_count = 2;

  auto x = MAKE_REDUCED_POLYNOMIAL(1, 1099516280831, 3, 1099506515965, 5,
                                   1152921504606748667);
  auto y = MAKE_REDUCED_POLYNOMIAL();

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t q_half[3]{549758140416, 549753257984, 576460752303374336};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.make_signed(x, y, q, q_half, chain_count,
                               reduced_coeff_count);

  int64_t expected[6]{1, -2, 3, -4, 5, -6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontAdd) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(7, 8, 9, 10, 11, 12);
  auto y = MAKE_POLYNOMIAL();

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_add(x1, x2, y, q_double, chain_count);

  int64_t expected[6]{8, 10, 12, 14, 16, 18};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, AddTiled) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(7, 9);
  auto y = MAKE_POLYNOMIAL();
  const uint64_t q_double[3]{6, 10, 14};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.add_tiled(x1, x2, y, q_double, chain_count);

  int64_t expected[6]{2, 5, 0, 3, 12, 1};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, SubTiled) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(11, 12, 13, 14, 15, 16);
  auto x2 = MAKE_POLYNOMIAL(7, 9);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 0;
  const int y_offset = 0;

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.sub_tiled(x1, x2, y, q_double, chain_count, x1_offset,
                             y_offset);

  int64_t expected[6]{4, 3, 6, 5, 8, 7};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, SubTiledWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(11, 12, 13, 14, 15, 16);
  auto x2 = MAKE_POLYNOMIAL(7, 9);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 1;
  chain_count -= x1_offset;
  const int y_offset = 1;

  uint64_t q_double[2]{2199013031938, 2305843009213497346};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.sub_tiled(x1, x2, y, q_double, chain_count, x1_offset,
                             y_offset);

  int64_t expected[6]{0, 0, 6, 5, 8, 7};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, GetRounder) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 1;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 2;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;

  const uint64_t q_half = 4;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.get_rounder(x, y, q_half, x_offset);

  int64_t expected[8]{0, 0, 0, 0, 1, 1, 1, 1};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, GetRounderWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 2;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(8, 8, 8, 8, 8, 8, 8, 8, 1, 2, 3, 4, 5, 6, 7, 8);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 1;

  const uint64_t q_half = 4;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.get_rounder(x, y, q_half, x_offset);

  int64_t expected[8]{0, 0, 0, 0, 1, 1, 1, 1};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterTiled) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_tiled(x, y, r_squared, q, k, chain_count,
                                    x_offset, y_offset);

  int64_t expected[6]{274957467666, 549914935332, 549848743917,
                      190971865,    393212,       786424};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterTiledWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(0, 0, 1, 2);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[2];

  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_tiled(x, y, r_squared, q, k, chain_count,
                                    x_offset, y_offset);

  int64_t expected[6]{0, 0, 549848743917, 190971865, 393212, 786424};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterTiledAdd) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2);
  auto y = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);

  const int x_offset = 0;
  const int y_offset = 0;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_tiled_add(x, y, r_squared, q_double, q, k,
                                        chain_count, x_offset, y_offset);

  int64_t expected[6]{274957467666 + 1, 549914935332 + 2, 549848743917 + 3,
                      190971865 + 4,    393212 + 5,       786424 + 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterTiledAddWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(0, 0, 1, 2);
  auto y = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[2];

  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_tiled_add(x, y, r_squared, q_double, q, k,
                                        chain_count, x_offset, y_offset);

  int64_t expected[6]{1,          2,         549848743917 + 3, 190971865 + 4,
                      393212 + 5, 786424 + 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterTiledAddReduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2);
  auto y = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);

  const int x_offset = 0;
  const int y_offset = 0;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_tiled_add_reduce_2q_to_q(
      x, y, r_squared, q_double, q, k, chain_count, x_offset, y_offset);

  int64_t expected[6]{274957467666 + 1, 549914935332 + 2, 549848743917 + 3,
                      190971865 + 4,    393212 + 5,       786424 + 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterTiledAddReduce2QToQWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(0, 0, 1, 2);
  auto y = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[2];

  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_tiled_add_reduce_2q_to_q(
      x, y, r_squared, q_double, q, k, chain_count, x_offset, y_offset);

  int64_t expected[6]{1,          2,         549848743917 + 3, 190971865 + 4,
                      393212 + 5, 786424 + 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontMultAdd) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(2, 2, 2, 2, 2, 2);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 0;
  const int x2_offset = 0;

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_mult_add(x1, x2, y, q_double, q, k, chain_count,
                                 x1_offset, x2_offset);

  int64_t expected[6]{277956291297, 555912582594,        922304131616,
                      863236670165, 1150546535331315913, 1150071541476229361};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontMultAddWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(2, 2, 2, 2, 2, 2);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 1;
  const int x2_offset = 1;
  chain_count -= x1_offset;

  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_mult_add(x1, x2, y, q_double, q, k, chain_count,
                                 x1_offset, x2_offset);

  int64_t expected[6]{922304131616,
                      863236670165,
                      1150546535331315913,
                      1150071541476229361,
                      0,
                      0};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontSubEnterReduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(1, 1, 1, 1, 1, 1);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 0;
  const int x2_offset = 0;
  const int y_offset = 0;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_sub_enter_reduce_2q_to_q(x1, x2, y, r_squared, q_double,
                                                 q, k, chain_count, x1_offset,
                                                 x2_offset, y_offset);

  int64_t expected[6]{0,       274957467666, 190971865, 550039715782,
                      1572848, 1966060};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontSubEnterReduce2QToQWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(1, 1, 1, 1, 1, 1);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 1;
  const int x2_offset = 1;
  const int y_offset = 1;
  chain_count -= x1_offset;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[2];

  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_sub_enter_reduce_2q_to_q(x1, x2, y, r_squared, q_double,
                                                 q, k, chain_count, x1_offset,
                                                 x2_offset, y_offset);

  int64_t expected[6]{0, 0, 190971865, 550039715782, 1572848, 1966060};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontSubTiledEnter) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(1, 1);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 0;
  const int x2_offset = 0;
  const int y_offset = 0;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_sub_tiled_enter(x1, x2, y, r_squared, q_double, q, k,
                                        chain_count, x1_offset, x2_offset,
                                        y_offset);

  int64_t expected[6]{0,       274957467666, 190971865, 550039715782,
                      1572848, 1966060};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontSubTiledEnterWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(0, 0, 1, 1);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 1;
  const int x2_offset = 1;
  const int y_offset = 1;
  chain_count -= x1_offset;

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_sub_tiled_enter(x1, x2, y, r_squared, q_double, q, k,
                                        chain_count, x1_offset, x2_offset,
                                        y_offset);

  int64_t expected[6]{0, 0, 190971865, 550039715782, 1572848, 1966060};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontEnterExit) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_exit(x, y, r_squared, q, k, chain_count);

  int64_t expected[6]{1, 2, 3, 4, 5, 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontEnterExitReduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  int64_t one = 1;
  int64_t r = one << 62;
  int64_t r_squared[3];

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    r_squared[chain_index] = modulus_multiply_128(r, r, q[chain_index]);
  }

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_enter_exit_reduce_2q_to_q(x, y, r_squared, q, k,
                                                  chain_count);

  int64_t expected[6]{1, 2, 3, 4, 5, 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MontAddReduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(7, 8, 9, 10, 11, 12);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 0;
  const int x2_offset = 0;
  const int y_offset = 0;

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_add_reduce_2q_to_q(x1, x2, y, q_double, q, chain_count,
                                           x1_offset, x2_offset, y_offset);

  int64_t expected[6]{8, 10, 12, 14, 16, 18};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontAddReduce2QToQWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto x2 = MAKE_POLYNOMIAL(7, 8, 9, 10, 11, 12);
  auto y = MAKE_POLYNOMIAL();

  const int x1_offset = 1;
  const int x2_offset = 1;
  const int y_offset = 1;
  chain_count -= x1_offset;

  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t q[2]{1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_add_reduce_2q_to_q(x1, x2, y, q_double, q, chain_count,
                                           x1_offset, x2_offset, y_offset);

  int64_t expected[6]{0, 0, 12, 14, 16, 18};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MontSubReduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(7, 8, 9, 10, 11, 12);
  auto x2 = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q, chain_count);

  int64_t expected[6]{6, 6, 6, 6, 6, 6};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, MakeUnsignedReduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(-2, -1, 0, 1, 2, 3);
  auto y = MAKE_POLYNOMIAL();

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.make_unsigned_reduce_2q_to_q(x, y, q, chain_count,
                                                coeff_count);

  int64_t expected[6]{1099516280831, 1099516280832, 0, 1, 2, 3};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MakeUnsignedReduce2QToQWithReducedCoeffCount) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 1;
  const int reduced_coeff_count = 2;

  auto x = MAKE_REDUCED_POLYNOMIAL(-2, -1, 0, 1, 2, 3);
  auto y = MAKE_REDUCED_POLYNOMIAL();

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.make_unsigned_reduce_2q_to_q(x, y, q, chain_count,
                                                reduced_coeff_count);

  int64_t expected[6]{1099516280831, 1099516280832, 0, 1, 2, 3};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, TileUnsignedReduce2QToQ) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(-2, 2, 13, 21);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  uint64_t q[3]{5, 7, 11};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.tile_unsigned_reduce_2q_to_q(
      x, y, q, chain_count, coeff_count, x_offset, y_offset);

  int64_t expected[12]{3, 2, 8, 16, 5, 2, 6, 14, 9, 2, 2, 10};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, TileUnsignedReduce2QToQWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(0, 0, 0, 0, -2, 2, 13, 21);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  uint64_t q[2]{7, 11};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.tile_unsigned_reduce_2q_to_q(
      x, y, q, chain_count, coeff_count, x_offset, y_offset);

  int64_t expected[12]{0, 0, 0, 0, 5, 2, 6, 14, 9, 2, 2, 10};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, TileUnsignedReduce2QToQWithReducedCoeffCount) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 1;
  const int reduced_coeff_count = 2;

  auto x = MAKE_REDUCED_POLYNOMIAL(-2, 13);
  auto y = MAKE_REDUCED_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  uint64_t q[3]{5, 7, 11};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.tile_unsigned_reduce_2q_to_q(
      x, y, q, chain_count, reduced_coeff_count, x_offset, y_offset);

  int64_t expected[6]{3, 8, 5, 6, 9, 2};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, NegateMakeUnsigned) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const int moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.negate_make_unsigned(x, y, q, chain_count);

  int64_t expected[6]{
      static_cast<int64_t>(q[0] - 1), static_cast<int64_t>(q[0] - 2),
      static_cast<int64_t>(q[1] - 3), static_cast<int64_t>(q[1] - 4),
      static_cast<int64_t>(q[2] - 5), static_cast<int64_t>(q[2] - 6)};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, ConcatenateTileUnsigned) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const int moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x1 = MAKE_POLYNOMIAL(0, 1);
  auto x2 = MAKE_POLYNOMIAL(2, 3);
  auto y = MAKE_POLYNOMIAL();

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.concatenate_tile_unsigned(x1, x2, y, q, chain_count);

  const uint128_t mean_value = static_cast<uint128_t>(1) << 75;

  int64_t expected[6]{
      static_cast<int64_t>((2 - mean_value) % q[0] + q[0]),
      static_cast<int64_t>(
          ((static_cast<uint128_t>(1) << 63) + 3 - mean_value) % q[0] + q[0]),
      static_cast<int64_t>((2 - mean_value) % q[1] + q[1]),
      static_cast<int64_t>(
          ((static_cast<uint128_t>(1) << 63) + 3 - mean_value) % q[1] + q[1]),
      static_cast<int64_t>((2 - mean_value) % q[2] + q[2]),
      static_cast<int64_t>(
          ((static_cast<uint128_t>(1) << 63) + 3 - mean_value) % q[2] + q[2])};

  expect_polynomial_equals(y, expected);

  delete x1;
  delete x2;
  delete y;
}

TEST(SingleProcessor, ApplySkewer) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 1;
  const int slot_count = 4;
  const int coeff_count = 2 * slot_count;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 3;
  const double step = std::numbers::pi / (coeff_count * 2);
  auto x = MAKE_DOUBLE_POLYNOMIAL(coeff_count, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0,
                                  7.0, 8.0);
  auto y = MAKE_DOUBLE_POLYNOMIAL(coeff_count * 2);

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.apply_skewer(x, y, step, coeff_count);

  double expected[coeff_count * 2]{1.000000,  0.000000, 1.847759,  0.765367,
                                   2.121320,  2.121320, 1.530734,  3.695518,
                                   0.000000,  5.000000, -2.296101, 5.543277,
                                   -4.949747, 4.949747, -7.391036, 3.061467};

  expect_array_near(y->buffer_, expected, coeff_count * 2, 1e-6);

  delete x;
  delete y;
}

TEST(SingleProcessor, FFT) {
  auto x = new std::complex<double>[8]{
      std::complex(0.0, 1.0),   std::complex(2.0, 3.0),
      std::complex(4.0, 5.0),   std::complex(6.0, 7.0),
      std::complex(8.0, 9.0),   std::complex(10.0, 11.0),
      std::complex(12.0, 13.0), std::complex(14.0, 15.0)};
  auto y = new std::complex<double>[8]{};

  std::complex<double> twiddle_factor[8]{
      std::complex<double>(1.0, -0.0),
      std::complex<double>(0.7071067811865476, -0.7071067811865475),
      std::complex<double>(0.0, -1.0),
      std::complex<double>(-0.7071067811865475, -0.7071067811865476),
      std::complex<double>(-1.0, 0.0),
      std::complex<double>(-0.7071067811865477, 0.7071067811865475),
      std::complex<double>(0.0, 1.0),
      std::complex<double>(0.7071067811865474, 0.7071067811865477)};

  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 3;
  const int thread_count = 8;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.fft(x, y, twiddle_factor, coeff_count);

  std::complex<double> expected[8]{
      std::complex<double>(56.0, 64.0),
      std::complex<double>(-6.828427124746190, 2.828427124746190),
      std::complex<double>(-16.0, 0.0),
      std::complex<double>(-2.828427124746190, -1.171572875253810),
      std::complex<double>(-32.0, -32.0),
      std::complex<double>(-1.171572875253810, -2.828427124746190),
      std::complex<double>(0.0, -16.0),
      std::complex<double>(2.828427124746190, -6.828427124746190)};

  expect_complex_array_near(y, expected, 8, 1e-10);

  delete[] x;
  delete[] y;
}

TEST(SingleProcessor, IFFT) {

  auto x = new std::complex<double>[8]{
      std::complex(0.0, 1.0),   std::complex(2.0, 3.0),
      std::complex(4.0, 5.0),   std::complex(6.0, 7.0),
      std::complex(8.0, 9.0),   std::complex(10.0, 11.0),
      std::complex(12.0, 13.0), std::complex(14.0, 15.0)};
  auto y = new std::complex<double>[8]{};

  std::complex<double> twiddle_factor[8]{
      std::complex<double>(1.0, -0.0),
      std::complex<double>(0.7071067811865476, -0.7071067811865475),
      std::complex<double>(0.0, -1.0),
      std::complex<double>(-0.7071067811865475, -0.7071067811865476),
      std::complex<double>(-1.0, 0.0),
      std::complex<double>(-0.7071067811865477, 0.7071067811865475),
      std::complex<double>(0.0, 1.0),
      std::complex<double>(0.7071067811865474, 0.7071067811865477)};

  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 3;
  const int thread_count = 8;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.ifft(x, y, twiddle_factor, coeff_count);

  std::complex<double> expected[8]{
      std::complex<double>(56.0, 64.0),
      std::complex<double>(-6.828427124746190, 2.828427124746190),
      std::complex<double>(-16.0, 0.0),
      std::complex<double>(-2.828427124746190, -1.171572875253810),
      std::complex<double>(-32.0, -32.0),
      std::complex<double>(-1.171572875253810, -2.828427124746190),
      std::complex<double>(0.0, -16.0),
      std::complex<double>(2.828427124746190, -6.828427124746190)};

  expect_complex_array_near(y, expected, 8, 1e-10);

  delete[] x;
  delete[] y;
}

TEST(SingleProcessor, ExtractDoubleDiagonals) {
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 4;
  const int slot_count = 4;
  int outer_loop_count = 2;
  int inner_loop_count = 2;
  const int matrix_size = slot_count * slot_count;

  double x[matrix_size]{0.0, 1.0, 2.0,  3.0,  4.0,  5.0,  6.0,  7.0,
                        8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
  double y[matrix_size]{};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.extract_diagonals(x, y, outer_loop_count, inner_loop_count);

  double expected[matrix_size]{8.0, 13.0, 2.0,  7.0,  11.0, 12.0, 1.0, 6.0,
                               0.0, 5.0,  10.0, 15.0, 3.0,  4.0,  9.0, 14.0};

  expect_array_near(y, expected, matrix_size, 1e-6);
}

TEST(SingleProcessor, ExtractComplexDoubleDiagonals) {
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 4;
  const int slot_count = 4;
  int outer_loop_count = 2;
  int inner_loop_count = 2;
  const int matrix_size = slot_count * slot_count;

  // clang-format off
  std::complex<double> x[matrix_size]= {
     0.0 +  1.0i,  2.0 +  3.0i,  4.0 +  5.0i,  6.0 +  7.0i,
     8.0 +  9.0i, 10.0 + 11.0i, 12.0 + 13.0i, 14.0 + 15.0i,
    16.0 + 17.0i, 18.0 + 19.0i, 20.0 + 21.0i, 22.0 + 23.0i,
    24.0 + 25.0i, 26.0 + 27.0i, 28.0 + 29.0i, 30.0 + 31.0i
  };
  // clang-format on
  std::complex<double> y[matrix_size]{};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.extract_diagonals(x, y, outer_loop_count, inner_loop_count);

  // clang-format off
  std::complex<double> expected[matrix_size] = {
    16.0 + 17.0i, 26.0 + 27.0i,  4.0 +  5.0i, 14.0 + 15.0i,
    22.0 + 23.0i, 24.0 + 25.0i,  2.0 +  3.0i, 12.0 + 13.0i,
     0.0 +  1.0i, 10.0 + 11.0i, 20.0 + 21.0i, 30.0 + 31.0i,
     6.0 +  7.0i,  8.0 +  9.0i, 18.0 + 19.0i, 28.0 + 29.0i
  };
  // clang-format on

  expect_complex_array_near(y, expected, matrix_size, 1e-6);
}

TEST(SingleProcessor, NTT) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const int moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 16;
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 4;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                           29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                           42, 43, 44, 45, 46, 47, 48);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  int64_t root[45]{
      780606812115,       763731180544,        154587623593,
      958218454078,       176803883671,        477177733653,
      939578091236,       481845117488,        49782997585,
      466568132087,       1018420183770,       840788436137,
      731920682876,       617280680927,        263790634652,
      410805163054,       991750328952,        389842085578,
      439443786801,       853871996568,        592509650983,
      449067419331,       1023482402500,       265930125494,
      504933639342,       1002010863354,       262215764403,
      643209271845,       983060172814,        770523189176,
      445523564914844012, 1114543911831482092, 92957750393765587,
      374223376506562498, 237945617869062053,  918685707495368215,
      506518236117363374, 942691695796424289,  1016829299996668691,
      698654225727993496, 766768146987828485,  1024812789527317631,
      75383585495846076,  890374734757206973,  1140647851859174720};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.ntt(x, y, root, q_double, q, k, chain_count, x_offset,
                       y_offset);

  int64_t expected[48]{
      235537799153,        802484260053,        1551971690156,
      683241780856,        1243328266515,       554377011293,
      611044096611,        1157289888235,       1598732250346,
      73266655482,         1734532673907,       1466597893825,
      1581525955325,       417312901033,        1987198349242,
      1893819021312,       192509668603,        557756868883,
      1480019253145,       2139879973313,       172082602833,
      1582614032277,       1000993543929,       2016059715809,
      1741320531557,       749916550715,        2105696609975,
      903699014977,        158319883481,        5217026777,
      1704332540548,       1081686438954,       14947412712467306,
      918950323753715060,  1477059581712712580, 879497993422722796,
      1992569885800496398, 745418019322416606,  539288231784624233,
      1650948683454272661, 659143952246137398,  2145440732021704152,
      48847083800160000,   1328621037977257730, 242945182709862997,
      533872763849377063,  1903125346161202939, 1060224833765352031};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, NTTWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const int moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 16;
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 4;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                           29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                           42, 43, 44, 45, 46, 47, 48);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  int64_t root[30]{
      410805163054,       991750328952,        389842085578,
      439443786801,       853871996568,        592509650983,
      449067419331,       1023482402500,       265930125494,
      504933639342,       1002010863354,       262215764403,
      643209271845,       983060172814,        770523189176,
      445523564914844012, 1114543911831482092, 92957750393765587,
      374223376506562498, 237945617869062053,  918685707495368215,
      506518236117363374, 942691695796424289,  1016829299996668691,
      698654225727993496, 766768146987828485,  1024812789527317631,
      75383585495846076,  890374734757206973,  1140647851859174720};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.ntt(x, y, root, q_double, q, k, chain_count, x_offset,
                       y_offset);

  int64_t expected[48]{0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       192509668603,
                       557756868883,
                       1480019253145,
                       2139879973313,
                       172082602833,
                       1582614032277,
                       1000993543929,
                       2016059715809,
                       1741320531557,
                       749916550715,
                       2105696609975,
                       903699014977,
                       158319883481,
                       5217026777,
                       1704332540548,
                       1081686438954,
                       14947412712467306,
                       918950323753715060,
                       1477059581712712580,
                       879497993422722796,
                       1992569885800496398,
                       745418019322416606,
                       539288231784624233,
                       1650948683454272661,
                       659143952246137398,
                       2145440732021704152,
                       48847083800160000,
                       1328621037977257730,
                       242945182709862997,
                       533872763849377063,
                       1903125346161202939,
                       1060224833765352031};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, INTT) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const int moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 16;
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 4;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                           29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                           42, 43, 44, 45, 46, 47, 48);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  uint64_t q_double[3]{2199032561666, 2199013031938, 2305843009213497346};
  uint64_t k[3]{2888757134567604223, 2181968988386492415, 4610736030717214719};

  int64_t root_inverse[45]{
      835725646181,        482235599906,       367595597957,
      258727844696,        81096097063,        632948148746,
      1049733283248,       617671163345,       159938189597,
      622338547180,        922712397162,       141297826755,
      944928657240,        335785100289,       318909468718,
      328983326793,        116446343155,       456297244124,
      837290751566,        97495652615,        594572876627,
      833576390475,        76024113469,        650439096638,
      506996864986,        245634519401,       660062729168,
      709664430391,        107756187017,       688701352915,
      12273652747573953,   262546769849541700, 1077537919110902597,
      128108715079431042,  386153357618920188, 454267278878755177,
      136092204610079982,  210229808810324384, 646403268489385299,
      234235797111380458,  914975886737686620, 778698128100186175,
      1059963754212983086, 38377592775266581,  707397939691904661};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.intt(x, y, root_inverse, q_double, q, k, chain_count,
                        x_offset, y_offset);

  int64_t expected[48]{136,
                       536603497834,
                       1050608649481,
                       1126716830923,
                       1688134858523,
                       1859107302369,
                       1871375589873,
                       545144540470,
                       948279394214,
                       545144540470,
                       771859309040,
                       759591021536,
                       588618577690,
                       27200550090,
                       1050608649481,
                       536603497834,
                       392,
                       2135616629993,
                       1297526045276,
                       21753508409,
                       1625288829819,
                       1471253393054,
                       1767580382843,
                       610656070308,
                       1078242063942,
                       610656070308,
                       668073866874,
                       371746877085,
                       525782313850,
                       21753508409,
                       198019529307,
                       1036110114024,
                       648,
                       772928433585957056,
                       1137027003840613666,
                       251299145997629478,
                       1264353765431944172,
                       1897903561927580023,
                       811444778175028849,
                       2153052526931802254,
                       1097484243238681534,
                       1000131022325053581,
                       811444778175028849,
                       744982057320831350,
                       1264353765431944172,
                       251299145997629478,
                       1137027003840613666,
                       772928433585957056};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, INTTWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const int moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 16;
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 4;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                           29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                           42, 43, 44, 45, 46, 47, 48);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  uint64_t q[2]{1099506515969, 1152921504606748673};
  uint64_t q_double[2]{2199013031938, 2305843009213497346};
  uint64_t k[2]{2181968988386492415, 4610736030717214719};

  int64_t root_inverse[30]{
      328983326793,        116446343155,       456297244124,
      837290751566,        97495652615,        594572876627,
      833576390475,        76024113469,        650439096638,
      506996864986,        245634519401,       660062729168,
      709664430391,        107756187017,       688701352915,
      12273652747573953,   262546769849541700, 1077537919110902597,
      128108715079431042,  386153357618920188, 454267278878755177,
      136092204610079982,  210229808810324384, 646403268489385299,
      234235797111380458,  914975886737686620, 778698128100186175,
      1059963754212983086, 38377592775266581,  707397939691904661};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.intt(x, y, root_inverse, q_double, q, k, chain_count,
                        x_offset, y_offset);

  int64_t expected[48]{0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       0,
                       392,
                       2135616629993,
                       1297526045276,
                       21753508409,
                       1625288829819,
                       1471253393054,
                       1767580382843,
                       610656070308,
                       1078242063942,
                       610656070308,
                       668073866874,
                       371746877085,
                       525782313850,
                       21753508409,
                       198019529307,
                       1036110114024,
                       648,
                       772928433585957056,
                       1137027003840613666,
                       251299145997629478,
                       1264353765431944172,
                       1897903561927580023,
                       811444778175028849,
                       2153052526931802254,
                       1097484243238681534,
                       1000131022325053581,
                       811444778175028849,
                       744982057320831350,
                       1264353765431944172,
                       251299145997629478,
                       1137027003840613666,
                       772928433585957056};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, RotatePolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 2;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 3;

  auto x =
      MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18);
  auto y = MAKE_POLYNOMIAL();

  int32_t permutation[8]{0, 5, 2, 7, 4, 1, 6, 3};
  int32_t sign[8]{1, -1, -1, 1, 1, 1, -1, -1};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.rotate_polynomial(x, y, permutation, sign, chain_count);

  int64_t expected[16]{1,  6,  -3,  -8,  5,  -2,  -7,  4,
                       11, 16, -13, -18, 15, -12, -17, 14};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, PermutePolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 2;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 3;

  auto x =
      MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18);
  auto y = MAKE_POLYNOMIAL();

  int32_t permutation[8]{0, 5, 2, 7, 4, 1, 6, 3};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.permute_polynomial(x, y, permutation, chain_count);

  int64_t expected[16]{1, 6, 3, 8, 5, 2, 7, 4, 11, 16, 13, 18, 15, 12, 17, 14};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, AddScalar) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  int64_t scalar[3]{1, 2, 3};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.add_scalar(x, y, scalar, chain_count);

  int64_t expected[6]{2, 2, 5, 4, 8, 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, ZeroFill) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto y = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);

  const int y_offset = 0;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.zero_fill(y, chain_count, coeff_count, y_offset);

  int64_t expected[6]{0, 0, 0, 0, 0, 0};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, ZeroFillWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto y = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);

  const int y_offset = 1;
  chain_count -= y_offset;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.zero_fill(y, chain_count, coeff_count, y_offset);

  int64_t expected[6]{1, 2, 0, 0, 0, 0};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, ZeroFillWithReducedCoeffCount) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 1;
  const int reduced_coeff_count = 2;

  auto y = MAKE_REDUCED_POLYNOMIAL(1, 2, 3, 4, 5, 6);

  const int y_offset = 0;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.zero_fill(y, chain_count, reduced_coeff_count, y_offset);

  int64_t expected[6]{0, 0, 0, 0, 0, 0};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, Copy) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.copy(x, y, chain_count, x_offset, y_offset);

  int64_t expected[6]{1, 2, 3, 4, 5, 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, CopyWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 1;
  const int y_offset = 1;
  chain_count -= x_offset;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.copy(x, y, chain_count, x_offset, y_offset);

  int64_t expected[6]{0, 0, 3, 4, 5, 6};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, DecompressPolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int log_codec_coeff_count = 1;
  const int reduced_coeff_count = 2;

  auto x = MAKE_REDUCED_POLYNOMIAL(1, 2, 3, 4, 5, 6);
  auto y = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.decompress_polynomial(x, y, chain_count);

  int64_t expected[24]{1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,
                       4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, CompressPolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int reduced_coeff_count = 2;
  const int log_codec_coeff_count = 1;

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24);
  auto y = MAKE_REDUCED_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.compress_polynomial(x, y, chain_count);

  int64_t expected[6]{1, 5, 9, 13, 17, 21};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, CompressThenDecompressPolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 3;
  const int coeff_count = 8;
  const int log_coeff_count = 3;
  const int reduced_coeff_count = 2;
  const int log_codec_coeff_count = 1;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  auto x = MAKE_POLYNOMIAL(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24);
  auto y = MAKE_REDUCED_POLYNOMIAL();
  auto z = MAKE_POLYNOMIAL();

  const int x_offset = 0;
  const int y_offset = 0;
  const int z_offset = 0;

  single_processor.compress_polynomial(x, y, chain_count);
  single_processor.decompress_polynomial(y, z, chain_count);

  int64_t expected[24]{1,  0, 0, 0, 5,  0, 0, 0, 9,  0, 0, 0,
                       13, 0, 0, 0, 17, 0, 0, 0, 21, 0, 0, 0};

  expect_polynomial_equals(z, expected);

  delete x;
  delete y;
  delete z;
}

TEST(SingleProcessor, CopyToPolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 3;
  const int coeff_count = 2;
  const int log_coeff_count = 1;
  const int log_codec_coeff_count = 1;

  int64_t x[6]{1, 2, 3, 4, 5, 6};
  auto y = MAKE_POLYNOMIAL();

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.copy_to_polynomial(x, y, chain_count);

  int64_t expected[6]{1, 2, 3, 4, 5, 6};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, Round) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 1;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 2;

  auto x_buffer = new double[4]{1.2, 3.4, 5.6, 7.8};
  auto x =
      new desilo::fhe::DoublePolynomial(x_buffer, flag, moduli_id, coeff_count);
  auto y = MAKE_POLYNOMIAL();

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.round(x, y, chain_count);

  int64_t expected[coeff_count]{1, 3, 6, 8};

  expect_polynomial_equals(y, expected);

  delete x;
  delete y;
}

TEST(SingleProcessor, MaxAbsolutePositiveValue) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 1;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 2;

  auto x_buffer = new double[4]{1.2, 7.8, -5.6, -3.4};
  auto x =
      new desilo::fhe::DoublePolynomial(x_buffer, flag, moduli_id, coeff_count);
  double y;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.max_absolute(x, &y);

  EXPECT_EQ(y, 7.8);

  delete x;
}

TEST(SingleProcessor, MaxAbsoluteNegativeValue) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 1;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 2;

  auto x_buffer = new double[4]{1.0, -5.6, 3.2, -4.1};
  auto x =
      new desilo::fhe::DoublePolynomial(x_buffer, flag, moduli_id, coeff_count);
  double y;

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.max_absolute(x, &y);

  EXPECT_EQ(y, 5.6);

  delete x;
}

TEST(SingleProcessor, DoubleToRNS) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 2;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 2;

  double x[4]{8.0, 9.0, 10.0, 11.0};
  auto y = MAKE_POLYNOMIAL();

  const int y_offset = 0;

  uint64_t q[2]{5, 7};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.double_to_rns(x, y, q, chain_count, y_offset);

  int64_t expected[8]{3, 4, 0, 1, 1, 2, 3, 4};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, DoubleToRNSReducedCoeffCount) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const int chain_count = 2;
  const int coeff_count = 16;
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 2;
  const int output_count = chain_count * coeff_count;
  const int reduced_coeff_count = 4;

  double x[4]{8.0, 9.0, 10.0, 11.0};
  auto y = MAKE_REDUCED_POLYNOMIAL();

  const int y_offset = 0;

  uint64_t q[2]{5, 7};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.double_to_rns(x, y, q, chain_count, y_offset);

  int64_t expected[8]{3, 4, 0, 1, 1, 2, 3, 4};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, DoubleToRNSWithOffset) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 2;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 2;

  double x[4]{8.0, 9.0, 10.0, 11.0};
  auto y = MAKE_POLYNOMIAL();

  const int y_offset = 1;
  chain_count -= y_offset;

  uint64_t q[1]{7};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.double_to_rns(x, y, q, chain_count, y_offset);

  int64_t expected[8]{0, 0, 0, 0, 1, 2, 3, 4};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, DoubleToRNSWithOffsetReducedCoeffCount) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  int chain_count = 2;
  const int coeff_count = 16;
  const int log_coeff_count = 4;
  const int log_codec_coeff_count = 2;
  const int output_count = chain_count * coeff_count;
  const int reduced_coeff_count = 4;

  double x[4]{8.0, 9.0, 10.0, 11.0};
  auto y = MAKE_REDUCED_POLYNOMIAL();

  const int y_offset = 1;
  chain_count -= y_offset;

  uint64_t q[1]{7};

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.double_to_rns(x, y, q, chain_count, y_offset);

  int64_t expected[8]{0, 0, 0, 0, 1, 2, 3, 4};

  expect_polynomial_equals(y, expected);

  delete y;
}

TEST(SingleProcessor, CastInt64ToDouble) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const int moduli_id = 0;
  const int chain_count = 1;
  const int coeff_count = 4;
  const int log_coeff_count = 2;
  const int log_codec_coeff_count = 2;

  auto x = MAKE_POLYNOMIAL(1, -2, 3, -4);
  auto y = MAKE_DOUBLE_POLYNOMIAL(coeff_count);

  desilo::fhe::SingleProcessor single_processor(log_coeff_count,
                                                log_codec_coeff_count);

  single_processor.cast_int64_to_double(x, y, chain_count);

  double expected[coeff_count]{1.0, -2.0, 3.0, -4.0};

  expect_array_near(y->buffer_, expected, coeff_count, 1e-9);

  delete x;
  delete y;
}
