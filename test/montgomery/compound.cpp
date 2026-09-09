#include "montgomery/compound.h"
#include "common/test.h"

typedef unsigned __int128 uint128_t;

TEST(Montgomery, EnterAddZero) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_add(x, y, r_squared, q_double, q, k, coeff_count);

  int64_t expected[2]{274957467666, 549914935332};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterAdd) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{1, 2};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_add(x, y, r_squared, q_double, q, k, coeff_count);

  int64_t expected[2]{274957467666 + 1, 549914935332 + 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterAddReduce2QToQZero) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_add_reduce_2q_to_q(x, y, r_squared, q_double, q, k,
                                             coeff_count);

  int64_t expected[6]{274957467666, 549914935332};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterAddReduce2QToQ) {
  const int coeff_count = 2;

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{int64_t(q) + 1, int64_t(q) + 2};

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_add_reduce_2q_to_q(x, y, r_squared, q_double, q, k,
                                             coeff_count);

  int64_t expected[6]{274957467666 + 1, 549914935332 + 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, MultAddZero) {
  int64_t x1[2]{1, 2};
  int64_t x2[2]{2, 2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  const int coeff_count = 2;

  desilo::fhe::mont_mult_add(x1, x2, y, q_double, q, k, coeff_count);

  uint128_t r_inverse = 688736286065;
  int64_t expected[2]{277956291297, 555912582594};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {

    EXPECT_EQ(
        expected[coeff_index],
        modulus_multiply_128(x1[coeff_index], x2[coeff_index], r_inverse, q));

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, MultAdd) {
  int64_t x1[2]{1, 2};
  int64_t x2[2]{2, 2};
  int64_t y[2]{1, 2};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  const int coeff_count = 2;

  desilo::fhe::mont_mult_add(x1, x2, y, q_double, q, k, coeff_count);

  int64_t expected[2]{
      277956291297 + 1,
      555912582594 + 2,
  };

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, MultAddGuard) {
  int64_t x1[2]{1, 2};
  int64_t x2[2]{2, 2};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  int64_t y[2]{static_cast<int64_t>(q_double) + 1,
               static_cast<int64_t>(q_double) + 2};
  uint64_t k = 2888757134567604223;

  const int coeff_count = 2;

  desilo::fhe::mont_mult_add(x1, x2, y, q_double, q, k, coeff_count);

  int64_t expected[2]{277956291297 + 1, 555912582594 + 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubEnterReduce2QToQPositive) {
  const int coeff_count = 2;

  int64_t x1[2]{1, 2};
  int64_t x2[2]{1, 1};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_sub_enter_reduce_2q_to_q(x1, x2, y, r_squared, q_double, q,
                                             k, coeff_count);

  int64_t expected[2]{0, 274957467666};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {

    EXPECT_EQ(expected[coeff_index],
              modulus_multiply_128(x1[coeff_index] - x2[coeff_index], r, q));

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubEnterReduce2QToQNegative) {
  const int coeff_count = 2;

  int64_t x1[2]{1, 2};
  int64_t x2[2]{7, 7};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_sub_enter_reduce_2q_to_q(x1, x2, y, r_squared, q_double, q,
                                             k, coeff_count);

  int64_t expected[2]{549287755670, 824245223336};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {

    EXPECT_EQ(expected[coeff_index],
              modulus_multiply_128(q_double + x1[coeff_index] - x2[coeff_index],
                                   r, q));

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubEnterPositive) {
  const int coeff_count = 2;

  int64_t x1[2]{1, 2};
  int64_t x2[2]{1, 1};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_sub_enter(x1, x2, y, r_squared, q_double, q, k,
                              coeff_count);

  int64_t expected[2]{0, 274957467666};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {

    EXPECT_EQ(expected[coeff_index],
              modulus_multiply_128(x1[coeff_index] - x2[coeff_index], r, q));

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubEnterNegative) {
  const int coeff_count = 2;

  int64_t x1[2]{1, 2};
  int64_t x2[2]{7, 7};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_sub_enter(x1, x2, y, r_squared, q_double, q, k,
                              coeff_count);

  int64_t expected[2]{549287755670, 824245223336};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {

    EXPECT_EQ(expected[coeff_index],
              modulus_multiply_128(q_double + x1[coeff_index] - x2[coeff_index],
                                   r, q));

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterExit) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_exit(x, y, r_squared, q, k, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterExitConstant) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = 2 * modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_exit(x, y, r_squared, q, k, coeff_count);

  int64_t expected[2]{2, 4};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterReduce2QToQ) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_exit_reduce_2q_to_q(x, y, r_squared, q, k,
                                              coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterReduce2QToQConstant) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = 2 * modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_exit_reduce_2q_to_q(x, y, r_squared, q, k,
                                              coeff_count);

  int64_t expected[2]{2, 4};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterReduce2QToQGuard) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  x[0] += q;
  x[1] += q;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_exit_reduce_2q_to_q(x, y, r_squared, q, k,
                                              coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, EnterReduce2QToQGuardConstant) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  x[0] += q;
  x[1] += q;

  int64_t r_squared = 2 * modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter_exit_reduce_2q_to_q(x, y, r_squared, q, k,
                                              coeff_count);

  int64_t expected[2]{2, 4};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, AddReduce2QToQAddIsLessThanQ) {

  int64_t x1[2]{1, 2};
  int64_t x2[2]{};
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  const int coeff_count = 2;

  desilo::fhe::mont_add_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, AddReduce2QToQAddIsBiggerThanQ) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{static_cast<int64_t>(q), static_cast<int64_t>(q + 1)};
  int64_t x2[2]{1, 1};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_add_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, AddReduce2QToQAddIsBiggerThan2Q) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{static_cast<int64_t>(q_double - 1),
                static_cast<int64_t>(q_double + 0)};
  int64_t x2[2]{1, 1};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_add_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{0, 1};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, AddReduce2QToQAddIsBiggerThan3Q) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{static_cast<int64_t>(q * 3 - 1),
                static_cast<int64_t>(q * 3 + 0)};
  int64_t x2[2]{1, 1};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_add_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{0, 1};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubReduce2QToQSubIsLessThanZero) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{};
  int64_t x2[2]{1, static_cast<int64_t>(q)};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);
  int64_t expected[2]{static_cast<int64_t>(q - 1), 0};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    auto guarded_value = x1[coeff_index] + q - x2[coeff_index];
    EXPECT_EQ(expected[coeff_index], guarded_value);

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubReduce2QToQSubIsLessThanMinusQ) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{};
  int64_t x2[2]{static_cast<int64_t>(q + 1), static_cast<int64_t>(q * 2)};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{static_cast<int64_t>(q - 1), 0};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    auto guarded_value = x1[coeff_index] + q_double - x2[coeff_index];
    EXPECT_EQ(expected[coeff_index], guarded_value);

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubReduce2QToQSubIsLessThanMinus2Q) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{};
  int64_t x2[2]{static_cast<int64_t>(q_double + 1),
                static_cast<int64_t>(q_double + 2)};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{-1, -2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    auto guarded_value = x1[coeff_index] + q_double - x2[coeff_index];
    EXPECT_EQ(expected[coeff_index], guarded_value);

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubReduce2QToQSubIsLessThanQ) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{1, static_cast<int64_t>(q)};
  int64_t x2[2]{1, 1};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{0, static_cast<int64_t>(q - 1)};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubReduce2QToQSubIsBiggerThanQ) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{static_cast<int64_t>(q + 1), static_cast<int64_t>(q * 2)};
  int64_t x2[2]{1, 1};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{0, static_cast<int64_t>(q - 1)};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    auto guarded_value = x1[coeff_index] - q - x2[coeff_index];
    EXPECT_EQ(expected[coeff_index], guarded_value);

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubReduce2QToQSubIsBiggerThan2Q) {

  uint64_t q = 1099516280833;
  uint64_t q_double = q * 2;

  int64_t x1[2]{static_cast<int64_t>(q_double + 1),
                static_cast<int64_t>(q_double + 2)};
  int64_t x2[2]{1, 1};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q, coeff_count);

  int64_t expected[2]{static_cast<int64_t>(q), static_cast<int64_t>(q + 1)};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    auto guarded_value = x1[coeff_index] - q - x2[coeff_index];
    EXPECT_EQ(expected[coeff_index], guarded_value);

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, UnsignedReduce2QToQNegative) {

  int64_t x[2]{-1, -2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;

  const int coeff_count = 2;

  desilo::fhe::make_unsigned_reduce_2q_to_q(x, y, q, coeff_count);

  int64_t expected[2]{static_cast<int64_t>(q - 1), static_cast<int64_t>(q - 2)};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, UnsignedReduce2QToQPositiveGuarded) {

  uint64_t q = 1099516280833;

  int64_t x[2]{static_cast<int64_t>(q), static_cast<int64_t>(q + 1)};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::make_unsigned_reduce_2q_to_q(x, y, q, coeff_count);

  int64_t expected[2]{0, 1};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, UnsignedReduce2QToQPositiveUnguarded) {

  int64_t x[2]{1, 2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;

  const int coeff_count = 2;

  desilo::fhe::make_unsigned_reduce_2q_to_q(x, y, q, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, NegateMakeUnsigned) {
  uint64_t q = 1099516280833;

  int64_t x[2]{1, 2};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::negate_make_unsigned(x, y, q, coeff_count);

  int64_t expected[2]{static_cast<int64_t>(q - 1), static_cast<int64_t>(q - 2)};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, ConcatenateMakeUnsignedNegative) {
  uint64_t q = 1099516280833;

  int64_t x1[2]{0, 1};
  int64_t x2[2]{2, 3};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::concatenate_make_unsigned(x1, x2, y, q, coeff_count);

  const uint128_t mean_value = static_cast<uint128_t>(1) << 75;

  uint128_t expected[2]{
      (2 - mean_value) % q + q,
      ((static_cast<uint128_t>(1) << 63) + 3 - mean_value) % q + q};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, ConcatenateMakeUnsignedNonNegative) {
  uint64_t q = 1099516280833;

  int64_t x1[2]{1UL << 12, (1UL << 12) + 1};
  int64_t x2[2]{2, 3};
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::concatenate_make_unsigned(x1, x2, y, q, coeff_count);

  uint128_t expected[2]{2 + q, ((static_cast<uint128_t>(1) << 63) + 3) % q + q};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}
