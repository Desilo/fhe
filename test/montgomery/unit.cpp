#include "montgomery/unit.h"
#include "common/test.h"

typedef unsigned __int128 uint128_t;

TEST(Montgomery, Multiply) {
  int64_t x1[2]{1, 2};
  int64_t x2[2]{2, 2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  const int coeff_count = 2;

  desilo::fhe::mont_mult(x1, x2, y, q, k, coeff_count);

  int64_t r_inverse = 688736286065;

  int64_t expected[2]{277956291297, 555912582594};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {

    EXPECT_EQ(
        expected[coeff_index],
        modulus_multiply_128(x1[coeff_index], x2[coeff_index], r_inverse, q));
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, MultiplyR) {
  int64_t x1[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t x2[2]{r, r};
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  const int coeff_count = 2;

  desilo::fhe::mont_mult(x1, x2, y, q, k, coeff_count);

  int64_t expected[6]{1, 2, 3, 4, 5, 6};
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, Enter) {
  const int coeff_count = 2;

  int64_t x[2]{1, 2};
  int64_t one = 1;
  int64_t r = one << 62;
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t k = 2888757134567604223;

  int64_t r_squared = modulus_multiply_128(r, r, q);

  desilo::fhe::mont_enter(x, y, r_squared, q, k, coeff_count);

  int64_t expected[2]{274957467666, 549914935332};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {

    auto expected_value = modulus_multiply_128(x[coeff_index], r, q);

    EXPECT_EQ(expected[coeff_index], expected_value);

    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, Reduce2QToQSmall) {
  int64_t x[2]{1, 2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;

  const int coeff_count = 2;

  desilo::fhe::reduce_2q_to_q(x, y, q, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, Reduce2QToQBig) {
  int64_t x[2]{1, 2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;

  const int coeff_count = 2;

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    x[coeff_index] += q;
  }

  desilo::fhe::reduce_2q_to_q(x, y, q, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, MakeSignedSmall) {
  int64_t x[2]{1, 2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_half = 549758140416;

  const int coeff_count = 2;

  desilo::fhe::make_signed(x, y, q, q_half, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, MakeSignedBig) {
  int64_t x[2]{1, 2};
  int64_t y[2]{};

  uint64_t q = 1099516280833;
  uint64_t q_half = 549758140416;

  const int coeff_count = 2;

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    x[coeff_index] += q;
  }

  desilo::fhe::make_signed(x, y, q, q_half, coeff_count);

  int64_t expected[2]{1, 2};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, Negate) {
  int64_t x[6]{1, 2, 3, 4, 5, 6};
  int64_t y[6]{};

  const int chain_count = 3;
  const int coeff_count = 2;

  desilo::fhe::negate(x, y, chain_count, coeff_count);

  int64_t expected[6]{-1, -2, -3, -4, -5, -6};

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
      int index = chain_index * coeff_count + coeff_index;
      EXPECT_EQ(y[index], expected[index]);
    }
  }
}

TEST(Montgomery, AddGuarded) {

  int64_t x1[2]{0, 1};
  int64_t y[2]{};

  uint64_t q_double = 2199032561666;
  int64_t x2[2]{static_cast<int64_t>(q_double), static_cast<int64_t>(q_double)};

  const int coeff_count = 2;

  desilo::fhe::mont_add(x1, x2, y, q_double, coeff_count);

  int64_t expected[2]{0, 1};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, AddUnguarded) {

  int64_t x1[2]{1, 2};
  int64_t x2[2]{2, 2};
  int64_t y[2]{};

  uint64_t q_double = 2199032561666;

  const int coeff_count = 2;

  desilo::fhe::mont_add(x1, x2, y, q_double, coeff_count);

  int64_t expected[2]{3, 4};

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    EXPECT_EQ(y[coeff_index], expected[coeff_index]);
  }
}

TEST(Montgomery, SubtractPositive) {
  int64_t x1[2]{10, 20};
  int64_t x2[2]{5, 10};
  int64_t y[2]{};

  const uint64_t q_double = 2199032561666;

  const int coeff_count = 2;

  desilo::fhe::mont_subtract(x1, x2, y, q_double, coeff_count);

  int64_t expected[2]{10 - 5, 20 - 10};

  expect_array_equals(y, expected, 2);
}

TEST(Montgomery, SubtractNegative) {
  int64_t x1[2]{1, 2};
  int64_t x2[2]{10, 100};
  int64_t y[2]{};

  const uint64_t q_double = 2199032561666;

  const int coeff_count = 2;

  desilo::fhe::mont_subtract(x1, x2, y, q_double, coeff_count);

  int64_t expected[6]{1 - 10 + 2199032561666, 2 - 100 + 2199032561666};

  expect_array_equals(y, expected, 2);
}

TEST(Montgomery, GetRounder) {
  int64_t x[6]{1, 2, 3, 4, 5, 6};
  int64_t y[6]{};

  uint64_t q_half = 3;

  const int coeff_count = 6;

  desilo::fhe::get_rounder(x, y, q_half, coeff_count);

  int64_t expected[6]{0, 0, 0, 1, 1, 1};

  expect_array_equals(y, expected, 6);
}
