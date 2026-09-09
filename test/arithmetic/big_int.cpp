#include "arithmetic/big_int.h"
#include "common/test.h"

TEST(BigInt, PowerOfTwo) {
  uint64_t one = 1;

  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(0), desilo::fhe::BigInt(1));
  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(1), desilo::fhe::BigInt(2));
  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(2), desilo::fhe::BigInt(4));
  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(40),
            desilo::fhe::BigInt(one << 40));
  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(50),
            desilo::fhe::BigInt(one << 50));
  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(60),
            desilo::fhe::BigInt(one << 60));
  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(64), desilo::fhe::BigInt({0, 1}));
  EXPECT_EQ(desilo::fhe::BigInt::power_of_two(100),
            desilo::fhe::BigInt({0, one << 36}));
}

TEST(BigInt, FromDouble) {
  EXPECT_EQ(desilo::fhe::BigInt::from_double(123.0), desilo::fhe::BigInt(123));
  EXPECT_EQ(desilo::fhe::BigInt::from_double(std::pow(2, 65)),
            desilo::fhe::BigInt({0, 2}));
}

TEST(BigInt, Multiply) {
  auto x = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});
  uint64_t multiplier = 968738560891204246;

  auto y = x * multiplier;
  auto expected =
      desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                           12382517138924307298U, 20182053351898367});

  EXPECT_EQ(y.data_.size(), 4);
  expect_vector_equals(y.data_, expected.data_, 4);
}

TEST(BigInt, MultiplyZero) {
  auto x = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});
  uint64_t multiplier = 0;

  auto y = x * multiplier;
  auto expected = desilo::fhe::BigInt(0UL);

  EXPECT_EQ(y.data_.size(), 1);
  expect_vector_equals(y.data_, expected.data_, 1);
}

TEST(BigInt, MultiplyAssign) {
  auto x = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});
  uint64_t multiplier = 968738560891204246;

  x *= multiplier;
  auto expected =
      desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                           12382517138924307298U, 20182053351898367});

  EXPECT_EQ(x.data_.size(), 4);
  expect_vector_equals(x.data_, expected.data_, 4);
}

TEST(BigInt, MultiplyAssignZero) {
  auto x = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});
  uint64_t multiplier = 0;

  x *= multiplier;
  auto expected = desilo::fhe::BigInt(0UL);

  EXPECT_EQ(x.data_.size(), 1);
  expect_vector_equals(x.data_, expected.data_, 1);
}

TEST(BigInt, Divide) {
  auto x = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                12382517138924307298U, 20182053351898367});
  uint64_t divisor = 968738560891204246;

  auto y = x / divisor;
  auto expected = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});

  expect_vector_equals(y.data_, expected.data_, 3);
}

TEST(BigInt, DivideByZero) {
  auto x = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                12382517138924307298U, 20182053351898367});
  uint64_t divisor = 0;

  try {
    auto y = x / divisor;
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Divide: can not divide with 0.", e.what());
  }
}

TEST(BigInt, Modulo) {
  EXPECT_EQ(desilo::fhe::BigInt(7) % 3, 1);
  EXPECT_EQ(desilo::fhe::BigInt(8) % 3, 2);
  EXPECT_EQ(desilo::fhe::BigInt({1, 1}) % 2, 1);
  EXPECT_EQ(desilo::fhe::BigInt({2, 3}) % 3, 2);
}

TEST(BigInt, AddLong) {
  auto x = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});
  auto input = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                    12382517138924307298U, 20182053351898367});

  auto y = x + input;
  auto expected =
      desilo::fhe::BigInt({3704798772354233493, 256697805148844719,
                           12766824307126556857U, 20182053351898367});

  expect_vector_equals(y.data_, expected.data_, 4);
}

TEST(BigInt, AddShort) {
  auto x = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                12382517138924307298U, 20182053351898367});
  auto input = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});

  auto y = x + input;
  auto expected =
      desilo::fhe::BigInt({3704798772354233493, 256697805148844719,
                           12766824307126556857U, 20182053351898367});

  expect_vector_equals(y.data_, expected.data_, 4);
}

TEST(BigInt, AddSame) {
  auto x = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                12382517138924307298U, 20182053351898367});
  auto input = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558, 123456789});

  auto y = x + input;
  auto expected =
      desilo::fhe::BigInt({3704798772354233493, 256697805148844719,
                           12766824307126556857U, 20182053475355156});

  expect_vector_equals(y.data_, expected.data_, 4);
}

TEST(BigInt, AddSameCarry) {
  auto x = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                12382517138924307298U, 17550520374251647662U});
  auto input = desilo::fhe::BigInt({1715157987554227, 1152921504606748673U,
                                    384307168202249558, 1152921504606748673U});

  auto y = x + input;
  auto expected =
      desilo::fhe::BigInt({3704798772354233493, 256697805148844719,
                           12766824307126556857U, 256697805148844719, 1});

  expect_vector_equals(y.data_, expected.data_, 5);
}

TEST(BigInt, SubtractSame) {
  auto x = desilo::fhe::BigInt({3704798772354233493, 256697805148844719,
                                12766824307126556857U, 20182053351898367});
  auto input = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                    12382517138924307298U, 20182053351898367});

  auto y = x - input;
  auto expected = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 384307168202249558});

  expect_vector_equals(y.data_, expected.data_, 3);
}

TEST(BigInt, SubtractShort) {
  auto x = desilo::fhe::BigInt({3704798772354233493, 256697805148844719,
                                12766824307126556857U, 20182053351898367});
  auto input = desilo::fhe::BigInt(
      {3703083614366679266, 17550520374251647662U, 20182053351898367});

  auto y = x - input;
  auto expected =
      desilo::fhe::BigInt({1715157987554227, 1152921504606748673U,
                           12746642253774658489U, 20182053351898367});

  expect_vector_equals(y.data_, expected.data_, 4);
}

TEST(BigInt, SubtractShortBorrow1) {
  auto x = desilo::fhe::BigInt(
      {3704798772354233493, 256697805148844719, 12766824307126556857U, 2});
  auto input = desilo::fhe::BigInt(
      {3703083614366679266, 17550520374251647662U, 12766824307126556858U});

  auto y = x - input;
  auto expected = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 18446744073709551614U, 1});

  expect_vector_equals(y.data_, expected.data_, 4);
}

TEST(BigInt, SubtractShortBorrow2) {
  auto x = desilo::fhe::BigInt(
      {3704798772354233493, 256697805148844719, 12766824307126556857U, 1});
  auto input = desilo::fhe::BigInt(
      {3703083614366679266, 17550520374251647662U, 12766824307126556858U});

  auto y = x - input;
  auto expected = desilo::fhe::BigInt(
      {1715157987554227, 1152921504606748673U, 18446744073709551614U});

  expect_vector_equals(y.data_, expected.data_, 3);
}

TEST(BigInt, EqualLonger) {
  auto x = desilo::fhe::BigInt({1, 2, 3});
  auto y = desilo::fhe::BigInt({1, 2});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualShorter) {
  auto x = desilo::fhe::BigInt({1, 2});
  auto y = desilo::fhe::BigInt({1, 2, 3});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthBigger) {
  auto x = desilo::fhe::BigInt({1, 3});
  auto y = desilo::fhe::BigInt({1, 2});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthBigger2) {
  auto x = desilo::fhe::BigInt({2, 3});
  auto y = desilo::fhe::BigInt({1, 3});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthBigger3) {
  auto x = desilo::fhe::BigInt({2, 4});
  auto y = desilo::fhe::BigInt({1, 3});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthBigger4) {
  auto x = desilo::fhe::BigInt({1, 4});
  auto y = desilo::fhe::BigInt({2, 3});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthEqual) {
  auto x = desilo::fhe::BigInt({1, 2});
  auto y = desilo::fhe::BigInt({1, 2});

  EXPECT_TRUE(x == y);
}

TEST(BigInt, EqualSameLengthSmaller) {
  auto x = desilo::fhe::BigInt({1, 2});
  auto y = desilo::fhe::BigInt({1, 3});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthSmaller2) {
  auto x = desilo::fhe::BigInt({1, 3});
  auto y = desilo::fhe::BigInt({2, 3});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthSmaller3) {
  auto x = desilo::fhe::BigInt({1, 3});
  auto y = desilo::fhe::BigInt({2, 4});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, EqualSameLengthSmaller4) {
  auto x = desilo::fhe::BigInt({2, 3});
  auto y = desilo::fhe::BigInt({1, 4});

  EXPECT_FALSE(x == y);
}

TEST(BigInt, GreaterOrEqualLonger) {
  auto x = desilo::fhe::BigInt({3704798772354233493, 256697805148844719,
                                12766824307126556857U, 20182053351898367});
  auto input = desilo::fhe::BigInt(
      {3703083614366679266, 17550520374251647662U, 12382517138924307298U});

  auto y = x >= input;
  bool expected = true;

  EXPECT_EQ(y, expected);
}

TEST(BigInt, GreaterOrEqualShorter) {
  auto x = desilo::fhe::BigInt(
      {3704798772354233493, 256697805148844719, 12766824307126556857U});
  auto input = desilo::fhe::BigInt({3703083614366679266, 17550520374251647662U,
                                    12382517138924307298U, 20182053351898367});

  auto y = x >= input;
  bool expected = false;

  EXPECT_EQ(y, expected);
}

TEST(BigInt, GreaterOrEqualSameLengthBigger) {
  auto x = desilo::fhe::BigInt(
      {3704798772354233494, 256697805148844719, 12766824307126556857U});
  auto input = desilo::fhe::BigInt(
      {3704798772354233493, 256697805148844719, 12766824307126556857U});

  auto y = x >= input;
  bool expected = true;

  EXPECT_EQ(y, expected);
}

TEST(BigInt, GreaterOrEqualSameLengthEqual) {
  auto x = desilo::fhe::BigInt(
      {3704798772354233494, 256697805148844719, 12766824307126556857U});
  auto input = desilo::fhe::BigInt(
      {3704798772354233494, 256697805148844719, 12766824307126556857U});

  auto y = x >= input;
  bool expected = true;

  EXPECT_EQ(y, expected);
}

TEST(BigInt, GreaterOrEqualSameLengthSmaller) {
  auto x = desilo::fhe::BigInt(
      {3704798772354233493, 256697805148844719, 12766824307126556857U});
  auto input = desilo::fhe::BigInt(
      {3704798772354233494, 256697805148844719, 12766824307126556857U});

  auto y = x >= input;
  bool expected = false;

  EXPECT_EQ(y, expected);
}

TEST(BigInt, MontgomeryModulusSmallerThanModulus) {

  auto x = desilo::fhe::BigInt({13835058055282163712U, 5045513337974591});
  auto modulus = desilo::fhe::BigInt({1234567771, 968738560891204246});
  uint64_t k = 688227565439853101;

  auto y = x.montgomery_modulus(modulus, k);
  auto expected = desilo::fhe::BigInt(20182053351898367U);

  expect_vector_equals(y.data_, expected.data_, 1);
}

TEST(BigInt, MontgomeryModulusBiggerThanModulus) {

  auto x = desilo::fhe::BigInt({10815715962157911227U, 588448842609760147});
  auto modulus = desilo::fhe::BigInt({1234567771, 968738560891204246});
  uint64_t k = 688227565439853101;

  auto y = x.montgomery_modulus(modulus, k);
  auto expected = desilo::fhe::BigInt({1025452595047182620, 60546160029974941});

  expect_vector_equals(y.data_, expected.data_, 2);
}

TEST(BigInt, MontgomeryModulusBiggerThanUpperBound) {

  auto x = desilo::fhe::BigInt(
      {10815715962157911227U, 588448842609760147, 10815715962157911227U});
  auto modulus = desilo::fhe::BigInt({1234567771, 968738560891204246});
  uint64_t k = 688227565439853101;

  auto y = x.montgomery_modulus(modulus, k);
  auto expected =
      desilo::fhe::BigInt({1025452540726200696, 698913329448633025});

  expect_vector_equals(y.data_, expected.data_, 2);
}
