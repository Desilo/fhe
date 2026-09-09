#include <gtest/gtest.h>

#include "arithmetic/prime.h"
#include "common/test.h"

TEST(Prime, IsPrimeTrue) {
  EXPECT_TRUE(desilo::fhe::is_prime(2));
  EXPECT_TRUE(desilo::fhe::is_prime(3));
  EXPECT_TRUE(desilo::fhe::is_prime(5));
  EXPECT_TRUE(desilo::fhe::is_prime(7));
  EXPECT_TRUE(desilo::fhe::is_prime(11));
  EXPECT_TRUE(desilo::fhe::is_prime(999983));
  EXPECT_TRUE(desilo::fhe::is_prime(1099516280833u));
  EXPECT_TRUE(desilo::fhe::is_prime(1099506515969u));
  EXPECT_TRUE(desilo::fhe::is_prime(1099506515969u + 2));
  EXPECT_TRUE(desilo::fhe::is_prime(1152921504606748673u));

  const uint64_t start = 1ULL << 40;
  int count = 0;

  for (int index = 0; index < 1000; index++) {
    if (desilo::fhe::is_prime(start + index)) {
      count++;
    }
  }

  EXPECT_EQ(count, 36);
}

TEST(Prime, IsPrimeFalse) {
  EXPECT_FALSE(desilo::fhe::is_prime(1));
  EXPECT_FALSE(desilo::fhe::is_prime(10));
  EXPECT_FALSE(desilo::fhe::is_prime(1000000U));
  EXPECT_FALSE(desilo::fhe::is_prime(1099516280833u + 2));
  EXPECT_FALSE(desilo::fhe::is_prime(1099506515969u + 4));
  EXPECT_FALSE(desilo::fhe::is_prime(1152921504606748673u + 2));
  EXPECT_FALSE(desilo::fhe::is_prime(1152921504606748673u + 4));
}

TEST(Prime, JacobiSymbol) {
  EXPECT_EQ(desilo::fhe::jacobi_symbol(0, 0), 0);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(1, 0), 0);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(1, 1), 1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(1, 2), 0);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(1, 3), 1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(2, 3), -1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(0, 7), 0);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(1, 7), 1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(2, 7), 1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(3, 7), -1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(4, 7), 1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(5, 7), -1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(6, 7), -1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(7, 7), 0);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(28, 51), -1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(29, 51), 1);
  EXPECT_EQ(desilo::fhe::jacobi_symbol(30, 51), 0);
}

TEST(Prime, LucasProbablePrimeTestTrue) {
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(2));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(3));

  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(323));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(1159));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(1829));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(3827));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(10877));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(47879));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(999983));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(1099516280833u));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(1099506515969u));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(1099506515969u + 2));
  EXPECT_TRUE(desilo::fhe::lucas_probable_prime_test(1152921504606748673u));
}

TEST(Prime, LucasProbablePrimTestFalse) {
  EXPECT_FALSE(desilo::fhe::lucas_probable_prime_test(1));
  EXPECT_FALSE(desilo::fhe::lucas_probable_prime_test(10));
  EXPECT_FALSE(desilo::fhe::lucas_probable_prime_test(1000000U));
  EXPECT_FALSE(desilo::fhe::lucas_probable_prime_test(1099516280833u + 2));
  EXPECT_FALSE(desilo::fhe::lucas_probable_prime_test(1099506515969u + 4));
  EXPECT_FALSE(
      desilo::fhe::lucas_probable_prime_test(1152921504606748673u + 2));
  EXPECT_FALSE(
      desilo::fhe::lucas_probable_prime_test(1152921504606748673u + 4));
}

TEST(Prime, MilerRabinTestTrue) {
  EXPECT_TRUE(desilo::fhe::miller_rabin_test(1099516280833u, 2));
  EXPECT_TRUE(desilo::fhe::miller_rabin_test(1099516280833u, 7));
  EXPECT_TRUE(desilo::fhe::miller_rabin_test(1099506515969u, 11));
  EXPECT_TRUE(desilo::fhe::miller_rabin_test(1099506515969u, 17));
  EXPECT_TRUE(
      desilo::fhe::miller_rabin_test(1099506515969u + 2, 1099516280833u));
  EXPECT_TRUE(
      desilo::fhe::miller_rabin_test(1152921504606748673u, 1099516280833u));
}

TEST(Prime, MilerRabinTestFalse) {
  EXPECT_FALSE(desilo::fhe::miller_rabin_test(1099516280833u, 1099516280833u));
  EXPECT_FALSE(desilo::fhe::miller_rabin_test(1099516280833u + 2, 2));
  EXPECT_FALSE(desilo::fhe::miller_rabin_test(1099516280833u + 2, 7));
  EXPECT_FALSE(desilo::fhe::miller_rabin_test(1099506515969u + 4, 11));
  EXPECT_FALSE(desilo::fhe::miller_rabin_test(1099506515969u + 4, 17));
  EXPECT_FALSE(
      desilo::fhe::miller_rabin_test(1152921504606748673u + 2, 1099516280833u));
  EXPECT_FALSE(
      desilo::fhe::miller_rabin_test(1152921504606748673u + 4, 1099516280833u));
}

TEST(Prime, MakeAlternatingPrimes40) {
  int message_bit = 40;
  int ntt_prime_modulus = 8192;
  int prime_count = 5;

  auto output = desilo::fhe::make_alternating_primes(
      message_bit, ntt_prime_modulus, prime_count);

  std::vector<uint64_t> expected = {1099511922689, 1099510890497, 1099512004609,
                                    1099510824961, 1099512938497};

  for (auto &expected_prime : expected) {
    EXPECT_TRUE(desilo::fhe::is_ntt_prime(expected_prime, ntt_prime_modulus));
  }
  expect_vector_equals(output, expected);

  int64_t from = INT64_C(1) << message_bit;
  int64_t difference[5]{-294913, 737279, -376833, 802815, -1310721};
  for (int prime_index = 0; prime_index < prime_count; prime_index++) {
    EXPECT_EQ(from - static_cast<int64_t>(output[prime_index]),
              difference[prime_index]);
  }
}

TEST(Prime, MakeAlternatingPrimes59) {
  int message_bit = 59;
  int ntt_prime_modulus = 8192;
  int prime_count = 5;

  auto output = desilo::fhe::make_alternating_primes(
      message_bit, ntt_prime_modulus, prime_count);

  std::vector<uint64_t> expected = {576460752303210497, 576460752304439297,
                                    576460752302161921, 576460752304619521,
                                    576460752301228033};

  for (auto &expected_prime : expected) {
    EXPECT_TRUE(desilo::fhe::is_ntt_prime(expected_prime, ntt_prime_modulus));
  }
  expect_vector_equals(output, expected);

  int64_t from = INT64_C(1) << message_bit;
  int64_t difference[5]{212991, -1015809, 1261567, -1196033, 2195455};
  for (int prime_index = 0; prime_index < prime_count; prime_index++) {
    EXPECT_EQ(from - static_cast<int64_t>(output[prime_index]),
              difference[prime_index]);
  }
}

TEST(Prime, MakeAlternatingPrimes2_40) {
  int message_bit = 40;
  int ntt_prime_modulus = 8192;
  int prime_count = 5;

  auto output = desilo::fhe::make_alternating_primes_2(
      message_bit, ntt_prime_modulus, prime_count);

  std::vector<uint64_t> expected = {1099511922689, 1099511480321, 1099512004609,
                                    1099510890497, 1099512266753};

  for (auto &expected_prime : expected) {
    EXPECT_TRUE(desilo::fhe::is_ntt_prime(expected_prime, ntt_prime_modulus));
  }
  expect_vector_equals(output, expected);

  int64_t from = INT64_C(1) << message_bit;
  int64_t difference[5]{-294913, 147455, -376833, 737279, -638977};
  for (int prime_index = 0; prime_index < prime_count; prime_index++) {
    EXPECT_EQ(from - static_cast<int64_t>(output[prime_index]),
              difference[prime_index]);
  }
}

TEST(Prime, MakeAlternatingPrimes2_59) {
  int message_bit = 59;
  int ntt_prime_modulus = 8192;
  int prime_count = 5;

  auto output = desilo::fhe::make_alternating_primes_2(
      message_bit, ntt_prime_modulus, prime_count);

  std::vector<uint64_t> expected = {576460752303210497, 576460752303439873,
                                    576460752303046657, 576460752303702017,
                                    576460752302473217};

  for (auto &expected_prime : expected) {
    EXPECT_TRUE(desilo::fhe::is_ntt_prime(expected_prime, ntt_prime_modulus));
  }
  expect_vector_equals(output, expected);

  int64_t from = INT64_C(1) << message_bit;
  int64_t difference[5]{212991, -16385, 376831, -278529, 950271};
  for (int prime_index = 0; prime_index < prime_count; prime_index++) {
    EXPECT_EQ(from - static_cast<int64_t>(output[prime_index]),
              difference[prime_index]);
  }
}

TEST(Prime, MakeDecreasingPrimes40) {
  int message_bit = 40;
  int ntt_prime_modulus = 8192;
  int prime_count = 5;

  auto output = desilo::fhe::make_decreasing_primes(
      message_bit, ntt_prime_modulus, prime_count);

  std::vector<uint64_t> expected = {1099511480321, 1099510890497, 1099510824961,
                                    1099510054913, 1099510005761};

  for (auto &expected_prime : expected) {
    EXPECT_TRUE(desilo::fhe::is_ntt_prime(expected_prime, ntt_prime_modulus));
  }
  expect_vector_equals(output, expected);

  for (int prime_index = 1; prime_index < prime_count; prime_index++) {
    EXPECT_GT(output[prime_index - 1], output[prime_index]);
  }
}

TEST(Prime, MakeDecreasingPrimes59) {
  int message_bit = 59;
  int ntt_prime_modulus = 8192;
  int prime_count = 5;

  auto output = desilo::fhe::make_decreasing_primes(
      message_bit, ntt_prime_modulus, prime_count);

  std::vector<uint64_t> expected = {576460752303210497, 576460752303046657,
                                    576460752302473217, 576460752302161921,
                                    576460752302080001};

  for (auto &expected_prime : expected) {
    EXPECT_TRUE(desilo::fhe::is_ntt_prime(expected_prime, ntt_prime_modulus));
  }
  expect_vector_equals(output, expected);

  for (int prime_index = 1; prime_index < prime_count; prime_index++) {
    EXPECT_GT(output[prime_index - 1], output[prime_index]);
  }
}

TEST(Prime, MakeDecreasingPrimes60) {
  int message_bit = 60;
  int ntt_prime_modulus = 8192;
  int prime_count = 5;

  auto output = desilo::fhe::make_decreasing_primes(
      message_bit, ntt_prime_modulus, prime_count);

  std::vector<uint64_t> expected = {1152921504606830593, 1152921504606748673,
                                    1152921504606683137, 1152921504606601217,
                                    1152921504606584833};

  for (auto &expected_prime : expected) {
    EXPECT_TRUE(desilo::fhe::is_ntt_prime(expected_prime, ntt_prime_modulus));
  }
  expect_vector_equals(output, expected);

  for (int prime_index = 1; prime_index < prime_count; prime_index++) {
    EXPECT_GT(output[prime_index - 1], output[prime_index]);
  }
}

class Precomputed : public testing::TestWithParam<int> {};

INSTANTIATE_TEST_SUITE_P(PrimeParametrized, Precomputed,
                         testing::Values(8, 16, 8192, 16384, 32768, 65536,
                                         131072));

TEST_P(Precomputed, SmallPrimes) {
  int coeff_count = GetParam();
  int ntt_prime_modulus = coeff_count;
  int message_bit = 40;
  int prime_count = 64;

  if (coeff_count == 131072) {
    prime_count = 128;
  }

  const auto [cached_primes, cached_count] =
      desilo::fhe::get_cached_small_primes(coeff_count);
  const auto primes = desilo::fhe::make_alternating_primes(
      message_bit, ntt_prime_modulus, prime_count);

  ASSERT_EQ(cached_count, prime_count);
  for (int prime_index = 0; prime_index < prime_count; prime_index++) {
    EXPECT_TRUE(
        desilo::fhe::is_ntt_prime(primes[prime_index], ntt_prime_modulus));
    EXPECT_EQ(primes[prime_index], cached_primes[prime_index]);
  }
}

TEST_P(Precomputed, BootstrapPrimes) {
  int coeff_count = GetParam();
  int ntt_prime_modulus = coeff_count;
  int message_bit = 54;
  int prime_count = 64;

  if (coeff_count == 8192 || coeff_count == 16384 || coeff_count == 32768 ||
      coeff_count == 131072) {
    GTEST_SKIP();
  }

  const auto [cached_primes, cached_count] =
      desilo::fhe::get_cached_bootstrap_primes(coeff_count);
  const auto primes = desilo::fhe::make_alternating_primes(
      message_bit, ntt_prime_modulus, prime_count);

  ASSERT_EQ(cached_count, prime_count);
  for (int prime_index = 0; prime_index < prime_count; prime_index++) {
    ASSERT_TRUE(
        desilo::fhe::is_ntt_prime(primes[prime_index], ntt_prime_modulus));
    EXPECT_EQ(primes[prime_index], cached_primes[prime_index]);
  }
}

TEST_P(Precomputed, LargePrimes) {
  int coeff_count = GetParam();
  int ntt_prime_modulus = coeff_count;
  int message_bit = 60;
  int prime_count = 64;

  const auto [cached_primes, cached_count] =
      desilo::fhe::get_cached_large_primes(coeff_count);
  const auto primes = desilo::fhe::make_decreasing_primes(
      message_bit, ntt_prime_modulus, prime_count);

  ASSERT_EQ(cached_count, prime_count);
  for (int prime_index = 0; prime_index < prime_count; prime_index++) {
    EXPECT_TRUE(
        desilo::fhe::is_ntt_prime(primes[prime_index], ntt_prime_modulus));
    EXPECT_EQ(primes[prime_index], cached_primes[prime_index]);
  }
}

TEST(Prime, PrecomputedSmallPrimesInvalidCoeffCount) {
  int coeff_count = 1;

  const auto [cached, cached_count] =
      desilo::fhe::get_cached_small_primes(coeff_count);

  EXPECT_EQ(cached, nullptr);
  EXPECT_EQ(cached_count, 0);
}

TEST(Prime, PrecomputedBootstrapPrimesInvalidCoeffCount) {
  int coeff_count = 1;

  const auto [cached, cached_count] =
      desilo::fhe::get_cached_bootstrap_primes(coeff_count);

  EXPECT_EQ(cached, nullptr);
  EXPECT_EQ(cached_count, 0);
}

TEST(Prime, PrecomputedLargePrimesInvalidCoeffCount) {
  int coeff_count = 1;

  const auto [cached, cached_count] =
      desilo::fhe::get_cached_large_primes(coeff_count);

  EXPECT_EQ(cached, nullptr);
  EXPECT_EQ(cached_count, 0);
}

TEST(Prime, GetSmallPrimes) {
  int coeff_count = 8192;
  int ntt_prime_modulus = coeff_count * 2;
  int prime_count = 3;

  auto output = desilo::fhe::get_small_primes(coeff_count, prime_count);
  auto [expected, cached_count] =
      desilo::fhe::get_cached_small_primes(coeff_count);

  ASSERT_GE(cached_count, prime_count);
  expect_array_equals(output.data(), expected, prime_count);
}

TEST(Prime, GetBootstrapPrimes) {
  int coeff_count = 65536;
  int ntt_prime_modulus = coeff_count * 2;
  int prime_count = 3;

  auto output = desilo::fhe::get_bootstrap_primes(coeff_count, prime_count);
  auto [expected, cached_count] =
      desilo::fhe::get_cached_bootstrap_primes(coeff_count);

  ASSERT_GE(cached_count, prime_count);
  expect_array_equals(output.data(), expected, prime_count);
}

TEST(Prime, GetLargePrimes) {
  int coeff_count = 8192;
  int ntt_prime_modulus = coeff_count * 2;
  int prime_count = 5;

  auto output = desilo::fhe::get_large_primes(coeff_count, prime_count);
  auto [expected, cached_count] =
      desilo::fhe::get_cached_large_primes(coeff_count);

  ASSERT_GE(cached_count, prime_count);
  expect_array_equals(output.data(), expected, prime_count);
}

TEST(Prime, GetSmallPrimesInvalidCoeffCount) {
  int coeff_count = 4096;
  int prime_count = 3;

  auto output = desilo::fhe::get_small_primes(coeff_count, prime_count);

  EXPECT_EQ(output.size(), prime_count);
}

TEST(Prime, GetSmallPrimesInvalidPrimeCount) {
  int coeff_count = 8192;
  int prime_count = 100;

  auto output = desilo::fhe::get_small_primes(coeff_count, prime_count);

  EXPECT_EQ(output.size(), prime_count);
}

TEST(Prime, GetBootstrapPrimesInvalidCoeffCount) {
  int coeff_count = 4096;
  int prime_count = 3;

  auto output = desilo::fhe::get_bootstrap_primes(coeff_count, prime_count);

  EXPECT_EQ(output.size(), prime_count);
}

TEST(Prime, GetBootstrapPrimesInvalidPrimeCount) {
  int coeff_count = 8192;
  int prime_count = 100;

  auto output = desilo::fhe::get_bootstrap_primes(coeff_count, prime_count);

  EXPECT_EQ(output.size(), prime_count);
}

TEST(Prime, GetLargePrimesInvalidCoeffCount) {
  int coeff_count = 4096;
  int prime_count = 3;

  auto output = desilo::fhe::get_large_primes(coeff_count, prime_count);

  EXPECT_EQ(output.size(), prime_count);
}

TEST(Prime, GetLargePrimesInvalidPrimeCount) {
  int coeff_count = 8192;
  int prime_count = 100;

  auto output = desilo::fhe::get_large_primes(coeff_count, prime_count);

  EXPECT_EQ(output.size(), prime_count);
}
