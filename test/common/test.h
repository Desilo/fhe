#include <complex>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <tuple>

#include "ckks/config.h"
#include "data/polynomial.h"

#pragma once

typedef unsigned __int128 uint128_t;

template <typename T>
inline void expect_array_equals(const T *output, const T *expected,
                                size_t size) {
  for (auto index = 0; index < size; index++) {
    ASSERT_EQ(output[index], expected[index])
        << "values different at index " << index;
  }
}

template <typename T>
inline void expect_array_equals(const T *output, std::vector<T> expected) {
  for (auto index = 0; index < expected.size(); index++) {
    ASSERT_EQ(output[index], expected[index])
        << "values different at index " << index;
  }
}

#define EXPECT_ARRAY_EQUALS_VECTOR(output, expected)                           \
  for (auto index = 0; index < expected.size(); index++) {                     \
    EXPECT_EQ(output[index], expected[index])                                  \
        << "values different at index " << index;                              \
  }

template <typename T>
inline void expect_vector_equals(std::vector<T> output, std::vector<T> expected,
                                 size_t size) {
  for (auto index = 0; index < size; index++) {
    ASSERT_EQ(output[index], expected[index])
        << "values different at index " << index;
  }
}

template <typename T>
inline void expect_vector_equals(std::vector<T> output,
                                 std::vector<T> expected) {
  ASSERT_EQ(output.size(), expected.size());
  for (auto index = 0; index < expected.size(); index++) {
    ASSERT_EQ(output[index], expected[index])
        << "values different at index " << index;
  }
}

#define EXPECT_VECTOR_EQUALS(output, expected)                                 \
  for (auto index = 0; index < expected.size(); index++) {                     \
    EXPECT_EQ(output[index], expected[index])                                  \
        << "values different at index " << index;                              \
  }

template <typename T>
inline void expect_vector_vector_equals(std::vector<std::vector<T>> output,
                                        std::vector<std::vector<T>> expected,
                                        size_t size1, size_t size2) {
  for (auto index1 = 0; index1 < size1; index1++) {
    for (auto index2 = 0; index2 < size2; index2++) {
      ASSERT_EQ(output[index1][index2], expected[index1][index2])
          << "values different at index (" << index1 << ", " << index2 << ")";
    }
  }
}

template <typename T>
inline void expect_2d_array_equals(T *const *output, T *const *expected,
                                   size_t size1, size_t size2) {
  for (auto index1 = 0; index1 < size1; index1++) {
    for (auto index2 = 0; index2 < size2; index2++) {
      ASSERT_EQ(output[index1][index2], expected[index1][index2])
          << "values different at index (" << index1 << ", " << index2 << ")";
    }
  }
}

inline void expect_polynomial_equals(desilo::fhe::Polynomial *output,
                                     int64_t *expected) {
  const auto chain_count = output->chain_count_;
  const auto coeff_count = output->coeff_count_;
  const auto output_chains = output->chains_;
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
      const auto index = chain_index * coeff_count + coeff_index;
      ASSERT_EQ(output_chains[chain_index][coeff_index], expected[index])
          << "values different at chain_index " << chain_index
          << " coeff_index " << coeff_index << " and index " << index;
    }
  }
}

inline void expect_polynomial_equals(desilo::fhe::Polynomial *output,
                                     std::vector<int64_t> expected) {
  const auto chain_count = output->chain_count_;
  const auto coeff_count = output->coeff_count_;
  const auto output_chains = output->chains_;
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
      const auto index = chain_index * coeff_count + coeff_index;
      ASSERT_EQ(output_chains[chain_index][coeff_index], expected[index])
          << "values different at chain_index " << chain_index
          << " coeff_index " << coeff_index << " and index " << index;
    }
  }
}

inline void expect_array_near(double *output, double *expected,
                              const size_t size, const double abs_error) {
  for (auto index = 0; index < size; index++) {
    ASSERT_NEAR(output[index], expected[index], abs_error)
        << "values different at index " << index;
  }
}

inline void expect_complex_array_near(std::complex<double> *output,
                                      std::complex<double> *expected,
                                      const size_t size,
                                      const double abs_error) {
  for (auto index = 0; index < size; index++) {
    ASSERT_NEAR(output[index].real(), expected[index].real(), abs_error)
        << "real values different at index " << index;
    ASSERT_NEAR(output[index].imag(), expected[index].imag(), abs_error)
        << "imag values different at index " << index;
  }
}

template <typename T>
inline void expect_vector_near(std::vector<T> output, std::vector<T> expected,
                               size_t size, const double abs_error) {
  for (auto index = 0; index < size; index++) {
    ASSERT_NEAR(output[index], expected[index], abs_error)
        << "values different at index " << index;
  }
}

#define EXPECT_VECTOR_NEAR(output, expected, abs_error)                        \
  for (auto index = 0; index < expected.size(); index++) {                     \
    EXPECT_NEAR(output[index], expected[index], abs_error)                     \
        << "values different at index " << index;                              \
  }

template <typename T>
inline void expect_complex_vector_near(std::vector<std::complex<T>> output,
                                       std::vector<std::complex<T>> expected,
                                       const size_t size,
                                       const double abs_error) {
  for (auto index = 0; index < size; index++) {
    ASSERT_NEAR(output[index].real(), expected[index].real(), abs_error)
        << "real values different at index " << index;
    ASSERT_NEAR(output[index].imag(), expected[index].imag(), abs_error)
        << "imag values different at index " << index;
  }
}

inline int64_t modulus_multiply_128(int64_t x1, int64_t x2, int64_t modulus) {
  return static_cast<int64_t>(static_cast<uint128_t>(x1) *
                              static_cast<uint128_t>(x2) %
                              static_cast<uint128_t>(modulus));
}

inline int64_t modulus_multiply_128(int64_t x1, int64_t x2, int64_t x3,
                                    int64_t modulus) {
  return modulus_multiply_128(modulus_multiply_128(x1, x2, modulus), x3,
                              modulus);
}

void initialize_random_state(int64_t *state, const int chain_count,
                             const int coeff_count);

extern std::map<std::string, std::tuple<int, int, bool>> tier_parameters;
extern std::map<std::string, desilo::fhe::CKKSConfig> tier_configs;
extern std::map<std::string, desilo::fhe::CKKSConfig> test_configs;

desilo::fhe::CKKSConfig get_wide_bronze(int special_prime_count);

extern std::map<int, std::tuple<bool, bool>> rescale_flags;
