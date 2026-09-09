#include <cmath>
#include <cstdint>

#include "arithmetic/arithmetic.h"

namespace desilo::fhe {

typedef __int128 int128_t;

int64_t modulus_invert(int64_t x, int64_t modulus) {
  int64_t dividend = x;
  int64_t divisor = modulus;

  int64_t dividend_reverse = 1;
  int64_t divisor_reverse = 0;

  while (divisor > 0) {
    int64_t quotient = dividend / divisor;
    std::swap(dividend, divisor);
    divisor -= quotient * dividend;
    std::swap(dividend_reverse, divisor_reverse);
    divisor_reverse -= quotient * dividend_reverse;
  }

  if (dividend != 1) {
    return 0;
  }

  return (dividend_reverse >= 0) ? dividend_reverse
                                 : dividend_reverse + modulus;
}

int64_t modulus_multiply(int64_t x1, int64_t x2, int64_t modulus) {
  int128_t product = static_cast<int128_t>(x1) * static_cast<int128_t>(x2);
  product %= static_cast<int128_t>(modulus);

  return static_cast<int64_t>(product);
}

template <typename T> T modulus_power(T base, T exponent, T modulus) {
  T current = 1;

  for (; exponent > 0; exponent >>= 1) {
    if ((exponent & 1) == 1) {
      current = modulus_multiply(current, base, modulus);
    }

    base = modulus_multiply(base, base, modulus);
  }

  return current;
}

template int64_t modulus_power(int64_t base, int64_t exponent, int64_t modulus);
template uint64_t modulus_power(uint64_t base, uint64_t exponent,
                                uint64_t modulus);
template uint32_t modulus_power(uint32_t base, uint32_t exponent,
                                uint32_t modulus);

void scale_modulo(int64_t *output, double value, double scale, double deviation,
                  const uint64_t *q, int chain_count) {
  const double product_as_double = (value * scale * deviation + 0.5) * scale;

  const auto product = BigInt::from_double(std::abs(product_as_double));

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_q = q[chain_index];

    int64_t chain_scalar = product % chain_q;
    if (product_as_double < 0) {
      chain_scalar = chain_q - chain_scalar;
    }

    output[chain_index] = chain_scalar;
  }
}

void scale_enter_modulo(int64_t *output, double value, double scale,
                        double deviation, int64_t r, const uint64_t *q,
                        int chain_count) {
  const double product_as_double = value * scale * std::sqrt(deviation) + 0.5;

  const auto product = BigInt::from_double(std::abs(product_as_double)) * r;

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_q = q[chain_index];

    int64_t chain_scalar = product % chain_q;
    if (product_as_double < 0) {
      chain_scalar = chain_q - chain_scalar;
    }

    output[chain_index] = chain_scalar;
  }
}

int64_t find_root(int64_t modulus_prime, int coeff_count) {
  int64_t unit_power = (modulus_prime - 1) / (2 * coeff_count);

  int64_t exp_unit;
  int64_t coeff_count_ = static_cast<int64_t>(coeff_count);

  for (int index = 2; index < modulus_prime; index++) {
    int64_t base = index;
    exp_unit = modulus_power(base, unit_power, modulus_prime);

    if (modulus_power(exp_unit, coeff_count_, modulus_prime) != 1) {
      break;
    }
  }

  return exp_unit;
}

int64_t find_cyclic_root(int64_t prime, int root_count) {
  int64_t unit_power = (prime - 1) / root_count;
  int64_t prime_half = (prime - 1) / (2 * root_count);
  int64_t root_value;

  for (int64_t base = 2; base < prime; base++) {
    root_value = modulus_power(base, unit_power, prime);

    if (modulus_power(base, prime_half, prime) != 1) {
      return root_value;
    }
  }

  return 0;
}

int64_t find_generator(int64_t prime) {
  int64_t prime_half = prime / 2;

  int64_t value = 2;
  for (; value < prime; value++) {
    if (modulus_power(value, prime_half, prime) == prime - 1) {
      return value;
    }
  }

  return 0;
}

std::vector<int64_t> get_power_series(int64_t root, int64_t modulus_prime,
                                      int coeff_count) {
  std::vector<int64_t> power_series;
  power_series.push_back(1);

  int64_t product = 1;
  for (int index = 1; index < coeff_count; index++) {
    product = modulus_multiply(product, root, modulus_prime);

    power_series.push_back(product);
  }

  return power_series;
}

uint64_t calculate_k(int64_t r, int64_t modulus) {
  auto modulus_inverse = modulus_invert(r, modulus);

  int128_t k =
      static_cast<int128_t>(r) * static_cast<int128_t>(modulus_inverse) - 1;
  k /= static_cast<int128_t>(modulus);

  return static_cast<uint64_t>(k);
}

void rns_to_double(int64_t **x, double *y, const uint64_t *q, BigInt q_product,
                   BigInt q_product_half, const BigInt *rns_reverser,
                   uint64_t r_minus_k_product, int chain_count, int coeff_count,
                   int coeff_start, int coeff_end) {
  constexpr int64_t r = UINT64_C(1) << 62;

  for (int coeff_index = coeff_start; coeff_index < coeff_end; coeff_index++) {
    auto rns_reversed = BigInt(UINT64_C(0));

    for (int chain_index = 0; chain_index < chain_count; chain_index++) {
      const auto chain_q = q[chain_index];

      auto x_value = modulus_multiply(x[chain_index][coeff_index], r, chain_q);
      auto x_product = rns_reverser[chain_index] * x_value;

      rns_reversed = rns_reversed + x_product;
    }

    rns_reversed =
        rns_reversed.montgomery_modulus(q_product, r_minus_k_product);

    if (rns_reversed >= q_product_half) {
      rns_reversed = q_product - rns_reversed;
      y[coeff_index] = -rns_reversed.get_double();
    } else {
      y[coeff_index] = rns_reversed.get_double();
    }
  }
}

void rns_to_double_with_power_of_two(int64_t **x, double *y, const uint64_t *q,
                                     BigInt q_product,
                                     const BigInt *rns_reverser,
                                     uint64_t r_minus_k_product,
                                     int chain_count, int coeff_count,
                                     int coeff_start, int coeff_end) {
  int64_t r = (UINT64_C(1) << 62) / q[0];
  auto true_q_product_half = q_product * (q[0] >> 1);
  auto true_q_product = q_product * q[0];

  for (int coeff_index = coeff_start; coeff_index < coeff_end; coeff_index++) {
    auto rns_reversed = BigInt(UINT64_C(0));
    auto q_0_modulus = x[0][coeff_index];

    for (int chain_index = 1; chain_index < chain_count; chain_index++) {
      const auto chain_q = q[chain_index];

      auto x_value = x[chain_index][coeff_index] - q_0_modulus;
      if (x_value < 0) {
        x_value += chain_q;
      }
      x_value = modulus_multiply(x_value, r, chain_q);
      auto x_product = rns_reverser[chain_index - 1] * x_value;

      rns_reversed = rns_reversed + x_product;
    }

    rns_reversed =
        rns_reversed.montgomery_modulus(q_product, r_minus_k_product);

    rns_reversed *= q[0];
    auto q_0_modulo = BigInt(x[0][coeff_index]);
    rns_reversed = rns_reversed + q_0_modulo;

    if (rns_reversed >= true_q_product_half) {
      rns_reversed = true_q_product - rns_reversed;
      y[coeff_index] = -rns_reversed.get_double();
    } else {
      y[coeff_index] = rns_reversed.get_double();
    }
  }
}

void double_to_rns(double *x, int64_t **y, const uint64_t *q, int chain_count,
                   int coeff_count, int coeff_start, int coeff_end) {
  for (size_t coeff_index = coeff_start; coeff_index < coeff_end;
       coeff_index++) {

    if (std::abs(x[coeff_index]) < (1L << 62)) {
      int64_t int_to_convert = static_cast<int64_t>(x[coeff_index] + 0.5);
      for (size_t chain_index = 0; chain_index < chain_count; chain_index++) {
        const int64_t chain_q = static_cast<int64_t>(q[chain_index]);
        y[chain_index][coeff_index] = positive_modulo(int_to_convert, chain_q);
      }
    } else {
      int exponent;
      double mantissa = std::frexp(x[coeff_index] + 0.5, &exponent);
      int64_t int_mantissa = mantissa * (1L << 52);
      for (size_t chain_index = 0; chain_index < chain_count; chain_index++) {
        const int64_t chain_q = static_cast<int64_t>(q[chain_index]);
        int64_t chain_y = positive_modulo(int_mantissa, chain_q);
        for (int local_exponent = 52; local_exponent < exponent;
             local_exponent++) {
          chain_y <<= 1;
          chain_y %= chain_q;
        }
        y[chain_index][coeff_index] = chain_y;
      }
    }
  }
}

template <typename T> T positive_modulo(T x, T modulus) {
  return (modulus + x % modulus) % modulus;
}

template int positive_modulo(int x, int modulus);
template int64_t positive_modulo(int64_t x, int64_t modulus);
template int128_t positive_modulo(int128_t x, int128_t modulus);

}
