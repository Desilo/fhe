#include <cstring>

#include "arithmetic/type.h"

#pragma once

namespace desilo::fhe {

constexpr int64_t one = 1;
constexpr int64_t nbits = sizeof(int64_t) * 8 - 2;
constexpr int64_t fb_mask = ((one << nbits) - one);

inline int64_t guard(int64_t x, int64_t q) { return (x < q) ? x : x - q; }

inline int64_t mont_mult_scalar(int64_t x1, int64_t x2, uint64_t q,
                                uint64_t k) {
  const uint128_t x = static_cast<uint128_t>(x1) * static_cast<uint128_t>(x2);

  const uint64_t s = (x * k) & fb_mask;

  const uint128_t sq = static_cast<uint128_t>(s) * static_cast<uint128_t>(q);
  return static_cast<int64_t>((x + sq) >> nbits);
}

inline int64_t mont_exit_scalar(int64_t x, uint64_t q, uint64_t k) {

  const uint64_t s = (x * k) & fb_mask;

  const uint128_t sq = static_cast<uint128_t>(s) * static_cast<uint128_t>(q);
  return static_cast<uint64_t>((x + sq) >> nbits);
}

void mont_mult(int64_t *x1, const int64_t *x2, int64_t *y, uint64_t q,
               uint64_t k, int coeff_count);

void mont_enter(int64_t *x, int64_t *y, int64_t constant, uint64_t q,
                uint64_t k, int coeff_count);

void reduce_2q_to_q(int64_t *x, int64_t *y, uint64_t q, int coeff_count);

void make_signed(int64_t *x, int64_t *y, uint64_t q, uint64_t q_half,
                 int coeff_count);

void negate(int64_t *x, int64_t *y, int chain_count, int coeff_count);

void mont_add(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
              int coeff_count);

void mont_subtract(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
                   int coeff_count);

void get_rounder(int64_t *x, int64_t *y, uint64_t q_half, int coeff_count);

void decompress_polynomial(int64_t *x, int64_t *y, int x_count, int jump);

void compress_polynomial(int64_t *x, int64_t *y, int y_count, int jump);

}
