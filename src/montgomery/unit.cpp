#include "montgomery/unit.h"

namespace desilo::fhe {

void mont_mult(int64_t *x1, const int64_t *x2, int64_t *y, uint64_t q,
               uint64_t k, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = mont_mult_scalar(*x1++, *x2++, q, k);
  }
}

void mont_enter(int64_t *x, int64_t *y, int64_t constant, uint64_t q,
                uint64_t k, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = mont_mult_scalar(*x++, constant, q, k);
  }
}

void reduce_2q_to_q(int64_t *x, int64_t *y, const uint64_t *q, int chain_count,
                    int coeff_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_q = *q++;

    for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
      *y++ = guard(*x++, chain_q);
    }
  }
}

void reduce_2q_to_q(int64_t *x, int64_t *y, uint64_t q, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = guard(*x++, q);
  }
}

void make_signed(int64_t *x, int64_t *y, uint64_t q, uint64_t q_half,
                 int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    auto x_value = *x++;
    *y++ = (x_value <= q_half) ? x_value : x_value - q;
  }
}

void negate(int64_t *x, int64_t *y, int chain_count, int coeff_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
      *y++ = -*x++;
    }
  }
}

void mont_add(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
              int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = guard(*x1++ + *x2++, q_double);
  }
}

void mont_subtract(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
                   int coeff_count) {
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto subtracted = *x1++ - *x2++;
    *y++ = (subtracted >= 0) ? subtracted : subtracted + q_double;
  }
}

void get_rounder(int64_t *x, int64_t *y, uint64_t q_half, int coeff_count) {
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = (*x++ > q_half) ? 1 : 0;
  }
}

void decompress_polynomial(int64_t *x, int64_t *y, int x_count, int jump) {
  for (auto x_index = 0; x_index < x_count; x_index++) {
    *y++ = *x++;
    for (auto pad_index = 1; pad_index < jump; pad_index++) {
      *y++ = 0;
    }
  }
}

void compress_polynomial(int64_t *x, int64_t *y, int y_count, int jump) {
  for (auto y_index = 0; y_index < y_count; y_index++) {
    *y++ = x[y_index * jump];
  }
}

}
