#include "montgomery/compound.h"
#include "montgomery/unit.h"

namespace desilo::fhe {

void mont_enter_add(int64_t *x, int64_t *y, int64_t r_squared,
                    uint64_t q_double, uint64_t q, uint64_t k,
                    int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto product = mont_mult_scalar(*x++, r_squared, q, k);
    *y = guard(product + *y, q_double);
    y++;
  }
}

void mont_enter_add_reduce_2q_to_q(int64_t *x, int64_t *y, int64_t r_squared,
                                   uint64_t q_double, uint64_t q, uint64_t k,
                                   int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto product = mont_mult_scalar(*x++, r_squared, q, k);
    *y = guard(guard(product + *y, q_double), q);
    y++;
  }
}

void mont_mult_add(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
                   uint64_t q, uint64_t k, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto product = mont_mult_scalar(*x1++, *x2++, q, k);
    *y = guard(product + *y, q_double);
    y++;
  }
}

void mont_sub_enter_reduce_2q_to_q(int64_t *x1, int64_t *x2, int64_t *y,
                                   int64_t constant, uint64_t q_double,
                                   uint64_t q, uint64_t k, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto diff = guard(*x1++ + q_double - *x2++, q_double);
    const auto product = mont_mult_scalar(diff, constant, q, k);
    *y++ = guard(product, q);
  }
}

void mont_sub_enter(int64_t *x1, int64_t *x2, int64_t *y, int64_t r_squared,
                    uint64_t q_double, uint64_t q, uint64_t k,
                    int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto diff = guard(*x1++ + q_double - *x2++, q_double);
    *y++ = mont_mult_scalar(diff, r_squared, q, k);
  }
}

void mont_enter_exit(int64_t *x, int64_t *y, int64_t r_squared, uint64_t q,
                     uint64_t k, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto entered = mont_mult_scalar(*x++, r_squared, q, k);
    *y++ = mont_exit_scalar(entered, q, k);
  }
}

void mont_enter_exit_reduce_2q_to_q(int64_t *x, int64_t *y, int64_t r_squared,
                                    uint64_t q, uint64_t k, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto entered = mont_mult_scalar(*x++, r_squared, q, k);
    const auto exited = mont_exit_scalar(entered, q, k);
    *y++ = guard(exited, q);
  }
}

void mont_add_reduce_2q_to_q(int64_t *x1, int64_t *x2, int64_t *y,
                             uint64_t q_double, uint64_t q, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = guard(guard(*x1++ + *x2++, q_double), q);
  }
}

void mont_sub_reduce_2q_to_q(int64_t *x1, int64_t *x2, int64_t *y,
                             uint64_t q_double, uint64_t q, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = guard(guard(*x1++ + q_double - *x2++, q_double), q);
  }
}

void make_unsigned_reduce_2q_to_q(int64_t *x, int64_t *y, uint64_t q,
                                  int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    const auto x_value = *x++;
    *y++ = (x_value < 0) ? x_value + q : guard(x_value, q);
  }
}

void negate_make_unsigned(int64_t *x, int64_t *y, uint64_t q, int coeff_count) {
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *y++ = q - *x++;
  }
}

void concatenate_make_unsigned(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q,
                               int coeff_count) {
  constexpr uint128_t mask = (1UL << (76 - 63)) - 1;
  constexpr uint128_t mean_value = static_cast<uint128_t>(1) << 75;

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    uint128_t output =
        ((static_cast<uint128_t>(*x1++) & mask) << 63) + *x2++ - mean_value;
    *y++ = output % q + q;
  }
}

}
