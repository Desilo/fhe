#include <cstdint>

#pragma once

namespace desilo::fhe {

void mont_enter_add(int64_t *x, int64_t *y, int64_t r_squared,
                    uint64_t q_double, uint64_t q, uint64_t k, int coeff_count);

void mont_enter_add_reduce_2q_to_q(int64_t *x, int64_t *y, int64_t r_squared,
                                   uint64_t q_double, uint64_t q, uint64_t k,
                                   int coeff_count);

void mont_mult_add(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
                   uint64_t q, uint64_t k, int coeff_count);

void mont_sub_enter_reduce_2q_to_q(int64_t *x1, int64_t *x2, int64_t *y,
                                   int64_t constant, uint64_t q_double,
                                   uint64_t q, uint64_t k, int coeff_count);

void mont_sub_enter(int64_t *x1, int64_t *x2, int64_t *y, int64_t r_squared,
                    uint64_t q_double, uint64_t q, uint64_t k, int coeff_count);

void mont_enter_exit(int64_t *x, int64_t *y, int64_t r_squared, uint64_t q,
                     uint64_t k, int coeff_count);

void mont_enter_exit_reduce_2q_to_q(int64_t *x, int64_t *y, int64_t r_squared,
                                    uint64_t q, uint64_t k, int coeff_count);

void mont_add_reduce_2q_to_q(int64_t *x1, int64_t *x2, int64_t *y,
                             uint64_t q_double, uint64_t q, int coeff_count);

void mont_sub_reduce_2q_to_q(int64_t *x1, int64_t *x2, int64_t *y,
                             uint64_t q_double, uint64_t q, int coeff_count);

void make_unsigned_reduce_2q_to_q(int64_t *x, int64_t *y, uint64_t q,
                                  int coeff_count);

void negate_make_unsigned(int64_t *x, int64_t *y, uint64_t q, int coeff_count);

void concatenate_make_unsigned(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q,
                               int coeff_count);

}
