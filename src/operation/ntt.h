#include <cstdint>

#pragma once

namespace desilo::fhe {

void split_ntt(int64_t *x, int64_t *y, const int64_t *root, uint64_t q_double,
               uint64_t q, const uint64_t k, int jump_size, int coeff_start,
               int coeff_end);

void unit_ntt(int64_t *x, int64_t *y, const int64_t *root, uint64_t q_double,
              uint64_t q, uint64_t k, int jump_size, int jump_count);

void split_intt(int64_t *x, int64_t *y, const int64_t *root_inverse,
                uint64_t q_double, uint64_t q, uint64_t k, int jump_size,
                int coeff_start, int coeff_end);

void unit_intt(int64_t *x, int64_t *y, const int64_t *root_inverse,
               uint64_t q_double, uint64_t q, uint64_t k, int jump_size,
               int jump_count);

void ntt(int64_t *x, int64_t *y, const int64_t *root, uint64_t q_double,
         uint64_t q, uint64_t k, int coeff_count, int log_coeff_count);
void intt(int64_t *x, int64_t *y, const int64_t *root_inverse,
          uint64_t q_double, uint64_t q, uint64_t k, int coeff_count,
          int log_coeff_count);

}
