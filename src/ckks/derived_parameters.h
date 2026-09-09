#include <cstdint>
#include <vector>

#pragma once

namespace desilo::fhe {

std::vector<int64_t> bit_reverse_order(const std::vector<int64_t> &original,
                                       int log_coeff_count);

struct CKKSDerivedParameters {
  CKKSDerivedParameters(uint64_t q, int64_t r, int log_coeff_count,
                        int coeff_count,
                        const std::vector<int> &backward_paint);

  uint64_t q_;
  uint64_t k_;
  uint64_t q_double_;
  uint64_t q_half_;

  int64_t r_;
  int64_t r_squared_;
  int64_t coeff_count_inverse_;
  std::vector<int64_t> root_;
  std::vector<int64_t> root_inverse_;

  int log_coeff_count_;
  int coeff_count_;
};

}
