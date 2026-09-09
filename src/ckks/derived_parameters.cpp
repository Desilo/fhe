#include "ckks/derived_parameters.h"
#include "arithmetic/arithmetic.h"
#include "ckks/encode.h"
#include "montgomery/unit.h"

namespace desilo::fhe {

std::vector<int64_t> bit_reverse_order(const std::vector<int64_t> &original,
                                       int log_coeff_count) {
  std::vector<int64_t> shuffled = original;

  for (int index = 0; index < original.size(); index++) {
    shuffled[reverse_integer_bits(index, log_coeff_count)] = original[index];
  }

  return shuffled;
}

CKKSDerivedParameters::CKKSDerivedParameters(
    uint64_t q, int64_t r, int log_coeff_count, int coeff_count,
    const std::vector<int> &backward_paint)
    : q_(q), r_(r), log_coeff_count_(log_coeff_count),
      coeff_count_(coeff_count), q_double_(q << 1), q_half_(q >> 1) {
  r_squared_ = modulus_multiply(r, r, q);
  k_ = calculate_k(r, q);
  coeff_count_inverse_ = modulus_multiply(modulus_invert(coeff_count, q), r, q);

  const auto root = find_root(q, coeff_count);
  const auto root_inverse = modulus_invert(root, q);

  const auto root_power_series = get_power_series(root, q, coeff_count);
  const auto root_inverse_power_series =
      get_power_series(root_inverse, q, coeff_count);

  const auto shuffled_root_power_series =
      bit_reverse_order(root_power_series, log_coeff_count_);
  const auto shuffled_root_inverse_power_series =
      bit_reverse_order(root_inverse_power_series, log_coeff_count_);

  for (int index = 1; index < coeff_count_; index++) {
    root_.push_back(shuffled_root_power_series[index]);
  }
  for (const auto paint_index : backward_paint) {
    root_inverse_.push_back(shuffled_root_inverse_power_series[paint_index]);
  }

  mont_enter(root_.data(), root_.data(), r_squared_, q, k_, root_.size());
  mont_enter(root_inverse_.data(), root_inverse_.data(), r_squared_, q, k_,
             root_inverse_.size());
}

}
