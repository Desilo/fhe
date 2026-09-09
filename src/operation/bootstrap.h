#include <complex>
#include <utility>
#include <vector>

#pragma once

namespace desilo::fhe {

constexpr int64_t ROUND_BOUND = 28;

struct TwiddleFactors {
  std::vector<std::vector<std::complex<double>>> center;
  std::vector<std::vector<std::complex<double>>> left;
  std::vector<std::vector<std::complex<double>>> right;
};

std::vector<std::complex<double>> get_phi(int slot_count);
std::vector<std::complex<double>> get_inverse_phi(int slot_count);
const TwiddleFactors get_twiddle_factor(int slot_count, int log_slot_count);
const TwiddleFactors get_inverse_twiddle_factor(int slot_count,
                                                int log_slot_count);

inline int get_coeff_to_slot_log_radix_count(int stage_index, int stage_count,
                                             int log_slot_count) {
  const int log_radix_count =
      (stage_index >= (stage_count - log_slot_count % stage_count))
          ? log_slot_count / stage_count + 1
          : log_slot_count / stage_count;

  return log_radix_count;
};

inline int get_slot_to_coeff_log_radix_count(int stage_index, int stage_count,
                                             int log_slot_count) {
  const int log_radix_count = (stage_index < log_slot_count % stage_count)
                                  ? log_slot_count / stage_count + 1
                                  : log_slot_count / stage_count;

  return log_radix_count;
};
std::vector<std::vector<std::vector<std::complex<double>>>>
get_coeff_to_slot_twiddles(int slot_count, int log_slot_count, int stage_count);
std::vector<std::vector<std::vector<std::complex<double>>>>
get_slot_to_coeff_twiddles(int slot_count, int log_slot_count, int stage_count);
std::pair<int, int> get_stage_loop_counts(int twiddle_count,
                                          int inner_loop_shift = 0);

}
