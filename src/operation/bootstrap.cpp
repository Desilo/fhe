#include <cstring>

#include "arithmetic/arithmetic.h"
#include "arithmetic/pi.h"
#include "operation/bootstrap.h"

namespace desilo::fhe {

std::vector<std::complex<double>> get_phi(int slot_count) {

  std::vector<std::complex<double>> phi(slot_count);

  const double pi_over_slot_count = pi / slot_count;
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    phi[slot_index] =
        std::exp(std::complex<double>(0, -2 * pi_over_slot_count * slot_index));
  }

  return phi;
}

std::vector<std::complex<double>> get_inverse_phi(int slot_count) {

  std::vector<std::complex<double>> inverse_phi(slot_count);

  const double pi_over_slot_count = pi / slot_count;
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    inverse_phi[slot_index] =
        std::exp(std::complex<double>(0, 2 * pi_over_slot_count * slot_index));
  }

  return inverse_phi;
}

const TwiddleFactors get_twiddle_factor(int slot_count, int log_slot_count) {
  TwiddleFactors twiddle_factors;
  const auto quadruple_slot_count = slot_count << 2;

  const auto phi = get_phi(quadruple_slot_count);

  auto jump_size = slot_count;
  for (int log_slot_index = 0; log_slot_index < log_slot_count;
       log_slot_index++) {
    const auto jump_count = 1 << log_slot_index;
    jump_size >>= 1;

    std::vector<int> phi_index;
    int power_of_five = 1;
    for (int slot_index = 0; slot_index < jump_size; slot_index++) {
      phi_index.push_back(power_of_five * jump_count);
      power_of_five *= 5;
      power_of_five &= (jump_size << 3) - 1;
    }

    std::vector<std::complex<double>> center(slot_count, 0);
    std::vector<std::complex<double>> left(slot_count, 0);
    std::vector<std::complex<double>> right(slot_count, 0);

    for (int jump_index = 0; jump_index < jump_count; jump_index++) {
      auto index = 2 * jump_index * jump_size;
      for (int slot_index = 0; slot_index < jump_size; slot_index++) {
        const auto phi_value = phi[phi_index[slot_index]];
        center[index] = 1;
        center[jump_size + index] = -phi_value;
        left[index] = 1;
        right[jump_size + index] = phi_value;
        index++;
      }
    }
    twiddle_factors.center.push_back(center);
    twiddle_factors.left.push_back(left);
    twiddle_factors.right.push_back(right);
  }

  return twiddle_factors;
}

const TwiddleFactors get_inverse_twiddle_factor(int slot_count,
                                                int log_slot_count) {
  TwiddleFactors twiddle_factors;
  const auto quadruple_slot_count = slot_count << 2;

  const auto inverse_phi = get_inverse_phi(quadruple_slot_count);

  auto jump_size = 1;
  for (int log_slot_index = log_slot_count - 1; log_slot_index >= 0;
       log_slot_index--) {
    const auto jump_count = 1 << log_slot_index;

    std::vector<int> inverse_phi_index;
    int power_of_five = 1;
    for (int slot_index = 0; slot_index < jump_size; slot_index++) {
      inverse_phi_index.push_back(power_of_five * jump_count);
      power_of_five *= 5;
      power_of_five &= (jump_size << 3) - 1;
    }

    std::vector<std::complex<double>> center(slot_count, 0);
    std::vector<std::complex<double>> left(slot_count, 0);
    std::vector<std::complex<double>> right(slot_count, 0);

    for (int jump_index = 0; jump_index < jump_count; jump_index++) {
      auto index = 2 * jump_index * jump_size;
      for (int slot_index = 0; slot_index < jump_size; slot_index++) {
        const auto inverse_phi_value =
            inverse_phi[inverse_phi_index[slot_index]];
        center[index] = 1;
        center[jump_size + index] = -inverse_phi_value;
        left[index] = inverse_phi_value;
        right[jump_size + index] = 1;
        index++;
      }
    }
    twiddle_factors.center.push_back(center);
    twiddle_factors.left.push_back(left);
    twiddle_factors.right.push_back(right);

    jump_size <<= 1;
  }

  return twiddle_factors;
}

std::vector<std::vector<std::vector<std::complex<double>>>>
get_coeff_to_slot_twiddles(int slot_count, int log_slot_count,
                           int stage_count) {
  const auto twiddle_factors = get_twiddle_factor(slot_count, log_slot_count);
  const auto centers = twiddle_factors.center;
  const auto lefts = twiddle_factors.left;
  const auto rights = twiddle_factors.right;

  std::vector<std::vector<std::vector<std::complex<double>>>>
      coeff_to_slot_twiddles;
  auto radix_jump_size = slot_count;

  int twiddle_index_offset = 0;
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    const int log_radix_count = get_coeff_to_slot_log_radix_count(
        stage_index, stage_count, log_slot_count);
    const int radix_count = 1 << log_radix_count;
    const int total_radix_count = 2 * radix_count - 1;

    std::vector<std::vector<std::complex<double>>> stage_twiddles(
        total_radix_count, std::vector<std::complex<double>>(slot_count, 1));

    for (int log_radix_index = 0; log_radix_index < log_radix_count;
         log_radix_index++) {
      radix_jump_size >>= 1;
      const int radix_index = 1 << log_radix_index;
      const int jump_size = radix_count / (2 * radix_index);
      const int twiddle_index = twiddle_index_offset + log_radix_index;

      std::vector<std::vector<std::complex<double>>> radix_twiddles(
          total_radix_count, std::vector<std::complex<double>>(slot_count, 0));
      stage_twiddles.swap(radix_twiddles);

      const auto center = centers[twiddle_index];
      const auto left = lefts[twiddle_index];
      const auto right = rights[twiddle_index];

      for (int index = -radix_index + 1; index < radix_index; index++) {
        const int unit_index = index * radix_count / radix_index;
        const int center_index = positive_modulo(unit_index, total_radix_count);
        const int left_index =
            positive_modulo(unit_index - jump_size, total_radix_count);
        const int right_index =
            positive_modulo(unit_index + jump_size, total_radix_count);

        for (int slot_index = 0; slot_index < slot_count; slot_index++) {
          stage_twiddles[center_index][slot_index] +=
              center[slot_index] * radix_twiddles[center_index][slot_index];
          stage_twiddles[left_index][slot_index] +=
              left[slot_index] * radix_twiddles[center_index][positive_modulo(
                                     slot_index + radix_jump_size, slot_count)];
          stage_twiddles[right_index][slot_index] +=
              right[slot_index] *
              radix_twiddles[center_index][positive_modulo(
                  slot_index - radix_jump_size, slot_count)];
        }
      }
    }

    const int normalizing_value = 2 * slot_count * ROUND_BOUND;
    if (stage_index == stage_count - 1) {
      for (int radix_index = 0; radix_index < total_radix_count;
           radix_index++) {
        for (int slot_index = 0; slot_index < slot_count; slot_index++) {
          stage_twiddles[radix_index][slot_index] /= normalizing_value;
        }
      }
    }

    coeff_to_slot_twiddles.emplace_back(std::move(stage_twiddles));
    twiddle_index_offset += log_radix_count;
  }

  return coeff_to_slot_twiddles;
}

std::vector<std::vector<std::vector<std::complex<double>>>>
get_slot_to_coeff_twiddles(int slot_count, int log_slot_count,
                           int stage_count) {
  const auto inverse_twiddle_factors =
      get_inverse_twiddle_factor(slot_count, log_slot_count);
  const auto centers = inverse_twiddle_factors.center;
  const auto lefts = inverse_twiddle_factors.left;
  const auto rights = inverse_twiddle_factors.right;

  std::vector<std::vector<std::vector<std::complex<double>>>>
      slot_to_coeff_twiddles;
  auto radix_jump_size = 1;

  int twiddle_index_offset = 0;
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    const int log_radix_count = get_slot_to_coeff_log_radix_count(
        stage_index, stage_count, log_slot_count);
    const int radix_count = 1 << log_radix_count;
    const int total_radix_count = 2 * radix_count - 1;

    std::vector<std::vector<std::complex<double>>> stage_twiddles(
        total_radix_count, std::vector<std::complex<double>>(slot_count, 1));

    for (int log_radix_index = 0; log_radix_index < log_radix_count;
         log_radix_index++) {
      const int radix_index = 1 << log_radix_index;
      const int jump_size = radix_index;
      const int twiddle_index = twiddle_index_offset + log_radix_index;

      std::vector<std::vector<std::complex<double>>> radix_twiddles(
          total_radix_count, std::vector<std::complex<double>>(slot_count, 0));
      stage_twiddles.swap(radix_twiddles);

      const auto center = centers[twiddle_index];
      const auto left = lefts[twiddle_index];
      const auto right = rights[twiddle_index];

      for (int index = -radix_index + 1; index < radix_index; index++) {
        const int center_index = positive_modulo(index, total_radix_count);
        const int left_index =
            positive_modulo(index - jump_size, total_radix_count);
        const int right_index =
            positive_modulo(index + jump_size, total_radix_count);

        for (int slot_index = 0; slot_index < slot_count; slot_index++) {
          stage_twiddles[center_index][slot_index] +=
              center[slot_index] * radix_twiddles[center_index][slot_index];
          stage_twiddles[left_index][slot_index] +=
              left[slot_index] * radix_twiddles[center_index][positive_modulo(
                                     slot_index + radix_jump_size, slot_count)];
          stage_twiddles[right_index][slot_index] +=
              right[slot_index] *
              radix_twiddles[center_index][positive_modulo(
                  slot_index - radix_jump_size, slot_count)];
        }
      }
      radix_jump_size <<= 1;
    }
    slot_to_coeff_twiddles.emplace_back(std::move(stage_twiddles));
    twiddle_index_offset += log_radix_count;
  }

  return slot_to_coeff_twiddles;
}

std::pair<int, int> get_stage_loop_counts(int twiddle_count,
                                          int inner_loop_shift) {
  int bit_count = 0;
  int temp = twiddle_count;
  while (temp > 0) {
    temp >>= 1;
    bit_count++;
  }

  const int inner_loop_count = 1 << ((bit_count + 1) / 2 + inner_loop_shift);
  const int outer_loop_count = (twiddle_count + 1) / inner_loop_count;

  return {inner_loop_count, outer_loop_count};
}

}
