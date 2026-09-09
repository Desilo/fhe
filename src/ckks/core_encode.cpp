#include <algorithm>
#include <cstring>

#include "arithmetic/arithmetic.h"
#include "ckks/core.h"
#include "ckks/encode.h"
#include "operation/fft.h"

namespace desilo::fhe {

template <typename T>
DoublePolynomial *CKKSCore::encode_to_double_(T &input, double scale) {
  auto permuted_polynomial = permute_for_fft_(input);

  auto permuted_buffer = permuted_polynomial->buffer_;

  auto data = reinterpret_cast<std::complex<double> *>(permuted_buffer);

  bit_reversal_permute_(data);

  fft_(data, data);

  normalize_(permuted_buffer, permuted_buffer);

  auto twisted_data = apply_twister_(permuted_polynomial, scale);

  delete permuted_polynomial;

  return twisted_data;
}

template <typename T>
UnitPlaintext *CKKSCore::encode_polynomial(T &input, int level,
                                           bool include_special) {
  auto moduli_id = to_moduli_id(level);
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;
  const auto coeff_count = precomputed_.coeff_count_;
  auto chain_count = parameters_.get_chain_count(moduli_id, include_special);
  const auto scale = precomputed_.scale_;
  const auto ckks_scale = precomputed_.get_ckks_scale(level);
  auto q = precomputed_.get_q(moduli_id);

  DataFlag flag = get_complex_flag<T>();
  if (include_special) {
    flag |= DataFlag::INCLUDE_SPECIAL;
  }
  auto plaintext = allocate_text<UnitPlaintext>(flag, moduli_id, 1, ckks_scale);
  auto compressed0 = get_polynomial(plaintext, 0);
  if (coeff_count != codec_coeff_count) {
    compressed0 =
        allocate_polynomial_(moduli_id, chain_count, flag, codec_coeff_count);
  }
  int plaintext_offset = 0;

  double scale_before_tile = precomputed_.get_scale_before_tile(level);
  int64_t log_scale_after_tile = precomputed_.get_log_scale_after_tile(level);

  const auto flexible_chain_scale_bit =
      parameters_.get_flexible_chain_scale_bit(moduli_id);
  const auto one_more_level_index = flexible_chain_scale_bit == 0 ? 0 : 1;
  const auto p1 = q[one_more_level_index];

  bool max_level_in_one_more_level = false;

  if (precomputed_.one_more_level_ && moduli_id == 0 &&
      (ckks_scale >= p1 * scale)) {

    if (flexible_chain_scale_bit == 0) {
      zero_fill_with_coeff_count(compressed0, 1, codec_coeff_count,
                                 plaintext_offset);
    }
    plaintext_offset++;
    chain_count -= 1;
    moduli_id = to_moduli_id(level - 1);
    q = precomputed_.get_q(moduli_id);
    max_level_in_one_more_level = true;
  }

  auto encoded = encode_to_double_(input, scale_before_tile);

  double max_absolute_coeff = 0.0;

  max_absolute_(encoded, &max_absolute_coeff);

  if (max_absolute_coeff > (double)(1UL << 59)) {

    double_to_rns_(encoded->buffer_, compressed0, moduli_id, chain_count,
                   plaintext_offset);
  } else {
    auto rounded_polynomial =
        allocate_polynomial_(moduli_id, chain_count, flag, codec_coeff_count);
    round_(encoded, rounded_polynomial);

    const int rounded_polynomial_offset = 0;
    tile_unsigned_reduce_2q_to_q_with_coeff_count_(
        rounded_polynomial, compressed0, moduli_id, chain_count,
        codec_coeff_count, rounded_polynomial_offset, plaintext_offset);
    release(rounded_polynomial);
  }

  const auto r_mult_scale_after_tile =
      precomputed_.get_r_mult_scale_after_tile(level);

  if ((q[0] & 1) == 0) {
    auto flexible_q = q[0];

    auto x0 = compressed0->get(0);
    auto x1 = compressed0->get(1);
    if (max_level_in_one_more_level) {
      for (auto coeff_index = 0; coeff_index < codec_coeff_count;
           coeff_index++) {
        x0[coeff_index] = modulus_multiply(x1[coeff_index], p1, flexible_q);
        x1[coeff_index] = 0;
      }
    } else {
      for (auto coeff_index = 0; coeff_index < codec_coeff_count;
           coeff_index++) {
        x0[coeff_index] <<= log_scale_after_tile;
        x0[coeff_index] &= flexible_q - 1;
      }
    }

    auto parameter_offset = 1;
    mont_enter_with_coeff_count_(
        compressed0, compressed0, r_mult_scale_after_tile, moduli_id,
        chain_count - 1, codec_coeff_count, plaintext_offset + 1,
        plaintext_offset + 1, parameter_offset);
  } else {
    mont_enter_with_coeff_count_(
        compressed0, compressed0, r_mult_scale_after_tile, moduli_id,
        chain_count, codec_coeff_count, plaintext_offset, plaintext_offset, 0);
  }

  if (coeff_count != codec_coeff_count) {
    auto plaintext0 = get_polynomial(plaintext, 0);

    moduli_id = to_moduli_id(level);
    chain_count = parameters_.get_chain_count(moduli_id, include_special);

    zero_fill(plaintext0, chain_count);

    decompress_polynomial(compressed0, plaintext0, chain_count);

    release(compressed0);
  }

  release(encoded);

  return plaintext;
}

UnitPlaintext *CKKSCore::encode(double *input, int level,
                                bool include_special) {
  const auto slot_count = precomputed_.slot_count_;
  auto input_polynomial = allocate_double_polynomial(slot_count);
  auto input_buffer = input_polynomial->buffer_;

  std::memcpy(input_buffer, input, sizeof(double) * slot_count);
  auto encoded = encode_polynomial(input_polynomial, level, include_special);

  release(input_polynomial);

  return encoded;
}

UnitPlaintext *CKKSCore::encode(std::complex<double> *input, int level,
                                bool include_special) {
  const auto slot_count = precomputed_.slot_count_;
  auto input_polynomial = allocate_complex_double_polynomial(slot_count);
  auto input_buffer = input_polynomial->buffer_;

  std::memcpy(input_buffer, input, sizeof(std::complex<double>) * slot_count);
  auto encoded = encode_polynomial(input_polynomial, level, include_special);

  release(input_polynomial);

  return encoded;
}

UnitPlaintext *CKKSCore::encode(std::vector<double> &input, int level,
                                bool include_special) {
  return encode(input.data(), level, include_special);
}

UnitPlaintext *CKKSCore::encode(std::vector<std::complex<double>> &input,
                                int level, bool include_special) {
  return encode(input.data(), level, include_special);
}

UnitPlaintext *CKKSCore::encode_imaginary(int64_t input, int level) {
  const auto flag = DataFlag::COMPLEX;
  const auto moduli_id = to_moduli_id(level);
  const auto chain_count = 1;
  const auto coeff_count = precomputed_.coeff_count_;
  long double ckks_scale = 1.;

  std::vector<int64_t *> chains = {
      desilo::fhe::encode_imaginary(input, coeff_count)};
  const auto encoded_polynomial =
      new Polynomial(chains, flag, moduli_id, coeff_count);

  auto plaintext = allocate_text<UnitPlaintext>(flag, moduli_id, 1, ckks_scale);
  auto plaintext0 = get_polynomial(plaintext, 0);

  tile_unsigned_reduce_2q_to_q_(encoded_polynomial, plaintext0, moduli_id);

  delete encoded_polynomial;

  return plaintext;
}

template <typename T>
std::vector<T> CKKSCore::pad(std::vector<T> &input, int count) {
  if (input.size() < count) {
    std::vector<T> padded(count);
    for (int index = 0; index < input.size(); index++) {
      padded[index] = input[index];
    }

    return padded;
  }

  return input;
}

template std::vector<int64_t> CKKSCore::pad(std::vector<int64_t> &input,
                                            int count);
template std::vector<double> CKKSCore::pad(std::vector<double> &input,
                                           int count);
template std::vector<std::complex<double>>
CKKSCore::pad(std::vector<std::complex<double>> &input, int count);

template <typename T> std::vector<T> CKKSCore::pad(std::vector<T> &input) {
  const auto slot_count = precomputed_.slot_count_;

  return pad(input, slot_count);
}

template std::vector<int64_t> CKKSCore::pad(std::vector<int64_t> &input);
template std::vector<double> CKKSCore::pad(std::vector<double> &input);
template std::vector<std::complex<double>>
CKKSCore::pad(std::vector<std::complex<double>> &input);

double *CKKSCore::pad(double *input, int input_size) {
  const auto slot_count = get_slot_count();

  if (input_size < slot_count) {
    auto padded = new double[slot_count]{};

    for (int index = 0; index < input_size; index++) {
      padded[index] = input[index];
    }
    return padded;
  }

  return input;
}

std::complex<double> *CKKSCore::pad(std::complex<double> *input,
                                    int input_size) {
  const auto slot_count = get_slot_count();

  if (input_size < slot_count) {
    auto padded = new std::complex<double>[slot_count] {};

    for (int index = 0; index < input_size; index++) {
      padded[index] = input[index];
    }
    return padded;
  }

  return input;
}

}
