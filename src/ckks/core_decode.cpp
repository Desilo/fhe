#include "arithmetic/arithmetic.h"
#include "ckks/core.h"
#include "ckks/encode.h"
#include "montgomery/compound.h"
#include "montgomery/unit.h"
#include "operation/fft.h"

namespace desilo::fhe {

std::tuple<DoublePolynomial *, long double>
CKKSCore::convert_plaintext_to_double(UnitPlaintext *input) {
  const auto include_special = includes_special(input->flag_);
  const auto coeff_count = precomputed_.coeff_count_;
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;
  const auto moduli_id = input->moduli_id_;
  auto q = precomputed_.get_q(moduli_id);
  const auto chain_count =
      parameters_.get_chain_count(moduli_id, include_special);
  const auto flag = input->flag_;

  if (input->chain_count_ == 1) {
    throw std::runtime_error(
        "A plaintext needs at least two chains to be decoded.");
  }

  long double plaintext_modulus = 1;
  for (size_t index = 0; index < chain_count; index++) {
    plaintext_modulus *= static_cast<long double>(q[index]);
  }
  if (input->ckks_scale_ > plaintext_modulus) {
    throw std::invalid_argument(
        "Overflow due to large ckks_scale and small unit plaintext modulus.");
  }

  UnitPlaintext *rescaled = input;

  if (!include_special) {
    UnitPlaintext *prev_rescaled = nullptr;
    while (parameters_.can_rescale_from(rescaled->moduli_id_)) {
      auto ckks_scale = get_rescaled_scale(rescaled);
      if (ckks_scale <= precomputed_.scale_) {
        break;
      }

      if (rescaled != input) {
        prev_rescaled = rescaled;
      }

      rescaled = rescale(rescaled);

      if (prev_rescaled) {
        release(prev_rescaled);
      }
    }
  }
  auto output_scale = rescaled->ckks_scale_;
  const auto rescaled_chain_count = rescaled->chain_count_;

  const auto next_moduli_id = rescaled->moduli_id_;
  const auto next_chain_count =
      parameters_.get_chain_count(next_moduli_id, include_special);
  const auto q0_is_even = (precomputed_.get_q(next_moduli_id)[0] & 1) == 0;

  auto rescaled0 = get_polynomial(rescaled, 0);
  const auto plaintext_double = allocate_double_polynomial(codec_coeff_count);
  const auto decode_parameters =
      precomputed_.make_decode_parameters(rescaled_chain_count, next_moduli_id);

  Polynomial *compressed0 = rescaled0;
  if (coeff_count != codec_coeff_count) {
    compressed0 = allocate_polynomial_(next_moduli_id, next_chain_count, flag,
                                       codec_coeff_count);

    compress_polynomial(rescaled0, compressed0, next_chain_count);
  }

  if (rescaled_chain_count == 1) {
    make_signed_with_coeff_count_(compressed0, compressed0, next_moduli_id,
                                  codec_coeff_count);
    cast_int64_to_double_(compressed0, plaintext_double, rescaled_chain_count);
  } else {
    make_unsigned_reduce_2q_to_q_with_coeff_count_(
        compressed0, compressed0, next_moduli_id, next_chain_count,
        codec_coeff_count);
    if (q0_is_even) {
      q = precomputed_.get_q(next_moduli_id);

      rns_to_double_with_power_of_two(
          compressed0->chains_.data(), plaintext_double->buffer_, q,
          decode_parameters->q_product_,
          decode_parameters->rns_reverser_.data(),
          decode_parameters->r_minus_k_product_, rescaled_chain_count,
          codec_coeff_count, 0, codec_coeff_count);
    } else {

      rns_to_double_(compressed0, plaintext_double->buffer_, *decode_parameters,
                     next_moduli_id, rescaled_chain_count);
    }
  }

  if (compressed0 != rescaled0) {
    release(compressed0);
  }
  if (rescaled != input) {
    release(rescaled);
  }

  release(decode_parameters);

  return std::make_tuple(plaintext_double, output_scale);
}

template <typename T>
void CKKSCore::decode_(DoublePolynomial *input, T *output, long double scale) {
  auto skewed = apply_skewer_(input);

  const auto iffted = reinterpret_cast<std::complex<double> *>(skewed->buffer_);

  bit_reversal_permute_(iffted);
  ifft_(iffted, iffted);
  permute_after_ifft_(skewed->buffer_, output, scale);

  release(skewed);
}

void CKKSCore::decode_to_buffer(UnitPlaintext *input, double *output) {
  const auto slot_count = precomputed_.slot_count_;
  auto [plaintext_double, rescaled_scale] = convert_plaintext_to_double(input);

  decode_(plaintext_double, output, rescaled_scale);

  delete plaintext_double;
}

std::vector<double> CKKSCore::decode(UnitPlaintext *input) {
  const auto slot_count = precomputed_.slot_count_;
  std::vector<double> decoded(slot_count);

  decode_to_buffer(input, decoded.data());

  return decoded;
}

void CKKSCore::decode_complex_plaintext_to_buffer(
    UnitPlaintext *input, std::complex<double> *output) {
  const auto slot_count = precomputed_.slot_count_;
  auto [plaintext_double, rescaled_scale] = convert_plaintext_to_double(input);

  decode_(plaintext_double, output, rescaled_scale);

  delete plaintext_double;
}

std::vector<std::complex<double>>
CKKSCore::decode_complex_plaintext(UnitPlaintext *input) {
  const auto slot_count = precomputed_.slot_count_;
  std::vector<std::complex<double>> decoded(slot_count);

  decode_complex_plaintext_to_buffer(input, decoded.data());

  return decoded;
}

}
