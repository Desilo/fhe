#include <cmath>
#include <cstdint>
#include <map>

#include "arithmetic/arithmetic.h"
#include "arithmetic/big_int.h"
#include "arithmetic/pi.h"
#include "ckks/derived_parameters.h"
#include "ckks/encode.h"
#include "ckks/precomputed.h"
#include "montgomery/unit.h"

namespace desilo::fhe {

std::vector<int> get_backward_paint(int log_coeff_count) {
  std::vector<int> output;
  int one = 1;

  for (int log_coeff_index = log_coeff_count - 1; log_coeff_index >= 0;
       log_coeff_index--) {
    int group_length = one << (log_coeff_count - log_coeff_index - 1);
    int group_count = one << log_coeff_index;
    int root_index = group_count;

    for (int group_index = 0; group_index < group_count; group_index++) {
      output.push_back(root_index++);
    }
  }

  return output;
}

CKKSPrecomputed::CKKSPrecomputed(const CKKSConfig &config)
    : parameters_(config), log_coeff_count_(parameters_.get_log_coeff_count()),
      coeff_count_(parameters_.get_coeff_count()),
      log_slot_count_(parameters_.get_log_slot_count()),
      slot_count_(parameters_.get_slot_count()),
      log_codec_coeff_count_(parameters_.get_log_codec_coeff_count()),
      codec_coeff_count_(parameters_.get_codec_coeff_count()),
      scale_bit_length_(parameters_.get_scale_bit_length()),
      scale_(parameters_.get_scale()), r_(INT64_C(1) << buffer_bit_length_),
      chain_count_(parameters_.get_chain_count()),
      prime_count_(parameters_.get_prime_count()),
      special_prime_count_(parameters_.get_special_prime_count()),
      one_more_level_(parameters_.get_use_one_more_level()),
      engine_test_(parameters_.get_use_engine_test()),
      deviation_(parameters_.get_deviations()) {
  const auto backward_paint = get_backward_paint(log_coeff_count_);

  const auto circular_shift = circular_shift_permutation(codec_coeff_count_);
  const auto fold_canon = fold_canon_permutation(codec_coeff_count_);
  auto post_permutation =
      conjugate_permutations(fold_canon, circular_shift, codec_coeff_count_);

  auto pre_permutation =
      invert_permutation(post_permutation, codec_coeff_count_);
  pre_permutation_.assign(pre_permutation,
                          pre_permutation + codec_coeff_count_);
  post_permutation_.assign(post_permutation,
                           post_permutation + codec_coeff_count_);

  delete[] circular_shift;
  delete[] fold_canon;
  delete[] post_permutation;
  delete[] pre_permutation;

  const double unit_angle = -2 * pi / codec_coeff_count_;

  for (int index = 0; index < codec_coeff_count_; index++) {
    const double angle = index * unit_angle;
    fft_twiddle_factor_.push_back(
        std::complex<double>(std::cos(angle), std::sin(angle)));
    ifft_twiddle_factor_.push_back(
        std::complex<double>(std::cos(angle), std::sin(-angle)));
  }

  std::map<int64_t, CKKSDerivedParameters> already_derived;
  q_ = parameters_.get_moduli(0);
  for (const auto q : q_) {
    if (!already_derived.contains(q)) {
      already_derived.emplace(q, CKKSDerivedParameters(q, r_, log_coeff_count_,
                                                       coeff_count_,
                                                       backward_paint));
    }
    auto &derived = already_derived.at(q);

    k_.push_back(derived.k_);
    q_double_.push_back(derived.q_double_);
    q_half_.push_back(derived.q_half_);
    r_squared_.push_back(derived.r_squared_);
    coeff_count_inverse_.push_back(derived.coeff_count_inverse_);
    root_.insert(root_.end(), derived.root_.begin(), derived.root_.end());
    root_inverse_.insert(root_inverse_.end(), derived.root_inverse_.begin(),
                         derived.root_inverse_.end());
  }

  for (int q_index = 0; q_index < chain_count_; q_index++) {
    const auto q = q_[q_index];
    int64_t product = r_;

    for (int p_index = chain_count_; p_index < q_.size(); p_index++) {
      const auto p = q_[p_index];
      product = modulus_multiply(product, p, q);
    }

    p_product_mult_r_.push_back(product);
  }

  for (int p_index = q_.size() - 1; p_index >= chain_count_; p_index--) {
    const auto p = q_[p_index];

    std::vector<int64_t> p_inverse_mult_r;

    for (int q_index = 0; q_index < p_index; q_index++) {
      const auto q = q_[q_index];
      const auto p_inverse = modulus_invert(p, q);
      p_inverse_mult_r.push_back(modulus_multiply(p_inverse, r_, q));
    }

    p_inverse_mult_r_.push_back(p_inverse_mult_r);
  }

  for (int q_from_index = 0; q_from_index < prime_count_ - 1; q_from_index++) {
    const auto q_from = q_[q_from_index];

    std::vector<int64_t> rescale_scale;

    for (int q_to_index = q_from_index + 1; q_to_index < prime_count_;
         q_to_index++) {
      const auto q_to = q_[q_to_index];
      const auto q_from_inverse = modulus_invert(q_from, q_to);

      rescale_scale.push_back(modulus_multiply(q_from_inverse, r_, q_to));
    }

    rescale_scale_.push_back(rescale_scale);
  }

  for (int level = 0; level <= parameters_.get_full_level(); level++) {
    auto moduli_id = parameters_.get_moduli_id(level);
    auto chain_count = parameters_.get_chain_count(moduli_id, true);
    auto log_scale = scale_bit_length_;
    auto deviation = deviation_[level];
    auto q = get_q(moduli_id);

    long double ckks_scale =
        static_cast<long double>(deviation) * scale_ * scale_;

    if (one_more_level_ && moduli_id == 0) {
      ckks_scale = scale_ * static_cast<long double>(q[0]);
    }

    ckks_scale_.push_back(ckks_scale);

    double scale_before_tile;
    int64_t log_scale_after_tile = 0;

    const auto flexible_chain_scale_bit =
        parameters_.get_flexible_chain_scale_bit(moduli_id);
    const auto one_more_level_index = flexible_chain_scale_bit == 0 ? 0 : 1;
    const auto p0 = q[one_more_level_index];

    bool max_level_in_one_more_level =
        one_more_level_ && moduli_id == 0 && (ckks_scale >= p0 * scale_);

    if (max_level_in_one_more_level) {
      scale_before_tile = ckks_scale / p0;

      chain_count -= 1;
      moduli_id = parameters_.get_moduli_id(level - 1);
      q = get_q(moduli_id);
    } else {

      int ckks_scale_exponent;
      double ckks_scale_mantisa = std::frexp(ckks_scale, &ckks_scale_exponent);

      if (ckks_scale_exponent >= log_scale) {
        scale_before_tile = ckks_scale_mantisa * scale_;
        log_scale_after_tile = ckks_scale_exponent - log_scale;
      } else {
        scale_before_tile = ckks_scale;
        log_scale_after_tile = 0;
      }
    }

    std::vector<int64_t> r_mult_scale_after_tile(chain_count);

    const int64_t chunk_length = 60;

    if (max_level_in_one_more_level) {
      for (size_t chain_index = 0; chain_index < chain_count; chain_index++) {
        const auto q_to = q[chain_index];
        r_mult_scale_after_tile[chain_index] = modulus_multiply(r_, p0, q_to);
      }
    } else {
      for (size_t chain_index = 0; chain_index < chain_count; chain_index++) {
        const auto q_to = q[chain_index];
        r_mult_scale_after_tile[chain_index] = r_ % q_to;
      }

      auto log_scale = log_scale_after_tile;
      for (; log_scale > 0; log_scale -= chunk_length) {
        int64_t partial_scale = 1L << std::min(chunk_length, log_scale);

        for (size_t chain_index = 0; chain_index < chain_count; chain_index++) {
          r_mult_scale_after_tile[chain_index] =
              modulus_multiply(r_mult_scale_after_tile[chain_index],
                               partial_scale, q[chain_index]);
        }
      }
    }

    r_mult_scale_after_tile_.push_back(r_mult_scale_after_tile);
    scale_before_tile_.push_back(scale_before_tile);
    log_scale_after_tile_.push_back(log_scale_after_tile);
  }
}

const uint64_t *CKKSPrecomputed::get_pre_permutation() const {
  return pre_permutation_.data();
}

const uint64_t *CKKSPrecomputed::get_post_permutation() const {
  return post_permutation_.data();
}

const uint64_t *CKKSPrecomputed::get_q(int moduli_id, int chain_start) const {
  auto depth = moduli_id + chain_start;
  return &q_.data()[depth];
}

const uint64_t *CKKSPrecomputed::get_k(int moduli_id, int chain_start) const {
  auto depth = moduli_id + chain_start;
  return &k_.data()[depth];
}

const uint64_t *CKKSPrecomputed::get_q_double(int moduli_id,
                                              int chain_start) const {
  auto depth = moduli_id + chain_start;
  return &q_double_.data()[depth];
}

const uint64_t *CKKSPrecomputed::get_q_half(int moduli_id,
                                            int chain_start) const {
  auto depth = moduli_id + chain_start;
  return &q_half_.data()[depth];
}

const int64_t *CKKSPrecomputed::get_r_squared(int moduli_id,
                                              int chain_start) const {
  auto depth = moduli_id + chain_start;
  return &r_squared_.data()[depth];
}

const int64_t *CKKSPrecomputed::get_coeff_count_inverse(int moduli_id,
                                                        int chain_start) const {
  auto depth = moduli_id + chain_start;
  return &coeff_count_inverse_.data()[depth];
}

const int64_t *CKKSPrecomputed::get_root(int moduli_id, int chain_start) const {
  auto count_per_chain = coeff_count_ - 1;

  auto offset = (moduli_id + chain_start) * count_per_chain;
  return &root_.data()[offset];
}

const int64_t *CKKSPrecomputed::get_root_inverse(int moduli_id,
                                                 int chain_start) const {
  auto count_per_chain = coeff_count_ - 1;

  auto offset = (moduli_id + chain_start) * count_per_chain;
  return &root_inverse_.data()[offset];
}

const int64_t *CKKSPrecomputed::get_p_product_mult_r(int moduli_id) const {
  return &p_product_mult_r_.data()[moduli_id];
}

std::vector<const int64_t *>
CKKSPrecomputed::get_p_inverse_mult_r(int moduli_id) const {
  std::vector<const int64_t *> p_inverse_mult_r;
  for (int special_prime_index = 0; special_prime_index < special_prime_count_;
       special_prime_index++) {
    const int64_t *pir;
    pir = &p_inverse_mult_r_[special_prime_index].data()[moduli_id];
    p_inverse_mult_r.push_back(pir);
  }

  return p_inverse_mult_r;
}

const int64_t *CKKSPrecomputed::get_rescale_scale(int moduli_id) const {

  auto previous_moduli_id = moduli_id - 1;

  return rescale_scale_[previous_moduli_id].data();
}

long double CKKSPrecomputed::get_rescaled_scale(long double scale,
                                                int moduli_id) const {
  auto q = get_q(moduli_id);

  auto rescaled_scale = scale / q[0];

  return rescaled_scale;
}

long double CKKSPrecomputed::get_ckks_scale(int level) const {
  return ckks_scale_[level];
}

double CKKSPrecomputed::get_scale_before_tile(int level) const {
  return scale_before_tile_[level];
}

int64_t CKKSPrecomputed::get_log_scale_after_tile(int level) const {
  return log_scale_after_tile_[level];
}

const int64_t *CKKSPrecomputed::get_r_mult_scale_after_tile(int level) const {
  return r_mult_scale_after_tile_[level].data();
}

CKKSPartitionParameters
CKKSPrecomputed::make_partition_parameters(const Partition &partition) const {
  CKKSPartitionParameters parameters;

  auto moduli_id = partition.moduli_id_;
  auto q = get_q(moduli_id);
  auto r_squared = get_r_squared(moduli_id);
  auto prime_count = parameters_.get_chain_count(moduli_id, true);

  auto q_product = BigInt(q[partition[0]]);

  for (int chain_index = 1; chain_index < partition.size_; chain_index++) {
    const auto chain_q = q[partition[chain_index]];
    int64_t q_product_mod_chain_q = q_product % chain_q;
    int64_t q_product_inverse = modulus_invert(q_product_mod_chain_q, chain_q);
    if ((chain_q & 1) == 0) {
      parameters.q_product_inverse_mult_r_.push_back(q_product_inverse);
    } else {
      parameters.q_product_inverse_mult_r_.push_back(
          modulus_multiply(q_product_inverse, r_, chain_q));
    }

    if (chain_index < partition.size_ - 1) {
      std::vector<int64_t> q_product_mult_r;
      for (int modulus_index = chain_index + 1; modulus_index < partition.size_;
           modulus_index++) {
        const auto modulus_q = q[partition[modulus_index]];
        int64_t q_product_mod_modulus_q = q_product % modulus_q;

        if ((modulus_q & 1) == 0) {
          q_product_mult_r.push_back(q_product_mod_modulus_q);
        } else {
          q_product_mult_r.push_back(
              modulus_multiply(q_product_mod_modulus_q, r_, modulus_q));
        }
      }
      parameters.q_product_mult_r_.push_back(q_product_mult_r);
    }

    std::vector<int64_t> q_product_mult_r_squared;
    for (int modulus_index = 0; modulus_index < prime_count; modulus_index++) {
      const auto modulus_q = q[modulus_index];
      int64_t q_product_mod_modulus_q = q_product % modulus_q;

      if ((modulus_q & 1) == 0) {
        q_product_mult_r_squared.push_back(q_product_mod_modulus_q);
      } else {
        q_product_mult_r_squared.push_back(modulus_multiply(
            q_product_mod_modulus_q, r_squared[modulus_index], modulus_q));
      }
    }
    parameters.q_product_mult_r_squared_.push_back(q_product_mult_r_squared);

    q_product = q_product * chain_q;
  }

  return parameters;
}

PermutationParameters *
CKKSPrecomputed::make_bit_reversal_permutation_parameters(int size) const {
  auto parameters = new PermutationParameters();

  parameters->values_.resize(coeff_count_);
  get_bit_reversal_permutation_and_sign(parameters->values_.data(), size);

  return parameters;
}

std::tuple<PermutationParameters *, PermutationParameters *>
CKKSPrecomputed::make_permutation_parameters(int delta) const {
  auto permutation = new PermutationParameters();
  auto sign = new PermutationParameters();

  permutation->values_.resize(coeff_count_);
  sign->values_.resize(coeff_count_);

  get_permutation_and_sign(permutation->values_.data(), sign->values_.data(),
                           coeff_count_, delta);

  return std::make_tuple(permutation, sign);
}

PermutationParameters *
CKKSPrecomputed::make_ntt_permutation_parameters(int delta) const {
  auto parameters = new PermutationParameters();

  parameters->values_.resize(coeff_count_);
  get_ntt_permutation(parameters->values_.data(), coeff_count_, delta);

  return parameters;
}

Multiplier *CKKSPrecomputed::make_level_down_multiplier_after_rescale(
    int source_level, int destination_level) {
  auto multiplier = new Multiplier();

  const auto source_deviation = deviation_[source_level - 1];
  const auto destination_deviation = deviation_[destination_level];
  const auto deviation_diff =
      destination_deviation / std::sqrt(source_deviation);
  const auto deviated_delta =
      BigInt::from_double(std::round(scale_ * deviation_diff)) * r_;

  const auto destination_moduli_id =
      parameters_.get_moduli_id(destination_level);
  for (int index = destination_moduli_id; index < chain_count_; index++) {
    multiplier->multiplier_.push_back(deviated_delta % q_[index]);
  }

  return multiplier;
}

Multiplier *CKKSPrecomputed::make_level_down_multiplier(int source_level,
                                                        int destination_level) {
  auto multiplier = new Multiplier();

  const auto source_moduli_id = parameters_.get_moduli_id(source_level);
  const auto source_deviation = deviation_[source_level];
  const auto destination_deviation = deviation_[destination_level];
  const auto deviation_diff = destination_deviation / source_deviation;

  double deviation_delta;
  if (one_more_level_ && source_moduli_id == 0) {
    deviation_delta = scale_ * deviation_diff;
  } else {
    deviation_delta = q_[source_moduli_id] * deviation_diff;
  }

  const auto deviated_delta_mult_r =
      BigInt::from_double(std::round(deviation_delta)) * r_;

  for (int index = source_moduli_id; index < chain_count_; index++) {
    multiplier->multiplier_.push_back(deviated_delta_mult_r % q_[index]);
  }

  return multiplier;
}

int CKKSPrecomputed::to_normalized_delta(int delta) const {
  return positive_modulo(delta, slot_count_);
}

DecodeParameters *CKKSPrecomputed::make_decode_parameters(int chain_count,
                                                          int moduli_id) const {
  auto q = get_q(moduli_id);
  auto k = get_k(moduli_id);

  return new DecodeParameters(q, k, r_, chain_count);
}

Multiplier *CKKSPrecomputed::make_add_multiplier(double value, int level) {
  auto multiplier = new Multiplier();

  const auto moduli_id = parameters_.get_moduli_id(level);
  const auto chain_count = parameters_.get_chain_count(moduli_id);
  const auto q = get_q(moduli_id);
  auto deviation = deviation_[level];
  auto scalar = new int64_t[chain_count];

  if (parameters_.get_use_one_more_level() && moduli_id == 0) {
    deviation = *q / scale_;
  }

  scale_modulo(scalar, value, scale_, deviation, q, chain_count);

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    multiplier->multiplier_.push_back(scalar[chain_index]);
  }

  delete[] scalar;

  return multiplier;
}

Multiplier *CKKSPrecomputed::make_mult_multiplier(double value, int level) {
  auto multiplier = new Multiplier();

  const auto moduli_id = parameters_.get_moduli_id(level);
  const auto chain_count = parameters_.get_chain_count(moduli_id);
  const auto q = get_q(moduli_id);
  const auto deviation = deviation_[level - 1];
  auto scalar = new int64_t[chain_count];

  scale_enter_modulo(scalar, value, scale_, deviation, r_, q, chain_count);

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    multiplier->multiplier_.push_back(scalar[chain_index]);
  }

  delete[] scalar;

  return multiplier;
}

Multiplier *CKKSPrecomputed::make_mult_multiplier(int64_t value,
                                                  int moduli_id) {
  auto multiplier = new Multiplier();

  const auto chain_count = parameters_.get_chain_count(moduli_id);
  const auto q = get_q(moduli_id);

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    multiplier->multiplier_.push_back(
        modulus_multiply(value, r_, q[chain_index]));
  }

  return multiplier;
}

}
