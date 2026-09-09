#include <complex>
#include <cstdint>
#include <map>
#include <tuple>
#include <vector>

#include "ckks/config.h"
#include "ckks/parameters.h"
#include "operation/scalar.h"
#include "parameter/decode.h"
#include "parameter/multiplier.h"
#include "parameter/partition.h"
#include "parameter/permutation.h"

#pragma once

namespace desilo::fhe {

std::vector<int> get_backward_paint(int log_coeff_count);

class CKKSPrecomputed {
public:
  CKKSPrecomputed(const CKKSConfig &config);

  const CKKSParameters parameters_;

  const int log_coeff_count_;
  const int coeff_count_;
  const int log_slot_count_;
  const int slot_count_;

  const int log_codec_coeff_count_;
  const int codec_coeff_count_;

  const int buffer_bit_length_ = 62;
  const int scale_bit_length_;

  const int chain_count_;

  const int prime_count_;
  const int special_prime_count_;

  const bool one_more_level_;
  const bool engine_test_;

  const double scale_;
  const int64_t r_;

  std::vector<uint64_t> pre_permutation_;
  std::vector<uint64_t> post_permutation_;
  std::vector<std::complex<double>> fft_twiddle_factor_;
  std::vector<std::complex<double>> ifft_twiddle_factor_;

  const std::vector<double> deviation_;

  const uint64_t *get_pre_permutation() const;
  const uint64_t *get_post_permutation() const;
  const uint64_t *get_q(int moduli_id, int chain_start = 0) const;
  const uint64_t *get_k(int moduli_id, int chain_start = 0) const;
  const uint64_t *get_q_double(int moduli_id, int chain_start = 0) const;
  const uint64_t *get_q_half(int moduli_id, int chain_start = 0) const;

  const int64_t *get_r_squared(int moduli_id, int chain_start = 0) const;
  const int64_t *get_coeff_count_inverse(int moduli_id,
                                         int chain_start = 0) const;
  const int64_t *get_root(int moduli_id, int chain_start = 0) const;
  const int64_t *get_root_inverse(int moduli_id, int chain_start = 0) const;

  const int64_t *get_p_product_mult_r(int moduli_id) const;
  std::vector<const int64_t *> get_p_inverse_mult_r(int moduli_id) const;
  const int64_t *get_rescale_scale(int moduli_id) const;
  long double get_rescaled_scale(long double scale, int moduli_id) const;
  long double get_ckks_scale(int level) const;
  double get_scale_before_tile(int level) const;
  int64_t get_log_scale_after_tile(int level) const;
  const int64_t *get_r_mult_scale_after_tile(int level) const;

  CKKSPartitionParameters
  make_partition_parameters(const Partition &partition) const;

  PermutationParameters *
  make_bit_reversal_permutation_parameters(int size) const;
  std::tuple<PermutationParameters *, PermutationParameters *>
  make_permutation_parameters(int delta) const;
  PermutationParameters *make_ntt_permutation_parameters(int delta) const;

  Multiplier *make_level_down_multiplier_after_rescale(int source_level,
                                                       int destination_level);
  Multiplier *make_level_down_multiplier(int source_level,
                                         int destination_level);

  int to_normalized_delta(int delta) const;

  DecodeParameters *make_decode_parameters(int chain_count,
                                           int moduli_id = 0) const;

  Multiplier *make_add_multiplier(double value, int level);
  Multiplier *make_mult_multiplier(double value, int level);
  Multiplier *make_mult_multiplier(int64_t value, int moduli_id);

#ifdef DESILO_FHE_DEBUG
  void print() const;
#endif

private:
  std::vector<uint64_t> q_;
  std::vector<uint64_t> k_;
  std::vector<uint64_t> q_double_;
  std::vector<uint64_t> q_half_;

  std::vector<int64_t> r_squared_;
  std::vector<int64_t> coeff_count_inverse_;
  std::vector<int64_t> root_;
  std::vector<int64_t> root_inverse_;

  std::vector<int64_t> p_product_mult_r_;

  std::vector<std::vector<int64_t>> p_inverse_mult_r_;

  std::vector<std::vector<int64_t>> rescale_scale_;

  std::vector<long double> ckks_scale_;

  std::vector<double> scale_before_tile_;
  std::vector<int64_t> log_scale_after_tile_;
  std::vector<std::vector<int64_t>> r_mult_scale_after_tile_;
};

}
