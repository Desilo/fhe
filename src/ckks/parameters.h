#include <map>
#include <ostream>
#include <set>
#include <vector>

#include "ckks/config.h"
#include "engine/moduli_type.h"
#include "engine/processor.h"
#include "engine/scheme_preset.h"
#include "parameter/partition.h"

#pragma once

namespace desilo::fhe {

struct CKKSParameters {
  CKKSParameters(const CKKSConfig &config);

  int get_log_coeff_count() const;
  int get_coeff_count() const;
  int get_log_slot_count() const;
  int get_slot_count() const;
  int get_log_codec_coeff_count() const;
  int get_codec_coeff_count() const;
  int get_special_prime_count() const;

  SchemePreset get_scheme_preset() const;
  EngineProcessor get_processor() const;

  int get_stream_count() const;
  int get_thread_count() const;

  int get_scale_bit_length() const;
  double get_scale() const;
  int get_small_prime_bit_length() const;
  bool get_use_bootstrap() const;
  bool get_use_one_more_level() const;
  bool get_use_engine_test() const;
  int get_small_prime_count() const;
  int get_large_prime_count() const;
  int get_chain_count() const;
  int get_prime_count() const;
  int get_max_level() const;
  int get_max_key_switching_level() const;
  int get_full_level() const;

  std::vector<uint64_t> get_moduli(int moduli_id) const;
  std::vector<double> get_deviations() const;
  uint64_t get_base_prime() const;

  int get_moduli_id(int level) const;
  int get_level(int moduli_id, bool rescaled = false) const;
  int get_chain_count(int moduli_id, bool include_special = false) const;
  bool has_flexible_chain(int moduli_id) const;
  int get_flexible_chain_scale_bit(int moduli_id) const;
  int get_chain_offset(int from_moduli_id, int to_moduli_id) const;
  ModuliType get_moduli_type(int moduli_id) const;
  int get_level_moduli_id(int moduli_id) const;
  int get_ntt_moduli_id(int moduli_id) const;
  int get_intt_moduli_id(int moduli_id) const;
  int get_key_moduli_id(int moduli_id) const;
  int get_ntt_flexible_chain_count(int moduli_id) const;

  int get_next_moduli_id_at_rescale(int modulid_id) const;
  bool get_is_prime_removed_at_rescale(int moduli_id) const;
  int get_flexible_chain_change_at_rescale(int moduli_id) const;
  std::vector<int> get_rescale_moduli_ids(int moduli_id) const;
  bool can_rescale_from(int moduli_id) const;

  std::vector<Partition> get_partitions(int ciphertext_moduli_id,
                                        int key_moduli_id) const;

private:
  const CKKSConfig config_;

  const int coeff_count_;
  double scale_;

  int small_prime_count_;
  int full_level_;

  std::vector<uint64_t> q_;
  std::vector<long double> deviations_;

  std::map<int, int> moduli_ids_;

  std::map<int, int> next_moduli_ids_at_rescale_;

  std::map<int, int> not_rescaled_levels_;

  std::map<int, int> rescaled_levels_;

  std::map<int, int> chain_counts_;

  std::map<int, int> flexible_chain_scale_bits_;

  std::map<int, bool> is_prime_removed_at_rescale_;

  std::map<int, int> flexible_chain_change_at_rescale_;

  std::map<int, std::vector<int>> rescale_moduli_ids_;

  std::set<int> can_rescale_from_;

  std::map<int, ModuliType> moduli_types_;

  std::map<int, int> level_moduli_ids_;

  std::map<int, int> ntt_moduli_ids_;

  std::map<int, int> key_moduli_ids_;

  std::map<int, int> intt_moduli_ids_;

  std::map<int, int> ntt_flexible_chain_counts_;

  int get_partition_count_(int moduli_id) const;
};

std::ostream &operator<<(std::ostream &ostream, const CKKSParameters &config);

}
