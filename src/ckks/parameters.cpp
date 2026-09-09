#include <algorithm>
#include <cmath>

#include "arithmetic/prime.h"
#include "ckks/parameters.h"

namespace desilo::fhe {

CKKSParameters::CKKSParameters(const CKKSConfig &config)
    : config_(config), coeff_count_(int(1) << config.log_coeff_count_),
      small_prime_count_(config.get_small_prime_count()) {
  if (small_prime_count_ < 2) {
    throw std::invalid_argument("CKKS Parameters: unsupported config.");
  }

  int small_prime_bit_length = get_small_prime_bit_length();
  int large_prime_count = get_large_prime_count();
  int coeff_count = get_coeff_count();

  std::vector<uint64_t> small_primes, large_primes;

  if (!(small_prime_bit_length == 40 || small_prime_bit_length == 50 ||
        small_prime_bit_length == 54)) {
    throw std::invalid_argument("CKKS Parameters: unsupported config.");
  }

  if (small_prime_bit_length == 54) {
    small_primes = get_bootstrap_primes(coeff_count_, small_prime_count_);
  } else {
    small_primes = get_small_primes(coeff_count_, small_prime_count_);
  }

  large_primes = get_large_primes(coeff_count_, large_prime_count);

  if (small_primes.size() != small_prime_count_) {
    throw std::invalid_argument("CKKS Parameters: unsupported config.");
  }

  if (large_primes.size() != large_prime_count) {
    throw std::invalid_argument("CKKS Parameters: unsupported config.");
  }

  q_.swap(small_primes);

  for (auto prime : large_primes) {
    q_.push_back(prime);
  }

  if (get_use_one_more_level()) {
    q_.insert(q_.begin(), large_primes[1]);
  }

  auto scale_bit_length = get_scale_bit_length();
  scale_ = std::pow(2, scale_bit_length);

  int chain_count = q_.size() - get_special_prime_count();

  int moduli_id_per_level = 1;
  auto chain_count_per_level = 1;
  double scale = get_scale();
  full_level_ = chain_count;
  full_level_ -= 2;

  int chain_index = 0;
  int moduli_id = 0;
  for (int level = full_level_; level >= -1; level--) {
    chain_counts_[moduli_id] = chain_count;

    moduli_ids_[level] = moduli_id;
    not_rescaled_levels_[moduli_id] = level;
    moduli_types_[moduli_id] = ModuliType::LEVEL;

    if (level == -1) {
      break;
    }

    for (int rescale_index = 1; rescale_index <= moduli_id_per_level;
         rescale_index++) {
      auto next_moduli_id = moduli_id + rescale_index;
      rescaled_levels_[next_moduli_id] = level;
      next_moduli_ids_at_rescale_[next_moduli_id - 1] = next_moduli_id;
      can_rescale_from_.insert(next_moduli_id - 1);
      if (rescale_index > 1) {
        moduli_types_[next_moduli_id - 1] = ModuliType::IN_RESCALE;
      }
    }

    if (level == full_level_ ||
        (get_use_one_more_level() && level == full_level_ - 1)) {
      deviations_.push_back(1.0);
    } else if (level >= 0) {
      long double level_q_product =
          static_cast<long double>(q_[chain_index - 1]);
      const auto alpha = std::pow(scale / level_q_product, 2);
      const auto deviation = std::pow(deviations_.back(), 2) * alpha;
      deviations_.push_back(deviation);
    }

    chain_count -= chain_count_per_level;
    chain_index += chain_count_per_level;
    moduli_id += moduli_id_per_level;
  }

  std::reverse(deviations_.begin(), deviations_.end());
}

int CKKSParameters::get_log_coeff_count() const {
  return config_.log_coeff_count_;
}

int CKKSParameters::get_coeff_count() const { return coeff_count_; }

int CKKSParameters::get_special_prime_count() const {
  return config_.special_prime_count_;
}

SchemePreset CKKSParameters::get_scheme_preset() const {
  return config_.scheme_preset_;
}
EngineProcessor CKKSParameters::get_processor() const {
  return config_.processor_;
}

int CKKSParameters::get_stream_count() const { return config_.stream_count_; }

int CKKSParameters::get_thread_count() const { return config_.thread_count_; }

int CKKSParameters::get_scale_bit_length() const {
  return scheme_preset::get_scale_bit_length(get_scheme_preset());
}

double CKKSParameters::get_scale() const { return scale_; }

int CKKSParameters::get_small_prime_bit_length() const {
  return scheme_preset::get_small_prime_bit_length(get_scheme_preset());
}

bool CKKSParameters::get_use_bootstrap() const {
  return scheme_preset::get_use_bootstrap(get_scheme_preset());
}

bool CKKSParameters::get_use_one_more_level() const {
  return scheme_preset::get_use_one_more_level(get_scheme_preset());
}

bool CKKSParameters::get_use_engine_test() const {
  return scheme_preset::get_use_engine_test(get_scheme_preset());
}

int CKKSParameters::get_small_prime_count() const { return small_prime_count_; }

int CKKSParameters::get_large_prime_count() const {
  return config_.special_prime_count_ + 1;
}

int CKKSParameters::get_chain_count() const {
  int moduli_id = 0;
  bool include_special = false;
  return get_chain_count(moduli_id, include_special);
}

int CKKSParameters::get_prime_count() const {
  int moduli_id = 0;
  bool include_special = true;
  return get_chain_count(moduli_id, include_special);
}

int CKKSParameters::get_max_level() const {
  auto max_level = config_.max_level_;

  return max_level == -1 ? get_full_level() : max_level;
}

int CKKSParameters::get_max_key_switching_level() const {
  auto full_level = get_full_level();
  auto max_level = get_max_level();

  if (get_use_one_more_level() && max_level == full_level) {
    return full_level - 1;
  }

  return max_level;
}

int CKKSParameters::get_full_level() const { return full_level_; }

std::vector<uint64_t> CKKSParameters::get_moduli(int moduli_id) const {
  auto chain_offset = get_chain_offset(0, moduli_id);
  auto flexible_chain_scale_bit = get_flexible_chain_scale_bit(moduli_id);
  std::vector<uint64_t> moduli;

  if (flexible_chain_scale_bit > 0) {
    moduli.push_back(UINT64_C(1) << flexible_chain_scale_bit);
  }

  auto moduli_type = get_moduli_type(moduli_id);
  if (moduli_type == ModuliType::NTT || moduli_type == ModuliType::KEY_NTT) {
    auto ntt_flexible_chain_count = get_ntt_flexible_chain_count(moduli_id);

    moduli.insert(moduli.end(), q_.begin(),
                  q_.begin() + ntt_flexible_chain_count);
    chain_offset += ntt_flexible_chain_count;
  }

  moduli.insert(moduli.end(), q_.begin() + chain_offset, q_.end());
  return moduli;
}

std::vector<double> CKKSParameters::get_deviations() const {
  std::vector<double> deviations;
  for (auto deviation : deviations_) {
    deviations.push_back(static_cast<double>(deviation));
  }
  return deviations;
}

uint64_t CKKSParameters::get_base_prime() const {
  int base_prime_index = small_prime_count_;

  if (get_use_one_more_level()) {
    base_prime_index += 1;
  }

  return q_[base_prime_index];
}

int CKKSParameters::get_moduli_id(int level) const {
  return moduli_ids_.at(level);
}

int CKKSParameters::get_level(int moduli_id, bool rescaled) const {
  auto level_moduli_id = get_level_moduli_id(moduli_id);
  return rescaled ? rescaled_levels_.at(level_moduli_id)
                  : not_rescaled_levels_.at(level_moduli_id);
}

int CKKSParameters::get_chain_count(int moduli_id, bool include_special) const {
  auto chain_count = chain_counts_.at(moduli_id);

  if (include_special) {
    chain_count += get_special_prime_count();
  }

  return chain_count;
}

int CKKSParameters::get_log_slot_count() const {
  auto log_slot_count = config_.log_slot_count_;
  return log_slot_count == -1 ? config_.log_coeff_count_ - 1 : log_slot_count;
}

int CKKSParameters::get_slot_count() const {
  return int(1) << get_log_slot_count();
}

int CKKSParameters::get_log_codec_coeff_count() const {
  return get_log_slot_count() + 1;
}

int CKKSParameters::get_codec_coeff_count() const {
  return get_slot_count() << 1;
}

bool CKKSParameters::has_flexible_chain(int moduli_id) const {
  return get_flexible_chain_scale_bit(moduli_id) > 0;
}

int CKKSParameters::get_flexible_chain_scale_bit(int moduli_id) const {
  return 0;
}

int CKKSParameters::get_next_moduli_id_at_rescale(int moduli_id) const {
  return next_moduli_ids_at_rescale_.at(moduli_id);
}

bool CKKSParameters::get_is_prime_removed_at_rescale(int moduli_id) const {
  return false;
}

int CKKSParameters::get_flexible_chain_change_at_rescale(int moduli_id) const {
  return 0;
}

bool CKKSParameters::can_rescale_from(int moduli_id) const {
  return can_rescale_from_.contains(moduli_id);
}

std::vector<int> CKKSParameters::get_rescale_moduli_ids(int moduli_id) const {
  return {};
}

int CKKSParameters::get_chain_offset(int from_moduli_id,
                                     int to_moduli_id) const {
  return get_chain_count(from_moduli_id) - get_chain_count(to_moduli_id);
}

ModuliType CKKSParameters::get_moduli_type(int moduli_id) const {
  return moduli_types_.at(moduli_id);
}

int CKKSParameters::get_level_moduli_id(int moduli_id) const {
  return level_moduli_ids_.contains(moduli_id) ? level_moduli_ids_.at(moduli_id)
                                               : moduli_id;
}

int CKKSParameters::get_ntt_moduli_id(int moduli_id) const {
  return ntt_moduli_ids_.contains(moduli_id) ? ntt_moduli_ids_.at(moduli_id)
                                             : moduli_id;
}

int CKKSParameters::get_intt_moduli_id(int moduli_id) const {
  return intt_moduli_ids_.contains(moduli_id) ? intt_moduli_ids_.at(moduli_id)
                                              : moduli_id;
}

int CKKSParameters::get_key_moduli_id(int moduli_id) const {
  return key_moduli_ids_.contains(moduli_id) ? key_moduli_ids_.at(moduli_id)
                                             : moduli_id;
}

int CKKSParameters::get_ntt_flexible_chain_count(int moduli_id) const {
  return ntt_flexible_chain_counts_.at(moduli_id);
}

int CKKSParameters::get_partition_count_(int moduli_id) const {

  const int intt_moduli_id = get_intt_moduli_id(moduli_id);
  const int chain_count = get_chain_count(intt_moduli_id);
  const int special_prime_count = config_.special_prime_count_;

  return (chain_count + special_prime_count - 1) / special_prime_count;
}

std::vector<Partition> CKKSParameters::get_partitions(int ciphertext_moduli_id,
                                                      int key_moduli_id) const {
  int intt_moduli_id = get_intt_moduli_id(ciphertext_moduli_id);
  int partition_count = get_partition_count_(ciphertext_moduli_id);
  int partition_index = get_partition_count_(key_moduli_id) - partition_count;

  const int special_prime_count = get_special_prime_count();
  const int chain_count = get_chain_count(intt_moduli_id);

  std::vector<Partition> partitions;
  auto offset = 1;

  for (int start = chain_count - partition_count * special_prime_count;
       start < chain_count; start += special_prime_count, partition_index++) {
    std::vector<int> indices;
    int stop = std::min(chain_count, start + special_prime_count);
    for (int index = std::max(0, start); index < stop; index++) {
      int adjusted_index = index;
      indices.push_back(adjusted_index);
    }

    partitions.push_back(
        Partition(indices, ciphertext_moduli_id, partition_index));
  }

  return partitions;
}

std::ostream &operator<<(std::ostream &ostream,
                         const CKKSParameters &parameters) {
  return ostream << "CKKSConfig(log_coeff_count: "
                 << parameters.get_log_coeff_count() << " special_prime_count: "
                 << parameters.get_special_prime_count()
                 << " small_prime_bit_length: "
                 << parameters.get_small_prime_bit_length()
                 << " bootstrap: " << parameters.get_use_bootstrap()
                 << " one_more_level: " << parameters.get_use_one_more_level()
                 << ")";
}

}
