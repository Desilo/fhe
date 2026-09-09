#include <cmath>
#include <stdexcept>

#include "ckks/config.h"
#include "util/string_transform.h"

namespace desilo::fhe {

void CKKSConfig::validate() const {
  if (log_coeff_count_ < get_min_log_coeff_count()) {
    throw std::invalid_argument(
        "The given log coefficient count is too small.");
  }

  if (log_coeff_count_ > get_max_log_coeff_count()) {
    throw std::invalid_argument(
        "The given log coefficient count is too large.");
  }

  if (log_slot_count_ >= log_coeff_count_) {
    throw std::invalid_argument("The given log slot count is too large.");
  }

  if (log_slot_count_ < -1) {
    throw std::invalid_argument("The given log slot count is too small.");
  }

  if (special_prime_count_ < 0) {
    throw std::invalid_argument("The given special prime count is too small.");
  }

  if (special_prime_count_ > 16) {
    throw std::invalid_argument("The given special prime count is too large.");
  }

  if (max_level_ < -1) {
    throw std::invalid_argument("The given max level is too small.");
  }

  if (max_level_ > 77) {
    throw std::invalid_argument("The given max level is too large.");
  }

  if (thread_count_ > 1 && processor_ != EngineProcessor::CPU_PARALLEL) {
    throw std::invalid_argument("The given thread count is too large.");
  }
}

int CKKSConfig::get_small_prime_count() const {
  int maximum_q_bits;
  switch (log_coeff_count_) {
#ifdef DESILO_FHE_GOOGLE_TEST
  case 3:
  case 4:

    maximum_q_bits = 1000;
    break;
#endif
  case 13:
    maximum_q_bits = 214;
    break;
  case 14:
    maximum_q_bits = 430;
    break;
  case 15:
    maximum_q_bits = 868;
    break;
  case 16:
    maximum_q_bits = 1747;
    break;
  case 17:
    maximum_q_bits = 3523;
    break;
  default:
    throw std::invalid_argument("CKKS Parameters: unsupported config.");
  }

  int small_prime_bit_length =
      scheme_preset::get_small_prime_bit_length(scheme_preset_);
  maximum_q_bits -= 60 * (1 + special_prime_count_);
  auto small_prime_count = maximum_q_bits / small_prime_bit_length;

  return small_prime_count;
}

int CKKSConfig::get_max_log_coeff_count() const {
  if (scheme_preset::get_use_engine_test(scheme_preset_)) {
    return 4;
  } else if (scheme_preset::get_use_bootstrap(scheme_preset_)) {
    return 16;
  } else {
    return 17;
  }
}

int CKKSConfig::get_min_log_coeff_count() const {
  if (scheme_preset::get_use_engine_test(scheme_preset_)) {
    return 3;
  } else if (scheme_preset::get_use_bootstrap(scheme_preset_)) {
    return 16;
  } else {
    return 13;
  }
}

CKKSConfig CKKSConfig::from_tier(const std::string &tier_name) {
  const auto normalized_tier_name = to_lowercase(tier_name);
  CKKSConfig config;

#ifdef DESILO_FHE_GOOGLE_TEST
  if (normalized_tier_name == "sand") {
    config.log_coeff_count_ = 3;
    config.special_prime_count_ = 1;
  } else if (normalized_tier_name == "pebble") {
    config.log_coeff_count_ = 4;
    config.special_prime_count_ = 1;
  } else
#endif
      if (normalized_tier_name == "iron") {
    config.log_coeff_count_ = 13;
    config.special_prime_count_ = 1;
  } else if (normalized_tier_name == "bronze") {
    config.log_coeff_count_ = 14;
    config.special_prime_count_ = 1;
  } else if (normalized_tier_name == "silver") {
    config.log_coeff_count_ = 15;
    config.special_prime_count_ = 2;
  } else if (normalized_tier_name == "gold") {
    config.log_coeff_count_ = 16;
    config.special_prime_count_ = 4;
  } else if (normalized_tier_name == "platinum") {
    config.log_coeff_count_ = 17;
    config.special_prime_count_ = 6;
  } else {
    throw std::invalid_argument("Not supported tier name.");
  }

  return config;
}

CKKSConfig CKKSConfig::from_max_level(int max_level) {
  std::string tier;
  if (max_level < 0) {
    throw std::invalid_argument("Not supported max level.");
  } else if (max_level <= 2) {
    tier = "iron";
  } else if (max_level <= 7) {
    tier = "bronze";
  } else if (max_level <= 17) {
    tier = "silver";
  } else if (max_level <= 36) {
    tier = "gold";
  } else if (max_level <= 77) {
    tier = "platinum";
  } else {
    throw std::invalid_argument("Not supported max level.");
  }

  auto config = CKKSConfig::from_tier(tier);
  config.max_level_ = max_level;

  return config;
}

int to_log_slot_count(int slot_count, int log_coeff_count) {
  int log_slot_count = std::ceil(std::log2(slot_count));

  if (log_slot_count <= 0) {
    throw std::invalid_argument("The given slot count is too small.");
  }

  if (log_slot_count >= log_coeff_count) {
    throw std::invalid_argument("The given slot count is too large.");
  }

  return log_slot_count;
}

CKKSConfig CKKSConfig::from_slot_count_and_max_level(int slot_count,
                                                     int max_level) {
  auto config = CKKSConfig::from_max_level(max_level);
  config.log_slot_count_ =
      to_log_slot_count(slot_count, config.log_coeff_count_);

  return config;
}

CKKSConfig CKKSConfig::for_bootstrap() {
  CKKSConfig config = CKKSConfig::from_tier("gold");
  config.scheme_preset_ = SchemePreset::CKKS_54_60_BOOTSTRAP;

  return config;
}

CKKSConfig CKKSConfig::for_sparse_bootstrap(int slot_count) {
  CKKSConfig config = CKKSConfig::for_bootstrap();
  config.log_slot_count_ =
      to_log_slot_count(slot_count, config.log_coeff_count_);

  return config;
}

}
