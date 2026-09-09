#include <string>
#include <vector>

#include "engine/processor.h"
#include "engine/scheme_preset.h"

#pragma once

namespace desilo::fhe {

struct CKKSConfig {
  int log_coeff_count_ = 14;
  int log_slot_count_ = -1;
  int special_prime_count_ = 1;
  int max_level_ = -1;
  SchemePreset scheme_preset_ = SchemePreset::CKKS_40_60_DEFAULT;

  EngineProcessor processor_ = EngineProcessor::CPU;
  int stream_count_ = 1;
  int thread_count_ = 0;

  void validate() const;

  int get_small_prime_count() const;
  int get_max_log_coeff_count() const;
  int get_min_log_coeff_count() const;

  static CKKSConfig from_tier(const std::string &tier_name);
  static CKKSConfig from_max_level(int max_level);
  static CKKSConfig from_slot_count_and_max_level(int slot_count,
                                                  int max_level);
  static CKKSConfig for_bootstrap();
  static CKKSConfig for_sparse_bootstrap(int slot_count);
};

}
