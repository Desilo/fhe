#include <cstdint>

#pragma once

namespace desilo::fhe {

enum class SchemePreset : uint8_t {
  NONE = 0,
  CKKS_40_60_DEFAULT = 1,
  CKKS_54_60_BOOTSTRAP = 2,
  CKKS_40_60_DEFAULT_ENGINE_TEST = 3,
  CKKS_54_60_BOOTSTRAP_ENGINE_TEST = 4,
};

namespace scheme_preset {

int get_scale_bit_length(const SchemePreset scheme_preset);
int get_small_prime_bit_length(const SchemePreset scheme_preset);
int get_large_prime_bit_length(const SchemePreset scheme_preset);
bool get_use_bootstrap(const SchemePreset scheme_preset);
bool get_use_one_more_level(const SchemePreset scheme_preset);
bool get_use_engine_test(const SchemePreset scheme_preset);

}

}
