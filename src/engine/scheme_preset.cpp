#include <map>
#include <tuple>

#include "engine/scheme_preset.h"

namespace desilo::fhe {

std::map<SchemePreset, std::tuple<int, int, int, bool, bool, bool>>
    scheme_preset_parameters = {

        {SchemePreset::CKKS_40_60_DEFAULT, {40, 40, 60, false, true, false}},
        {SchemePreset::CKKS_54_60_BOOTSTRAP, {54, 54, 60, true, true, false}},
        {SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST,
         {40, 40, 60, false, true, true}},
        {SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST,
         {54, 54, 60, true, true, true}}};

namespace scheme_preset {

int get_scale_bit_length(const SchemePreset scheme_preset) {
  return std::get<0>(scheme_preset_parameters[scheme_preset]);
}

int get_small_prime_bit_length(const SchemePreset scheme_preset) {
  return std::get<1>(scheme_preset_parameters[scheme_preset]);
}

int get_large_prime_bit_length(const SchemePreset scheme_preset) {
  return std::get<2>(scheme_preset_parameters[scheme_preset]);
}

bool get_use_bootstrap(const SchemePreset scheme_preset) {
  return std::get<3>(scheme_preset_parameters[scheme_preset]);
}

bool get_use_one_more_level(const SchemePreset scheme_preset) {
  return std::get<4>(scheme_preset_parameters[scheme_preset]);
}

bool get_use_engine_test(const SchemePreset scheme_preset) {
  return std::get<5>(scheme_preset_parameters[scheme_preset]);
}

}

}
