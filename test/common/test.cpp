#include "common/test.h"

std::map<std::string, std::tuple<int, int, bool>> tier_parameters = {
    {"Iron", std::make_tuple(13, 1, false)},
    {"Bronze", std::make_tuple(14, 1, false)},
    {"Silver", std::make_tuple(15, 2, false)},
    {"Gold", std::make_tuple(16, 4, false)},
    {"GoldBootstrap", std::make_tuple(16, 4, true)},
    {"Platinum", std::make_tuple(17, 6, false)}};

desilo::fhe::CKKSConfig to_sparse(desilo::fhe::CKKSConfig config,
                                  int log_slot_count) {
  config.log_slot_count_ = log_slot_count;

  return config;
}

std::map<std::string, desilo::fhe::CKKSConfig> tier_configs = {
    {"Iron", desilo::fhe::CKKSConfig::from_tier("iron")},
    {"IronSparse", to_sparse(desilo::fhe::CKKSConfig::from_tier("iron"), 10)},
    {"Bronze", desilo::fhe::CKKSConfig::from_tier("bronze")},
    {"Silver", desilo::fhe::CKKSConfig::from_tier("silver")},
    {"Gold", desilo::fhe::CKKSConfig::from_tier("gold")},
    {"Platinum", desilo::fhe::CKKSConfig::from_tier("platinum")},
    {"GoldBootstrap", desilo::fhe::CKKSConfig::for_bootstrap()},
};

desilo::fhe::CKKSConfig
to_custom_config(std::string tier, int special_prime_count, int max_level) {
  auto config = desilo::fhe::CKKSConfig::from_tier(tier);
  config.scheme_preset_ =
      desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST;
  config.special_prime_count_ = special_prime_count;
  config.max_level_ = max_level;
  return config;
}

std::map<std::string, desilo::fhe::CKKSConfig> test_configs = {
    {"Sand1", to_custom_config("sand", 1, 7)},

    {"Pebble1Sparse", to_sparse(to_custom_config("pebble", 1, 7), 1)},
    {"Sand1Level2", to_custom_config("sand", 1, 2)},
    {"Sand2", to_custom_config("sand", 2, 17)},

    {"Sand4", to_custom_config("sand", 4, 17)},
};

std::map<int, std::tuple<bool, bool>> rescale_flags = {{1, {false, false}},
                                                       {2, {true, false}},
                                                       {3, {false, true}},
                                                       {4, {true, true}}};
