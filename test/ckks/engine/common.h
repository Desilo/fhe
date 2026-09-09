#pragma once

#define PROCESS_TEST testing::Values(1, 2)

#include "ckks/engine.h"

inline void set_process_type(desilo::fhe::CKKSConfig &config,
                             int process_type) {
  if (process_type == 2) {
    config.processor_ = desilo::fhe::EngineProcessor::CPU_PARALLEL;
    config.thread_count_ = 4;
  }
}

inline desilo::fhe::CKKSConfig
update_process_type(desilo::fhe::CKKSConfig config, int process_type) {
  set_process_type(config, process_type);
  return config;
}

#define ENGINE()                                                               \
  ({                                                                           \
    const auto process_type = GetParam();                                      \
    auto config = test_configs["Sand1"];                                       \
    desilo::fhe::CKKSEngine(update_process_type(config, process_type));        \
  })
