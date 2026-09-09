#include <cstdint>
#include <vector>

#pragma once

namespace desilo::fhe {

struct Multiplier {
  Multiplier(){};
  Multiplier(Multiplier &&other) noexcept;

  std::vector<int64_t> multiplier_;

  int64_t *get();
};

}
