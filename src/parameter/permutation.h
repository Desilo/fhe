#include <cstddef>
#include <cstdint>
#include <tuple>
#include <vector>

#pragma once

namespace desilo::fhe {

struct PermutationParameters {
  PermutationParameters(){};
  PermutationParameters(const PermutationParameters &other);

  std::vector<int32_t> values_;

  const int32_t *get() const;

  size_t nbytes() const;
};

}
