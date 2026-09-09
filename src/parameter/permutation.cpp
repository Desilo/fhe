#include "parameter/permutation.h"

namespace desilo::fhe {

PermutationParameters::PermutationParameters(const PermutationParameters &other)
    : values_(other.values_) {}

const int32_t *PermutationParameters::get() const { return values_.data(); }

size_t PermutationParameters::nbytes() const {
  return sizeof(PermutationParameters) +

         sizeof(*values_.data()) * values_.capacity();
}

}
