#include <cstdint>
#include <vector>

#include "arithmetic/arithmetic.h"
#include "arithmetic/big_int.h"
#include "arithmetic/type.h"

#pragma once

namespace desilo::fhe {

struct DecodeParameters {
  DecodeParameters(const uint64_t *q, const uint64_t *k, const int64_t r,
                   int chain_count);

  BigInt q_product_;
  BigInt q_product_half_;
  std::vector<BigInt> rns_reverser_;

  uint64_t r_minus_k_product_;
};

}
