#include <map>
#include <vector>

#include "data/bytearray.h"
#include "data/data.h"
#include "data/plain_matrix.h"
#include "parameter/permutation.h"

#pragma once

namespace desilo::fhe {

class SmallBootstrapKey {
public:
  SmallBootstrapKey(KeySwitchingKey *to_sparse, KeySwitchingKey *to_dense);
  ~SmallBootstrapKey();

  size_t nbytes() const;

  KeySwitchingKey *to_sparse_;
  KeySwitchingKey *to_dense_;
};

class BootstrapKey {
public:
  BootstrapKey(
      int stage_count, int inner_loop_shift,
      std::vector<std::pair<FixedRotationKey *, PermutationParameters *>>
          &rotation_contexts,
      std::vector<PlainMatrix *> &coeff_to_slot_stages,
      std::vector<PlainMatrix *> &slot_to_coeff_stages,
      SmallBootstrapKey *small_bootstrap_key);
  ~BootstrapKey();

  size_t nbytes() const;

  const int stage_count_;
  const int inner_loop_shift_;
  std::map<int, std::pair<FixedRotationKey *, PermutationParameters *>>
      rotation_contexts_;
  std::vector<PlainMatrix *> coeff_to_slot_stages_;
  std::vector<PlainMatrix *> slot_to_coeff_stages_;
  SmallBootstrapKey *small_bootstrap_key_;
};

}
