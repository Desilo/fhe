#include "data/bootstrap.h"

namespace desilo::fhe {

SmallBootstrapKey::SmallBootstrapKey(KeySwitchingKey *to_sparse,
                                     KeySwitchingKey *to_dense)
    : to_sparse_(to_sparse), to_dense_(to_dense) {}

SmallBootstrapKey::~SmallBootstrapKey() {
  delete to_sparse_;
  delete to_dense_;
}

size_t SmallBootstrapKey::nbytes() const {
  auto size = sizeof(SmallBootstrapKey);
  size += to_sparse_->nbytes();
  size += to_dense_->nbytes();

  return size;
}

BootstrapKey::BootstrapKey(
    int stage_count, int inner_loop_shift,
    std::vector<std::pair<FixedRotationKey *, PermutationParameters *>>
        &rotation_contexts,
    std::vector<PlainMatrix *> &coeff_to_slot_stages,
    std::vector<PlainMatrix *> &slot_to_coeff_stages,
    SmallBootstrapKey *small_bootstrap_key)
    : stage_count_(stage_count), inner_loop_shift_(inner_loop_shift),
      coeff_to_slot_stages_(std::move(coeff_to_slot_stages)),
      slot_to_coeff_stages_(std::move(slot_to_coeff_stages)),
      small_bootstrap_key_(small_bootstrap_key) {
  for (auto &[fixed_rotation_key, ntt_permutation_parameters] :
       rotation_contexts) {
    auto delta = fixed_rotation_key->delta_;
    rotation_contexts_[delta] =
        std::make_pair(fixed_rotation_key, ntt_permutation_parameters);
  }
}

BootstrapKey::~BootstrapKey() {
  for (const auto &[delta, rotation_context] : rotation_contexts_) {
    const auto &[fixed_rotation_key, ntt_permutation_parameters] =
        rotation_context;
    delete fixed_rotation_key;
    delete ntt_permutation_parameters;
  }

  for (const auto stage : coeff_to_slot_stages_) {
    delete stage;
  }

  for (const auto stage : slot_to_coeff_stages_) {
    delete stage;
  }

  delete small_bootstrap_key_;
}

size_t BootstrapKey::nbytes() const {
  auto size = sizeof(BootstrapKey);
  for (const auto &rotation_context : rotation_contexts_) {
    size += sizeof(rotation_context);
    size += rotation_context.second.first->nbytes();
    size += rotation_context.second.second->nbytes();
  }
  for (const auto bootstrap_stage : coeff_to_slot_stages_) {
    size += sizeof(bootstrap_stage) + bootstrap_stage->nbytes();
  }
  for (const auto bootstrap_stage : slot_to_coeff_stages_) {
    size += sizeof(bootstrap_stage) + bootstrap_stage->nbytes();
  }
  size += small_bootstrap_key_->nbytes();

  return size;
}

}
