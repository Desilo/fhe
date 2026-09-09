#include <set>

#include "arithmetic/arithmetic.h"
#include "ckks/encode.h"
#include "ckks/engine.h"
#include "util/string_transform.h"

namespace desilo::fhe {

CKKSEngine::CKKSEngine(const CKKSConfig &config)
    : core_(new CKKSCore(config)), parameters_(config) {}

SecretKey *CKKSEngine::create_secret_key(int level) {
  validate_target_level("Create Secret Key", level);

  SecretKey *secret_key = core_->create_secret_key(level);

  return secret_key;
}

SecretKey *CKKSEngine::create_secret_key() {
  return create_secret_key(get_max_level());
}

SecretKey *CKKSEngine::create_secret_key(std::vector<int64_t> &secret,
                                         int level) {
  const auto function_name = "Create Custom Secret Key";
  require_engine_compatibility(function_name, secret);
  validate_target_level(function_name, level);

  auto padded = core_->pad(secret, core_->get_coeff_count());
  SecretKey *secret_key = core_->create_secret_key(padded, level);

  return secret_key;
}

SecretKey *CKKSEngine::create_secret_key(std::vector<int64_t> &secret) {
  return create_secret_key(secret, get_max_level());
}

SecretKey *CKKSEngine::create_sparse_secret_key() {
  const int hamming_weight = 128;

  SecretKey *secret_key =
      core_->create_sparse_secret_key(hamming_weight, get_max_level());

  return secret_key;
}

PublicKey *CKKSEngine::create_public_key(SecretKey *secret_key, int level) {
  const auto function_name = "Create Public Key";
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key}, level);

  auto public_key = core_->create_public_key(secret_key, level);

  return public_key;
}

PublicKey *CKKSEngine::create_public_key(SecretKey *secret_key) {
  return create_public_key(secret_key, get_max_level());
}

RelinearizationKey *
CKKSEngine::create_relinearization_key(SecretKey *secret_key, int level) {
  const auto function_name = "Create Relinearization Key";
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key}, level);
  validate_key_switching_key_level(function_name, level);

  auto relinearization_key =
      core_->create_relinearization_key(secret_key, level);

  return relinearization_key;
}

RelinearizationKey *
CKKSEngine::create_relinearization_key(SecretKey *secret_key) {
  return create_relinearization_key(secret_key, get_max_key_switching_level());
}

ConjugationKey *CKKSEngine::create_conjugation_key(SecretKey *secret_key,
                                                   int level) {
  const auto function_name = "Create Conjugation Key";
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key}, level);
  validate_key_switching_key_level(function_name, level);

  auto conjugation_key = core_->create_conjugation_key(secret_key, level);

  return conjugation_key;
}

ConjugationKey *CKKSEngine::create_conjugation_key(SecretKey *secret_key) {
  return create_conjugation_key(secret_key, get_max_key_switching_level());
}

FixedRotationKey *
CKKSEngine::create_fixed_rotation_key(SecretKey *secret_key, int delta,
                                      int level, bool normalize_by_slot_count) {
  const auto function_name = "Create Fixed Rotation Key";
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key}, level);
  validate_key_switching_key_level(function_name, level);

  const int normalized_delta =
      to_normalized_delta(delta, normalize_by_slot_count);

  auto fixed_rotation_key =
      core_->create_fixed_rotation_key(secret_key, level, normalized_delta);

  return fixed_rotation_key;
}

FixedRotationKey *CKKSEngine::create_fixed_rotation_key(SecretKey *secret_key,
                                                        int delta, int level) {
  return create_fixed_rotation_key(secret_key, delta, level, true);
}

FixedRotationKey *CKKSEngine::create_fixed_rotation_key(SecretKey *secret_key,
                                                        int delta) {
  return create_fixed_rotation_key(secret_key, delta,
                                   get_max_key_switching_level());
}
RotationKey *CKKSEngine::create_rotation_key(SecretKey *secret_key, int level) {
  const auto function_name = "Create Rotation Key";
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key}, level);
  validate_key_switching_key_level(function_name, level);

  auto rotation_key = core_->create_rotation_key(secret_key, level);

  return rotation_key;
}

RotationKey *CKKSEngine::create_rotation_key(SecretKey *secret_key) {
  return create_rotation_key(secret_key, get_max_key_switching_level());
}

SmallBootstrapKey *
CKKSEngine::create_small_bootstrap_key(SecretKey *secret_key) {
  const std::string function_name = "Create Small Bootstrap Key";
  require_bootstrap_engine(function_name);
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key},
                        get_max_key_switching_level());

  const int switch_key_to_sparse_level = 0;

  const auto sparse_secret_key = create_sparse_secret_key();

  const auto to_sparse = core_->create_key_switching_key(
      secret_key, sparse_secret_key, switch_key_to_sparse_level);
  const auto to_dense = core_->create_key_switching_key(
      sparse_secret_key, secret_key, get_max_key_switching_level());

  delete sparse_secret_key;

  return new SmallBootstrapKey(to_sparse, to_dense);
}

BootstrapKey *CKKSEngine::create_bootstrap_key(SecretKey *secret_key,
                                               int stage_count,
                                               const std::string &size) {
  const std::string function_name = "Create Bootstrap Key";
  require_bootstrap_engine(function_name);
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key},
                        get_max_key_switching_level());
  int inner_loop_shift = require_bootstrap_key_size(function_name, size);
  require_bootstrap_stage_count(function_name, stage_count, inner_loop_shift);

  auto partial_sum_deltas = make_partial_sum_deltas();
  const auto [coeff_to_slot_stage_level, slot_to_coeff_stage_level] =
      get_bootstrap_stage_levels(stage_count);

  auto coeff_to_slot_stages = make_coeff_to_slot_stages(
      stage_count, inner_loop_shift, coeff_to_slot_stage_level);
  auto slot_to_coeff_stages = make_slot_to_coeff_stages(
      stage_count, inner_loop_shift, slot_to_coeff_stage_level);

  std::set<int> deltas;
  std::vector<std::pair<FixedRotationKey *, PermutationParameters *>>
      rotation_contexts;

#define MAKE_ROTATION_CONTEXT(delta_vector, level, normalize_by_slot_count)    \
  for (auto delta : delta_vector) {                                            \
    if (delta != 0 && !deltas.contains(delta)) {                               \
      rotation_contexts.push_back(                                             \
          std::make_pair(create_fixed_rotation_key(secret_key, delta, level,   \
                                                   normalize_by_slot_count),   \
                         core_->make_ntt_permutation_parameters(delta)));      \
      deltas.insert(delta);                                                    \
    }                                                                          \
  }

  const auto max_level = get_max_key_switching_level();
  MAKE_ROTATION_CONTEXT(partial_sum_deltas, max_level, false);

  for (auto stage : coeff_to_slot_stages) {
    int level = stage->level_;
    MAKE_ROTATION_CONTEXT(stage->inner_loop_deltas_, level, true);
    MAKE_ROTATION_CONTEXT(stage->outer_loop_deltas_, level, true);
  }

  for (auto stage : slot_to_coeff_stages) {
    int level = stage->level_;
    MAKE_ROTATION_CONTEXT(stage->inner_loop_deltas_, level, true);
    MAKE_ROTATION_CONTEXT(stage->outer_loop_deltas_, level, true);
  }

  const auto small_bootstrap_key = create_small_bootstrap_key(secret_key);

  return new BootstrapKey(stage_count, inner_loop_shift, rotation_contexts,
                          coeff_to_slot_stages, slot_to_coeff_stages,
                          small_bootstrap_key);
}

int CKKSEngine::get_max_level() const { return parameters_.get_max_level(); };

int CKKSEngine::get_max_key_switching_level() const {
  return parameters_.get_max_key_switching_level();
};

std::string CKKSEngine::get_mode() const { return "cpu"; }

int CKKSEngine::to_normalized_delta(int delta, bool normalize_by_slot_count) {
  auto coeff_count_half = get_coeff_count() / 2;
  int normalization_value = coeff_count_half;
  if (normalize_by_slot_count) {
    normalization_value = get_slot_count();
  }

  return positive_modulo(delta, normalization_value);
}

void CKKSEngine::clear_temp_data() {
  for (auto data : temp_data_) {
    delete data;
  }
  temp_data_.clear();

  for (auto text : temp_text_) {
    delete text;
  }
  temp_text_.clear();
}

}
