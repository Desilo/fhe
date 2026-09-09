#include "ckks/engine.h"
#include "data/data.h"
#include "util/string_transform.h"

namespace desilo::fhe {

void CKKSEngine::require_bootstrap_engine(const std::string &function_name) {
  if (!parameters_.get_use_bootstrap()) {
    throw std::runtime_error(
        function_name +
        ": this engine does not support the bootstrap operation.");
  }
}

bool CKKSEngine::is_compatible(const DataInterface *data) {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  return parameters_.get_scheme_preset() == data->scheme_preset() &&
         log_slot_count == data->log_slot_count() &&
         log_coeff_count == data->log_coeff_count() &&
         special_prime_count == data->special_prime_count();
}

bool CKKSEngine::is_key_compatible(const DataInterface *data, const Data *key) {

  if (key->type_ == DataType::KEY_SWITCHING_KEY &&
      parameters_.get_use_one_more_level() && data->moduli_id() == 0 &&
      key->moduli_id_ == 1) {
    return true;
  }

  return data->moduli_id() >= key->moduli_id_;
}

void CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                              const SecretKey *secret_key) {
  if (!is_compatible(secret_key)) {
    throw std::runtime_error(
        function_name +
        ": the input secret key is not compatible with this engine.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const std::vector<SecretKey *> &secret_keys) {
  const int size = secret_keys.size();
  if (size < 1) {
    throw std::runtime_error(function_name +
                             ": the input secret key vector is empty.");
  }

  for (int index = 0; index < size; index++) {
    auto initial_prefix = function_name + ": the";
    auto prefix = get_ordinalized_prefix(initial_prefix, size, index);
    if (!is_compatible(secret_keys[index])) {
      throw std::runtime_error(
          prefix + " input secret key is not compatible with this engine.");
    }
  }
}

void CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                              const PublicKey *public_key) {
  if (!is_compatible(public_key)) {
    throw std::runtime_error(
        function_name +
        ": the input public key is not compatible with this engine.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const FixedRotationKey *fixed_rotation_key) {
  if (!is_compatible(fixed_rotation_key->key_switching_key_)) {
    throw std::runtime_error(
        function_name +
        ": the input fixed rotation key is not compatible with this engine.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const std::vector<FixedRotationKey *> &fixed_rotation_keys,
    const std::initializer_list<Requirement> requirements) {
  const int size = fixed_rotation_keys.size();
  if (size < 1) {
    throw std::runtime_error(function_name +
                             ": the input fixed rotation key vector is empty.");
  }

  const auto first = fixed_rotation_keys[0];
  for (int index = 0; index < size; index++) {
    auto initial_prefix = function_name + ": the";
    auto prefix = get_ordinalized_prefix(initial_prefix, size, index);
    const auto current = fixed_rotation_keys[index];
    if (!is_compatible(current->key_switching_key_)) {
      throw std::runtime_error(
          prefix +
          " input fixed rotation key is not compatible with this engine.");
    }

    for (auto requirement : requirements) {
      switch (requirement) {
      case Requirement::SAME_DELTA:
        if (current->delta_ != first->delta_) {
          throw std::runtime_error(
              function_name +
              ": the delta of the input fixed rotation keys does not match.");
        }
        break;
      default:
        break;
      }
    }
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name, const ConjugationKey *conjugation_key) {
  if (!is_compatible(conjugation_key->key_switching_key_)) {
    throw std::runtime_error(
        function_name +
        ": the input conjugation key is not compatible with this engine.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name, const ConjugationKey *conjugation_key,
    int minimum_level) {
  require_engine_compatibility(function_name, conjugation_key);
  if (conjugation_key->level_ < minimum_level) {
    throw std::runtime_error(
        function_name + ": the level of the input conjugation key is too low.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const std::vector<ConjugationKey *> &conjugation_keys) {
  const int size = conjugation_keys.size();
  if (size < 1) {
    throw std::runtime_error(function_name +
                             ": the input conjugation key vector is empty.");
  }

  const auto first = conjugation_keys[0];
  for (int index = 0; index < size; index++) {
    auto initial_prefix = function_name + ": the";
    auto prefix = get_ordinalized_prefix(initial_prefix, size, index);
    const auto current = conjugation_keys[index];
    if (!is_compatible(current->key_switching_key_)) {
      throw std::runtime_error(
          prefix +
          " input conjugation key is not compatible with this engine.");
    }
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const RelinearizationKey *relinearization_key) {
  if (!is_compatible(relinearization_key->key_switching_key_)) {
    throw std::runtime_error(
        function_name +
        ": the input relinearization key is not compatible with this engine.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const RelinearizationKey *relinearization_key, int minimum_level) {
  require_engine_compatibility(function_name, relinearization_key);
  if (relinearization_key->level_ < minimum_level) {
    throw std::runtime_error(
        function_name +
        ": the level of the input relinearization key is too low.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const std::vector<RelinearizationKey *> &relinearization_keys) {
  const int size = relinearization_keys.size();
  if (size < 1) {
    throw std::runtime_error(
        function_name + ": the input relinearization key vector is empty.");
  }

  const auto first = relinearization_keys[0];
  for (int index = 0; index < size; index++) {
    auto initial_prefix = function_name + ": the";
    auto prefix = get_ordinalized_prefix(initial_prefix, size, index);
    const auto current = relinearization_keys[index];
    if (!is_compatible(current->key_switching_key_)) {
      throw std::runtime_error(
          prefix +
          " input relinearization key is not compatible with this engine.");
    }
  }
}

void CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                              const RotationKey *rotation_key) {
  for (auto fixed_rotation_key : rotation_key->fixed_rotation_keys_) {
    if (!is_compatible(fixed_rotation_key->key_switching_key_)) {
      throw std::runtime_error(
          function_name +
          ": the input rotation key is not compatible with this engine.");
    }
  }
}

void CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                              const RotationKey *rotation_key,
                                              int minimum_level) {
  require_engine_compatibility(function_name, rotation_key);
  if (rotation_key->level_ < minimum_level) {
    throw std::runtime_error(
        function_name + ": the level of the input rotation key is too low.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const std::vector<RotationKey *> &rotation_keys) {
  const int size = rotation_keys.size();
  if (size < 1) {
    throw std::runtime_error(function_name +
                             ": the input rotation key vector is empty.");
  }

  const auto first = rotation_keys[0];
  for (int index = 0; index < size; index++) {
    auto initial_prefix = function_name + ": the";
    auto prefix = get_ordinalized_prefix(initial_prefix, size, index);
    const auto current = rotation_keys[index];
    for (auto fixed_rotation_key : current->fixed_rotation_keys_) {
      if (!is_compatible(fixed_rotation_key->key_switching_key_)) {
        throw std::runtime_error(
            prefix + " input rotation key is not compatible with this engine.");
      }
    }
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const SmallBootstrapKey *small_bootstrap_key) {
  if (!is_compatible(small_bootstrap_key->to_sparse_)) {
    throw std::runtime_error(
        function_name +
        ": the input small bootstrap key is not compatible with this engine.");
  }

  if (!is_compatible(small_bootstrap_key->to_dense_)) {
    throw std::runtime_error(
        function_name +
        ": the input small bootstrap key is not compatible with this engine.");
  }
}

void CKKSEngine::require_engine_compatibility(
    const std::string &function_name, const BootstrapKey *bootstrap_key) {
  for (const auto &[delta, rotation_context] :
       bootstrap_key->rotation_contexts_) {
    const auto &[fixed_rotation_key, ntt_permutation_parameters] =
        rotation_context;
    if (!is_compatible(fixed_rotation_key->key_switching_key_)) {
      throw std::runtime_error(
          function_name +
          ": the input bootstrap key is not compatible with this engine.");
    }
  }

  for (const auto stage : bootstrap_key->coeff_to_slot_stages_) {
    for (const auto &[outer_index, outer_map] : stage->encoded_diagonals_) {
      for (const auto &[inner_index, encoded_diagonal] : outer_map) {
        if (!is_compatible(encoded_diagonal)) {
          throw std::runtime_error(
              function_name +
              ": the input bootstrap key is not compatible with this engine.");
        }
      }
    }
  }

  for (const auto stage : bootstrap_key->slot_to_coeff_stages_) {
    for (const auto &[outer_index, outer_map] : stage->encoded_diagonals_) {
      for (const auto &[inner_index, encoded_diagonal] : outer_map) {
        if (!is_compatible(encoded_diagonal)) {
          throw std::runtime_error(
              function_name +
              ": the input bootstrap key is not compatible with this engine.");
        }
      }
    }
  }

  if (!is_compatible(bootstrap_key->small_bootstrap_key_->to_sparse_)) {
    throw std::runtime_error(
        function_name +
        ": the input bootstrap key is not compatible with this engine.");
  }

  if (!is_compatible(bootstrap_key->small_bootstrap_key_->to_dense_)) {
    throw std::runtime_error(
        function_name +
        ": the input bootstrap key is not compatible with this engine.");
  }
}

template <typename T>
void CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                              const std::vector<T> &input) {
  if (input.size() > core_->get_slot_count()) {
    throw std::runtime_error(function_name +
                             ": the given input is too long to be processed.");
  }
}

template void
CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                         const std::vector<double> &input);
template void CKKSEngine::require_engine_compatibility(
    const std::string &function_name,
    const std::vector<std::complex<double>> &input);

template <>
void CKKSEngine::require_engine_compatibility(
    const std::string &function_name, const std::vector<int64_t> &input) {
  if (input.size() > core_->get_coeff_count()) {
    throw std::runtime_error(function_name +
                             ": the given input is too long to be processed.");
  }
}

template <typename T>
void CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                              const TextInterface *text,
                                              const std::vector<T> &input) {
  if (text->type_name() == "unit ciphertext") {
    if (input.size() > core_->get_slot_count()) {
      throw std::runtime_error(
          function_name + ": the given input is too long to be processed.");
    }
  }

  if (text->type_name() == "ciphertext") {
    if (input.size() <= core_->get_slot_count() * (text->size() - 1)) {
      throw std::runtime_error(
          function_name + ": the given input is too short to be processed.");
    }
    if (input.size() > core_->get_slot_count() * text->size()) {
      throw std::runtime_error(
          function_name + ": the given input is too long to be processed.");
    }
  }
}

template void
CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                         const TextInterface *text,
                                         const std::vector<double> &input);
template void CKKSEngine::require_engine_compatibility(
    const std::string &function_name, const TextInterface *text,
    const std::vector<std::complex<double>> &input);

void CKKSEngine::require_engine_compatibility(const std::string &function_name,
                                              const TextInterface *text,
                                              const int input_size) {
  if (text->type_name() == "ciphertext") {
    if (input_size <= core_->get_slot_count() * (text->size() - 1)) {
      throw std::runtime_error(
          function_name + ": the given input is too short to be processed.");
    }
    if (input_size > core_->get_slot_count() * text->size()) {
      throw std::runtime_error(
          function_name + ": the given input is too long to be processed.");
    }
  }
}

void CKKSEngine::require(
    const std::string &function_name,
    const std::initializer_list<const TextInterface *> texts,
    const std::initializer_list<Requirement> requirements) {
  auto text_index = 0;
  const TextInterface *first_text;
  for (auto text : texts) {
    auto initial_prefix = function_name + ": the";
    auto prefix =
        get_ordinalized_prefix(initial_prefix, texts.size(), text_index);

    std::string type_name = text->type_name();

    if (text_index == 0) {
      first_text = text;
    }
    text_index++;

    prefix += " input " + type_name + " ";

    if (!is_compatible(text)) {
      throw std::runtime_error(prefix + "is not compatible with this engine.");
    }

    for (auto requirement : requirements) {
      switch (requirement) {
      case Requirement::DUO:
        if (text->polynomial_count() != 2) {
          throw std::runtime_error(prefix + "should have 2 polynomials.");
        }
        break;
      case Requirement::TRIO:
        if (text->polynomial_count() != 3) {
          throw std::runtime_error(prefix + "should have 3 polynomials.");
        }
        break;
      case Requirement::NTT:
        if (!is_ntt_form(text->flag())) {
          throw std::runtime_error(prefix + "should be in NTT form.");
        }
        break;
      case Requirement::INTT:
        if (is_ntt_form(text->flag())) {
          throw std::runtime_error(prefix + "should not be in NTT form.");
        }
        break;
      case Requirement::MATCH_NTT:
        if (text_index > 1 &&
            is_ntt_form(text->flag()) != is_ntt_form(first_text->flag())) {
          throw std::runtime_error(function_name +
                                   ": the NTT state of the input " + type_name +
                                   "s does not match.");
        }
        break;
      case Requirement::NOT_RESCALED:
        if (is_rescaled(text->flag())) {
          throw std::runtime_error(prefix + "should not be rescaled.");
        }
        break;
      case Requirement::DUOS_OR_TRIOS: {
        const int polynomial_count = text->polynomial_count();
        if (polynomial_count != 2 && polynomial_count != 3) {
          throw std::runtime_error(prefix +
                                   "should have either 2 or 3 polynomials.");
        }
        if (text_index > 1 &&
            polynomial_count != first_text->polynomial_count()) {
          throw std::runtime_error(function_name +
                                   ": the polynomial count of the input " +
                                   type_name + "s does not match.");
        }
        break;
      }
      case Requirement::LEVEL_ZERO:
        if (text->level() > 0) {
          throw std::runtime_error(prefix + "should be level 0.");
        }
        break;
      case Requirement::MATCH_CKKS_SCALE:
        if (text_index > 1) {
          const auto scale_difference =
              std::abs(text->ckks_scale() - first_text->ckks_scale()) /
              text->ckks_scale();

          if (scale_difference > 1e-4 && text->level() == first_text->level() &&
              is_rescaled(text->flag()) == is_rescaled(first_text->flag())) {
            throw std::runtime_error(function_name +
                                     ": the ckks scale of the input " +
                                     type_name + "s does not match.");
          }
        }
        break;
      case Requirement::MATCH_SIZE:
        if (text_index > 1 && text->size() != first_text->size()) {
          throw std::runtime_error(function_name + ": the size of the input " +
                                   type_name + "s does not match.");
        }
        break;
      case Requirement::NOT_ONE_MORE_LEVEL:
        if (parameters_.get_use_one_more_level() && text->moduli_id() == 0) {
          throw std::runtime_error(prefix + "should not be at max level.");
        }
        break;
      case Requirement::DUO_OR_TRIO: {
        const int polynomial_count = text->polynomial_count();
        if (polynomial_count != 2 && polynomial_count != 3) {
          throw std::runtime_error(prefix +
                                   "should have either 2 or 3 polynomials.");
        }
        break;
      }
      case Requirement::POSITIVE_LEVEL: {
        if (text->level() <= 0) {
          throw std::runtime_error(prefix + "should have a positive level.");
        }
        break;
      }
      case Requirement::NOT_LEVEL_ZERO_RESCALED: {
        if (text->level() <= 0 && is_rescaled(text->flag())) {
          throw std::runtime_error(prefix +
                                   "should not be rescaled at level 0.");
        }
        break;
      case Requirement::MATCH_LEVEL:
        if (text_index > 1 && text->level() != first_text->level()) {
          throw std::runtime_error(function_name + ": the level of the input " +
                                   type_name + "s does not match.");
        }
        break;
      case Requirement::MATCH_RESCALED:
        if (text_index > 1 &&
            is_rescaled(text->flag()) != is_rescaled(first_text->flag())) {
          throw std::runtime_error(function_name +
                                   ": the rescaled state of the input " +
                                   type_name + "s does not match.");
        }
        break;
      }
      default:
        break;
      }
    }
  }
}

template <class T>
void CKKSEngine::require(
    const std::string &function_name, std::vector<T *> &texts,
    const std::initializer_list<Requirement> requirements) {
  auto text_index = 0;
  const TextInterface *first_text;
  for (auto text : texts) {
    auto initial_prefix = function_name + ": the";
    auto prefix =
        get_ordinalized_prefix(initial_prefix, texts.size(), text_index);

    std::string type_name = text->type_name();

    if (text_index == 0) {
      first_text = text;
    }
    text_index++;

    prefix += " input " + type_name + " ";

    if (!is_compatible(text)) {
      throw std::runtime_error(prefix + "is not compatible with this engine.");
    }

    for (auto requirement : requirements) {
      switch (requirement) {
      case Requirement::DUO:
        if (text->polynomial_count() != 2) {
          throw std::runtime_error(prefix + "should have 2 polynomials.");
        }
        break;
      case Requirement::TRIO:
        if (text->polynomial_count() != 3) {
          throw std::runtime_error(prefix + "should have 3 polynomials.");
        }
        break;
      case Requirement::NTT:
        if (!is_ntt_form(text->flag())) {
          throw std::runtime_error(prefix + "should be in NTT form.");
        }
        break;
      case Requirement::INTT:
        if (is_ntt_form(text->flag())) {
          throw std::runtime_error(prefix + "should not be in NTT form.");
        }
        break;
      case Requirement::MATCH_NTT:
        if (text_index > 1 &&
            is_ntt_form(text->flag()) != is_ntt_form(first_text->flag())) {
          throw std::runtime_error(function_name +
                                   ": the NTT state of the input " + type_name +
                                   "s does not match.");
        }
        break;
      case Requirement::NOT_RESCALED:
        if (is_rescaled(text->flag())) {
          throw std::runtime_error(prefix + "should not be rescaled.");
        }
        break;

      case Requirement::DUOS_OR_TRIOS: {
        const int polynomial_count = text->polynomial_count();
        if (polynomial_count != 2 && polynomial_count != 3) {
          throw std::runtime_error(prefix +
                                   "should have either 2 or 3 polynomials.");
        }
        if (text_index > 1 &&
            polynomial_count != first_text->polynomial_count()) {
          throw std::runtime_error(function_name +
                                   ": the polynomial count of the input " +
                                   type_name + "s does not match.");
        }
        break;
      }
      case Requirement::LEVEL_ZERO:
        if (text->level() > 0) {
          throw std::runtime_error(prefix + "should be level 0.");
        }
        break;
      case Requirement::MATCH_CKKS_SCALE:
        if (text_index > 1) {
          const auto scale_difference =
              std::abs(text->ckks_scale() - first_text->ckks_scale()) /
              text->ckks_scale();

          if (scale_difference > 1e-4 && text->level() == first_text->level()) {
            throw std::runtime_error(function_name +
                                     ": the ckks scale of the input " +
                                     type_name + "s does not match.");
          }
        }
        break;
      case Requirement::MATCH_SIZE:
        if (text_index > 1 && text->size() != first_text->size()) {
          throw std::runtime_error(function_name + ": the size of the input " +
                                   type_name + "s does not match.");
        }
        break;
      case Requirement::NOT_ONE_MORE_LEVEL:
        if (parameters_.get_use_one_more_level() && text->moduli_id() == 0) {
          throw std::runtime_error(prefix + "should not be at max level.");
        }
        break;
      case Requirement::DUO_OR_TRIO: {
        const int polynomial_count = text->polynomial_count();
        if (polynomial_count != 2 && polynomial_count != 3) {
          throw std::runtime_error(prefix +
                                   "should have either 2 or 3 polynomials.");
        }
        break;
      }
      case Requirement::POSITIVE_LEVEL: {
        if (text->level() <= 0) {
          throw std::runtime_error(prefix + "should have a positive level.");
        }
        break;
      }
      case Requirement::MATCH_LEVEL:
        if (text_index > 1 && text->level() != first_text->level()) {
          throw std::runtime_error(function_name + ": the level of the input " +
                                   type_name + "s does not match.");
        }
        break;
      case Requirement::MATCH_RESCALED:
        if (text_index > 1 &&
            is_rescaled(text->flag()) != is_rescaled(first_text->flag())) {
          throw std::runtime_error(function_name +
                                   ": the rescaled state of the input " +
                                   type_name + "s does not match.");
        }
        break;
      case Requirement::MATCH_POLYNOMIAL_COUNT:
        if (text_index > 1 &&
            text->polynomial_count() != first_text->polynomial_count()) {
          throw std::runtime_error(function_name +
                                   ": the polynomial count of the input " +
                                   type_name + "s does not match.");
        }
        break;
      default:
        break;
      }
    }
  }
}

template void
CKKSEngine::require(const std::string &function_name,
                    std::vector<UnitCiphertext *> &texts,
                    const std::initializer_list<Requirement> requirements);

template void
CKKSEngine::require(const std::string &function_name,
                    std::vector<Ciphertext *> &texts,
                    const std::initializer_list<Requirement> requirements);

void CKKSEngine::require(
    const std::string &function_name, const TextInterface *text,
    const std::initializer_list<Requirement> requirements) {
  return require(function_name, {text}, requirements);
}

void CKKSEngine::require(
    const std::string &function_name, const TextInterface *ciphertext,
    const TextInterface *plaintext,
    const std::initializer_list<Requirement> requirements) {
  for (auto requirement : requirements) {
    switch (requirement) {
    case Requirement::MATCH_CKKS_SCALE: {
      const auto relative_error =
          std::abs(ciphertext->ckks_scale() - plaintext->ckks_scale()) /
          ciphertext->ckks_scale();

      if (ciphertext->level() == plaintext->level() &&
          is_rescaled(ciphertext->flag()) == is_rescaled(plaintext->flag()) &&
          relative_error > 1e-4) {
        throw std::runtime_error(function_name +
                                 ": the ckks scale of the input " +
                                 ciphertext->type_name() + " and " +
                                 plaintext->type_name() + " does not match.");
      }
      break;
    }
    case Requirement::MATCH_SIZE:
      if (ciphertext->size() != plaintext->size()) {
        throw std::runtime_error(function_name + ": the size of the input " +
                                 ciphertext->type_name() + " and " +
                                 plaintext->type_name() + " does not match.");
      }
      break;
    case Requirement::MATCH_LEVEL:
      if (ciphertext->level() != plaintext->level()) {
        throw std::runtime_error(function_name + ": the level of the input " +
                                 ciphertext->type_name() + " and " +
                                 plaintext->type_name() + " does not match.");
      }
      break;
    case Requirement::MATCH_NTT:
      if (is_ntt_form(ciphertext->flag()) != is_ntt_form(plaintext->flag())) {
        throw std::runtime_error(function_name +
                                 ": the NTT state of the input " +
                                 ciphertext->type_name() + " and " +
                                 plaintext->type_name() + " does not match.");
      }
      break;
    case Requirement::MATCH_RESCALED:
      if (is_rescaled(ciphertext->flag()) != is_rescaled(plaintext->flag())) {
        throw std::runtime_error(function_name +
                                 ": the rescaled state of the input " +
                                 ciphertext->type_name() + " and " +
                                 plaintext->type_name() + " does not match.");
      }
      break;
    default:
      break;
    }
  }
}

void CKKSEngine::require(
    const std::string &function_name, const UnitCiphertext *ciphertext,
    const DecomposedUnitCiphertext *decomposed_ciphertext,
    const std::initializer_list<Requirement> requirements) {
  for (auto requirement : requirements) {
    switch (requirement) {
    case Requirement::MATCH_LEVEL:
      if (ciphertext->level_ != decomposed_ciphertext->level_) {
        throw std::runtime_error(function_name + ": the size of the input " +
                                 ciphertext->type_name() +
                                 " and decomposed ciphertext does not match.");
      }
      break;
    default:
      break;
    }
  }
}

void CKKSEngine::require_key_compatibility(const std::string &function_name,
                                           const TextInterface *text,
                                           const SecretKey *secret_key) {
  if (!is_key_compatible(text, secret_key)) {
    throw std::runtime_error(function_name + ": the level of the input " +
                             text->type_name() +
                             " is greater than that of the input secret key.");
  }
}

void CKKSEngine::require_key_compatibility(const std::string &function_name,
                                           const TextInterface *text,
                                           const PublicKey *public_key) {
  if (!is_key_compatible(text, public_key)) {
    throw std::runtime_error(function_name + ": the level of the input " +
                             text->type_name() +
                             " is greater than that of the input public key.");
  }
}

void CKKSEngine::require_key_compatibility(
    const std::string &function_name, const TextInterface *text,
    const RelinearizationKey *relinearization_key, bool for_multiply) {
  auto key_switching_key = relinearization_key->key_switching_key_;
  if (!is_key_compatible(text, key_switching_key) &&

      !(for_multiply && text->level() - 1 == key_switching_key->level_)) {
    throw std::runtime_error(
        function_name + ": the level of the input " + text->type_name() +
        " is greater than that of the input relinearization key.");
  }
}

void CKKSEngine::require_key_compatibility(
    const std::string &function_name, const TextInterface *text,
    const FixedRotationKey *fixed_rotation_key) {
  auto key_switching_key = fixed_rotation_key->key_switching_key_;
  if (!is_key_compatible(text, key_switching_key)) {
    throw std::runtime_error(
        function_name + ": the level of the input " + text->type_name() +
        " is greater than that of the input fixed rotation key.");
  }
}

void CKKSEngine::require_key_compatibility(
    const std::string &function_name, const TextInterface *text,
    const std::vector<FixedRotationKey *> fixed_rotation_keys) {
  const int size = fixed_rotation_keys.size();
  if (size < 1) {
    throw std::runtime_error(function_name +
                             ": the input fixed rotation key vector is empty.");
  }

  for (int index = 0; index < size; index++) {
    auto prefix = get_ordinalized_prefix("the", size, index);
    auto key_switching_key = fixed_rotation_keys[index]->key_switching_key_;
    if (!is_key_compatible(text, key_switching_key)) {
      throw std::runtime_error(function_name + ": the level of the input " +
                               text->type_name() + " is greater than that of " +
                               prefix + " input fixed rotation key.");
    }
  }
}

void CKKSEngine::require_key_compatibility(const std::string &function_name,
                                           const TextInterface *text,
                                           const RotationKey *rotation_key) {
  for (auto fixed_rotation_key : rotation_key->fixed_rotation_keys_) {
    auto key_switching_key = fixed_rotation_key->key_switching_key_;
    if (!is_key_compatible(text, key_switching_key)) {
      throw std::runtime_error(
          function_name + ": the level of the input " + text->type_name() +
          " is greater than that of the input rotation key.");
    }
  }
}

void CKKSEngine::require_key_compatibility(
    const std::string &function_name,
    const std::initializer_list<const UnitCiphertext *> ciphertexts,
    const RotationKey *rotation_key) {
  auto ciphertext_index = 0;
  const UnitCiphertext *first_ciphertext;
  for (auto ciphertext : ciphertexts) {
    auto initial_prefix = function_name + ": the level of the";
    auto prefix = get_ordinalized_prefix(initial_prefix, ciphertexts.size(),
                                         ciphertext_index);

    if (ciphertext_index == 0) {
      first_ciphertext = ciphertext;
    }
    ciphertext_index++;

    for (auto fixed_rotation_key : rotation_key->fixed_rotation_keys_) {
      auto key_switching_key = fixed_rotation_key->key_switching_key_;
      if (!is_key_compatible(ciphertext, key_switching_key)) {
        throw std::runtime_error(prefix + " input ciphertext is greater than "
                                          "that of the input rotation key.");
      }
    }
  }
}

void CKKSEngine::require_key_compatibility(
    const std::string &function_name, const TextInterface *text,
    const ConjugationKey *conjugation_key) {
  auto key_switching_key = conjugation_key->key_switching_key_;
  if (!is_key_compatible(text, key_switching_key)) {
    throw std::runtime_error(
        function_name + ": the level of the input " + text->type_name() +
        " is greater than that of the input conjugation key.");
  }
}

void CKKSEngine::require_key_compatibility(
    const std::string &function_name,
    const std::initializer_list<const UnitCiphertext *> ciphertexts,
    const ConjugationKey *conjugation_key) {
  auto ciphertext_index = 0;
  const UnitCiphertext *first_ciphertext;
  auto key_switching_key = conjugation_key->key_switching_key_;
  for (auto ciphertext : ciphertexts) {
    auto initial_prefix = function_name + ": the level of the";
    auto prefix = get_ordinalized_prefix(initial_prefix, ciphertexts.size(),
                                         ciphertext_index);

    if (ciphertext_index == 0) {
      first_ciphertext = ciphertext;
    }
    ciphertext_index++;

    if (!is_key_compatible(ciphertext, key_switching_key)) {
      throw std::runtime_error(prefix +
                               " input ciphertext is greater than that "
                               "of the input conjugation key.");
    }
  }
}

template <typename T>
void CKKSEngine::require_matrix_compatibility(const std::string &function_name,
                                              const std::vector<T> &input) {
  auto slot_count = core_->get_slot_count();
  if (input.size() != slot_count * slot_count) {
    throw std::runtime_error(
        function_name +
        ": the given matrix is not compatible with this engine.");
  }
}

template void
CKKSEngine::require_matrix_compatibility(const std::string &function_name,
                                         const std::vector<double> &input);
template void CKKSEngine::require_matrix_compatibility(
    const std::string &function_name,
    const std::vector<std::complex<double>> &input);

void CKKSEngine::validate_target_level(const std::string &function_name,
                                       int level) {
  const int max_level = get_max_level();
  if (level < 0 || level > max_level) {
    throw std::runtime_error(function_name +
                             ": the target level cannot be reached with the "
                             "current engine parameters.");
  }
}

void CKKSEngine::validate_target_level(const std::string &function_name,
                                       int destination_level,
                                       int source_level) {
  if (destination_level < 0 || destination_level > source_level) {
    throw std::runtime_error(function_name +
                             ": the target level cannot be reached.");
  }
}

void CKKSEngine::validate_target_level(const std::string &function_name,
                                       const TextInterface *ciphertext,
                                       int level) {
  validate_target_level(function_name, level);

  if (ciphertext->level() < level) {
    throw std::runtime_error(function_name + ": the level of the input " +
                             ciphertext->type_name() +
                             " is less than the target level.");
  }
}

void CKKSEngine::validate_target_level(const std::string &function_name,
                                       const std::initializer_list<Data *> keys,
                                       int level) {
  validate_target_level(function_name, level);

  for (auto &key : keys) {
    if (key->level_ < level) {
      throw std::runtime_error(
          function_name +
          ": the target level cannot be reached with the provided keys.");
    }
  }
}

template <typename T>
void CKKSEngine::validate_target_level(const std::string &function_name,
                                       const std::vector<T> &keys, int level) {
  validate_target_level(function_name, level);

  for (auto &key : keys) {
    if (key->level_ < level) {
      throw std::runtime_error(
          function_name +
          ": the target level cannot be reached with the provided keys.");
    }
  }
}

template void
CKKSEngine::validate_target_level(const std::string &function_name,
                                  const std::vector<RelinearizationKey *> &keys,
                                  int level);
template void
CKKSEngine::validate_target_level(const std::string &function_name,
                                  const std::vector<ConjugationKey *> &keys,
                                  int level);
template void
CKKSEngine::validate_target_level(const std::string &function_name,
                                  const std::vector<FixedRotationKey *> &keys,
                                  int level);
template void
CKKSEngine::validate_target_level(const std::string &function_name,
                                  const std::vector<RotationKey *> &keys,
                                  int level);

void CKKSEngine::validate_key_switching_key_level(
    const std::string &function_name, int level) {
  const int max_level = get_max_key_switching_level();
  if (level < 0 || level > max_level) {
    throw std::runtime_error(function_name +
                             ": the target level cannot be reached with the "
                             "current engine parameters.");
  }
}
void CKKSEngine::validate_matrix_target_level(const std::string &function_name,
                                              int level) {
  if (level < 1 || level > get_max_key_switching_level()) {
    throw std::runtime_error(function_name +
                             ": the target level cannot be reached with the "
                             "current engine parameters.");
  }
}

void CKKSEngine::require_bootstrap_stage_count(const std::string &function_name,
                                               int stage_count,
                                               int inner_loop_shift) {
  int log_slot_count = parameters_.get_log_slot_count();
  int min_stage_count = 3;
  int max_stage_count = 5;
  bool invalid = false;

  switch (inner_loop_shift) {
  case 0:
    switch (log_slot_count) {
    case 1:
    case 2:
    case 3:
      min_stage_count = 1, max_stage_count = 1;
      break;
    case 4:
    case 5:
      min_stage_count = 1, max_stage_count = 2;
      break;
    case 6:
      min_stage_count = 2, max_stage_count = 2;
      break;
    case 7:
    case 8:
    case 9:
      min_stage_count = 2, max_stage_count = 3;
      break;
    case 10:
      min_stage_count = 2, max_stage_count = 4;
      break;
    case 11:
    case 12:
      min_stage_count = 3, max_stage_count = 4;
      break;
    case 13:
    case 14:
      min_stage_count = 3, max_stage_count = 5;
      break;
    default:
      break;
    }
    break;
  case 1:
    switch (log_slot_count) {
    case 1:
    case 2:
      invalid = true;
      break;
    case 3:
    case 4:
    case 5:
      min_stage_count = 1, max_stage_count = 1;
      break;
    case 6:
    case 7:
    case 8:
      min_stage_count = 2, max_stage_count = 2;
      break;
    case 9:
    case 10:
      min_stage_count = 2, max_stage_count = 3;
      break;
    case 11:
      min_stage_count = 3, max_stage_count = 3;
      break;
    case 12:
    case 13:
    case 14:
      min_stage_count = 3, max_stage_count = 4;
      break;
    default:
      break;
    }
  default:
    break;
  }

  if (invalid || stage_count < min_stage_count ||
      stage_count > max_stage_count) {
    throw std::runtime_error(function_name + ": invalid stage count.");
  }
}

int CKKSEngine::require_bootstrap_key_size(const std::string &function_name,
                                           const std::string &size) {
  const std::string size_lowercase = desilo::fhe::to_lowercase(size);
  int inner_loop_shift;
  if (size_lowercase == "medium") {
    inner_loop_shift = 0;
  } else if (size_lowercase == "large") {
    inner_loop_shift = 1;
  } else {
    throw std::runtime_error(function_name + ": invalid size.");
  }
  return inner_loop_shift;
}

}
