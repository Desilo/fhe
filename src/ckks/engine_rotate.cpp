#include "ckks/engine.h"

namespace desilo::fhe {

template <class T>
void CKKSEngine::require_rotate_(const std::string &function_name, T *text) {
  require(function_name, text, {});
}

UnitPlaintext *CKKSEngine::rotate(UnitPlaintext *unit_plaintext, int delta) {
  const auto function_name = "Rotate Unit Plaintext";
  require_rotate_(function_name, unit_plaintext);

  UnitPlaintext *rotated;

  int normalized_delta = to_normalized_delta(delta);
  if (is_ntt_form(unit_plaintext->flag_)) {
    rotated = core_->rotate_ntt_form(unit_plaintext, normalized_delta);
  } else {
    rotated = core_->rotate_intt_form(unit_plaintext, normalized_delta);
  }

  return rotated;
}

Plaintext *CKKSEngine::rotate(Plaintext *plaintext, int delta) {
  const auto function_name = "Rotate Plaintext";
  require_rotate_(function_name, plaintext);

  const auto flag = plaintext->flag();

  int normalized_delta = to_normalized_delta(delta);
  std::vector<UnitPlaintext *> unit_plaintexts;
  for (int index = 0; index < plaintext->size(); index++) {
    if (is_ntt_form(flag)) {
      unit_plaintexts.push_back(
          core_->rotate_ntt_form(plaintext->get(index), normalized_delta));
    } else {
      unit_plaintexts.push_back(
          core_->rotate_intt_form(plaintext->get(index), normalized_delta));
    }
  }

  return new Plaintext(unit_plaintexts);
}

template <class T>
void CKKSEngine::require_rotate_(const std::string &function_name, T *text,
                                 FixedRotationKey *fixed_rotation_key) {
  require(function_name, text, {Requirement::DUO});
  require_engine_compatibility(function_name, fixed_rotation_key);
  require_key_compatibility(function_name, text, fixed_rotation_key);
}

UnitCiphertext *CKKSEngine::rotate(UnitCiphertext *unit_ciphertext,
                                   FixedRotationKey *fixed_rotation_key) {
  const auto function_name = "Rotate Unit Ciphertext With Fixed Rotation Key";
  require_rotate_(function_name, unit_ciphertext, fixed_rotation_key);

  auto rotate_input = unit_ciphertext;
  auto temp = true;

  if (parameters_.get_use_one_more_level() &&
      unit_ciphertext->moduli_id_ == 0) {
    rotate_input =
        level_down_(unit_ciphertext, unit_ciphertext->level_ - 1, temp);
  }

  rotate_input = intt_(rotate_input, temp);

  auto rotated = core_->rotate(rotate_input, fixed_rotation_key);

  clear_temp_data();

  return rotated;
}

Ciphertext *CKKSEngine::rotate(Ciphertext *ciphertext,
                               FixedRotationKey *fixed_rotation_key) {
  const auto function_name = "Rotate Ciphertext With Fixed Rotation Key";
  require_rotate_(function_name, ciphertext, fixed_rotation_key);

  auto rotate_input = ciphertext;
  auto temp = true;

  if (parameters_.get_use_one_more_level() && ciphertext->moduli_id() == 0) {
    rotate_input = level_down_(ciphertext, ciphertext->level() - 1, temp);
  }

  rotate_input = intt_(rotate_input, temp);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(
        core_->rotate(rotate_input->get(index), fixed_rotation_key));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

template <class T>
void CKKSEngine::require_rotate_(const std::string &function_name, T *text,
                                 RotationKey *rotation_key) {
  require(function_name, text, {Requirement::DUO});
  require_engine_compatibility(function_name, rotation_key);
  require_key_compatibility(function_name, text, rotation_key);
}

UnitCiphertext *CKKSEngine::rotate(UnitCiphertext *unit_ciphertext,
                                   RotationKey *rotation_key, int delta,
                                   bool normalize_by_slot_count) {
  const auto function_name = "Rotate Unit Ciphertext With Rotation Key";
  require_rotate_(function_name, unit_ciphertext, rotation_key);

  auto current = unit_ciphertext;
  UnitCiphertext *rotated;
  int normalized_delta = to_normalized_delta(delta, normalize_by_slot_count);

  if (normalized_delta == 0) {
    return intt(unit_ciphertext);
  }

  for (auto fixed_rotation_key : rotation_key->fixed_rotation_keys_) {
    if ((normalized_delta & fixed_rotation_key->delta_) == 0) {
      continue;
    }

    rotated = rotate(current, fixed_rotation_key);

    if (current != unit_ciphertext) {
      delete current;
    }

    current = rotated;
  }

  return rotated;
}

Ciphertext *CKKSEngine::rotate(Ciphertext *ciphertext,
                               RotationKey *rotation_key, int delta) {
  const auto function_name = "Rotate Ciphertext With Rotation Key";
  require_rotate_(function_name, ciphertext, rotation_key);

  auto current = ciphertext;
  Ciphertext *rotated;
  int normalized_delta = to_normalized_delta(delta);

  if (normalized_delta == 0) {
    return intt(ciphertext);
  }

  for (auto fixed_rotation_key : rotation_key->fixed_rotation_keys_) {
    if ((normalized_delta & fixed_rotation_key->delta_) == 0) {
      continue;
    }

    rotated = rotate(current, fixed_rotation_key);

    if (current != ciphertext) {
      delete current;
    }

    current = rotated;
  }

  return rotated;
}

std::pair<FixedRotationKey *, PermutationParameters *>
CKKSEngine::get_rotation_context(const std::string &function_name,
                                 BootstrapKey *bootstrap_key, int delta) {

  if (!bootstrap_key->rotation_contexts_.contains(delta)) {
    throw std::runtime_error(
        function_name +
        ": the bootstrap key does not contain a rotation context for delta " +
        std::to_string(delta) + ".");
  }

  return bootstrap_key->rotation_contexts_[delta];
}

FixedRotationKey *
CKKSEngine::get_fixed_rotation_key(const std::string &function_name,
                                   BootstrapKey *bootstrap_key, int delta) {
  return get_rotation_context(function_name, bootstrap_key, delta).first;
}

UnitCiphertext *CKKSEngine::rotate(UnitCiphertext *unit_ciphertext,
                                   BootstrapKey *bootstrap_key, int delta,
                                   bool normalize_by_slot_count) {
  const std::string function_name = "Rotate Unit Ciphertext with Bootstrap Key";
  int normalized_delta = to_normalized_delta(delta, normalize_by_slot_count);

  if (normalized_delta == 0) {

    return clone(unit_ciphertext);
  }

  auto fixed_rotation_key =
      get_fixed_rotation_key(function_name, bootstrap_key, normalized_delta);
  return rotate(unit_ciphertext, fixed_rotation_key);
}

Ciphertext *CKKSEngine::rotate(Ciphertext *ciphertext,
                               BootstrapKey *bootstrap_key, int delta) {
  const std::string function_name = "Rotate Ciphertext with Bootstrap Key";
  int normalized_delta = to_normalized_delta(delta);

  if (normalized_delta == 0) {

    return clone(ciphertext);
  }

  auto fixed_rotation_key =
      get_fixed_rotation_key(function_name, bootstrap_key, normalized_delta);
  return rotate(ciphertext, fixed_rotation_key);
}

template <class T>
UnitCiphertext *
CKKSEngine::ntt_rotate_(const std::string &function_name,
                        UnitCiphertext *unit_ciphertext,
                        DecomposedUnitCiphertext *decomposed_unit_ciphertext,
                        T *bootstrap_key, int delta) {
  int normalized_delta = to_normalized_delta(delta);

  if (normalized_delta == 0) {

    return clone(unit_ciphertext);
  }

  auto [fixed_rotation_key, ntt_permutation_parameters] =
      get_rotation_context(function_name, bootstrap_key, normalized_delta);

  auto rotated =
      core_->ntt_rotate(unit_ciphertext, decomposed_unit_ciphertext,
                        fixed_rotation_key, ntt_permutation_parameters);

  return rotated;
}

UnitCiphertext *
CKKSEngine::ntt_rotate(UnitCiphertext *unit_ciphertext,
                       DecomposedUnitCiphertext *decomposed_unit_ciphertext,
                       BootstrapKey *bootstrap_key, int delta) {
  const std::string function_name =
      "Rotate Unit Ciphertext in NTT Form with Bootstrap Key";
  require(function_name, unit_ciphertext, {Requirement::DUO, Requirement::NTT});

  require(function_name, unit_ciphertext, decomposed_unit_ciphertext,
          {Requirement::MATCH_LEVEL});

  return ntt_rotate_(function_name, unit_ciphertext, decomposed_unit_ciphertext,
                     bootstrap_key, delta);
}

std::vector<Ciphertext *>
CKKSEngine::rotate_batch(Ciphertext *ciphertext,
                         std::vector<FixedRotationKey *> fixed_rotation_keys) {
  const std::string function_name =
      "Batch Rotate Ciphertext With Fixed Rotation Keys";
  require(function_name, ciphertext, {Requirement::DUO});
  require_engine_compatibility(function_name, fixed_rotation_keys, {});
  require_key_compatibility(function_name, ciphertext, fixed_rotation_keys);

  auto rotate_input = ciphertext;
  auto temp = true;
  if (parameters_.get_use_one_more_level() && ciphertext->moduli_id() == 0) {
    rotate_input = level_down_(ciphertext, ciphertext->level() - 1, temp);
  }
  rotate_input = intt_(rotate_input, temp);

  auto ciphertext_size = ciphertext->size();
  auto rotate_count = fixed_rotation_keys.size();
  std::vector<std::vector<UnitCiphertext *>> unit_ciphertexts(rotate_count);

  for (int ciphertext_index = 0; ciphertext_index < ciphertext_size;
       ciphertext_index++) {
    auto unit_ciphertext = rotate_input->get(ciphertext_index);
    auto decomposed = core_->decompose(unit_ciphertext);
    temp_data_.push_back(decomposed);

    for (int rotate_index = 0; rotate_index < rotate_count; rotate_index++) {
      auto fixed_rotation_key = fixed_rotation_keys[rotate_index];
      unit_ciphertexts[rotate_index].push_back(
          core_->rotate(unit_ciphertext, decomposed, fixed_rotation_key));
    }
  }

  clear_temp_data();

  std::vector<Ciphertext *> rotated;
  for (auto &rotated_unit_ciphertexts : unit_ciphertexts) {
    rotated.push_back(new Ciphertext(rotated_unit_ciphertexts));
  }

  return rotated;
}

std::vector<UnitCiphertext *>
CKKSEngine::rotate_batch(UnitCiphertext *unit_ciphertext,
                         RotationKey *rotation_key, std::vector<int> deltas) {
  const std::string function_name =
      "Batch Rotate Unit Ciphertext With Rotation Key";
#ifdef DESILO_FHE_DEBUG
  require(function_name, unit_ciphertext, {Requirement::DUO});
  require_engine_compatibility(function_name, rotation_key);
  require_key_compatibility(function_name, unit_ciphertext, rotation_key);
#endif
  if (deltas.size() < 1) {
    throw std::runtime_error(function_name +
                             ": the input delta vector is empty.");
  }

  auto rotate_input = unit_ciphertext;
  auto temp = true;
  if (parameters_.get_use_one_more_level() &&
      unit_ciphertext->moduli_id() == 0) {
    auto level = unit_ciphertext->level_ - 1;
    rotate_input = level_down_(unit_ciphertext, level, temp);
  }
  rotate_input = intt_(rotate_input, temp);

  std::vector<int> normalized_deltas;
  std::map<int, int> delta_counter;
  for (auto delta : deltas) {
    auto normalized_delta = to_normalized_delta(delta);
    normalized_deltas.push_back(normalized_delta);
    if (!delta_counter.contains(normalized_delta)) {

      delta_counter[normalized_delta] = normalized_delta == 0 ? 1 : 0;
    }
    delta_counter[normalized_delta]++;
  }

  auto rotate_count = deltas.size();

  std::map<int, DecomposedUnitCiphertext *> decomposed_unit_ciphertexts = {};

  std::map<int, UnitCiphertext *> rotated_unit_ciphertexts = {
      {0, rotate_input}};
  std::vector<UnitCiphertext *> output(rotate_count);
  std::set<int> delta_set(deltas.begin(), deltas.end());

  for (int rotate_index = 0; rotate_index < rotate_count; rotate_index++) {
    int delta = normalized_deltas[rotate_index];

    if (rotated_unit_ciphertexts.contains(delta)) {
      output[rotate_index] = rotated_unit_ciphertexts[delta];
      continue;
    }

    for (auto fixed_rotation_key : rotation_key->fixed_rotation_keys_) {
      if ((delta & fixed_rotation_key->delta_) == 0) {
        continue;
      }

      auto previous_delta = delta & (fixed_rotation_key->delta_ - 1);
      auto current_delta = previous_delta + fixed_rotation_key->delta_;

      UnitCiphertext *rotated;
      if (rotated_unit_ciphertexts.contains(current_delta)) {
        rotated = rotated_unit_ciphertexts[current_delta];
      } else {
        auto previous_unit_ciphertext =
            rotated_unit_ciphertexts[previous_delta];

        if (!decomposed_unit_ciphertexts.contains(previous_delta)) {
          auto decomposed = core_->decompose(previous_unit_ciphertext);
          decomposed_unit_ciphertexts[previous_delta] = decomposed;

          temp_data_.push_back(decomposed);
        }

        auto decomposed = decomposed_unit_ciphertexts[previous_delta];
        rotated = core_->rotate(previous_unit_ciphertext, decomposed,
                                fixed_rotation_key);
        rotated_unit_ciphertexts[current_delta] = rotated;
      }

      if (!delta_set.contains(current_delta)) {

        temp_data_.push_back(rotated);
      }

      if (current_delta == delta) {
        output[rotate_index] = rotated;
        break;
      }
    }
  }

  for (int rotate_index = 0; rotate_index < rotate_count; rotate_index++) {
    int delta = normalized_deltas[rotate_index];
    if (delta_counter[delta] > 1) {
      output[rotate_index] = clone(output[rotate_index]);
      delta_counter[delta]--;
    }
  }

  clear_temp_data();

  return output;
}

std::vector<Ciphertext *> CKKSEngine::rotate_batch(Ciphertext *ciphertext,
                                                   RotationKey *rotation_key,
                                                   std::vector<int> deltas) {
  const std::string function_name = "Batch Rotate Ciphertext With Rotation Key";
  require(function_name, ciphertext, {Requirement::DUO});
  require_engine_compatibility(function_name, rotation_key);
  require_key_compatibility(function_name, ciphertext, rotation_key);
  if (deltas.size() < 1) {
    throw std::runtime_error(function_name +
                             ": the input delta vector is empty.");
  }

  auto rotate_input = ciphertext;
  auto temp = true;
  if (parameters_.get_use_one_more_level() && ciphertext->moduli_id() == 0) {
    rotate_input = level_down_(ciphertext, ciphertext->level() - 1, temp);
  }
  rotate_input = intt_(rotate_input, temp);

  std::vector<int> normalized_deltas;
  std::map<int, int> delta_counter;
  for (auto delta : deltas) {
    auto normalized_delta = to_normalized_delta(delta);
    normalized_deltas.push_back(normalized_delta);
    if (!delta_counter.contains(normalized_delta)) {
      delta_counter[normalized_delta] = 0;
    }
    delta_counter[normalized_delta]++;
  }

  auto ciphertext_size = ciphertext->size();
  auto rotate_count = deltas.size();

  std::map<int, std::map<int, DecomposedUnitCiphertext *>>
      decomposed_unit_ciphertexts;

  std::map<int, std::map<int, UnitCiphertext *>> rotated_unit_ciphertexts;
  std::vector<std::vector<UnitCiphertext *>> unit_ciphertexts(rotate_count);

  for (int rotate_index = 0; rotate_index < rotate_count; rotate_index++) {
    int delta = normalized_deltas[rotate_index];
    if (delta == 0) {
      for (int ciphertext_index = 0; ciphertext_index < ciphertext_size;
           ciphertext_index++) {
        auto unit_ciphertext = rotate_input->get(ciphertext_index);
        unit_ciphertexts[rotate_index].push_back(clone(unit_ciphertext));
      }
      delta_counter[delta]--;
    }
  }

  for (int ciphertext_index = 0; ciphertext_index < ciphertext_size;
       ciphertext_index++) {
    auto unit_ciphertext = rotate_input->get(ciphertext_index);
    decomposed_unit_ciphertexts[ciphertext_index] = {};
    rotated_unit_ciphertexts[ciphertext_index] = {{0, unit_ciphertext}};

    for (int rotate_index = 0; rotate_index < rotate_count; rotate_index++) {
      int delta = normalized_deltas[rotate_index];

      if (delta == 0) {
        continue;
      }

      if (rotated_unit_ciphertexts[ciphertext_index].contains(delta)) {
        unit_ciphertexts[rotate_index].push_back(
            rotated_unit_ciphertexts[ciphertext_index][delta]);
        continue;
      }

      for (auto fixed_rotation_key : rotation_key->fixed_rotation_keys_) {
        if ((delta & fixed_rotation_key->delta_) == 0) {
          continue;
        }

        auto previous_delta = delta & (fixed_rotation_key->delta_ - 1);
        auto current_delta = previous_delta + fixed_rotation_key->delta_;

        UnitCiphertext *rotated;
        if (rotated_unit_ciphertexts[ciphertext_index].contains(
                current_delta)) {
          rotated = rotated_unit_ciphertexts[ciphertext_index][current_delta];
        } else {
          auto previous_unit_ciphertext =
              rotated_unit_ciphertexts[ciphertext_index][previous_delta];

          if (!decomposed_unit_ciphertexts[ciphertext_index].contains(
                  previous_delta)) {
            auto decomposed = core_->decompose(previous_unit_ciphertext);
            decomposed_unit_ciphertexts[ciphertext_index][previous_delta] =
                decomposed;

            temp_data_.push_back(decomposed);
          }

          auto decomposed =
              decomposed_unit_ciphertexts[ciphertext_index][previous_delta];
          rotated = core_->rotate(previous_unit_ciphertext, decomposed,
                                  fixed_rotation_key);
          rotated_unit_ciphertexts[ciphertext_index][current_delta] = rotated;
        }

        if (!delta_counter.contains(current_delta)) {

          temp_data_.push_back(rotated);
        }

        if (current_delta == delta) {
          unit_ciphertexts[rotate_index].push_back(rotated);
          break;
        }
      }
    }
  }

  clear_temp_data();

  for (int rotate_index = 0; rotate_index < rotate_count; rotate_index++) {
    int delta = normalized_deltas[rotate_index];
    if (delta_counter[delta] > 1) {
      for (int ciphertext_index = 0; ciphertext_index < ciphertext_size;
           ciphertext_index++) {
        auto unit_ciphertext = unit_ciphertexts[rotate_index][ciphertext_index];
        unit_ciphertexts[rotate_index][ciphertext_index] =
            clone(unit_ciphertext);
      }
      delta_counter[delta]--;
    }
  }

  std::vector<Ciphertext *> rotated;
  for (auto &rotated_unit_ciphertexts : unit_ciphertexts) {
    rotated.push_back(new Ciphertext(rotated_unit_ciphertexts));
  }

  return rotated;
}

}
