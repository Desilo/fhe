#include "ckks/engine.h"

namespace desilo::fhe {

template <class T>
void CKKSEngine::require_conjugate_(const std::string &function_name, T *text) {
  require(function_name, text, {});
}

UnitPlaintext *CKKSEngine::conjugate(UnitPlaintext *unit_plaintext) {
  const auto function_name = "Conjugate Unit Plaintext";
  require_conjugate_(function_name, unit_plaintext);

  UnitPlaintext *conjugated;

  if (is_ntt_form(unit_plaintext->flag_)) {
    conjugated = core_->conjugate_ntt_form(unit_plaintext);
  } else {
    conjugated = core_->conjugate_intt_form(unit_plaintext);
  }

  return conjugated;
}

Plaintext *CKKSEngine::conjugate(Plaintext *plaintext) {
  const auto function_name = "Conjugate Plaintext";
  require_conjugate_(function_name, plaintext);

  const auto ntt_form = is_ntt_form(plaintext->flag());

  std::vector<UnitPlaintext *> unit_plaintexts;
  for (int index = 0; index < plaintext->size(); index++) {
    if (ntt_form) {
      unit_plaintexts.push_back(
          core_->conjugate_ntt_form(plaintext->get(index)));
    } else {
      unit_plaintexts.push_back(
          core_->conjugate_intt_form(plaintext->get(index)));
    }
  }

  return new Plaintext(unit_plaintexts);
}

template <class T>
void CKKSEngine::require_conjugate_(const std::string &function_name, T *text,
                                    ConjugationKey *conjugation_key) {
  require(function_name, text, {Requirement::DUO});
  require_engine_compatibility(function_name, conjugation_key);
  require_key_compatibility(function_name, text, conjugation_key);
}

UnitCiphertext *CKKSEngine::conjugate(UnitCiphertext *unit_ciphertext,
                                      ConjugationKey *conjugation_key) {
  const auto function_name = "Conjugate Unit Ciphertext";
  require_conjugate_(function_name, unit_ciphertext, conjugation_key);

  auto conjugate_input = unit_ciphertext;
  const auto temp = true;
  if (parameters_.get_use_one_more_level() &&
      unit_ciphertext->moduli_id_ == 0) {
    conjugate_input =
        level_down_(unit_ciphertext, unit_ciphertext->level_ - 1, temp);
  }

  conjugate_input = intt_(conjugate_input, temp);

  auto conjugated = core_->conjugate(conjugate_input, conjugation_key);

  clear_temp_data();

  return conjugated;
}

Ciphertext *CKKSEngine::conjugate(Ciphertext *ciphertext,
                                  ConjugationKey *conjugation_key) {
  const auto function_name = "Conjugate Ciphertext";
  require_conjugate_(function_name, ciphertext, conjugation_key);

  auto conjugate_input = ciphertext;
  const auto temp = true;
  if (parameters_.get_use_one_more_level() && ciphertext->moduli_id() == 0) {
    conjugate_input = level_down_(ciphertext, ciphertext->level() - 1, temp);
  }

  conjugate_input = intt_(conjugate_input, temp);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(
        core_->conjugate(conjugate_input->get(index), conjugation_key));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

}
