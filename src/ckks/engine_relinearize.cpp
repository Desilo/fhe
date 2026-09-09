#include "ckks/engine.h"

namespace desilo::fhe {

template <class T>
void CKKSEngine::require_relinearize_(const std::string &function_name, T *text,
                                      RelinearizationKey *relinearization_key) {
  require(function_name, text, {Requirement::TRIO});
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text, relinearization_key);
}

UnitCiphertext *
CKKSEngine::relinearize(UnitCiphertext *unit_ciphertext,
                        RelinearizationKey *relinearization_key) {
  const auto function_name = "Relinearize Unit Ciphertext";
  require_relinearize_(function_name, unit_ciphertext, relinearization_key);

  const auto temp = true;
  auto input_unit_ciphertext = ntt_(unit_ciphertext, temp);

  auto relinearized =
      core_->relinearize(input_unit_ciphertext, relinearization_key);

  clear_temp_data();

  return relinearized;
}

Ciphertext *CKKSEngine::relinearize(Ciphertext *ciphertext,
                                    RelinearizationKey *relinearization_key) {
  const auto function_name = "Relinearize Ciphertext";
  require_relinearize_(function_name, ciphertext, relinearization_key);

  const auto temp = true;
  auto input_ciphertext = ntt_(ciphertext, temp);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(
        core_->relinearize(input_ciphertext->get(index), relinearization_key));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

}
