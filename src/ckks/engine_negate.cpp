#include "ckks/engine.h"

namespace desilo::fhe {

UnitCiphertext *CKKSEngine::negate(UnitCiphertext *unit_ciphertext) {
  require("Negate Unit Ciphertext", unit_ciphertext,
          {Requirement::DUO_OR_TRIO});

  const auto negated = core_->negate(unit_ciphertext);

  return negated;
}

Ciphertext *CKKSEngine::negate(Ciphertext *ciphertext) {
  require("Negate Ciphertext", ciphertext, {Requirement::DUO_OR_TRIO});

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(core_->negate(ciphertext->get(index)));
  }

  return new Ciphertext(unit_ciphertexts);
}

}
