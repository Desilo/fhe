#include "ckks/engine.h"

namespace desilo::fhe {

UnitPlaintext *CKKSEngine::clone(UnitPlaintext *unit_plaintext) {
  require("Clone Unit Plaintext", unit_plaintext, {});

  auto cloned = core_->clone(unit_plaintext);

  return cloned;
}

UnitCiphertext *CKKSEngine::clone(UnitCiphertext *unit_ciphertext) {
  require("Clone Unit Ciphertext", unit_ciphertext, {});

  auto cloned = core_->clone(unit_ciphertext);

  return cloned;
}

Plaintext *CKKSEngine::clone(Plaintext *plaintext) {
  require("Clone Plaintext", plaintext, {});

  std::vector<UnitPlaintext *> unit_plaintexts;
  for (int index = 0; index < plaintext->size(); index++) {
    unit_plaintexts.push_back(core_->clone(plaintext->get(index)));
  }

  return new Plaintext(unit_plaintexts);
}

Ciphertext *CKKSEngine::clone(Ciphertext *ciphertext) {
  require("Clone Ciphertext", ciphertext, {});

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(core_->clone(ciphertext->get(index)));
  }

  return new Ciphertext(unit_ciphertexts);
}

}
