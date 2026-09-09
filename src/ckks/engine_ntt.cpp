#include "ckks/engine.h"

namespace desilo::fhe {

template <class T> T *CKKSEngine::ntt_(T *text, bool temp) {
  if ((text->flag() & DataFlag::NTT_FORM) != DataFlag::NONE) {
    if (temp) {
      return text;
    } else {
      return clone(text);
    }
  }

  auto ntt_form = core_->to_ntt_form(text);

  if (temp) {
    temp_data_.push_back(ntt_form);
  }

  return ntt_form;
}

template UnitPlaintext *CKKSEngine::ntt_(UnitPlaintext *text, bool temp);
template UnitCiphertext *CKKSEngine::ntt_(UnitCiphertext *text, bool temp);

UnitPlaintext *CKKSEngine::ntt(UnitPlaintext *unit_plaintext) {
  require("NTT Unit Plaintext", unit_plaintext, {});

  const auto temp = false;
  auto ntt_form = ntt_(unit_plaintext, temp);

  return ntt_form;
}

UnitCiphertext *CKKSEngine::ntt(UnitCiphertext *unit_ciphertext) {
  require("NTT Unit Ciphertext", unit_ciphertext, {});

  const auto temp = false;
  auto ntt_form = ntt_(unit_ciphertext, temp);

  return ntt_form;
}

template <class T, class U> T *CKKSEngine::ntt_(T *long_text, bool temp) {
  if ((long_text->flag() & DataFlag::NTT_FORM) != DataFlag::NONE) {
    if (temp) {
      return long_text;
    } else {
      return clone(long_text);
    }
  }

  std::vector<U *> texts;
  for (int index = 0; index < long_text->size(); index++) {
    texts.push_back(core_->to_ntt_form(long_text->get(index)));
  }
  auto ntt_form = new T(texts);

  if (temp) {
    temp_text_.push_back(ntt_form);
  }

  return ntt_form;
}

Plaintext *CKKSEngine::ntt_(Plaintext *plaintext, bool temp) {
  return ntt_<Plaintext, UnitPlaintext>(plaintext, temp);
}

Ciphertext *CKKSEngine::ntt_(Ciphertext *ciphertext, bool temp) {
  return ntt_<Ciphertext, UnitCiphertext>(ciphertext, temp);
}

Plaintext *CKKSEngine::ntt(Plaintext *plaintext) {
  require("NTT Plaintext", plaintext, {});

  const auto temp = false;
  auto ntt_form = ntt_(plaintext, temp);

  return ntt_form;
}

Ciphertext *CKKSEngine::ntt(Ciphertext *ciphertext) {
  require("NTT Ciphertext", ciphertext, {});

  const auto temp = false;
  auto ntt_form = ntt_(ciphertext, temp);

  return ntt_form;
}

}
