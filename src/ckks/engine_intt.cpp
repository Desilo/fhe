#include "ckks/engine.h"

namespace desilo::fhe {

template <class T> T *CKKSEngine::intt_(T *text, bool temp) {
  if ((text->flag() & DataFlag::NTT_FORM) == DataFlag::NONE) {
    if (temp) {
      return text;
    } else {
      return clone(text);
    }
  }

  auto intt_form = core_->to_intt_form(text);

  if (temp) {
    temp_data_.push_back(intt_form);
  }

  return intt_form;
}

template UnitPlaintext *CKKSEngine::intt_(UnitPlaintext *text, bool temp);
template UnitCiphertext *CKKSEngine::intt_(UnitCiphertext *text, bool temp);

template <class T, class U> T *CKKSEngine::intt_(T *long_text, bool temp) {
  if ((long_text->flag() & DataFlag::NTT_FORM) == DataFlag::NONE) {
    if (temp) {
      return long_text;
    } else {
      return clone(long_text);
    }
  }

  std::vector<U *> texts;
  for (int index = 0; index < long_text->size(); index++) {
    texts.push_back(core_->to_intt_form(long_text->get(index)));
  }
  auto intt_form = new T(texts);

  if (temp) {
    temp_text_.push_back(intt_form);
  }

  return intt_form;
}

Plaintext *CKKSEngine::intt_(Plaintext *plaintext, bool temp) {
  return intt_<Plaintext, UnitPlaintext>(plaintext, temp);
}

Ciphertext *CKKSEngine::intt_(Ciphertext *ciphertext, bool temp) {
  return intt_<Ciphertext, UnitCiphertext>(ciphertext, temp);
}

UnitPlaintext *CKKSEngine::intt(UnitPlaintext *unit_plaintext) {
  require("INTT Unit Plaintext", unit_plaintext, {});

  const auto temp = false;
  auto intt_form = intt_(unit_plaintext, temp);

  return intt_form;
}

UnitCiphertext *CKKSEngine::intt(UnitCiphertext *unit_ciphertext) {
  require("INTT Unit Ciphertext", unit_ciphertext, {});

  const auto temp = false;
  auto intt_form = intt_(unit_ciphertext, temp);

  return intt_form;
}

Plaintext *CKKSEngine::intt(Plaintext *plaintext) {
  require("INTT Plaintext", plaintext, {});

  const auto temp = false;
  auto intt_form = intt_(plaintext, temp);

  return intt_form;
}

Ciphertext *CKKSEngine::intt(Ciphertext *ciphertext) {
  require("INTT Ciphertext", ciphertext, {});

  const auto temp = false;
  auto intt_form = intt_(ciphertext, temp);

  return intt_form;
}

}
