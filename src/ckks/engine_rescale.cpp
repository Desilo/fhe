#include "ckks/engine.h"

namespace desilo::fhe {

template <class T> T *CKKSEngine::rescale_(T *text, bool temp) {
  if (is_rescaled(text->flag_)) {
    if (temp) {
      return text;
    } else {
      return clone(text);
    }
  }

  T *rescaled;

  if (is_ntt_form(text->flag_)) {
    const auto ntt_temp = true;

    const auto intt_form = intt_(text, ntt_temp);
    const auto rescaled_intt = core_->rescale(intt_form);
    rescaled = core_->to_ntt_form(rescaled_intt);

    temp_data_.push_back(rescaled_intt);
  } else {
    rescaled = core_->rescale(text);
  }

  if (temp) {
    temp_data_.push_back(rescaled);
  }

  return rescaled;
}

template UnitPlaintext *CKKSEngine::rescale_(UnitPlaintext *text, bool temp);
template UnitCiphertext *CKKSEngine::rescale_(UnitCiphertext *text, bool temp);

UnitPlaintext *CKKSEngine::rescale(UnitPlaintext *unit_plaintext) {
  const auto function_name = "Rescale Unit Plaintext";
  require(function_name, unit_plaintext, {Requirement::POSITIVE_LEVEL});

  const auto temp = false;
  auto rescaled = rescale_(unit_plaintext, temp);

  clear_temp_data();

  return rescaled;
}

UnitCiphertext *CKKSEngine::rescale(UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Rescale Unit Ciphertext";
  require(function_name, unit_ciphertext,
          {Requirement::DUO_OR_TRIO, Requirement::POSITIVE_LEVEL});

  const auto temp = false;
  auto rescaled = rescale_(unit_ciphertext, temp);

  clear_temp_data();

  return rescaled;
}

template <class T, class U> T *CKKSEngine::rescale_(T *long_text, bool temp) {
  if (is_rescaled(long_text->flag())) {
    if (temp) {
      return long_text;
    } else {
      return clone(long_text);
    }
  }

  std::vector<U *> texts;
  const auto flag = long_text->flag();
  U *rescaled_intt;

  for (int index = 0; index < long_text->size(); index++) {
    if (is_ntt_form(flag)) {
      const auto ntt_temp = true;
      const auto intt_form = intt_(long_text->get(index), ntt_temp);

      rescaled_intt = core_->rescale(intt_form);
      texts.push_back(core_->to_ntt_form(rescaled_intt));

      temp_data_.push_back(rescaled_intt);
    } else {
      texts.push_back(core_->rescale(long_text->get(index)));
    }
  }
  auto rescaled = new T(texts);

  if (temp) {
    temp_text_.push_back(rescaled);
  }

  return rescaled;
}

Plaintext *CKKSEngine::rescale_(Plaintext *plaintext, bool temp) {
  return rescale_<Plaintext, UnitPlaintext>(plaintext, temp);
}

Ciphertext *CKKSEngine::rescale_(Ciphertext *ciphertext, bool temp) {
  return rescale_<Ciphertext, UnitCiphertext>(ciphertext, temp);
}

Plaintext *CKKSEngine::rescale(Plaintext *plaintext) {
  const auto function_name = "Rescale Plaintext";
  require(function_name, plaintext, {Requirement::POSITIVE_LEVEL});

  const auto temp = false;
  auto rescaled = rescale_(plaintext, temp);

  clear_temp_data();

  return rescaled;
}

Ciphertext *CKKSEngine::rescale(Ciphertext *ciphertext) {
  const auto function_name = "Rescale Ciphertext";
  require(function_name, ciphertext,
          {Requirement::DUO_OR_TRIO, Requirement::POSITIVE_LEVEL});

  const auto temp = false;
  auto rescaled = rescale_(ciphertext, temp);

  clear_temp_data();

  return rescaled;
}

}
