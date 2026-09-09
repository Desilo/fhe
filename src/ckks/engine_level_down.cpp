#include "ckks/engine.h"

namespace desilo::fhe {

template <class T> T *CKKSEngine::level_down_(T *text, int level, bool temp) {
  if (text->level_ == level) {
    if (temp) {
      return text;
    } else {
      return clone(text);
    }
  }

  T *leveled_down;

  if (is_rescaled(text->flag_)) {
    leveled_down = core_->level_down_after_rescale(text, level);
  } else {
    if (is_ntt_form(text->flag_)) {
      const auto ntt_temp = true;

      const auto intt_form = intt_(text, ntt_temp);
      const auto leveled_down_intt = core_->level_down(intt_form, level);
      leveled_down = core_->to_ntt_form(leveled_down_intt);

      delete leveled_down_intt;
    } else {
      leveled_down = core_->level_down(text, level);
    }
  }

  if (temp) {
    temp_data_.push_back(leveled_down);
  }

  return leveled_down;
}

template UnitPlaintext *CKKSEngine::level_down_(UnitPlaintext *text, int level,
                                                bool temp);
template UnitCiphertext *CKKSEngine::level_down_(UnitCiphertext *text,
                                                 int level, bool temp);

UnitPlaintext *CKKSEngine::level_down(UnitPlaintext *unit_plaintext,
                                      int level) {
  const auto function_name = "Level Down Unit Plaintext";
  require(function_name, unit_plaintext, {});
  validate_target_level(function_name, level, unit_plaintext->level_);

  const auto temp = false;
  auto leveled_down = level_down_(unit_plaintext, level, temp);

  clear_temp_data();

  return leveled_down;
}

UnitCiphertext *CKKSEngine::level_down(UnitCiphertext *unit_ciphertext,
                                       int level) {
  const auto function_name = "Level Down Unit Ciphertext";
  require(function_name, unit_ciphertext, {Requirement::DUO_OR_TRIO});
  validate_target_level(function_name, level, unit_ciphertext->level_);

  const auto temp = false;
  auto leveled_down = level_down_(unit_ciphertext, level, temp);

  clear_temp_data();

  return leveled_down;
}

template <class T, class U>
T *CKKSEngine::level_down_(T *long_text, int level, bool temp) {
  if (long_text->level() == level) {
    if (temp) {
      return long_text;
    } else {
      return clone(long_text);
    }
  }

  std::vector<U *> texts;
  const auto flag = long_text->flag();
  U *leveled_down_intt;

  for (int index = 0; index < long_text->size(); index++) {
    if (is_rescaled(flag)) {
      texts.push_back(
          core_->level_down_after_rescale(long_text->get(index), level));
    } else {
      if (is_ntt_form(flag)) {
        const auto ntt_temp = true;
        const auto intt_form = intt_(long_text->get(index), ntt_temp);

        leveled_down_intt = core_->level_down(intt_form, level);
        texts.push_back(core_->to_ntt_form(leveled_down_intt));

        delete leveled_down_intt;
      } else {
        texts.push_back(core_->level_down(long_text->get(index), level));
      }
    }
  }
  auto leveled_down = new T(texts);

  if (temp) {
    temp_text_.push_back(leveled_down);
  }

  return leveled_down;
}

Plaintext *CKKSEngine::level_down_(Plaintext *plaintext, int level, bool temp) {
  return level_down_<Plaintext, UnitPlaintext>(plaintext, level, temp);
}

Ciphertext *CKKSEngine::level_down_(Ciphertext *ciphertext, int level,
                                    bool temp) {
  return level_down_<Ciphertext, UnitCiphertext>(ciphertext, level, temp);
}

Plaintext *CKKSEngine::level_down(Plaintext *plaintext, int level) {
  const auto function_name = "Level Down Plaintext";
  require(function_name, plaintext, {});
  validate_target_level(function_name, level, plaintext->level());

  const auto temp = false;
  auto leveled_down = level_down_(plaintext, level, temp);

  clear_temp_data();

  return leveled_down;
}

Ciphertext *CKKSEngine::level_down(Ciphertext *ciphertext, int level) {
  const auto function_name = "Level Down Ciphertext";
  require(function_name, ciphertext, {Requirement::DUO_OR_TRIO});
  validate_target_level(function_name, level, ciphertext->level());

  const auto temp = false;
  auto leveled_down = level_down_(ciphertext, level, temp);

  clear_temp_data();

  return leveled_down;
}

}
