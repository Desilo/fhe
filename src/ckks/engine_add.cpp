#include "ckks/engine.h"

namespace desilo::fhe {

template <class T>
void CKKSEngine::require_add_subtract_(const std::string &function_name,
                                       T *text1, T *text2) {
  require(function_name, {text1, text2},
          {Requirement::DUO_OR_TRIO, Requirement::MATCH_CKKS_SCALE,
           Requirement::MATCH_SIZE});
}

template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  UnitCiphertext *text1, UnitCiphertext *text2);
template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  Ciphertext *text1, Ciphertext *text2);

template <class T>
void CKKSEngine::require_add_subtract_inplace_(const std::string &function_name,
                                               T *text1, T *text2) {

  require(function_name, {text1, text2},
          {Requirement::DUOS_OR_TRIOS, Requirement::MATCH_CKKS_SCALE,
           Requirement::MATCH_SIZE, Requirement::MATCH_LEVEL,
           Requirement::MATCH_NTT, Requirement::MATCH_RESCALED});
}

template void
CKKSEngine::require_add_subtract_inplace_(const std::string &function_name,
                                          UnitCiphertext *text1,
                                          UnitCiphertext *text2);
template void
CKKSEngine::require_add_subtract_inplace_(const std::string &function_name,
                                          Ciphertext *text1, Ciphertext *text2);

template <class T>
std::tuple<T *, T *> CKKSEngine::match_form(T *text1, T *text2) {
  const auto temp = true;
  const auto ntt_form = is_ntt_form(text1->flag());

  auto text1_intt = text1;
  auto text2_intt = text2;

  if (!ntt_form) {
    text1_intt = intt_(text1, temp);
    text2_intt = intt_(text2, temp);
  } else if (text1->level() > text2->level()) {
    text1_intt = intt_(text1, temp);
  } else if (text1->level() < text2->level()) {
    text2_intt = intt_(text2, temp);
  }

  const auto min_level = std::min(text1->level(), text2->level());
  auto text1_matched = level_down_(text1_intt, min_level, temp);
  auto text2_matched = level_down_(text2_intt, min_level, temp);

  if (is_rescaled(text1_matched->flag()) !=
      is_rescaled(text2_matched->flag())) {
    if (!is_rescaled(text1_matched->flag())) {
      text1_matched = rescale_(text1_matched, temp);
    } else {
      text2_matched = rescale_(text2_matched, temp);
    }
  }

  if (ntt_form) {
    text1_matched = ntt_(text1_matched, temp);
    text2_matched = ntt_(text2_matched, temp);
  }

  return {text1_matched, text2_matched};
}

template std::tuple<UnitCiphertext *, UnitCiphertext *>
CKKSEngine::match_form(UnitCiphertext *unit_ciphertext1,
                       UnitCiphertext *unit_ciphertext2);
template std::tuple<Ciphertext *, Ciphertext *>
CKKSEngine::match_form(Ciphertext *ciphertext1, Ciphertext *ciphertext2);

UnitCiphertext *CKKSEngine::add(UnitCiphertext *unit_ciphertext1,
                                UnitCiphertext *unit_ciphertext2) {
  const auto function_name = "Add Unit Ciphertexts";
  require_add_subtract_(function_name, unit_ciphertext1, unit_ciphertext2);

  auto [unit_ciphertext1_matched, unit_ciphertext2_matched] =
      match_form(unit_ciphertext1, unit_ciphertext2);

  UnitCiphertext *added;

  if (unit_ciphertext1_matched->polynomial_count() >
      unit_ciphertext2_matched->polynomial_count()) {
    added = core_->add_trio_and_duo(unit_ciphertext1_matched,
                                    unit_ciphertext2_matched);
  }

  else if (unit_ciphertext1_matched->polynomial_count() <
           unit_ciphertext2_matched->polynomial_count()) {
    added = core_->add_trio_and_duo(unit_ciphertext2_matched,
                                    unit_ciphertext1_matched);
  }

  else {
    added = core_->add(unit_ciphertext1_matched, unit_ciphertext2_matched);
  }

  clear_temp_data();

  return added;
}

Ciphertext *CKKSEngine::add(Ciphertext *ciphertext1, Ciphertext *ciphertext2) {
  const auto function_name = "Add Ciphertexts";
  require_add_subtract_(function_name, ciphertext1, ciphertext2);

  auto [ciphertext1_matched, ciphertext2_matched] =
      match_form(ciphertext1, ciphertext2);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext1_matched->size(); index++) {

    if (ciphertext1_matched->polynomial_count() >
        ciphertext2_matched->polynomial_count()) {
      unit_ciphertexts.push_back(core_->add_trio_and_duo(
          ciphertext1_matched->get(index), ciphertext2_matched->get(index)));
    }

    else if (ciphertext1_matched->polynomial_count() <
             ciphertext2_matched->polynomial_count()) {
      unit_ciphertexts.push_back(core_->add_trio_and_duo(
          ciphertext2_matched->get(index), ciphertext1_matched->get(index)));
    }

    else {
      unit_ciphertexts.push_back(core_->add(ciphertext1_matched->get(index),
                                            ciphertext2_matched->get(index)));
    }
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

void CKKSEngine::add_inplace(UnitCiphertext *unit_ciphertext1,
                             UnitCiphertext *unit_ciphertext2) {
  const auto function_name = "Add Inplace Unit Ciphertexts";
  require_add_subtract_inplace_(function_name, unit_ciphertext1,
                                unit_ciphertext2);

  core_->add_inplace(unit_ciphertext1, unit_ciphertext2);
}

void CKKSEngine::add_inplace(Ciphertext *ciphertext1, Ciphertext *ciphertext2) {
  const auto function_name = "Add Inplace Ciphertexts";
  require_add_subtract_inplace_(function_name, ciphertext1, ciphertext2);

  for (int index = 0; index < ciphertext1->size(); index++) {
    core_->add_inplace(ciphertext1->get(index), ciphertext2->get(index));
  }
}

template <class T, class U>
void CKKSEngine::require_add_subtract_(const std::string &function_name,
                                       T *ciphertext, U *plaintext) {
  require(function_name, ciphertext, {Requirement::DUO_OR_TRIO});
  require(function_name, plaintext, {});
  require(function_name, ciphertext, plaintext,
          {Requirement::MATCH_CKKS_SCALE, Requirement::MATCH_SIZE});
}

template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  UnitCiphertext *unit_ciphertext,
                                  UnitPlaintext *unit_plaintext);
template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  Ciphertext *ciphertext, Plaintext *plaintext);

template <class T, class U>
std::tuple<T *, U *> CKKSEngine::match_form(T *ciphertext, U *plaintext) {
  const auto temp = true;
  const auto ntt_form = is_ntt_form(ciphertext->flag());

  auto ciphertext_intt = ciphertext;
  auto plaintext_intt = intt_(plaintext, temp);

  if (!ntt_form) {
    ciphertext_intt = intt_(ciphertext, temp);
  } else if (ciphertext->level() > plaintext->level()) {
    ciphertext_intt = intt_(ciphertext, temp);
  }

  const auto min_level = std::min(ciphertext->level(), plaintext->level());
  auto ciphertext_matched = level_down_(ciphertext_intt, min_level, temp);
  auto plaintext_matched = level_down_(plaintext_intt, min_level, temp);

  if (is_rescaled(ciphertext_matched->flag()) !=
      is_rescaled(plaintext_matched->flag())) {
    if (!is_rescaled(ciphertext_matched->flag())) {
      ciphertext_matched = rescale_(ciphertext_matched, temp);
    } else {
      plaintext_matched = rescale_(plaintext_matched, temp);
    }
  }

  if (ntt_form) {
    ciphertext_matched = ntt_(ciphertext_matched, temp);
  }

  return {ciphertext_matched, plaintext_matched};
}

template std::tuple<UnitCiphertext *, UnitPlaintext *>
CKKSEngine::match_form(UnitCiphertext *unit_ciphertext,
                       UnitPlaintext *unit_plaintext);
template std::tuple<Ciphertext *, Plaintext *>
CKKSEngine::match_form(Ciphertext *ciphertext, Plaintext *plaintext);

UnitCiphertext *CKKSEngine::add(UnitCiphertext *unit_ciphertext,
                                UnitPlaintext *unit_plaintext) {
  const auto function_name = "Add Unit Ciphertext And Unit Plaintext";
  require_add_subtract_(function_name, unit_ciphertext, unit_plaintext);

  auto [unit_ciphertext_matched, unit_plaintext_matched] =
      match_form(unit_ciphertext, unit_plaintext);

  auto added = core_->add(unit_ciphertext_matched, unit_plaintext_matched);

  clear_temp_data();

  return added;
}

UnitCiphertext *CKKSEngine::add(UnitPlaintext *unit_plaintext,
                                UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Add Unit Plaintext And Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext, unit_plaintext);

  return add(unit_ciphertext, unit_plaintext);
}

Ciphertext *CKKSEngine::add(Ciphertext *ciphertext, Plaintext *plaintext) {
  const auto function_name = "Add Ciphertext And Plaintext";
  require_add_subtract_(function_name, ciphertext, plaintext);

  auto [ciphertext_matched, plaintext_matched] =
      match_form(ciphertext, plaintext);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext_matched->size(); index++) {
    unit_ciphertexts.push_back(core_->add(ciphertext_matched->get(index),
                                          plaintext_matched->get(index)));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::add(Plaintext *plaintext, Ciphertext *ciphertext) {
  const auto function_name = "Add Plaintext And Ciphertext";
  require_add_subtract_(function_name, ciphertext, plaintext);

  return add(ciphertext, plaintext);
}

template <class T, class U>
void CKKSEngine::require_add_subtract_inplace_(const std::string &function_name,
                                               T *ciphertext, U *plaintext) {
  require(function_name, ciphertext, {Requirement::DUO_OR_TRIO});
  require(function_name, plaintext, {});
  require(function_name, ciphertext, plaintext,
          {Requirement::MATCH_CKKS_SCALE, Requirement::MATCH_SIZE,
           Requirement::MATCH_LEVEL, Requirement::MATCH_RESCALED});
}

template void
CKKSEngine::require_add_subtract_inplace_(const std::string &function_name,
                                          UnitCiphertext *unit_ciphertext,
                                          UnitPlaintext *unit_plaintext);
template void
CKKSEngine::require_add_subtract_inplace_(const std::string &function_name,
                                          Ciphertext *ciphertext,
                                          Plaintext *plaintext);

template <class T, class U>
std::tuple<T *, U *> CKKSEngine::match_form_inplace(T *ciphertext,
                                                    U *plaintext) {
  const auto temp = true;
  const auto ntt_form = is_ntt_form(ciphertext->flag());

  U *plaintext_matched;
  if (ntt_form) {
    plaintext_matched = ntt_(plaintext, temp);
  } else {
    plaintext_matched = intt_(plaintext, temp);
  }

  return {ciphertext, plaintext_matched};
}
template std::tuple<UnitCiphertext *, UnitPlaintext *>
CKKSEngine::match_form_inplace(UnitCiphertext *unit_ciphertext,
                               UnitPlaintext *unit_plaintext);
template std::tuple<Ciphertext *, Plaintext *>
CKKSEngine::match_form_inplace(Ciphertext *ciphertext, Plaintext *plaintext);

void CKKSEngine::add_inplace(UnitCiphertext *unit_ciphertext,
                             UnitPlaintext *unit_plaintext) {
  const auto function_name = "Add Inplace Unit Ciphertext And Unit Plaintext";
  require_add_subtract_inplace_(function_name, unit_ciphertext, unit_plaintext);

  auto [unit_ciphertext_matched, unit_plaintext_matched] =
      match_form_inplace(unit_ciphertext, unit_plaintext);

  core_->add_inplace(unit_ciphertext_matched, unit_plaintext_matched);
}

void CKKSEngine::add_inplace(UnitPlaintext *unit_plaintext,
                             UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Add Inplace Unit Plaintext And Unit Ciphertext";
  require_add_subtract_inplace_(function_name, unit_ciphertext, unit_plaintext);

  add_inplace(unit_ciphertext, unit_plaintext);
}

void CKKSEngine::add_inplace(Ciphertext *ciphertext, Plaintext *plaintext) {
  const auto function_name = "Add Inplace Ciphertext And Plaintext";
  require_add_subtract_inplace_(function_name, ciphertext, plaintext);

  auto [ciphertext_matched, plaintext_matched] =
      match_form_inplace(ciphertext, plaintext);

  for (int index = 0; index < ciphertext->size(); index++) {
    core_->add_inplace(ciphertext_matched->get(index),
                       plaintext_matched->get(index));
  }
}

void CKKSEngine::add_inplace(Plaintext *plaintext, Ciphertext *ciphertext) {
  const auto function_name = "Add Inplace Plaintext And Ciphertext";
  require_add_subtract_inplace_(function_name, ciphertext, plaintext);

  add_inplace(ciphertext, plaintext);
}

template <class T, typename U>
void CKKSEngine::require_add_subtract_(const std::string &function_name,
                                       T *text, std::vector<U> &message) {
  require(function_name, text, {});
  require_engine_compatibility(function_name, text, message);
}

template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  UnitCiphertext *text,
                                  std::vector<double> &message);
template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  UnitCiphertext *text,
                                  std::vector<std::complex<double>> &message);
template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  Ciphertext *text,
                                  std::vector<double> &message);
template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  Ciphertext *text,
                                  std::vector<std::complex<double>> &message);

UnitCiphertext *CKKSEngine::add(UnitCiphertext *unit_ciphertext,
                                std::vector<double> &message) {
  const auto function_name = "Add Unit Ciphertext And Double Vector";
  require_add_subtract_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto added = add(unit_ciphertext, unit_plaintext);

  delete unit_plaintext;

  return added;
}

UnitCiphertext *CKKSEngine::add(std::vector<double> &message,
                                UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Add Double Vector And Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext, message);

  return add(unit_ciphertext, message);
}

UnitCiphertext *CKKSEngine::add(UnitCiphertext *unit_ciphertext,
                                std::vector<std::complex<double>> &message) {
  const auto function_name = "Add Unit Ciphertext And Complex Double Vector";
  require_add_subtract_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto added = add(unit_ciphertext, unit_plaintext);

  delete unit_plaintext;

  return added;
}

UnitCiphertext *CKKSEngine::add(std::vector<std::complex<double>> &message,
                                UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Add Complex Double Vector And Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext, message);

  return add(unit_ciphertext, message);
}

Ciphertext *CKKSEngine::add(Ciphertext *ciphertext,
                            std::vector<double> &message) {
  const auto function_name = "Add Ciphertext And Double Vector";
  require_add_subtract_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto added = add(ciphertext, plaintext);

  delete plaintext;

  return added;
}

Ciphertext *CKKSEngine::add(std::vector<double> &message,
                            Ciphertext *ciphertext) {
  const auto function_name = "Add Double Vector And Ciphertext";
  require_add_subtract_(function_name, ciphertext, message);

  return add(ciphertext, message);
}

Ciphertext *CKKSEngine::add(Ciphertext *ciphertext,
                            std::vector<std::complex<double>> &message) {
  const auto function_name = "Add Ciphertext And Complex Double Vector";
  require_add_subtract_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto added = add(ciphertext, plaintext);

  delete plaintext;

  return added;
}

Ciphertext *CKKSEngine::add(std::vector<std::complex<double>> &message,
                            Ciphertext *ciphertext) {
  const auto function_name = "Add Complex Double Vector And Ciphertext";
  require_add_subtract_(function_name, ciphertext, message);

  return add(ciphertext, message);
}

void CKKSEngine::require_add_subtract_(const std::string &function_name,
                                       Ciphertext *ciphertext,
                                       int message_size) {
  require(function_name, ciphertext, {});
  require_engine_compatibility(function_name, ciphertext, message_size);
}

Ciphertext *CKKSEngine::add(Ciphertext *ciphertext, double *message,
                            int message_size) {
  const auto function_name = "Add Ciphertext And Double Buffer";
  require_add_subtract_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto added = add(ciphertext, plaintext);

  delete plaintext;

  return added;
}

Ciphertext *CKKSEngine::add(double *message, Ciphertext *ciphertext,
                            int message_size) {
  const auto function_name = "Add Double Buffer And Ciphertext";
  require_add_subtract_(function_name, ciphertext, message_size);

  return add(ciphertext, message, message_size);
}

Ciphertext *CKKSEngine::add(Ciphertext *ciphertext,
                            std::complex<double> *message, int message_size) {
  const auto function_name = "Add Ciphertext And Complex Double Buffer";
  require_add_subtract_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto added = add(ciphertext, plaintext);

  delete plaintext;

  return added;
}

Ciphertext *CKKSEngine::add(std::complex<double> *message,
                            Ciphertext *ciphertext, int message_size) {
  const auto function_name = "Add Complex Double Buffer And Ciphertext";
  require_add_subtract_(function_name, ciphertext, message_size);

  return add(ciphertext, message, message_size);
}

template <class T>
void CKKSEngine::require_add_subtract_(const std::string &function_name,
                                       T *text) {
  require(function_name, text, {});
}

template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  UnitCiphertext *text);
template void
CKKSEngine::require_add_subtract_(const std::string &function_name,
                                  Ciphertext *text);

UnitCiphertext *CKKSEngine::add(UnitCiphertext *unit_ciphertext, double value) {
  const auto function_name = "Add Unit Ciphertext And Double Scalar";
  require_add_subtract_(function_name, unit_ciphertext);

  UnitCiphertext *added;

  if (is_ntt_form(unit_ciphertext->flag_) ||
      is_rescaled(unit_ciphertext->flag_)) {
    const auto slot_count = get_slot_count();

    std::vector<double> message(slot_count, value);

    added = add(unit_ciphertext, message);
  } else {
    added = core_->add(unit_ciphertext, value);
  }

  return added;
}

UnitCiphertext *CKKSEngine::add(double value, UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Add Double Scalar And Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext);

  return add(unit_ciphertext, value);
}

Ciphertext *CKKSEngine::add(Ciphertext *ciphertext, double value) {
  const auto function_name = "Add Ciphertext And Double Scalar";
  require_add_subtract_(function_name, ciphertext);

  std::vector<UnitCiphertext *> unit_ciphertexts;

  Ciphertext *added;

  if (is_ntt_form(ciphertext->flag()) || is_rescaled(ciphertext->flag())) {
    const auto slot_count = get_slot_count();

    std::vector<double> message(ciphertext->size() * slot_count, value);

    added = add(ciphertext, message);
  } else {
    for (int index = 0; index < ciphertext->size(); index++) {
      unit_ciphertexts.push_back(core_->add(ciphertext->get(index), value));
    }

    added = new Ciphertext(unit_ciphertexts);
  }

  return added;
}

Ciphertext *CKKSEngine::add(double value, Ciphertext *ciphertext) {
  const auto function_name = "Add Double Scalar And Ciphertext";
  require_add_subtract_(function_name, ciphertext);

  return add(ciphertext, value);
}

}
