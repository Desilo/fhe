#include "ckks/engine.h"

namespace desilo::fhe {

template <class T>
void CKKSEngine::require_multiply_(const std::string &function_name, T *text1,
                                   T *text2) {
  require(
      function_name, {text1, text2},
      {Requirement::DUO, Requirement::MATCH_SIZE, Requirement::POSITIVE_LEVEL});
}

template <class T> T *CKKSEngine::prepare_for_multiply(T *text, int level) {
  const auto temp = true;

  auto text_intt = text;

  if (text->level() > level) {
    text_intt = intt_(text, temp);
  }

  auto leveled_down = level_down_(text_intt, level, temp);
  auto rescaled = rescale_(leveled_down, temp);
  auto rescaled_ntt = ntt_(rescaled, temp);

  return rescaled_ntt;
}

template UnitCiphertext *
CKKSEngine::prepare_for_multiply(UnitCiphertext *unit_ciphertext, int level);
template UnitPlaintext *
CKKSEngine::prepare_for_multiply(UnitPlaintext *unit_plaintext, int level);

template Ciphertext *CKKSEngine::prepare_for_multiply(Ciphertext *ciphertext,
                                                      int level);
template Plaintext *CKKSEngine::prepare_for_multiply(Plaintext *plaintext,
                                                     int level);

UnitCiphertext *CKKSEngine::multiply(UnitCiphertext *unit_ciphertext1,
                                     UnitCiphertext *unit_ciphertext2) {
  const auto function_name = "Multiply Unit Ciphertexts";
  require_multiply_(function_name, unit_ciphertext1, unit_ciphertext2);

  auto min_level = std::min(unit_ciphertext1->level_, unit_ciphertext2->level_);

  auto input_unit_ciphertext1 =
      prepare_for_multiply(unit_ciphertext1, min_level);
  auto input_unit_ciphertext2 =
      prepare_for_multiply(unit_ciphertext2, min_level);

  auto multiplied =
      core_->multiply(input_unit_ciphertext1, input_unit_ciphertext2);

  clear_temp_data();

  return multiplied;
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext1,
                                 Ciphertext *ciphertext2) {
  const auto function_name = "Multiply Ciphertexts";
  require_multiply_(function_name, ciphertext1, ciphertext2);

  auto min_level = std::min(ciphertext1->level(), ciphertext2->level());

  auto input_ciphertext1 = prepare_for_multiply(ciphertext1, min_level);
  auto input_ciphertext2 = prepare_for_multiply(ciphertext2, min_level);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < input_ciphertext1->size(); index++) {
    unit_ciphertexts.push_back(core_->multiply(input_ciphertext1->get(index),
                                               input_ciphertext2->get(index)));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

template <class T>
void CKKSEngine::require_square_(const std::string &function_name, T *text) {
  require(function_name, {text},
          {Requirement::DUO, Requirement::POSITIVE_LEVEL});
}

UnitCiphertext *CKKSEngine::square(UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Square Unit Ciphertext";
  require_square_(function_name, unit_ciphertext);

  auto temp = true;
  auto rescaled = rescale_(unit_ciphertext, temp);
  auto rescaled_ntt = ntt_(rescaled, temp);

  auto squared = core_->square(rescaled_ntt);

  clear_temp_data();

  return squared;
}

Ciphertext *CKKSEngine::square(Ciphertext *ciphertext) {
  const auto function_name = "Square Ciphertext";
  require_square_(function_name, ciphertext);

  auto temp = true;
  auto rescaled = rescale_(ciphertext, temp);
  auto rescaled_ntt = ntt_(rescaled, temp);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < rescaled_ntt->size(); index++) {
    unit_ciphertexts.push_back(core_->square(rescaled_ntt->get(index)));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

template <class T>
void CKKSEngine::require_multiply_(const std::string &function_name, T *text1,
                                   T *text2,
                                   RelinearizationKey *relinearization_key) {
  bool for_multiply = true;
  require(
      function_name, {text1, text2},
      {Requirement::DUO, Requirement::MATCH_SIZE, Requirement::POSITIVE_LEVEL});
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text1, relinearization_key,
                            for_multiply);
  require_key_compatibility(function_name, text2, relinearization_key,
                            for_multiply);
}

UnitCiphertext *CKKSEngine::multiply(UnitCiphertext *unit_ciphertext1,
                                     UnitCiphertext *unit_ciphertext2,
                                     RelinearizationKey *relinearization_key) {
  const auto function_name = "Multiply Unit Ciphertexts Then Relinearize";
  require_multiply_(function_name, unit_ciphertext1, unit_ciphertext2,
                    relinearization_key);

  auto multiplied = multiply(unit_ciphertext1, unit_ciphertext2);
  auto relinearized = relinearize(multiplied, relinearization_key);

  delete multiplied;

  return relinearized;
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext1,
                                 Ciphertext *ciphertext2,
                                 RelinearizationKey *relinearization_key) {
  const auto function_name = "Multiply Ciphertexts Then Relinearize";
  require_multiply_(function_name, ciphertext1, ciphertext2,
                    relinearization_key);

  auto multiplied = multiply(ciphertext1, ciphertext2);
  auto relinearized = relinearize(multiplied, relinearization_key);

  delete multiplied;

  return relinearized;
}

template <class T>
void CKKSEngine::require_square_(const std::string &function_name, T *text,
                                 RelinearizationKey *relinearization_key) {
  bool for_multiply = true;
  require(function_name, {text},
          {Requirement::DUO, Requirement::POSITIVE_LEVEL});
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text, relinearization_key,
                            for_multiply);
}

UnitCiphertext *CKKSEngine::square(UnitCiphertext *unit_ciphertext,
                                   RelinearizationKey *relinearization_key) {
  const auto function_name = "Square Unit Ciphertext Then Relinearize";
  require_square_(function_name, unit_ciphertext, relinearization_key);

  auto squared = square(unit_ciphertext);
  auto relinearized = relinearize(squared, relinearization_key);

  delete squared;

  return relinearized;
}

Ciphertext *CKKSEngine::square(Ciphertext *ciphertext,
                               RelinearizationKey *relinearization_key) {
  const auto function_name = "Square Ciphertext Then Relinearize";
  require_square_(function_name, ciphertext, relinearization_key);

  auto squared = square(ciphertext);
  auto relinearized = relinearize(squared, relinearization_key);

  delete squared;

  return relinearized;
}

template <class T, class U>
void CKKSEngine::require_multiply_(const std::string &function_name,
                                   T *ciphertext, U *plaintext) {
  require(function_name, ciphertext,
          {Requirement::DUO_OR_TRIO, Requirement::POSITIVE_LEVEL});
  require(function_name, plaintext, {Requirement::POSITIVE_LEVEL});
  require(function_name, ciphertext, plaintext, {Requirement::MATCH_SIZE});
}

UnitCiphertext *CKKSEngine::multiply(UnitCiphertext *unit_ciphertext,
                                     UnitPlaintext *unit_plaintext) {
  const auto function_name = "Multiply Unit Ciphertext And Unit Plaintext";
  require_multiply_(function_name, unit_ciphertext, unit_plaintext);

  auto min_level = std::min(unit_ciphertext->level_, unit_plaintext->level_);
  const auto input_unit_ciphertext =
      prepare_for_multiply(unit_ciphertext, min_level);
  const auto input_unit_plaintext =
      prepare_for_multiply(unit_plaintext, min_level);

  auto multiplied =
      core_->multiply(input_unit_ciphertext, input_unit_plaintext);

  clear_temp_data();

  return multiplied;
}

UnitCiphertext *CKKSEngine::multiply(UnitPlaintext *unit_plaintext,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Multiply Unit Plaintext And Unit Ciphertext";
  require_multiply_(function_name, unit_ciphertext, unit_plaintext);

  return multiply(unit_ciphertext, unit_plaintext);
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext, Plaintext *plaintext) {
  const auto function_name = "Multiply Ciphertext And Plaintext";
  require_multiply_(function_name, ciphertext, plaintext);

  auto min_level = std::min(ciphertext->level(), plaintext->level());
  const auto input_ciphertext = prepare_for_multiply(ciphertext, min_level);
  const auto input_plaintext = prepare_for_multiply(plaintext, min_level);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < input_ciphertext->size(); index++) {
    unit_ciphertexts.push_back(core_->multiply(input_ciphertext->get(index),
                                               input_plaintext->get(index)));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::multiply(Plaintext *plaintext, Ciphertext *ciphertext) {
  const auto function_name = "Multiply Plaintext And Ciphertext";
  require_multiply_(function_name, ciphertext, plaintext);

  return multiply(ciphertext, plaintext);
}

template <class T, typename U>
void CKKSEngine::require_multiply_(const std::string &function_name, T *text,
                                   std::vector<U> &message) {
  require(function_name, text,
          {Requirement::DUO_OR_TRIO, Requirement::POSITIVE_LEVEL});
  require_engine_compatibility(function_name, text, message);
}

UnitCiphertext *CKKSEngine::multiply(UnitCiphertext *unit_ciphertext,
                                     std::vector<double> &message) {
  const auto function_name = "Multiply Unit Ciphertext And Double Vector";
  require_multiply_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto multiplied = multiply(unit_ciphertext, unit_plaintext);

  delete unit_plaintext;

  return multiplied;
}

UnitCiphertext *CKKSEngine::multiply(std::vector<double> &message,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Multiply Double Vector And Unit Ciphertext";
  require_multiply_(function_name, unit_ciphertext, message);

  return multiply(unit_ciphertext, message);
}

UnitCiphertext *
CKKSEngine::multiply(UnitCiphertext *unit_ciphertext,
                     std::vector<std::complex<double>> &message) {
  const auto function_name =
      "Multiply Unit Ciphertext And Complex Double Vector";
  require_multiply_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto multiplied = multiply(unit_ciphertext, unit_plaintext);

  delete unit_plaintext;

  return multiplied;
}

UnitCiphertext *CKKSEngine::multiply(std::vector<std::complex<double>> &message,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name =
      "Multiply Complex Double Vector And Unit Ciphertext";
  require_multiply_(function_name, unit_ciphertext, message);

  return multiply(unit_ciphertext, message);
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext,
                                 std::vector<double> &message) {
  const auto function_name = "Multiply Ciphertext And Double Vector";
  require_multiply_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto multiplied = multiply(ciphertext, plaintext);

  delete plaintext;

  return multiplied;
}

Ciphertext *CKKSEngine::multiply(std::vector<double> &message,
                                 Ciphertext *ciphertext) {
  const auto function_name = "Multiply Double Vector And Ciphertext";
  require_multiply_(function_name, ciphertext, message);

  return multiply(ciphertext, message);
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext,
                                 std::vector<std::complex<double>> &message) {
  const auto function_name = "Multiply Ciphertext And Complex Double Vector";
  require_multiply_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto multiplied = multiply(ciphertext, plaintext);

  delete plaintext;

  return multiplied;
}

Ciphertext *CKKSEngine::multiply(std::vector<std::complex<double>> &message,
                                 Ciphertext *ciphertext) {
  const auto function_name = "Multiply Complex Double Vector And Ciphertext";
  require_multiply_(function_name, ciphertext, message);

  return multiply(ciphertext, message);
}

void CKKSEngine::require_multiply_(const std::string &function_name,
                                   Ciphertext *ciphertext, int message_size) {
  require(function_name, ciphertext,
          {Requirement::DUO_OR_TRIO, Requirement::POSITIVE_LEVEL});
  require_engine_compatibility(function_name, ciphertext, message_size);
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext, double *message,
                                 int message_size) {
  const auto function_name = "Multiply Ciphertext And Double Buffer";
  require_multiply_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto multiplied = multiply(ciphertext, plaintext);

  delete plaintext;

  return multiplied;
}

Ciphertext *CKKSEngine::multiply(double *message, Ciphertext *ciphertext,
                                 int message_size) {
  const auto function_name = "Multiply Double Buffer And Ciphertext";
  require_multiply_(function_name, ciphertext, message_size);

  return multiply(ciphertext, message, message_size);
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext,
                                 std::complex<double> *message,
                                 int message_size) {
  const auto function_name = "Multiply Ciphertext And Complex Double Buffer";
  require_multiply_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto multiplied = multiply(ciphertext, plaintext);

  delete plaintext;

  return multiplied;
}

Ciphertext *CKKSEngine::multiply(std::complex<double> *message,
                                 Ciphertext *ciphertext, int message_size) {
  const auto function_name = "Multiply Complex Double Buffer And Ciphertext";
  require_multiply_(function_name, ciphertext, message_size);

  return multiply(ciphertext, message, message_size);
}

template <class T>
void CKKSEngine::require_multiply_(const std::string &function_name, T *text,
                                   bool allow_level_zero) {
  require(function_name, text,
          {Requirement::DUO_OR_TRIO, Requirement::NOT_RESCALED});
  if (!allow_level_zero) {
    require(function_name, text, {Requirement::POSITIVE_LEVEL});
  }
}

UnitCiphertext *CKKSEngine::multiply(UnitCiphertext *unit_ciphertext,
                                     double value) {
  const auto function_name = "Multiply Unit Ciphertext And Double Scalar";
  bool allow_level_zero = false;
  require_multiply_(function_name, unit_ciphertext, allow_level_zero);

  auto temp = true;
  auto intt_unit_ciphertext = intt_(unit_ciphertext, temp);

  auto multiplied = core_->multiply(intt_unit_ciphertext, value);

  clear_temp_data();

  return multiplied;
}

UnitCiphertext *CKKSEngine::multiply(double value,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Multiply Double Scalar And Unit Ciphertext";
  bool allow_level_zero = false;
  require_multiply_(function_name, unit_ciphertext, allow_level_zero);

  return multiply(unit_ciphertext, value);
}

UnitCiphertext *CKKSEngine::multiply(UnitCiphertext *unit_ciphertext,
                                     int64_t value) {
  const auto function_name = "Multiply Unit Ciphertext And Integer Scalar";
  bool allow_level_zero = true;
  require_multiply_(function_name, unit_ciphertext, allow_level_zero);

  auto temp = true;
  auto intt_unit_ciphertext = intt_(unit_ciphertext, temp);

  auto multiplied = core_->multiply(intt_unit_ciphertext, value);

  clear_temp_data();

  return multiplied;
}

UnitCiphertext *CKKSEngine::multiply(int64_t value,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Multiply Integer Scalar And Unit Ciphertext";
  bool allow_level_zero = true;
  require_multiply_(function_name, unit_ciphertext, allow_level_zero);

  return multiply(unit_ciphertext, value);
}

UnitCiphertext *CKKSEngine::multiply_imaginary(UnitCiphertext *unit_ciphertext,
                                               int64_t value) {
  const auto function_name =
      "Multiply Unit Ciphertext And Imaginary Integer Scalar";
  bool allow_level_zero = true;
  require_multiply_(function_name, unit_ciphertext, allow_level_zero);

  auto temp = true;
  auto ntt_unit_ciphertext = ntt_(unit_ciphertext, temp);
  auto unit_plaintext = core_->encode_imaginary(value, unit_ciphertext->level_);
  auto ntt_unit_plaintext = ntt_(unit_plaintext, temp);
  auto multiplied = core_->multiply(ntt_unit_ciphertext, ntt_unit_plaintext);

  delete unit_plaintext;

  clear_temp_data();

  if (!is_ntt_form(unit_ciphertext->flag_)) {
    auto intt_multiplied = intt(multiplied);

    delete multiplied;

    return intt_multiplied;
  }

  return multiplied;
}

UnitCiphertext *
CKKSEngine::multiply_imaginary(int64_t value, UnitCiphertext *unit_ciphertext) {
  const auto function_name =
      "Multiply Imaginary Integer Scalar And Unit Ciphertext";
  bool allow_level_zero = true;
  require_multiply_(function_name, unit_ciphertext, allow_level_zero);

  return multiply_imaginary(unit_ciphertext, value);
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext, double value) {
  const auto function_name = "Multiply Ciphertext And Double Scalar";
  bool allow_level_zero = false;
  require_multiply_(function_name, ciphertext, allow_level_zero);

  auto temp = true;
  auto intt_ciphertext = intt_(ciphertext, temp);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < intt_ciphertext->size(); index++) {
    unit_ciphertexts.push_back(
        core_->multiply(intt_ciphertext->get(index), value));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::multiply(double value, Ciphertext *ciphertext) {
  const auto function_name = "Multiply Double Scalar And Ciphertext";
  bool allow_level_zero = false;
  require_multiply_(function_name, ciphertext, allow_level_zero);

  return multiply(ciphertext, value);
}

Ciphertext *CKKSEngine::multiply(Ciphertext *ciphertext, int64_t value) {
  const auto function_name = "Multiply Ciphertext And Integer Scalar";
  bool allow_level_zero = true;
  require_multiply_(function_name, ciphertext, allow_level_zero);

  auto temp = true;
  auto intt_ciphertext = intt_(ciphertext, temp);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < intt_ciphertext->size(); index++) {
    unit_ciphertexts.push_back(
        core_->multiply(intt_ciphertext->get(index), value));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::multiply(int64_t value, Ciphertext *ciphertext) {
  const auto function_name = "Multiply Integer Scalar And Ciphertext";
  bool allow_level_zero = true;
  require_multiply_(function_name, ciphertext, allow_level_zero);

  return multiply(ciphertext, value);
}

Ciphertext *CKKSEngine::multiply_imaginary(Ciphertext *ciphertext,
                                           int64_t value) {
  const auto function_name = "Multiply Ciphertext And Imaginary Integer Scalar";
  bool allow_level_zero = true;
  require_multiply_(function_name, ciphertext, allow_level_zero);

  auto temp = true;
  auto unit_plaintext = core_->encode_imaginary(value, ciphertext->level());
  auto ntt_unit_plaintext = ntt_(unit_plaintext, temp);

  delete unit_plaintext;

  auto ntt_ciphertext = ntt_(ciphertext, temp);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ntt_ciphertext->size(); index++) {
    unit_ciphertexts.push_back(
        core_->multiply(ntt_ciphertext->get(index), ntt_unit_plaintext));
  }

  clear_temp_data();

  auto multiplied = new Ciphertext(unit_ciphertexts);

  if (!is_ntt_form(ciphertext->flag())) {
    auto intt_multiplied = intt(multiplied);

    delete multiplied;

    return intt_multiplied;
  }

  return multiplied;
}

Ciphertext *CKKSEngine::multiply_imaginary(int64_t value,
                                           Ciphertext *ciphertext) {
  const auto function_name = "Multiply Imaginary Integer Scalar And Ciphertext";
  bool allow_level_zero = true;
  require_multiply_(function_name, ciphertext, allow_level_zero);

  return multiply_imaginary(ciphertext, value);
}

}
