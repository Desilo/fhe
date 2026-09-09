#include "ckks/engine.h"

namespace desilo::fhe {

UnitCiphertext *CKKSEngine::subtract(UnitCiphertext *unit_ciphertext1,
                                     UnitCiphertext *unit_ciphertext2) {
  const auto function_name = "Subtract Unit Ciphertexts";
  require_add_subtract_(function_name, unit_ciphertext1, unit_ciphertext2);

  auto [unit_ciphertext1_matched, unit_ciphertext2_matched] =
      match_form(unit_ciphertext1, unit_ciphertext2);

  UnitCiphertext *subtracted;

  if (unit_ciphertext1_matched->polynomial_count() >
      unit_ciphertext2_matched->polynomial_count()) {
    subtracted = core_->subtract_trio_by_duo(unit_ciphertext1_matched,
                                             unit_ciphertext2_matched);
  }

  else if (unit_ciphertext1_matched->polynomial_count() <
           unit_ciphertext2_matched->polynomial_count()) {
    subtracted = core_->subtract_duo_by_trio(unit_ciphertext1_matched,
                                             unit_ciphertext2_matched);
  }

  else {
    subtracted =
        core_->subtract(unit_ciphertext1_matched, unit_ciphertext2_matched);
  }

  clear_temp_data();

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Ciphertext *ciphertext1,
                                 Ciphertext *ciphertext2) {
  const auto function_name = "Subtract Ciphertexts";
  require_add_subtract_(function_name, ciphertext1, ciphertext2);

  auto [ciphertext1_matched, ciphertext2_matched] =
      match_form(ciphertext1, ciphertext2);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext1->size(); index++) {

    if (ciphertext1_matched->polynomial_count() >
        ciphertext2_matched->polynomial_count()) {
      unit_ciphertexts.push_back(core_->subtract_trio_by_duo(
          ciphertext1_matched->get(index), ciphertext2_matched->get(index)));
    }

    else if (ciphertext1_matched->polynomial_count() <
             ciphertext2_matched->polynomial_count()) {
      unit_ciphertexts.push_back(core_->subtract_duo_by_trio(
          ciphertext1_matched->get(index), ciphertext2_matched->get(index)));
    }

    else {
      unit_ciphertexts.push_back(core_->subtract(
          ciphertext1_matched->get(index), ciphertext2_matched->get(index)));
    }
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

void CKKSEngine::subtract_inplace(UnitCiphertext *unit_ciphertext1,
                                  UnitCiphertext *unit_ciphertext2) {
  const auto function_name = "Subtract Inplace Unit Ciphertexts";
  require_add_subtract_inplace_(function_name, unit_ciphertext1,
                                unit_ciphertext2);

  UnitCiphertext *subtracted;
  core_->subtract_inplace(unit_ciphertext1, unit_ciphertext2);
}

void CKKSEngine::subtract_inplace(Ciphertext *ciphertext1,
                                  Ciphertext *ciphertext2) {
  const auto function_name = "Subtract Inplace Ciphertexts";
  require_add_subtract_inplace_(function_name, ciphertext1, ciphertext2);

  for (int index = 0; index < ciphertext1->size(); index++) {
    core_->subtract_inplace(ciphertext1->get(index), ciphertext2->get(index));
  }
}

UnitCiphertext *CKKSEngine::subtract(UnitCiphertext *unit_ciphertext,
                                     UnitPlaintext *unit_plaintext) {
  const auto function_name = "Subtract Unit Ciphertext By Unit Plaintext";
  require_add_subtract_(function_name, unit_ciphertext, unit_plaintext);

  auto [unit_ciphertext_matched, unit_plaintext_matched] =
      match_form(unit_ciphertext, unit_plaintext);

  auto subtracted =
      core_->subtract(unit_ciphertext_matched, unit_plaintext_matched);

  clear_temp_data();

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Ciphertext *ciphertext, Plaintext *plaintext) {
  const auto function_name = "Subtract Ciphertext By Plaintext";
  require_add_subtract_(function_name, ciphertext, plaintext);

  auto [ciphertext_matched, plaintext_matched] =
      match_form(ciphertext, plaintext);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext_matched->size(); index++) {
    unit_ciphertexts.push_back(core_->subtract(ciphertext_matched->get(index),
                                               plaintext_matched->get(index)));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

UnitCiphertext *CKKSEngine::subtract(UnitPlaintext *unit_plaintext,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Subtract Unit Plaintext By Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext, unit_plaintext);

  auto [unit_ciphertext_matched, unit_plaintext_matched] =
      match_form(unit_ciphertext, unit_plaintext);

  auto subtracted =
      core_->subtract(unit_plaintext_matched, unit_ciphertext_matched);

  clear_temp_data();

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Plaintext *plaintext, Ciphertext *ciphertext) {
  const auto function_name = "Subtract Plaintext By Ciphertext";
  require_add_subtract_(function_name, ciphertext, plaintext);

  auto [ciphertext_matched, plaintext_matched] =
      match_form(ciphertext, plaintext);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext_matched->size(); index++) {
    unit_ciphertexts.push_back(core_->subtract(plaintext_matched->get(index),
                                               ciphertext_matched->get(index)));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

UnitCiphertext *CKKSEngine::subtract(UnitCiphertext *unit_ciphertext,
                                     std::vector<double> &message) {
  const auto function_name = "Subtract Unit Ciphertext By Double Vector";
  require_add_subtract_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto subtracted = subtract(unit_ciphertext, unit_plaintext);

  delete unit_plaintext;

  return subtracted;
}

UnitCiphertext *CKKSEngine::subtract(std::vector<double> &message,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Subtract Double Vector By Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto subtracted = subtract(unit_plaintext, unit_ciphertext);

  delete unit_plaintext;

  return subtracted;
}

UnitCiphertext *
CKKSEngine::subtract(UnitCiphertext *unit_ciphertext,
                     std::vector<std::complex<double>> &message) {
  const auto function_name =
      "Subtract Unit Ciphertext By Complex Double Vector";
  require_add_subtract_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto subtracted = subtract(unit_ciphertext, unit_plaintext);

  delete unit_plaintext;

  return subtracted;
}

UnitCiphertext *CKKSEngine::subtract(std::vector<std::complex<double>> &message,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name =
      "Subtract Complex Double Vector By Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext, message);

  auto unit_plaintext = encode_unit(message, unit_ciphertext->level_);
  auto subtracted = subtract(unit_plaintext, unit_ciphertext);

  delete unit_plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Ciphertext *ciphertext,
                                 std::vector<double> &message) {
  const auto function_name = "Subtract Ciphertext By Double Vector";
  require_add_subtract_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto subtracted = subtract(ciphertext, plaintext);

  delete plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(std::vector<double> &message,
                                 Ciphertext *ciphertext) {
  const auto function_name = "Subtract Double Vector By Ciphertext";
  require_add_subtract_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto subtracted = subtract(plaintext, ciphertext);

  delete plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Ciphertext *ciphertext,
                                 std::vector<std::complex<double>> &message) {
  const auto function_name = "Subtract Ciphertext By Complex Double Vector";
  require_add_subtract_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto subtracted = subtract(ciphertext, plaintext);

  delete plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(std::vector<std::complex<double>> &message,
                                 Ciphertext *ciphertext) {
  const auto function_name = "Subtract Complex Double Vector By Ciphertext";
  require_add_subtract_(function_name, ciphertext, message);

  auto plaintext = encode(message, ciphertext->level());
  auto subtracted = subtract(plaintext, ciphertext);

  delete plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Ciphertext *ciphertext, double *message,
                                 int message_size) {
  const auto function_name = "Subtract Ciphertext By Double Buffer";
  require_add_subtract_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto subtracted = subtract(ciphertext, plaintext);

  delete plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(double *message, Ciphertext *ciphertext,
                                 int message_size) {
  const auto function_name = "Subtract Double Buffer By Ciphertext";
  require_add_subtract_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto subtracted = subtract(plaintext, ciphertext);

  delete plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Ciphertext *ciphertext,
                                 std::complex<double> *message,
                                 int message_size) {
  const auto function_name = "Subtract Ciphertext By Complex Double Buffer";
  require_add_subtract_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto subtracted = subtract(ciphertext, plaintext);

  delete plaintext;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(std::complex<double> *message,
                                 Ciphertext *ciphertext, int message_size) {
  const auto function_name = "Subtract Complex Double Buffer By Ciphertext";
  require_add_subtract_(function_name, ciphertext, message_size);

  auto plaintext = encode(message, message_size, ciphertext->level());
  auto subtracted = subtract(plaintext, ciphertext);

  delete plaintext;

  return subtracted;
}

UnitCiphertext *CKKSEngine::subtract(UnitCiphertext *unit_ciphertext,
                                     double value) {
  const auto function_name = "Subtract Unit Ciphertext By Double Scalar";
  require_add_subtract_(function_name, unit_ciphertext);

  return add(unit_ciphertext, -value);
}

UnitCiphertext *CKKSEngine::subtract(double value,
                                     UnitCiphertext *unit_ciphertext) {
  const auto function_name = "Subtract Double Scalar By Unit Ciphertext";
  require_add_subtract_(function_name, unit_ciphertext);

  auto negated = negate(unit_ciphertext);
  auto subtracted = add(value, negated);

  delete negated;

  return subtracted;
}

Ciphertext *CKKSEngine::subtract(Ciphertext *ciphertext, double value) {
  const auto function_name = "Subtract Ciphertext By Double Scalar";
  require_add_subtract_(function_name, ciphertext);

  return add(ciphertext, -value);
}

Ciphertext *CKKSEngine::subtract(double value, Ciphertext *ciphertext) {
  const auto function_name = "Subtract Double Scalar By Ciphertext";
  require_add_subtract_(function_name, ciphertext);

  auto negated = negate(ciphertext);
  auto subtracted = add(value, negated);

  delete negated;

  return subtracted;
}

}
