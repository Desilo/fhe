#include "ckks/engine.h"

namespace desilo::fhe {

template <class T>
void CKKSEngine::require_decrypt_(const std::string &function_name, T *text,
                                  SecretKey *secret_key) {
  require(function_name, text,
          {Requirement::DUO_OR_TRIO, Requirement::NOT_LEVEL_ZERO_RESCALED});
  require_engine_compatibility(function_name, secret_key);
  require_key_compatibility(function_name, text, secret_key);
}

std::vector<double> CKKSEngine::decrypt(UnitCiphertext *unit_ciphertext,
                                        SecretKey *secret_key) {
  constexpr auto function_name = "Decrypt Unit Ciphertext To Double Vector";
  require_decrypt_(function_name, unit_ciphertext, secret_key);

  auto unit_plaintext = decrypt_to_unit_plaintext(unit_ciphertext, secret_key);

  auto values = decode_unit(unit_plaintext);

  delete unit_plaintext;

  return values;
}

std::vector<double> CKKSEngine::decrypt(Ciphertext *ciphertext,
                                        SecretKey *secret_key) {
  constexpr auto function_name = "Decrypt To Double Vector";
  require_decrypt_(function_name, ciphertext, secret_key);

  auto plaintext = decrypt_to_plaintext(ciphertext, secret_key);

  auto values = decode(plaintext);

  delete plaintext;

  return values;
}

void CKKSEngine::decrypt_to_buffer(Ciphertext *ciphertext, double *output,
                                   SecretKey *secret_key) {
  constexpr auto function_name = "Decrypt To Double Buffer";
  require(function_name, {ciphertext}, {});
  require_decrypt_(function_name, ciphertext, secret_key);

  auto plaintext = decrypt_to_plaintext(ciphertext, secret_key);

  decode_to_buffer(plaintext, output);

  delete plaintext;
}

std::vector<std::complex<double>>
CKKSEngine::decrypt_complex(UnitCiphertext *unit_ciphertext,
                            SecretKey *secret_key) {
  constexpr auto function_name =
      "Decrypt Unit Ciphertext To Complex Double Vector";
  require_decrypt_(function_name, unit_ciphertext, secret_key);

  auto unit_plaintext = decrypt_to_unit_plaintext(unit_ciphertext, secret_key);

  auto values = decode_complex_unit_plaintext(unit_plaintext);

  delete unit_plaintext;

  return values;
}

std::vector<std::complex<double>>
CKKSEngine::decrypt_complex(Ciphertext *ciphertext, SecretKey *secret_key) {
  constexpr auto function_name = "Decrypt To Complex Double Vector";
  require_decrypt_(function_name, ciphertext, secret_key);

  auto plaintext = decrypt_to_plaintext(ciphertext, secret_key);

  auto long_values = decode_complex_plaintext(plaintext);

  delete plaintext;

  return long_values;
}

void CKKSEngine::decrypt_to_complex_buffer(Ciphertext *ciphertext,
                                           std::complex<double> *output,
                                           SecretKey *secret_key) {
  constexpr auto function_name = "Decrypt To Complex Double Buffer";
  require(function_name, {ciphertext}, {});
  require_decrypt_(function_name, ciphertext, secret_key);

  auto plaintext = decrypt_to_plaintext(ciphertext, secret_key);

  decode_complex_plaintext_to_buffer(plaintext, output);

  delete plaintext;
}

UnitPlaintext *
CKKSEngine::decrypt_to_unit_plaintext(UnitCiphertext *unit_ciphertext,
                                      SecretKey *secret_key) {
  constexpr auto function_name = "Decrypt Unit Ciphertext To Unit Plaintext";
  require_decrypt_(function_name, unit_ciphertext, secret_key);

  const auto polynomial_count = unit_ciphertext->polynomial_count();

  const auto temp = true;
  auto input_unit_ciphertext = unit_ciphertext;

  if (is_rescaled(unit_ciphertext->flag_)) {
    input_unit_ciphertext = level_down_(
        input_unit_ciphertext, input_unit_ciphertext->level_ - 1, temp);
  }

  UnitPlaintext *unit_plaintext;

  if (polynomial_count == 2) {
    input_unit_ciphertext = intt_(input_unit_ciphertext, temp);
    unit_plaintext = core_->decrypt_duo(input_unit_ciphertext, secret_key);
  } else {
    input_unit_ciphertext = ntt_(input_unit_ciphertext, temp);
    unit_plaintext = core_->decrypt_trio(input_unit_ciphertext, secret_key);
  }

  clear_temp_data();

  return unit_plaintext;
}

Plaintext *CKKSEngine::decrypt_to_plaintext(Ciphertext *ciphertext,
                                            SecretKey *secret_key) {
  constexpr auto function_name = "Decrypt To Plaintext";
  require_decrypt_(function_name, ciphertext, secret_key);

  const auto polynomial_count = ciphertext->polynomial_count();

  const auto temp = true;
  auto input_ciphertext = ciphertext;

  if (is_rescaled(ciphertext->flag())) {
    input_ciphertext =
        level_down_(input_ciphertext, input_ciphertext->level() - 1, temp);
  }

  if (polynomial_count == 2) {
    input_ciphertext = intt_(input_ciphertext, temp);
  } else {
    input_ciphertext = ntt_(input_ciphertext, temp);
  }

  std::vector<UnitPlaintext *> unit_plaintexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    auto unit_ciphertext = input_ciphertext->get(index);
    auto unit_plaintext =
        unit_ciphertext->polynomial_count() == 2
            ? core_->decrypt_duo(unit_ciphertext, secret_key)
            : core_->decrypt_trio(unit_ciphertext, secret_key);
    unit_plaintexts.push_back(unit_plaintext);
  }

  clear_temp_data();

  return new Plaintext(unit_plaintexts);
}

}
