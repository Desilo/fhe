#include "ckks/engine.h"

namespace desilo::fhe {

template <typename T>
void CKKSEngine::require_encrypt_(const std::string &function_name, T *input,
                                  PublicKey *public_key, int level) {
  require_engine_compatibility(function_name, public_key);
  validate_target_level(function_name, {public_key}, level);
}

template <typename T>
Ciphertext *CKKSEngine::encrypt_(T *input, PublicKey *public_key,
                                 int input_size, int level) {
  auto plaintext = encode(input, input_size, level);
  auto encrypted = encrypt(plaintext, public_key);

  delete plaintext;

  return encrypted;
}

Ciphertext *CKKSEngine::encrypt(double *input, PublicKey *public_key,
                                int input_size, int level) {
  constexpr auto function_name = "Encrypt Double Buffer";
  require_encrypt_(function_name, input, public_key, level);
  return encrypt_(input, public_key, input_size, level);
}

Ciphertext *CKKSEngine::encrypt(double *input, PublicKey *public_key,
                                int input_size) {
  return encrypt(input, public_key, input_size, get_max_level());
}

Ciphertext *CKKSEngine::encrypt(std::complex<double> *input,
                                PublicKey *public_key, int input_size,
                                int level) {
  constexpr auto function_name = "Encrypt Complex Double Buffer";
  require_encrypt_(function_name, input, public_key, level);
  return encrypt_(input, public_key, input_size, level);
}

Ciphertext *CKKSEngine::encrypt(std::complex<double> *input,
                                PublicKey *public_key, int input_size) {
  return encrypt(input, public_key, input_size, get_max_level());
}

template <typename T>
void CKKSEngine::require_encrypt_(const std::string &function_name, T *input,
                                  SecretKey *secret_key, int level) {
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key}, level);
}

template <typename T>
Ciphertext *CKKSEngine::encrypt_(T *input, SecretKey *secret_key,
                                 int input_size, int level) {
  auto plaintext = encode(input, input_size, level);
  auto encrypted = encrypt(plaintext, secret_key);

  delete plaintext;

  return encrypted;
}

Ciphertext *CKKSEngine::encrypt(double *input, SecretKey *secret_key,
                                int input_size, int level) {
  constexpr auto function_name = "Encrypt Double Buffer With Secret Key";
  require_encrypt_(function_name, input, secret_key, level);
  return encrypt_(input, secret_key, input_size, level);
}

Ciphertext *CKKSEngine::encrypt(double *input, SecretKey *secret_key,
                                int input_size) {
  return encrypt(input, secret_key, input_size, get_max_level());
}

Ciphertext *CKKSEngine::encrypt(std::complex<double> *input,
                                SecretKey *secret_key, int input_size,
                                int level) {
  constexpr auto function_name =
      "Encrypt Complex Double Buffer With Secret Key";
  require_encrypt_(function_name, input, secret_key, level);
  return encrypt_(input, secret_key, input_size, level);
}

Ciphertext *CKKSEngine::encrypt(std::complex<double> *input,
                                SecretKey *secret_key, int input_size) {
  return encrypt(input, secret_key, input_size, get_max_level());
}

template <typename T>
void CKKSEngine::require_encrypt_(const std::string &function_name,
                                  std::vector<T> &input, PublicKey *public_key,
                                  int level, bool for_unit) {
  if (for_unit) {
    require_engine_compatibility(function_name, input);
  }
  require_engine_compatibility(function_name, public_key);
  validate_target_level(function_name, {public_key}, level);
}

template <typename T>
UnitCiphertext *CKKSEngine::encrypt_unit_(std::vector<T> &input,
                                          PublicKey *public_key, int level) {
  auto encoded = encode_unit(input, level);
  auto encrypted = core_->encrypt(encoded, public_key);

  delete encoded;

  return encrypted;
}

UnitCiphertext *CKKSEngine::encrypt_unit(std::vector<double> &input,
                                         PublicKey *public_key, int level) {
  constexpr auto function_name = "Encode Double Vector To Unit Ciphertext";
  bool for_unit = true;
  require_encrypt_(function_name, input, public_key, level, for_unit);
  return encrypt_unit_(input, public_key, level);
}

UnitCiphertext *CKKSEngine::encrypt_unit(std::vector<double> &input,
                                         PublicKey *public_key) {
  return encrypt_unit(input, public_key, get_max_level());
}

UnitCiphertext *
CKKSEngine::encrypt_unit(std::vector<std::complex<double>> &input,
                         PublicKey *public_key, int level) {
  constexpr auto function_name =
      "Encode Complex Double Vector To Unit Ciphertext";
  bool for_unit = true;
  require_encrypt_(function_name, input, public_key, level, for_unit);
  return encrypt_unit_(input, public_key, level);
}

UnitCiphertext *
CKKSEngine::encrypt_unit(std::vector<std::complex<double>> &input,
                         PublicKey *public_key) {
  return encrypt_unit(input, public_key, get_max_level());
}

template <typename T>
Ciphertext *CKKSEngine::encrypt_(std::vector<T> &input, PublicKey *public_key,
                                 int level) {
  auto plaintext = encode(input, level);
  auto encrypted = encrypt(plaintext, public_key);

  delete plaintext;

  return encrypted;
}

Ciphertext *CKKSEngine::encrypt(std::vector<double> &input,
                                PublicKey *public_key, int level) {
  constexpr auto function_name = "Encrypt Double Vector";
  bool for_unit = false;
  require_encrypt_(function_name, input, public_key, level, for_unit);
  return encrypt_(input, public_key, level);
}

Ciphertext *CKKSEngine::encrypt(std::vector<double> &input,
                                PublicKey *public_key) {
  return encrypt(input, public_key, get_max_level());
}

Ciphertext *CKKSEngine::encrypt(std::vector<std::complex<double>> &input,
                                PublicKey *public_key, int level) {
  constexpr auto function_name = "Encrypt Complex Double Vector";
  bool for_unit = false;
  require_encrypt_(function_name, input, public_key, level, for_unit);
  return encrypt_(input, public_key, level);
}

Ciphertext *CKKSEngine::encrypt(std::vector<std::complex<double>> &input,
                                PublicKey *public_key) {
  return encrypt(input, public_key, get_max_level());
}

template <typename T>
void CKKSEngine::require_encrypt_(const std::string &function_name, T *text,
                                  PublicKey *public_key) {
  require(function_name, text, {Requirement::NOT_RESCALED});
  require_engine_compatibility(function_name, public_key);
  require_key_compatibility(function_name, text, public_key);
}

UnitCiphertext *CKKSEngine::encrypt_unit(UnitPlaintext *unit_plaintext,
                                         PublicKey *public_key) {
  constexpr auto function_name = "Encrypt Unit Plaintext";
  require_encrypt_(function_name, unit_plaintext, public_key);

  auto encrypted = core_->encrypt(unit_plaintext, public_key);

  return encrypted;
}

Ciphertext *CKKSEngine::encrypt(Plaintext *plaintext, PublicKey *public_key) {
  constexpr auto function_name = "Encrypt Plaintext";
  require_encrypt_(function_name, plaintext, public_key);

  std::vector<UnitCiphertext *> ciphertexts;
  for (int index = 0; index < plaintext->size(); index++) {
    auto ciphertext = core_->encrypt(plaintext->get(index), public_key);
    ciphertexts.push_back(ciphertext);
  }

  return new Ciphertext(ciphertexts);
}

template <typename T>
void CKKSEngine::require_encrypt_(const std::string &function_name,
                                  std::vector<T> &input, SecretKey *secret_key,
                                  int level, bool for_unit) {
  if (for_unit) {
    require_engine_compatibility(function_name, input);
  }
  require_engine_compatibility(function_name, secret_key);
  validate_target_level(function_name, {secret_key}, level);
}

template <typename T>
UnitCiphertext *CKKSEngine::encrypt_unit_(std::vector<T> &input,
                                          SecretKey *secret_key, int level) {
  auto encoded = encode_unit(input, level);
  auto encrypted = core_->encrypt(encoded, secret_key);

  delete encoded;

  return encrypted;
}

UnitCiphertext *CKKSEngine::encrypt_unit(std::vector<double> &input,
                                         SecretKey *secret_key, int level) {
  constexpr auto function_name =
      "Encode Double Vector To Unit Ciphertext With Secret Key";
  bool for_unit = true;
  require_encrypt_(function_name, input, secret_key, level, for_unit);
  return encrypt_unit_(input, secret_key, level);
}

UnitCiphertext *CKKSEngine::encrypt_unit(std::vector<double> &input,
                                         SecretKey *secret_key) {
  return encrypt_unit(input, secret_key, get_max_level());
}

UnitCiphertext *
CKKSEngine::encrypt_unit(std::vector<std::complex<double>> &input,
                         SecretKey *secret_key, int level) {
  constexpr auto function_name =
      "Encode Complex Double Vector To Unit Ciphertext With Secret Key";
  bool for_unit = true;
  require_encrypt_(function_name, input, secret_key, level, for_unit);
  return encrypt_unit_(input, secret_key, level);
}

UnitCiphertext *
CKKSEngine::encrypt_unit(std::vector<std::complex<double>> &input,
                         SecretKey *secret_key) {
  return encrypt_unit(input, secret_key, get_max_level());
}

template <typename T>
Ciphertext *CKKSEngine::encrypt_(std::vector<T> &input, SecretKey *secret_key,
                                 int level) {
  auto plaintext = encode(input, level);
  auto encrypted = encrypt(plaintext, secret_key);

  delete plaintext;

  return encrypted;
}

Ciphertext *CKKSEngine::encrypt(std::vector<double> &input,
                                SecretKey *secret_key, int level) {
  constexpr auto function_name = "Encrypt Double Vector With Secret Key";
  bool for_unit = false;
  require_encrypt_(function_name, input, secret_key, level, for_unit);
  return encrypt_(input, secret_key, level);
}

Ciphertext *CKKSEngine::encrypt(std::vector<double> &input,
                                SecretKey *secret_key) {
  return encrypt(input, secret_key, get_max_level());
}

Ciphertext *CKKSEngine::encrypt(std::vector<std::complex<double>> &input,
                                SecretKey *secret_key, int level) {
  constexpr auto function_name =
      "Encrypt Complex Double Vector With Secret Key";
  bool for_unit = false;
  require_encrypt_(function_name, input, secret_key, level, for_unit);
  return encrypt_(input, secret_key, level);
}

Ciphertext *CKKSEngine::encrypt(std::vector<std::complex<double>> &input,
                                SecretKey *secret_key) {
  return encrypt(input, secret_key, get_max_level());
}

template <typename T>
void CKKSEngine::require_encrypt_(const std::string &function_name, T *text,
                                  SecretKey *secret_key) {
  require(function_name, text, {Requirement::NOT_RESCALED});
  require_engine_compatibility(function_name, secret_key);
  require_key_compatibility(function_name, text, secret_key);
}

UnitCiphertext *CKKSEngine::encrypt_unit(UnitPlaintext *unit_plaintext,
                                         SecretKey *secret_key) {
  constexpr auto function_name = "Encrypt Unit Plaintext With Secret Key";
  require_encrypt_(function_name, unit_plaintext, secret_key);

  auto encrypted = core_->encrypt(unit_plaintext, secret_key);

  return encrypted;
}

Ciphertext *CKKSEngine::encrypt(Plaintext *plaintext, SecretKey *secret_key) {
  constexpr auto function_name = "Encrypt Plaintext With Secret Key";
  require_encrypt_(function_name, plaintext, secret_key);

  std::vector<UnitCiphertext *> ciphertexts;
  for (int index = 0; index < plaintext->size(); index++) {
    auto ciphertext = core_->encrypt(plaintext->get(index), secret_key);
    ciphertexts.push_back(ciphertext);
  }

  return new Ciphertext(ciphertexts);
}

}
