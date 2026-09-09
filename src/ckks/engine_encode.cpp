#include "ckks/encode.h"
#include "ckks/engine.h"

namespace desilo::fhe {

UnitPlaintext *CKKSEngine::encode_unit(std::vector<double> &input) {
  return encode_unit(input, get_max_level());
}

UnitPlaintext *CKKSEngine::encode_unit(std::vector<double> &input, int level) {
  const auto function_name = "Encode Double Vector To Unit Plaintext";
  require_engine_compatibility(function_name, input);
  validate_target_level(function_name, level);

  auto padded = core_->pad(input);
  bool include_special = false;

  return core_->encode(padded, level, include_special);
}

UnitPlaintext *
CKKSEngine::encode_unit(std::vector<std::complex<double>> &input) {
  return encode_unit(input, get_max_level());
}

UnitPlaintext *CKKSEngine::encode_unit(std::vector<std::complex<double>> &input,
                                       int level) {
  const auto function_name = "Encode Complex Double Vector To Unit Plaintext";
  require_engine_compatibility(function_name, input);
  validate_target_level(function_name, level);

  auto padded = core_->pad(input);
  bool include_special = false;

  return core_->encode(padded, level, include_special);
}

template <typename T>
Plaintext *CKKSEngine::encode_(std::vector<T> &input, int level) {
  auto slot_count = core_->get_slot_count();
  std::vector<UnitPlaintext *> unit_plaintexts;

  if (input.size() == 0) {
    std::vector<T> empty;
    auto padded = core_->pad(empty);
    bool include_special = false;

    auto unit_plaintext = core_->encode(padded, level, include_special);
    unit_plaintexts.push_back(unit_plaintext);
  }

  for (size_t index = 0; index < input.size(); index += slot_count) {
    auto end_index = std::min(index + slot_count, input.size());
    std::vector input_slice(input.begin() + index, input.begin() + end_index);

    auto padded = core_->pad(input_slice);
    bool include_special = false;

    auto unit_plaintext = core_->encode(padded, level, include_special);
    unit_plaintexts.push_back(unit_plaintext);
  }

  return new Plaintext(unit_plaintexts);
}

Plaintext *CKKSEngine::encode(std::vector<double> &input) {
  return encode(input, get_max_level());
}

Plaintext *CKKSEngine::encode(std::vector<double> &input, int level) {
  const auto function_name = "Encode Double Vector";
  validate_target_level(function_name, level);
  return encode_(input, level);
}

Plaintext *CKKSEngine::encode(std::vector<std::complex<double>> &input) {
  return encode(input, get_max_level());
}

Plaintext *CKKSEngine::encode(std::vector<std::complex<double>> &input,
                              int level) {
  const auto function_name = "Encode Complex Double Vector";
  validate_target_level(function_name, level);
  return encode_(input, level);
}

template <typename T>
Plaintext *CKKSEngine::encode_(T *input, int input_size, int level) {
  auto slot_count = core_->get_slot_count();
  std::vector<UnitPlaintext *> unit_plaintexts;

  if (input_size == 0) {
    std::vector<T> empty;
    auto padded = core_->pad(empty);
    bool include_special = false;

    auto unit_plaintext = core_->encode(padded, level, include_special);
    unit_plaintexts.push_back(unit_plaintext);
  }

  std::vector<T *> padded_buffers;
  for (int index = 0; index < input_size; index += slot_count) {
    auto unit_input_size = std::min(slot_count, input_size - index);
    auto padded = core_->pad(&input[index], unit_input_size);
    bool include_special = false;

    auto unit_plaintext = core_->encode(padded, level, include_special);
    unit_plaintexts.push_back(unit_plaintext);

    if (unit_input_size < slot_count) {
      padded_buffers.push_back(padded);
    }
  }

  for (auto &buffer : padded_buffers) {
    delete[] buffer;
  }

  return new Plaintext(unit_plaintexts);
}

Plaintext *CKKSEngine::encode(double *input, int input_size) {
  return encode(input, input_size, get_max_level());
}

Plaintext *CKKSEngine::encode(double *input, int input_size, int level) {
  const auto function_name = "Encode Double Buffer";
  validate_target_level(function_name, level);
  return encode_(input, input_size, level);
}

Plaintext *CKKSEngine::encode(std::complex<double> *input, int input_size) {
  return encode(input, input_size, get_max_level());
}

Plaintext *CKKSEngine::encode(std::complex<double> *input, int input_size,
                              int level) {
  const auto function_name = "Encode Complex Double Buffer";
  validate_target_level(function_name, level);
  return encode_(input, input_size, level);
}

}
