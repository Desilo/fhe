#include "ckks/encode.h"
#include "ckks/engine.h"

namespace desilo::fhe {

std::vector<double> CKKSEngine::decode_unit(UnitPlaintext *plaintext) {
  require("Decode Unit Plaintext To Double Vector", plaintext,
          {Requirement::NOT_RESCALED});

  return core_->decode(plaintext);
}

std::vector<std::complex<double>>
CKKSEngine::decode_complex_unit_plaintext(UnitPlaintext *plaintext) {
  require("Decode Unit Plaintext To Complex Vector", plaintext,
          {Requirement::NOT_RESCALED});

  return core_->decode_complex_plaintext(plaintext);
}

std::vector<double> CKKSEngine::decode(Plaintext *plaintext) {
  require("Decode Plaintext", plaintext, {Requirement::NOT_RESCALED});

  std::vector<double> long_values;
  for (int index = 0; index < plaintext->size(); index++) {
    auto unit_plaintext = plaintext->get(index);
    auto values = core_->decode(unit_plaintext);
    long_values.insert(long_values.end(), values.begin(), values.end());
  }
  return long_values;
}

void CKKSEngine::decode_to_buffer(Plaintext *plaintext, double *output) {
  require("Decode Plaintext To Buffer", plaintext, {Requirement::NOT_RESCALED});
  const auto slot_count = get_slot_count();

  for (int index = 0; index < plaintext->size(); index++) {
    auto unit_plaintext = plaintext->get(index);
    core_->decode_to_buffer(unit_plaintext, &output[index * slot_count]);
  }
}

std::vector<std::complex<double>>
CKKSEngine::decode_complex_plaintext(Plaintext *plaintext) {
  require("Decode Complex Plaintext", plaintext, {Requirement::NOT_RESCALED});

  std::vector<std::complex<double>> long_values;
  for (int index = 0; index < plaintext->size(); index++) {
    auto unit_plaintext = plaintext->get(index);
    auto values = core_->decode_complex_plaintext(unit_plaintext);
    long_values.insert(long_values.end(), values.begin(), values.end());
  }
  return long_values;
}

void CKKSEngine::decode_complex_plaintext_to_buffer(
    Plaintext *plaintext, std::complex<double> *output) {
  require("Decode Complex Plaintext To Buffer", plaintext,
          {Requirement::NOT_RESCALED});
  const auto slot_count = get_slot_count();

  for (int index = 0; index < plaintext->size(); index++) {
    auto unit_plaintext = plaintext->get(index);
    core_->decode_complex_plaintext_to_buffer(unit_plaintext,
                                              &output[index * slot_count]);
  }
}

}
