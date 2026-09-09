#include "ckks/engine.h"

namespace desilo::fhe {

template <typename T>
PlainMatrix *CKKSEngine::make_plain_matrix(T matrix, int level) {
  const auto slot_count = get_slot_count();
  auto stage = new PlainMatrix();

  auto log_slot_count = int(std::log2(slot_count));
  auto outer_loop_count = slot_count >> (log_slot_count / 2);
  auto inner_loop_count = slot_count / outer_loop_count;

  stage->level_ = level;
  stage->outer_loop_count_ = outer_loop_count;
  stage->inner_loop_count_ = inner_loop_count;

  for (int index = 0; index < inner_loop_count; index++) {
    stage->inner_loop_deltas_.push_back(index);
  }

  auto diagonals =
      core_->extract_diagonals(matrix, outer_loop_count, inner_loop_count);

  for (int outer_loop_index = 0; outer_loop_index < outer_loop_count;
       outer_loop_index++) {
    const auto normalized_outer_loop_index =
        outer_loop_index - outer_loop_count / 2;
    const auto delta = inner_loop_count * normalized_outer_loop_index;
    stage->outer_loop_deltas_.push_back(positive_modulo(delta, slot_count));

    auto &inner_diagonals = stage->encoded_diagonals_[outer_loop_index];
    for (int inner_loop_index = 0; inner_loop_index < inner_loop_count;
         inner_loop_index++) {
      auto loop_index = inner_loop_count * outer_loop_index + inner_loop_index;
      auto diagonal = &diagonals[loop_index * slot_count];
      auto encoded_diagonal = core_->encode(diagonal, level, false);
      inner_diagonals[inner_loop_index] = encoded_diagonal;
    }
  }

  delete[] diagonals;

  return stage;
}

template PlainMatrix *CKKSEngine::make_plain_matrix(double *matrix, int level);
template PlainMatrix *
CKKSEngine::make_plain_matrix(std::complex<double> *matrix, int level);
template PlainMatrix *CKKSEngine::make_plain_matrix(std::vector<double> &matrix,
                                                    int level);
template PlainMatrix *
CKKSEngine::make_plain_matrix(std::vector<std::complex<double>> &matrix,
                              int level);

UnitCiphertext *
CKKSEngine::multiply_plain_matrix(UnitCiphertext *unit_ciphertext,
                                  PlainMatrix *plain_matrix,
                                  RotationKey *rotation_key) {
  const auto outer_loop_count = plain_matrix->outer_loop_count_;
  const auto inner_loop_count = plain_matrix->inner_loop_count_;
  const auto &inner_loop_deltas = plain_matrix->inner_loop_deltas_;

  auto inner_rotated_unit_ciphertexts =
      rotate_batch(unit_ciphertext, rotation_key, inner_loop_deltas);
  auto &diagonals = plain_matrix->encoded_diagonals_;

  UnitCiphertext *outer_sum = nullptr;
  for (int outer_loop_index = 0; outer_loop_index < outer_loop_count;
       outer_loop_index++) {
    const auto diagonal_delta =
        plain_matrix->outer_loop_deltas_[outer_loop_index];

    UnitCiphertext *inner_sum = nullptr;
    for (int inner_loop_index = 0; inner_loop_index < inner_loop_count;
         inner_loop_index++) {
      auto diagonal = diagonals[outer_loop_index][inner_loop_index];
      auto multiplied =
          multiply(inner_rotated_unit_ciphertexts[inner_loop_index], diagonal);

      if (inner_sum == nullptr) {
        inner_sum = multiplied;
      } else {
        add_inplace(inner_sum, multiplied);
        delete multiplied;
      }
    }

    const auto rotated = rotate(inner_sum, rotation_key, diagonal_delta);
    delete inner_sum;

    if (outer_sum == nullptr) {
      outer_sum = rotated;
    } else {
      add_inplace(outer_sum, rotated);
      delete rotated;
    }
  }

  for (auto rotated : inner_rotated_unit_ciphertexts) {
    delete rotated;
  }

  return outer_sum;
}

template <typename T>
void CKKSEngine::require_multiply_matrix_(const std::string &function_name,
                                          T *text, RotationKey *rotation_key) {
  require(function_name, text, {Requirement::DUO, Requirement::POSITIVE_LEVEL});
  require_engine_compatibility(function_name, rotation_key);
  require_key_compatibility(function_name, text, rotation_key);
}

template <typename T>
UnitCiphertext *CKKSEngine::multiply_matrix_(T matrix,
                                             UnitCiphertext *unit_ciphertext,
                                             RotationKey *rotation_key) {
  const auto plain_matrix = make_plain_matrix(matrix, unit_ciphertext->level_);
  const auto outer_loop_count = plain_matrix->outer_loop_count_;
  const auto inner_loop_count = plain_matrix->inner_loop_count_;

  auto multiplied =
      multiply_plain_matrix(unit_ciphertext, plain_matrix, rotation_key);

  delete plain_matrix;

  return multiplied;
}

UnitCiphertext *CKKSEngine::multiply_matrix(double *matrix,
                                            UnitCiphertext *unit_ciphertext,

                                            RotationKey *rotation_key) {
  const auto function_name = "Multiply Double Matrix And Unit Ciphertext";
  require_multiply_matrix_(function_name, unit_ciphertext, rotation_key);

  return multiply_matrix_(matrix, unit_ciphertext, rotation_key);
}

UnitCiphertext *CKKSEngine::multiply_matrix(std::complex<double> *matrix,
                                            UnitCiphertext *unit_ciphertext,

                                            RotationKey *rotation_key) {
  const auto function_name =
      "Multiply Complex Double Matrix And Unit Ciphertext";
  require_multiply_matrix_(function_name, unit_ciphertext, rotation_key);

  return multiply_matrix_(matrix, unit_ciphertext, rotation_key);
}

UnitCiphertext *CKKSEngine::multiply_matrix(std::vector<double> &matrix,
                                            UnitCiphertext *unit_ciphertext,

                                            RotationKey *rotation_key) {
  const auto function_name =
      "Multiply Double Matrix Vector And Unit Ciphertext";

  require_multiply_matrix_(function_name, unit_ciphertext, rotation_key);

  return multiply_matrix_(matrix, unit_ciphertext, rotation_key);
}

UnitCiphertext *
CKKSEngine::multiply_matrix(std::vector<std::complex<double>> &matrix,
                            UnitCiphertext *unit_ciphertext,

                            RotationKey *rotation_key) {
  const auto function_name =
      "Multiply Complex Double Matrix Vector And Unit Ciphertext";

  require_multiply_matrix_(function_name, unit_ciphertext, rotation_key);

  return multiply_matrix_(matrix, unit_ciphertext, rotation_key);
}

template <typename T>
Ciphertext *CKKSEngine::multiply_matrix_(T matrix, Ciphertext *ciphertext,
                                         RotationKey *rotation_key) {

  const auto plain_matrix = make_plain_matrix(matrix, ciphertext->level());
  const auto outer_loop_count = plain_matrix->outer_loop_count_;
  const auto inner_loop_count = plain_matrix->inner_loop_count_;

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(multiply_plain_matrix(
        ciphertext->get(index), plain_matrix, rotation_key));
  }

  clear_temp_data();

  delete plain_matrix;

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::multiply_matrix(double *matrix, Ciphertext *ciphertext,
                                        RotationKey *rotation_key) {
  const auto function_name = "Multiply Double Matrix And Ciphertext";
  require_multiply_matrix_(function_name, ciphertext, rotation_key);

  return multiply_matrix_(matrix, ciphertext, rotation_key);
}

Ciphertext *CKKSEngine::multiply_matrix(std::complex<double> *matrix,
                                        Ciphertext *ciphertext,
                                        RotationKey *rotation_key) {
  const auto function_name = "Multiply Complex Double Matrix And Ciphertext";
  require_multiply_matrix_(function_name, ciphertext, rotation_key);

  return multiply_matrix_(matrix, ciphertext, rotation_key);
}

Ciphertext *CKKSEngine::multiply_matrix(std::vector<double> &matrix,
                                        Ciphertext *ciphertext,
                                        RotationKey *rotation_key) {
  const auto function_name = "Multiply Double Matrix Vector And Ciphertext";

  require_multiply_matrix_(function_name, ciphertext, rotation_key);

  return multiply_matrix_(matrix, ciphertext, rotation_key);
}

Ciphertext *
CKKSEngine::multiply_matrix(std::vector<std::complex<double>> &matrix,
                            Ciphertext *ciphertext, RotationKey *rotation_key) {
  const auto function_name =
      "Multiply Complex Double Matrix Vector And Ciphertext";

  require_multiply_matrix_(function_name, ciphertext, rotation_key);

  return multiply_matrix_(matrix, ciphertext, rotation_key);
}

}
