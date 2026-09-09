#include "ckks/engine.h"
#include "operation/bootstrap.h"

namespace desilo::fhe {

template <typename T>
PlainMatrix *CKKSEngine::encode_matrix_(T matrix, int level) {
  const auto slot_count = get_slot_count();

  const auto [inner_loop_count, outer_loop_count] =
      get_stage_loop_counts(slot_count, 0);
  auto stage = new PlainMatrix();

  stage->level_ = level;
  stage->inner_loop_count_ = inner_loop_count;
  stage->outer_loop_count_ = outer_loop_count;

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

      auto encoded_diagonal = core_->encode(diagonal, level, true);
      inner_diagonals[inner_loop_index] = encoded_diagonal;
    }
  }

  delete[] diagonals;

  return stage;
}

PlainMatrix *CKKSEngine::encode_matrix(double *matrix, int level) {
  const auto function_name = "Encode Double Matrix Buffer";
  validate_matrix_target_level(function_name, level);

  return encode_matrix_(matrix, level);
}

PlainMatrix *CKKSEngine::encode_matrix(double *matrix) {

  return encode_matrix(matrix, get_max_key_switching_level());
}

PlainMatrix *CKKSEngine::encode_matrix(std::complex<double> *matrix,
                                       int level) {
  const auto function_name = "Encode Complex Double Matrix Buffer";
  validate_matrix_target_level(function_name, level);

  return encode_matrix_(matrix, level);
}

PlainMatrix *CKKSEngine::encode_matrix(std::complex<double> *matrix) {

  return encode_matrix(matrix, get_max_key_switching_level());
}

PlainMatrix *CKKSEngine::encode_matrix(std::vector<double> &matrix, int level) {
  const auto function_name = "Encode Double Matrix Vector";
  validate_matrix_target_level(function_name, level);
  require_matrix_compatibility(function_name, matrix);

  return encode_matrix_(matrix.data(), level);
}

PlainMatrix *CKKSEngine::encode_matrix(std::vector<double> &matrix) {

  return encode_matrix(matrix, get_max_key_switching_level());
}

PlainMatrix *
CKKSEngine::encode_matrix(std::vector<std::complex<double>> &matrix,
                          int level) {
  const auto function_name = "Encode Complex Double Matrix Vector";
  validate_matrix_target_level(function_name, level);
  require_matrix_compatibility(function_name, matrix);

  return encode_matrix_(matrix.data(), level);
}

PlainMatrix *
CKKSEngine::encode_matrix(std::vector<std::complex<double>> &matrix) {

  return encode_matrix(matrix, get_max_key_switching_level());
}

}
