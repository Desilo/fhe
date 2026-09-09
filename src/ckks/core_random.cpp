#include <cstring>

#include "ckks/core.h"

namespace desilo::fhe {

Polynomial *CKKSCore::get_single_error() {
  Polynomial *polynomial;

  std::vector<int64_t *> chains = {rng_.get_discrete_gaussian_integer_chain()};

  const auto flag = DataFlag::NONE;
  const auto moduli_id = 0;
  const auto chain_count = 1;
  const auto coeff_count = precomputed_.coeff_count_;

  polynomial = new Polynomial(chains, flag, moduli_id, coeff_count);

  return polynomial;
}

Polynomial *CKKSCore::get_integer_chain(int64_t max_value, int shift) {
  auto polynomial = allocate_polynomial();
  const int polynomial_offset = 0;

  rng_.assign_uniform_distribution_integer_chain(polynomial->get(0), max_value,
                                                 shift);

  return polynomial;
}

void CKKSCore::assign_a(Polynomial *output, int moduli_id,
                        bool include_special) {
  auto max_values = precomputed_.get_q(moduli_id);
  auto chain_count = parameters_.get_chain_count(moduli_id, include_special);

  int shift = 0;

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    auto output_offset = chain_index;
    auto max_value = max_values[chain_index];

    rng_.assign_uniform_distribution_integer_chain(output->get(chain_index),
                                                   max_value, shift);
  }
}

Polynomial *CKKSCore::get_binary() {
  const uint64_t max_value = 2;
  const int shift = 0;

  return get_integer_chain(max_value, shift);
}

Polynomial *CKKSCore::get_ternary() {
  const int max_value = 3;
  const int shift = -1;

  return get_integer_chain(max_value, shift);
}

Polynomial *CKKSCore::get_sparse_ternary(const int hamming_weight) {
  auto random_index = allocate_polynomial();
  auto output = allocate_polynomial();

  rng_.assign_sparse_ternary_chain(output->get(0), random_index->get(0),
                                   hamming_weight);

  release(random_index);

  return output;
}

}
