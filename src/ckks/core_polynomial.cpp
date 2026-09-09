#include "ckks/core.h"

namespace desilo::fhe {

Polynomial *CKKSCore::get_polynomial(Data *data, int index) {
  return data->get_polynomial(index);
}

PolynomialView *CKKSCore::get_polynomial_view(Data *data, int index,
                                              int moduli_id) {
  const int offset = get_chain_offset(data->moduli_id_, moduli_id);
  return new PolynomialView(data->get_polynomial(index), offset);
}

std::tuple<Polynomial *, Polynomial *>
CKKSCore::get_duo_polynomials(Data *data) {
  return {get_polynomial(data, 0), get_polynomial(data, 1)};
};

std::tuple<PolynomialView *, PolynomialView *>
CKKSCore::get_duo_polynomial_views(Data *data, int moduli_id) {
  return {get_polynomial_view(data, 0, moduli_id),
          get_polynomial_view(data, 1, moduli_id)};
};

std::tuple<Polynomial *, Polynomial *, Polynomial *>
CKKSCore::get_trio_polynomials(Data *data) {
  return {get_polynomial(data, 0), get_polynomial(data, 1),
          get_polynomial(data, 2)};
};

PolynomialView *CKKSCore::get_key_polynomial_view(Data *key, int index,
                                                  int moduli_id) {
  const auto polynomial = get_polynomial(key, index);
  const int offset = get_chain_offset(key->moduli_id_, moduli_id);
  auto ntt_flexible_chain_count =
      parameters_.get_ntt_flexible_chain_count(moduli_id);

  std::vector<int64_t *> chains;

  for (int chain_index = 0; chain_index < ntt_flexible_chain_count;
       chain_index++) {
    chains.push_back(polynomial->get(chain_index));
  }

  for (int chain_index = offset + ntt_flexible_chain_count;
       chain_index < polynomial->chain_count(); chain_index++) {
    chains.push_back(polynomial->get(chain_index));
  }

  return new PolynomialView(polynomial->id(), chains, polynomial->flag(),
                            moduli_id, polynomial->coeff_count());
}

}
