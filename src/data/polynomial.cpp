#include "data/polynomial.h"

namespace desilo::fhe {

PolynomialView::PolynomialView(void *id, const std::vector<int64_t *> &chains,
                               DataFlag flag, int moduli_id, int coeff_count)
    : id_(id), chains_(chains), flag_(flag), moduli_id_(moduli_id),
      chain_count_(chains.size()), coeff_count_(coeff_count) {}

PolynomialView::PolynomialView(Polynomial *polynomial, int offset)
    : PolynomialView(
          static_cast<void *>(polynomial->id()),
          std::vector<int64_t *>(polynomial->chains_.begin() + offset,
                                 polynomial->chains_.end()),
          polynomial->flag(), polynomial->moduli_id(),
          polynomial->coeff_count()) {}

}
