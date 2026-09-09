#include "operation/scalar.h"

namespace desilo::fhe {

void add_scalar(int64_t *x, int64_t *y, int64_t scalar, int coeff_count) {

  *y++ = *x++ + scalar;
  for (auto coeff_index = 1; coeff_index < coeff_count; coeff_index++) {
    *y++ = *x++;
  }
}

}
