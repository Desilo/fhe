#include <cstdint>
#include <vector>

#pragma once

namespace desilo::fhe {

void add_scalar(int64_t *x, int64_t *y, const int64_t scalar, int coeff_count);

}
