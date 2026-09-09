#include "operation/scalar.h"
#include "common/test.h"

TEST(Scalar, AddScalar) {
  int64_t x[2]{1, 2};
  int64_t scalar = 1;
  int64_t y[2]{};

  const int coeff_count = 2;

  desilo::fhe::add_scalar(x, y, scalar, coeff_count);

  int64_t expected[2]{2, 2};

  expect_array_equals(y, expected, 2);
}
