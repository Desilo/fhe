#include "parameter/multiplier.h"
#include "common/test.h"

TEST(Multiplier, Get) {
  desilo::fhe::Multiplier multiplier;
  multiplier.multiplier_ = {1, 2, 3, 4};
  expect_array_equals(multiplier.get(), multiplier.multiplier_);
}
