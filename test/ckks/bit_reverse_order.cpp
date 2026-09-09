#include "ckks/derived_parameters.h"
#include "common/common.h"
#include "common/test.h"

TEST(BitReverseOrder, 3) {
  const std::vector<int64_t> original = {10, 11, 12, 13, 14, 15, 16, 17};

  auto reversed = desilo::fhe::bit_reverse_order(original, 3);

  const int expected[8]{10, 14, 12, 16, 11, 15, 13, 17};

  for (int index = 0; index < 4; index++) {
    EXPECT_EQ(reversed[index], expected[index]);
  }
}

TEST(BitReverseOrder, 4) {
  const std::vector<int64_t> original = {10, 11, 12, 13, 14, 15, 16, 17,
                                         18, 19, 20, 21, 22, 23, 24, 25};

  auto reversed = desilo::fhe::bit_reverse_order(original, 4);

  const int expected[16]{10, 18, 14, 22, 12, 20, 16, 24,
                         11, 19, 15, 23, 13, 21, 17, 25};

  for (int index = 0; index < 16; index++) {
    EXPECT_EQ(reversed[index], expected[index]);
  }
}
