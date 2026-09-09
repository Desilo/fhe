#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <tuple>

#include "util/string_transform.h"

class ToLowercase : public ::testing::TestWithParam<
                        std::tuple<const std::string, const std::string>> {};

INSTANTIATE_TEST_SUITE_P(StringTransformation, ToLowercase,
                         testing::Values(std::make_tuple("iron", "iron"),
                                         std::make_tuple("IRON", "iron"),
                                         std::make_tuple("Iron", "iron"),
                                         std::make_tuple("IrOn", "iron"),
                                         std::make_tuple("bronze", "bronze")));

TEST_P(ToLowercase, ) {
  const auto [input, expected] = GetParam();

  auto output = desilo::fhe::to_lowercase(input);

  EXPECT_EQ(output, expected);
}

class GetOrdinalizedPrefix
    : public ::testing::TestWithParam<std::tuple<int, int, const std::string>> {
};

INSTANTIATE_TEST_SUITE_P(StringTransformation, GetOrdinalizedPrefix,
                         testing::Values(std::make_tuple(1, 0, "the"),
                                         std::make_tuple(1, 1, "the"),

                                         std::make_tuple(2, 0, "the first"),
                                         std::make_tuple(2, 1, "the second"),
                                         std::make_tuple(2, 2, "the third"),
                                         std::make_tuple(2, 3, "the 4th"),
                                         std::make_tuple(2, 4, "the 5th")));

TEST(GetOrdinalizedPrefix, InvalidCount) {
  try {
    desilo::fhe::get_ordinalized_prefix("the", 0, 0);
    FAIL();
  } catch (std::invalid_argument &e) {
    EXPECT_STREQ("Count must be greater than or equal to 1.", e.what());
  }
}

TEST_P(GetOrdinalizedPrefix, ) {
  const auto [count, index, expected] = GetParam();

  auto output = desilo::fhe::get_ordinalized_prefix("the", count, index);

  EXPECT_EQ(output, expected);
}
