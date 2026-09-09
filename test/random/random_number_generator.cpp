#include "random/random_number_generator.h"
#include "common/common.h"
#include "common/test.h"

class RandomNumberGeneratorConstruct : public ::testing::TestWithParam<int> {};

INSTANTIATE_TEST_SUITE_P(, RandomNumberGeneratorConstruct,
                         ::testing::Values(1, 2, 4));

TEST_P(RandomNumberGeneratorConstruct, ) {
  auto thread_count = GetParam();
  auto coeff_count = 8192;

  auto rng = new desilo::fhe::RandomNumberGenerator(thread_count, coeff_count);

  delete rng;
}

TEST(RandomNumberGenerator, AssignUniformDistributionIntegerChain) {
  auto thread_count = 1;
  auto coeff_count = 8192;

  desilo::fhe::RandomNumberGenerator rng(thread_count, coeff_count);

  auto output = new int64_t[coeff_count];

  int max_value = 10;
  int shift = 0;

  rng.assign_uniform_distribution_integer_chain(output, max_value, shift);

  for (int index = 0; index < coeff_count; index++) {
    ASSERT_GE(output[index], 0);
    ASSERT_LT(output[index], 10);
  }

  delete[] output;
}

TEST(RandomNumberGenerator, AssignUniformDistributionIntegerChainShifted) {
  auto thread_count = 1;
  auto coeff_count = 8192;

  desilo::fhe::RandomNumberGenerator rng(thread_count, coeff_count);

  auto output = new int64_t[coeff_count];

  int max_value = 10;
  int shift = -5;

  rng.assign_uniform_distribution_integer_chain(output, max_value, shift);

  for (int index = 0; index < coeff_count; index++) {
    ASSERT_GE(output[index], -5);
    ASSERT_LT(output[index], 5);
  }

  delete[] output;
}

TEST(RandomNumberGenerator, AssignSpraseTernaryChain) {
  auto thread_count = 1;
  int coeff_count = 8192;
  int hamming_weight = 192;

  desilo::fhe::RandomNumberGenerator rng(thread_count, coeff_count);

  auto random_index = new int64_t[hamming_weight + 4];
  auto output = new int64_t[coeff_count];

  rng.assign_sparse_ternary_chain(output, random_index, hamming_weight);

  int count = 0;
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    if (output[coeff_index] == -1 || output[coeff_index] == 1) {
      count++;
    }
  }

  EXPECT_EQ(count, hamming_weight);

  delete[] random_index;
  delete[] output;
}

TEST(RandomNumberGenerator, GetDiscreteGaussianIntegerChain) {
  auto thread_count = 1;
  int coeff_count = 1000000;

  desilo::fhe::RandomNumberGenerator rng(thread_count, coeff_count);

  auto output = rng.get_discrete_gaussian_integer_chain();

  int counter[100]{};

  for (int index = 0; index < coeff_count; index++) {
    counter[50 + output[index]]++;
  }

  for (int index = 40; index < 50; index++) {
    EXPECT_LT(counter[index], counter[index + 1]) << "index " << index;
  }

  for (int index = 50; index < 60; index++) {
    EXPECT_GT(counter[index], counter[index + 1]) << "index " << index;
  }

  delete[] output;
}
