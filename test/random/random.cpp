#include "random/random.h"
#include "common/common.h"
#include "common/test.h"
#include "random/gaussian_sampler.h"

#define STATE_SIZE 16

class Random : public ::testing::TestWithParam<std::tuple<int, int>> {};

INSTANTIATE_TEST_SUITE_P(, Random,
                         ::testing::Values(std::make_tuple(1, 1),
                                           std::make_tuple(1, 4),
                                           std::make_tuple(2, 2),
                                           std::make_tuple(4, 1)));

TEST_P(Random, ChaCha20) {
  const auto [thread_count, run_count] = GetParam();

  int64_t state[STATE_SIZE * thread_count];
  initialize_random_state(state, thread_count);

  uint64_t x[16];

  const uint64_t expected_chacha20[4][16]{
      {1293042404, 2667992612, 1162979569, 108866081, 2658055580, 3124423110,
       279327637, 2496180306, 3439228403, 734486407, 820662886, 3142069368,
       1456961552, 1146780051, 1415799667, 3940163035},
      {1273358637, 2843729459, 922022464, 619947645, 4236793831, 3737886963,
       3498545694, 3766979243, 987719850, 1369737522, 1155333775, 1354577056,
       959755423, 266767108, 3996774875, 2575401178},
      {4047943391, 1213427171, 187734792, 1491619405, 4189455891, 361253285,
       1531657442, 2144855898, 2007104367, 2859351556, 2823188689, 1139643442,
       2496344495, 2994222735, 3024968113, 821050846},
      {2534864070, 3714682907, 2014697874, 2070728685, 1498982404, 2590185404,
       3159691733, 3078997847, 3328429779, 2907001082, 4261345669, 4219620181,
       1824987030, 2297616227, 3903312684, 1475110484},
  };

  for (int run_index = 0; run_index < run_count; run_index++) {
    for (int thread_index = 0; thread_index < thread_count; thread_index++) {
      desilo::fhe::chacha20(&state[STATE_SIZE * thread_index], x, thread_count);

      int index = run_index * thread_count + thread_index;
      expect_array_equals(x, expected_chacha20[index], STATE_SIZE);
    }
  }
}

TEST_P(Random, RandInt) {
  const auto [thread_count, run_count] = GetParam();

  int64_t state[STATE_SIZE * thread_count];
  initialize_random_state(state, thread_count);

  int output_count = run_count * thread_count * 4 * 2;
  int64_t output[output_count];
  uint64_t max_value = 10;
  int64_t shift = 0;

  for (int thread_index = 0; thread_index < thread_count; thread_index++) {
    desilo::fhe::rand_int(&state[STATE_SIZE * thread_index],
                          &output[thread_index * 4], max_value, shift,
                          output_count, thread_count);
  }

  const int64_t expected_rand_int[32]{
      2, 0, 1, 3, 2, 8, 2, 9, 0, 3, 6, 7, 4, 7, 9, 9,
      2, 0, 2, 2, 2, 5, 7, 1, 5, 7, 7, 0, 7, 3, 6, 3,
  };

  expect_array_equals(output, expected_rand_int, output_count);
}

TEST_P(Random, RandIntShifted) {
  const auto [thread_count, run_count] = GetParam();

  int64_t state[STATE_SIZE * thread_count];
  initialize_random_state(state, thread_count);

  int output_count = run_count * thread_count * 4 * 2;
  int64_t output[output_count];
  uint64_t max_value = 10;
  int64_t shift = 10;

  for (int thread_index = 0; thread_index < thread_count; thread_index++) {
    desilo::fhe::rand_int(&state[STATE_SIZE * thread_index],
                          &output[thread_index * 4], max_value, shift,
                          output_count, thread_count);
  }

  const int64_t expected_rand_int_shifted[32]{
      12, 10, 11, 13, 12, 18, 12, 19, 10, 13, 16, 17, 14, 17, 19, 19,
      12, 10, 12, 12, 12, 15, 17, 11, 15, 17, 17, 10, 17, 13, 16, 13,
  };

  expect_array_equals(output, expected_rand_int_shifted, output_count);
}

TEST_P(Random, DiscreteGaussian) {
  const auto [thread_count, run_count] = GetParam();

  int64_t state[STATE_SIZE * thread_count];
  initialize_random_state(state, thread_count);

  int output_count = run_count * thread_count * 4 * 2;
  int64_t output[output_count];

  auto tree = desilo::fhe::GaussianSamplingTree();

  for (int thread_index = 0; thread_index < thread_count; thread_index++) {
    desilo::fhe::discrete_gaussian(
        &state[STATE_SIZE * thread_index], &output[thread_index * 4],
        tree.data_, tree.size_, tree.depth_, output_count, thread_count);
  }

  const int64_t expected_discrete_gaussian[32]{
      1, 0, -1, 1,  1,  4,  -1, -6, 0, -1, -3, -3, 2,  4,  8, -5,
      1, 0, 1,  -1, -1, -2, -4, -1, 2, -4, -4, 0,  -4, -1, 3, -2,
  };

  expect_array_equals(output, expected_discrete_gaussian, output_count);
}

TEST_P(Random, DiscreteGaussianDistribution) {
  const auto [thread_count, run_count] = GetParam();

  int64_t state[STATE_SIZE];
  initialize_random_state(state, thread_count);

  const int output_count = 65536;
  auto output = new int64_t[output_count];

  auto tree = desilo::fhe::GaussianSamplingTree();

  for (int thread_index = 0; thread_index < thread_count; thread_index++) {
    desilo::fhe::discrete_gaussian(
        &state[STATE_SIZE * thread_index], &output[thread_index * 4],
        tree.data_, tree.size_, tree.depth_, output_count, thread_count);
  }

  int counter[100];
  for (int index = 0; index < 100; index++) {
    counter[index] = 0;
  }

  for (int index = 0; index < output_count; index++) {
    counter[50 + output[index]]++;
  }

  for (int index = 40; index < 50; index++) {
    EXPECT_LT(counter[index], counter[index + 1]);
  }

  for (int index = 50; index < 60; index++) {
    EXPECT_GT(counter[index], counter[index + 1]);
  }

  delete[] output;
}
