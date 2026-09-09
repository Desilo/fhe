#include "ckks/encode.h"
#include "common/test.h"

TEST(CKKS, ReverseIntegerBits3) {
  const int expected[8]{0, 4, 2, 6, 1, 5, 3, 7};

  for (int index = 0; index < 8; index++) {
    EXPECT_EQ(desilo::fhe::reverse_integer_bits(index, 3), expected[index]);
  }
}

TEST(CKKS, ReverseIntegerBits4) {
  const int expected[16]{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};

  for (int index = 0; index < 16; index++) {
    EXPECT_EQ(desilo::fhe::reverse_integer_bits(index, 4), expected[index]);
  }
}

TEST(Encode, CircularShiftPermuation4) {
  auto output = desilo::fhe::circular_shift_permutation(4);

  uint64_t expected[4]{1, 0, 3, 2};

  expect_array_equals<uint64_t>(output, expected, 4);

  delete[] output;
}

TEST(Encode, CircularShiftPermuation8) {
  auto output = desilo::fhe::circular_shift_permutation(8);

  uint64_t expected[8]{3, 0, 1, 2, 5, 6, 7, 4};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, CanonPermuationNegative) {
  const int k = -1;
  try {
    auto output = desilo::fhe::canon_permutation(4, k);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Input of canon_permutation must be positive.", e.what());
  }
}

TEST(Encode, CanonPermuationK1) {
  const int k = 1;
  auto output = desilo::fhe::canon_permutation(4, k);

  uint64_t expected[8]{0, 5, 2, 7, 4, 1, 6, 3};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, CanonPermuationK2) {
  const int k = 2;
  auto output = desilo::fhe::canon_permutation(4, k);

  uint64_t expected[8]{0, 1, 2, 3, 4, 5, 6, 7};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, FoldCanonPermuation4) {
  auto output = desilo::fhe::fold_canon_permutation(4);

  uint64_t expected[4]{2, 3, 0, 1};

  expect_array_equals<uint64_t>(output, expected, 4);

  delete[] output;
}

TEST(Encode, FoldCanonPermuationK8) {
  auto output = desilo::fhe::fold_canon_permutation(8);

  uint64_t expected[8]{6, 3, 0, 5, 2, 7, 4, 1};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, GetPermutationCycles1) {
  uint64_t permutation[8]{3, 0, 1, 2, 5, 6, 7, 4};

  auto output = desilo::fhe::get_permutation_cycles(permutation, 8);

  uint64_t expected[8]{3, 2, 1, 0, 5, 6, 7, 4};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, GetPermutationCycles2) {
  uint64_t permutation[8]{1, 4, 7, 2, 5, 0, 3, 6};

  auto output = desilo::fhe::get_permutation_cycles(permutation, 8);

  uint64_t expected[8]{1, 4, 5, 0, 7, 6, 3, 2};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, GetPermutationCycles3) {
  uint64_t permutation[8]{1, 0, 3, 2, 5, 4, 7, 6};

  auto output = desilo::fhe::get_permutation_cycles(permutation, 8);

  uint64_t expected[8]{1, 0, 3, 2, 5, 4, 7, 6};
  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, GetPermutationCycles4) {
  uint64_t permutation[8]{0, 1, 2, 3, 4, 5, 6, 7};

  auto output = desilo::fhe::get_permutation_cycles(permutation, 8);

  uint64_t expected[8]{0, 1, 2, 3, 4, 5, 6, 7};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, ConjugatePermutations1) {

  uint64_t permutation1[8]{3, 0, 1, 2, 5, 6, 7, 4};

  uint64_t permutation2[8]{1, 4, 7, 2, 5, 0, 3, 6};

  auto output =
      desilo::fhe::conjugate_permutations(permutation1, permutation2, 8);

  uint64_t expected[8]{0, 5, 4, 1, 2, 7, 6, 3};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, ConjugatePermutations2) {

  uint64_t permutation1[8]{3, 0, 1, 2, 5, 6, 7, 4};

  uint64_t permutation2[8]{1, 4, 7, 2, 5, 0, 3, 6};

  auto output =
      desilo::fhe::conjugate_permutations(permutation2, permutation1, 8);

  uint64_t expected[8]{0, 3, 4, 7, 2, 1, 6, 5};

  expect_array_equals<uint64_t>(output, expected, 8);

  delete[] output;
}

TEST(Encode, InvertPermutation1) {
  uint64_t permutation[4]{3, 0, 1, 2};

  auto output = desilo::fhe::invert_permutation(permutation, 4);

  uint64_t expected[4]{1, 2, 3, 0};

  expect_array_equals<uint64_t>(output, expected, 4);

  delete[] output;
}

TEST(Encode, InvertPermutation2) {
  uint64_t permutation[4]{3, 2, 1, 0};

  auto output = desilo::fhe::invert_permutation(permutation, 4);

  uint64_t expected[4]{3, 2, 1, 0};

  expect_array_equals<uint64_t>(output, expected, 4);

  delete[] output;
}

TEST(Encode, InvertPermutation3) {
  uint64_t permutation[4]{3, 1, 0, 2};

  auto output = desilo::fhe::invert_permutation(permutation, 4);

  uint64_t expected[4]{2, 1, 3, 0};

  expect_array_equals<uint64_t>(output, expected, 4);

  delete[] output;
}

TEST(Encode, PrePermuteReal4) {
  double input[4]{1.0, 2.0, 3.0, 4.0};
  uint64_t permutation[4]{0, 5, 4, 1};
  double output[16]{};
  int start = 0;
  int end = 4;

  desilo::fhe::pre_permute(input, output, permutation, 16, start, end);

  double expected[16]{1.0, 0.0, 4.0, 0.0, 2.0, 0.0, 3.0, 0.0,
                      3.0, 0.0, 2.0, 0.0, 4.0, 0.0, 1.0, 0.0};

  expect_array_equals<double>(output, expected, 16);
}

TEST(Encode, PrePermuteReal4ShiftedStart) {
  double input[4]{1.0, 2.0, 3.0, 4.0};
  uint64_t permutation[4]{0, 5, 4, 1};
  double output[16]{};
  int start = 2;
  int end = 4;

  desilo::fhe::pre_permute(input, output, permutation, 16, start, end);

  double expected[16]{0.0, 0.0, 4.0, 0.0, 0.0, 0.0, 3.0, 0.0,
                      3.0, 0.0, 0.0, 0.0, 4.0, 0.0, 0.0, 0.0};

  expect_array_equals<double>(output, expected, 16);
}

TEST(Encode, PrePermuteReal4ShiftedEnd) {
  double input[4]{1.0, 2.0, 3.0, 4.0};
  uint64_t permutation[4]{0, 5, 4, 1};
  double output[16]{};
  int start = 0;
  int end = 2;

  desilo::fhe::pre_permute(input, output, permutation, 16, start, end);

  double expected[16]{1.0, 0.0, 0.0, 0.0, 2.0, 0.0, 0.0, 0.0,
                      0.0, 0.0, 2.0, 0.0, 0.0, 0.0, 1.0, 0.0};

  expect_array_equals<double>(output, expected, 16);
}

TEST(Encode, PrePermuteComplex4) {
  std::complex<double> input[4]{std::complex(1.0, 2.0), std::complex(3.0, 4.0),
                                std::complex(5.0, 6.0), std::complex(7.0, 8.0)};
  uint64_t permutation[4]{0, 5, 4, 1};
  double output[16]{};
  int start = 0;
  int end = 4;

  desilo::fhe::pre_permute(input, output, permutation, 16, start, end);

  double expected[16]{1.0, 2.0, 7.0, 8.0, 3.0, -4.0, 5.0, -6.0,
                      5.0, 6.0, 3.0, 4.0, 7.0, -8.0, 1.0, -2.0};

  expect_array_equals<double>(output, expected, 16);
}

TEST(Encode, PrePermuteComplex4ShiftedStart) {
  std::complex<double> input[8]{std::complex(1.0, 2.0), std::complex(3.0, 4.0),
                                std::complex(5.0, 6.0), std::complex(7.0, 8.0)};
  uint64_t permutation[4]{0, 5, 4, 1};
  double output[16]{};
  int start = 2;
  int end = 4;

  desilo::fhe::pre_permute(input, output, permutation, 16, start, end);

  double expected[16]{0.0, 0.0, 7.0, 8.0, 0.0, 0.0,  5.0, -6.0,
                      5.0, 6.0, 0.0, 0.0, 7.0, -8.0, 0.0, 0.0};

  expect_array_equals<double>(output, expected, 16);
}

TEST(Encode, PrePermuteComplex4ShiftedEnd) {
  std::complex<double> input[8]{std::complex(1.0, 2.0), std::complex(3.0, 4.0),
                                std::complex(5.0, 6.0), std::complex(7.0, 8.0)};
  uint64_t permutation[4]{0, 5, 4, 1};
  double output[16]{};
  int start = 0;
  int end = 2;

  desilo::fhe::pre_permute(input, output, permutation, 16, start, end);

  double expected[16]{1.0, 2.0, 0.0, 0.0, 3.0, -4.0, 0.0, 0.0,
                      0.0, 0.0, 3.0, 4.0, 0.0, 0.0,  1.0, -2.0};

  expect_array_equals<double>(output, expected, 16);
}

TEST(Encode, PrePermuteReal8) {
  double input[8]{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};

  uint64_t permutation[8]{0, 5, 12, 9, 8, 13, 4, 1};
  double output[32]{};
  int start = 0;
  int end = 8;

  desilo::fhe::pre_permute(input, output, permutation, 32, start, end);

  double expected[32]{
      1.0, 0.0, 8.0, 0.0, 6.0, 0.0, 3.0, 0.0, 7.0, 0.0, 2.0,
      0.0, 4.0, 0.0, 5.0, 0.0, 5.0, 0.0, 4.0, 0.0, 2.0, 0.0,
      7.0, 0.0, 3.0, 0.0, 6.0, 0.0, 8.0, 0.0, 1.0, 0.0,
  };

  expect_array_equals<double>(output, expected, 16);
}

TEST(Encode, PostPermute8) {

  double input[8]{1.0, 4.0, 2.0, 3.0, 3.0, 2.0, 4.0, 1.0};

  uint64_t permutation[8]{0, 3, 4, 7, 2, 1, 6, 5};

  auto output = desilo::fhe::post_permute(input, permutation, 8);

  double expected[8]{1.0, 2.0, 3.0, 4.0, 2.0, 1.0, 4.0, 3.0};

  expect_array_equals<double>(output, expected, 8);

  delete[] output;
}

TEST(Encode, PostPermute16) {

  double input[16]{
      1.0, 8.0, 6.0, 3.0, 7.0, 2.0, 4.0, 5.0,
      5.0, 4.0, 2.0, 7.0, 3.0, 6.0, 8.0, 1.0,
  };

  uint64_t permutation[16]{0, 7, 8,  11, 6, 1, 10, 9,
                           4, 3, 12, 15, 2, 5, 14, 13};

  auto output = desilo::fhe::post_permute(input, permutation, 16);

  double expected[16]{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0,
                      6.0, 5.0, 4.0, 3.0, 2.0, 1.0, 8.0, 7.0};

  expect_array_equals<double>(output, expected, 16);

  delete[] output;
}

TEST(Encode, Skewer4) {
  auto output = desilo::fhe::generate_skewer(4);

  double expected[8]{1.0, 0.0, 0.7071, 0.7071, 0.0, 1.0, -0.7071, 0.7071};

  expect_array_near(output, expected, 8, 1e-4);

  delete[] output;
}

TEST(Encode, Skewer8) {
  auto output = desilo::fhe::generate_skewer(8);

  double expected[16]{
      1.0, 0.0, 0.9239,  0.3827, 0.7071,  0.7071, 0.3827,  0.9239,
      0.0, 1.0, -0.3827, 0.9239, -0.7071, 0.7071, -0.9239, 0.3827,
  };

  expect_array_near(output, expected, 16, 1e-4);

  delete[] output;
}

TEST(Encode, Twister4) {
  auto output = desilo::fhe::generate_twister(4);

  double expected[8]{1.0, 0.0, 0.7071, -0.7071, 0.0, -1.0, -0.7071, -0.7071};

  expect_array_near(output, expected, 8, 1e-4);

  delete[] output;
}

TEST(Encode, Twister8) {
  auto output = desilo::fhe::generate_twister(8);

  double expected[16]{
      1.0, 0.0,  0.9239,  -0.3827, 0.7071,  -0.7071, 0.3827,  -0.9239,
      0.0, -1.0, -0.3827, -0.9239, -0.7071, -0.7071, -0.9239, -0.3827,
  };

  expect_array_near(output, expected, 16, 1e-4);

  delete[] output;
}

TEST(Encode, ApplySkewer8Full) {
  const int count = 8;
  const int output_count = 2 * count;
  const double step = std::numbers::pi / output_count;
  double x[count]{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};

  double y[output_count]{};
  desilo::fhe::apply_skewer(x, y, count, 0, step);

  double expected[output_count]{1.000000,  0.000000, 1.847759,  0.765367,
                                2.121320,  2.121320, 1.530734,  3.695518,
                                0.000000,  5.000000, -2.296101, 5.543277,
                                -4.949747, 4.949747, -7.391036, 3.061467};
  expect_array_near(y, expected, output_count, 1e-4);
}

TEST(Encode, ApplySkewer8Split) {
  const int count = 8;
  const int output_count = 2 * count;
  const double step = std::numbers::pi / output_count;
  double x[count]{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};

  double y[output_count]{};

  desilo::fhe::apply_skewer(x, y, count / 2, 0, step);
  double expected_1[output_count]{1.000000, 0.000000, 1.847759, 0.765367,
                                  2.121320, 2.121320, 1.530734, 3.695518,
                                  0.000000, 0.000000, 0.000000, 0.000000,
                                  0.000000, 0.000000, 0.000000, 0.000000};
  expect_array_near(y, expected_1, output_count, 1e-4);

  desilo::fhe::apply_skewer(x, y, count / 2, count / 2, step);
  double expected_2[output_count]{1.000000,  0.000000, 1.847759,  0.765367,
                                  2.121320,  2.121320, 1.530734,  3.695518,
                                  0.000000,  5.000000, -2.296101, 5.543277,
                                  -4.949747, 4.949747, -7.391036, 3.061467};
  expect_array_near(y, expected_2, output_count, 1e-4);
}

TEST(Encode, EncodeReal4) {
  double input[4]{1.0, 2.0, 3.0, 4.0};
  const double scale = 100;
  std::complex<double> twiddle_factor[8]{
      std::complex(1.0, -0.0),
      std::complex(0.7071067811865476, -0.7071067811865475),
      std::complex(0.0, -1.0),
      std::complex(-0.7071067811865475, -0.7071067811865476),
      std::complex(-1.0, 0.0),
      std::complex(-0.7071067811865477, 0.7071067811865475),
      std::complex(0.0, 1.0),
      std::complex(0.7071067811865474, 0.7071067811865477)};

  auto output = desilo::fhe::encode_real(input, twiddle_factor, 4, scale);

  double expected[8]{250.0, -27.0598, -35.3553, -65.3281,
                     0.0,   65.3281,  35.3553,  27.0598};

  expect_array_near(output, expected, 8, 1e-4);

  delete[] output;
}

TEST(Encode, EncodeComplex4) {
  std::complex<double> input[4]{std::complex(1.0, 1.0), std::complex(2.0, 2.0),
                                std::complex(3.0, 3.0), std::complex(4.0, 4.0)};
  const double scale = 100;
  std::complex<double> twiddle_factor[8]{
      std::complex(1.0, -0.0),
      std::complex(0.7071067811865476, -0.7071067811865475),
      std::complex(0.0, -1.0),
      std::complex(-0.7071067811865475, -0.7071067811865476),
      std::complex(-1.0, 0.0),
      std::complex(-0.7071067811865477, 0.7071067811865475),
      std::complex(0.0, 1.0),
      std::complex(0.7071067811865474, 0.7071067811865477)};

  auto output = desilo::fhe::encode_complex(input, twiddle_factor, 4, scale);

  double expected[8]{250.0, -92.3880, -70.7107, -92.3880,
                     250.0, 38.2683,  0.0,      -38.2683};

  expect_array_near(output, expected, 8, 1e-4);

  delete[] output;
}

TEST(Encode, EncodeImaginary4) {
  int64_t input = 1;

  auto output = desilo::fhe::encode_imaginary(input, 8);

  int64_t expected[8]{0, 0, 0, 0, 1, 0, 0, 0};

  expect_array_equals(output, expected, 8);

  delete[] output;
}

TEST(Encode, DecodeReal4) {
  double input[8]{250.0, -27.0598, -35.3553, -65.3281,
                  0.0,   65.3281,  35.3553,  27.0598};
  const double scale = 100;

  auto output = desilo::fhe::decode_real(input, 8, scale);

  double expected[4]{1.0, 2.0, 3.0, 4.0};

  expect_array_near(output, expected, 4, 1e-4);

  delete[] output;
}

TEST(Encode, DecodeComplex4) {
  double input[8]{250.0, -92.3880, -70.7107, -92.3880,
                  250.0, 38.2683,  0.0,      -38.2683};
  const double scale = 100;

  auto output = desilo::fhe::decode_complex(input, 8, scale);

  std::complex<double> expected[4]{
      std::complex(1.0, 1.0), std::complex(2.0, 2.0), std::complex(3.0, 3.0),
      std::complex(4.0, 4.0)};

  expect_complex_array_near(output, expected, 4, 1e-4);

  delete[] output;
}

TEST(Encode, EncodeReal8) {
  double input[8]{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
  const double scale = 100;
  std::complex<double> twiddle_factor[16]{
      std::complex(1.0, -0.0),
      std::complex(0.9238795325112867, -0.3826834323650898),
      std::complex(0.7071067811865476, -0.7071067811865475),
      std::complex(0.38268343236508984, -0.9238795325112867),
      std::complex(0.0, -1.0),
      std::complex(-0.3826834323650897, -0.9238795325112867),
      std::complex(-0.7071067811865475, -0.7071067811865476),
      std::complex(-0.9238795325112867, -0.3826834323650899),
      std::complex(-1.0, 0.0),
      std::complex(-0.9238795325112868, 0.38268343236508967),
      std::complex(-0.7071067811865477, 0.7071067811865475),
      std::complex(-0.38268343236509034, 0.9238795325112865),
      std::complex(0.0, 1.0),
      std::complex(0.38268343236509, 0.9238795325112866),
      std::complex(0.7071067811865474, 0.7071067811865477),
      std::complex(0.9238795325112865, 0.3826834323650904)};

  auto output = desilo::fhe::encode_real(input, twiddle_factor, 8, scale);

  double expected[16]{450.0,    -128.1458, -27.0598, 44.9988,
                      -35.3553, -30.0672,  -65.3281, 25.4898,
                      0.0,      -25.4898,  65.3281,  30.0672,
                      35.3553,  -44.9988,  27.0598,  128.1458};

  expect_array_near(output, expected, 16, 1e-4);

  delete[] output;
}

TEST(Encode, EncodeComplex8) {
  std::complex<double> input[8]{std::complex(1.0, 1.0), std::complex(2.0, 2.0),
                                std::complex(3.0, 3.0), std::complex(4.0, 4.0),
                                std::complex(5.0, 5.0), std::complex(6.0, 6.0),
                                std::complex(7.0, 7.0), std::complex(8.0, 8.0)};
  const double encode_scale = 100.;
  std::complex<double> twiddle_factor[16]{
      std::complex(1.0, -0.0),
      std::complex(0.9238795325112867, -0.3826834323650898),
      std::complex(0.7071067811865476, -0.7071067811865475),
      std::complex(0.38268343236508984, -0.9238795325112867),
      std::complex(0.0, -1.0),
      std::complex(-0.3826834323650897, -0.9238795325112867),
      std::complex(-0.7071067811865475, -0.7071067811865476),
      std::complex(-0.9238795325112867, -0.3826834323650899),
      std::complex(-1.0, 0.0),
      std::complex(-0.9238795325112868, 0.38268343236508967),
      std::complex(-0.7071067811865477, 0.7071067811865475),
      std::complex(-0.38268343236509034, 0.9238795325112865),
      std::complex(0.0, 1.0),
      std::complex(0.38268343236509, 0.9238795325112866),
      std::complex(0.7071067811865474, 0.7071067811865477),
      std::complex(0.9238795325112865, 0.3826834323650904)};

  auto output =
      desilo::fhe::encode_complex(input, twiddle_factor, 8, encode_scale);

  double expected[16]{450.0,    -102.6560, -92.3880, 14.9316,
                      -70.7107, 14.9316,   -92.3880, -102.6560,
                      450.0,    -153.6356, 38.2683,  75.0661,
                      0.0,      -75.0661,  -38.2683, 153.6356};

  expect_array_near(output, expected, 16, 1e-4);

  delete[] output;
}

TEST(Encode, EncodeImaginary8) {
  int64_t input = 1;

  auto output = desilo::fhe::encode_imaginary(input, 16);

  int64_t expected[16]{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};

  expect_array_equals(output, expected, 16);

  delete[] output;
}

TEST(Encode, DecodeReal8) {
  double input[16]{450.0,    -128.1458, -27.0598, 44.9988,  -35.3553, -30.0672,
                   -65.3281, 25.4898,   0.0,      -25.4898, 65.3281,  30.0672,
                   35.3553,  -44.9988,  27.0598,  128.1458};
  const double scale = 100;

  auto output = desilo::fhe::decode_real(input, 16, scale);

  double expected[8]{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};

  expect_array_near(output, expected, 8, 1e-4);

  delete[] output;
}

TEST(Encode, DecodeComplex8) {
  double input[16]{450.0,    -102.6560, -92.3880, 14.9316,   -70.7107, 14.9316,
                   -92.3880, -102.6560, 450.0,    -153.6356, 38.2683,  75.0661,
                   0.0,      -75.0661,  -38.2683, 153.6356};
  const double scale = 100;

  auto output = desilo::fhe::decode_complex(input, 16, scale);

  std::complex<double> expected[8]{
      std::complex(1.0, 1.0), std::complex(2.0, 2.0), std::complex(3.0, 3.0),
      std::complex(4.0, 4.0), std::complex(5.0, 5.0), std::complex(6.0, 6.0),
      std::complex(7.0, 7.0), std::complex(8.0, 8.0)};

  expect_complex_array_near(output, expected, 8, 1e-4);

  delete[] output;
}

TEST(Encode, EncodeReal4Deviation) {
  double input[4]{1.0, 2.0, 3.0, 4.0};
  const double scale = 100;
  double deviation = 10.0;
  double encode_scale = deviation * static_cast<double>(scale);
  std::complex<double> twiddle_factor[8]{
      std::complex(1.0, -0.0),
      std::complex(0.7071067811865476, -0.7071067811865475),
      std::complex(0.0, -1.0),
      std::complex(-0.7071067811865475, -0.7071067811865476),
      std::complex(-1.0, 0.0),
      std::complex(-0.7071067811865477, 0.7071067811865475),
      std::complex(0.0, 1.0),
      std::complex(0.7071067811865474, 0.7071067811865477)};

  auto output =
      desilo::fhe::encode_real(input, twiddle_factor, 4, encode_scale);

  double expected[8]{2500.0, -270.598, -353.553, -653.281,
                     0.0,    653.281,  353.553,  270.598};

  expect_array_near(output, expected, 8, 1e-3);

  delete[] output;
}

TEST(Encode, PermuteAfterIfftDoubleFull) {
  int coeff_count = 8;
  int output_count = coeff_count / 2;
  double scale_inverse = 0.1;
  int start = 0;
  int end = coeff_count;

  double iffted[coeff_count * 2]{1.0, 2.0,  3.0,  4.0,  5.0,  6.0,  7.0,  8.0,
                                 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0};
  double output[output_count]{};
  uint64_t post_permutation[coeff_count]{0, 3, 4, 7, 2, 1, 6, 5};

  desilo::fhe::permute_after_ifft(iffted, output, post_permutation,
                                  output_count, scale_inverse, start, end);

  double expected[output_count]{0.1, 1.1, 0.9, 0.3};

  expect_array_near(output, expected, output_count, 1e-9);
}

TEST(Encode, PermuteAfterIfftDoubleHalf) {
  int coeff_count = 8;
  int output_count = coeff_count / 2;
  double scale_inverse = 0.1;
  int start = 4;
  int end = coeff_count;

  double iffted[coeff_count * 2]{1.0, 2.0,  3.0,  4.0,  5.0,  6.0,  7.0,  8.0,
                                 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0};
  double output[output_count]{};
  uint64_t post_permutation[coeff_count]{0, 3, 4, 7, 2, 1, 6, 5};

  desilo::fhe::permute_after_ifft(iffted, output, post_permutation,
                                  output_count, scale_inverse, start, end);

  double expected[output_count]{0.0, 1.1, 0.9, 0.0};

  expect_array_near(output, expected, output_count, 1e-9);
}

TEST(Encode, PermuteAfterIfftComplexDoubleFull) {
  int coeff_count = 8;
  int output_count = coeff_count / 2;
  double scale_inverse = 0.1;
  int start = 0;
  int end = coeff_count;

  double iffted[coeff_count * 2]{1.0, 2.0,  3.0,  4.0,  5.0,  6.0,  7.0,  8.0,
                                 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0};
  std::complex<double> output[output_count]{};
  uint64_t post_permutation[coeff_count]{0, 3, 4, 7, 2, 1, 6, 5};

  desilo::fhe::permute_after_ifft(iffted, output, post_permutation,
                                  output_count, scale_inverse, start, end);

  std::complex<double> expected[output_count]{
      std::complex<double>(0.1, 0.2), std::complex<double>(1.1, 1.2),
      std::complex<double>(0.9, 1.0), std::complex<double>(0.3, 0.4)};

  expect_complex_array_near(output, expected, output_count, 1e-9);
}

TEST(Encode, PermuteAfterIfftComplexDoubleHalf) {
  int coeff_count = 8;
  int output_count = coeff_count / 2;
  double scale_inverse = 0.1;
  int start = 4;
  int end = coeff_count;

  double iffted[coeff_count * 2]{1.0, 2.0,  3.0,  4.0,  5.0,  6.0,  7.0,  8.0,
                                 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0};
  std::complex<double> output[output_count]{};
  uint64_t post_permutation[coeff_count]{0, 3, 4, 7, 2, 1, 6, 5};

  desilo::fhe::permute_after_ifft(iffted, output, post_permutation,
                                  output_count, scale_inverse, start, end);

  std::complex<double> expected[output_count]{
      std::complex<double>(0.0, 0.0), std::complex<double>(1.1, 1.2),
      std::complex<double>(0.9, 1.0), std::complex<double>(0.0, 0.0)};

  expect_complex_array_near(output, expected, output_count, 1e-9);
}

TEST(Encode, GetPermutationAndSign8Delta1) {
  int32_t permutation[8]{};
  int32_t sign[8]{};
  const int coeff_count = 8;
  const int delta = 1;

  desilo::fhe::get_permutation_and_sign(permutation, sign, coeff_count, delta);

  int32_t expected_permutation[8]{0, 5, 2, 7, 4, 1, 6, 3};
  int32_t expected_sign[8]{1, -1, -1, 1, 1, 1, -1, -1};

  expect_array_equals(permutation, expected_permutation, 8);
  expect_array_equals(sign, expected_sign, 8);
}

TEST(Encode, GetPermutationAndSign8Delta2) {
  int32_t permutation[8]{};
  int32_t sign[8]{};
  const int coeff_count = 8;
  const int delta = 2;

  desilo::fhe::get_permutation_and_sign(permutation, sign, coeff_count, delta);

  int32_t expected_permutation[8]{0, 1, 2, 3, 4, 5, 6, 7};
  int32_t expected_sign[8]{1, -1, 1, -1, 1, -1, 1, -1};

  expect_array_equals(permutation, expected_permutation, 8);
  expect_array_equals(sign, expected_sign, 8);
}

TEST(Encode, GetPermutationAndSign16Delta1) {
  int32_t permutation[16]{};
  int32_t sign[16]{};
  const int coeff_count = 16;
  const int delta = 1;

  desilo::fhe::get_permutation_and_sign(permutation, sign, coeff_count, delta);

  int32_t expected_permutation[16]{0, 13, 10, 7,  4,  1, 14, 11,
                                   8, 5,  2,  15, 12, 9, 6,  3};
  int32_t expected_sign[16]{1, 1,  -1, 1, -1, 1, 1,  -1,
                            1, -1, 1,  1, -1, 1, -1, 1};

  expect_array_equals(permutation, expected_permutation, 16);
  expect_array_equals(sign, expected_sign, 16);
}

class GetNTTPermutation
    : public ::testing::TestWithParam<std::tuple<int, int, std::vector<int>>> {
};

INSTANTIATE_TEST_SUITE_P(
    Encode, GetNTTPermutation,
    ::testing::Values(
        std::make_tuple(8, 0, std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7}),
        std::make_tuple(8, 1, std::vector<int>{3, 2, 0, 1, 6, 7, 5, 4}),
        std::make_tuple(8, 2, std::vector<int>{1, 0, 3, 2, 5, 4, 7, 6}),
        std::make_tuple(8, 3, std::vector<int>{2, 3, 1, 0, 7, 6, 4, 5}),
        std::make_tuple(8, 4, std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7}),
        std::make_tuple(8, -1, std::vector<int>{7, 6, 5, 4, 3, 2, 1, 0}),
        std::make_tuple(16, 0,
                        std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                                         12, 13, 14, 15}),
        std::make_tuple(16, 1,
                        std::vector<int>{6, 7, 5, 4, 0, 1, 2, 3, 12, 13, 14, 15,
                                         11, 10, 8, 9}),
        std::make_tuple(16, 2,
                        std::vector<int>{2, 3, 1, 0, 6, 7, 5, 4, 11, 10, 8, 9,
                                         15, 14, 12, 13}),
        std::make_tuple(16, 3,
                        std::vector<int>{5, 4, 7, 6, 2, 3, 1, 0, 15, 14, 12, 13,
                                         9, 8, 11, 10}),
        std::make_tuple(16, 4,
                        std::vector<int>{1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10,
                                         13, 12, 15, 14}),
        std::make_tuple(16, -1,
                        std::vector<int>{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
                                         4, 3, 2, 1, 0})));

TEST_P(GetNTTPermutation, ) {
  auto [coeff_count, delta, expected] = GetParam();
  int32_t permutation[coeff_count]{};

  desilo::fhe::get_ntt_permutation(permutation, coeff_count, delta);

  expect_array_equals(permutation, expected.data(), coeff_count);
}

TEST(Encode, RotateChain8Delta1) {
  int64_t input[8]{1, 2, 3, 4, 5, 6, 7, 8};
  int64_t output[8]{};
  int32_t permutation[8]{0, 5, 2, 7, 4, 1, 6, 3};
  int32_t sign[8]{1, -1, -1, 1, 1, 1, -1, -1};
  const int coeff_count = 8;

  desilo::fhe::rotate_chain(input, output, permutation, sign, coeff_count);

  int64_t expected[8]{1, 6, -3, -8, 5, -2, -7, 4};

  expect_array_equals<int64_t>(output, expected, 8);
}

TEST(Encode, RotatePolynomial8Delta1) {
  int64_t input[8]{1, 2, 3, 4, 5, 6, 7, 8};
  int64_t output[8]{};
  int32_t permutation[8]{0, 5, 2, 7, 4, 1, 6, 3};
  int32_t sign[8]{1, -1, -1, 1, 1, 1, -1, -1};
  const int coeff_count = 8;

  desilo::fhe::rotate_polynomial(input, output, permutation, sign, coeff_count);

  int64_t expected[8]{1, 6, -3, -8, 5, -2, -7, 4};

  expect_array_equals<int64_t>(output, expected, 8);
}

TEST(Encode, RotatePolynomial8Delta2) {
  int64_t input[8]{1, 2, 3, 4, 5, 6, 7, 8};
  int64_t output[8]{};
  int32_t permutation[8]{0, 1, 2, 3, 4, 5, 6, 7};
  int32_t sign[8]{1, -1, 1, -1, 1, -1, 1, -1};
  const int coeff_count = 8;

  desilo::fhe::rotate_polynomial(input, output, permutation, sign, coeff_count);

  int64_t expected[8]{1, -2, 3, -4, 5, -6, 7, -8};

  expect_array_equals<int64_t>(output, expected, 8);
}

TEST(Encode, RotatePolynomial16Delta1) {
  int64_t input[16]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  int64_t output[16]{};
  int32_t permutation[16]{0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
  int32_t sign[16]{1, 1, -1, 1, -1, 1, 1, -1, 1, -1, 1, 1, -1, 1, -1, 1};
  const int coeff_count = 16;

  desilo::fhe::rotate_polynomial(input, output, permutation, sign, coeff_count);

  int64_t expected[16]{1, 6,  11, 16, -5,  -10, -15, 4,
                       9, 14, -3, -8, -13, 2,   7,   12};

  expect_array_equals<int64_t>(output, expected, 16);
}

TEST(Encode, PermuteChain) {
  int64_t input[8]{1, 2, 3, 4, 5, 6, 7, 8};
  int64_t output[8]{};
  int32_t permutation[8]{0, 5, 2, 7, 4, 1, 6, 3};
  const int coeff_count = 8;

  desilo::fhe::permute_chain(input, output, permutation, coeff_count);

  int64_t expected[8]{1, 6, 3, 8, 5, 2, 7, 4};

  expect_array_equals<int64_t>(output, expected, 8);
}

TEST(Encode, PermutePolynomial8) {
  int64_t input[8]{1, 2, 3, 4, 5, 6, 7, 8};
  int64_t output[8]{};
  int32_t permutation[8]{0, 5, 2, 7, 4, 1, 6, 3};
  const int coeff_count = 8;

  desilo::fhe::permute_polynomial(input, output, permutation, coeff_count);

  int64_t expected[8]{1, 6, 3, 8, 5, 2, 7, 4};

  expect_array_equals<int64_t>(output, expected, 8);
}
