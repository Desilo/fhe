#include "operation/bootstrap.h"
#include "common/test.h"

TEST(Bootstrap, GetPhi2) {
  const int slot_count = 2;
  const int quadruple_slot_count = 8;

  std::vector<std::complex<double>> expected = {
      std::complex(1.0, 0.0),
      std::complex(0.7071067811865476, -0.7071067811865475),
      std::complex(0.0, -1.0),
      std::complex(-0.7071067811865475, -0.7071067811865476),
      std::complex(-1.0, 0.0),
      std::complex(-0.7071067811865477, 0.7071067811865475),
      std::complex(-0.0, 1.0),
      std::complex(0.7071067811865474, 0.7071067811865477)};

  auto phi = desilo::fhe::get_phi(quadruple_slot_count);

  expect_complex_vector_near(phi, expected, quadruple_slot_count, 1e-15);
}

TEST(Bootstrap, GetPhi4) {
  const int slot_count = 4;
  const int quadruple_slot_count = 16;

  std::vector<std::complex<double>> expected = {
      std::complex(1.0, 0.0),
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

  auto phi = desilo::fhe::get_phi(quadruple_slot_count);

  expect_complex_vector_near(phi, expected, quadruple_slot_count, 1e-15);
}

TEST(Bootstrap, GetInversePhi2) {
  const int slot_count = 2;
  const int quadruple_slot_count = 8;

  std::vector<std::complex<double>> expected = {
      std::complex(1.0, 0.0),
      std::complex(0.7071067811865476, 0.7071067811865475),
      std::complex(0.0, 1.0),
      std::complex(-0.7071067811865475, 0.7071067811865476),
      std::complex(-1.0, 0.0),
      std::complex(-0.7071067811865477, -0.7071067811865475),
      std::complex(-0.0, -1.0),
      std::complex(0.7071067811865474, -0.7071067811865477)};

  auto inverse_phi = desilo::fhe::get_inverse_phi(quadruple_slot_count);

  expect_complex_vector_near(inverse_phi, expected, quadruple_slot_count,
                             1e-15);
}

TEST(Bootstrap, GetInversePhi4) {
  const int slot_count = 4;
  const int quadruple_slot_count = 16;

  std::vector<std::complex<double>> expected = {
      std::complex(1.0, 0.0),
      std::complex(0.9238795325112867, 0.3826834323650898),
      std::complex(0.7071067811865476, 0.7071067811865475),
      std::complex(0.38268343236508984, 0.9238795325112867),
      std::complex(0.0, 1.0),
      std::complex(-0.3826834323650897, 0.9238795325112867),
      std::complex(-0.7071067811865475, 0.7071067811865476),
      std::complex(-0.9238795325112867, 0.3826834323650899),
      std::complex(-1.0, 0.0),
      std::complex(-0.9238795325112868, -0.38268343236508967),
      std::complex(-0.7071067811865477, -0.7071067811865475),
      std::complex(-0.38268343236509034, -0.9238795325112865),
      std::complex(0.0, -1.0),
      std::complex(0.38268343236509, -0.9238795325112866),
      std::complex(0.7071067811865474, -0.7071067811865477),
      std::complex(0.9238795325112865, -0.3826834323650904)};

  auto inverse_phi = desilo::fhe::get_inverse_phi(quadruple_slot_count);

  expect_complex_vector_near(inverse_phi, expected, quadruple_slot_count,
                             1e-15);
}

TEST(Bootstrap, GetTwiddleFactor2) {
  const int slot_count = 2;
  const int log_slot_count = 1;
  const int quadruple_slot_count = 8;

  std::vector<std::vector<std::complex<double>>> center_expected = {
      {std::complex(1.0, 0.0),
       std::complex(-0.7071067811865476, 0.7071067811865475)}};

  std::vector<std::vector<std::complex<double>>> left_expected = {
      {std::complex(1.0, 0.0), std::complex(0.0, 0.0)}};

  std::vector<std::vector<std::complex<double>>> right_expected = {
      {std::complex(0.0, 0.0),
       std::complex(0.7071067811865476, -0.7071067811865475)}};

  const auto twiddle_factors =
      desilo::fhe::get_twiddle_factor(slot_count, log_slot_count);
  const auto center_twiddle_factors = twiddle_factors.center;
  const auto left_twiddle_factors = twiddle_factors.left;
  const auto right_twiddle_factors = twiddle_factors.right;

  ASSERT_EQ(center_twiddle_factors.size(), log_slot_count);
  ASSERT_EQ(left_twiddle_factors.size(), log_slot_count);
  ASSERT_EQ(right_twiddle_factors.size(), log_slot_count);

  for (int index = 0; index < log_slot_count; index++) {
    expect_complex_vector_near(center_twiddle_factors[index],
                               center_expected[index], slot_count, 1e-15);
    expect_complex_vector_near(left_twiddle_factors[index],
                               left_expected[index], slot_count, 1e-15);
    expect_complex_vector_near(right_twiddle_factors[index],
                               right_expected[index], slot_count, 1e-15);
  }
}

TEST(Bootstrap, GetTwiddleFactor4) {
  const int slot_count = 4;
  const int log_slot_count = 2;
  const int quadruple_slot_count = 16;

  std::vector<std::vector<std::complex<double>>> center_expected = {
      {std::complex(1.0, 0.0), std::complex(1.0, 0.0),
       std::complex(-0.9238795325112867, 0.3826834323650898),
       std::complex(0.3826834323650897, 0.9238795325112867)},
      {std::complex(1.0, 0.0),
       std::complex(-0.7071067811865476, 0.7071067811865475),
       std::complex(1.0, 0.0),
       std::complex(-0.7071067811865476, 0.7071067811865475)}};

  std::vector<std::vector<std::complex<double>>> left_expected = {
      {std::complex(1.0, 0.0), std::complex(1.0, 0.0), std::complex(0.0, 0.0),
       std::complex(0.0, 0.0)},
      {std::complex(1.0, 0.0), std::complex(0.0, 0.0), std::complex(1.0, 0.0),
       std::complex(0.0, 0.0)}};

  std::vector<std::vector<std::complex<double>>> right_expected = {
      {std::complex(0.0, 0.0), std::complex(0.0, 0.0),
       std::complex(0.9238795325112867, -0.3826834323650898),
       std::complex(-0.3826834323650897, -0.9238795325112867)},
      {std::complex(0.0, 0.0),
       std::complex(0.7071067811865476, -0.7071067811865475),
       std::complex(0.0, 0.0),
       std::complex(0.7071067811865476, -0.7071067811865475)}};

  const auto twiddle_factors =
      desilo::fhe::get_twiddle_factor(slot_count, log_slot_count);
  const auto center_twiddle_factors = twiddle_factors.center;
  const auto left_twiddle_factors = twiddle_factors.left;
  const auto right_twiddle_factors = twiddle_factors.right;

  ASSERT_EQ(center_twiddle_factors.size(), log_slot_count);
  ASSERT_EQ(left_twiddle_factors.size(), log_slot_count);
  ASSERT_EQ(right_twiddle_factors.size(), log_slot_count);

  for (int index = 0; index < log_slot_count; index++) {
    expect_complex_vector_near(center_twiddle_factors[index],
                               center_expected[index], slot_count, 1e-15);
    expect_complex_vector_near(left_twiddle_factors[index],
                               left_expected[index], slot_count, 1e-15);
    expect_complex_vector_near(right_twiddle_factors[index],
                               right_expected[index], slot_count, 1e-15);
  }
}

TEST(Bootstrap, GetInverseTwiddleFactor2) {
  const int slot_count = 2;
  const int log_slot_count = 1;
  const int quadruple_slot_count = 8;

  std::vector<std::vector<std::complex<double>>> center_expected = {
      {std::complex(1.0, 0.0),
       std::complex(-0.7071067811865476, -0.7071067811865475)}};

  std::vector<std::vector<std::complex<double>>> left_expected = {
      {std::complex(0.7071067811865476, 0.7071067811865475),
       std::complex(0.0, 0.0)}};

  std::vector<std::vector<std::complex<double>>> right_expected = {
      {std::complex(0.0, 0.0), std::complex(1.0, 0.0)}};

  const auto inverse_twiddle_factors =
      desilo::fhe::get_inverse_twiddle_factor(slot_count, log_slot_count);
  const auto center = inverse_twiddle_factors.center;
  const auto left = inverse_twiddle_factors.left;
  const auto right = inverse_twiddle_factors.right;

  ASSERT_EQ(center.size(), log_slot_count);
  ASSERT_EQ(left.size(), log_slot_count);
  ASSERT_EQ(right.size(), log_slot_count);

  for (int index = 0; index < log_slot_count; index++) {
    expect_complex_vector_near(center[index], center_expected[index],
                               slot_count, 1e-15);
    expect_complex_vector_near(left[index], left_expected[index], slot_count,
                               1e-15);
    expect_complex_vector_near(right[index], right_expected[index], slot_count,
                               1e-15);
  }
}

TEST(Bootstrap, GetInverseTwiddleFactor4) {
  const int slot_count = 4;
  const int log_slot_count = 2;
  const int quadruple_slot_count = 16;

  std::vector<std::vector<std::complex<double>>> center_expected = {
      {std::complex(1.0, 0.0),
       std::complex(-0.7071067811865476, -0.7071067811865475),
       std::complex(1.0, 0.0),
       std::complex(-0.7071067811865476, -0.7071067811865475)},
      {std::complex(1.0, 0.0), std::complex(1.0, 0.0),
       std::complex(-0.9238795325112867, -0.3826834323650898),
       std::complex(0.3826834323650897, -0.9238795325112867)}};

  std::vector<std::vector<std::complex<double>>> left_expected = {
      {std::complex(0.7071067811865476, 0.7071067811865475),
       std::complex(0.0, 0.0),
       std::complex(0.7071067811865476, 0.7071067811865475),
       std::complex(0.0, 0.0)},
      {std::complex(0.9238795325112867, 0.3826834323650898),
       std::complex(-0.3826834323650897, 0.9238795325112867),
       std::complex(0.0, 0.0), std::complex(0.0, 0.0)}};

  std::vector<std::vector<std::complex<double>>> right_expected = {
      {std::complex(0.0, 0.0), std::complex(1.0, 0.0), std::complex(0.0, 0.0),
       std::complex(1.0, 0.0)},
      {std::complex(0.0, 0.0), std::complex(0.0, 0.0), std::complex(1.0, 0.0),
       std::complex(1.0, 0.0)}};

  const auto inverse_twiddle_factors =
      desilo::fhe::get_inverse_twiddle_factor(slot_count, log_slot_count);
  const auto center = inverse_twiddle_factors.center;
  const auto left = inverse_twiddle_factors.left;
  const auto right = inverse_twiddle_factors.right;

  ASSERT_EQ(center.size(), log_slot_count);
  ASSERT_EQ(left.size(), log_slot_count);
  ASSERT_EQ(right.size(), log_slot_count);

  for (int index = 0; index < log_slot_count; index++) {
    expect_complex_vector_near(center[index], center_expected[index],
                               slot_count, 1e-15);
    expect_complex_vector_near(left[index], left_expected[index], slot_count,
                               1e-15);
    expect_complex_vector_near(right[index], right_expected[index], slot_count,
                               1e-15);
  }
}

TEST(Bootstrap, GetCoeffToSlotTwiddles2) {
  const int slot_count = 2;
  const int log_slot_count = 1;
  const int stage_count = 1;
  const int radix_count = 3;

  std::vector<std::vector<std::vector<std::complex<double>>>> expected = {
      {{std::complex<double>(0.0089285714285714281, 0.0),
        std::complex<double>(-0.0063134534034513176, 0.0063134534034513167)},
       {std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0063134534034513176, -0.0063134534034513167)},
       {std::complex<double>(0.0089285714285714281, 0.0),
        std::complex<double>(0.0, 0.0)}}};

  auto coeff_to_slot_messages = desilo::fhe::get_coeff_to_slot_twiddles(
      slot_count, log_slot_count, stage_count);

  ASSERT_EQ(coeff_to_slot_messages.size(), stage_count);

  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    ASSERT_EQ(coeff_to_slot_messages[stage_index].size(), radix_count);

    for (int index = 0; index < radix_count; index++) {
      expect_complex_vector_near(coeff_to_slot_messages[stage_index][index],
                                 expected[stage_index][index], slot_count,
                                 1e-15);
    }
  }
}

TEST(Bootstrap, GetCoeffToSlotTwiddles4) {
  const int slot_count = 4;
  const int log_slot_count = 2;
  const int stage_count = 1;
  const int radix_count = 7;

  std::vector<std::vector<std::vector<std::complex<double>>>> expected = {
      {{std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(-0.0031567267017256588, 0.0031567267017256584),
        std::complex<double>(-0.0041244621987111011, 0.0017084081802012936),
        std::complex<double>(-0.0041244621987111011, -0.0017084081802012936)},
       {std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0031567267017256588, -0.0031567267017256584),
        std::complex<double>(-0.0017084081802012934, -0.0041244621987111011),
        std::complex<double>(-0.0017084081802012934, 0.0041244621987111011)},
       {std::complex<double>(0.0, 0.0), std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0041244621987111011, -0.0017084081802012934),
        std::complex<double>(0.0041244621987111011, 0.0017084081802012934)},
       {std::complex<double>(0.0, 0.0), std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0017084081802012934, -0.0041244621987111011)},
       {std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(0.0, 0.0), std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0, 0.0)},
       {std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(-0.0031567267017256584, 0.0031567267017256588),
        std::complex<double>(0.0, 0.0), std::complex<double>(0.0, 0.0)},
       {std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(0.0031567267017256584, -0.0031567267017256588),
        std::complex<double>(0.0017084081802012934, 0.0041244621987111011),
        std::complex<double>(0.0, 0.0)}}};

  auto coeff_to_slot_messages = desilo::fhe::get_coeff_to_slot_twiddles(
      slot_count, log_slot_count, stage_count);

  ASSERT_EQ(coeff_to_slot_messages.size(), stage_count);

  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    ASSERT_EQ(coeff_to_slot_messages[stage_index].size(), radix_count);

    for (int index = 0; index < radix_count; index++) {
      expect_complex_vector_near(coeff_to_slot_messages[stage_index][index],
                                 expected[stage_index][index], slot_count,
                                 1e-15);
    }
  }
}

TEST(Bootstrap, GetCoeffToSlotTwiddles4Stage2) {
  const int slot_count = 4;
  const int log_slot_count = 2;
  const int stage_count = 2;
  const int radix_count = 3;

  std::vector<std::vector<std::vector<std::complex<double>>>> expected = {
      {{std::complex<double>(1.0, 0.0), std::complex<double>(1.0, 0.0),
        std::complex<double>(-0.9238795325112867, 0.3826834323650898),
        std::complex<double>(0.3826834323650897, 0.9238795325112867)},
       {std::complex<double>(0.0, 0.0), std::complex<double>(0.0, 0.0),
        std::complex<double>(0.9238795325112867, -0.3826834323650898),
        std::complex<double>(-0.3826834323650897, -0.9238795325112867)},
       {std::complex<double>(1.0, 0.0), std::complex<double>(1.0, 0.0),
        std::complex<double>(0.0, 0.0), std::complex<double>(0.0, 0.0)}},
      {{std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(-0.0031567267017256588, 0.0031567267017256588),
        std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(-0.0031567267017256588, 0.0031567267017256588)},
       {std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0031567267017256588, -0.0031567267017256588),
        std::complex<double>(0.0, 0.0),
        std::complex<double>(0.0031567267017256588, -0.0031567267017256588)},
       {std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(0.0, 0.0),
        std::complex<double>(0.004464285714285714, 0.0),
        std::complex<double>(0.0, 0.0)}}};

  auto coeff_to_slot_messages = desilo::fhe::get_coeff_to_slot_twiddles(
      slot_count, log_slot_count, stage_count);

  ASSERT_EQ(coeff_to_slot_messages.size(), stage_count);

  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    ASSERT_EQ(coeff_to_slot_messages[stage_index].size(), radix_count);

    for (int index = 0; index < radix_count; index++) {
      expect_complex_vector_near(coeff_to_slot_messages[stage_index][index],
                                 expected[stage_index][index], slot_count,
                                 1e-15);
    }
  }
}

TEST(Bootstrap, GetSlotToCoeffTwiddles2) {
  const int slot_count = 2;
  const int log_slot_count = 1;
  const int stage_count = 1;
  const int radix_count = 3;

  std::vector<std::vector<std::vector<std::complex<double>>>> expected = {
      {{std::complex(1.0, 0.0),
        std::complex(-0.7071067811865476, -0.7071067811865475)},
       {std::complex(0.0, 0.0), std::complex(1.0, 0.0)},
       {std::complex(0.7071067811865476, 0.7071067811865475),
        std::complex(0.0, 0.0)}}};

  auto slot_to_coeff_messages = desilo::fhe::get_slot_to_coeff_twiddles(
      slot_count, log_slot_count, stage_count);

  ASSERT_EQ(slot_to_coeff_messages.size(), stage_count);

  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    ASSERT_EQ(slot_to_coeff_messages[stage_index].size(), radix_count);

    for (int index = 0; index < radix_count; index++) {
      expect_complex_vector_near(slot_to_coeff_messages[stage_index][index],
                                 expected[stage_index][index], slot_count,
                                 1e-15);
    }
  }
}

TEST(Bootstrap, GetSlotToCoeffTwiddles4) {
  const int slot_count = 4;
  const int log_slot_count = 2;
  const int stage_count = 1;
  const int radix_count = 7;

  std::vector<std::vector<std::vector<std::complex<double>>>> expected = {
      {{std::complex(1.0, 0.0),
        std::complex(-0.7071067811865476, -0.7071067811865475),
        std::complex(-0.9238795325112867, -0.3826834323650898),
        std::complex(-0.9238795325112866, 0.38268343236508984)},
       {std::complex(0.0, 0.0), std::complex(1.0, 0.0),
        std::complex(0.7071067811865476, 0.7071067811865475),
        std::complex(0.3826834323650897, -0.9238795325112867)},
       {std::complex(0.0, 0.0), std::complex(0.0, 0.0), std::complex(1.0, 0.0),
        std::complex(-0.7071067811865476, -0.7071067811865475)},
       {std::complex(0.0, 0.0), std::complex(0.0, 0.0), std::complex(0.0, 0.0),
        std::complex(1.0, 0.0)},
       {std::complex(0.38268343236508984, 0.9238795325112867),
        std::complex(0.0, 0.0), std::complex(0.0, 0.0), std::complex(0.0, 0.0)},
       {std::complex(0.9238795325112867, 0.3826834323650898),
        std::complex(0.9238795325112866, -0.38268343236508984),
        std::complex(0.0, 0.0), std::complex(0.0, 0.0)},
       {std::complex(0.7071067811865476, 0.7071067811865475),
        std::complex(-0.3826834323650897, 0.9238795325112867),
        std::complex(-0.38268343236508984, -0.9238795325112867),
        std::complex(0.0, 0.0)}}};

  auto slot_to_coeff_messages = desilo::fhe::get_slot_to_coeff_twiddles(
      slot_count, log_slot_count, stage_count);

  ASSERT_EQ(slot_to_coeff_messages.size(), stage_count);

  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    ASSERT_EQ(slot_to_coeff_messages[stage_index].size(), radix_count);

    for (int index = 0; index < radix_count; index++) {
      expect_complex_vector_near(slot_to_coeff_messages[stage_index][index],
                                 expected[stage_index][index], slot_count,
                                 1e-15);
    }
  }
}

TEST(Bootstrap, GetSlotToCoeffTwiddles4Stage2) {
  const int slot_count = 4;
  const int log_slot_count = 2;
  const int stage_count = 2;
  const int radix_count = 3;

  std::vector<std::vector<std::vector<std::complex<double>>>> expected = {
      {{std::complex(1.0, 0.0),
        std::complex(-0.7071067811865476, -0.7071067811865475),
        std::complex(1.0, 0.0),
        std::complex(-0.7071067811865476, -0.7071067811865475)},
       {std::complex(0.0, 0.0), std::complex(1.0, 0.0), std::complex(0.0, 0.0),
        std::complex(1.0, 0.0)},
       {std::complex(0.7071067811865476, 0.7071067811865475),
        std::complex(0.0, 0.0),
        std::complex(0.7071067811865476, 0.7071067811865475),
        std::complex(0.0, 0.0)}},
      {{std::complex(1.0, 0.0), std::complex(1.0, 0.0),
        std::complex(-0.9238795325112867, -0.3826834323650898),
        std::complex(0.3826834323650897, -0.9238795325112867)},
       {std::complex(0.0, 0.0), std::complex(0.0, 0.0), std::complex(1.0, 0.0),
        std::complex(1.0, 0.0)},
       {std::complex(0.9238795325112867, 0.3826834323650898),
        std::complex(-0.3826834323650897, 0.9238795325112867),
        std::complex(0.0, 0.0), std::complex(0.0, 0.0)}}};

  auto slot_to_coeff_messages = desilo::fhe::get_slot_to_coeff_twiddles(
      slot_count, log_slot_count, stage_count);

  ASSERT_EQ(slot_to_coeff_messages.size(), stage_count);

  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    ASSERT_EQ(slot_to_coeff_messages[stage_index].size(), radix_count);

    for (int index = 0; index < radix_count; index++) {
      expect_complex_vector_near(slot_to_coeff_messages[stage_index][index],
                                 expected[stage_index][index], slot_count,
                                 1e-15);
    }
  }
}
