#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPF31(
    RotateSPF31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) + "And" +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(RotateSPF31, Ciphertext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  const auto decrypted_level = input_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  auto input_ciphertext = ciphertext;

  if (input_rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);

    if (input_ntt) {
      input_ciphertext = engine.ntt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
  } else if (input_ntt) {
    input_ciphertext = engine.ntt(input_ciphertext);
  }

  const auto rotated = engine.rotate(input_ciphertext, fixed_rotation_key_);

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(rotated->level(), expected_level);
  EXPECT_EQ(rotated->flag(), flag);
  EXPECT_EQ(rotated->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(rotated);

  const auto normalized_delta = delta_ % slot_count;

  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    auto offset = slice_index * slot_count;
    for (int i = 0; i < normalized_delta; i++) {
      const auto expected = message[slot_count - normalized_delta + i + offset];
      ASSERT_NEAR(expected.real(), decrypted[i + offset].real(), 1e-4);
      ASSERT_NEAR(expected.imag(), decrypted[i + offset].imag(), 1e-4);
    }

    for (int i = normalized_delta; i < slot_count; i++) {
      const auto expected = message[i - normalized_delta + offset];
      ASSERT_NEAR(expected.real(), decrypted[i + offset].real(), 1e-4);
      ASSERT_NEAR(expected.imag(), decrypted[i + offset].imag(), 1e-4);
    }
  }

  if (input_ntt || input_rescaled) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete rotated;
})
