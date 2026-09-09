#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPF21(
    RotateUnitSPF21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(RotateUnitSPF21, Ciphertext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  const auto decrypted_level = input_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);

  auto input_unit_ciphertext = unit_ciphertext;

  if (input_rescaled) {
    auto rescaled_unit_ciphertext = engine.rescale(input_unit_ciphertext);

    if (input_ntt) {
      input_unit_ciphertext = engine.ntt(rescaled_unit_ciphertext);

      delete rescaled_unit_ciphertext;
    } else {
      input_unit_ciphertext = rescaled_unit_ciphertext;
    }
  } else if (input_ntt) {
    input_unit_ciphertext = engine.ntt(input_unit_ciphertext);
  }

  const auto rotated =
      engine.rotate(input_unit_ciphertext, fixed_rotation_key_);

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(rotated->level_, expected_level);
  EXPECT_EQ(rotated->flag_, flag);
  EXPECT_EQ(rotated->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(rotated);

  const auto normalized_delta = delta_ % slot_count;

  for (int i = 0; i < normalized_delta; i++) {
    const auto expected = message[slot_count - normalized_delta + i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  for (int i = normalized_delta; i < slot_count; i++) {
    const auto expected = message[i - normalized_delta];
    EXPECT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    EXPECT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete rotated;
})
