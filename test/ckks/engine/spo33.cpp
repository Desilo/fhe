#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPO33(
    RotateSPO33,
    [](const std::tuple<bool, bool, bool, std::tuple<int, int, int>> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) + "And" +
             print_level_depth(std::get<0>(std::get<3>(param))) +
             print_delta(std::get<1>(std::get<3>(param)));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),
        testing::Values(

            std::make_tuple(0, 0, 0), std::make_tuple(0, 1, 1),
            std::make_tuple(0, 3, 3), std::make_tuple(0, -1, 8191),
            std::make_tuple(1, 0, 0), std::make_tuple(1, 1, 1),
            std::make_tuple(1, 3, 3), std::make_tuple(1, -1, 8191))));

ALL_ENGINE_TEST(RotateSPO33, Plaintext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level_depth = std::get<0>(std::get<3>(GetParam()));
  const auto delta = std::get<1>(std::get<3>(GetParam()));
  auto normalized_delta = std::get<2>(std::get<3>(GetParam()));
  const auto level = max_level_ - level_depth;
  const auto decoded_level = input_rescaled ? level - 1 : level;

  if (decoded_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto plaintext = engine.encode(message, level);

  auto input_plaintext = plaintext;

  if (input_rescaled) {
    auto rescaled_plaintext = engine.rescale(input_plaintext);

    if (input_ntt) {
      input_plaintext = engine.ntt(rescaled_plaintext);

      delete rescaled_plaintext;
    } else {
      input_plaintext = rescaled_plaintext;
    }
  } else if (input_ntt) {
    input_plaintext = engine.ntt(input_plaintext);
  }

  const auto rotated = engine.rotate(input_plaintext, delta);

  auto expected_flag = desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (input_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(rotated->level(), level);
  EXPECT_EQ(rotated->flag(), expected_flag);
  EXPECT_EQ(rotated->polynomial_count(), 1);

  if (delta == -1) {
    normalized_delta = 7;
  }

  normalized_delta %= slot_count;

  auto decode_input = rotated;
  if (input_ntt) {
    auto rotated_intt = engine.intt(decode_input);

    if (is_rescaled(decode_input->flag())) {
      decode_input = engine.level_down(rotated_intt, level - 1);

      delete rotated_intt;
    } else {
      decode_input = rotated_intt;
    }
  } else if (is_rescaled(decode_input->flag())) {
    decode_input = engine.level_down(decode_input, level - 1);
  }

  const auto decoded = engine.decode_complex_plaintext(decode_input);

  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    auto offset = slice_index * slot_count;
    for (int i = 0; i < normalized_delta; i++) {
      const auto expected = message[slot_count - normalized_delta + i + offset];
      ASSERT_NEAR(expected.real(), decoded[i + offset].real(), 1e-4);
      ASSERT_NEAR(expected.imag(), decoded[i + offset].imag(), 1e-4);
    }

    for (int i = normalized_delta; i < slot_count; i++) {
      const auto expected = message[i - normalized_delta + offset];
      ASSERT_NEAR(expected.real(), decoded[i + offset].real(), 1e-4);
      ASSERT_NEAR(expected.imag(), decoded[i + offset].imag(), 1e-4);
    }
  }

  if (input_ntt || input_rescaled) {
    delete input_plaintext;
    delete decode_input;
  }

  delete plaintext;
  delete rotated;
})

ALL_ENGINE_TEST(RotateSPO33, Ciphertext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level_depth = std::get<0>(std::get<3>(GetParam()));
  const auto delta = std::get<1>(std::get<3>(GetParam()));
  auto normalized_delta = std::get<2>(std::get<3>(GetParam()));
  const auto level = max_level_ - level_depth;
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

  const auto rotated = engine.rotate(input_ciphertext, rotation_key_, delta);

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && delta != 0 && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(rotated->level(), expected_level);
  EXPECT_EQ(rotated->flag(), flag);
  EXPECT_EQ(rotated->polynomial_count(), 2);

  if (delta == -1) {
    normalized_delta = 7;
  }

  normalized_delta %= slot_count;

  const auto decrypted = DECRYPT_COMPLEX(rotated);

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

ALL_ENGINE_TEST(RotateSPO33, BatchCiphertextFixedRotationKeys, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level_depth = std::get<0>(std::get<3>(GetParam()));
  const auto delta = std::get<1>(std::get<3>(GetParam()));
  auto normalized_delta = std::get<2>(std::get<3>(GetParam()));
  const auto level = max_level_ - level_depth;
  const auto decrypted_level = input_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (delta != 0) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  if (slot_count == 2) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  std::vector<desilo::fhe::FixedRotationKey *> fixed_rotation_keys(2);
  fixed_rotation_keys[0] = rotation_key_->fixed_rotation_keys_[0];
  fixed_rotation_keys[1] = rotation_key_->fixed_rotation_keys_[1];

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

  const auto rotated =
      engine.rotate_batch(input_ciphertext, fixed_rotation_keys);

  ASSERT_EQ(rotated.size(), fixed_rotation_keys.size());

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  for (auto rotate_index = 0; rotate_index < fixed_rotation_keys.size();
       rotate_index++) {
    auto rotated_ciphertext = rotated[rotate_index];
    auto delta = fixed_rotation_keys[rotate_index]->delta_;
    EXPECT_EQ(rotated_ciphertext->level(), expected_level);
    EXPECT_EQ(rotated_ciphertext->flag(), flag);
    EXPECT_EQ(rotated_ciphertext->polynomial_count(), 2);

    const auto decrypted = DECRYPT_COMPLEX(rotated_ciphertext);

    for (int slice_index = 0; slice_index < slice_count; slice_index++) {
      auto offset = slice_index * slot_count;
      for (int i = 0; i < delta; i++) {
        const auto expected = message[slot_count - delta + i + offset];
        ASSERT_NEAR(expected.real(), decrypted[i + offset].real(), 1e-4);
        ASSERT_NEAR(expected.imag(), decrypted[i + offset].imag(), 1e-4);
      }

      for (int i = delta; i < slot_count; i++) {
        const auto expected = message[i - delta + offset];
        ASSERT_NEAR(expected.real(), decrypted[i + offset].real(), 1e-4);
        ASSERT_NEAR(expected.imag(), decrypted[i + offset].imag(), 1e-4);
      }
    }
  }

  if (input_ntt || input_rescaled) {
    delete input_ciphertext;
  }
  delete ciphertext;
  for (auto rotated_ciphertext : rotated) {
    delete rotated_ciphertext;
  }
})

ALL_ENGINE_TEST(RotateSPO33, BatchCiphertextRotationKey, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level_depth = std::get<0>(std::get<3>(GetParam()));
  const auto delta = std::get<1>(std::get<3>(GetParam()));
  auto normalized_delta = std::get<2>(std::get<3>(GetParam()));
  const auto level = max_level_ - level_depth;
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

  std::vector<int> deltas;
  switch (delta) {
  case 0:
    deltas.resize(2);
    deltas[0] = 1;
    deltas[1] = 2;
    break;
  case 1:
    deltas.resize(4);
    deltas[0] = 1;
    deltas[1] = 1;
    deltas[2] = 1;
    deltas[3] = 1;
    break;
  case 3:
    deltas.resize(8);
    deltas[0] = 1;
    deltas[1] = 2;
    deltas[2] = 3;
    deltas[3] = 4;
    deltas[4] = 5;
    deltas[5] = 6;
    deltas[6] = 7;
    deltas[7] = 8;
    break;
  case -1:
    deltas.resize(4);
    deltas[0] = 7;
    deltas[1] = 3;
    deltas[2] = 1;
    deltas[3] = 0;
    break;
  default:
    FAIL();
  }

  for (auto rotate_index = 0; rotate_index < deltas.size(); rotate_index++) {
    deltas[rotate_index] %= slot_count;
  }
  const auto rotated =
      engine.rotate_batch(input_ciphertext, rotation_key_, deltas);

  ASSERT_EQ(rotated.size(), deltas.size());

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  for (auto rotate_index = 0; rotate_index < deltas.size(); rotate_index++) {
    auto rotated_ciphertext = rotated[rotate_index];
    auto delta = deltas[rotate_index];
    EXPECT_EQ(rotated_ciphertext->level(), expected_level);
    EXPECT_EQ(rotated_ciphertext->flag(), flag);
    EXPECT_EQ(rotated_ciphertext->polynomial_count(), 2);

    const auto decrypted = DECRYPT_COMPLEX(rotated_ciphertext);

    for (int slice_index = 0; slice_index < slice_count; slice_index++) {
      auto offset = slice_index * slot_count;
      for (int i = 0; i < delta; i++) {
        const auto expected = message[slot_count - delta + i + offset];
        ASSERT_NEAR(expected.real(), decrypted[i + offset].real(), 1e-4);
        ASSERT_NEAR(expected.imag(), decrypted[i + offset].imag(), 1e-4);
      }

      for (int i = delta; i < slot_count; i++) {
        const auto expected = message[i - delta + offset];
        ASSERT_NEAR(expected.real(), decrypted[i + offset].real(), 1e-4);
        ASSERT_NEAR(expected.imag(), decrypted[i + offset].imag(), 1e-4);
      }
    }
  }

  if (input_ntt || input_rescaled) {
    delete input_ciphertext;
  }
  delete ciphertext;
  for (auto rotated_ciphertext : rotated) {
    delete rotated_ciphertext;
  }
})
