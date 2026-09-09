#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPO23(
    RotateUnitSPO23,
    [](const std::tuple<bool, bool, std::tuple<int, int, int>> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_level_depth(std::get<0>(std::get<2>(param))) +
             print_delta(std::get<1>(std::get<2>(param)));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),
        testing::Values(

            std::make_tuple(0, 0, 0), std::make_tuple(0, 1, 1),
            std::make_tuple(0, 3, 3), std::make_tuple(0, -1, 8191),
            std::make_tuple(1, 0, 0), std::make_tuple(1, 1, 1),
            std::make_tuple(1, 3, 3), std::make_tuple(1, -1, 8191))));

ALL_ENGINE_TEST(RotateUnitSPO23, Plaintext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto level_depth = std::get<0>(std::get<2>(GetParam()));
  const auto delta = std::get<1>(std::get<2>(GetParam()));
  auto normalized_delta = std::get<2>(std::get<2>(GetParam()));
  const auto level = max_level_ - level_depth;
  const auto decoded_level = input_rescaled ? level - 1 : level;

  if (decoded_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_plaintext = engine.encode_unit(message, level);

  auto input_unit_plaintext = unit_plaintext;

  if (input_rescaled) {
    auto rescaled_unit_plaintext = engine.rescale(input_unit_plaintext);

    if (input_ntt) {
      input_unit_plaintext = engine.ntt(rescaled_unit_plaintext);

      delete rescaled_unit_plaintext;
    } else {
      input_unit_plaintext = rescaled_unit_plaintext;
    }
  } else if (input_ntt) {
    input_unit_plaintext = engine.ntt(input_unit_plaintext);
  }

  const auto rotated = engine.rotate(input_unit_plaintext, delta);

  auto expected_flag = desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (input_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(rotated->level_, level);
  EXPECT_EQ(rotated->flag_, expected_flag);
  EXPECT_EQ(rotated->polynomial_count(), 1);

  if (delta == -1) {
    normalized_delta = 7;
  }

  normalized_delta %= slot_count;

  auto decode_input = rotated;
  if (input_ntt) {
    auto rotated_intt = engine.intt(decode_input);

    if (is_rescaled(decode_input->flag_)) {
      decode_input = engine.level_down(rotated_intt, level - 1);

      delete rotated_intt;
    } else {
      decode_input = rotated_intt;
    }
  } else if (is_rescaled(decode_input->flag_)) {
    decode_input = engine.level_down(decode_input, level - 1);
  }

  const auto decoded = engine.decode_complex_unit_plaintext(decode_input);

  for (int i = 0; i < normalized_delta; i++) {
    const auto expected = message[slot_count - normalized_delta + i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  for (int i = normalized_delta; i < slot_count; i++) {
    const auto expected = message[i - normalized_delta];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_unit_plaintext;
    delete decode_input;
  }

  delete unit_plaintext;
  delete rotated;
})

ALL_ENGINE_TEST(RotateUnitSPO23, Ciphertext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto level_depth = std::get<0>(std::get<2>(GetParam()));
  const auto delta = std::get<1>(std::get<2>(GetParam()));
  auto normalized_delta = std::get<2>(std::get<2>(GetParam()));
  const auto level = max_level_ - level_depth;
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
      engine.rotate(input_unit_ciphertext, rotation_key_, delta);

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && delta != 0 && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(rotated->level_, expected_level);
  EXPECT_EQ(rotated->flag_, flag);
  EXPECT_EQ(rotated->polynomial_count(), 2);

  if (delta == -1) {
    normalized_delta = 7;
  }

  normalized_delta %= slot_count;

  const auto decrypted = DECRYPT_UNIT_COMPLEX(rotated);

  for (int i = 0; i < normalized_delta; i++) {
    const auto expected = message[slot_count - normalized_delta + i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  for (int i = normalized_delta; i < slot_count; i++) {
    const auto expected = message[i - normalized_delta];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete rotated;
})

ALL_ENGINE_TEST(RotateUnitSPO23, BatchUnitCiphertextRotationKey, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto level_depth = std::get<0>(std::get<2>(GetParam()));
  const auto delta = std::get<1>(std::get<2>(GetParam()));
  auto normalized_delta = std::get<2>(std::get<2>(GetParam()));
  const auto level = max_level_ - level_depth;
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
      engine.rotate_batch(input_unit_ciphertext, rotation_key_, deltas);

  ASSERT_EQ(rotated.size(), deltas.size());

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  for (auto rotate_index = 0; rotate_index < deltas.size(); rotate_index++) {
    auto rotated_unit_ciphertext = rotated[rotate_index];
    auto delta = deltas[rotate_index];
    EXPECT_EQ(rotated_unit_ciphertext->level(), expected_level);
    EXPECT_EQ(rotated_unit_ciphertext->flag(), flag);
    EXPECT_EQ(rotated_unit_ciphertext->polynomial_count(), 2);

    const auto decrypted = DECRYPT_UNIT_COMPLEX(rotated_unit_ciphertext);

    for (int i = 0; i < delta; i++) {
      const auto expected = message[slot_count - delta + i];
      ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
      ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
    }

    for (int i = delta; i < slot_count; i++) {
      const auto expected = message[i - delta];
      ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
      ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
    }
  }

  if (input_ntt || input_rescaled) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  for (auto rotated_unit_ciphertext : rotated) {
    delete rotated_unit_ciphertext;
  }
})
