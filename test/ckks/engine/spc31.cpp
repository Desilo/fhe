#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPC31(
    ConjugateSPC31,
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

ALL_ENGINE_TEST(ConjugateSPC31, Plaintext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level_depth = std::get<3>(GetParam());
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

  const auto conjugated = engine.conjugate(input_plaintext);

  auto expected_flag = desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (input_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(conjugated->level(), level);
  EXPECT_EQ(conjugated->flag(), expected_flag);
  EXPECT_EQ(conjugated->polynomial_count(), 1);

  auto decode_input = conjugated;
  if (input_ntt) {
    auto conjugated_intt = engine.intt(decode_input);

    if (is_rescaled(decode_input->flag())) {
      decode_input = engine.level_down(conjugated_intt, level - 1);

      delete conjugated_intt;
    } else {
      decode_input = conjugated_intt;
    }
  } else if (is_rescaled(decode_input->flag())) {
    decode_input = engine.level_down(decode_input, level - 1);
  }

  const auto decoded = engine.decode_complex_plaintext(decode_input);

  for (int i = 0; i < message.size(); i++) {
    const auto expected = std::conj(message[i]);
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_plaintext;
    delete decode_input;
  }

  delete plaintext;
  delete conjugated;
})

ALL_ENGINE_TEST(ConjugateSPC31, Ciphertext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level_depth = std::get<3>(GetParam());
  const auto level = max_level_ - level_depth;
  const auto decrypted_level = input_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

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

  const auto conjugated = engine.conjugate(input_ciphertext, conjugation_key_);

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(conjugated->level(), expected_level);
  EXPECT_EQ(conjugated->flag(), flag);
  EXPECT_EQ(conjugated->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(conjugated);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(-message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete conjugated;
})
