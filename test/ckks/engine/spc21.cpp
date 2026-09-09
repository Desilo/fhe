#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPC21(
    ConjugateUnitSPC21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(ConjugateUnitSPC21, Plaintext, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto level_depth = std::get<2>(GetParam());
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

  const auto conjugated = engine.conjugate(input_unit_plaintext);

  auto expected_flag = desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (input_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(conjugated->level_, level);
  EXPECT_EQ(conjugated->flag_, expected_flag);
  EXPECT_EQ(conjugated->polynomial_count(), 1);

  auto decode_input = conjugated;
  if (input_ntt) {
    auto conjugated_intt = engine.intt(decode_input);

    if (is_rescaled(decode_input->flag_)) {
      decode_input = engine.level_down(conjugated_intt, level - 1);

      delete conjugated_intt;
    } else {
      decode_input = conjugated_intt;
    }
  } else if (is_rescaled(decode_input->flag_)) {
    decode_input = engine.level_down(decode_input, level - 1);
  }

  const auto decoded = engine.decode_complex_unit_plaintext(decode_input);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = std::conj(message[i]);
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_unit_plaintext;
    delete decode_input;
  }

  delete unit_plaintext;
  delete conjugated;
})

ALL_ENGINE_TEST(ConjugateUnitSPC21, Ciphertext, {
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

  const auto conjugated =
      engine.conjugate(input_unit_ciphertext, conjugation_key_);

  int expected_level = level;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL && !input_rescaled) {
    expected_level -= 1;
  }

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = input_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(conjugated->level_, expected_level);
  EXPECT_EQ(conjugated->flag_, flag);
  EXPECT_EQ(conjugated->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(conjugated);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(-message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete conjugated;
})
