#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP63(
    AddSubtractPlaintextSP63,
    [](const std::tuple<bool, bool, bool, bool, bool, bool,
                        std::tuple<int, int, int>> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_rescaled_flag(std::get<2>(param)) + "And" +
             print_ntt_flag(std::get<3>(param)) +
             print_rescaled_flag(std::get<4>(param)) +
             print_long_extended(std::get<5>(param)) +
             print_level_depth(std::get<0>(std::get<6>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<6>(param)));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(std::make_tuple(0, 0, 0), std::make_tuple(0, 1, 1),
                        std::make_tuple(1, 0, 1), std::make_tuple(1, 1, 1))));

ALL_ENGINE_TEST(AddSubtractPlaintextSP63, AddDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto plaintext_ntt = std::get<3>(GetParam());
  const auto plaintext_rescaled = std::get<4>(GetParam());
  const auto slice_count = std::get<5>(GetParam()) ? 2 : 1;
  const auto levels = std::get<6>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto added_level = max_level_ - std::get<2>(levels);

  if ((ciphertext_rescaled && level1 - 1 < 0) ||
      (plaintext_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level1);
  auto plaintext = engine.encode(message, level2);

  auto input_ciphertext = ciphertext;
  auto input_plaintext = plaintext;

  if (ciphertext_rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);

    if (ciphertext_ntt) {
      input_ciphertext = engine.ntt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
  } else if (ciphertext_ntt) {
    input_ciphertext = engine.ntt(input_ciphertext);
  }

  if (plaintext_rescaled) {
    auto rescaled_plaintext = engine.rescale(input_plaintext);

    if (plaintext_ntt) {
      input_plaintext = engine.ntt(rescaled_plaintext);

      delete rescaled_plaintext;
    } else {
      input_plaintext = rescaled_plaintext;
    }
  } else if (plaintext_ntt) {
    input_plaintext = engine.ntt(input_plaintext);
  }

  auto added = ciphertext_first ? engine.add(input_ciphertext, input_plaintext)
                                : engine.add(input_plaintext, input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (plaintext_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), added_level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(added);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }
  if (plaintext_ntt || plaintext_rescaled) {
    delete input_plaintext;
  }

  delete ciphertext;
  delete plaintext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractPlaintextSP63, SubtractDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto plaintext_ntt = std::get<3>(GetParam());
  const auto plaintext_rescaled = std::get<4>(GetParam());
  const auto slice_count = std::get<5>(GetParam()) ? 2 : 1;
  const auto levels = std::get<6>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto subtracted_level = max_level_ - std::get<2>(levels);

  if ((ciphertext_rescaled && level1 - 1 < 0) ||
      (plaintext_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_sliced_message(message1, slice_count, slot_count, 1.0);
  initiate_sliced_message(message2, slice_count, slot_count, 2.0);

  auto ciphertext = engine.encrypt(message1, public_key_, level1);
  auto plaintext = engine.encode(message2, level2);

  auto input_ciphertext = ciphertext;
  auto input_plaintext = plaintext;

  if (ciphertext_rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);

    if (ciphertext_ntt) {
      input_ciphertext = engine.ntt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
  } else if (ciphertext_ntt) {
    input_ciphertext = engine.ntt(input_ciphertext);
  }

  if (plaintext_rescaled) {
    auto rescaled_plaintext = engine.rescale(input_plaintext);

    if (plaintext_ntt) {
      input_plaintext = engine.ntt(rescaled_plaintext);

      delete rescaled_plaintext;
    } else {
      input_plaintext = rescaled_plaintext;
    }
  } else if (plaintext_ntt) {
    input_plaintext = engine.ntt(input_plaintext);
  }

  auto subtracted = ciphertext_first
                        ? engine.subtract(input_ciphertext, input_plaintext)
                        : engine.subtract(input_plaintext, input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (plaintext_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), subtracted_level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(subtracted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = ciphertext_first ? message1[i] - message2[i]
                                           : message2[i] - message1[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }
  if (plaintext_ntt || plaintext_rescaled) {
    delete input_plaintext;
  }

  delete ciphertext;
  delete plaintext;
  delete subtracted;
})

SETUP_ENGINE_TEST_SP63(
    MultiplySP63,
    [](const std::tuple<bool, bool, bool, bool, bool, bool,
                        std::tuple<int, int, int>> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_rescaled_flag(std::get<2>(param)) + "And" +
             print_ntt_flag(std::get<3>(param)) +
             print_rescaled_flag(std::get<4>(param)) +
             print_long_extended(std::get<5>(param)) +
             print_level_depth(std::get<0>(std::get<6>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<6>(param)));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(std::make_tuple(0, 0, 1), std::make_tuple(0, 1, 2),
                        std::make_tuple(1, 0, 2), std::make_tuple(1, 1, 2))));

ALL_ENGINE_TEST(MultiplySP63, MultiplyPlaintext, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto plaintext_ntt = std::get<3>(GetParam());
  const auto plaintext_rescaled = std::get<4>(GetParam());
  const auto slice_count = std::get<5>(GetParam()) ? 2 : 1;
  const auto levels = std::get<6>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto multiplied_level = max_level_ - std::get<2>(levels);

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level1);
  auto plaintext = engine.encode(message, level2);

  auto input_ciphertext = ciphertext;
  auto input_plaintext = plaintext;

  if (ciphertext_rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);

    if (ciphertext_ntt) {
      input_ciphertext = engine.ntt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
  } else if (ciphertext_ntt) {
    input_ciphertext = engine.ntt(input_ciphertext);
  }

  if (plaintext_rescaled) {
    auto rescaled_plaintext = engine.rescale(input_plaintext);

    if (plaintext_ntt) {
      input_plaintext = engine.ntt(rescaled_plaintext);

      delete rescaled_plaintext;
    } else {
      input_plaintext = rescaled_plaintext;
    }
  } else if (plaintext_ntt) {
    input_plaintext = engine.ntt(input_plaintext);
  }

  auto multiplied = ciphertext_first
                        ? engine.multiply(input_ciphertext, input_plaintext)
                        : engine.multiply(input_plaintext, input_ciphertext);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }
  if (plaintext_ntt || plaintext_rescaled) {
    delete input_plaintext;
  }

  delete ciphertext;
  delete plaintext;
  delete multiplied;
})
