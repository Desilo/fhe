#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPR31(
    SquareSPR31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) + "And" +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(SquareSPR31, SquareThenRelinearlize, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  const auto squared_level = level - 1;

  if (squared_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level);

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

  auto squared = engine.square(input_ciphertext, relinearization_key_);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(squared->level(), squared_level);
  EXPECT_EQ(squared->flag(), flag);
  EXPECT_EQ(squared->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(squared);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete squared;
})

SETUP_ENGINE_TEST_SPR31(
    RelinearizeSPR31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) + "And" +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(RelinearizeSPR31, Ciphertext, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam()) - 1;
  const auto decrypted_level = ciphertext_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level + 1);
  auto squared = engine.square(ciphertext);

  auto input_ciphertext = squared;

  if (ciphertext_rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);

    if (!ciphertext_ntt) {
      input_ciphertext = engine.intt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
  } else if (!ciphertext_ntt) {
    input_ciphertext = engine.intt(input_ciphertext);
  }

  const auto relinearized =
      engine.relinearize(input_ciphertext, relinearization_key_);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = ciphertext_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(relinearized->level(), level);
  EXPECT_EQ(relinearized->flag(), flag);
  EXPECT_EQ(relinearized->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(relinearized);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete squared;
  delete relinearized;
})
