#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPR21(
    SquareUnitSPR21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(SquareUnitSPR21, SquareThenRelinearlize, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto input_rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  const auto squared_level = level - 1;

  if (squared_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);

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

  auto squared = engine.square(input_unit_ciphertext, relinearization_key_);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(squared->level_, squared_level);
  EXPECT_EQ(squared->flag_, flag);
  EXPECT_EQ(squared->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(squared);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (input_ntt || input_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete squared;
})

SETUP_ENGINE_TEST_SPR21(
    RelinearizeUnitSPR21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(RelinearizeUnitSPR21, Ciphertext, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam()) - 1;
  const auto decrypted_level = ciphertext_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext =
      engine.encrypt_unit(message, public_key_, level + 1);
  auto squared = engine.square(unit_ciphertext);

  auto input_unit_ciphertext = squared;

  if (ciphertext_rescaled) {
    auto rescaled_unit_ciphertext = engine.rescale(input_unit_ciphertext);

    if (!ciphertext_ntt) {
      input_unit_ciphertext = engine.intt(rescaled_unit_ciphertext);

      delete rescaled_unit_ciphertext;
    } else {
      input_unit_ciphertext = rescaled_unit_ciphertext;
    }
  } else if (!ciphertext_ntt) {
    input_unit_ciphertext = engine.intt(input_unit_ciphertext);
  }

  const auto relinearized =
      engine.relinearize(input_unit_ciphertext, relinearization_key_);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag = ciphertext_rescaled ? flag | desilo::fhe::DataFlag::RESCALED : flag;

  EXPECT_EQ(relinearized->level_, level);
  EXPECT_EQ(relinearized->flag_, flag);
  EXPECT_EQ(relinearized->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(relinearized);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete squared;
  delete relinearized;
})
