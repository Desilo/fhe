#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPE22(
    LevelDownSPE22,
    [](const std::tuple<bool, bool, std::tuple<int, int>> &param) {
      return (std::get<0>(param) ? "Rescaled" : "") +
             print_level_depth(std::get<0>(std::get<2>(param))) + "To" +
             print_level_depth(std::get<1>(std::get<2>(param)));
    },
    testing::Values(

        std::make_tuple(false, false, std::make_tuple(0, 0)),
        std::make_tuple(true, true, std::make_tuple(0, 0)),
        std::make_tuple(false, false, std::make_tuple(0, 1)),
        std::make_tuple(true, false, std::make_tuple(0, 1)),

        std::make_tuple(false, false, std::make_tuple(0, 2)),
        std::make_tuple(true, false, std::make_tuple(0, 2))));

ALL_ENGINE_TEST(LevelDownSPE22, NTTTrioUnitCiphertext, {
  const auto source_rescaled = std::get<0>(GetParam());
  const auto destination_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);

  const auto destination_level = max_level_ - std::get<1>(level_depths) - 1;

  if (destination_level < 0 ||
      (destination_rescaled && destination_level < 1)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext1 =
      engine.encrypt_unit(message, public_key_, source_level);
  const auto unit_ciphertext2 =
      engine.encrypt_unit(message, public_key_, source_level);
  const auto multiplied = engine.multiply(unit_ciphertext1, unit_ciphertext2);

  const auto level_down_input =
      source_rescaled ? engine.rescale(multiplied) : multiplied;

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  auto flag = desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(leveled_down->level_, destination_level);
  EXPECT_EQ(leveled_down->flag_, destination_rescaled
                                     ? desilo::fhe::DataFlag::RESCALED | flag
                                     : flag);
  EXPECT_EQ(leveled_down->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete multiplied;
  if (source_rescaled) {
    delete level_down_input;
  }
  delete leveled_down;
})

ALL_ENGINE_TEST(LevelDownSPE22, INTTTrioUnitCiphertext, {
  const auto source_rescaled = std::get<0>(GetParam());
  const auto destination_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);

  const auto destination_level = max_level_ - std::get<1>(level_depths) - 1;

  if (destination_level < 0 ||
      (destination_rescaled && destination_level < 1)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext1 =
      engine.encrypt_unit(message, public_key_, source_level);
  const auto unit_ciphertext2 =
      engine.encrypt_unit(message, public_key_, source_level);
  const auto multiplied = engine.multiply(unit_ciphertext1, unit_ciphertext2);

  const auto level_down_ntt =
      source_rescaled ? engine.rescale(multiplied) : multiplied;
  const auto level_down_input = engine.intt(level_down_ntt);

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(leveled_down->level_, destination_level);
  EXPECT_EQ(leveled_down->flag_, destination_rescaled
                                     ? desilo::fhe::DataFlag::RESCALED | flag
                                     : flag);
  EXPECT_EQ(leveled_down->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete multiplied;
  if (source_rescaled) {
    delete level_down_ntt;
  }
  delete level_down_input;
  delete leveled_down;
})

SETUP_ENGINE_TEST_SPE22(
    LevelDownSPE22B,
    [](const std::tuple<bool, bool, std::tuple<int, int>> &param) {
      return print_long_extended(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_level_depth(std::get<0>(std::get<2>(param))) + "To" +
             print_level_depth(std::get<1>(std::get<2>(param)));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(std::make_tuple(0, 0), std::make_tuple(0, 1),
                        std::make_tuple(0, 2), std::make_tuple(1, 2))));

ALL_ENGINE_TEST(LevelDownSPE22B, NTTTrioCiphertext, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto source_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths) - 1;

  auto destination_rescaled = false;
  if (source_rescaled && source_level - 1 == destination_level) {
    destination_rescaled = true;
  }

  if (destination_level < 0 ||
      (destination_rescaled && destination_level < 1)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext1 = engine.encrypt(message, public_key_, source_level);
  const auto ciphertext2 = engine.encrypt(message, public_key_, source_level);
  const auto multiplied = engine.multiply(ciphertext1, ciphertext2);

  const auto level_down_input =
      source_rescaled ? engine.rescale(multiplied) : multiplied;

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  auto flag = desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(leveled_down->level(), destination_level);
  EXPECT_EQ(leveled_down->flag(), destination_rescaled
                                      ? desilo::fhe::DataFlag::RESCALED | flag
                                      : flag);
  EXPECT_EQ(leveled_down->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext1;
  delete ciphertext2;
  delete multiplied;
  if (source_rescaled) {
    delete level_down_input;
  }
  delete leveled_down;
})

ALL_ENGINE_TEST(LevelDownSPE22B, INTTTrioCiphertext, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto source_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths) - 1;

  auto destination_rescaled = false;
  if (source_rescaled && source_level - 1 == destination_level) {
    destination_rescaled = true;
  }

  if (destination_level < 0 ||
      (destination_rescaled && destination_level < 1)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext1 = engine.encrypt(message, public_key_, source_level);
  const auto ciphertext2 = engine.encrypt(message, public_key_, source_level);
  const auto multiplied = engine.multiply(ciphertext1, ciphertext2);

  const auto level_down_ntt =
      source_rescaled ? engine.rescale(multiplied) : multiplied;
  const auto level_down_input = engine.intt(level_down_ntt);

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(leveled_down->level(), destination_level);
  EXPECT_EQ(leveled_down->flag(), destination_rescaled
                                      ? desilo::fhe::DataFlag::RESCALED | flag
                                      : flag);
  EXPECT_EQ(leveled_down->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext1;
  delete ciphertext2;
  delete multiplied;
  if (source_rescaled) {
    delete level_down_ntt;
  }
  delete level_down_input;
  delete leveled_down;
})
