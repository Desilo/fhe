#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP22(
    LevelDownSP22,
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

ALL_ENGINE_TEST(LevelDownSP22, UnitPlaintext, {
  const auto source_rescaled = std::get<0>(GetParam());
  const auto destination_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths);

  if (destination_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_plaintext = engine.encode_unit(message, source_level);

  const auto level_down_input =
      source_rescaled ? engine.rescale(unit_plaintext) : unit_plaintext;

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  EXPECT_EQ(leveled_down->level_, destination_level);
  EXPECT_EQ(leveled_down->flag_, destination_rescaled
                                     ? desilo::fhe::DataFlag::RESCALED |
                                           desilo::fhe::DataFlag::COMPLEX
                                     : desilo::fhe::DataFlag::COMPLEX);

  const auto encrypt_input =
      destination_rescaled
          ? engine.level_down(leveled_down, destination_level - 1)
          : leveled_down;

  const auto unit_ciphertext = engine.encrypt_unit(encrypt_input, public_key_);
  const auto decrypted = DECRYPT_UNIT_COMPLEX(unit_ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_plaintext;
  if (source_rescaled) {
    delete level_down_input;
  }
  delete leveled_down;
  if (destination_rescaled) {
    delete encrypt_input;
  }
  delete unit_ciphertext;
})

ALL_ENGINE_TEST(LevelDownSP22, INTTDuoUnitCiphertext, {
  const auto source_rescaled = std::get<0>(GetParam());
  const auto destination_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths);

  if (destination_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext =
      engine.encrypt_unit(message, public_key_, source_level);

  const auto level_down_input =
      source_rescaled ? engine.rescale(unit_ciphertext) : unit_ciphertext;

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(leveled_down->level_, destination_level);
  EXPECT_EQ(leveled_down->flag_, destination_rescaled
                                     ? desilo::fhe::DataFlag::RESCALED | flag
                                     : flag);
  EXPECT_EQ(leveled_down->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  if (source_rescaled) {
    delete level_down_input;
  }
  delete leveled_down;
})

ALL_ENGINE_TEST(LevelDownSP22, NTTDuoUnitCiphertext, {
  const auto source_rescaled = std::get<0>(GetParam());
  const auto destination_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths);

  if (destination_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext =
      engine.encrypt_unit(message, public_key_, source_level);

  const auto level_down_intt =
      source_rescaled ? engine.rescale(unit_ciphertext) : unit_ciphertext;
  const auto level_down_input = engine.ntt(level_down_intt);

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  auto flag = desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(leveled_down->level_, destination_level);
  EXPECT_EQ(leveled_down->flag_, destination_rescaled
                                     ? desilo::fhe::DataFlag::RESCALED | flag
                                     : flag);
  EXPECT_EQ(leveled_down->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  if (source_rescaled) {
    delete level_down_intt;
  }
  delete level_down_input;
  delete leveled_down;
})

SETUP_ENGINE_TEST_SP22(
    LevelDownSP22B,
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

ALL_ENGINE_TEST(LevelDownSP22B, Plaintext, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto source_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths);

  if (destination_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto destination_rescaled = false;
  if (source_rescaled && source_level == destination_level) {
    destination_rescaled = true;
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto plaintext = engine.encode(message, source_level);

  const auto level_down_input =
      source_rescaled ? engine.rescale(plaintext) : plaintext;

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  EXPECT_EQ(leveled_down->level(), destination_level);
  EXPECT_EQ(leveled_down->flag(), destination_rescaled
                                      ? desilo::fhe::DataFlag::RESCALED |
                                            desilo::fhe::DataFlag::COMPLEX
                                      : desilo::fhe::DataFlag::COMPLEX);

  const auto decode_input =
      destination_rescaled
          ? engine.level_down(leveled_down, destination_level - 1)
          : leveled_down;

  const auto decoded = engine.decode_complex_plaintext(decode_input);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  if (source_rescaled) {
    delete level_down_input;
  }
  if (destination_rescaled) {
    delete decode_input;
  }
  delete leveled_down;
})

ALL_ENGINE_TEST(LevelDownSP22B, INTTDuoCiphertext, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto source_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths);

  if (destination_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto destination_rescaled = false;
  if (source_rescaled && source_level == destination_level) {
    destination_rescaled = true;
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, source_level);

  const auto level_down_input =
      source_rescaled ? engine.rescale(ciphertext) : ciphertext;

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(leveled_down->level(), destination_level);
  EXPECT_EQ(leveled_down->flag(), destination_rescaled
                                      ? desilo::fhe::DataFlag::RESCALED | flag
                                      : flag);

  const auto decrypted = DECRYPT_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext;
  if (source_rescaled) {
    delete level_down_input;
  }
  delete leveled_down;
})

ALL_ENGINE_TEST(LevelDownSP22B, NTTDuoCiphertext, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto source_rescaled = std::get<1>(GetParam());
  const auto level_depths = std::get<2>(GetParam());
  const auto source_level = max_level_ - std::get<0>(level_depths);
  const auto destination_level = max_level_ - std::get<1>(level_depths);

  if (destination_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto destination_rescaled = false;
  if (source_rescaled && source_level == destination_level) {
    destination_rescaled = true;
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, source_level);

  const auto level_down_intt =
      source_rescaled ? engine.rescale(ciphertext) : ciphertext;
  const auto level_down_input = engine.ntt(level_down_intt);

  const auto leveled_down =
      engine.level_down(level_down_input, destination_level);

  auto flag = desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(leveled_down->level(), destination_level);
  EXPECT_EQ(leveled_down->flag(), destination_rescaled
                                      ? desilo::fhe::DataFlag::RESCALED | flag
                                      : flag);

  const auto decrypted = DECRYPT_COMPLEX(leveled_down);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext;
  if (source_rescaled) {
    delete level_down_intt;
  }
  delete level_down_input;
  delete leveled_down;
})
