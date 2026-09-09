#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP21(
    MultiplyUnitScalarSP21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(MultiplyUnitScalarSP21, MultiplyDuoDouble, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto input_unit_ciphertext =
      ciphertext_ntt ? engine.ntt(unit_ciphertext) : unit_ciphertext;
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_unit_ciphertext, 2.0)
                              : engine.multiply(2.0, input_unit_ciphertext);
  const auto decrypted = DECRYPT_UNIT_COMPLEX(multiplied);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level_, multiplied_level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyUnitScalarSP21, MultiplyDuoInteger, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto input_unit_ciphertext =
      ciphertext_ntt ? engine.ntt(unit_ciphertext) : unit_ciphertext;
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_unit_ciphertext, 2l)
                              : engine.multiply(2l, input_unit_ciphertext);
  const auto decrypted = DECRYPT_UNIT_COMPLEX(multiplied);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level_, level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyUnitScalarSP21, MultiplyDuoImaginary, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto input_unit_ciphertext =
      ciphertext_ntt ? engine.ntt(unit_ciphertext) : unit_ciphertext;
  const auto multiplied =
      ciphertext_first ? engine.multiply_imaginary(input_unit_ciphertext, 1)
                       : engine.multiply_imaginary(1, input_unit_ciphertext);
  const auto decrypted = DECRYPT_UNIT_COMPLEX(multiplied);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  if (ciphertext_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(multiplied->level_, level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * std::complex(0.0, 1.0);
    EXPECT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    EXPECT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete multiplied;
})

SETUP_ENGINE_TEST_SP21(
    RescaleSP21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_long_extended(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(0, 1, 2)));

ALL_ENGINE_TEST(RescaleSP21, CiphertextDuo, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto input_ntt = std::get<1>(GetParam());
  const auto level_depth = std::get<2>(GetParam());
  const auto source_level = max_level_ - level_depth;

  if (source_level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto unit_ciphertext =
      engine.encrypt(message, public_key_, source_level);

  const auto rescale_input =
      input_ntt ? engine.ntt(unit_ciphertext) : unit_ciphertext;

  const auto rescaled = engine.rescale(rescale_input);

  auto flag = desilo::fhe::DataFlag::RESCALED | desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(rescaled->level(), source_level);
  EXPECT_EQ(rescaled->flag(), flag);

  const auto decrypted = DECRYPT_COMPLEX(rescaled);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete rescaled;
  if (input_ntt) {
    delete rescale_input;
  }
})

ALL_ENGINE_TEST(RescaleSP21, Plaintext, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto input_ntt = std::get<1>(GetParam());
  const auto level_depth = std::get<2>(GetParam());
  const auto source_level = max_level_ - level_depth;

  if (source_level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto plaintext = engine.encode(message, source_level);

  const auto rescale_input = input_ntt ? engine.ntt(plaintext) : plaintext;

  const auto rescaled = engine.rescale(rescale_input);

  auto flag = desilo::fhe::DataFlag::RESCALED | desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(rescaled->level(), source_level);
  EXPECT_EQ(rescaled->flag(), flag);

  const auto leveled_down = engine.level_down(rescaled, source_level - 1);
  const auto decode_input =
      input_ntt ? engine.intt(leveled_down) : leveled_down;

  const auto decrypted = engine.decode_complex_plaintext(decode_input);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete plaintext;
  delete rescaled;
  delete leveled_down;
  if (input_ntt) {
    delete rescale_input;
    delete decode_input;
  }
})

SETUP_ENGINE_TEST_SP21(
    DecryptUnitSP21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(DecryptUnitSP21, DecryptUnitDuo, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  const auto decrypted_level = ciphertext_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);

  auto input_unit_ciphertext = unit_ciphertext;

  if (ciphertext_rescaled) {
    auto rescaled_unit_ciphertext = engine.rescale(input_unit_ciphertext);

    if (ciphertext_ntt) {
      input_unit_ciphertext = engine.ntt(rescaled_unit_ciphertext);

      delete rescaled_unit_ciphertext;
    } else {
      input_unit_ciphertext = rescaled_unit_ciphertext;
    }
  } else if (ciphertext_ntt) {
    input_unit_ciphertext = engine.ntt(input_unit_ciphertext);
  }

  const auto decrypted = DECRYPT_UNIT_COMPLEX(input_unit_ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
})

SETUP_ENGINE_TEST_SP21(
    AddSubtractUnitSP21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(AddSubtractUnitSP21, AddInplaceDuo, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext1 = engine.encrypt_unit(message, public_key_, level);
  auto unit_ciphertext2 = engine.encrypt_unit(message, public_key_, level);

  auto input_unit_ciphertext1 = unit_ciphertext1;
  auto input_unit_ciphertext2 = unit_ciphertext2;

  if (rescaled) {
    auto rescaled_unit_ciphertext1 = engine.rescale(input_unit_ciphertext1);
    auto rescaled_unit_ciphertext2 = engine.rescale(input_unit_ciphertext2);

    if (ntt) {
      input_unit_ciphertext1 = engine.ntt(rescaled_unit_ciphertext1);
      input_unit_ciphertext2 = engine.ntt(rescaled_unit_ciphertext2);

      delete rescaled_unit_ciphertext1;
      delete rescaled_unit_ciphertext2;
    } else {
      input_unit_ciphertext1 = rescaled_unit_ciphertext1;
      input_unit_ciphertext2 = rescaled_unit_ciphertext2;
    }
  } else if (ntt) {
    input_unit_ciphertext1 = engine.ntt(input_unit_ciphertext1);
    input_unit_ciphertext2 = engine.ntt(input_unit_ciphertext2);
  }

  engine.add_inplace(input_unit_ciphertext1, input_unit_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(input_unit_ciphertext1->level_, level);
  EXPECT_EQ(input_unit_ciphertext1->flag_, expected_flag);
  EXPECT_EQ(input_unit_ciphertext1->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(input_unit_ciphertext1);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ntt || rescaled) {
    delete input_unit_ciphertext1;
    delete input_unit_ciphertext2;
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
})

ALL_ENGINE_TEST(AddSubtractUnitSP21, SubtractInplaceDuo, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 4);
  initiate_message(message2, 2);

  auto unit_ciphertext1 = engine.encrypt_unit(message1, public_key_, level);
  auto unit_ciphertext2 = engine.encrypt_unit(message2, public_key_, level);

  auto input_unit_ciphertext1 = unit_ciphertext1;
  auto input_unit_ciphertext2 = unit_ciphertext2;

  if (rescaled) {
    auto rescaled_unit_ciphertext1 = engine.rescale(input_unit_ciphertext1);
    auto rescaled_unit_ciphertext2 = engine.rescale(input_unit_ciphertext2);

    if (ntt) {
      input_unit_ciphertext1 = engine.ntt(rescaled_unit_ciphertext1);
      input_unit_ciphertext2 = engine.ntt(rescaled_unit_ciphertext2);

      delete rescaled_unit_ciphertext1;
      delete rescaled_unit_ciphertext2;
    } else {
      input_unit_ciphertext1 = rescaled_unit_ciphertext1;
      input_unit_ciphertext2 = rescaled_unit_ciphertext2;
    }
  } else if (ntt) {
    input_unit_ciphertext1 = engine.ntt(input_unit_ciphertext1);
    input_unit_ciphertext2 = engine.ntt(input_unit_ciphertext2);
  }

  engine.subtract_inplace(input_unit_ciphertext1, input_unit_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(input_unit_ciphertext1->level_, level);
  EXPECT_EQ(input_unit_ciphertext1->flag_, expected_flag);
  EXPECT_EQ(input_unit_ciphertext1->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(input_unit_ciphertext1);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] - message2[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ntt || rescaled) {
    delete input_unit_ciphertext1;
    delete input_unit_ciphertext2;
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
})
