#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPE21(
    RescaleSPE21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_long_extended(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(0, 1, 2)));

ALL_ENGINE_TEST(RescaleSPE21, CiphertextTrio, {
  const auto slice_count = std::get<0>(GetParam()) ? 2 : 1;
  const auto input_ntt = std::get<1>(GetParam());
  const auto level_depth = std::get<2>(GetParam());
  const auto source_level = max_level_ - level_depth;

  if (source_level < 2) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto unit_ciphertext =
      engine.encrypt(message, public_key_, source_level);
  const auto squared = engine.square(unit_ciphertext);

  const auto rescale_input = input_ntt ? squared : engine.intt(squared);

  const auto rescaled = engine.rescale(rescale_input);

  auto flag = desilo::fhe::DataFlag::RESCALED | desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(rescaled->level(), source_level - 1);
  EXPECT_EQ(rescaled->flag(), flag);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(rescaled);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete squared;
  delete rescaled;
  if (!input_ntt) {
    delete rescale_input;
  }
})

SETUP_ENGINE_TEST_SPE21(
    SquareUnitSPE21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(SquareUnitSPE21, Ciphertext, {
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

  auto squared = engine.square(input_unit_ciphertext);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(squared->level_, squared_level);
  EXPECT_EQ(squared->flag_, flag);
  EXPECT_EQ(squared->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(squared);

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

SETUP_ENGINE_TEST_SPE21(
    MultiplyUnitScalarSPE21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(1, 2)));

ALL_ENGINE_TEST(MultiplyUnitScalarSPE21, MultiplyTrioDouble, {
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

  const auto unit_ciphertext =
      engine.encrypt_unit(message, public_key_, level + 1);
  const auto squared = engine.square(unit_ciphertext);
  const auto input_unit_ciphertext =
      ciphertext_ntt ? squared : engine.intt(squared);
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_unit_ciphertext, 2.0)
                              : engine.multiply(2.0, input_unit_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level_, multiplied_level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] + message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete squared;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyUnitScalarSPE21, MultiplyTrioInteger, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext =
      engine.encrypt_unit(message, public_key_, level + 1);
  const auto squared = engine.square(unit_ciphertext);
  const auto input_unit_ciphertext =
      ciphertext_ntt ? squared : engine.intt(squared);
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_unit_ciphertext, 2l)
                              : engine.multiply(2l, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level_, level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] + message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete squared;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyUnitScalarSPE21, MultiplyTrioImaginary, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext =
      engine.encrypt_unit(message, public_key_, level + 1);
  const auto squared = engine.square(unit_ciphertext);
  const auto input_unit_ciphertext =
      ciphertext_ntt ? squared : engine.intt(squared);
  const auto multiplied =
      ciphertext_first ? engine.multiply_imaginary(input_unit_ciphertext, 1)
                       : engine.multiply_imaginary(1, input_unit_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  if (ciphertext_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(multiplied->level_, level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] * std::complex(0.0, 1.0);
    EXPECT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    EXPECT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt) {
    delete input_unit_ciphertext;
  }
  delete unit_ciphertext;
  delete squared;
  delete multiplied;
})

SETUP_ENGINE_TEST_SPE21(
    DecryptUnitSPE21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(DecryptUnitSPE21, DecryptUnitTrio, {
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

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(input_unit_ciphertext);

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
})

SETUP_ENGINE_TEST_SPE21(
    AddSubtractUnitSPE21,
    [](const std::tuple<bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(1, 2)));

ALL_ENGINE_TEST(AddSubtractUnitSPE21, AddInplaceTrio, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext1 = engine.encrypt_unit(message, public_key_, level + 1);
  auto unit_ciphertext2 = engine.encrypt_unit(message, public_key_, level + 1);
  auto squared1 = engine.square(unit_ciphertext1);
  auto squared2 = engine.square(unit_ciphertext2);

  auto input_unit_ciphertext1 = squared1;
  auto input_unit_ciphertext2 = squared2;

  if (rescaled) {
    auto rescaled_unit_ciphertext1 = engine.rescale(input_unit_ciphertext1);
    auto rescaled_unit_ciphertext2 = engine.rescale(input_unit_ciphertext2);

    if (!ntt) {
      input_unit_ciphertext1 = engine.intt(rescaled_unit_ciphertext1);
      input_unit_ciphertext2 = engine.intt(rescaled_unit_ciphertext2);

      delete rescaled_unit_ciphertext1;
      delete rescaled_unit_ciphertext2;
    } else {
      input_unit_ciphertext1 = rescaled_unit_ciphertext1;
      input_unit_ciphertext2 = rescaled_unit_ciphertext2;
    }
  } else if (!ntt) {
    input_unit_ciphertext1 = engine.intt(input_unit_ciphertext1);
    input_unit_ciphertext2 = engine.intt(input_unit_ciphertext2);
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
  EXPECT_EQ(input_unit_ciphertext1->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(input_unit_ciphertext1);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] + message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ntt || rescaled) {
    delete input_unit_ciphertext1;
    delete input_unit_ciphertext2;
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete squared1;
  delete squared2;
})

ALL_ENGINE_TEST(AddSubtractUnitSPE21, SubtractInplaceTrio, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 4);
  initiate_message(message2, 2);

  auto unit_ciphertext1 = engine.encrypt_unit(message1, public_key_, level + 1);
  auto unit_ciphertext2 = engine.encrypt_unit(message2, public_key_, level + 1);
  auto squared1 = engine.square(unit_ciphertext1);
  auto squared2 = engine.square(unit_ciphertext2);

  auto input_unit_ciphertext1 = squared1;
  auto input_unit_ciphertext2 = squared2;

  if (rescaled) {
    auto rescaled_unit_ciphertext1 = engine.rescale(input_unit_ciphertext1);
    auto rescaled_unit_ciphertext2 = engine.rescale(input_unit_ciphertext2);

    if (!ntt) {
      input_unit_ciphertext1 = engine.intt(rescaled_unit_ciphertext1);
      input_unit_ciphertext2 = engine.intt(rescaled_unit_ciphertext2);

      delete rescaled_unit_ciphertext1;
      delete rescaled_unit_ciphertext2;
    } else {
      input_unit_ciphertext1 = rescaled_unit_ciphertext1;
      input_unit_ciphertext2 = rescaled_unit_ciphertext2;
    }
  } else if (!ntt) {
    input_unit_ciphertext1 = engine.intt(input_unit_ciphertext1);
    input_unit_ciphertext2 = engine.intt(input_unit_ciphertext2);
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
  EXPECT_EQ(input_unit_ciphertext1->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(input_unit_ciphertext1);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message1[i] - message2[i] * message2[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ntt || rescaled) {
    delete input_unit_ciphertext1;
    delete input_unit_ciphertext2;
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete squared1;
  delete squared2;
})
