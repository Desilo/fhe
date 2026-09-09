#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP31(
    AddSubtractUnitMessageSP31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_rescaled_flag(std::get<2>(param)) + "And" +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(AddSubtractUnitMessageSP31, AddDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

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

  const auto added = ciphertext_first
                         ? engine.add(input_unit_ciphertext, message)
                         : engine.add(message, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level_, level);
  EXPECT_EQ(added->flag_, expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(added);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractUnitMessageSP31, SubtractDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 4);
  initiate_message(message2, 2);

  const auto unit_ciphertext =
      engine.encrypt_unit(message1, public_key_, level);

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

  const auto subtracted =
      ciphertext_first ? engine.subtract(input_unit_ciphertext, message2)
                       : engine.subtract(message2, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level_, level);
  EXPECT_EQ(subtracted->flag_, expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(subtracted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = ciphertext_first ? message1[i] - message2[i]
                                           : message2[i] - message1[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete subtracted;
})

ALL_ENGINE_TEST(AddSubtractUnitMessageSP31, AddDuoDoubleScalar, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level - 1 < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

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

  const auto added = ciphertext_first ? engine.add(input_unit_ciphertext, 1.0)
                                      : engine.add(1.0, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level_, level);
  EXPECT_EQ(added->flag_, expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(added);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real() + 1.0, decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractUnitMessageSP31, SubtractDuoDoubleScalar, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 4);

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

  const auto subtracted = ciphertext_first
                              ? engine.subtract(input_unit_ciphertext, 1.0)
                              : engine.subtract(1.0, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level_, level);
  EXPECT_EQ(subtracted->flag_, expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(subtracted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected =
        ciphertext_first ? message[i] - 1.0 : 1.0 - message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete subtracted;
})

SETUP_ENGINE_TEST_SP31(
    MultiplyUnitMessageSP31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_rescaled_flag(std::get<2>(param)) + "And" +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(MultiplyUnitMessageSP31, MultiplyDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

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

  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_unit_ciphertext, message)
                              : engine.multiply(message, input_unit_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag |= desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(multiplied->level_, multiplied_level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete multiplied;
})

SETUP_ENGINE_TEST_SP31(
    MultiplyScalarSP31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(MultiplyScalarSP31, MultiplyDuoDouble, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level);
  const auto input_ciphertext =
      ciphertext_ntt ? engine.ntt(ciphertext) : ciphertext;
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_ciphertext, 2.0)
                              : engine.multiply(2.0, input_ciphertext);
  const auto decrypted = DECRYPT_COMPLEX(multiplied);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  for (int i = 0; i < message.size(); i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyScalarSP31, MultiplyDuoInteger, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level);
  const auto input_ciphertext =
      ciphertext_ntt ? engine.ntt(ciphertext) : ciphertext;
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_ciphertext, 2l)
                              : engine.multiply(2l, input_ciphertext);
  const auto decrypted = DECRYPT_COMPLEX(multiplied);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level(), level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  for (int i = 0; i < message.size(); i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyScalarSP31, MultiplyDuoImaginary, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level);
  const auto input_ciphertext =
      ciphertext_ntt ? engine.ntt(ciphertext) : ciphertext;
  const auto multiplied = ciphertext_first
                              ? engine.multiply_imaginary(input_ciphertext, 1)
                              : engine.multiply_imaginary(1, input_ciphertext);
  const auto decrypted = DECRYPT_COMPLEX(multiplied);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  if (ciphertext_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(multiplied->level(), level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  for (int i = 0; i < message.size(); i++) {
    const auto expected = message[i] * std::complex(0.0, 1.0);
    EXPECT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    EXPECT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete multiplied;
})

SETUP_ENGINE_TEST_SP31(
    DecryptSP31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(true, false),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(DecryptSP31, DecryptDuo, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  const auto decrypted_level = ciphertext_rescaled ? level - 1 : level;

  if (decrypted_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  auto input_ciphertext = ciphertext;

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

  const auto decrypted = DECRYPT_COMPLEX(input_ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }
  delete ciphertext;
})

SETUP_ENGINE_TEST_SP31(
    AddSubtractSP31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(AddSubtractSP31, AddInplaceDuo, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext1 = engine.encrypt(message, public_key_, level);
  auto ciphertext2 = engine.encrypt(message, public_key_, level);

  auto input_ciphertext1 = ciphertext1;
  auto input_ciphertext2 = ciphertext2;

  if (rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (ntt) {
      input_ciphertext1 = engine.ntt(rescaled_ciphertext1);
      input_ciphertext2 = engine.ntt(rescaled_ciphertext2);

      delete rescaled_ciphertext1;
      delete rescaled_ciphertext2;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (ntt) {
    input_ciphertext1 = engine.ntt(input_ciphertext1);
    input_ciphertext2 = engine.ntt(input_ciphertext2);
  }

  engine.add_inplace(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(input_ciphertext1->level(), level);
  EXPECT_EQ(input_ciphertext1->flag(), expected_flag);
  EXPECT_EQ(input_ciphertext1->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(input_ciphertext1);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ntt || rescaled) {
    delete input_ciphertext1;
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
})

ALL_ENGINE_TEST(AddSubtractSP31, SubtractInplaceDuo, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_sliced_message(message1, slice_count, slot_count, 2.0);
  initiate_sliced_message(message2, slice_count, slot_count, 1.0);

  auto ciphertext1 = engine.encrypt(message1, public_key_, level);
  auto ciphertext2 = engine.encrypt(message2, public_key_, level);

  auto input_ciphertext1 = ciphertext1;
  auto input_ciphertext2 = ciphertext2;

  if (rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (ntt) {
      input_ciphertext1 = engine.ntt(rescaled_ciphertext1);
      input_ciphertext2 = engine.ntt(rescaled_ciphertext2);

      delete rescaled_ciphertext1;
      delete rescaled_ciphertext2;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (ntt) {
    input_ciphertext1 = engine.ntt(input_ciphertext1);
    input_ciphertext2 = engine.ntt(input_ciphertext2);
  }

  engine.subtract_inplace(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(input_ciphertext1->level(), level);
  EXPECT_EQ(input_ciphertext1->flag(), expected_flag);
  EXPECT_EQ(input_ciphertext1->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(input_ciphertext1);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message1[i] - message2[i];
    EXPECT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    EXPECT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ntt || rescaled) {
    delete input_ciphertext1;
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
})
