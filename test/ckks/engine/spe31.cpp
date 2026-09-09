#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPE31(
    AddSubtractUnitMessageSPE31,
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

        testing::Values(1, 2)));

ALL_ENGINE_TEST(AddSubtractUnitMessageSPE31, AddTrio, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level + 1);
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

  auto added = ciphertext_first ? engine.add(input_unit_ciphertext, message)
                                : engine.add(message, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), level);
  EXPECT_EQ(added->flag_, expected_flag);
  EXPECT_EQ(added->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(added);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete squared;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractUnitMessageSPE31, SubtractTrio, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 4);
  initiate_message(message2, 2);

  auto unit_ciphertext = engine.encrypt_unit(message1, public_key_, level + 1);
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

  auto subtracted = ciphertext_first
                        ? engine.subtract(input_unit_ciphertext, message2)
                        : engine.subtract(message2, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), level);
  EXPECT_EQ(subtracted->flag_, expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(subtracted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = ciphertext_first
                              ? message1[i] * message1[i] - message2[i]
                              : message2[i] - message1[i] * message1[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete squared;
  delete subtracted;
})

ALL_ENGINE_TEST(AddSubtractUnitMessageSPE31, AddTrioDoubleScalar, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level - 1 < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level + 1);
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

  auto added = ciphertext_first ? engine.add(input_unit_ciphertext, 1.0)
                                : engine.add(1.0, input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), level);
  EXPECT_EQ(added->flag_, expected_flag);
  EXPECT_EQ(added->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(added);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] + 1.0;
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete squared;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractUnitMessageSPE31, SubtractTrioDoubleScalar, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto level = max_level_ - std::get<3>(GetParam());

  if (ciphertext_rescaled && level - 1 < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 4);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level + 1);
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

  auto subtracted = ciphertext_first
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

  EXPECT_EQ(subtracted->level(), level);
  EXPECT_EQ(subtracted->flag_, expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(subtracted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = ciphertext_first ? message[i] * message[i] - 1.0
                                           : 1.0 - message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete squared;
  delete subtracted;
})

SETUP_ENGINE_TEST_SPE31(
    SquareSPE31,
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

ALL_ENGINE_TEST(SquareSPE31, Ciphertext, {
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

  auto squared = engine.square(input_ciphertext);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(squared->level(), squared_level);
  EXPECT_EQ(squared->flag(), flag);
  EXPECT_EQ(squared->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(squared);

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

SETUP_ENGINE_TEST_SPE31(
    MultiplyUnitMessageSPE31,
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

        testing::Values(1, 2)));

ALL_ENGINE_TEST(MultiplyUnitMessageSPE31, MultiplyTrio, {
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

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level + 1);
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

  auto multiplied = ciphertext_first
                        ? engine.multiply(input_unit_ciphertext, message)
                        : engine.multiply(message, input_unit_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag |= desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag_, flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete squared;
  delete multiplied;
})

SETUP_ENGINE_TEST_SPE31(
    MultiplyScalarSPE31,
    [](const std::tuple<bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_long_extended(std::get<2>(param)) +
             print_level_depth(std::get<3>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(1, 2)));

ALL_ENGINE_TEST(MultiplyScalarSPE31, MultiplyTrioDouble, {
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

  const auto ciphertext = engine.encrypt(message, public_key_, level + 1);
  const auto squared = engine.square(ciphertext);
  const auto input_ciphertext = ciphertext_ntt ? squared : engine.intt(squared);
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_ciphertext, 2.0)
                              : engine.multiply(2.0, input_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] + message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete squared;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyScalarSPE31, MultiplyTrioInteger, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level + 1);
  const auto squared = engine.square(ciphertext);
  const auto input_ciphertext = ciphertext_ntt ? squared : engine.intt(squared);
  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_ciphertext, 2l)
                              : engine.multiply(2l, input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level(), level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] + message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete squared;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyScalarSPE31, MultiplyTrioImaginary, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level + 1);
  const auto squared = engine.square(ciphertext);
  const auto input_ciphertext = ciphertext_ntt ? squared : engine.intt(squared);
  const auto multiplied = ciphertext_first
                              ? engine.multiply_imaginary(input_ciphertext, 1)
                              : engine.multiply_imaginary(1, input_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  if (ciphertext_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(multiplied->level(), level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i] * std::complex(0.0, 1.0);
    EXPECT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    EXPECT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt) {
    delete input_ciphertext;
  }
  delete ciphertext;
  delete squared;
  delete multiplied;
})

SETUP_ENGINE_TEST_SPE31(
    DecryptSPE31,
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

ALL_ENGINE_TEST(DecryptSPE31, DecryptTrio, {
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

  const auto decrypted = DECRYPT_TRIO_COMPLEX(input_ciphertext);

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
})

SETUP_ENGINE_TEST_SPE31(
    AddSubtractUnitSPE31,
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

        testing::Values(1, 2)));

ALL_ENGINE_TEST(AddSubtractUnitSPE31, AddInplaceTrio, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext1 = engine.encrypt(message, public_key_, level + 1);
  auto ciphertext2 = engine.encrypt(message, public_key_, level + 1);
  auto squared1 = engine.square(ciphertext1);
  auto squared2 = engine.square(ciphertext2);

  auto input_ciphertext1 = squared1;
  auto input_ciphertext2 = squared2;

  if (rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (!ntt) {
      input_ciphertext1 = engine.intt(rescaled_ciphertext1);
      input_ciphertext2 = engine.intt(rescaled_ciphertext2);

      delete rescaled_ciphertext1;
      delete rescaled_ciphertext2;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (!ntt) {
    input_ciphertext1 = engine.intt(input_ciphertext1);
    input_ciphertext2 = engine.intt(input_ciphertext2);
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
  EXPECT_EQ(input_ciphertext1->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(input_ciphertext1);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] * message[i] + message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ntt || rescaled) {
    delete input_ciphertext1;
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
  delete squared1;
  delete squared2;
})

ALL_ENGINE_TEST(AddSubtractUnitSPE31, SubtractInplaceTrio, {
  const auto ntt = std::get<0>(GetParam());
  const auto rescaled = std::get<1>(GetParam());
  const auto slice_count = std::get<2>(GetParam()) ? 2 : 1;
  const auto level = max_level_ - std::get<3>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_sliced_message(message1, slice_count, slot_count, 2.0);
  initiate_sliced_message(message2, slice_count, slot_count, 1.0);

  auto ciphertext1 = engine.encrypt(message1, public_key_, level + 1);
  auto ciphertext2 = engine.encrypt(message2, public_key_, level + 1);
  auto squared1 = engine.square(ciphertext1);
  auto squared2 = engine.square(ciphertext2);

  auto input_ciphertext1 = squared1;
  auto input_ciphertext2 = squared2;

  if (rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (!ntt) {
      input_ciphertext1 = engine.intt(rescaled_ciphertext1);
      input_ciphertext2 = engine.intt(rescaled_ciphertext2);

      delete rescaled_ciphertext1;
      delete rescaled_ciphertext2;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (!ntt) {
    input_ciphertext1 = engine.intt(input_ciphertext1);
    input_ciphertext2 = engine.intt(input_ciphertext2);
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
  EXPECT_EQ(input_ciphertext1->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(input_ciphertext1);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message1[i] * message1[i] - message2[i] * message2[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ntt || rescaled) {
    delete input_ciphertext1;
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
  delete squared1;
  delete squared2;
})
