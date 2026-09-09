#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP41(
    AddSubtractMessageSP41,
    [](const std::tuple<bool, bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_long_extended(std::get<1>(param)) +
             print_ntt_flag(std::get<2>(param)) +
             print_rescaled_flag(std::get<3>(param)) + "And" +
             print_level_depth(std::get<4>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(AddSubtractMessageSP41, AddDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
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

  const auto added = ciphertext_first ? engine.add(input_ciphertext, message)
                                      : engine.add(message, input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(added);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractMessageSP41, SubtractDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_sliced_message(message1, slice_count, slot_count, 1.0);
  initiate_sliced_message(message2, slice_count, slot_count, 2.0);

  const auto ciphertext = engine.encrypt(message1, public_key_, level);

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

  const auto subtracted = ciphertext_first
                              ? engine.subtract(input_ciphertext, message2)
                              : engine.subtract(message2, input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(subtracted);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = ciphertext_first ? message1[i] - message2[i]
                                           : message2[i] - message1[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete subtracted;
})

ALL_ENGINE_TEST(AddSubtractMessageSP41, AddDuoDoubleBuffer, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  int message_size = slot_count * slice_count;
  double message[message_size];
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext =
      engine.encrypt(message, public_key_, message_size, level);

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

  const auto added = ciphertext_first
                         ? engine.add(input_ciphertext, message, message_size)
                         : engine.add(message, input_ciphertext, message_size);

  const auto flag = desilo::fhe::DataFlag::NONE;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT(added);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected, decrypted[i], 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractMessageSP41, AddDuoComplexBuffer, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  int message_size = slot_count * slice_count;
  std::complex<double> message[message_size];
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext =
      engine.encrypt(message, public_key_, message_size, level);

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

  const auto added = ciphertext_first
                         ? engine.add(input_ciphertext, message, message_size)
                         : engine.add(message, input_ciphertext, message_size);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(added);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractMessageSP41, SubtractDuoDoubleBuffer, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  int message_size = slot_count * slice_count;
  double message1[message_size];
  double message2[message_size];
  initiate_sliced_message(message1, slice_count, slot_count, 1.0);
  initiate_sliced_message(message2, slice_count, slot_count, 2.0);

  const auto ciphertext =
      engine.encrypt(message1, public_key_, message_size, level);

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

  const auto subtracted =
      ciphertext_first
          ? engine.subtract(input_ciphertext, message2, message_size)
          : engine.subtract(message2, input_ciphertext, message_size);

  const auto flag = desilo::fhe::DataFlag::NONE;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT(subtracted);

  for (int i = 0; i < message_size; i++) {
    const auto expected = ciphertext_first ? message1[i] - message2[i]
                                           : message2[i] - message1[i];
    ASSERT_NEAR(expected, decrypted[i], 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete subtracted;
})

ALL_ENGINE_TEST(AddSubtractMessageSP41, SubtractDuoComplexBuffer, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  int message_size = slot_count * slice_count;
  std::complex<double> message1[message_size];
  std::complex<double> message2[message_size];
  initiate_sliced_message(message1, slice_count, slot_count, 1.0);
  initiate_sliced_message(message2, slice_count, slot_count, 2.0);

  const auto ciphertext =
      engine.encrypt(message1, public_key_, message_size, level);

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

  const auto subtracted =
      ciphertext_first
          ? engine.subtract(input_ciphertext, message2, message_size)
          : engine.subtract(message2, input_ciphertext, message_size);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(subtracted);

  for (int i = 0; i < message_size; i++) {
    const auto expected = ciphertext_first ? message1[i] - message2[i]
                                           : message2[i] - message1[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete subtracted;
})

ALL_ENGINE_TEST(AddSubtractMessageSP41, AddDuoDoubleScalar, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
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

  const auto added = ciphertext_first ? engine.add(input_ciphertext, 1.0)
                                      : engine.add(1.0, input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(added);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + 1.0;
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractMessageSP41, SubtractDuoDoubleScalar, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count, 2.0);

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

  const auto subtracted = ciphertext_first
                              ? engine.subtract(input_ciphertext, 1.0)
                              : engine.subtract(1.0, input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(subtracted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected =
        ciphertext_first ? message[i] - 1.0 : 1.0 - message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete subtracted;
})

SETUP_ENGINE_TEST_SP41(
    AddSubtractInplaceUnitPlaintextSP41,
    [](const std::tuple<bool, bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) + "And" +
             print_ntt_flag(std::get<2>(param)) +
             print_rescaled_flag(std::get<3>(param)) + "And" +
             print_level_depth(std::get<4>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(AddSubtractInplaceUnitPlaintextSP41, AddDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto plaintext_ntt = std::get<2>(GetParam());
  const auto rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());

  if (rescaled && level - 1 < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto unit_plaintext = engine.encode_unit(message, level);

  auto input_unit_ciphertext = unit_ciphertext;
  auto input_unit_plaintext = unit_plaintext;

  if (rescaled) {
    auto rescaled_unit_ciphertext = engine.rescale(input_unit_ciphertext);
    auto rescaled_unit_plaintext = engine.rescale(input_unit_plaintext);

    if (ciphertext_ntt) {
      input_unit_ciphertext = engine.ntt(rescaled_unit_ciphertext);

      delete rescaled_unit_ciphertext;
    } else {
      input_unit_ciphertext = rescaled_unit_ciphertext;
    }

    if (plaintext_ntt) {
      input_unit_plaintext = engine.ntt(rescaled_unit_plaintext);

      delete rescaled_unit_plaintext;
    } else {
      input_unit_plaintext = rescaled_unit_plaintext;
    }
  } else {
    if (ciphertext_ntt) {
      input_unit_ciphertext = engine.ntt(input_unit_ciphertext);
    }
    if (plaintext_ntt) {
      input_unit_plaintext = engine.ntt(input_unit_plaintext);
    }
  }

  if (ciphertext_first) {
    engine.add_inplace(input_unit_ciphertext, input_unit_plaintext);
  } else {
    engine.add_inplace(input_unit_plaintext, input_unit_ciphertext);
  }

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(input_unit_ciphertext->level_, level);
  EXPECT_EQ(input_unit_ciphertext->flag_, expected_flag);
  EXPECT_EQ(input_unit_ciphertext->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(input_unit_ciphertext);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || rescaled) {
    delete input_unit_ciphertext;
  }
  if (plaintext_ntt || rescaled) {
    delete input_unit_plaintext;
  }

  delete unit_ciphertext;
  delete unit_plaintext;
})

SETUP_ENGINE_TEST_SP41(
    MultiplyMessageSP41,
    [](const std::tuple<bool, bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_long_extended(std::get<1>(param)) +
             print_ntt_flag(std::get<2>(param)) +
             print_rescaled_flag(std::get<3>(param)) + "And" +
             print_level_depth(std::get<4>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(MultiplyMessageSP41, MultiplyDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
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

  const auto multiplied = ciphertext_first
                              ? engine.multiply(input_ciphertext, message)
                              : engine.multiply(message, input_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag |= desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(multiplied);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyMessageSP41, MultiplyDuoDoubleBuffer, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const int message_size = slot_count * slice_count;
  double message[message_size];
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext =
      engine.encrypt(message, public_key_, message_size, level);

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

  const auto multiplied =
      ciphertext_first
          ? engine.multiply(input_ciphertext, message, message_size)
          : engine.multiply(message, input_ciphertext, message_size);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  const auto decrypted = DECRYPT(multiplied);

  for (int i = 0; i < message_size; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected, decrypted[i], 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(MultiplyMessageSP41, MultiplyDuoComplexBuffer, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto ciphertext_rescaled = std::get<3>(GetParam());
  const auto level = max_level_ - std::get<4>(GetParam());
  const auto multiplied_level = level - 1;

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const int message_size = slot_count * slice_count;
  std::complex<double> message[message_size];
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext =
      engine.encrypt(message, public_key_, message_size, level);

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

  const auto multiplied =
      ciphertext_first
          ? engine.multiply(input_ciphertext, message, message_size)
          : engine.multiply(message, input_ciphertext, message_size);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag |= desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(multiplied);

  for (int i = 0; i < message_size; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete multiplied;
})
