#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPE53(
    AddSubtractSPE53,
    [](const std::tuple<bool, bool, bool, bool, bool, std::tuple<int, int, int>>
           &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_ntt_flag(std::get<2>(param)) +
             print_rescaled_flag(std::get<3>(param)) +
             print_long_extended(std::get<4>(param)) +
             print_level_depth(std::get<0>(std::get<5>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<5>(param)));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(std::make_tuple(1, 1, 1), std::make_tuple(1, 2, 2),
                        std::make_tuple(2, 1, 2), std::make_tuple(2, 2, 2))));

ALL_ENGINE_TEST(AddSubtractSPE53, AddTrioAndDuo, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto added_level = max_level_ - std::get<2>(levels);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext1 = engine.encrypt(message, public_key_, level1 + 1);
  auto squared1 = engine.square(ciphertext1);
  auto ciphertext2 = engine.encrypt(message, public_key_, level2);

  auto input_ciphertext1 = squared1;
  auto input_ciphertext2 = ciphertext2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (!first_ntt) {
      input_ciphertext1 = engine.intt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (!first_ntt) {
    input_ciphertext1 = engine.intt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (second_ntt) {
      input_ciphertext2 = engine.ntt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (second_ntt) {
    input_ciphertext2 = engine.ntt(input_ciphertext2);
  }

  auto added = engine.add(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (first_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (first_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (second_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), added_level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(added);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] * message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete squared1;
  delete ciphertext2;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractSPE53, AddDuoAndTrio, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto added_level = max_level_ - std::get<2>(levels);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext1 = engine.encrypt(message, public_key_, level1);
  auto ciphertext2 = engine.encrypt(message, public_key_, level2 + 1);
  auto squared2 = engine.square(ciphertext2);

  auto input_ciphertext1 = ciphertext1;
  auto input_ciphertext2 = squared2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (first_ntt) {
      input_ciphertext1 = engine.ntt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (first_ntt) {
    input_ciphertext1 = engine.ntt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (!second_ntt) {
      input_ciphertext2 = engine.intt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (!second_ntt) {
    input_ciphertext2 = engine.intt(input_ciphertext2);
  }

  auto added = engine.add(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (first_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (first_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (second_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), added_level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(added);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] * message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (!second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
  delete squared2;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractSPE53, AddTrio, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto added_level = max_level_ - std::get<2>(levels);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext1 = engine.encrypt(message, public_key_, level1 + 1);
  auto squared1 = engine.square(ciphertext1);
  auto ciphertext2 = engine.encrypt(message, public_key_, level2 + 1);
  auto squared2 = engine.square(ciphertext2);

  auto input_ciphertext1 = squared1;
  auto input_ciphertext2 = squared2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (!first_ntt) {
      input_ciphertext1 = engine.intt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (!first_ntt) {
    input_ciphertext1 = engine.intt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (!second_ntt) {
      input_ciphertext2 = engine.intt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (!second_ntt) {
    input_ciphertext2 = engine.intt(input_ciphertext2);
  }

  auto added = engine.add(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (first_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (first_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (second_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(added->level(), added_level);
  EXPECT_EQ(added->flag(), expected_flag);
  EXPECT_EQ(added->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(added);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] * message[i] + message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (!second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete squared1;
  delete ciphertext2;
  delete squared2;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractSPE53, SubtractTrioByDuo, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto subtracted_level = max_level_ - std::get<2>(levels);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_sliced_message(message1, slice_count, slot_count, 1.0);
  initiate_sliced_message(message2, slice_count, slot_count, 2.0);

  auto ciphertext1 = engine.encrypt(message1, public_key_, level1 + 1);
  auto squared1 = engine.square(ciphertext1);
  auto ciphertext2 = engine.encrypt(message2, public_key_, level2);

  auto input_ciphertext1 = squared1;
  auto input_ciphertext2 = ciphertext2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (!first_ntt) {
      input_ciphertext1 = engine.intt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (!first_ntt) {
    input_ciphertext1 = engine.intt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (second_ntt) {
      input_ciphertext2 = engine.ntt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (second_ntt) {
    input_ciphertext2 = engine.ntt(input_ciphertext2);
  }

  auto subtracted = engine.subtract(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (first_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (first_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (second_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), subtracted_level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(subtracted);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message1[i] * message1[i] - message2[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete squared1;
  delete ciphertext2;
  delete subtracted;
})

ALL_ENGINE_TEST(AddSubtractSPE53, SubtractDuoByTrio, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto subtracted_level = max_level_ - std::get<2>(levels);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_sliced_message(message1, slice_count, slot_count, 1.0);
  initiate_sliced_message(message2, slice_count, slot_count, 2.0);

  auto ciphertext1 = engine.encrypt(message1, public_key_, level1);
  auto ciphertext2 = engine.encrypt(message2, public_key_, level2 + 1);
  auto squared2 = engine.square(ciphertext2);

  auto input_ciphertext1 = ciphertext1;
  auto input_ciphertext2 = squared2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (first_ntt) {
      input_ciphertext1 = engine.ntt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (first_ntt) {
    input_ciphertext1 = engine.ntt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (!second_ntt) {
      input_ciphertext2 = engine.intt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (!second_ntt) {
    input_ciphertext2 = engine.intt(input_ciphertext2);
  }

  auto subtracted = engine.subtract(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (first_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (first_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (second_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), subtracted_level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(subtracted);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message1[i] - message2[i] * message2[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (!second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
  delete squared2;
  delete subtracted;
})

ALL_ENGINE_TEST(AddSubtractSPE53, SubtractTrio, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto subtracted_level = max_level_ - std::get<2>(levels);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_sliced_message(message1, slice_count, slot_count, 1.0);
  initiate_sliced_message(message2, slice_count, slot_count, 2.0);

  auto ciphertext1 = engine.encrypt(message1, public_key_, level1 + 1);
  auto squared1 = engine.square(ciphertext1);
  auto ciphertext2 = engine.encrypt(message2, public_key_, level2 + 1);
  auto squared2 = engine.square(ciphertext2);

  auto input_ciphertext1 = squared1;
  auto input_ciphertext2 = squared2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (!first_ntt) {
      input_ciphertext1 = engine.intt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (!first_ntt) {
    input_ciphertext1 = engine.intt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (!second_ntt) {
      input_ciphertext2 = engine.intt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (!second_ntt) {
    input_ciphertext2 = engine.intt(input_ciphertext2);
  }

  auto subtracted = engine.subtract(input_ciphertext1, input_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (first_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (first_rescaled && level1 < level2 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }
  if (second_rescaled && level2 < level1 + 1) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(subtracted->level(), subtracted_level);
  EXPECT_EQ(subtracted->flag(), expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(subtracted);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message1[i] * message1[i] - message2[i] * message2[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (!second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete squared1;
  delete ciphertext2;
  delete squared2;
  delete subtracted;
})

SETUP_ENGINE_TEST_SPE53(
    AddSubtractUnitPlaintextSPE53,
    [](const std::tuple<bool, bool, bool, bool, bool, std::tuple<int, int, int>>
           &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_rescaled_flag(std::get<2>(param)) + "And" +
             print_ntt_flag(std::get<3>(param)) +
             print_rescaled_flag(std::get<4>(param)) +
             print_level_depth(std::get<0>(std::get<5>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<5>(param)));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(std::make_tuple(1, 1, 1), std::make_tuple(1, 2, 2),
                        std::make_tuple(2, 1, 2), std::make_tuple(2, 2, 2))));

ALL_ENGINE_TEST(AddSubtractUnitPlaintextSPE53, AddTrio, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto plaintext_ntt = std::get<3>(GetParam());
  const auto plaintext_rescaled = std::get<4>(GetParam());
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto added_level = max_level_ - std::get<2>(levels);

  if ((ciphertext_rescaled && level1 - 1 < 0) ||
      (plaintext_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level1 + 1);
  auto squared = engine.square(unit_ciphertext);
  auto unit_plaintext = engine.encode_unit(message, level2);

  auto input_unit_ciphertext = squared;
  auto input_unit_plaintext = unit_plaintext;

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

  if (plaintext_rescaled) {
    auto rescaled_unit_plaintext = engine.rescale(input_unit_plaintext);

    if (plaintext_ntt) {
      input_unit_plaintext = engine.ntt(rescaled_unit_plaintext);

      delete rescaled_unit_plaintext;
    } else {
      input_unit_plaintext = rescaled_unit_plaintext;
    }
  } else if (plaintext_ntt) {
    input_unit_plaintext = engine.ntt(input_unit_plaintext);
  }

  auto added = ciphertext_first
                   ? engine.add(input_unit_ciphertext, input_unit_plaintext)
                   : engine.add(input_unit_plaintext, input_unit_ciphertext);

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

  EXPECT_EQ(added->level_, added_level);
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
  if (plaintext_ntt || plaintext_rescaled) {
    delete input_unit_plaintext;
  }

  delete unit_ciphertext;
  delete squared;
  delete unit_plaintext;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractUnitPlaintextSPE53, SubtractTrio, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto plaintext_ntt = std::get<3>(GetParam());
  const auto plaintext_rescaled = std::get<4>(GetParam());
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto subtracted_level = max_level_ - std::get<2>(levels);

  if ((ciphertext_rescaled && level1 - 1 < 0) ||
      (plaintext_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  if (level1 < 0 || level2 < 0) {
    GTEST_SKIP() << "Impossible Encryption level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 4);
  initiate_message(message2, 2);

  auto unit_ciphertext = engine.encrypt_unit(message1, public_key_, level1 + 1);
  auto squared = engine.square(unit_ciphertext);
  auto unit_plaintext = engine.encode_unit(message2, level2);

  auto input_unit_ciphertext = squared;
  auto input_unit_plaintext = unit_plaintext;

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

  if (plaintext_rescaled) {
    auto rescaled_unit_plaintext = engine.rescale(input_unit_plaintext);

    if (plaintext_ntt) {
      input_unit_plaintext = engine.ntt(rescaled_unit_plaintext);

      delete rescaled_unit_plaintext;
    } else {
      input_unit_plaintext = rescaled_unit_plaintext;
    }
  } else if (plaintext_ntt) {
    input_unit_plaintext = engine.ntt(input_unit_plaintext);
  }

  auto subtracted =
      ciphertext_first
          ? engine.subtract(input_unit_ciphertext, input_unit_plaintext)
          : engine.subtract(input_unit_plaintext, input_unit_ciphertext);

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

  EXPECT_EQ(subtracted->level_, subtracted_level);
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
  if (plaintext_ntt || plaintext_rescaled) {
    delete input_unit_plaintext;
  }

  delete unit_ciphertext;
  delete squared;
  delete unit_plaintext;
  delete subtracted;
})

SETUP_ENGINE_TEST_SPE53(
    MultiplySPE53,
    [](const std::tuple<bool, bool, bool, bool, bool, std::tuple<int, int, int>>
           &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_ntt_flag(std::get<2>(param)) +
             print_rescaled_flag(std::get<3>(param)) +
             print_long_extended(std::get<4>(param)) +
             print_level_depth(std::get<0>(std::get<5>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<5>(param)));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(std::make_tuple(0, 0, 1), std::make_tuple(0, 1, 2),
                        std::make_tuple(1, 0, 2), std::make_tuple(1, 1, 2))));

ALL_ENGINE_TEST(MultiplySPE53, Multiply, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
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

  auto ciphertext1 = engine.encrypt(message, public_key_, level1);
  auto ciphertext2 = engine.encrypt(message, public_key_, level2);

  auto input_ciphertext1 = ciphertext1;
  auto input_ciphertext2 = ciphertext2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (first_ntt) {
      input_ciphertext1 = engine.ntt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (first_ntt) {
    input_ciphertext1 = engine.ntt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (second_ntt) {
      input_ciphertext2 = engine.ntt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (second_ntt) {
    input_ciphertext2 = engine.ntt(input_ciphertext2);
  }

  auto multiplied = engine.multiply(input_ciphertext1, input_ciphertext2);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(multiplied);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
  delete multiplied;
})

SETUP_ENGINE_TEST_SPE53(
    MultiplyUnitPlaintextSPE53,
    [](const std::tuple<bool, bool, bool, bool, bool, std::tuple<int, int, int>>
           &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_ntt_flag(std::get<1>(param)) +
             print_rescaled_flag(std::get<2>(param)) + "And" +
             print_ntt_flag(std::get<3>(param)) +
             print_rescaled_flag(std::get<4>(param)) +
             print_level_depth(std::get<0>(std::get<5>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<5>(param)));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(std::make_tuple(1, 1, 2), std::make_tuple(1, 2, 3),
                        std::make_tuple(2, 1, 3), std::make_tuple(2, 2, 3))));

ALL_ENGINE_TEST(MultiplyUnitPlaintextSPE53, MultiplyTrio, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto ciphertext_ntt = std::get<1>(GetParam());
  const auto ciphertext_rescaled = std::get<2>(GetParam());
  const auto plaintext_ntt = std::get<3>(GetParam());
  const auto plaintext_rescaled = std::get<4>(GetParam());
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto multiplied_level = max_level_ - std::get<2>(levels);

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level1 + 1);
  auto squared = engine.square(unit_ciphertext);
  auto unit_plaintext = engine.encode_unit(message, level2);

  auto input_unit_ciphertext = squared;
  auto input_unit_plaintext = unit_plaintext;

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

  if (plaintext_rescaled) {
    auto rescaled_unit_plaintext = engine.rescale(input_unit_plaintext);

    if (plaintext_ntt) {
      input_unit_plaintext = engine.ntt(rescaled_unit_plaintext);

      delete rescaled_unit_plaintext;
    } else {
      input_unit_plaintext = rescaled_unit_plaintext;
    }
  } else if (plaintext_ntt) {
    input_unit_plaintext = engine.ntt(input_unit_plaintext);
  }

  auto multiplied =
      ciphertext_first
          ? engine.multiply(input_unit_ciphertext, input_unit_plaintext)
          : engine.multiply(input_unit_plaintext, input_unit_ciphertext);

  auto flag = desilo::fhe::DataFlag::COMPLEX;
  flag |= desilo::fhe::DataFlag::NTT_FORM;

  EXPECT_EQ(multiplied->level_, multiplied_level);
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
  if (plaintext_ntt || plaintext_rescaled) {
    delete input_unit_plaintext;
  }

  delete unit_ciphertext;
  delete squared;
  delete unit_plaintext;
  delete multiplied;
})
