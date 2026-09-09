#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP43(
    AddSubtractUnitSP43,
    [](const std::tuple<bool, bool, bool, bool, std::tuple<int, int, int>>
           &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_ntt_flag(std::get<2>(param)) +
             print_rescaled_flag(std::get<3>(param)) +
             print_level_depth(std::get<0>(std::get<4>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<4>(param)));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(std::make_tuple(0, 0, 0), std::make_tuple(0, 1, 1),
                        std::make_tuple(1, 0, 1), std::make_tuple(1, 1, 1))));

ALL_ENGINE_TEST(AddSubtractUnitSP43, AddDuo, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto levels = std::get<4>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto added_level = max_level_ - std::get<2>(levels);
  auto engine = desilo::fhe::CKKSEngine(config_);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext1 = engine.encrypt_unit(message, public_key_, level1);
  auto unit_ciphertext2 = engine.encrypt_unit(message, public_key_, level2);

  auto input_unit_ciphertext1 = unit_ciphertext1;
  auto input_unit_ciphertext2 = unit_ciphertext2;

  if (first_rescaled) {
    auto rescaled_unit_ciphertext1 = engine.rescale(input_unit_ciphertext1);

    if (first_ntt) {
      input_unit_ciphertext1 = engine.ntt(rescaled_unit_ciphertext1);

      delete rescaled_unit_ciphertext1;
    } else {
      input_unit_ciphertext1 = rescaled_unit_ciphertext1;
    }
  } else if (first_ntt) {
    input_unit_ciphertext1 = engine.ntt(input_unit_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_unit_ciphertext2 = engine.rescale(input_unit_ciphertext2);

    if (second_ntt) {
      input_unit_ciphertext2 = engine.ntt(rescaled_unit_ciphertext2);

      delete rescaled_unit_ciphertext2;
    } else {
      input_unit_ciphertext2 = rescaled_unit_ciphertext2;
    }
  } else if (second_ntt) {
    input_unit_ciphertext2 = engine.ntt(input_unit_ciphertext2);
  }

  auto added = engine.add(input_unit_ciphertext1, input_unit_ciphertext2);

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

  EXPECT_EQ(added->level_, added_level);
  EXPECT_EQ(added->flag_, expected_flag);
  EXPECT_EQ(added->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(added);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (first_ntt || first_rescaled) {
    delete input_unit_ciphertext1;
  }
  if (second_ntt || second_rescaled) {
    delete input_unit_ciphertext2;
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete added;
})

ALL_ENGINE_TEST(AddSubtractUnitSP43, SubtractDuo, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto levels = std::get<4>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto subtracted_level = max_level_ - std::get<2>(levels);
  auto engine = desilo::fhe::CKKSEngine(config_);

  if ((first_rescaled && level1 - 1 < 0) ||
      (second_rescaled && level2 - 1 < 0)) {
    GTEST_SKIP() << "Impossible target level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 4);
  initiate_message(message2, 2);

  auto unit_ciphertext1 = engine.encrypt_unit(message1, public_key_, level1);
  auto unit_ciphertext2 = engine.encrypt_unit(message2, public_key_, level2);

  auto input_unit_ciphertext1 = unit_ciphertext1;
  auto input_unit_ciphertext2 = unit_ciphertext2;

  if (first_rescaled) {
    auto rescaled_unit_ciphertext1 = engine.rescale(input_unit_ciphertext1);

    if (first_ntt) {
      input_unit_ciphertext1 = engine.ntt(rescaled_unit_ciphertext1);

      delete rescaled_unit_ciphertext1;
    } else {
      input_unit_ciphertext1 = rescaled_unit_ciphertext1;
    }
  } else if (first_ntt) {
    input_unit_ciphertext1 = engine.ntt(input_unit_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_unit_ciphertext2 = engine.rescale(input_unit_ciphertext2);

    if (second_ntt) {
      input_unit_ciphertext2 = engine.ntt(rescaled_unit_ciphertext2);

      delete rescaled_unit_ciphertext2;
    } else {
      input_unit_ciphertext2 = rescaled_unit_ciphertext2;
    }
  } else if (second_ntt) {
    input_unit_ciphertext2 = engine.ntt(input_unit_ciphertext2);
  }

  auto subtracted =
      engine.subtract(input_unit_ciphertext1, input_unit_ciphertext2);

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

  EXPECT_EQ(subtracted->level_, subtracted_level);
  EXPECT_EQ(subtracted->flag_, expected_flag);
  EXPECT_EQ(subtracted->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(subtracted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] - message2[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (first_ntt || first_rescaled) {
    delete input_unit_ciphertext1;
  }
  if (second_ntt || second_rescaled) {
    delete input_unit_ciphertext2;
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete subtracted;
})
