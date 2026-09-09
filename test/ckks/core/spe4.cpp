#include "ckks/core/macro.h"
#include "ckks/engine.h"
#include "ckks/precomputed.h"
#include "common/common.h"

SETUP_TIER_TEST_SPE4(
    SPE4A, LEVELS_1_TO_MAX,
    [](const std::tuple<int, int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_message_type(std::get<2>(param)) +
             print_input_order(std::get<3>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3), testing::Values(1, 2));

TIER_TEST(SPE4A, SubtractTrioPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const int input_order = std::get<3>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  std::vector<double> message3(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, 2);
  initiate_message(message3, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto plaintext2 = core.encode(message2, level, include_special);
  const auto plaintext3 = core.encode(message3, level - 1, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled1 = core.rescale(ciphertext1);
  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);
  desilo::fhe::UnitCiphertext *subtracted;
  if (input_order == 1) {
    subtracted = core.subtract(multiplied, plaintext3);
  } else {
    subtracted = core.subtract(plaintext3, multiplied);
  }
  const auto decrypted = DECRYPT_TRIO(subtracted);
  const auto decoded = core.decode(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(subtracted->flag_, flag | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(subtracted->polynomial_count(), 3);

  auto threshold = 1e-4;
  if (message_type_1 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = (input_order == 1)
                              ? (message1[i] * message2[i] - message3[i])
                              : (message3[i] - message1[i] * message2[i]);
    ASSERT_NEAR(expected, decoded[i], threshold);
  }
  EXPECT_NEAR(subtracted->ckks_scale_, multiplied->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete plaintext3;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete subtracted;
  delete decrypted;
})

SETUP_TIER_TEST_SPE4(
    SPE4B, LEVELS_2_TO_MAX,
    [](const std::tuple<int, int, int, int> &param) {
      const int level_from = std::get<0>(param) - 1;
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_message_type(std::get<2>(param)) + "From" +
             print_level(level_from) + "To" +
             print_level(level_from - std::get<3>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3),
    testing::Values(1, 2, 3));

TIER_TEST(SPE4B, RescaleNTTFormLevelDownTrio, {
  const int level = std::get<0>(GetParam());
  const int level_from = level - 1;
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const int level_to = level_from - std::get<3>(GetParam());
  const bool include_special = false;

  if (level_to == 0 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  if (level_from < 1) {
    GTEST_SKIP() << "Impossible starting level.";
  }

  if (level_to < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto plaintext2 = core.encode(message2, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled1 = core.rescale(ciphertext1);
  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);
  const auto rescaled3 = core.rescale(multiplied);
  const auto leveled_down = core.level_down_after_rescale(rescaled3, level_to);
  const auto decrypted = DECRYPT_TRIO(leveled_down);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(rescaled3->level_, level_from);
  EXPECT_EQ(rescaled3->polynomial_count(), 3);
  EXPECT_EQ(leveled_down->level_, level_to);
  EXPECT_EQ(leveled_down->polynomial_count(), 3);

  auto threshold = 1e-3;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-1;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message2[i], decoded[i], threshold);
  }

  const auto precomputed = desilo::fhe::CKKSPrecomputed(config_);
  const auto q = precomputed.get_q(multiplied->moduli_id_);
  long double divisor = q[0];

  const long double rescaled_scale = multiplied->ckks_scale_ / divisor;
  EXPECT_NEAR(rescaled3->ckks_scale_, rescaled_scale, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete rescaled3;
  delete leveled_down;
  delete decrypted;
})

TIER_TEST(SPE4B, INTTFormLevelDownTrio, {
  const int level = std::get<0>(GetParam());
  const int level_from = level - 1;
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const int level_to = level_from - std::get<3>(GetParam());
  const bool include_special = false;

  if (level_to == 0 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  if (level_from < 1) {
    GTEST_SKIP() << "Impossible starting level.";
  }

  if (level_to < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto plaintext2 = core.encode(message2, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled1 = core.rescale(ciphertext1);
  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);
  const auto multiplied_intt = core.to_intt_form(multiplied);
  const auto leveled_down_intt = core.level_down(multiplied_intt, level_to);
  const auto leveled_down = core.to_ntt_form(leveled_down_intt);
  const auto decrypted = DECRYPT_TRIO(leveled_down);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(multiplied_intt->level_, level_from);
  EXPECT_EQ(multiplied_intt->polynomial_count(), 3);
  EXPECT_EQ(leveled_down->level_, level_to);
  EXPECT_EQ(leveled_down->polynomial_count(), 3);

  auto threshold = 1e-3;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-1;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message2[i], decoded[i], threshold);
  }

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete multiplied_intt;
  delete leveled_down_intt;
  delete leveled_down;
  delete decrypted;
})
