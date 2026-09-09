#include "ckks/core/macro.h"
#include "common/common.h"

SETUP_TIER_TEST_SPE3(
    SPE3, LEVELS_1_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_message_type(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3));

TIER_TEST(SPE3, DecryptTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
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
  const auto decrypted = DECRYPT_TRIO(multiplied);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message2[i], decoded[i], threshold);
  }

  EXPECT_EQ(decrypted->ckks_scale_, multiplied->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete decrypted;
})

TIER_TEST(SPE3, DecryptComplexTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
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
  const auto decrypted = DECRYPT_TRIO(multiplied);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), threshold);
  }

  EXPECT_EQ(decrypted->ckks_scale_, multiplied->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete decrypted;
})

TIER_TEST(SPE3, AddTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && (message_type_1 == 3 || message_type_2 == 3)) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
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
  const auto multiplied1 = core.square(ntt_form1);
  const auto multiplied2 = core.square(ntt_form2);
  const auto added = core.add(multiplied1, multiplied2);
  const auto decrypted = DECRYPT_TRIO(added);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message1[i] + message2[i] * message2[i],
                decoded[i], threshold);
  }

  EXPECT_EQ(added->ckks_scale_, multiplied1->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied1;
  delete multiplied2;
  delete added;
  delete decrypted;
})

TIER_TEST(SPE3, AddInplaceTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && (message_type_1 == 3 || message_type_2 == 3)) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
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
  const auto multiplied1 = core.square(ntt_form1);
  const auto multiplied2 = core.square(ntt_form2);
  core.add_inplace(multiplied1, multiplied2);
  const auto decrypted = DECRYPT_TRIO(multiplied1);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message1[i] + message2[i] * message2[i],
                decoded[i], threshold);
  }

  EXPECT_EQ(multiplied1->ckks_scale_, multiplied1->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied1;
  delete multiplied2;
  delete decrypted;
})

TIER_TEST(SPE3, SubtractTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && (message_type_1 == 3 || message_type_2 == 3)) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
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
  const auto multiplied1 = core.square(ntt_form1);
  const auto multiplied2 = core.square(ntt_form2);
  const auto subtracted = core.subtract(multiplied1, multiplied2);
  const auto decrypted = DECRYPT_TRIO(subtracted);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message1[i] - message2[i] * message2[i],
                decoded[i], threshold);
  }

  EXPECT_EQ(subtracted->ckks_scale_, multiplied1->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied1;
  delete multiplied2;
  delete subtracted;
  delete decrypted;
})

TIER_TEST(SPE3, SubtractInplaceTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && (message_type_1 == 3 || message_type_2 == 3)) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
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
  const auto multiplied1 = core.square(ntt_form1);
  const auto multiplied2 = core.square(ntt_form2);
  core.subtract_inplace(multiplied1, multiplied2);
  const auto decrypted = DECRYPT_TRIO(multiplied1);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message1[i] - message2[i] * message2[i],
                decoded[i], threshold);
  }

  EXPECT_EQ(multiplied1->ckks_scale_, multiplied1->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied1;
  delete multiplied2;
  delete decrypted;
})

TIER_TEST(SPE3, MultiplyNTTForm, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
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
  const auto decrypted = DECRYPT_TRIO(multiplied);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), threshold);
  }

  EXPECT_NEAR(multiplied->ckks_scale_,
              rescaled1->ckks_scale_ * rescaled2->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete decrypted;
})

TIER_TEST(SPE3, ToINTTFormAndToNTTFormTrioCiphertext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
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
  const auto intt_form = core.to_intt_form(multiplied);
  const auto ntt_form = core.to_ntt_form(intt_form);
  const auto decrypted = DECRYPT_TRIO(ntt_form);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), threshold);
  }

  EXPECT_EQ(intt_form->ckks_scale_, multiplied->ckks_scale_);
  EXPECT_EQ(ntt_form->ckks_scale_, multiplied->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete intt_form;
  delete ntt_form;
  delete decrypted;
})

TIER_TEST(SPE3, MultiplyTrioPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = 2;
  const int message_type_3 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level < 2) {
    GTEST_SKIP() << "Not enough level.";
  }

  if (level == 2 && message_type_1 == 3 && message_type_3 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  std::vector<std::complex<double>> message3(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);
  initiate_message(message3, message_type_3);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto plaintext2 = core.encode(message2, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled_ciphertext1 = core.rescale(ciphertext1);
  const auto rescaled_ciphertext2 = core.rescale(ciphertext2);
  const auto ntt_ciphertext1 = core.to_ntt_form(rescaled_ciphertext1);
  const auto ntt_ciphertext2 = core.to_ntt_form(rescaled_ciphertext2);
  const auto multiplied1 = core.multiply(ntt_ciphertext1, ntt_ciphertext2);
  const auto intt_multiplied1 = core.to_intt_form(multiplied1);
  const auto rescaled_multiplied1 = core.rescale(intt_multiplied1);
  const auto ntt_multiplied1 = core.to_ntt_form(rescaled_multiplied1);
  const auto plaintext3 = core.encode(message3, level - 1, include_special);
  const auto rescaled_plaintext3 = core.rescale(plaintext3);
  const auto ntt_plaintext3 = core.to_ntt_form(rescaled_plaintext3);
  const auto multiplied2 = core.multiply(ntt_multiplied1, ntt_plaintext3);
  const auto decrypted = DECRYPT_TRIO(multiplied2);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(multiplied2->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                                    desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(multiplied2->polynomial_count(), 3);

  auto threshold = 1e-3;

  if (message_type_1 == 3 || message_type_3 == 3) {
    threshold = 10;

    if (config_.log_coeff_count_ == 17) {
      threshold = 100;
    }

    if (message_type_1 == 3 && message_type_3 == 3) {
      threshold = 1000;

      if (config_.log_coeff_count_ == 17) {
        threshold = 10000;
      }
    }
  }

  EXPECT_NEAR(multiplied2->ckks_scale_,
              rescaled_multiplied1->ckks_scale_ *
                  rescaled_plaintext3->ckks_scale_,
              1e-12);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message3[i];
    EXPECT_NEAR(expected.real(), decoded[i].real(), threshold);
    EXPECT_NEAR(expected.imag(), decoded[i].imag(), threshold);
  }

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled_ciphertext1;
  delete rescaled_ciphertext2;
  delete ntt_ciphertext1;
  delete ntt_ciphertext2;
  delete multiplied1;
  delete intt_multiplied1;
  delete rescaled_multiplied1;
  delete ntt_multiplied1;
  delete plaintext3;
  delete rescaled_plaintext3;
  delete ntt_plaintext3;
  delete multiplied2;
  delete decrypted;
})

TIER_TEST(SPE3, AddTrioPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
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
  const auto added = core.add(multiplied, plaintext3);
  const auto decrypted = DECRYPT_TRIO(added);
  const auto decoded = core.decode(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(added->flag_, flag | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(added->polynomial_count(), 3);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message2[i] + message3[i];
    ASSERT_NEAR(expected, decoded[i], threshold);
  }

  EXPECT_EQ(added->ckks_scale_, multiplied->ckks_scale_);

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
  delete added;
  delete decrypted;
})

TIER_TEST(SPE3, AddInplaceTrioPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
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
  const auto ntt_form3 = core.to_ntt_form(plaintext3);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);
  core.add_inplace(multiplied, ntt_form3);
  const auto decrypted = DECRYPT_TRIO(multiplied);
  const auto decoded = core.decode(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(multiplied->flag_, flag | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message2[i] + message3[i];
    ASSERT_NEAR(expected, decoded[i], threshold);
  }

  EXPECT_EQ(multiplied->ckks_scale_, multiplied->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete plaintext3;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete ntt_form3;
  delete multiplied;
  delete decrypted;
})

TIER_TEST(SPE3, NegateTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
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
  const auto negated = core.negate(multiplied);
  const auto decrypted = DECRYPT_TRIO(negated);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = -(message1[i] * message2[i]);
    ASSERT_NEAR(expected, decoded[i], threshold);
  }

  EXPECT_EQ(negated->ckks_scale_, multiplied->ckks_scale_);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete negated;
  delete decrypted;
})

TIER_TEST(SPE3, AddTrioAndDuo, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const int include_special = false;

  if (level == 1 && (message_type_1 == 3 || message_type_2 == 3)) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);

  const auto plaintext2 = core.encode(message2, level - 1, include_special);

  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);

  const auto rescaled1 = core.rescale(ciphertext1);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto squared1 = core.square(ntt_form1);
  const auto ntt_form2 = core.to_ntt_form(ciphertext2);

  const auto added = core.add_trio_and_duo(squared1, ntt_form2);
  const auto decrypted = DECRYPT_TRIO(added);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected_i = message1[i] * message1[i] + message2[i];
    ASSERT_NEAR(expected_i, decoded[i], threshold);
  }

  auto threshold_scale = ciphertext1->ckks_scale_ * 1e-15;
  EXPECT_NEAR(added->ckks_scale_, squared1->ckks_scale_, threshold_scale);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete ntt_form1;
  delete ntt_form2;
  delete rescaled1;
  delete squared1;
  delete added;
  delete decrypted;
})

TIER_TEST(SPE3, SubtractTrioAndDuo, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && (message_type_1 == 3 || message_type_2 == 3)) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);

  const auto plaintext2 = core.encode(message2, level - 1, include_special);

  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);

  const auto rescaled1 = core.rescale(ciphertext1);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto squared1 = core.square(ntt_form1);
  const auto ntt_form2 = core.to_ntt_form(ciphertext2);

  const auto subtracted = core.subtract_trio_by_duo(squared1, ntt_form2);
  const auto decrypted = DECRYPT_TRIO(subtracted);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected_i = message1[i] * message1[i] - message2[i];
    ASSERT_NEAR(expected_i, decoded[i], threshold);
  }

  auto threshold_scale = ciphertext1->ckks_scale_ * 1e-15;
  EXPECT_NEAR(subtracted->ckks_scale_, squared1->ckks_scale_, threshold_scale);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete ntt_form1;
  delete ntt_form2;
  delete rescaled1;
  delete squared1;
  delete subtracted;
  delete decrypted;
})

TIER_TEST(SPE3, SubtractDuoAndTrio, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && (message_type_1 == 3 || message_type_2 == 3)) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level - 1, include_special);
  const auto plaintext2 = core.encode(message2, level, include_special);

  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);

  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto squared2 = core.square(ntt_form2);
  const auto ntt_form1 = core.to_ntt_form(ciphertext1);

  const auto subtracted = core.subtract_duo_by_trio(ntt_form1, squared2);
  const auto decrypted = DECRYPT_TRIO(subtracted);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected_i = message1[i] - message2[i] * message2[i];
    ASSERT_NEAR(expected_i, decoded[i], threshold);
  }

  auto threshold_scale = ciphertext2->ckks_scale_ * 1e-15;
  EXPECT_NEAR(subtracted->ckks_scale_, squared2->ckks_scale_, threshold_scale);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete ntt_form1;
  delete ntt_form2;
  delete rescaled2;
  delete squared2;
  delete subtracted;
  delete decrypted;
})

TIER_TEST(SPE3, SubtractInplaceTrioPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
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
  core.subtract_inplace(multiplied, plaintext3);
  const auto decrypted = DECRYPT_TRIO(multiplied);
  const auto decoded = core.decode(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(multiplied->flag_, flag | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  auto threshold = 1e-4;
  if (message_type_1 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] * message2[i] - message3[i];
    ASSERT_NEAR(expected, decoded[i], threshold);
  }
  EXPECT_NEAR(multiplied->ckks_scale_, multiplied->ckks_scale_, 1e-12);

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
  delete decrypted;
})

const int LARGE_SCALAR = 1 << 26;

SETUP_TIER_TEST_SPE3(
    SPE3A, LEVELS_1_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) +
             print_scalar(std::get<2>(param));
    },
    testing::Values(1, 2, 3),
    testing::Values(1, -1, LARGE_SCALAR, -LARGE_SCALAR));

TIER_TEST(SPE3A, AddTrioScalar, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const double scalar = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with a single chain.";
  }

  if (level == 1 && abs(scalar) == LARGE_SCALAR) {
    GTEST_SKIP() << "Cannot decrypt big numbers with a single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto ntt_form = core.to_ntt_form(rescaled);
  const auto squared = core.square(ntt_form);
  const auto squared_intt = core.to_intt_form(squared);
  const auto added = core.add(squared_intt, scalar);
  const auto decrypt_input = core.to_ntt_form(added);
  const auto decrypted = DECRYPT_TRIO(decrypt_input);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(added->level_, level - 1);
  EXPECT_EQ(added->polynomial_count(), 3);

  auto threshold = 1e-4;
  if (message_type == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * message[i] + scalar, decoded[i], threshold);
  }

  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete ntt_form;
  delete squared;
  delete squared_intt;
  delete decrypt_input;
  delete added;
  delete decrypted;
})

TIER_TEST(SPE3A, AddInplaceTrioScalar, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const double scalar = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with a single chain.";
  }

  if (level == 1 && abs(scalar) == LARGE_SCALAR) {
    GTEST_SKIP() << "Cannot decrypt big numbers with a single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto ntt_form = core.to_ntt_form(rescaled);
  const auto squared = core.square(ntt_form);
  const auto squared_intt = core.to_intt_form(squared);
  core.add_inplace(squared_intt, scalar);
  const auto decrypt_input = core.to_ntt_form(squared_intt);
  const auto decrypted = DECRYPT_TRIO(decrypt_input);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(squared_intt->level_, level - 1);
  EXPECT_EQ(squared_intt->polynomial_count(), 3);

  auto threshold = 1e-4;
  if (message_type == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * message[i] + scalar, decoded[i], threshold);
  }

  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete ntt_form;
  delete squared;
  delete squared_intt;
  delete decrypt_input;
  delete decrypted;
})
