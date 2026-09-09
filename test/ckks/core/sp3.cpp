#include "ckks/core.h"
#include "ckks/core/macro.h"
#include "ckks/precomputed.h"
#include "common/common.h"

SETUP_TIER_TEST_SP3(
    SP3A, LEVELS_0_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_message_type(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3));

TIER_TEST(SP3A, Add, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

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
  const auto added = core.add(ciphertext1, ciphertext2);
  const auto decrypted = DECRYPT_DUO(added);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] + message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, added->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete added;
  delete decrypted;
})

TIER_TEST(SP3A, AddIncludeSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
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
  const auto ciphertext1_attached =
      core.attach_special_prime_chains(ciphertext1);
  const auto ciphertext2_attached =
      core.attach_special_prime_chains(ciphertext2);
  const auto added = core.add(ciphertext1_attached, ciphertext2_attached);
  const auto added_removed = core.remove_special_prime_chains(added);
  const auto decrypted = DECRYPT_DUO(added_removed);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(added->level_, level);
  EXPECT_EQ(added->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                              desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(added->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] + message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, added->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete ciphertext1_attached;
  delete ciphertext2_attached;
  delete added;
  delete added_removed;
  delete decrypted;
})

TIER_TEST(SP3A, AddPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto plaintext2 = core.encode(message2, level, include_special);
  const auto added = core.add(ciphertext1, plaintext2);
  const auto decrypted = DECRYPT_DUO(added);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] + message2[i], decoded[i], 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, added->ckks_scale_, 1e-12);
  EXPECT_NEAR(plaintext1->ckks_scale_, added->ckks_scale_, 1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete plaintext2;
  delete added;
  delete decrypted;
})

TIER_TEST(SP3A, AddInplace, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

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
  core.add_inplace(ciphertext1, ciphertext2);
  const auto decrypted = DECRYPT_DUO(ciphertext1);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] + message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, ciphertext1->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete decrypted;
})

TIER_TEST(SP3A, AddInplaceIncludeSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
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
  const auto ciphertext1_attached =
      core.attach_special_prime_chains(ciphertext1);
  const auto ciphertext2_attached =
      core.attach_special_prime_chains(ciphertext2);
  core.add_inplace(ciphertext1_attached, ciphertext2_attached);
  const auto added_removed =
      core.remove_special_prime_chains(ciphertext1_attached);
  const auto decrypted = DECRYPT_DUO(added_removed);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(ciphertext1_attached->level_, level);
  EXPECT_EQ(ciphertext1_attached->flag_,
            flag | desilo::fhe::DataFlag::NTT_FORM |
                desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(ciphertext1_attached->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] + message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, ciphertext1_attached->ckks_scale_,
              1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete ciphertext1_attached;
  delete ciphertext2_attached;
  delete added_removed;
  delete decrypted;
})

TIER_TEST(SP3A, AddInplacePlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto plaintext2 = core.encode(message2, level, include_special);
  core.add_inplace(ciphertext1, plaintext2);
  const auto decrypted = DECRYPT_DUO(ciphertext1);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] + message2[i], decoded[i], 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, ciphertext1->ckks_scale_, 1e-12);
  EXPECT_NEAR(plaintext1->ckks_scale_, ciphertext1->ckks_scale_, 1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete plaintext2;
  delete decrypted;
})

TIER_TEST(SP3A, Subtract, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

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
  const auto subtracted = core.subtract(ciphertext1, ciphertext2);
  const auto decrypted = DECRYPT_DUO(subtracted);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] - message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, subtracted->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete subtracted;
  delete decrypted;
})

TIER_TEST(SP3A, SubtractInplace, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

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
  core.subtract_inplace(ciphertext1, ciphertext2);
  const auto decrypted = DECRYPT_DUO(ciphertext1);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] - message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, ciphertext1->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete decrypted;
})

TIER_TEST(SP3A, SubtractInplacePlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto plaintext2 = core.encode(message2, level, include_special);
  core.subtract_inplace(ciphertext1, plaintext2);
  const auto decrypted = DECRYPT_DUO(ciphertext1);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] - message2[i];
    ASSERT_NEAR(expected, decoded[i], 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, ciphertext1->ckks_scale_, 1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete plaintext2;
  delete decrypted;
})

TIER_TEST(SP3A, NTTCiphertextSubtractInplacePlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext1_ntt = core.to_ntt_form(ciphertext1);
  const auto plaintext2 = core.encode(message2, level, include_special);
  core.subtract_inplace(ciphertext1_ntt, plaintext2);
  const auto subtracted_intt = core.to_intt_form(ciphertext1_ntt);
  const auto decrypted = DECRYPT_DUO(subtracted_intt);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] - message2[i];
    ASSERT_NEAR(expected, decoded[i], 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, ciphertext1_ntt->ckks_scale_, 1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete ciphertext1_ntt;
  delete plaintext2;
  delete subtracted_intt;
  delete decrypted;
})

SETUP_TIER_TEST_SP3(
    SP3B, LEVELS_1_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_message_type(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3));

TIER_TEST(SP3B, AddIncludeSpecialRescaled, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
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
  const auto ciphertext1_rescaled = core.rescale(ciphertext1);
  const auto ciphertext2_rescaled = core.rescale(ciphertext2);
  const auto ciphertext1_attached =
      core.attach_special_prime_chains(ciphertext1_rescaled);
  const auto ciphertext2_attached =
      core.attach_special_prime_chains(ciphertext2_rescaled);
  const auto added = core.add(ciphertext1_attached, ciphertext2_attached);
  const auto added_removed = core.remove_special_prime_chains(added);
  const auto leveled_down =
      core.level_down_after_rescale(added_removed, level - 1);
  const auto decrypted = DECRYPT_DUO(leveled_down);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::RESCALED;

  EXPECT_EQ(added->level_, level);
  EXPECT_EQ(added->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                              desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(added->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message1[i] + message2[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(ciphertext1_rescaled->ckks_scale_, added->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete ciphertext1_rescaled;
  delete ciphertext2_rescaled;
  delete ciphertext1_attached;
  delete ciphertext2_attached;
  delete added;
  delete added_removed;
  delete leveled_down;
  delete decrypted;
})

TIER_TEST(SP3B, MultiplyPlaintextINTTForm, {
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
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto plaintext2 = core.encode(message2, level, include_special);
  const auto rescaled_ciphertext1 = core.rescale(ciphertext1);
  const auto rescaled_plaintext2 = core.rescale(plaintext2);
  const auto ntt_ciphertext1 = core.to_ntt_form(rescaled_ciphertext1);
  const auto ntt_plaintext2 = core.to_ntt_form(rescaled_plaintext2);
  const auto multiplied = core.multiply(ntt_ciphertext1, ntt_plaintext2);
  const auto intt_multiplied = core.to_intt_form(multiplied);
  const auto decrypted = DECRYPT_DUO(intt_multiplied);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(multiplied->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::COMPLEX);

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
              rescaled_ciphertext1->ckks_scale_ *
                  rescaled_plaintext2->ckks_scale_,
              1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete plaintext2;
  delete rescaled_ciphertext1;
  delete rescaled_plaintext2;
  delete ntt_ciphertext1;
  delete ntt_plaintext2;
  delete multiplied;
  delete intt_multiplied;
  delete decrypted;
})

TIER_TEST(SP3B, MultiplyPlaintextNTTForm, {
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
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto plaintext2 = core.encode(message2, level, include_special);
  const auto rescaled_ciphertext1 = core.rescale(ciphertext1);
  const auto rescaled_plaintext2 = core.rescale(plaintext2);
  const auto ntt_ciphertext1 = core.to_ntt_form(rescaled_ciphertext1);
  const auto ntt_plaintext2 = core.to_ntt_form(rescaled_plaintext2);
  const auto multiplied = core.multiply(ntt_ciphertext1, ntt_plaintext2);
  const auto intt_multiplied = core.to_intt_form(multiplied);
  const auto decrypted = DECRYPT_DUO(intt_multiplied);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(multiplied->flag_, flag | desilo::fhe::DataFlag::COMPLEX |
                                   desilo::fhe::DataFlag::NTT_FORM);

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
              ntt_ciphertext1->ckks_scale_ * ntt_plaintext2->ckks_scale_,
              1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete plaintext2;
  delete rescaled_ciphertext1;
  delete rescaled_plaintext2;
  delete ntt_ciphertext1;
  delete ntt_plaintext2;
  delete multiplied;
  delete intt_multiplied;
  delete decrypted;
})

TIER_TEST(SP3B, MultiplyPlaintextNTTFormIncludeSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());

  if (level == 1 && message_type_1 == 3 && message_type_2 == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, message_type_1);
  initiate_message(message2, message_type_2);

  const auto plaintext1 = core.encode(message1, level, false);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto plaintext2 = core.encode(message2, level, true);

  const auto rescaled_ciphertext1 = core.rescale(ciphertext1);
  const auto rescaled_plaintext2 = core.rescale(plaintext2);
  const auto ciphertext1_attached =
      core.attach_special_prime_chains(rescaled_ciphertext1);

  const auto ntt_plaintext2 = core.to_ntt_form(rescaled_plaintext2);
  const auto multiplied = core.multiply(ciphertext1_attached, ntt_plaintext2);

  const auto multiplied_removed = core.remove_special_prime_chains(multiplied);

  const auto decrypted = DECRYPT_DUO(multiplied_removed);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(multiplied->flag_, flag | desilo::fhe::DataFlag::COMPLEX |
                                   desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);

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
              rescaled_ciphertext1->ckks_scale_ * ntt_plaintext2->ckks_scale_,
              1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete plaintext2;
  delete rescaled_ciphertext1;
  delete rescaled_plaintext2;
  delete ciphertext1_attached;
  delete ntt_plaintext2;
  delete multiplied;
  delete multiplied_removed;
  delete decrypted;
})

const int LARGE_SCALAR = 1 << 26;

SETUP_TIER_TEST_SP3(
    SP3C, LEVELS_0_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) +
             print_scalar(std::get<2>(param));
    },
    testing::Values(1, 2, 3),
    testing::Values(1, -1, LARGE_SCALAR, -LARGE_SCALAR));

TIER_TEST(SP3C, AddScalar, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const double scalar = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 0 && abs(scalar) == LARGE_SCALAR) {
    GTEST_SKIP() << "Cannot decrypt big numbers with a single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto added = core.add(ciphertext, scalar);
  const auto decrypted = DECRYPT_DUO(added);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(added->level_, level);
  EXPECT_EQ(added->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] + scalar, decoded[i], 1e-4);
  }

  EXPECT_NEAR(added->ckks_scale_, ciphertext->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete added;
  delete decrypted;
})

TIER_TEST(SP3C, MultiplyScalar, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const double scalar = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 0) {
    GTEST_SKIP() << "Cannot multiply when the level is 0.";
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
  const auto multiplied = core.multiply(ciphertext, scalar);
  const auto decrypted = DECRYPT_DUO(multiplied);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(multiplied->level_, level - 1);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  auto threshold = 1e-4;
  if (abs(scalar) == LARGE_SCALAR) {
    threshold = 1e-3;
    if (message_type == 3) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * scalar, decoded[i], threshold);
  }

  const auto precomputed = desilo::fhe::CKKSPrecomputed(config_);
  const auto q = precomputed.get_q(ciphertext->moduli_id_);
  long double rescaled_scale = ciphertext->ckks_scale_ / q[0];

  EXPECT_NEAR(multiplied->ckks_scale_, rescaled_scale * rescaled_scale, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete multiplied;
  delete decrypted;
})

TIER_TEST(SP3C, MultiplyIntegerScalar, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int64_t scalar = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 0) {
    GTEST_SKIP() << "Cannot multiply when the level is 0.";
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
  const auto multiplied = core.multiply(ciphertext, scalar);
  const auto decrypted = DECRYPT_DUO(multiplied);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(multiplied->level_, level);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  auto threshold = 1e-4;
  if (abs(scalar) == LARGE_SCALAR) {
    threshold = 1e-3;
    if (message_type == 3) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * scalar, decoded[i], threshold);
  }

  EXPECT_NEAR(multiplied->ckks_scale_, ciphertext->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete multiplied;
  delete decrypted;
})

TIER_TEST(SP3C, MultiplyImaginaryIntegerScalar, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int64_t scalar = std::get<2>(GetParam());
  const bool include_special = false;

  if (level == 0) {
    GTEST_SKIP() << "Cannot multiply when the level is 0.";
  }

  if (level == 1 && abs(scalar) == LARGE_SCALAR) {
    GTEST_SKIP() << "Cannot decrypt big numbers with a single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext1 = core.encode(message, level, include_special);
  const auto plaintext2 = core.encode_imaginary(scalar, level);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ntt_ciphertext1 = core.to_ntt_form(ciphertext1);
  const auto ntt_plaintext2 = core.to_ntt_form(plaintext2);
  const auto multiplied = core.multiply(ntt_ciphertext1, ntt_plaintext2);
  const auto intt_multiplied = core.to_intt_form(multiplied);
  const auto decrypted = DECRYPT_DUO(intt_multiplied);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  EXPECT_EQ(multiplied->level_, level);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  auto threshold = 1e-4;
  if (abs(scalar) == LARGE_SCALAR) {
    threshold = 1e-3;
    if (message_type == 3) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(-message[i].imag() * scalar, decoded[i].real(), threshold);
    ASSERT_NEAR(message[i].real() * scalar, decoded[i].imag(), threshold);
  }

  EXPECT_NEAR(multiplied->ckks_scale_, ciphertext1->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ntt_ciphertext1;
  delete ntt_plaintext2;
  delete multiplied;
  delete intt_multiplied;
  delete decrypted;
})

SETUP_TIER_TEST_SP3(
    SP3D, LEVELS_1_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      const int level = std::get<0>(param);
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "To" +
             print_level(level - std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3));

TIER_TEST(SP3D, RescaleINTTFormLevelDownPlaintext, {
  const int level_from = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int level_to = level_from - std::get<2>(GetParam());
  const bool include_special = false;

  if (level_to < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level_from, include_special);
  const auto rescaled = core.rescale(plaintext);
  const auto leveled_down = core.level_down_after_rescale(rescaled, level_to);
  const auto ciphertext = core.encrypt(leveled_down, public_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(plaintext->level_, level_from);
  EXPECT_EQ(rescaled->level_, level_from);
  EXPECT_EQ(leveled_down->level_, level_to);
  EXPECT_EQ(ciphertext->level_, level_to);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete rescaled;
  delete leveled_down;
  delete ciphertext;
  delete decrypted;
})

TIER_TEST(SP3D, INTTFormLevelDownPlaintext, {
  const int level_from = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int level_to = level_from - std::get<2>(GetParam());
  const bool include_special = false;

  if (level_to < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level_from, include_special);
  const auto leveled_down = core.level_down(plaintext, level_to);
  const auto decoded = core.decode(leveled_down);

  EXPECT_EQ(plaintext->level_, level_from);
  EXPECT_EQ(leveled_down->level_, level_to);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete leveled_down;
})

TIER_TEST(SP3D, RescaleINTTFormLevelDownCiphertext, {
  const int level_from = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int level_to = level_from - std::get<2>(GetParam());
  const bool include_special = false;

  if (level_to < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level_from, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto leveled_down = core.level_down_after_rescale(rescaled, level_to);
  const auto decrypted = DECRYPT_DUO(leveled_down);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(ciphertext->level_, level_from);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);
  EXPECT_EQ(rescaled->level_, level_from);
  EXPECT_EQ(rescaled->polynomial_count(), 2);
  EXPECT_EQ(leveled_down->level_, level_to);
  EXPECT_EQ(leveled_down->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  const auto precomputed = desilo::fhe::CKKSPrecomputed(config_);
  const auto q = precomputed.get_q(ciphertext->moduli_id_);
  long double divisor = q[0];

  const long double rescaled_scale = ciphertext->ckks_scale_ / divisor;

  EXPECT_NEAR(rescaled->ckks_scale_, rescaled_scale, rescaled_scale * 1e-12);

  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete leveled_down;
  delete decrypted;
})

TIER_TEST(SP3D, INTTFormLevelDownCiphertext, {
  const int level_from = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int level_to = level_from - std::get<2>(GetParam());
  const bool include_special = false;

  if (level_to < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level_from, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto leveled_down = core.level_down(ciphertext, level_to);
  const auto decrypted = DECRYPT_DUO(leveled_down);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(ciphertext->level_, level_from);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);
  EXPECT_EQ(leveled_down->level_, level_to);
  EXPECT_EQ(leveled_down->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete leveled_down;
  delete decrypted;
})

SETUP_TIER_TEST_SP3(
    SP3E, LEVELS_0_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_delta(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, -4));

TIER_TEST(SP3E, RotateINTTFormUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int delta = std::get<2>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto rotated = core.rotate_intt_form(plaintext, delta);

  EXPECT_EQ(rotated->level_, level);

  const auto ciphertext = core.encrypt(rotated, public_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode(decrypted);

  if (delta > 0) {
    for (int i = 0; i < delta; i++) {
      ASSERT_NEAR(message[slot_count - delta + i], decoded[i], 1e-4);
    }

    for (int i = 0; i < slot_count - delta; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  } else {
    for (int i = 0; i < -delta; i++) {
      ASSERT_NEAR(message[i], decoded[slot_count + delta + i], 1e-4);
    }

    for (int i = -delta; i < slot_count; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  }

  EXPECT_NEAR(rotated->ckks_scale_, plaintext->ckks_scale_, 1e-12);

  delete plaintext;
  delete rotated;
  delete ciphertext;
  delete decrypted;
})

TIER_TEST(SP3E, RotateNTTFormUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int delta = std::get<2>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ntt_plaintext = core.to_ntt_form(plaintext);
  const auto rotated = core.rotate_ntt_form(ntt_plaintext, delta);

  EXPECT_EQ(rotated->level_, level);

  const auto intt_rotated = core.to_intt_form(rotated);
  const auto decoded = core.decode(intt_rotated);

  if (delta > 0) {
    for (int i = 0; i < delta; i++) {
      ASSERT_NEAR(message[slot_count - delta + i], decoded[i], 1e-4);
    }

    for (int i = 0; i < slot_count - delta; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  } else {
    for (int i = 0; i < -delta; i++) {
      ASSERT_NEAR(message[i], decoded[slot_count + delta + i], 1e-4);
    }

    for (int i = -delta; i < slot_count; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  }

  EXPECT_NEAR(rotated->ckks_scale_, plaintext->ckks_scale_, 1e-12);

  delete plaintext;
  delete ntt_plaintext;
  delete rotated;
  delete intt_rotated;
})

SETUP_TIER_TEST_SP3(
    SP3F, LEVELS_1_TO_MAX_MINUS_1,
    [](const std::tuple<int, int, bool> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) +
             print_include_special(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(false, true));

TIER_TEST(SP3F, RescaleEncodedWithSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = std::get<2>(GetParam());

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto rescaled = core.rescale(plaintext);
  const auto decoded = core.decode(rescaled);

  const auto flag = include_special ? desilo::fhe::DataFlag::INCLUDE_SPECIAL
                                    : desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, flag);

  EXPECT_EQ(rescaled->level_, level);
  EXPECT_EQ(rescaled->flag_, flag | desilo::fhe::DataFlag::RESCALED);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete rescaled;
})

SETUP_TIER_TEST_SP3(
    SP3G, LEVELS_0_TO_MAX_MINUS_1,
    [](const std::tuple<int, int, bool> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) +
             print_include_special(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(false, true));

TIER_TEST(SP3G, EncodeDecodeBufferWithSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = std::get<2>(GetParam());

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  auto message = new double[slot_count];
  initiate_message(message, slot_count, message_type);

  auto decoded = new double[slot_count];
  auto plaintext = core.encode(message, level, include_special);
  core.decode_to_buffer(plaintext, decoded);

  const auto flag = include_special ? desilo::fhe::DataFlag::INCLUDE_SPECIAL
                                    : desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, flag);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

TIER_TEST(SP3G, EncodeDecodeVectorWithSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = std::get<2>(GetParam());

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  auto plaintext = core.encode(message, level, include_special);
  auto decoded = core.decode(plaintext);

  const auto flag = include_special ? desilo::fhe::DataFlag::INCLUDE_SPECIAL
                                    : desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, flag);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
})

TIER_TEST(SP3G, EncodeDecodeComplexBufferWithSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = std::get<2>(GetParam());

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  auto message = new std::complex<double>[slot_count];
  initiate_message(message, slot_count, message_type);

  auto decoded = new std::complex<double>[slot_count];
  auto plaintext = core.encode(message, level, include_special);
  core.decode_complex_plaintext_to_buffer(plaintext, decoded);

  const auto flag = include_special ? desilo::fhe::DataFlag::COMPLEX |
                                          desilo::fhe::DataFlag::INCLUDE_SPECIAL
                                    : desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, flag);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

TIER_TEST(SP3G, EncodeDecodeComplexVectorWithSpecial, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int include_special = std::get<2>(GetParam());

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  auto plaintext = core.encode(message, level, include_special);
  auto decoded = core.decode_complex_plaintext(plaintext);

  const auto flag = include_special ? desilo::fhe::DataFlag::COMPLEX |
                                          desilo::fhe::DataFlag::INCLUDE_SPECIAL
                                    : desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, flag);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
})
