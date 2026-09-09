#include "ckks/core.h"
#include "ckks/core/macro.h"
#include "common/common.h"
#include "data/data.h"

SETUP_TIER_TEST_SP2(
    SP2, LEVELS_0_TO_MAX,
    [](const std::tuple<int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param));
    },
    testing::Values(1, 2, 3));

TIER_TEST(SP2, EncodeEncryptDecryptDecode, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, desilo::fhe::DataFlag::NONE);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level_, level);
  EXPECT_EQ(ciphertext->flag_, flag);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);

  EXPECT_EQ(decrypted->level_, level);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::NONE);

  EXPECT_EQ(plaintext->ckks_scale_, ciphertext->ckks_scale_);
  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

TIER_TEST(SP2, EncryptUsingSecretKey, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, secret_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, desilo::fhe::DataFlag::NONE);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level_, level);
  EXPECT_EQ(ciphertext->flag_, flag);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);

  EXPECT_EQ(decrypted->level_, level);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::NONE);

  EXPECT_EQ(plaintext->ckks_scale_, ciphertext->ckks_scale_);
  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

TIER_TEST(SP2, DecodeComplexUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(plaintext->flag_, desilo::fhe::DataFlag::COMPLEX);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level_, level);
  EXPECT_EQ(ciphertext->flag_, flag | desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);

  EXPECT_EQ(decrypted->level_, level);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

TIER_TEST(SP2, CloneCiphertext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto cloned = core.clone(ciphertext);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level_, level);
  EXPECT_EQ(ciphertext->flag_, flag);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);

  EXPECT_EQ(cloned->level_, level);
  EXPECT_EQ(cloned->flag_, flag);
  EXPECT_EQ(cloned->polynomial_count(), 2);

  EXPECT_EQ(ciphertext->ckks_scale_, cloned->ckks_scale_);

  delete ciphertext;

  const auto decrypted = DECRYPT_DUO(cloned);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete cloned;
  delete decrypted;
})

TIER_TEST(SP2, CloneUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto cloned = core.clone(plaintext);

  EXPECT_EQ(plaintext->level_, level);
  EXPECT_EQ(cloned->level_, level);
  EXPECT_EQ(plaintext->ckks_scale_, cloned->ckks_scale_);

  delete plaintext;

  const auto ciphertext = core.encrypt(cloned, public_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level_, level);
  EXPECT_EQ(ciphertext->flag_, flag);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete cloned;
  delete ciphertext;
  delete decrypted;
})

TIER_TEST(SP2, Negate, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto negated = core.negate(ciphertext);
  const auto decrypted = DECRYPT_DUO(negated);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(ciphertext->ckks_scale_, negated->ckks_scale_);
  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(-message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete negated;
  delete decrypted;
})

TIER_TEST(SP2, ToNTTFormAndToINTTFormCiphertext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto ntt_form = core.to_ntt_form(ciphertext);
  const auto intt_form = core.to_intt_form(ntt_form);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode(decrypted);

  const auto intt_flag = desilo::fhe::DataFlag::NONE;
  const auto ntt_flag = desilo::fhe::DataFlag::NTT_FORM | intt_flag;

  EXPECT_EQ(ciphertext->flag_, intt_flag);

  EXPECT_EQ(ntt_form->level_, level);
  EXPECT_EQ(ntt_form->flag_, ntt_flag);
  EXPECT_EQ(ntt_form->polynomial_count(), 2);

  EXPECT_EQ(intt_form->level_, level);
  EXPECT_EQ(intt_form->flag_, intt_flag);
  EXPECT_EQ(intt_form->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete ntt_form;
  delete intt_form;
  delete decrypted;
})

TIER_TEST(SP2, ToNTTFormAndToINTTFormUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ntt_form = core.to_ntt_form(plaintext);
  const auto intt_form = core.to_intt_form(ntt_form);
  const auto ciphertext = core.encrypt(intt_form, public_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode(decrypted);

  EXPECT_EQ(ntt_form->level_, level);
  EXPECT_EQ(ntt_form->flag_, desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(ntt_form->polynomial_count(), 1);

  EXPECT_EQ(intt_form->level_, level);
  EXPECT_EQ(intt_form->flag_, desilo::fhe::DataFlag::NONE);
  EXPECT_EQ(intt_form->polynomial_count(), 1);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->flag_, flag);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete ntt_form;
  delete intt_form;
  delete decrypted;
})

TIER_TEST(SP2, ConjugateINTTFormUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto conjugated = core.conjugate_intt_form(plaintext);
  const auto ciphertext = core.encrypt(conjugated, public_key_);
  const auto decrypted = DECRYPT_DUO(ciphertext);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  EXPECT_EQ(conjugated->level_, level);
  EXPECT_EQ(plaintext->ckks_scale_, conjugated->ckks_scale_);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = std::conj(message[i]);
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete conjugated;
  delete ciphertext;
  delete decrypted;
})

TIER_TEST(SP2, ConjugateNTTFormUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ntt_plaintext = core.to_ntt_form(plaintext);
  const auto conjugated = core.conjugate_ntt_form(ntt_plaintext);

  EXPECT_EQ(conjugated->level_, level);

  const auto intt_conjugated = core.to_intt_form(conjugated);
  const auto decoded = core.decode_complex_plaintext(intt_conjugated);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = std::conj(message[i]);
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete ntt_plaintext;
  delete conjugated;
  delete intt_conjugated;
})

TIER_TEST(SP2, AttachThenRemoveSpecialPrimeChainsUnitPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext1 = core.encode(message, level, include_special);
  const auto plaintext2 = core.attach_special_prime_chains(plaintext1);
  const auto plaintext3 = core.remove_special_prime_chains(plaintext2);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext1->level_, level);
  EXPECT_EQ(plaintext1->flag_, flag);

  EXPECT_EQ(plaintext2->level_, level);
  EXPECT_EQ(plaintext2->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);

  EXPECT_EQ(plaintext3->level_, level);
  EXPECT_EQ(plaintext3->flag_, flag);

  EXPECT_EQ(plaintext1->ckks_scale_, plaintext2->ckks_scale_);
  EXPECT_EQ(plaintext1->ckks_scale_, plaintext3->ckks_scale_);

  const auto decoded = core.decode(plaintext3);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext1;
  delete plaintext2;
  delete plaintext3;
})

TIER_TEST(SP2, AttachThenRemoveSpecialPrimeChainsCiphertext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext, public_key_);
  const auto ciphertext2 = core.attach_special_prime_chains(ciphertext1);
  const auto ciphertext3 = core.remove_special_prime_chains(ciphertext2);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext1->level_, level);
  EXPECT_EQ(ciphertext1->flag_, flag);
  EXPECT_EQ(ciphertext1->polynomial_count(), 2);

  EXPECT_EQ(ciphertext2->level_, level);
  EXPECT_EQ(ciphertext2->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                                    desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(ciphertext2->polynomial_count(), 2);

  EXPECT_EQ(ciphertext3->level_, level);
  EXPECT_EQ(ciphertext3->flag_, flag);
  EXPECT_EQ(ciphertext3->polynomial_count(), 2);

  EXPECT_EQ(ciphertext1->ckks_scale_, ciphertext2->ckks_scale_);
  EXPECT_EQ(ciphertext1->ckks_scale_, ciphertext3->ckks_scale_);

  const auto decrypted = DECRYPT_DUO(ciphertext3);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext1;
  delete ciphertext2;
  delete ciphertext3;
  delete decrypted;
})

TIER_TEST(SP2, INTTThenNTTUnitPlaintextWithSpecialPrimeChains, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext1 = core.encode(message, level, include_special);
  const auto plaintext2 = core.attach_special_prime_chains(plaintext1);
  const auto plaintext3 = core.to_intt_form(plaintext2);
  const auto plaintext4 = core.to_ntt_form(plaintext3);
  const auto plaintext5 = core.remove_special_prime_chains(plaintext4);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext3->level_, level);
  EXPECT_EQ(plaintext3->flag_, flag | desilo::fhe::DataFlag::INCLUDE_SPECIAL);

  EXPECT_EQ(plaintext4->level_, level);
  EXPECT_EQ(plaintext4->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);

  EXPECT_EQ(plaintext1->ckks_scale_, plaintext3->ckks_scale_);
  EXPECT_EQ(plaintext1->ckks_scale_, plaintext4->ckks_scale_);

  const auto decoded = core.decode(plaintext5);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext1;
  delete plaintext2;
  delete plaintext3;
  delete plaintext4;
  delete plaintext5;
})

TIER_TEST(SP2, NTTThenINTTUnitPlaintextEncodedWithSpecialPrimeChains, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = true;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext1 = core.encode(message, level, include_special);
  const auto plaintext2 = core.to_ntt_form(plaintext1);
  const auto plaintext3 = core.to_intt_form(plaintext2);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext2->level_, level);
  EXPECT_EQ(plaintext2->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);

  EXPECT_EQ(plaintext3->level_, level);
  EXPECT_EQ(plaintext3->flag_, flag | desilo::fhe::DataFlag::INCLUDE_SPECIAL);

  EXPECT_EQ(plaintext1->ckks_scale_, plaintext2->ckks_scale_);
  EXPECT_EQ(plaintext1->ckks_scale_, plaintext3->ckks_scale_);

  const auto decoded = core.decode(plaintext3);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext1;
  delete plaintext2;
  delete plaintext3;
})

TIER_TEST(SP2, NTTThenINTTCiphertextWithSpecialPrimeChains, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext, public_key_);
  const auto ciphertext2 = core.attach_special_prime_chains(ciphertext1);
  const auto ciphertext3 = core.to_intt_form(ciphertext2);
  const auto ciphertext4 = core.to_ntt_form(ciphertext3);
  const auto ciphertext5 = core.remove_special_prime_chains(ciphertext4);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext3->level_, level);
  EXPECT_EQ(ciphertext3->flag_, flag | desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(ciphertext3->polynomial_count(), 2);

  EXPECT_EQ(ciphertext4->level_, level);
  EXPECT_EQ(ciphertext4->flag_, flag | desilo::fhe::DataFlag::NTT_FORM |
                                    desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(ciphertext4->polynomial_count(), 2);

  EXPECT_EQ(ciphertext1->ckks_scale_, ciphertext3->ckks_scale_);
  EXPECT_EQ(ciphertext1->ckks_scale_, ciphertext4->ckks_scale_);

  const auto decrypted = DECRYPT_DUO(ciphertext5);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext1;
  delete ciphertext2;
  delete ciphertext3;
  delete ciphertext4;
  delete ciphertext5;
  delete decrypted;
})

TIER_TEST(SP2, KeySwitchToAnotherSecretKey, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    GTEST_SKIP() << "Not supported for one more level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);

  const auto secret_key2 = core.create_secret_key(level);
  const auto key_switching_key =
      core.create_key_switching_key(secret_key_, secret_key2, level);

  const auto switched = core.switch_key(ciphertext, key_switching_key);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level_, level);
  EXPECT_EQ(ciphertext->flag_, flag);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);

  EXPECT_EQ(switched->level_, level);
  EXPECT_EQ(switched->flag_, flag);
  EXPECT_EQ(switched->polynomial_count(), 2);

  EXPECT_EQ(ciphertext->ckks_scale_, switched->ckks_scale_);

  const auto decrypted = core.decrypt_duo(switched, secret_key2);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete secret_key2;
  delete key_switching_key;
  delete switched;
  delete decrypted;
})
