#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP1(
    SP0, [](const std::tuple<int> &param) { return "0"; },

    testing::Values(0));

ALL_ENGINE_TEST(SP0, EncryptDecryptUnit, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 3);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  const auto decrypted = DECRYPT_UNIT(unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete unit_ciphertext;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptUnitLeveled, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto decrypted = DECRYPT_UNIT(unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(unit_ciphertext->level_, level);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete unit_ciphertext;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptUnitComplex, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  const auto decrypted = DECRYPT_UNIT_COMPLEX(unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptUnitComplexLeveled, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto decrypted = DECRYPT_UNIT_COMPLEX(unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(unit_ciphertext->level_, level);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptUnitTrio, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted = engine.decrypt(multiplied, secret_key_);

  EXPECT_EQ(multiplied->level_, max_level_ - 1);
  EXPECT_EQ(multiplied->flag_, desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * message[i], decrypted[i], 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptUnitLeveledTrio, {
  if (max_level_ <= 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);
  int level = max_level_ - 1;

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted = engine.decrypt(multiplied, secret_key_);

  EXPECT_EQ(multiplied->level_, level - 1);
  EXPECT_EQ(multiplied->flag_, desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * message[i], decrypted[i], 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptUnitComplexTrio, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted = engine.decrypt_complex(multiplied, secret_key_);

  EXPECT_EQ(multiplied->level_, max_level_ - 1);
  EXPECT_EQ(multiplied->flag_,
            desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptComplexUnitLeveledTrio, {
  if (max_level_ <= 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);
  int level = max_level_ - 1;

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted = engine.decrypt_complex(multiplied, secret_key_);

  EXPECT_EQ(multiplied->level_, level - 1);
  EXPECT_EQ(multiplied->flag_,
            desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(multiplied->polynomial_count(), 3);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
})

ALL_ENGINE_TEST(SP0, EncodeEncryptDecryptDecodeUnit, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 3);

  const auto unit_plaintext = engine.encode_unit(message);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, public_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_unit(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(unit_plaintext->level_, max_level_);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::NONE);
  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, max_level_);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::NONE);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncodeEncryptDecryptDecodeUnitShortMessage, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count / 2;
  std::vector<double> message(message_size);
  initiate_message(message, 3);

  const auto unit_plaintext = engine.encode_unit(message);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, public_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_unit(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(unit_plaintext->level_, max_level_);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::NONE);
  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, max_level_);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::NONE);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  for (int i = message_size; i < slot_count; i++) {
    ASSERT_NEAR(0, decoded[i], 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncodeEncryptDecryptDecodeUnitLeveled, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto unit_plaintext = engine.encode_unit(message, level);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, public_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_unit(decrypted);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(unit_plaintext->level_, level);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::NONE);
  EXPECT_EQ(unit_ciphertext->level_, level);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, level);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::NONE);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncodeEncryptDecryptDecodeUnitComplex, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_plaintext = engine.encode_unit(message);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, public_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(unit_plaintext->level_, max_level_);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, max_level_);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncodeEncryptDecryptDecodeUnitComplexShortMessage, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count / 2;
  std::vector<std::complex<double>> message(message_size);
  initiate_message(message, 3);

  const auto unit_plaintext = engine.encode_unit(message);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, public_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(unit_plaintext->level_, max_level_);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, max_level_);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  for (int i = message_size; i < slot_count; i++) {
    ASSERT_NEAR(0, decoded[i].real(), 1e-4);
    ASSERT_NEAR(0, decoded[i].imag(), 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncodeEncryptDecryptDecodeUnitComplexLeveled, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto unit_plaintext = engine.encode_unit(message, level);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, public_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(unit_plaintext->level_, level);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->level_, level);
  EXPECT_EQ(unit_ciphertext->flag_, flag);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, level);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptDecodeUnitTrio, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted =
      engine.decrypt_to_unit_plaintext(multiplied, secret_key_);
  const auto decoded = engine.decode_unit(decrypted);

  EXPECT_EQ(multiplied->level_, max_level_ - 1);
  EXPECT_EQ(multiplied->flag_, desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(multiplied->polynomial_count(), 3);
  EXPECT_EQ(decrypted->level_, max_level_ - 1);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::NONE);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * message[i], decoded[i], 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptDecodeUnitLeveledTrio, {
  if (max_level_ <= 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);
  int level = max_level_ - 1;

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted =
      engine.decrypt_to_unit_plaintext(multiplied, secret_key_);
  const auto decoded = engine.decode_unit(decrypted);

  EXPECT_EQ(multiplied->level_, level - 1);
  EXPECT_EQ(multiplied->flag_, desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(multiplied->polynomial_count(), 3);
  EXPECT_EQ(decrypted->level_, level - 1);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::NONE);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * message[i], decoded[i], 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptDecodeUnitComplexTrio, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted =
      engine.decrypt_to_unit_plaintext(multiplied, secret_key_);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  EXPECT_EQ(multiplied->level_, max_level_ - 1);
  EXPECT_EQ(multiplied->flag_,
            desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(multiplied->polynomial_count(), 3);
  EXPECT_EQ(decrypted->level_, max_level_ - 1);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptDecryptDecodeUnitComplexLeveledTrio, {
  if (max_level_ <= 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);
  int level = max_level_;

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto multiplied = engine.multiply(unit_ciphertext, unit_ciphertext);
  const auto decrypted =
      engine.decrypt_to_unit_plaintext(multiplied, secret_key_);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  EXPECT_EQ(multiplied->level_, level - 1);
  EXPECT_EQ(multiplied->flag_,
            desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(multiplied->polynomial_count(), 3);
  EXPECT_EQ(decrypted->level_, level - 1);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete multiplied;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptUnitPlaintextWithSecretKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_plaintext = engine.encode_unit(message);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, secret_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  EXPECT_EQ(unit_plaintext->level_, max_level_);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, max_level_);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptUnitPlaintextWithSecretKeyLeveled, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto level = max_level_ - 1;
  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_plaintext = engine.encode_unit(message, level);
  const auto unit_ciphertext = engine.encrypt_unit(unit_plaintext, secret_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  EXPECT_EQ(unit_plaintext->level_, level);
  EXPECT_EQ(unit_plaintext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->level_, level);
  EXPECT_EQ(unit_ciphertext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, level);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_plaintext;
  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptUnitComplexVectorWithSecretKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_ciphertext = engine.encrypt_unit(message, secret_key_);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  EXPECT_EQ(unit_ciphertext->level_, max_level_);
  EXPECT_EQ(unit_ciphertext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, max_level_);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, EncryptUnitComplexVectorWithSecretKeyLeveled, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto level = max_level_ - 1;
  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  const auto unit_ciphertext = engine.encrypt_unit(message, secret_key_, level);
  const auto decrypted = DECRYPT_UNIT_TO_PLAINTEXT(unit_ciphertext);
  const auto decoded = engine.decode_complex_unit_plaintext(decrypted);

  EXPECT_EQ(unit_ciphertext->level_, level);
  EXPECT_EQ(unit_ciphertext->flag_, desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(unit_ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level_, level);
  EXPECT_EQ(decrypted->flag_, desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP0, CloneUnitPlaintext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_plaintext1 = engine.encode_unit(message);
  const auto unit_plaintext2 = engine.clone(unit_plaintext1);

  delete unit_plaintext1;

  EXPECT_EQ(unit_plaintext2->level_, max_level_);
  EXPECT_EQ(unit_plaintext2->flag_, desilo::fhe::DataFlag::COMPLEX);

  const auto unit_ciphertext =
      engine.encrypt_unit(unit_plaintext2, public_key_);
  const auto decrypted = DECRYPT_UNIT_COMPLEX(unit_ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_plaintext2;
  delete unit_ciphertext;
})

ALL_ENGINE_TEST(SP0, CloneUnitCiphertext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext1 = engine.encrypt_unit(message, public_key_);
  const auto unit_ciphertext2 = engine.clone(unit_ciphertext1);

  delete unit_ciphertext1;

  const auto decrypted = DECRYPT_UNIT_COMPLEX(unit_ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(unit_ciphertext2->level_, max_level_);
  EXPECT_EQ(unit_ciphertext2->flag_, flag);
  EXPECT_EQ(unit_ciphertext2->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext2;
})

ALL_ENGINE_TEST(SP0, ClonePlaintext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto plaintext1 = engine.encode(message);
  const auto plaintext2 = engine.clone(plaintext1);

  delete plaintext1;

  EXPECT_EQ(plaintext2->level(), max_level_);
  EXPECT_EQ(plaintext2->flag(), desilo::fhe::DataFlag::COMPLEX);

  const auto ciphertext = engine.encrypt(plaintext2, public_key_);
  const auto decrypted = DECRYPT_COMPLEX(ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete plaintext2;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP0, CloneCiphertext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto ciphertext1 = engine.encrypt(message, public_key_);
  const auto ciphertext2 = engine.clone(ciphertext1);

  delete ciphertext1;

  const auto decrypted = DECRYPT_COMPLEX(ciphertext2);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(ciphertext2->level(), max_level_);
  EXPECT_EQ(ciphertext2->flag(), flag);
  EXPECT_EQ(ciphertext2->polynomial_count(), 2);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext2;
})

ALL_ENGINE_TEST(SP0, NTTThenINTTUnitPlaintext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_plaintext = engine.encode_unit(message);
  const auto ntt_form = engine.ntt(unit_plaintext);
  const auto intt_form = engine.intt(ntt_form);

  EXPECT_EQ(ntt_form->level_, max_level_);
  EXPECT_EQ(ntt_form->flag_,
            desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(intt_form->level_, max_level_);
  EXPECT_EQ(intt_form->flag_, desilo::fhe::DataFlag::COMPLEX);

  const auto decoded = engine.decode_complex_unit_plaintext(intt_form);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete unit_plaintext;
  delete ntt_form;
  delete intt_form;
})

ALL_ENGINE_TEST(SP0, NTTThenINTTUnitCiphertext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  const auto ntt_form = engine.ntt(unit_ciphertext);
  const auto intt_form = engine.intt(ntt_form);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(ntt_form->level_, max_level_);
  EXPECT_EQ(ntt_form->flag_, flag | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(ntt_form->polynomial_count(), 2);
  EXPECT_EQ(intt_form->level_, max_level_);
  EXPECT_EQ(intt_form->flag_, flag);
  EXPECT_EQ(intt_form->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(intt_form);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete ntt_form;
  delete intt_form;
})

ALL_ENGINE_TEST(SP0, NTTThenINTTPlaintext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto plaintext = engine.encode(message);
  const auto ntt_form = engine.ntt(plaintext);
  const auto intt_form = engine.intt(ntt_form);

  EXPECT_EQ(ntt_form->level(), max_level_);
  EXPECT_EQ(ntt_form->flag(),
            desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(intt_form->level(), max_level_);
  EXPECT_EQ(intt_form->flag(), desilo::fhe::DataFlag::COMPLEX);

  const auto decoded = engine.decode_complex_plaintext(intt_form);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete ntt_form;
  delete intt_form;
})

ALL_ENGINE_TEST(SP0, NTTThenINTTCiphertext, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto ciphertext = engine.encrypt(message, public_key_);
  const auto ntt_form = engine.ntt(ciphertext);
  const auto intt_form = engine.intt(ntt_form);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(ntt_form->level(), max_level_);
  EXPECT_EQ(ntt_form->flag(), flag | desilo::fhe::DataFlag::NTT_FORM);
  EXPECT_EQ(ntt_form->polynomial_count(), 2);
  EXPECT_EQ(intt_form->level(), max_level_);
  EXPECT_EQ(intt_form->flag(), flag);
  EXPECT_EQ(intt_form->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(intt_form);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext;
  delete ntt_form;
  delete intt_form;
})

ALL_ENGINE_TEST(SP0, EncodeEmpty, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message;

  const auto plaintext = engine.encode(message);

  ASSERT_EQ(plaintext->size(), 1);

  const auto decoded = engine.decode(plaintext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(0, decoded[i], 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP0, EncodeEmptyComplex, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message;

  const auto plaintext = engine.encode(message);

  ASSERT_EQ(plaintext->size(), 1);

  const auto decoded = engine.decode_complex_plaintext(plaintext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(0, decoded[i].real(), 1e-4);
    ASSERT_NEAR(0, decoded[i].imag(), 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP0, EncryptEmptyCiphertextWithPublicKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message;

  const auto ciphertext = engine.encrypt(message, public_key_);

  ASSERT_EQ(ciphertext->size(), 1);

  const auto decrypted = DECRYPT(ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(0, decrypted[i], 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP0, EncryptEmptyComplexCiphertextWithPublicKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message;

  const auto ciphertext = engine.encrypt(message, public_key_);

  ASSERT_EQ(ciphertext->size(), 1);

  const auto decrypted = DECRYPT_COMPLEX(ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(0, decrypted[i].real(), 1e-4);
    ASSERT_NEAR(0, decrypted[i].imag(), 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP0, EncryptEmptyCiphertextWithSecretKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message;

  const auto ciphertext = engine.encrypt(message, secret_key_);

  ASSERT_EQ(ciphertext->size(), 1);

  const auto decrypted = DECRYPT(ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(0, decrypted[i], 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP0, EncryptEmptyComplexCiphertextWithSecretKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message;

  const auto ciphertext = engine.encrypt(message, secret_key_);

  ASSERT_EQ(ciphertext->size(), 1);

  const auto decrypted = DECRYPT_COMPLEX(ciphertext);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(0, decrypted[i].real(), 1e-4);
    ASSERT_NEAR(0, decrypted[i].imag(), 1e-4);
  }

  delete ciphertext;
})
