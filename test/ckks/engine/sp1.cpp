#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP1(
    SP1,
    [](const std::tuple<int> &param) {
      return print_slice_count(std::get<0>(param));
    },
    testing::Values(1, 2, 3));

ALL_ENGINE_TEST(SP1, EncryptDecrypt, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto ciphertext = engine.encrypt(message, public_key_);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT(ciphertext);

  ASSERT_EQ(decrypted.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT(ciphertext);

  ASSERT_EQ(decrypted.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptComplex, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto ciphertext = engine.encrypt(message, public_key_);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT_COMPLEX(ciphertext);

  ASSERT_EQ(decrypted.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptComplexLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto ciphertext = engine.encrypt(message, public_key_, level);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT_COMPLEX(ciphertext);

  ASSERT_EQ(decrypted.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptBuffer, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new double[message_size];
  initiate_message(message, message_size, 3);

  const auto ciphertext = engine.encrypt(message, public_key_, message_size);

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::NONE);

  double *decrypted = new double[message_size];
  engine.decrypt_to_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptBufferLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new double[message_size];
  initiate_message(message, message_size, 3);
  int level = max_level_ - 1;

  const auto ciphertext =
      engine.encrypt(message, public_key_, message_size, level);

  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::NONE);

  double *decrypted = new double[message_size];
  engine.decrypt_to_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptComplexBuffer, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new std::complex<double>[message_size];
  initiate_message(message, message_size, 3);

  const auto ciphertext = engine.encrypt(message, public_key_, message_size);

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);

  std::complex<double> *decrypted = new std::complex<double>[message_size];
  engine.decrypt_to_complex_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptComplexBufferLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new std::complex<double>[message_size];
  initiate_message(message, message_size, 3);
  int level = max_level_ - 1;

  const auto ciphertext =
      engine.encrypt(message, public_key_, message_size, level);

  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);

  std::complex<double> *decrypted = new std::complex<double>[message_size];
  engine.decrypt_to_complex_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptBufferWithSecretKey, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new double[message_size];
  initiate_message(message, message_size, 3);

  const auto ciphertext = engine.encrypt(message, secret_key_, message_size);

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::NONE);

  double *decrypted = new double[message_size];
  engine.decrypt_to_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptBufferWithSecretKeyLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new double[message_size];
  initiate_message(message, message_size, 3);
  int level = max_level_ - 1;

  const auto ciphertext =
      engine.encrypt(message, secret_key_, message_size, level);

  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::NONE);

  auto decrypted = new double[message_size];
  engine.decrypt_to_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptComplexBufferWithSecretKey, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new std::complex<double>[message_size];
  initiate_message(message, message_size, 3);

  const auto ciphertext = engine.encrypt(message, secret_key_, message_size);

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);

  std::complex<double> *decrypted = new std::complex<double>[message_size];
  engine.decrypt_to_complex_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptComplexBufferWithSecretKeyLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new std::complex<double>[message_size];
  initiate_message(message, message_size, 3);
  int level = max_level_ - 1;

  const auto ciphertext =
      engine.encrypt(message, secret_key_, message_size, level);

  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);

  std::complex<double> *decrypted = new std::complex<double>[message_size];
  engine.decrypt_to_complex_buffer(ciphertext, decrypted, secret_key_);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete[] message;
  delete[] decrypted;
  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncryptDecryptPadded, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_count = slot_count * slice_count - 1;
  std::vector<double> message(message_count);
  initiate_message(message, 3);

  const auto ciphertext = engine.encrypt(message, public_key_);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT(ciphertext);

  ASSERT_EQ(decrypted.size(), slot_count * slice_count);

  for (int i = 0; i < message_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete ciphertext;
})

ALL_ENGINE_TEST(SP1, EncodeEncryptDecryptDecode, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);
  const auto ciphertext = engine.encrypt(plaintext, public_key_);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);
  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode(decrypted);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncryptPlaintextWithSecretKey, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);
  const auto ciphertext = engine.encrypt(plaintext, secret_key_);
  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode_complex_plaintext(decrypted);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->flag(), desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level(), max_level_);
  EXPECT_EQ(decrypted->flag(), desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncryptPlaintextWithSecretKeyLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto level = max_level_;
  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message, level);
  const auto ciphertext = engine.encrypt(plaintext, secret_key_);
  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode_complex_plaintext(decrypted);

  EXPECT_EQ(plaintext->level(), level);
  EXPECT_EQ(plaintext->flag(), desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level(), level);
  EXPECT_EQ(decrypted->flag(), desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncryptComplexVectorWithSecretKey, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto ciphertext = engine.encrypt(message, secret_key_);
  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode_complex_plaintext(decrypted);

  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level(), max_level_);
  EXPECT_EQ(decrypted->flag(), desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncryptComplexVectorWithSecretKeyLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto level = max_level_ - 1;
  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto ciphertext = engine.encrypt(message, secret_key_, level);
  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode_complex_plaintext(decrypted);

  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->flag(), desilo::fhe::DataFlag::COMPLEX);
  EXPECT_EQ(ciphertext->polynomial_count(), 2);
  EXPECT_EQ(decrypted->level(), level);
  EXPECT_EQ(decrypted->flag(), desilo::fhe::DataFlag::COMPLEX);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncodeEncryptDecryptDecodeLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto plaintext = engine.encode(message, level);
  const auto ciphertext = engine.encrypt(plaintext, public_key_);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext->level(), level);
  EXPECT_EQ(plaintext->size(), slice_count);
  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode(decrypted);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncodeEncryptDecryptDecodeComplex, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);
  const auto ciphertext = engine.encrypt(plaintext, public_key_);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);
  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode_complex_plaintext(decrypted);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncodeEncryptDecryptDecodeComplexLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto plaintext = engine.encode(message, level);
  const auto ciphertext = engine.encrypt(plaintext, public_key_);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(plaintext->level(), level);
  EXPECT_EQ(plaintext->size(), slice_count);
  EXPECT_EQ(ciphertext->level(), level);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode_complex_plaintext(decrypted);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncodeEncryptDecryptDecodePadded, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_count = slot_count * slice_count - 1;
  std::vector<double> message(message_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);
  const auto ciphertext = engine.encrypt(plaintext, public_key_);

  const auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);
  EXPECT_EQ(ciphertext->level(), max_level_);
  EXPECT_EQ(ciphertext->size(), slice_count);
  EXPECT_EQ(ciphertext->flag(), flag);

  const auto decrypted = DECRYPT_TO_PLAINTEXT(ciphertext);
  const auto decoded = engine.decode(decrypted);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < message_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete ciphertext;
  delete decrypted;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeBuffer, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new double[message_size];
  initiate_message(message, message_size, 3);

  const auto plaintext = engine.encode(message, message_size);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  auto decoded = new double[message_size];
  engine.decode_to_buffer(plaintext, decoded);

  for (int i = 0; i < message_size; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeVector, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  const auto decoded = engine.decode(plaintext);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeBufferLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new double[message_size];
  initiate_message(message, message_size, 3);
  int level = max_level_ - 1;

  const auto plaintext = engine.encode(message, message_size, level);

  EXPECT_EQ(plaintext->level(), level);
  EXPECT_EQ(plaintext->size(), slice_count);

  double *decoded = new double[message_size];
  engine.decode_to_buffer(plaintext, decoded);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeVectorLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto plaintext = engine.encode(message, level);

  EXPECT_EQ(plaintext->level(), level);
  EXPECT_EQ(plaintext->size(), slice_count);

  const auto decoded = engine.decode(plaintext);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeComplexBuffer, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new std::complex<double>[message_size];
  initiate_message(message, message_size, 3);

  const auto plaintext = engine.encode(message, message_size);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  auto decoded = new std::complex<double>[message_size];
  engine.decode_complex_plaintext_to_buffer(plaintext, decoded);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeComplexVector, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  const auto decoded = engine.decode_complex_plaintext(plaintext);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeComplexBufferLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_size = slot_count * slice_count;
  auto message = new std::complex<double>[message_size];
  int level = max_level_ - 1;

  const auto plaintext = engine.encode(message, message_size, level);

  EXPECT_EQ(plaintext->level(), level);
  EXPECT_EQ(plaintext->size(), slice_count);

  auto decoded = new std::complex<double>[message_size];
  engine.decode_complex_plaintext_to_buffer(plaintext, decoded);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeComplexVectorLeveled, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_message(message, 3);
  int level = max_level_ - 1;

  const auto plaintext = engine.encode(message, level);

  EXPECT_EQ(plaintext->level(), level);
  EXPECT_EQ(plaintext->size(), slice_count);

  const auto decoded = engine.decode_complex_plaintext(plaintext);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < slot_count * slice_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP1, EncodeDecodePaddedBuffer, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_count = slot_count * slice_count - 1;
  auto message = new double[message_count];
  initiate_message(message, message_count, 3);

  const auto plaintext = engine.encode(message, message_count);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  auto decoded = new double[slot_count * slice_count];
  engine.decode_to_buffer(plaintext, decoded);

  for (int i = 0; i < message_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

ALL_ENGINE_TEST(SP1, EncodeDecodePaddedVector, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_count = slot_count * slice_count - 1;
  std::vector<double> message(message_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  const auto decoded = engine.decode(plaintext);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < message_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeVectorPaddedComplexBuffer, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_count = slot_count * slice_count - 1;
  auto message = new std::complex<double>[message_count];
  initiate_message(message, message_count, 3);

  const auto plaintext = engine.encode(message, message_count);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  auto decoded = new std::complex<double>[slot_count * slice_count];
  engine.decode_complex_plaintext_to_buffer(plaintext, decoded);

  for (int i = 0; i < message_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
  delete[] message;
  delete[] decoded;
})

ALL_ENGINE_TEST(SP1, EncodeDecodeVectorPaddedComplexVector, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_count = slot_count * slice_count - 1;
  std::vector<std::complex<double>> message(message_count);
  initiate_message(message, 3);

  const auto plaintext = engine.encode(message);

  EXPECT_EQ(plaintext->level(), max_level_);
  EXPECT_EQ(plaintext->size(), slice_count);

  const auto decoded = engine.decode_complex_plaintext(plaintext);

  ASSERT_EQ(decoded.size(), slot_count * slice_count);

  for (int i = 0; i < message_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete plaintext;
})

ALL_ENGINE_TEST(SP1, Sum1DByColumn, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_);
  const auto summed = engine.sum_1d_by_column(ciphertext);
  const auto decrypted = DECRYPT(summed);

  auto level = ciphertext->level();
  auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(summed->size(), 1);
  EXPECT_EQ(summed->level(), level);
  EXPECT_EQ(summed->flag(), flag);
  EXPECT_EQ(summed->polynomial_count(), 2);

  std::vector<double> expected(slot_count);
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    expected[slot_index] = 0.0;
    for (int slice_index = 0; slice_index < slice_count; slice_index++) {
      expected[slot_index] += message[slice_index * slot_count + slot_index];
    }
  }

  auto threshold = 1e-4;
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    ASSERT_NEAR(decrypted[slot_index], expected[slot_index], threshold);
  }

  delete ciphertext;
  delete summed;
})

SETUP_ENGINE_TEST_SP1(
    WeightedSumSP1,
    [](const std::tuple<int> &param) {
      return print_polynomial(std::get<0>(param));
    },

    testing::Values(0, 1, 2, 3, 4, 5));

std::vector<std::vector<int64_t>> int_weights{{1, 2, 3, 4, 5, 6, 7, 8, 9},
                                              {9, 8, 7, 6, 5, 4, 3, 2, 1},
                                              {-1, 1, -2, 2, -3, 3, -4, 4, -5},
                                              {1, 2, 3},
                                              {9, 8, 7},
                                              {-1, 1, -2}};

const std::complex<double> expected_int_value[6]{
    std::complex<double>(43909, -12452), std::complex<double>(5241, -3928),
    std::complex<double>(-16607, -2414), std::complex<double>(5, 28),
    std::complex<double>(25, 72),        std::complex<double>(1, -14)};

ALL_ENGINE_TEST(WeightedSumSP1, IntegerWeights, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto polynomial_type = std::get<0>(GetParam());
  std::vector<int64_t> polynomial = int_weights[polynomial_type];

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts;

  for (int index = 1; index < polynomial.size(); index++) {
    const auto power_of_two = std::pow(std::complex<double>(2.0, 2.0), index);
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      message[slot_index] = power_of_two;
    }
    auto unit_ciphertext = engine.encrypt_unit(message, public_key_);

    unit_ciphertexts.push_back(unit_ciphertext);
  }

  auto weighted_sum = engine.weighted_sum(unit_ciphertexts, polynomial);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(weighted_sum->level_, max_level_);
  EXPECT_EQ(weighted_sum->flag_, flag);
  EXPECT_EQ(weighted_sum->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(weighted_sum);

  const auto expected = expected_int_value[polynomial_type];
  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete weighted_sum;

  for (auto &unit_ciphertext : unit_ciphertexts) {
    delete unit_ciphertext;
  }
})

std::vector<std::vector<double>> double_weights{
    {1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5},
    {9.5, 8.5, 7.5, 6.5, 5.5, 4.5, 3.5, 2.5, 1.5},
    {-1.5, 1.5, -2.5, 2.5, -3.5, 3.5, -4.5, 4.5, -5.5},
    {1.5, 2.5, 3.5},
    {9.5, 8.5, 7.5},
    {-1.5, 1.5, -2.5}};

const std::complex<double> expected_double_value[6]{
    std::complex<double>(46366.5, -13271), std::complex<double>(7698.5, -4747),
    std::complex<double>(-18182.5, -2729), std::complex<double>(6.5, 33),
    std::complex<double>(26.5, 77),        std::complex<double>(1.5, -17)};

ALL_ENGINE_TEST(WeightedSumSP1, DoubleWeights, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto polynomial_type = std::get<0>(GetParam());
  std::vector<double> polynomial = double_weights[polynomial_type];

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts;

  for (int index = 1; index < polynomial.size(); index++) {
    const auto power_of_two = std::pow(std::complex<double>(2.0, 2.0), index);
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      message[slot_index] = power_of_two;
    }
    auto unit_ciphertext = engine.encrypt_unit(message, public_key_);

    unit_ciphertexts.push_back(unit_ciphertext);
  }

  auto weighted_sum = engine.weighted_sum(unit_ciphertexts, polynomial);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(weighted_sum->level_, max_level_ - 1);
  EXPECT_EQ(weighted_sum->flag_, flag);
  EXPECT_EQ(weighted_sum->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(weighted_sum);

  const auto expected = expected_double_value[polynomial_type];
  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete weighted_sum;

  for (auto &unit_ciphertext : unit_ciphertexts) {
    delete unit_ciphertext;
  }
})
