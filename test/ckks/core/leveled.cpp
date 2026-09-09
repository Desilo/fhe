#include "ckks/config.h"
#include "ckks/core.h"
#include "common/common.h"
#include "common/test.h"

class CKKSCoreLeveled
    : public testing::TestWithParam<std::tuple<int, int, int, int>> {
public:
  static std::string
  test_name(const testing::TestParamInfo<CKKSCoreLeveled::ParamType> &info) {
    const auto max_level = std::get<0>(info.param);
    const auto ciphertext_level = max_level - std::get<2>(info.param);
    const auto message_type = std::get<3>(info.param);

    return "Max" + print_level(max_level) + "Ciphertext" +
           print_level(ciphertext_level) + print_message_type(message_type);
  }
};

INSTANTIATE_TEST_CASE_P(Iron, CKKSCoreLeveled,
                        testing::Combine(testing::Values(2), testing::Values(2),
                                         testing::Values(0, 1),
                                         testing::Values(1, 2, 3)),
                        CKKSCoreLeveled::test_name);

INSTANTIATE_TEST_CASE_P(Bronze, CKKSCoreLeveled,
                        testing::Combine(testing::Values(3, 4, 5, 6, 7),
                                         testing::Values(7),
                                         testing::Values(0, 1),
                                         testing::Values(1, 2, 3)),
                        CKKSCoreLeveled::test_name);

INSTANTIATE_TEST_CASE_P(
    Silver, CKKSCoreLeveled,
    testing::Combine(testing::Values(8, 9, 10, 11, 12, 13, 14, 15, 16, 17),
                     testing::Values(17), testing::Values(0, 1),
                     testing::Values(1, 2, 3)),
    CKKSCoreLeveled::test_name);

INSTANTIATE_TEST_CASE_P(
    Gold, CKKSCoreLeveled,
    testing::Combine(testing::Values(18, 32, 33, 34, 35, 36),
                     testing::Values(36), testing::Values(0, 1),
                     testing::Values(1, 2, 3)),
    CKKSCoreLeveled::test_name);

INSTANTIATE_TEST_CASE_P(Platinum, CKKSCoreLeveled,
                        testing::Combine(testing::Values(37, 72),
                                         testing::Values(72),
                                         testing::Values(0, 1),
                                         testing::Values(1, 2, 3)),
                        CKKSCoreLeveled::test_name);

TEST_P(CKKSCoreLeveled, UsePublicKeySecretKey) {
  const auto [max_level, tier_max_level, used_level, message_type] = GetParam();

  const bool include_special = false;
  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  ASSERT_EQ(core.parameters_.get_max_level(), config.max_level_);

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const int encode_level = max_level - used_level;
  const auto plaintext = core.encode(message, encode_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto decrypted = core.decrypt_duo(ciphertext, secret_key);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete plaintext;
  delete ciphertext;
  delete decrypted;
}

TEST_P(CKKSCoreLeveled, UseCustomSecretKey) {
  const auto [max_level, tier_max_level, used_level, message_type] = GetParam();

  const bool include_special = false;
  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  ASSERT_EQ(core.parameters_.get_max_level(), config.max_level_);

  std::vector<int64_t> secret(core.get_slot_count() * 2);
  for (int index = 0; index < secret.size(); index++) {
    secret[index] = (index % 3) - 1;
  }

  const auto secret_key = core.create_secret_key(secret, max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const int encode_level = max_level - used_level;
  const auto plaintext = core.encode(message, encode_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto decrypted = core.decrypt_duo(ciphertext, secret_key);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete plaintext;
  delete ciphertext;
  delete decrypted;
}

TEST_P(CKKSCoreLeveled, UseRelinearizationKey) {
  const auto [max_level, tier_max_level, used_level, message_type] = GetParam();

  if (tier_max_level == 2 && message_type == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  const bool include_special = false;
  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  ASSERT_EQ(core.parameters_.get_max_level(), config.max_level_);

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);
  const auto relinearization_key =
      core.create_relinearization_key(secret_key, max_level);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const int encode_level = max_level - used_level;
  const auto plaintext = core.encode(message, encode_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto rescaled = core.rescale(ciphertext);
  const auto ntt_form = core.to_ntt_form(rescaled);
  const auto multiplied = core.square(ntt_form);
  const auto relinearized = core.relinearize(multiplied, relinearization_key);
  const auto decrypted = core.decrypt_duo(relinearized, secret_key);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto threshold = 1e-4;
  if (message_type == 3) {
    threshold = 1e-2;

    if (tier_max_level == 72) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), threshold);
  }

  delete secret_key;
  delete public_key;
  delete relinearization_key;
  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete ntt_form;
  delete multiplied;
  delete relinearized;
  delete decrypted;
}

TEST_P(CKKSCoreLeveled, UseFixedRotationKey) {
  const auto [max_level, tier_max_level, used_level, message_type] = GetParam();

  if (tier_max_level == 13 && message_type == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  const int encode_level = max_level - used_level;
  if (encode_level == tier_max_level) {
    GTEST_SKIP()
        << "Cannot rotate when the unit ciphertext level is the same as "
           "the tier's max level.";
  }
  const bool include_special = false;

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  ASSERT_EQ(core.parameters_.get_max_level(), config.max_level_);

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);
  const auto delta = 10;
  const auto fixed_rotation_key =
      core.create_fixed_rotation_key(secret_key, max_level, delta);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, encode_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto rotated = core.rotate(ciphertext, fixed_rotation_key);
  const auto decrypted = core.decrypt_duo(rotated, secret_key);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < delta; i++) {
    ASSERT_NEAR(message[slot_count - delta + i].real(), decoded[i].real(),
                1e-4);
    ASSERT_NEAR(message[slot_count - delta + i].imag(), decoded[i].imag(),
                1e-4);
  }

  for (int i = 0; i < slot_count - delta; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i + delta].real(), 1e-4);
    ASSERT_NEAR(message[i].imag(), decoded[i + delta].imag(), 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete fixed_rotation_key;
  delete plaintext;
  delete ciphertext;
  delete rotated;
  delete decrypted;
}

TEST_P(CKKSCoreLeveled, UseConjugationKey) {
  const auto [max_level, tier_max_level, used_level, message_type] = GetParam();

  if (tier_max_level == 2 && message_type == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  const int encode_level = max_level - used_level;
  if (encode_level == tier_max_level) {
    GTEST_SKIP()
        << "Cannot conjugate when the unit ciphertext level is the same as "
           "the tier's max level.";
  }
  const bool include_special = false;

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  ASSERT_EQ(core.parameters_.get_max_level(), config.max_level_);

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);
  const auto conjugation_key =
      core.create_conjugation_key(secret_key, max_level);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, encode_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto conjugated = core.conjugate(ciphertext, conjugation_key);
  const auto decrypted = core.decrypt_duo(conjugated, secret_key);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(-message[i].imag(), decoded[i].imag(), 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete conjugation_key;
  delete plaintext;
  delete ciphertext;
  delete conjugated;
  delete decrypted;
}
