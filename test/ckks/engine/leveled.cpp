#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

class CKKSEngineLeveled
    : public testing::TestWithParam<std::tuple<
          std::tuple<int, int, int>, std::tuple<int, int>, int, int>> {};

INSTANTIATE_TEST_CASE_P(
    , CKKSEngineLeveled,
    testing::Combine(

        testing::Values(
            std::make_tuple(13, 2, 2), std::make_tuple(14, 3, 7),
            std::make_tuple(14, 4, 7), std::make_tuple(14, 5, 7),
            std::make_tuple(14, 6, 7), std::make_tuple(14, 7, 7),
            std::make_tuple(15, 8, 17), std::make_tuple(15, 9, 17),
            std::make_tuple(15, 10, 17), std::make_tuple(15, 11, 17),
            std::make_tuple(15, 12, 17), std::make_tuple(15, 13, 17),
            std::make_tuple(15, 14, 17), std::make_tuple(15, 15, 17),
            std::make_tuple(15, 16, 17), std::make_tuple(15, 17, 17),
            std::make_tuple(16, 18, 36), std::make_tuple(16, 32, 36),
            std::make_tuple(16, 33, 36), std::make_tuple(16, 34, 36),
            std::make_tuple(16, 35, 36), std::make_tuple(16, 36, 36),
            std::make_tuple(17, 37, 72), std::make_tuple(17, 72, 72)),

        testing::Values(std::make_tuple(0, 1), std::make_tuple(1, 1),
                        std::make_tuple(1, 2)),
        testing::Values(1, 2, 3), PROCESS_TEST),
    [](const testing::TestParamInfo<CKKSEngineLeveled::ParamType> &info) {
      const auto config_info = std::get<0>(info.param);
      const auto log_coeff_count = std::get<0>(config_info);
      const auto max_level = std::get<1>(config_info);
      const auto level_depths = std::get<1>(info.param);
      const auto key_level = max_level - std::get<0>(level_depths);
      const auto ciphertext_level = max_level - std::get<1>(level_depths);
      const auto message_type = std::get<2>(info.param);
      const auto process_type = std::get<3>(info.param);

      return print_tier(log_coeff_count) + "Max" + print_level(max_level) +
             "Key" + print_level(key_level) + "Ciphertext" +
             print_level(ciphertext_level) + print_message_type(message_type) +
             print_process_type(process_type);
    });

TEST_P(CKKSEngineLeveled, UseCustomSecretKey) {
  const auto [config_info, level_depths, message_type, process_type] =
      GetParam();
  const auto [key_level_depth, ciphertext_level_depth] = level_depths;
  const auto max_level = std::get<1>(config_info);
  const int key_level = max_level - key_level_depth;
  const int ciphertext_level = max_level - ciphertext_level_depth;

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  ASSERT_EQ(engine.get_max_level(), max_level);

  std::vector<int64_t> secret(engine.get_slot_count() * 2);
  for (int index = 0; index < secret.size(); index++) {
    secret[index] = (index % 3) - 1;
  }

  const auto secret_key = engine.create_secret_key(secret, max_level);
  const auto public_key = engine.create_public_key(secret_key, key_level);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto ciphertext = engine.encrypt(message, public_key, ciphertext_level);
  const auto decrypted = engine.decrypt(ciphertext, secret_key);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete ciphertext;
}

TEST_P(CKKSEngineLeveled, UsePaddedCustomSecretKey) {
  const auto [config_info, level_depths, message_type, process_type] =
      GetParam();
  const auto [key_level_depth, ciphertext_level_depth] = level_depths;
  const auto max_level = std::get<1>(config_info);
  const int key_level = max_level - key_level_depth;
  const int ciphertext_level = max_level - ciphertext_level_depth;

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  ASSERT_EQ(engine.get_max_level(), max_level);

  std::vector<int64_t> secret(engine.get_slot_count());
  for (int index = 0; index < secret.size(); index++) {
    secret[index] = (index % 3) - 1;
  }

  const auto secret_key = engine.create_secret_key(secret, max_level);
  const auto public_key = engine.create_public_key(secret_key, key_level);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto ciphertext = engine.encrypt(message, public_key, ciphertext_level);
  const auto decrypted = engine.decrypt(ciphertext, secret_key);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete ciphertext;
}

TEST_P(CKKSEngineLeveled, UsePublicKey) {
  const auto [config_info, level_depths, message_type, process_type] =
      GetParam();
  const auto [key_level_depth, ciphertext_level_depth] = level_depths;
  const auto max_level = std::get<1>(config_info);
  const int key_level = max_level - key_level_depth;
  const int ciphertext_level = max_level - ciphertext_level_depth;

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  ASSERT_EQ(engine.get_max_level(), max_level);

  const auto secret_key = engine.create_secret_key(max_level);
  const auto public_key = engine.create_public_key(secret_key, key_level);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto ciphertext = engine.encrypt(message, public_key, ciphertext_level);
  const auto decrypted = engine.decrypt(ciphertext, secret_key);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decrypted[i], 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete ciphertext;
}

TEST_P(CKKSEngineLeveled, UseRelinearizationKey) {
  const auto [config_info, level_depths, message_type, process_type] =
      GetParam();
  const auto [key_level_depth, ciphertext_level_depth] = level_depths;
  const auto max_level = std::get<1>(config_info);
  const auto tier_max_level = std::get<2>(config_info);
  const int key_level = max_level - key_level_depth;
  const int ciphertext_level = max_level - ciphertext_level_depth + 1;

  if (ciphertext_level < 1 || key_level == tier_max_level) {
    GTEST_SKIP() << "Impossible Target Level";
  }

  if (ciphertext_level == 1 && message_type == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  ASSERT_EQ(engine.get_max_level(), max_level);

  const auto secret_key = engine.create_secret_key(max_level);
  const auto public_key = engine.create_public_key(secret_key, max_level);
  const auto relinearization_key =
      engine.create_relinearization_key(secret_key, key_level);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto ciphertext = engine.encrypt(message, public_key, ciphertext_level);
  const auto multiplied =
      engine.multiply(ciphertext, ciphertext, relinearization_key);
  const auto decrypted = engine.decrypt(multiplied, secret_key);

  auto threshold = 1e-4;
  if (message_type == 3) {
    threshold = 1e-2;

    if (config.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i] * message[i], decrypted[i], threshold);
  }

  delete secret_key;
  delete public_key;
  delete relinearization_key;
  delete ciphertext;
  delete multiplied;
}

TEST_P(CKKSEngineLeveled, UseFixedRotationKey) {
  const auto [config_info, level_depths, message_type, process_type] =
      GetParam();
  const auto [key_level_depth, ciphertext_level_depth] = level_depths;
  const auto max_level = std::get<1>(config_info);
  const auto tier_max_level = std::get<2>(config_info);
  const int key_level = max_level - key_level_depth;
  const int ciphertext_level = max_level - ciphertext_level_depth;

  if (key_level == tier_max_level) {
    GTEST_SKIP() << "Impossible Target Level";
  }

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  ASSERT_EQ(engine.get_max_level(), max_level);

  const auto secret_key = engine.create_secret_key(max_level);
  const auto public_key = engine.create_public_key(secret_key, max_level);
  const auto delta = 10;
  const auto fixed_rotation_key =
      engine.create_fixed_rotation_key(secret_key, delta, key_level);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto ciphertext = engine.encrypt(message, public_key, ciphertext_level);
  const auto rotated = engine.rotate(ciphertext, fixed_rotation_key);
  const auto decrypted = engine.decrypt(rotated, secret_key);

  for (int i = 0; i < delta; i++) {
    ASSERT_NEAR(message[slot_count - delta + i], decrypted[i], 1e-4);
  }

  for (int i = 0; i < slot_count - delta; i++) {
    ASSERT_NEAR(message[i], decrypted[i + delta], 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete fixed_rotation_key;
  delete ciphertext;
  delete rotated;
}

TEST_P(CKKSEngineLeveled, UseConjugationKey) {
  const auto [config_info, level_depths, message_type, process_type] =
      GetParam();
  const auto [key_level_depth, ciphertext_level_depth] = level_depths;
  const auto max_level = std::get<1>(config_info);
  const auto tier_max_level = std::get<2>(config_info);
  const int key_level = max_level - key_level_depth;
  const int ciphertext_level = max_level - ciphertext_level_depth;

  if (key_level == tier_max_level) {
    GTEST_SKIP() << "Impossible Target Level";
  }

  const auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  ASSERT_EQ(engine.get_max_level(), max_level);

  const auto secret_key = engine.create_secret_key(max_level);
  const auto public_key = engine.create_public_key(secret_key, max_level);
  const auto conjugation_key =
      engine.create_conjugation_key(secret_key, key_level);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto ciphertext = engine.encrypt(message, public_key, ciphertext_level);
  const auto conjugated = engine.conjugate(ciphertext, conjugation_key);
  const auto decrypted = engine.decrypt_complex(conjugated, secret_key);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(-message[i].imag(), decrypted[i].imag(), 1e-4);
  }

  delete secret_key;
  delete public_key;
  delete conjugation_key;
  delete ciphertext;
  delete conjugated;
}
