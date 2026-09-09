#include <filesystem>
#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "common/common.h"
#include "common/test.h"
#include "data/bytearray.h"

class BootstrapKey3StagesMedium
    : public testing::TestWithParam<std::tuple<int, int, int>> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::for_bootstrap();
    auto engine = desilo::fhe::CKKSEngine(config);

    secret_key_ = engine.create_secret_key();
    public_key_ = engine.create_public_key(secret_key_);

    int stage_count = 3;
    bootstrap_key_ =
        engine.create_bootstrap_key(secret_key_, stage_count, "medium");
  }

  static void TearDownTestSuite() {
    delete secret_key_;
    delete public_key_;
    delete bootstrap_key_;
  }

  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::PublicKey *public_key_;
  static desilo::fhe::BootstrapKey *bootstrap_key_;
};

desilo::fhe::SecretKey *BootstrapKey3StagesMedium::secret_key_ = nullptr;
desilo::fhe::PublicKey *BootstrapKey3StagesMedium::public_key_ = nullptr;
desilo::fhe::BootstrapKey *BootstrapKey3StagesMedium::bootstrap_key_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    Gold, BootstrapKey3StagesMedium,
    testing::Combine(testing::Values(1, 2), testing::Values(0, 1, 2, 4),
                     PROCESS_TEST),
    [](const testing::TestParamInfo<BootstrapKey3StagesMedium::ParamType>
           &info) {
      return print_slice_count(std::get<0>(info.param)) +
             print_delta(std::get<1>(info.param)) +
             print_process_type(std::get<2>(info.param));
    });

TEST_P(BootstrapKey3StagesMedium, RotateUnitCiphertext) {
  const auto [slice_count, delta, process_type] = GetParam();

  if (slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 3);

  auto level = 1;

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  const auto rotated = engine.rotate(unit_ciphertext, bootstrap_key_, delta);
  const auto decrypted = engine.decrypt(rotated, secret_key_);

  EXPECT_EQ(rotated->level_, level);
  EXPECT_EQ(rotated->flag_, desilo::fhe::DataFlag::NONE);
  EXPECT_EQ(rotated->polynomial_count(), 2);

  for (int slot_index = 0; slot_index < delta; slot_index++) {
    const auto expected = message[slot_count - delta + slot_index];
    ASSERT_NEAR(expected, decrypted[slot_index], 1e-4);
  }

  for (int slot_index = delta; slot_index < slot_count; slot_index++) {
    const auto expected = message[slot_index - delta];
    ASSERT_NEAR(expected, decrypted[slot_index], 1e-4);
  }

  delete unit_ciphertext;
  delete rotated;
}

TEST_P(BootstrapKey3StagesMedium, RotateCiphertext) {
  const auto [slice_count, delta, process_type] = GetParam();
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  auto engine =
      desilo::fhe::CKKSEngine(update_process_type(config, process_type));

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count, 1000);

  auto level = 1;

  const auto unit_ciphertext = engine.encrypt(message, public_key_, level);
  const auto rotated = engine.rotate(unit_ciphertext, bootstrap_key_, delta);
  const auto decrypted = engine.decrypt(rotated, secret_key_);

  EXPECT_EQ(rotated->level(), level);
  EXPECT_EQ(rotated->flag(), desilo::fhe::DataFlag::NONE);
  EXPECT_EQ(rotated->polynomial_count(), 2);

  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    auto offset = slice_index * slot_count;
    for (int slot_index = 0; slot_index < delta; slot_index++) {
      const auto expected = message[slot_count - delta + slot_index + offset];
      ASSERT_NEAR(expected, decrypted[slot_index + offset], 1e-4);
    }

    for (int slot_index = delta; slot_index < slot_count; slot_index++) {
      const auto expected = message[slot_index - delta + offset];
      ASSERT_NEAR(expected, decrypted[slot_index + offset], 1e-4);
    }
  }

  delete unit_ciphertext;
  delete rotated;
}
