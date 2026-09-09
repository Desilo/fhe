#include "ckks/core/macro.h"
#include "ckks/engine.h"
#include "common/common.h"

SETUP_TIER_TEST_SP4(
    SP4A, LEVELS_0_TO_MAX,
    [](const std::tuple<int, int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_message_type(std::get<2>(param)) +
             print_input_order(std::get<3>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3), testing::Values(1, 2));

TIER_TEST(SP4A, SubtractPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const int input_order = std::get<3>(GetParam());
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
  desilo::fhe::UnitCiphertext *subtracted;
  if (input_order == 1) {
    subtracted = core.subtract(ciphertext1, plaintext2);
  } else {
    subtracted = core.subtract(plaintext2, ciphertext1);
  }
  const auto decrypted = DECRYPT_DUO(subtracted);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = (input_order == 1) ? (message1[i] - message2[i])
                                             : (message2[i] - message1[i]);
    ASSERT_NEAR(expected, decoded[i], 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, subtracted->ckks_scale_, 1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete plaintext2;
  delete subtracted;
  delete decrypted;
})

TIER_TEST(SP4A, NTTCiphertextSubtractPlaintext, {
  const int level = std::get<0>(GetParam());
  const int message_type_1 = std::get<1>(GetParam());
  const int message_type_2 = std::get<2>(GetParam());
  const int input_order = std::get<3>(GetParam());
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
  desilo::fhe::UnitCiphertext *subtracted;
  if (input_order == 1) {
    subtracted = core.subtract(ciphertext1_ntt, plaintext2);
  } else {
    subtracted = core.subtract(plaintext2, ciphertext1_ntt);
  }
  const auto subtracted_intt = core.to_intt_form(subtracted);
  const auto decrypted = DECRYPT_DUO(subtracted_intt);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = (input_order == 1) ? (message1[i] - message2[i])
                                             : (message2[i] - message1[i]);
    ASSERT_NEAR(expected, decoded[i], 1e-4);
  }

  EXPECT_NEAR(ciphertext1->ckks_scale_, subtracted->ckks_scale_, 1e-12);

  delete plaintext1;
  delete ciphertext1;
  delete ciphertext1_ntt;
  delete plaintext2;
  delete subtracted;
  delete subtracted_intt;
  delete decrypted;
})
