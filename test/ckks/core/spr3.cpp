#include "ckks/core/macro.h"
#include "ckks/engine.h"
#include "common/common.h"

SETUP_TIER_TEST_SPR3(
    SPR3, LEVELS_1_TO_MAX,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "And" +
             print_message_type(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, 3));

TIER_TEST(SPR3, Relinearize, {
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
  const auto relinearized = core.relinearize(multiplied, relinearization_key_);
  const auto decrypted = DECRYPT_DUO(relinearized);
  const auto decoded = core.decode(decrypted);

  auto threshold = 1e-4;
  if (message_type_1 == 3 && message_type_2 == 3) {
    threshold = 1e-0;
  } else if (message_type_1 == 3 || message_type_2 == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message1[i] * message2[i], decoded[i], threshold);
  }

  EXPECT_NEAR(multiplied->ckks_scale_, relinearized->ckks_scale_, 1e-12);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
  delete relinearized;
  delete decrypted;
})
