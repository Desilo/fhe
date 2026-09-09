#include "ckks/core/macro.h"
#include "common/common.h"

SETUP_TIER_TEST_SPE2(
    SPE2, LEVELS_1_TO_MAX,
    [](const std::tuple<int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param));
    },
    testing::Values(1, 2, 3));

TIER_TEST(SPE2, SquareNTTForm, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  if (level == 1 && message_type == 3) {
    GTEST_SKIP() << "Cannot decrypt big number with single chain.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto rescaled_ntt = core.to_ntt_form(rescaled);
  const auto squared = core.square(rescaled_ntt);
  const auto decrypted = DECRYPT_TRIO(squared);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  auto threshold = 1e-4;
  if (message_type == 3) {
    threshold = 1e-2;

    if (config_.log_coeff_count_ == 17) {
      threshold = 1e-1;
    }
  }

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decoded[i].real(), threshold);
    ASSERT_NEAR(expected.imag(), decoded[i].imag(), threshold);
  }

  EXPECT_NEAR(squared->ckks_scale_,
              rescaled->ckks_scale_ * rescaled->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete rescaled_ntt;
  delete squared;
  delete decrypted;
})
