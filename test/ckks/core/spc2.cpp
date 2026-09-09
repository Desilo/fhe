#include "ckks/core/macro.h"
#include "ckks/engine.h"
#include "common/common.h"

SETUP_TIER_TEST_SPC2(
    SPC2, LEVELS_0_TO_MAX_MINUS_1,
    [](const std::tuple<int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param));
    },
    testing::Values(1, 2, 3));

TIER_TEST(SPC2, ConjugateReal, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto conjugated = core.conjugate(ciphertext, conjugation_key_);
  const auto decrypted = DECRYPT_DUO(conjugated);
  const auto decoded = core.decode(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i], decoded[i], 1e-4);
  }

  EXPECT_NEAR(conjugated->ckks_scale_, ciphertext->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete conjugated;
  delete decrypted;
})

TIER_TEST(SPC2, ConjugateComplex, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto conjugated = core.conjugate(ciphertext, conjugation_key_);
  const auto decrypted = DECRYPT_DUO(conjugated);
  const auto decoded = core.decode_complex_plaintext(decrypted);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(message[i].real(), decoded[i].real(), 1e-4);
    ASSERT_NEAR(-message[i].imag(), decoded[i].imag(), 1e-4);
  }

  EXPECT_NEAR(conjugated->ckks_scale_, ciphertext->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete conjugated;
  delete decrypted;
})
