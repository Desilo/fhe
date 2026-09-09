#include "arithmetic/arithmetic.h"
#include "ckks/core/macro.h"
#include "ckks/engine.h"
#include "common/common.h"

SETUP_TIER_TEST_SPF3(
    SPF3, LEVELS_0_TO_MAX_MINUS_1,
    [](const std::tuple<int, int, int> &param) {
      return print_level(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) +
             print_delta(std::get<2>(param));
    },
    testing::Values(1, 2, 3), testing::Values(1, 2, -4));

TIER_TEST(SPF3, RotateCiphertext, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int delta = std::get<2>(GetParam());
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rotated = core.rotate(ciphertext, fixed_rotation_keys_[delta]);
  const auto decrypted = DECRYPT_DUO(rotated);
  const auto decoded = core.decode(decrypted);

  if (delta > 0) {
    for (int i = 0; i < delta; i++) {
      ASSERT_NEAR(message[slot_count - delta + i], decoded[i], 1e-4);
    }

    for (int i = 0; i < slot_count - delta; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  } else {
    for (int i = 0; i < -delta; i++) {
      ASSERT_NEAR(message[i], decoded[slot_count + delta + i], 1e-4);
    }

    for (int i = -delta; i < slot_count; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  }

  EXPECT_NEAR(rotated->ckks_scale_, ciphertext->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete rotated;
  delete decrypted;
})

TIER_TEST(SPF3, RotateCiphertextWithDecomposed, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int delta = std::get<2>(GetParam());
  const auto fixed_rotation_key = fixed_rotation_keys_[delta];
  const bool include_special = false;

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto decomposed = core.decompose(ciphertext);
  const auto rotated = core.rotate(ciphertext, decomposed, fixed_rotation_key);
  const auto decrypted = DECRYPT_DUO(rotated);
  const auto decoded = core.decode(decrypted);

  if (delta > 0) {
    for (int i = 0; i < delta; i++) {
      ASSERT_NEAR(message[slot_count - delta + i], decoded[i], 1e-4);
    }

    for (int i = 0; i < slot_count - delta; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  } else {
    for (int i = 0; i < -delta; i++) {
      ASSERT_NEAR(message[i], decoded[slot_count + delta + i], 1e-4);
    }

    for (int i = -delta; i < slot_count; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  }

  EXPECT_NEAR(rotated->ckks_scale_, ciphertext->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete decomposed;
  delete rotated;
  delete decrypted;
})

TIER_TEST(SPF3, NTTRotate, {
  const int level = std::get<0>(GetParam());
  const int message_type = std::get<1>(GetParam());
  const int delta = std::get<2>(GetParam());
  const auto fixed_rotation_key = fixed_rotation_keys_[delta];
  const bool include_special = false;

  if (level == 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto core = desilo::fhe::CKKSCore(config_);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto decomposed = core.decompose(rescaled);
  const auto attached = core.attach_special_prime_chains(rescaled);
  const auto ntt_permutation_parameters =
      core.make_ntt_permutation_parameters(delta);
  const auto rotated = core.ntt_rotate(attached, decomposed, fixed_rotation_key,
                                       ntt_permutation_parameters);
  const auto removed = core.remove_special_prime_chains(rotated);
  const auto decrypted = DECRYPT_DUO(removed);
  const auto decoded = core.decode(decrypted);

  if (delta > 0) {
    for (int i = 0; i < delta; i++) {
      ASSERT_NEAR(message[slot_count - delta + i], decoded[i], 1e-4);
    }

    for (int i = 0; i < slot_count - delta; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  } else {
    for (int i = 0; i < -delta; i++) {
      ASSERT_NEAR(message[i], decoded[slot_count + delta + i], 1e-4);
    }

    for (int i = -delta; i < slot_count; i++) {
      ASSERT_NEAR(message[i], decoded[i + delta], 1e-4);
    }
  }

  EXPECT_NEAR(rotated->ckks_scale_, rescaled->ckks_scale_, 1e-12);

  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete decomposed;
  delete attached;
  delete ntt_permutation_parameters;
  delete rotated;
  delete removed;
  delete decrypted;
})
