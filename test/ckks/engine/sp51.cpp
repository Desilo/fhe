#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP51(
    AddSubtractInplacePlaintextSP51,
    [](const std::tuple<bool, bool, bool, bool, bool, int> &param) {
      return print_ciphertext_first(std::get<0>(param)) +
             print_long_extended(std::get<1>(param)) +
             print_ntt_flag(std::get<2>(param)) + "And" +
             print_ntt_flag(std::get<3>(param)) +
             print_rescaled_flag(std::get<4>(param)) + "And" +
             print_level_depth(std::get<5>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(0, 1)));

ALL_ENGINE_TEST(AddSubtractInplacePlaintextSP51, AddDuo, {
  const auto ciphertext_first = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam()) ? 2 : 1;
  const auto ciphertext_ntt = std::get<2>(GetParam());
  const auto plaintext_ntt = std::get<3>(GetParam());
  const auto rescaled = std::get<4>(GetParam());
  const auto level = max_level_ - std::get<5>(GetParam());

  if (rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_, level);
  auto plaintext = engine.encode(message, level);

  auto input_ciphertext = ciphertext;
  auto input_plaintext = plaintext;

  if (rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);
    auto rescaled_plaintext = engine.rescale(input_plaintext);

    if (ciphertext_ntt) {
      input_ciphertext = engine.ntt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
    if (plaintext_ntt) {
      input_plaintext = engine.ntt(rescaled_plaintext);

      delete rescaled_plaintext;
    } else {
      input_plaintext = rescaled_plaintext;
    }
  } else {
    if (ciphertext_ntt) {
      input_ciphertext = engine.ntt(input_ciphertext);
    }
    if (plaintext_ntt) {
      input_plaintext = engine.ntt(input_plaintext);
    }
  }

  if (ciphertext_first) {
    engine.add_inplace(input_ciphertext, input_plaintext);
  } else {
    engine.add_inplace(input_plaintext, input_ciphertext);
  }

  const auto flag = desilo::fhe::DataFlag::COMPLEX;
  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(input_ciphertext->level(), level);
  EXPECT_EQ(input_ciphertext->flag(), expected_flag);
  EXPECT_EQ(input_ciphertext->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(input_ciphertext);

  for (int i = 0; i < slot_count * slice_count; i++) {
    const auto expected = message[i] + message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || rescaled) {
    delete input_ciphertext;
  }
  if (plaintext_ntt || rescaled) {
    delete input_plaintext;
  }

  delete ciphertext;
  delete plaintext;
})
