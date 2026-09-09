#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPE2(
    NegateSPE2,
    [](const std::tuple<bool, bool> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true)));

ALL_ENGINE_TEST(NegateSPE2, NegateUnitCiphertextTrio, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - 1;

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level + 1);
  auto squared = engine.square(unit_ciphertext);

  auto input_unit_ciphertext = squared;

  if (ciphertext_rescaled) {
    auto rescaled_unit_ciphertext = engine.rescale(input_unit_ciphertext);

    if (!ciphertext_ntt) {
      input_unit_ciphertext = engine.intt(rescaled_unit_ciphertext);

      delete rescaled_unit_ciphertext;
    } else {
      input_unit_ciphertext = rescaled_unit_ciphertext;
    }
  } else if (!ciphertext_ntt) {
    input_unit_ciphertext = engine.intt(input_unit_ciphertext);
  }

  auto negated = engine.negate(input_unit_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(negated->level_, level);
  EXPECT_EQ(negated->flag_, expected_flag);
  EXPECT_EQ(negated->polynomial_count(), 3);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(negated);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = -message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete squared;
  delete negated;
})

ALL_ENGINE_TEST(NegateSPE2, NegateCiphertextTrio, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto level = max_level_ - 1;

  if (ciphertext_rescaled && level < 1) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  auto ciphertext = engine.encrypt(message, public_key_, level + 1);
  auto squared = engine.square(ciphertext);

  auto input_ciphertext = squared;

  if (ciphertext_rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);

    if (!ciphertext_ntt) {
      input_ciphertext = engine.intt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
  } else if (!ciphertext_ntt) {
    input_ciphertext = engine.intt(input_ciphertext);
  }

  auto negated = engine.negate(input_ciphertext);

  const auto flag = desilo::fhe::DataFlag::COMPLEX;

  auto expected_flag = flag;
  if (ciphertext_ntt) {
    expected_flag |= desilo::fhe::DataFlag::NTT_FORM;
  }
  if (ciphertext_rescaled) {
    expected_flag |= desilo::fhe::DataFlag::RESCALED;
  }

  EXPECT_EQ(negated->level(), level);
  EXPECT_EQ(negated->flag(), expected_flag);
  EXPECT_EQ(negated->polynomial_count(), 3);

  const auto decrypted = DECRYPT_TRIO_COMPLEX(negated);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = -message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (!ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete squared;
  delete negated;
})
