#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPE11(
    RescaleSPE11,
    [](const std::tuple<bool, int> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_level_depth(std::get<1>(param));
    },
    testing::Combine(

        testing::Values(true, false),

        testing::Values(0, 1, 2)));

ALL_ENGINE_TEST(RescaleSPE11, UnitCiphertextTrio, {
  const auto input_ntt = std::get<0>(GetParam());
  const auto level_depth = std::get<1>(GetParam());
  const auto source_level = max_level_ - level_depth;

  if (source_level < 2) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext =
      engine.encrypt_unit(message, public_key_, source_level);
  const auto squared = engine.square(unit_ciphertext);

  const auto rescale_input = input_ntt ? squared : engine.intt(squared);

  const auto rescaled = engine.rescale(rescale_input);

  auto flag = desilo::fhe::DataFlag::RESCALED | desilo::fhe::DataFlag::COMPLEX;
  if (input_ntt) {
    flag |= desilo::fhe::DataFlag::NTT_FORM;
  }

  EXPECT_EQ(rescaled->level_, source_level - 1);
  EXPECT_EQ(rescaled->flag_, flag);

  const auto decrypted = DECRYPT_UNIT_TRIO_COMPLEX(rescaled);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext;
  delete squared;
  delete rescaled;
  if (!input_ntt) {
    delete rescale_input;
  }
})
