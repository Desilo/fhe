#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP2(
    WeightedSumSP2,
    [](const std::tuple<int, int> &param) {
      return print_level_depth(std::get<0>(param)) + "And" +
             print_level_depth(std::get<1>(param));
    },
    testing::Combine(

        testing::Values(0, 1),

        testing::Values(0, 1)));

std::vector<int64_t> int_weights{1, 2, 3};

ALL_ENGINE_TEST(WeightedSumSP2, IntegerWeights, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto level_depths = GetParam();
  const auto level1 = max_level_ - std::get<0>(level_depths);
  const auto level2 = max_level_ - std::get<1>(level_depths);
  const auto min_level = std::min(level1, level2);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 2);
  initiate_message(message2, 4);

  auto unit_ciphertext1 = engine.encrypt_unit(message1, public_key_, level1);
  auto unit_ciphertext2 = engine.encrypt_unit(message2, public_key_, level2);

  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts;
  unit_ciphertexts.push_back(unit_ciphertext1);
  unit_ciphertexts.push_back(unit_ciphertext2);

  const auto weighted_sum = engine.weighted_sum(unit_ciphertexts, int_weights);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(weighted_sum->level_, min_level);
  EXPECT_EQ(weighted_sum->flag_, flag);
  EXPECT_EQ(weighted_sum->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(weighted_sum);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(9.0, decrypted[i].real(), 1e-4);
    ASSERT_NEAR(8.0, decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete weighted_sum;
})

std::vector<double> double_weights{1.5, 2.5, 3.5};

ALL_ENGINE_TEST(WeightedSumSP2, DoubleWeights, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto level_depths = GetParam();
  const auto level1 = max_level_ - std::get<0>(level_depths);
  const auto level2 = max_level_ - std::get<1>(level_depths);
  const auto min_level = std::min(level1, level2);

  if (min_level < 1) {
    GTEST_SKIP() << "Impossible Level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 2);
  initiate_message(message2, 4);

  auto unit_ciphertext1 = engine.encrypt_unit(message1, public_key_, level1);
  auto unit_ciphertext2 = engine.encrypt_unit(message2, public_key_, level2);

  std::vector<desilo::fhe::UnitCiphertext *> unit_ciphertexts;
  unit_ciphertexts.push_back(unit_ciphertext1);
  unit_ciphertexts.push_back(unit_ciphertext2);

  auto weighted_sum = engine.weighted_sum(unit_ciphertexts, double_weights);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(weighted_sum->level_, min_level - 1);
  EXPECT_EQ(weighted_sum->flag_, flag);
  EXPECT_EQ(weighted_sum->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(weighted_sum);

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(11.0, decrypted[i].real(), 1e-4);
    ASSERT_NEAR(9.5, decrypted[i].imag(), 1e-4);
  }

  delete unit_ciphertext1;
  delete unit_ciphertext2;
  delete weighted_sum;
})

SETUP_ENGINE_TEST_SP2(
    NegateSP2,
    [](const std::tuple<bool, bool> &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true)));

ALL_ENGINE_TEST(NegateSP2, NegateUnitCiphertext, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto level = max_level_;

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);

  auto input_unit_ciphertext = unit_ciphertext;

  if (ciphertext_rescaled) {
    auto rescaled_unit_ciphertext = engine.rescale(input_unit_ciphertext);

    if (ciphertext_ntt) {
      input_unit_ciphertext = engine.ntt(rescaled_unit_ciphertext);

      delete rescaled_unit_ciphertext;
    } else {
      input_unit_ciphertext = rescaled_unit_ciphertext;
    }
  } else if (ciphertext_ntt) {
    input_unit_ciphertext = engine.ntt(input_unit_ciphertext);
  }

  const auto negated = engine.negate(input_unit_ciphertext);

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
  EXPECT_EQ(negated->polynomial_count(), 2);

  const auto decrypted = DECRYPT_UNIT_COMPLEX(negated);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = -message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_unit_ciphertext;
  }

  delete unit_ciphertext;
  delete negated;
})

ALL_ENGINE_TEST(NegateSP2, NegateCiphertext, {
  const auto ciphertext_ntt = std::get<0>(GetParam());
  const auto ciphertext_rescaled = std::get<1>(GetParam());
  const auto level = max_level_;

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 2);

  const auto ciphertext = engine.encrypt(message, public_key_);

  auto input_ciphertext = ciphertext;

  if (ciphertext_rescaled) {
    auto rescaled_ciphertext = engine.rescale(input_ciphertext);

    if (ciphertext_ntt) {
      input_ciphertext = engine.ntt(rescaled_ciphertext);

      delete rescaled_ciphertext;
    } else {
      input_ciphertext = rescaled_ciphertext;
    }
  } else if (ciphertext_ntt) {
    input_ciphertext = engine.ntt(input_ciphertext);
  }

  const auto negated = engine.negate(input_ciphertext);

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
  EXPECT_EQ(negated->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(negated);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = -message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (ciphertext_ntt || ciphertext_rescaled) {
    delete input_ciphertext;
  }

  delete ciphertext;
  delete negated;
})
