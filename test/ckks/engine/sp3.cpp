#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP3(
    WeightedSumSP3,
    [](const std::tuple<int, int, int> &param) {
      return print_slice_count(std::get<0>(param)) +
             print_level_depth(std::get<1>(param)) + "And" +
             print_level_depth(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(1, 2),

        testing::Values(0, 1),

        testing::Values(0, 1)));

std::vector<int64_t> int_weights{1, 2, 3};

ALL_ENGINE_TEST(WeightedSumSP3, IntegerWeights, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slice_count = std::get<0>(GetParam());
  const auto level_depths = GetParam();
  const auto level1 = max_level_ - std::get<1>(level_depths);
  const auto level2 = max_level_ - std::get<2>(level_depths);
  const auto min_level = std::min(level1, level2);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_message(message1, 2);
  initiate_message(message2, 4);

  auto ciphertext1 = engine.encrypt(message1, public_key_, level1);
  auto ciphertext2 = engine.encrypt(message2, public_key_, level2);

  std::vector<desilo::fhe::Ciphertext *> ciphertexts;
  ciphertexts.push_back(ciphertext1);
  ciphertexts.push_back(ciphertext2);

  auto weighted_sum = engine.weighted_sum(ciphertexts, int_weights);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(weighted_sum->level(), min_level);
  EXPECT_EQ(weighted_sum->flag(), flag);
  EXPECT_EQ(weighted_sum->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(weighted_sum);

  for (int i = 0; i < message1.size(); i++) {
    ASSERT_NEAR(9.0, decrypted[i].real(), 1e-4);
    ASSERT_NEAR(8.0, decrypted[i].imag(), 1e-4);
  }

  delete ciphertext1;
  delete ciphertext2;
  delete weighted_sum;
})

std::vector<double> double_weights{1.5, 2.5, 3.5};

ALL_ENGINE_TEST(WeightedSumSP3, DoubleWeights, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slice_count = std::get<0>(GetParam());
  const auto level_depths = GetParam();
  const auto level1 = max_level_ - std::get<1>(level_depths);
  const auto level2 = max_level_ - std::get<2>(level_depths);
  const auto min_level = std::min(level1, level2);

  if (min_level < 1) {
    GTEST_SKIP() << "Impossible Level.";
  }

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message1(slot_count * slice_count);
  std::vector<std::complex<double>> message2(slot_count * slice_count);
  initiate_message(message1, 2);
  initiate_message(message2, 4);

  auto ciphertext1 = engine.encrypt(message1, public_key_, level1);
  auto ciphertext2 = engine.encrypt(message2, public_key_, level2);

  std::vector<desilo::fhe::Ciphertext *> ciphertexts;
  ciphertexts.push_back(ciphertext1);
  ciphertexts.push_back(ciphertext2);

  auto weighted_sum = engine.weighted_sum(ciphertexts, double_weights);

  auto flag = desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(weighted_sum->level(), min_level - 1);
  EXPECT_EQ(weighted_sum->flag(), flag);
  EXPECT_EQ(weighted_sum->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(weighted_sum);

  for (int i = 0; i < message1.size(); i++) {
    ASSERT_NEAR(11.0, decrypted[i].real(), 1e-4);
    ASSERT_NEAR(9.5, decrypted[i].imag(), 1e-4);
  }

  delete ciphertext1;
  delete ciphertext2;
  delete weighted_sum;
})

SETUP_ENGINE_TEST_SP3(
    SP3B,
    [](const std::tuple<int, int, int> &param) {
      return print_slice_count(std::get<0>(param)) +
             print_slice_count(std::get<1>(param)) +
             print_slice_count(std::get<2>(param));
    },
    testing::Combine(

        testing::Values(1, 2, 3),

        testing::Values(0, 1, 2),

        testing::Values(0, 1, 2)));

ALL_ENGINE_TEST(SP3B, StackByRow, {
  const auto slice_count_1 = std::get<0>(GetParam());
  const auto slice_count_2 = std::get<1>(GetParam());
  const auto slice_count_3 = std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message_1(slot_count * slice_count_1);
  std::vector<double> message_2(slot_count * slice_count_2);
  std::vector<double> message_3(slot_count * slice_count_3);
  initiate_sliced_message(message_1, slice_count_1, slot_count, 1.0);
  initiate_sliced_message(message_2, slice_count_2, slot_count, 2.0);
  initiate_sliced_message(message_3, slice_count_3, slot_count, 3.0);

  std::vector<desilo::fhe::Ciphertext *> ciphertexts;
  ciphertexts.push_back(engine.encrypt(message_1, public_key_));
  if (slice_count_2 > 0) {
    ciphertexts.push_back(engine.encrypt(message_2, public_key_));
  }
  if (slice_count_3 > 0) {
    ciphertexts.push_back(engine.encrypt(message_3, public_key_));
  }

  const auto stacked = engine.stack_by_row(ciphertexts);
  const auto decrypted = DECRYPT(stacked);

  auto level = ciphertexts[0]->level();
  auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(stacked->size(), slice_count_1 + slice_count_2 + slice_count_3);
  EXPECT_EQ(stacked->level(), level);
  EXPECT_EQ(stacked->flag(), flag);
  EXPECT_EQ(stacked->polynomial_count(), 2);

  auto threshold = 1e-4;
  int stacked_slice_index = 0;
  for (int slice_index = 0; slice_index < slice_count_1; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      ASSERT_NEAR(decrypted[stacked_slice_index * slot_count + slot_index],
                  message_1[slice_index * slot_count + slot_index], threshold);
    }
    stacked_slice_index++;
  }

  for (int slice_index = 0; slice_index < slice_count_2; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      ASSERT_NEAR(decrypted[stacked_slice_index * slot_count + slot_index],
                  message_2[slice_index * slot_count + slot_index], threshold);
    }
    stacked_slice_index++;
  }

  for (int slice_index = 0; slice_index < slice_count_3; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      ASSERT_NEAR(decrypted[stacked_slice_index * slot_count + slot_index],
                  message_3[slice_index * slot_count + slot_index], threshold);
    }
    stacked_slice_index++;
  }

  for (auto ciphertext : ciphertexts) {
    delete ciphertext;
  }
  delete stacked;
})
