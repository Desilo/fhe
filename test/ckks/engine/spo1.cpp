#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPO1(
    SPO1,
    [](const std::tuple<int> &param) {
      return print_slice_count(std::get<0>(param));
    },
    testing::Values(1, 2, 3));

ALL_ENGINE_TEST(SPO1, Sum1DByRow, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_);
  const auto summed = engine.sum_1d_by_row(ciphertext, rotation_key_);
  const auto decrypted = DECRYPT(summed);

  auto level = ciphertext->level();
  if (ONE_MORE_LEVEL && level == FULL_LEVEL && slot_count > 1) {
    level--;
  }
  auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(summed->level(), level);
  EXPECT_EQ(summed->flag(), flag);
  EXPECT_EQ(summed->polynomial_count(), 2);

  std::vector<double> expected(slice_count);
  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    expected[slice_index] = 0.0;
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      expected[slice_index] += message[slice_index * slot_count + slot_index];
    }
  }

  auto threshold = 1e-4;
  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      auto index = slice_index * slot_count + slot_index;
      ASSERT_NEAR(decrypted[index], expected[slice_index], threshold);
    }
  }

  delete ciphertext;
  delete summed;
})

ALL_ENGINE_TEST(SPO1, Sum2D, {
  const auto slice_count = std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  const auto ciphertext = engine.encrypt(message, public_key_);
  const auto summed = engine.sum_2d(ciphertext, rotation_key_);
  const auto decrypted = DECRYPT(summed);

  auto level = ciphertext->level();
  if (ONE_MORE_LEVEL && level == FULL_LEVEL && slot_count > 1) {
    level--;
  }
  auto flag = desilo::fhe::DataFlag::NONE;

  EXPECT_EQ(summed->size(), 1);
  EXPECT_EQ(summed->level(), level);
  EXPECT_EQ(summed->flag(), flag);
  EXPECT_EQ(summed->polynomial_count(), 2);

  double expected = 0.0;
  for (int index = 0; index < slot_count * slice_count; index++) {
    expected += message[index];
  }

  auto threshold = 1e-4;
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    ASSERT_NEAR(decrypted[slot_index], expected, threshold);
  }

  delete ciphertext;
  delete summed;
})
