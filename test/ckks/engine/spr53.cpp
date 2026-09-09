#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPR53(
    MultiplySPR53,
    [](const std::tuple<bool, bool, bool, bool, bool, std::tuple<int, int, int>>
           &param) {
      return print_ntt_flag(std::get<0>(param)) +
             print_rescaled_flag(std::get<1>(param)) + "And" +
             print_ntt_flag(std::get<2>(param)) +
             print_rescaled_flag(std::get<3>(param)) +
             print_long_extended(std::get<4>(param)) +
             print_level_depth(std::get<0>(std::get<5>(param))) + "And" +
             print_level_depth(std::get<1>(std::get<5>(param)));
    },
    testing::Combine(

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(false, true),

        testing::Values(true, false),

        testing::Values(std::make_tuple(0, 0, 1), std::make_tuple(0, 1, 2),
                        std::make_tuple(1, 0, 2), std::make_tuple(1, 1, 2))));

ALL_ENGINE_TEST(MultiplySPR53, MultiplyThenRelinearize, {
  const auto first_ntt = std::get<0>(GetParam());
  const auto first_rescaled = std::get<1>(GetParam());
  const auto second_ntt = std::get<2>(GetParam());
  const auto second_rescaled = std::get<3>(GetParam());
  const auto slice_count = std::get<4>(GetParam()) ? 2 : 1;
  const auto levels = std::get<5>(GetParam());
  const auto level1 = max_level_ - std::get<0>(levels);
  const auto level2 = max_level_ - std::get<1>(levels);
  const auto multiplied_level = max_level_ - std::get<2>(levels);

  if (multiplied_level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext1 = engine.encrypt(message, public_key_, level1);
  auto ciphertext2 = engine.encrypt(message, public_key_, level2);

  auto input_ciphertext1 = ciphertext1;
  auto input_ciphertext2 = ciphertext2;

  if (first_rescaled) {
    auto rescaled_ciphertext1 = engine.rescale(input_ciphertext1);

    if (first_ntt) {
      input_ciphertext1 = engine.ntt(rescaled_ciphertext1);

      delete rescaled_ciphertext1;
    } else {
      input_ciphertext1 = rescaled_ciphertext1;
    }
  } else if (first_ntt) {
    input_ciphertext1 = engine.ntt(input_ciphertext1);
  }

  if (second_rescaled) {
    auto rescaled_ciphertext2 = engine.rescale(input_ciphertext2);

    if (second_ntt) {
      input_ciphertext2 = engine.ntt(rescaled_ciphertext2);

      delete rescaled_ciphertext2;
    } else {
      input_ciphertext2 = rescaled_ciphertext2;
    }
  } else if (second_ntt) {
    input_ciphertext2 = engine.ntt(input_ciphertext2);
  }

  auto multiplied = engine.multiply(input_ciphertext1, input_ciphertext2,
                                    relinearization_key_);

  auto flag = desilo::fhe::DataFlag::NONE;
  flag |= desilo::fhe::DataFlag::COMPLEX;

  EXPECT_EQ(multiplied->level(), multiplied_level);
  EXPECT_EQ(multiplied->flag(), flag);
  EXPECT_EQ(multiplied->polynomial_count(), 2);

  const auto decrypted = DECRYPT_COMPLEX(multiplied);

  for (int i = 0; i < slot_count; i++) {
    const auto expected = message[i] * message[i];
    ASSERT_NEAR(expected.real(), decrypted[i].real(), 1e-4);
    ASSERT_NEAR(expected.imag(), decrypted[i].imag(), 1e-4);
  }

  if (first_ntt || first_rescaled) {
    delete input_ciphertext1;
  }
  if (second_ntt || second_rescaled) {
    delete input_ciphertext2;
  }

  delete ciphertext1;
  delete ciphertext2;
  delete multiplied;
})
