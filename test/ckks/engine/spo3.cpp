#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPO3(
    MatrixMultiplySPO3,
    [](const std::tuple<int, int, int> &param) {
      return print_slice_count(std::get<0>(param)) +
             print_message_type(std::get<1>(param)) + "Message" +
             print_message_type(std::get<2>(param)) + "Matrix";
    },
    testing::Combine(

        testing::Values(1, 2, 3),

        testing::Values(1, 2, 3),

        testing::Values(1, 2, 3)));

ALL_ENGINE_TEST(MatrixMultiplySPO3, MatrixMultiplyCiphertext, {
  const auto slice_count = std::get<0>(GetParam());
  const auto message_type = std::get<1>(GetParam());
  const auto matrix_message_type = std::get<2>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  const auto message_count = slot_count * slice_count;
  std::vector<double> message(message_count);
  initiate_message(message, message_type);

  const auto ciphertext = engine.encrypt(message, public_key_);

  std::vector<double> matrix(slot_count * slot_count);
  initiate_message(matrix, matrix_message_type);

  const auto multiplied =
      engine.multiply_matrix(matrix.data(), ciphertext, rotation_key_);
  const auto decrypted = DECRYPT(multiplied);

  double expected[message_count]{};
  for (int i = 0; i < slice_count; i++) {
    auto slice_offset = i * slot_count;

    for (int j = 0; j < slot_count; j++) {
      for (int k = 0; k < slot_count; k++) {
        expected[slice_offset + j] +=
            matrix[j * slot_count + k] * message[slice_offset + k];
      }
    }
  }

  for (int i = 0; i < message_count; i++) {
    ASSERT_NEAR(expected[i], decrypted[i], 1e-4);
  };

  delete ciphertext;
  delete multiplied;
})
