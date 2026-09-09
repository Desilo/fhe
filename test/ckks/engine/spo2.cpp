#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SPO2(
    MultiplyMatrixSPO2,
    [](const std::tuple<int, int> &param) {
      return print_message_type(std::get<0>(param)) + "Message" +
             print_message_type(std::get<1>(param)) + "Matrix";
    },
    testing::Combine(

        testing::Values(1, 2, 3),

        testing::Values(1, 2, 3)));

ALL_ENGINE_TEST(MultiplyMatrixSPO2, UnitCiphertext, {
  const auto message_type = std::get<0>(GetParam());
  const auto matrix_message_type = std::get<1>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, message_type);

  const auto unit_ciphertext = engine.encrypt_unit(message, public_key_);

  std::vector<double> matrix(slot_count * slot_count);
  initiate_message(matrix, matrix_message_type);

  const auto multiplied =
      engine.multiply_matrix(matrix.data(), unit_ciphertext, rotation_key_);
  const auto decrypted = DECRYPT_UNIT(multiplied);

  double expected[slot_count]{};
  for (int i = 0; i < slot_count; i++) {
    for (int j = 0; j < slot_count; j++) {
      expected[i] += matrix[i * slot_count + j] * message[j];
    }
  }

  for (int i = 0; i < slot_count; i++) {
    ASSERT_NEAR(expected[i], decrypted[i], 1e-4);
  };

  delete unit_ciphertext;
  delete multiplied;
})
