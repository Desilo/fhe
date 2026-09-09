#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/encode.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "common/common.h"
#include "common/test.h"
#include "operation/bootstrap.h"

#define DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(log_slot_count, stage_count)            \
  class                                                                                  \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall   \
      : public testing::TestWithParam<std::tuple<int, int, int>> {                       \
  public:                                                                                \
    static void SetUpTestSuite() {                                                       \
      auto config = desilo::fhe::CKKSConfig::for_bootstrap();                            \
      config.log_slot_count_ = log_slot_count;                                           \
                                                                                         \
      auto engine = desilo::fhe::CKKSEngine(config);                                     \
                                                                                         \
      secret_key_ = engine.create_secret_key();                                          \
      public_key_ = engine.create_public_key(secret_key_);                               \
      relinearization_key_ = engine.create_relinearization_key(secret_key_);             \
      conjugation_key_ = engine.create_conjugation_key(secret_key_);                     \
      rotation_key_ = engine.create_rotation_key(secret_key_);                           \
      small_bootstrap_key_ = engine.create_small_bootstrap_key(secret_key_);             \
    }                                                                                    \
                                                                                         \
    static void TearDownTestSuite() {                                                    \
      delete secret_key_;                                                                \
      delete public_key_;                                                                \
      delete relinearization_key_;                                                       \
      delete conjugation_key_;                                                           \
      delete rotation_key_;                                                              \
      delete small_bootstrap_key_;                                                       \
      secret_key_ = nullptr;                                                             \
      public_key_ = nullptr;                                                             \
      relinearization_key_ = nullptr;                                                    \
      conjugation_key_ = nullptr;                                                        \
      rotation_key_ = nullptr;                                                           \
      small_bootstrap_key_ = nullptr;                                                    \
    }                                                                                    \
                                                                                         \
    static desilo::fhe::SecretKey *secret_key_;                                          \
    static desilo::fhe::PublicKey *public_key_;                                          \
    static desilo::fhe::RelinearizationKey *relinearization_key_;                        \
    static desilo::fhe::ConjugationKey *conjugation_key_;                                \
    static desilo::fhe::RotationKey *rotation_key_;                                      \
    static desilo::fhe::SmallBootstrapKey *small_bootstrap_key_;                         \
    static int log_slot_count_;                                                          \
    static int stage_count_;                                                             \
  };                                                                                     \
                                                                                         \
  desilo::fhe::SecretKey *                                                               \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
          secret_key_ = nullptr;                                                         \
  desilo::fhe::PublicKey *                                                               \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
          public_key_ = nullptr;                                                         \
  desilo::fhe::RelinearizationKey *                                                      \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
          relinearization_key_ = nullptr;                                                \
  desilo::fhe::ConjugationKey *                                                          \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
          conjugation_key_ = nullptr;                                                    \
  desilo::fhe::RotationKey *                                                             \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
          rotation_key_ = nullptr;                                                       \
  desilo::fhe::SmallBootstrapKey *                                                       \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
          small_bootstrap_key_ = nullptr;                                                \
  int BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
      log_slot_count_ = log_slot_count;                                                  \
  int BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
      stage_count_ = stage_count;

#define INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(log_slot_count, stage_count)                 \
  INSTANTIATE_TEST_CASE_P(                                                                   \
      CKKSEngineBootstrap,                                                                   \
      BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall,      \
      testing::Combine(testing::Values(0, 25), testing::Values(1, 2),                        \
                       PROCESS_TEST),                                                        \
      [](const testing::TestParamInfo<                                                       \
          BootstrapSparseGold##LogSlotCount##log_slot_count##And##stage_count##StagesSmall:: \
              ParamType> &info) {                                                            \
        return print_level(std::get<0>(info.param)) + "With" +                               \
               print_slice_count(std::get<1>(info.param)) +                                  \
               print_process_type(std::get<2>(info.param));                                  \
      });

#ifdef DESILO_FHE_LARGE_TEST
#define BOOTSTRAP_SPARSE_SMALL_TEST(test_name, test_body)                      \
  TEST_P(BootstrapSparseGoldLogSlotCount1And1StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount2And1StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount3And1StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount4And1StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount5And1StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount4And2StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount5And2StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount6And2StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount7And2StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount8And2StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount9And2StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount10And2StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount7And3StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount8And3StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount9And3StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount10And3StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount11And3StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount12And3StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount13And3StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount14And3StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount10And4StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount11And4StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount12And4StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount13And4StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount14And4StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount13And5StagesSmall, test_name)          \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount14And5StagesSmall, test_name)          \
  test_body;
#else
#define BOOTSTRAP_SPARSE_SMALL_TEST(test_name, test_body)                      \
  TEST_P(BootstrapSparseGoldLogSlotCount5And1StagesSmall, test_name)           \
  test_body;                                                                   \
  TEST_P(BootstrapSparseGoldLogSlotCount10And2StagesSmall, test_name)          \
  test_body;
#endif

#ifdef DESILO_FHE_LARGE_TEST
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(1, 1);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(2, 1);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(3, 1);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(4, 1);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(5, 1);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(4, 2);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(5, 2);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(6, 2);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(7, 2);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(8, 2);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(9, 2);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(10, 2);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(7, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(8, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(9, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(10, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(11, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(12, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(13, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(14, 3);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(10, 4);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(11, 4);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(12, 4);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(13, 4);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(14, 4);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(13, 5);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(14, 5);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(1, 1);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(2, 1);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(3, 1);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(4, 1);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(5, 1);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(4, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(5, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(6, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(7, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(8, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(9, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(10, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(7, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(8, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(9, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(10, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(11, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(12, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(13, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(14, 3);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(10, 4);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(11, 4);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(12, 4);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(13, 4);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(14, 4);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(13, 5);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(14, 5);
#else
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(5, 1);
DEFINE_BOOTSTRAP_SPARSE_SMALL_TEST_CLASS(10, 2);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(5, 1);
INSTANTIATE_BOOTSTRAP_SPARSE_SMALL_TEST(10, 2);
#endif

BOOTSTRAP_SPARSE_SMALL_TEST(PartialSum, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level == 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_slot_count_ = log_slot_count_;
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = 1 << log_slot_count_;
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);
  const auto coeff_count_half = engine.get_coeff_count() / 2;
  const double partial_sum_ratio = coeff_count_half / slot_count;

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    message[slot_index] /= 1000;
  }

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  engine.partial_sum_inplace(unit_ciphertext, rotation_key_);

  auto decrypted = engine.decrypt_complex(unit_ciphertext, secret_key_);

  std::vector<std::complex<double>> expected(slot_count);
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    expected[slot_index] = message[slot_index] * partial_sum_ratio;
  }

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    ASSERT_NEAR(decrypted[slot_index].real(), expected[slot_index].real(),
                1e-6);
    ASSERT_NEAR(decrypted[slot_index].imag(), expected[slot_index].imag(),
                1e-6);
  }

  delete unit_ciphertext;
})

BOOTSTRAP_SPARSE_SMALL_TEST(CoeffToSlot, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level == 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_slot_count_ = log_slot_count_;
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = 1 << log_slot_count_;
  const auto slot_count_double = 2 * slot_count;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  std::vector<std::complex<double>> twiddle_factor;
  const double unit_angle = -2 * std::numbers::pi / slot_count_double;
  for (int index = 0; index < slot_count_double; index++) {
    const double angle = index * unit_angle;
    twiddle_factor.push_back(
        std::complex<double>(std::cos(angle), std::sin(angle)));
  }

  auto expected = desilo::fhe::encode_complex(
      message.data(), twiddle_factor.data(), slot_count, 1);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto slot = engine.coeff_to_slot(unit_ciphertext, conjugation_key_,
                                   rotation_key_, stage_count_);

  auto decrypted0 = engine.decrypt(slot.first, secret_key_);
  auto decrypted1 = engine.decrypt(slot.second, secret_key_);

  ASSERT_EQ(slot.first->moduli_id_, stage_count_ + 1);
  ASSERT_EQ(slot.second->moduli_id_, stage_count_ + 1);

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {

    const int reversed_slot_index =
        desilo::fhe::reverse_integer_bits(slot_index, log_slot_count_);

    ASSERT_NEAR(decrypted0[reversed_slot_index],
                expected[slot_index] / desilo::fhe::ROUND_BOUND, 1e-6);

    ASSERT_NEAR(decrypted1[reversed_slot_index],
                expected[slot_count + slot_index] / desilo::fhe::ROUND_BOUND,
                1e-6);
  }

  delete[] expected;
  delete unit_ciphertext;
  delete slot.first;
  delete slot.second;
})

BOOTSTRAP_SPARSE_SMALL_TEST(SlotToCoeff, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level == 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  config.log_slot_count_ = log_slot_count_;
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = 1 << log_slot_count_;
  const auto slot_count_double = 2 * slot_count;

  std::vector<double> message_half(slot_count);

  initiate_message(message_half, 3);

  double message[slot_count_double];
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {

    const int reversed_slot_index =
        desilo::fhe::reverse_integer_bits(slot_index, log_slot_count_);
    message[reversed_slot_index] = message_half[slot_index];
    message[slot_count + reversed_slot_index] = message_half[slot_index];
  }

  const auto expected =
      desilo::fhe::decode_complex(message, slot_count_double, 1);

  int reduced_level_for_round = 9;
  int level_after_round = level - reduced_level_for_round - stage_count_;
  auto unit_ciphertext0 =
      engine.encrypt_unit(message_half, public_key_, level_after_round);
  auto unit_ciphertext1 =
      engine.encrypt_unit(message_half, public_key_, level_after_round);
  auto coeff =
      engine.slot_to_coeff(unit_ciphertext0, unit_ciphertext1, conjugation_key_,
                           rotation_key_, stage_count_);

  auto decrypted = engine.decrypt_complex(coeff, secret_key_);

  ASSERT_EQ(coeff->moduli_id_, 1 + reduced_level_for_round + stage_count_ * 2);

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    ASSERT_NEAR(decrypted[slot_index].real(), expected[slot_index].real(),
                1e-4);
    ASSERT_NEAR(decrypted[slot_index].imag(), expected[slot_index].imag(),
                1e-4);
  }

  delete[] expected;
  delete unit_ciphertext0;
  delete unit_ciphertext1;
  delete coeff;
})

BOOTSTRAP_SPARSE_SMALL_TEST(CoeffToSlotToCoeff, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level == 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  config.log_slot_count_ = log_slot_count_;
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = 1 << log_slot_count_;
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto slot = engine.coeff_to_slot(unit_ciphertext, conjugation_key_,
                                   rotation_key_, stage_count_);

  auto multiplied0 = engine.multiply(slot.first, desilo::fhe::ROUND_BOUND);
  auto multiplied1 = engine.multiply(slot.second, desilo::fhe::ROUND_BOUND);
  int level_after_round = 16;
  auto leveled_down0 =
      engine.level_down(multiplied0, level_after_round - stage_count_);
  auto leveled_down1 =
      engine.level_down(multiplied1, level_after_round - stage_count_);

  auto coeff =
      engine.slot_to_coeff(leveled_down0, leveled_down1, conjugation_key_,
                           rotation_key_, stage_count_);
  auto decrypted = engine.decrypt_complex(coeff, secret_key_);

  expect_complex_vector_near(decrypted, message, slot_count, 1e-4);

  delete unit_ciphertext;
  delete slot.first;
  delete slot.second;
  delete multiplied0;
  delete multiplied1;
  delete leveled_down0;
  delete leveled_down1;
  delete coeff;
})

BOOTSTRAP_SPARSE_SMALL_TEST(BootstrapUnitCiphertext, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_slot_count_ = log_slot_count_;
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = 1 << log_slot_count_;
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto bootstrapped =
      engine.bootstrap(unit_ciphertext, relinearization_key_, conjugation_key_,
                       rotation_key_, small_bootstrap_key_, stage_count_);

  auto decrypted = engine.decrypt(bootstrapped, secret_key_);

  EXPECT_EQ(bootstrapped->level_, 16 - stage_count_ * 2);
  expect_vector_near(decrypted, message, slot_count, 1e-2);

  delete unit_ciphertext;
  delete bootstrapped;
})

BOOTSTRAP_SPARSE_SMALL_TEST(BootstrapCiphertext, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_slot_count_ = log_slot_count_;
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = 1 << log_slot_count_;
  std::vector<double> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level);
  auto bootstrapped =
      engine.bootstrap(ciphertext, relinearization_key_, conjugation_key_,
                       rotation_key_, small_bootstrap_key_, stage_count_);

  auto decrypted = engine.decrypt(bootstrapped, secret_key_);

  EXPECT_EQ(bootstrapped->level(), 16 - stage_count_ * 2);
  expect_vector_near(decrypted, message, slot_count, 1e-2);

  delete ciphertext;
  delete bootstrapped;
})
