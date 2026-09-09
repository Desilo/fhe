#include <algorithm>

#include "ckks/encode.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/precomputed.h"
#include "common/common.h"
#include "common/test.h"
#include "operation/bootstrap.h"

#define DEFINE_BOOTSTRAP_TEST_CLASS(stage_count, size)                         \
  class BootstrapGold##stage_count##Stages##size                               \
      : public testing::TestWithParam<std::tuple<int, int, int>> {             \
  public:                                                                      \
    static void SetUpTestSuite() {                                             \
      auto config = desilo::fhe::CKKSConfig::for_bootstrap();                  \
                                                                               \
      auto engine = desilo::fhe::CKKSEngine(config);                           \
                                                                               \
      secret_key_ = engine.create_secret_key();                                \
      public_key_ = engine.create_public_key(secret_key_);                     \
      relinearization_key_ = engine.create_relinearization_key(secret_key_);   \
      conjugation_key_ = engine.create_conjugation_key(secret_key_);           \
                                                                               \
      stage_count_ = stage_count;                                              \
      bootstrap_key_ =                                                         \
          engine.create_bootstrap_key(secret_key_, stage_count, #size);        \
    }                                                                          \
                                                                               \
    static void TearDownTestSuite() {                                          \
      delete secret_key_;                                                      \
      delete public_key_;                                                      \
      delete relinearization_key_;                                             \
      delete conjugation_key_;                                                 \
      delete rotation_key_;                                                    \
      delete bootstrap_key_;                                                   \
      secret_key_ = nullptr;                                                   \
      public_key_ = nullptr;                                                   \
      relinearization_key_ = nullptr;                                          \
      conjugation_key_ = nullptr;                                              \
      bootstrap_key_ = nullptr;                                                \
    }                                                                          \
                                                                               \
    static desilo::fhe::SecretKey *secret_key_;                                \
    static desilo::fhe::PublicKey *public_key_;                                \
    static desilo::fhe::RelinearizationKey *relinearization_key_;              \
    static desilo::fhe::ConjugationKey *conjugation_key_;                      \
    static desilo::fhe::RotationKey *rotation_key_;                            \
    static desilo::fhe::BootstrapKey *bootstrap_key_;                          \
    static int stage_count_;                                                   \
  };                                                                           \
                                                                               \
  desilo::fhe::SecretKey                                                       \
      *BootstrapGold##stage_count##Stages##size::secret_key_ = nullptr;        \
  desilo::fhe::PublicKey                                                       \
      *BootstrapGold##stage_count##Stages##size::public_key_ = nullptr;        \
  desilo::fhe::RelinearizationKey                                              \
      *BootstrapGold##stage_count##Stages##size::relinearization_key_ =        \
          nullptr;                                                             \
  desilo::fhe::ConjugationKey                                                  \
      *BootstrapGold##stage_count##Stages##size::conjugation_key_ = nullptr;   \
  desilo::fhe::RotationKey                                                     \
      *BootstrapGold##stage_count##Stages##size::rotation_key_ = nullptr;      \
  desilo::fhe::BootstrapKey                                                    \
      *BootstrapGold##stage_count##Stages##size::bootstrap_key_ = nullptr;     \
  int BootstrapGold##stage_count##Stages##size::stage_count_;

#ifdef DESILO_FHE_LARGE_TEST
#define INSTANTIATE_BOOTSTRAP_TEST(stage_count, size)                          \
  INSTANTIATE_TEST_CASE_P(                                                     \
      CKKSEngineBootstrap, BootstrapGold##stage_count##Stages##size,           \
      testing::Combine(testing::Values(0, 25), testing::Values(1, 2),          \
                       PROCESS_TEST),                                          \
      [](const testing::TestParamInfo<                                         \
          BootstrapGold##stage_count##Stages##size::ParamType> &info) {        \
        return print_level(std::get<0>(info.param)) + "With" +                 \
               print_slice_count(std::get<1>(info.param)) +                    \
               print_process_type(std::get<2>(info.param));                    \
      });
#else
#define INSTANTIATE_BOOTSTRAP_TEST(stage_count, size)                          \
  INSTANTIATE_TEST_CASE_P(                                                     \
      CKKSEngineBootstrap, BootstrapGold##stage_count##Stages##size,           \
      testing::Combine(testing::Values(0, 25), testing::Values(1, 2),          \
                       testing::Values(1, 2)),                                 \
      [](const testing::TestParamInfo<                                         \
          BootstrapGold##stage_count##Stages##size::ParamType> &info) {        \
        return print_level(std::get<0>(info.param)) + "With" +                 \
               print_slice_count(std::get<1>(info.param)) +                    \
               print_process_type(std::get<2>(info.param));                    \
      });
#endif

#define BOOTSTRAP_TEST(test_name, test_body)                                   \
  TEST_P(BootstrapGold3StagesMedium, test_name)                                \
  test_body;                                                                   \
  TEST_P(BootstrapGold4StagesMedium, test_name)                                \
  test_body;                                                                   \
  TEST_P(BootstrapGold5StagesMedium, test_name)                                \
  test_body;                                                                   \
  TEST_P(BootstrapGold3StagesLarge, test_name)                                 \
  test_body;                                                                   \
  TEST_P(BootstrapGold4StagesLarge, test_name)                                 \
  test_body;                                                                   \
  TEST_P(BootstrapGold5StagesLarge, test_name)                                 \
  test_body;

DEFINE_BOOTSTRAP_TEST_CLASS(3, Medium);
DEFINE_BOOTSTRAP_TEST_CLASS(3, Large);
DEFINE_BOOTSTRAP_TEST_CLASS(4, Medium);
DEFINE_BOOTSTRAP_TEST_CLASS(4, Large);
DEFINE_BOOTSTRAP_TEST_CLASS(5, Medium);
DEFINE_BOOTSTRAP_TEST_CLASS(5, Large);
INSTANTIATE_BOOTSTRAP_TEST(3, Medium);
INSTANTIATE_BOOTSTRAP_TEST(3, Large);
INSTANTIATE_BOOTSTRAP_TEST(4, Medium);
INSTANTIATE_BOOTSTRAP_TEST(4, Large);
INSTANTIATE_BOOTSTRAP_TEST(5, Medium);
INSTANTIATE_BOOTSTRAP_TEST(5, Large);

TEST_P(BootstrapGold3StagesMedium, ModRaise) {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level != 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  const auto coeff_count = 2 * slot_count;

  std::vector<std::complex<double>> message(slot_count);

  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto raised =
      engine.mod_raise_(unit_ciphertext, bootstrap_key_->small_bootstrap_key_);
  auto slot = engine.coeff_to_slot(raised, conjugation_key_, bootstrap_key_);

  auto decrypted0 = engine.decrypt(slot.first, secret_key_);
  auto decrypted1 = engine.decrypt(slot.second, secret_key_);

  ASSERT_EQ(slot.first->moduli_id_, stage_count_ + 1);
  ASSERT_EQ(slot.second->moduli_id_, stage_count_ + 1);

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {

    ASSERT_NEAR(
        decrypted0[slot_index] * 2 * desilo::fhe::ROUND_BOUND,
        std::round(decrypted0[slot_index] * 2 * desilo::fhe::ROUND_BOUND),
        1e-1);
    ASSERT_NEAR(
        decrypted1[slot_index] * 2 * desilo::fhe::ROUND_BOUND,
        std::round(decrypted1[slot_index] * 2 * desilo::fhe::ROUND_BOUND),
        1e-1);
  }

  delete unit_ciphertext;
  delete raised;
  delete slot.first;
  delete slot.second;
}

TEST_P(BootstrapGold5StagesMedium, ModRaiseCiphertext) {
  const auto [level, slice_count, process_type] = GetParam();

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level);
  auto raised = engine.mod_raise(ciphertext, bootstrap_key_);

  EXPECT_EQ(raised->moduli_id(), 1);

  for (int slice_index = 0; slice_index < slice_count; slice_index++) {

    auto [slot_real, slot_imag] = engine.coeff_to_slot(
        raised->get(slice_index), conjugation_key_, bootstrap_key_);

    auto decrypted0 = engine.decrypt(slot_real, secret_key_);
    auto decrypted1 = engine.decrypt(slot_imag, secret_key_);

    for (int slot_index = 0; slot_index < slot_count; slot_index++) {

      ASSERT_NEAR(
          decrypted0[slot_index] * 2 * desilo::fhe::ROUND_BOUND,
          std::round(decrypted0[slot_index] * 2 * desilo::fhe::ROUND_BOUND),
          1e-1);
      ASSERT_NEAR(
          decrypted1[slot_index] * 2 * desilo::fhe::ROUND_BOUND,
          std::round(decrypted1[slot_index] * 2 * desilo::fhe::ROUND_BOUND),
          1e-1);
    }

    const auto precomputed = desilo::fhe::CKKSPrecomputed(config);

    EXPECT_NEAR(raised->ckks_scale(), precomputed.scale_ * precomputed.scale_,
                1e-12);

    delete slot_real;
    delete slot_imag;
  }

  delete ciphertext;
  delete raised;
}

BOOTSTRAP_TEST(CoeffToSlot, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level == 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  const auto coeff_count = 2 * slot_count;

  std::vector<std::complex<double>> message(slot_count);

  initiate_message(message, 3);

  std::vector<std::complex<double>> twiddle_factor;
  const double unit_angle = -2 * std::numbers::pi / coeff_count;
  for (int index = 0; index < coeff_count; index++) {
    const double angle = index * unit_angle;
    twiddle_factor.push_back(
        std::complex<double>(std::cos(angle), std::sin(angle)));
  }

  auto expected = desilo::fhe::encode_complex(
      message.data(), twiddle_factor.data(), slot_count, 1);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto slot =
      engine.coeff_to_slot(unit_ciphertext, conjugation_key_, bootstrap_key_);

  auto decrypted0 = engine.decrypt(slot.first, secret_key_);
  auto decrypted1 = engine.decrypt(slot.second, secret_key_);

  ASSERT_EQ(slot.first->moduli_id_, stage_count_ + 1);
  ASSERT_EQ(slot.second->moduli_id_, stage_count_ + 1);

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {

    const int reversed_slot_index =
        desilo::fhe::reverse_integer_bits(slot_index, 15);

    ASSERT_NEAR(decrypted0[reversed_slot_index],
                expected[slot_index] / desilo::fhe::ROUND_BOUND, 1e-3);

    ASSERT_NEAR(decrypted1[reversed_slot_index],
                expected[slot_count + slot_index] / desilo::fhe::ROUND_BOUND,
                1e-3);
  }

  delete[] expected;
  delete unit_ciphertext;
  delete slot.first;
  delete slot.second;
});

BOOTSTRAP_TEST(SlotToCoeff, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level == 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  const auto coeff_count = 2 * slot_count;

  std::vector<double> message0(slot_count);
  std::vector<double> message1(slot_count);

  initiate_message(message0, 3);
  initiate_message(message1, 3);

  double message[2 * slot_count];
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {

    const int reversed_slot_index =
        desilo::fhe::reverse_integer_bits(slot_index, 15);
    message[reversed_slot_index] = message0[slot_index];
    message[slot_count + reversed_slot_index] = message1[slot_index];
  }

  const auto expected = desilo::fhe::decode_complex(message, coeff_count, 1);

  int level_after_round = level - 9 - stage_count_;
  auto unit_ciphertext0 =
      engine.encrypt_unit(message0, public_key_, level_after_round);
  auto unit_ciphertext1 =
      engine.encrypt_unit(message1, public_key_, level_after_round);
  auto coeff = engine.slot_to_coeff(unit_ciphertext0, unit_ciphertext1,
                                    conjugation_key_, bootstrap_key_);

  auto decrypted = engine.decrypt_complex(coeff, secret_key_);

  ASSERT_EQ(coeff->moduli_id_, 1 + 9 + stage_count_ * 2);

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    ASSERT_NEAR(decrypted[slot_index].real(), expected[slot_index].real(),
                1e-1);
    ASSERT_NEAR(decrypted[slot_index].imag(), expected[slot_index].imag(),
                1e-1);
  }

  delete[] expected;
  delete unit_ciphertext0;
  delete unit_ciphertext1;
  delete coeff;
})

BOOTSTRAP_TEST(CoeffToSlotToCoeff, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (level == 0 || slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto slot =
      engine.coeff_to_slot(unit_ciphertext, conjugation_key_, bootstrap_key_);

  auto multiplied0 = engine.multiply(slot.first, desilo::fhe::ROUND_BOUND);
  auto multiplied1 = engine.multiply(slot.second, desilo::fhe::ROUND_BOUND);
  auto leveled_down0 = engine.level_down(multiplied0, 16 - stage_count_);
  auto leveled_down1 = engine.level_down(multiplied1, 16 - stage_count_);

  auto coeff = engine.slot_to_coeff(leveled_down0, leveled_down1,
                                    conjugation_key_, bootstrap_key_);
  auto decrypted = engine.decrypt_complex(coeff, secret_key_);

  expect_complex_vector_near(decrypted, message, slot_count, 1e-1);

  delete unit_ciphertext;
  delete slot.first;
  delete slot.second;
  delete multiplied0;
  delete multiplied1;
  delete leveled_down0;
  delete leveled_down1;
  delete coeff;
})

BOOTSTRAP_TEST(BootstrapUnitCiphertext, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  if (slice_count > 1) {
    GTEST_SKIP() << "Parameter is Not relevant to this test.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto bootstrapped = engine.bootstrap(unit_ciphertext, relinearization_key_,
                                       conjugation_key_, bootstrap_key_);
  auto decrypted = engine.decrypt(bootstrapped, secret_key_);

  EXPECT_EQ(bootstrapped->level_, 16 - stage_count_ * 2);
  expect_vector_near(decrypted, message, slot_count, 1e-2);

  delete unit_ciphertext;
  delete bootstrapped;
})

BOOTSTRAP_TEST(BootstrapCiphertext, {
  const auto level = std::get<0>(GetParam());
  const auto slice_count = std::get<1>(GetParam());
  const auto process_type = std::get<2>(GetParam());

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level);
  auto bootstrapped = engine.bootstrap(ciphertext, relinearization_key_,
                                       conjugation_key_, bootstrap_key_);
  auto decrypted = engine.decrypt(bootstrapped, secret_key_);

  EXPECT_EQ(bootstrapped->level(), 16 - stage_count_ * 2);
  expect_vector_near(decrypted, message, slot_count, 1e-2);

  delete ciphertext;
  delete bootstrapped;
})
