#include <algorithm>

#include "ckks/encode.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/precomputed.h"
#include "common/common.h"
#include "common/test.h"
#include "operation/bootstrap.h"

class Silver : public testing::TestWithParam<int> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::from_tier("silver");

    auto engine = desilo::fhe::CKKSEngine(config);

    secret_key_ = engine.create_secret_key();
    public_key_ = engine.create_public_key(secret_key_);
    relinearization_key_ = engine.create_relinearization_key(secret_key_);
    conjugation_key_ = engine.create_conjugation_key(secret_key_);
    rotation_key_ = engine.create_rotation_key(secret_key_);
  }

  static void TearDownTestSuite() {
    delete secret_key_;
    delete public_key_;
    delete relinearization_key_;
    delete conjugation_key_;
    delete rotation_key_;
    secret_key_ = nullptr;
    public_key_ = nullptr;
    relinearization_key_ = nullptr;
    conjugation_key_ = nullptr;
    rotation_key_ = nullptr;
  }

  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::PublicKey *public_key_;
  static desilo::fhe::RelinearizationKey *relinearization_key_;
  static desilo::fhe::ConjugationKey *conjugation_key_;
  static desilo::fhe::RotationKey *rotation_key_;
};

desilo::fhe::SecretKey *Silver::secret_key_ = nullptr;
desilo::fhe::PublicKey *Silver::public_key_ = nullptr;
desilo::fhe::RelinearizationKey *Silver::relinearization_key_ = nullptr;
desilo::fhe::ConjugationKey *Silver::conjugation_key_ = nullptr;
desilo::fhe::RotationKey *Silver::rotation_key_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSEngineBootstrap, Silver, PROCESS_TEST,
    [](const testing::TestParamInfo<Silver::ParamType> &info) {
      return print_process_type(info.param);
    });

TEST_P(Silver, CoeffToSlot) {
  const auto process_type = GetParam();
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const int stage_count = 7;
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

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  auto [slot_real, slot_imag] = engine.coeff_to_slot(
      unit_ciphertext, conjugation_key_, rotation_key_, stage_count);

  auto decrypted0 = engine.decrypt(slot_real, secret_key_);
  auto decrypted1 = engine.decrypt(slot_imag, secret_key_);

  ASSERT_EQ(slot_real->moduli_id_, stage_count + 1);
  ASSERT_EQ(slot_imag->moduli_id_, stage_count + 1);

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {

    const int reversed_slot_index =
        desilo::fhe::reverse_integer_bits(slot_index, 14);

    ASSERT_NEAR(decrypted0[reversed_slot_index],
                expected[slot_index] / desilo::fhe::ROUND_BOUND, 1e-3);

    ASSERT_NEAR(decrypted1[reversed_slot_index],
                expected[slot_count + slot_index] / desilo::fhe::ROUND_BOUND,
                1e-3);
  }

  delete[] expected;
  delete unit_ciphertext;
  delete slot_real;
  delete slot_imag;
}

TEST_P(Silver, SlotToCoeff) {
  const auto process_type = GetParam();
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const int stage_count = 7;

  const auto slot_count = engine.get_slot_count();
  const auto coeff_count = 2 * slot_count;

  std::vector<double> message0(slot_count);
  std::vector<double> message1(slot_count);

  initiate_message(message0, 3);
  initiate_message(message1, 3);

  double message[2 * slot_count];
  for (int slot_index = 0; slot_index < slot_count; slot_index++) {

    const int reversed_slot_index =
        desilo::fhe::reverse_integer_bits(slot_index, 14);
    message[reversed_slot_index] = message0[slot_index];
    message[slot_count + reversed_slot_index] = message1[slot_index];
  }

  const auto expected = desilo::fhe::decode_complex(message, coeff_count, 1);

  auto unit_ciphertext0 = engine.encrypt_unit(message0, public_key_);
  auto unit_ciphertext1 = engine.encrypt_unit(message1, public_key_);
  auto coeff =
      engine.slot_to_coeff(unit_ciphertext0, unit_ciphertext1, conjugation_key_,
                           rotation_key_, stage_count);

  auto decrypted = engine.decrypt_complex(coeff, secret_key_);

  ASSERT_EQ(coeff->moduli_id_, stage_count + 1);

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
}

TEST_P(Silver, CoeffToSlotToCoeff) {
  const auto process_type = GetParam();
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const int stage_count = 7;

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 3);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  auto [slot_real, slot_imag] = engine.coeff_to_slot(
      unit_ciphertext, conjugation_key_, rotation_key_, stage_count);

  auto decrypted_temp0 = engine.decrypt(slot_real, secret_key_);
  auto decrypted_temp1 = engine.decrypt(slot_imag, secret_key_);
  auto unit_ciphertext_temp0 =
      engine.encrypt_unit(decrypted_temp0, public_key_);
  auto unit_ciphertext_temp1 =
      engine.encrypt_unit(decrypted_temp1, public_key_);

  auto multiplied0 =
      engine.multiply(unit_ciphertext_temp0, desilo::fhe::ROUND_BOUND);
  auto multiplied1 =
      engine.multiply(unit_ciphertext_temp1, desilo::fhe::ROUND_BOUND);

  auto coeff = engine.slot_to_coeff(multiplied0, multiplied1, conjugation_key_,
                                    rotation_key_, stage_count);
  auto decrypted = engine.decrypt_complex(coeff, secret_key_);

  expect_complex_vector_near(decrypted, message, slot_count, 1e-1);

  delete unit_ciphertext;
  delete slot_real;
  delete slot_imag;
  delete unit_ciphertext_temp0;
  delete unit_ciphertext_temp1;
  delete multiplied0;
  delete multiplied1;
  delete coeff;
}

TEST_P(Silver, Round) {
  const auto process_type = GetParam();
  auto config = desilo::fhe::CKKSConfig::from_tier("silver");
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const int k = 28;

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  std::vector<double> expected(slot_count);

  for (int slot_index = 0; slot_index < slot_count; slot_index++) {
    const double integer_part = slot_index % (2 * k - 1) - k + 1;
    const double decimal_part = (slot_index % 5 - 2) / 100;
    expected[slot_index] = integer_part;
    message[slot_index] = (integer_part + decimal_part) / k;
  }

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_);
  auto integer_part = engine.round(unit_ciphertext, relinearization_key_);
  auto decrypted = engine.decrypt(integer_part, secret_key_);

  ASSERT_EQ(integer_part->moduli_id_, 9);

  expect_vector_near(decrypted, expected, slot_count, 1e-4);

  delete unit_ciphertext;
  delete integer_part;
}

class Gold : public testing::TestWithParam<std::tuple<int, int, int, int>> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::for_bootstrap();

    auto engine = desilo::fhe::CKKSEngine(config);

    secret_key_ = engine.create_secret_key();
    public_key_ = engine.create_public_key(secret_key_);
    relinearization_key_ = engine.create_relinearization_key(secret_key_, 22);
    conjugation_key_ = engine.create_conjugation_key(secret_key_, 22);
    rotation_key_ = engine.create_rotation_key(secret_key_, 25);
    small_bootstrap_key_ = engine.create_small_bootstrap_key(secret_key_);
  }

  static void TearDownTestSuite() {
    delete secret_key_;
    delete public_key_;
    delete relinearization_key_;
    delete conjugation_key_;
    delete rotation_key_;
    delete small_bootstrap_key_;
    secret_key_ = nullptr;
    public_key_ = nullptr;
    relinearization_key_ = nullptr;
    conjugation_key_ = nullptr;
    rotation_key_ = nullptr;
    small_bootstrap_key_ = nullptr;
  }

  static desilo::fhe::SecretKey *secret_key_;
  static desilo::fhe::PublicKey *public_key_;
  static desilo::fhe::RelinearizationKey *relinearization_key_;
  static desilo::fhe::ConjugationKey *conjugation_key_;
  static desilo::fhe::RotationKey *rotation_key_;
  static desilo::fhe::SmallBootstrapKey *small_bootstrap_key_;
};

desilo::fhe::SecretKey *Gold::secret_key_ = nullptr;
desilo::fhe::PublicKey *Gold::public_key_ = nullptr;
desilo::fhe::RelinearizationKey *Gold::relinearization_key_ = nullptr;
desilo::fhe::ConjugationKey *Gold::conjugation_key_ = nullptr;
desilo::fhe::RotationKey *Gold::rotation_key_ = nullptr;
desilo::fhe::SmallBootstrapKey *Gold::small_bootstrap_key_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSEngineBootstrap, Gold,
    testing::Combine(testing::Values(0, 25), testing::Values(3, 4, 5),
                     testing::Values(1, 2),
#ifdef DESILO_FHE_LARGE_TEST
                     PROCESS_TEST
#else

                     testing::Values(1, 2)
#endif
                     ),
    [](const testing::TestParamInfo<Gold::ParamType> &info) {
      return print_level(std::get<0>(info.param)) + "With" +
             std::to_string(std::get<1>(info.param)) + "StagesSmall" +
             print_slice_count(std::get<2>(info.param)) +
             print_process_type(std::get<3>(info.param));
    });

TEST_P(Gold, ModRaise) {
  const auto [level, stage_count, slice_count, process_type] = GetParam();

  if (stage_count < 5) {
    GTEST_SKIP() << "Only test with stage count 5.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  std::vector<std::complex<double>> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level);
  auto raised = engine.mod_raise(ciphertext, small_bootstrap_key_);

  EXPECT_EQ(raised->moduli_id(), 1);

  for (int slice_index = 0; slice_index < slice_count; slice_index++) {

    auto [slot_real, slot_imag] = engine.coeff_to_slot(
        raised->get(slice_index), conjugation_key_, rotation_key_, stage_count);

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

TEST_P(Gold, BootstrapUnitCiphertext) {
  const auto [level, stage_count, slice_count, process_type] = GetParam();

  if (slice_count > 1) {
    GTEST_SKIP() << "Irrelevant slice count.";
  }

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  auto unit_ciphertext = engine.encrypt_unit(message, public_key_, level);
  auto bootstrapped =
      engine.bootstrap(unit_ciphertext, relinearization_key_, conjugation_key_,
                       rotation_key_, small_bootstrap_key_, stage_count);
  auto decrypted = engine.decrypt(bootstrapped, secret_key_);

  EXPECT_EQ(bootstrapped->level_, 16 - stage_count * 2);
  expect_vector_near(decrypted, message, slot_count, 1e-2);

  delete unit_ciphertext;
  delete bootstrapped;
}

TEST_P(Gold, BootstrapCiphertext) {
  const auto [level, stage_count, slice_count, process_type] = GetParam();
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  set_process_type(config, process_type);
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto slot_count = engine.get_slot_count();
  std::vector<double> message(slot_count * slice_count);
  initiate_sliced_message(message, slice_count, slot_count);

  auto ciphertext = engine.encrypt(message, public_key_, level);
  auto bootstrapped =
      engine.bootstrap(ciphertext, relinearization_key_, conjugation_key_,
                       rotation_key_, small_bootstrap_key_, stage_count);
  auto decrypted = engine.decrypt(bootstrapped, secret_key_);

  EXPECT_EQ(bootstrapped->level(), 16 - stage_count * 2);
  expect_vector_near(decrypted, message, slot_count * slice_count, 1e-2);

  delete ciphertext;
  delete bootstrapped;
}
