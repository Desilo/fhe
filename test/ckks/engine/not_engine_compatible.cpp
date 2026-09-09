#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"

const auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
const auto log_slot_count = 13;
const auto log_coeff_count = 14;
const auto special_prime_count = 1;

class NotEngineCompatible
    : public testing::TestWithParam<
          std::tuple<desilo::fhe::SchemePreset, int, int, int>> {
public:
  static void SetUpTestSuite() { engine_ = new desilo::fhe::CKKSEngine(); }

  static void TearDownTestSuite() {
    delete engine_;
    engine_ = nullptr;
  }

  static desilo::fhe::CKKSEngine *engine_;
};

desilo::fhe::CKKSEngine *NotEngineCompatible::engine_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    , NotEngineCompatible,
    testing::Values(std::make_tuple(scheme_preset, 13, 13, 1),
                    std::make_tuple(scheme_preset, 12, 14, 1),
                    std::make_tuple(scheme_preset, 13, 14, 2),
                    std::make_tuple(desilo::fhe::SchemePreset::NONE, 13, 14,
                                    1)),
    [](const testing::TestParamInfo<NotEngineCompatible::ParamType> &info) {
      return print_scheme_preset(std::get<0>(info.param)) +
             std::to_string(std::get<1>(info.param)) + "And" +
             std::to_string(std::get<2>(info.param)) + "And" +
             std::to_string(std::get<3>(info.param));
    });

TEST_P(NotEngineCompatible, SecretKeyOfCreatePublicKey) {
  const auto [bad_scheme_preset, bad_log_slot_count, bad_log_coeff_count,
              bad_special_prime_count] = GetParam();
  auto secret_key =
      get_dummy_secret_key(bad_scheme_preset, bad_log_slot_count,
                           bad_log_coeff_count, bad_special_prime_count);

  try {
    engine_->create_public_key(secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Public Key: the input secret key is not compatible "
                 "with this engine.",
                 e.what());
  }

  delete secret_key;
}

TEST_P(NotEngineCompatible, SecretKeyOfCreateConjugationKey) {
  const auto [bad_scheme_preset, bad_log_slot_count, bad_log_coeff_count,
              bad_special_prime_count] = GetParam();
  auto secret_key =
      get_dummy_secret_key(bad_scheme_preset, bad_log_slot_count,
                           bad_log_coeff_count, bad_special_prime_count);

  try {
    engine_->create_conjugation_key(secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Conjugation Key: the input secret key is not "
                 "compatible with this engine.",
                 e.what());
  }

  delete secret_key;
}

TEST_P(NotEngineCompatible, SecretKeyOfCreateRelinearizationKey) {
  const auto [bad_scheme_preset, bad_log_slot_count, bad_log_coeff_count,
              bad_special_prime_count] = GetParam();
  auto secret_key =
      get_dummy_secret_key(bad_scheme_preset, bad_log_slot_count,
                           bad_log_coeff_count, bad_special_prime_count);

  try {
    engine_->create_relinearization_key(secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Relinearization Key: the input secret key is not "
                 "compatible with this engine.",
                 e.what());
  }

  delete secret_key;
}

TEST_P(NotEngineCompatible, SecretKeyOfCreateFixedRotationKey) {
  const auto [bad_scheme_preset, bad_log_slot_count, bad_log_coeff_count,
              bad_special_prime_count] = GetParam();
  auto secret_key =
      get_dummy_secret_key(bad_scheme_preset, bad_log_slot_count,
                           bad_log_coeff_count, bad_special_prime_count);
  const int delta = 1;

  try {
    engine_->create_fixed_rotation_key(secret_key, delta);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Fixed Rotation Key: the input secret key is not "
                 "compatible with this engine.",
                 e.what());
  }

  delete secret_key;
}

TEST_P(NotEngineCompatible, SecretKeyOfCreateRotationKey) {
  const auto [bad_scheme_preset, bad_log_slot_count, bad_log_coeff_count,
              bad_special_prime_count] = GetParam();
  auto secret_key =
      get_dummy_secret_key(bad_scheme_preset, bad_log_slot_count,
                           bad_log_coeff_count, bad_special_prime_count);

  try {
    engine_->create_rotation_key(secret_key);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Create Rotation Key: the input secret key is not compatible "
                 "with this engine.",
                 e.what());
  }

  delete secret_key;
}
