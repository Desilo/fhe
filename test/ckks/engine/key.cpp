#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

SETUP_ENGINE_TEST_SP1(
    SP0, [](const std::tuple<int> &param) { return "0"; },

    testing::Values(1));

ALL_ENGINE_TEST(SP0, CreateKeys, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto secret_key = engine.create_secret_key();
  const auto public_key = engine.create_public_key(secret_key);
  const auto relinearization_key =
      engine.create_relinearization_key(secret_key);
  const auto conjugation_key = engine.create_conjugation_key(secret_key);
  const int delta = 1;
  const auto fixed_rotation_key =
      engine.create_fixed_rotation_key(secret_key, delta);
  const auto rotation_key = engine.create_rotation_key(secret_key);

  delete secret_key;
  delete public_key;
  delete relinearization_key;
  delete conjugation_key;
  delete fixed_rotation_key;
  delete rotation_key;
})

ALL_ENGINE_TEST(SP0, CreateCustomSecretKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  std::vector<int64_t> secret(engine.get_coeff_count());

  const auto secret_key = engine.create_secret_key(secret);

  delete secret_key;
})

ALL_ENGINE_TEST(SP0, CreatePaddedCustomSecretKey, {
  auto engine = desilo::fhe::CKKSEngine(config_);

  std::vector<int64_t> secret(engine.get_slot_count());

  const auto secret_key = engine.create_secret_key(secret);

  delete secret_key;
})

TEST(CreateBootstrapKey, Gold3StagesMedium) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto secret_key = engine.create_secret_key();

  int stage_count = 3;
  const auto bootstrap_key =
      engine.create_bootstrap_key(secret_key, stage_count, "medium");

  delete secret_key;
  delete bootstrap_key;
}

TEST(CreateBootstrapKey, Gold3StagesLarge) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto secret_key = engine.create_secret_key();

  int stage_count = 3;
  const auto bootstrap_key =
      engine.create_bootstrap_key(secret_key, stage_count, "large");

  delete secret_key;
  delete bootstrap_key;
}

TEST(CreateSmallBootstrapKey, Gold3StagesSmall) {
  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  auto engine = desilo::fhe::CKKSEngine(config);

  const auto secret_key = engine.create_secret_key();

  const auto small_bootstrap_key =
      engine.create_small_bootstrap_key(secret_key);

  delete secret_key;
  delete small_bootstrap_key;
}

SETUP_DEFAULT_ENGINE_TEST_SP2(
    CreateFixedRotationKey,
    [](const std::tuple<int, int> &param) {
      return print_delta(std::get<0>(param));
    },

    testing::Values(std::make_tuple(1, 1), std::make_tuple(-1, 7),
                    std::make_tuple(8199, 7)));

DEFAULT_ENGINE_TEST(CreateFixedRotationKey, CreateFixedRotationKey, {
  const auto delta = std::get<0>(GetParam());
  auto normalized_delta = std::get<1>(GetParam());

  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto slot_count = engine.get_slot_count();

  normalized_delta %= slot_count;

  const auto fixed_rotation_key =
      engine.create_fixed_rotation_key(secret_key_, delta);

  EXPECT_EQ(fixed_rotation_key->delta_, normalized_delta);

  delete fixed_rotation_key;
})

class ToNormalizedDelta
    : public testing::TestWithParam<std::tuple<int, int, int, int>> {};

INSTANTIATE_TEST_CASE_P(
    , ToNormalizedDelta,

    testing::Values(
        std::make_tuple(1, 1, 1, 5), std::make_tuple(-1, 32767, 31, 5),
        std::make_tuple(32768, 0, 0, 5), std::make_tuple(1, 1, 1, 10),
        std::make_tuple(-1, 32767, 1023, 10), std::make_tuple(32768, 0, 0, 10),
        std::make_tuple(1, 1, 1, 14), std::make_tuple(-1, 32767, 16383, 14),
        std::make_tuple(32768, 0, 0, 14), std::make_tuple(1, 1, 1, 15),
        std::make_tuple(-1, 32767, 32767, 15),
        std::make_tuple(32768, 0, 0, 15)),
    [](const testing::TestParamInfo<ToNormalizedDelta::ParamType> &info) {
      return print_delta(std::get<0>(info.param)) +
             print_log_slot_count(std::get<3>(info.param));
    });

TEST_P(ToNormalizedDelta, ) {
  const auto delta = std::get<0>(GetParam());
  const auto expected_delta_by_half_coeff_count = std::get<1>(GetParam());
  const auto expected_delta_by_slot_count = std::get<2>(GetParam());
  const auto log_slot_count = std::get<3>(GetParam());

  auto config = desilo::fhe::CKKSConfig::for_bootstrap();
  config.log_slot_count_ = log_slot_count;

  auto engine = desilo::fhe::CKKSEngine(config);

  auto normalized_delta_by_half_coeff_count =
      engine.to_normalized_delta(delta, false);

  EXPECT_EQ(normalized_delta_by_half_coeff_count,
            expected_delta_by_half_coeff_count);

  auto normalized_delta_by_slot_count = engine.to_normalized_delta(delta, true);

  EXPECT_EQ(normalized_delta_by_slot_count, expected_delta_by_slot_count);
}
