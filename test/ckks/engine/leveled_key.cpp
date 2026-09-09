#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "ckks/engine/macro.h"
#include "common/common.h"

namespace ckks_engine_test {

SETUP_ENGINE_TEST_SP1(
    SP1,
    [](const std::tuple<int> &param) {
      return print_level_depth(std::get<0>(param));
    },
    testing::Values(0, 1, 2));

DEFAULT_ENGINE_TEST(SP1, CreateLeveledKeys, {
  const auto level = max_level_ - std::get<0>(GetParam());
  auto engine = desilo::fhe::CKKSEngine(config_);

  const auto secret_key = engine.create_secret_key(level);
  const auto public_key = engine.create_public_key(secret_key, level);

  auto key_switching_key_level = level;
  if (ONE_MORE_LEVEL && level == FULL_LEVEL) {
    key_switching_key_level -= 1;
  }

  const auto relinearization_key =
      engine.create_relinearization_key(secret_key, key_switching_key_level);
  const auto delta = 1;
  const auto fixed_rotation_key = engine.create_fixed_rotation_key(
      secret_key, delta, key_switching_key_level);
  const auto rotation_key =
      engine.create_rotation_key(secret_key, key_switching_key_level);
  const auto conjugation_key =
      engine.create_conjugation_key(secret_key, key_switching_key_level);

  EXPECT_EQ(secret_key->level_, level);
  EXPECT_EQ(public_key->level_, level);
  EXPECT_EQ(relinearization_key->level_, key_switching_key_level);
  EXPECT_EQ(fixed_rotation_key->level_, key_switching_key_level);
  EXPECT_EQ(rotation_key->level_, key_switching_key_level);
  EXPECT_EQ(conjugation_key->level_, key_switching_key_level);

  delete secret_key;
  delete public_key;
  delete relinearization_key;
  delete fixed_rotation_key;
  delete rotation_key;
  delete conjugation_key;
})

ALL_ENGINE_TEST(SP1, CreateCustomSecretKey, {
  const auto level = max_level_ - std::get<0>(GetParam());

  if (level < 0) {
    GTEST_SKIP() << "Impossible target level.";
  }

  auto engine = desilo::fhe::CKKSEngine(config_);

  std::vector<int64_t> secret(engine.get_coeff_count());

  const auto secret_key = engine.create_secret_key(secret, level);

  EXPECT_EQ(secret_key->level_, level);

  delete secret_key;
})

}
