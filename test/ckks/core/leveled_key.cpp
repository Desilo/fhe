#include "ckks/config.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class CKKSCoreLeveledKey
    : public testing::TestWithParam<std::tuple<int, int, int, int, int, int>> {
public:
  static std::string
  test_name(const testing::TestParamInfo<CKKSCoreLeveledKey::ParamType> &info) {
    const auto max_level = std::get<0>(info.param);
    return "Max" + print_level(max_level);
  }
};

INSTANTIATE_TEST_CASE_P(Iron, CKKSCoreLeveledKey,
                        testing::Values(

                            std::make_tuple(2, 1, 0, 5, 4, 6)),
                        CKKSCoreLeveledKey::test_name);

INSTANTIATE_TEST_CASE_P(Bronze, CKKSCoreLeveledKey,
                        testing::Values(

                            std::make_tuple(3, 3, 4, 6, 6, 10),
                            std::make_tuple(7, 6, 0, 10, 9, 16)),
                        CKKSCoreLeveledKey::test_name);

INSTANTIATE_TEST_CASE_P(Silver, CKKSCoreLeveledKey,
                        testing::Values(

                            std::make_tuple(8, 8, 9, 12, 12, 10),
                            std::make_tuple(17, 16, 0, 21, 20, 18)),
                        CKKSCoreLeveledKey::test_name);

INSTANTIATE_TEST_CASE_P(Gold, CKKSCoreLeveledKey,
                        testing::Values(

                            std::make_tuple(18, 18, 18, 24, 24, 10),
                            std::make_tuple(36, 35, 0, 42, 41, 20)),
                        CKKSCoreLeveledKey::test_name);

INSTANTIATE_TEST_CASE_P(Platinum, CKKSCoreLeveledKey,
                        testing::Values(

                            std::make_tuple(37, 37, 40, 45, 45, 14),
                            std::make_tuple(77, 76, 0, 85, 84, 26)),
                        CKKSCoreLeveledKey::test_name);

TEST_P(CKKSCoreLeveledKey, CreateSecretKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  const auto secret_key = core.create_secret_key(max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(secret_key->moduli_id_, moduli_id);
  EXPECT_EQ(secret_key->chain_count_, secret_key_chain_count);
  EXPECT_EQ(secret_key->polynomial_count(), 1);

  delete secret_key;
}

TEST_P(CKKSCoreLeveledKey, CreateCustomSecretKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  std::vector<int64_t> secret(core.get_slot_count() * 2);

  const auto secret_key = core.create_secret_key(secret, max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(secret_key->moduli_id_, moduli_id);
  EXPECT_EQ(secret_key->chain_count_, secret_key_chain_count);
  EXPECT_EQ(secret_key->polynomial_count(), 1);

  delete secret_key;
}

TEST_P(CKKSCoreLeveledKey, CreateSparseSecretKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);
  const int hamming_weight = 128;

  const auto secret_key =
      core.create_sparse_secret_key(hamming_weight, max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(secret_key->moduli_id_, moduli_id);
  EXPECT_EQ(secret_key->flag_, desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::SPARSE |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(secret_key->chain_count_, secret_key_chain_count);
  EXPECT_EQ(secret_key->polynomial_count(), 1);

  delete secret_key;
}

TEST_P(CKKSCoreLeveledKey, CreatePublicKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(public_key->moduli_id_, moduli_id);
  EXPECT_EQ(public_key->chain_count_,
            secret_key_chain_count - config.special_prime_count_);
  EXPECT_EQ(public_key->polynomial_count(), 2);

  delete secret_key;
  delete public_key;
}

TEST_P(CKKSCoreLeveledKey, CreateRelinearizationKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);
  const auto relinearization_key =
      core.create_relinearization_key(secret_key, max_key_switching_level);

  auto key_switching_key = relinearization_key->key_switching_key_;
  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(key_switching_key->chain_count_, key_switching_key_chain_count);
  EXPECT_EQ(key_switching_key->polynomial_count(),
            key_switching_key_polynomial_count);

  delete secret_key;
  delete public_key;
  delete relinearization_key;
}

TEST_P(CKKSCoreLeveledKey, CreateLeveledFixedRotationKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  const int delta = 2;
  const auto secret_key = core.create_secret_key(max_level);
  const auto fixed_rotation_key = core.create_fixed_rotation_key(
      secret_key, max_key_switching_level, delta);

  auto key_switching_key = fixed_rotation_key->key_switching_key_;
  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(key_switching_key->chain_count_, key_switching_key_chain_count);
  EXPECT_EQ(key_switching_key->polynomial_count(),
            key_switching_key_polynomial_count);

  delete secret_key;
  delete fixed_rotation_key;
}

TEST_P(CKKSCoreLeveledKey, CreateLeveledRotationKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);

#ifndef DESILO_FHE_LARGE_TEST
  if (config.log_coeff_count_ == 17) {
    GTEST_SKIP() << "Key size is too large for testing.";
  }
#endif

  auto core = desilo::fhe::CKKSCore(config);

  int log_coeff_count = config.log_coeff_count_;

  const auto secret_key = core.create_secret_key(max_level);
  const auto rotation_key =
      core.create_rotation_key(secret_key, max_key_switching_level);

  auto fixed_rotation_keys = rotation_key->fixed_rotation_keys_;
  ASSERT_EQ(fixed_rotation_keys.size(), log_coeff_count - 1);

  for (int fixed_rotation_key_index = 0, delta = 1;
       fixed_rotation_key_index < log_coeff_count - 1;
       fixed_rotation_key_index++, delta <<= 1) {
    auto &fixed_rotation_key = fixed_rotation_keys[fixed_rotation_key_index];
    auto key_switching_key = fixed_rotation_key->key_switching_key_;
    EXPECT_EQ(key_switching_key->scheme_preset_, config.scheme_preset_);
    EXPECT_EQ(key_switching_key->chain_count_, key_switching_key_chain_count);
    EXPECT_EQ(key_switching_key->polynomial_count(),
              key_switching_key_polynomial_count);
    EXPECT_EQ(fixed_rotation_key->delta_, delta);
  }

  delete secret_key;
  delete rotation_key;
}

TEST_P(CKKSCoreLeveledKey, CreateLeveledConjugationKey) {
  auto [max_level, max_key_switching_level, moduli_id, secret_key_chain_count,
        key_switching_key_chain_count, key_switching_key_polynomial_count] =
      GetParam();
  auto config = desilo::fhe::CKKSConfig::from_max_level(max_level);
  auto core = desilo::fhe::CKKSCore(config);

  const int delta = 2;
  const auto secret_key = core.create_secret_key(max_level);
  const auto conjugation_key =
      core.create_conjugation_key(secret_key, max_key_switching_level);

  auto key_switching_key = conjugation_key->key_switching_key_;
  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(key_switching_key->chain_count_, key_switching_key_chain_count);
  EXPECT_EQ(key_switching_key->polynomial_count(),
            key_switching_key_polynomial_count);

  delete secret_key;
  delete conjugation_key;
}
