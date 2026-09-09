#include "ckks/config.h"
#include "ckks/core/macro.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class CKKSCore : public testing::TestWithParam<
                     std::tuple<desilo::fhe::CKKSConfig, int, int>> {};

INSTANTIATE_TEST_CASE_P(
    , CKKSCore,
    testing::Values(
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("iron"), 5, 3),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("bronze"), 10, 8),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("silver"), 21, 9),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("gold"), 42, 10),
        std::make_tuple(desilo::fhe::CKKSConfig::from_tier("platinum"), 85, 13),
        std::make_tuple(desilo::fhe::CKKSConfig::for_bootstrap(), 32, 7)),
    [](const testing::TestParamInfo<CKKSCore::ParamType> &info) {
      const auto config = std::get<0>(info.param);
      return print_tier(config.log_coeff_count_) +
             print_scheme_preset(config.scheme_preset_);
    });

TEST_P(CKKSCore, ConstructCKKSCore) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
}

TEST_P(CKKSCore, CreateSecretKey) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();

  const auto secret_key = core.create_secret_key(max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(secret_key->flag_, desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(secret_key->chain_count_, prime_count);
  EXPECT_EQ(secret_key->polynomial_count(), 1);

  delete secret_key;
}

TEST_P(CKKSCore, CreateSecretKeyWithSecret) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();

  std::vector<int64_t> secret(core.get_slot_count() * 2);

  const auto secret_key = core.create_secret_key(max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(secret_key->flag_, desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(secret_key->chain_count_, prime_count);
  EXPECT_EQ(secret_key->polynomial_count(), 1);

  delete secret_key;
}

TEST_P(CKKSCore, CreateSparseSecretKey) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  const int hamming_weight = 128;

  const auto secret_key =
      core.create_sparse_secret_key(hamming_weight, max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(secret_key->flag_, desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::SPARSE |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(secret_key->chain_count_, prime_count);
  EXPECT_EQ(secret_key->polynomial_count(), 1);

  delete secret_key;
}

TEST_P(CKKSCore, CreatePublicKey) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(public_key->chain_count_,
            prime_count - config.special_prime_count_);
  EXPECT_EQ(public_key->polynomial_count(), 2);

  delete secret_key;
  delete public_key;
}

TEST_P(CKKSCore, CreateRelinearizationKey) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  auto max_key_switching_level = core.parameters_.get_max_key_switching_level();

  const auto secret_key = core.create_secret_key(max_level);
  const auto relinearization_key =
      core.create_relinearization_key(secret_key, max_key_switching_level);

  auto key_switching_key = relinearization_key->key_switching_key_;
  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  if (get_use_one_more_level(config)) {
    EXPECT_EQ(key_switching_key->chain_count_, prime_count - 1);
  } else {
    EXPECT_EQ(key_switching_key->chain_count_, prime_count);
  }
  EXPECT_EQ(key_switching_key->polynomial_count(), 2 * partition_count);

  delete secret_key;
  delete relinearization_key;
}

TEST_P(CKKSCore, CreateFixedRotationKey) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  auto max_key_switching_level = core.parameters_.get_max_key_switching_level();

  const auto secret_key = core.create_secret_key(max_level);

  const int delta = 2;
  const auto fixed_rotation_key = core.create_fixed_rotation_key(
      secret_key, max_key_switching_level, delta);

  EXPECT_EQ(fixed_rotation_key->delta_, delta);

  auto key_switching_key = fixed_rotation_key->key_switching_key_;
  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  if (get_use_one_more_level(config)) {
    EXPECT_EQ(key_switching_key->chain_count_, prime_count - 1);
  } else {
    EXPECT_EQ(key_switching_key->chain_count_, prime_count);
  }
  EXPECT_EQ(key_switching_key->polynomial_count(), 2 * partition_count);

  delete secret_key;
  delete fixed_rotation_key;
}

TEST_P(CKKSCore, CreateRotationKey) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  auto max_key_switching_level = core.parameters_.get_max_key_switching_level();

  int log_coeff_count = config.log_coeff_count_;

  const auto secret_key = core.create_secret_key(max_level);
  const auto rotation_key =
      core.create_rotation_key(secret_key, max_key_switching_level);

  auto fixed_rotation_keys = rotation_key->fixed_rotation_keys_;
  ASSERT_EQ(fixed_rotation_keys.size(), log_coeff_count - 1);

  for (int fixed_rotation_key_index = 0, delta = 1;
       fixed_rotation_key_index < log_coeff_count - 1;
       fixed_rotation_key_index++, delta <<= 1) {
    auto fixed_rotation_key = fixed_rotation_keys[fixed_rotation_key_index];
    auto key_switching_key = fixed_rotation_key->key_switching_key_;
    EXPECT_EQ(key_switching_key->scheme_preset_, config.scheme_preset_);
    if (get_use_one_more_level(config)) {
      EXPECT_EQ(key_switching_key->chain_count_, prime_count - 1);
    } else {
      EXPECT_EQ(key_switching_key->chain_count_, prime_count);
    }
    EXPECT_EQ(key_switching_key->polynomial_count(), 2 * partition_count);
    EXPECT_EQ(fixed_rotation_key->delta_, delta);
  }

  delete secret_key;
  delete rotation_key;
}

TEST_P(CKKSCore, CreateConjugationKey) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  auto max_key_switching_level = core.parameters_.get_max_key_switching_level();

  const auto secret_key = core.create_secret_key(max_level);
  const auto conjugation_key =
      core.create_conjugation_key(secret_key, max_key_switching_level);

  auto key_switching_key = conjugation_key->key_switching_key_;
  EXPECT_EQ(key_switching_key->scheme_preset_, config.scheme_preset_);
  if (get_use_one_more_level(config)) {
    EXPECT_EQ(key_switching_key->chain_count_, prime_count - 1);
  } else {
    EXPECT_EQ(key_switching_key->chain_count_, prime_count);
  }
  EXPECT_EQ(key_switching_key->polynomial_count(), 2 * partition_count);

  delete secret_key;
  delete conjugation_key;
}

TEST_P(CKKSCore, MakeSignedTile) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);

  const int log_slot_count = config.log_slot_count_;
  const int log_coeff_count = config.log_coeff_count_;
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto max_level = core.parameters_.get_max_level();
  const int moduli_id = max_level + 1;
  const int level = 0;
  const int chain_count = 1;
  const int coeff_count = 1 << log_coeff_count;
  std::vector<desilo::fhe::Polynomial *> polynomials{
      new desilo::fhe::Polynomial(flag, moduli_id, chain_count, coeff_count),
      new desilo::fhe::Polynomial(flag, moduli_id, chain_count, coeff_count)};

  int64_t first_large_prime;
  if (log_coeff_count == 13) {
    first_large_prime = 1152921504606830593;
  } else if (log_coeff_count == 14) {
    first_large_prime = 1152921504606748673;
  } else {
    first_large_prime = 1152921504606584833;
  }

  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    polynomials[0]->get(0)[coeff_index] = coeff_index;
    polynomials[1]->get(0)[coeff_index] = first_large_prime - coeff_index;
  }

  auto ciphertext = new desilo::fhe::UnitCiphertext(
      polynomials, flag, desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT,
      log_slot_count, log_coeff_count, config.special_prime_count_, moduli_id,
      level, chain_count, coeff_count);

  auto tiled = core.make_signed_tile(ciphertext);

  if (get_use_one_more_level(config)) {
    ASSERT_EQ(tiled->level_, max_level - 1);
  } else {
    ASSERT_EQ(tiled->level_, max_level);
  }

  std::vector<int64_t> q;

  if (log_coeff_count == 13) {
    q = {1099511922689, 1099510890497, 1152921504606830593};
  } else if (log_coeff_count == 14) {
    q = {1099510054913, 1099515691009, 1099508121601, 1099515789313,
         1099507695617, 1099516280833, 1099506515969, 1152921504606748673};
  } else if (log_coeff_count == 15) {
    q = {1099510054913, 1099515691009,      1099507695617, 1099516280833,
         1099506515969, 1099520606209,      1099504549889, 1099523555329,
         1099503894529, 1099527946241,      1099503370241, 1099529060353,
         1099498258433, 1099531223041,      1099469684737, 1099532009473,
         1099468767233, 1152921504606584833};
  } else if (log_coeff_count == 16) {
    q = {1099510054913,      1099515691009, 1099507695617, 1099516870657,
         1099506515969,      1099521458177, 1099503894529, 1099522375681,
         1099490000897,      1099523555329, 1099489607681, 1099525128193,
         1099486855169,      1099526176769, 1099484889089, 1099529060353,
         1099480956929,      1099535220737, 1099469684737, 1099536138241,
         1099468767233,      1099537580033, 1099461820417, 1099538104321,
         1099457495041,      1099540725761, 1099455004673, 1099540856833,
         1099454218241,      1099591974913, 1099453431809, 1099629723649,
         1099451465729,      1099630510081, 1099451072513, 1099630903297,
         1152921504606584833};
    if (get_use_bootstrap(config)) {
      q = {18014398506729473,   18014398514987009,   18014398505943041,
           18014398516559873,   18014398496243713,   18014398539104257,
           18014398495457281,   18014398539497473,   18014398479204353,
           18014398539890689,   18014398452203521,   18014398544084993,
           18014398443552769,   18014398545788929,   18014398438440961,
           18014398546051073,   18014398434902017,   18014398547623937,
           18014398432018433,   18014398661394433,   18014398431363073,
           18014398665195521,   18014398431232001,   18014398666899457,
           18014398388371457,   18014398674239489,   1152921504606584833,
           1152921504598720513, 1152921504597016577, 1152921504595968001,
           1152921504592822273};
    }
  }

  if (log_coeff_count < 17) {
    for (int chain_index = 0; chain_index < tiled->chain_count_;
         chain_index++) {
      for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
        ASSERT_EQ(tiled->get(0, chain_index)[coeff_index],
                  coeff_index % q[chain_index]);
        ASSERT_EQ(tiled->get(1, chain_index)[coeff_index],
                  (q[chain_index] - coeff_index) % q[chain_index]);
      }
    }
  }

  delete ciphertext;
  delete tiled;
}

TEST(CKKSCoreBootstrap, GetModRaiseRatio) {
  auto core = desilo::fhe::CKKSCore(desilo::fhe::CKKSConfig::for_bootstrap());

  auto ratio = core.get_mod_raise_ratio();

  EXPECT_EQ(ratio, 281474976710720);
}

TEST(CKKSCoreBootstrap, GetNormalizeRatio) {
  auto core = desilo::fhe::CKKSCore(desilo::fhe::CKKSConfig::for_bootstrap());

  auto ratio = core.get_normalize_ratio();

  EXPECT_EQ(ratio, 64);
}

TEST(CKKSCoreDefault, Construct) {
  auto core = desilo::fhe::CKKSCore();

  EXPECT_EQ(core.get_slot_count(), 8192);
  EXPECT_EQ(core.parameters_.get_max_level(), 7);
}

TEST_P(CKKSCore, Decompose) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(public_key->chain_count_,
            prime_count - config.special_prime_count_);
  EXPECT_EQ(public_key->polynomial_count(), 2);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto decomposed = core.decompose(ciphertext);

  EXPECT_EQ(decomposed->level_, max_level - 1);
  EXPECT_EQ(decomposed->flag_, desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(decomposed->polynomial_count(), partition_count);

  delete secret_key;
  delete public_key;
  delete plaintext;
  delete ciphertext;
  delete decomposed;
}

TEST_P(CKKSCore, DecomposeDepth2) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  auto level = max_level - 2;
  const bool include_special = false;

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);

  EXPECT_EQ(secret_key->scheme_preset_, config.scheme_preset_);
  EXPECT_EQ(public_key->chain_count_,
            prime_count - config.special_prime_count_);
  EXPECT_EQ(public_key->polynomial_count(), 2);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  const auto plaintext = core.encode(message, level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto decomposed = core.decompose(ciphertext);

  EXPECT_EQ(decomposed->level_, level);
  EXPECT_EQ(decomposed->flag_, desilo::fhe::DataFlag::NTT_FORM |
                                   desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  if (config.log_coeff_count_ == 13 || config.log_coeff_count_ == 14 ||

      (config.log_coeff_count_ == 16 &&
       config.scheme_preset_ ==
           desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT)) {
    EXPECT_EQ(decomposed->polynomial_count(), partition_count - 1);
  } else {
    EXPECT_EQ(decomposed->polynomial_count(), partition_count);
  }

  delete secret_key;
  delete public_key;
  delete plaintext;
  delete ciphertext;
  delete decomposed;
}

TEST_P(CKKSCore, CreateKeySwitcherFromDecomposedCiphertext) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);
  const int delta = 2;
  const auto fixed_rotation_key =
      core.create_fixed_rotation_key(secret_key, max_level, delta);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto decomposed = core.decompose(ciphertext);
  const auto key_switcher = core.create_key_switcher(
      decomposed, fixed_rotation_key->key_switching_key_);

  EXPECT_EQ(key_switcher->level_, max_level - 1);
  EXPECT_EQ(key_switcher->flag_, desilo::fhe::DataFlag::NTT_FORM |
                                     desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(key_switcher->polynomial_count(), 2);

  delete secret_key;
  delete public_key;
  delete fixed_rotation_key;
  delete plaintext;
  delete ciphertext;
  delete decomposed;
  delete key_switcher;
}

TEST_P(CKKSCore, CreateKeySwitcherForRotate) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);
  const int delta = 2;
  const auto fixed_rotation_key =
      core.create_fixed_rotation_key(secret_key, max_level, delta);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 2);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto decomposed = core.decompose(ciphertext);
  const auto rotate_key_switcher = core.create_key_switcher_for_rotate(
      ciphertext, decomposed, fixed_rotation_key);

  EXPECT_EQ(rotate_key_switcher->level_, max_level - 1);
  EXPECT_EQ(rotate_key_switcher->flag_,
            desilo::fhe::DataFlag::NTT_FORM |
                desilo::fhe::DataFlag::INCLUDE_SPECIAL);
  EXPECT_EQ(rotate_key_switcher->polynomial_count(), 2);

  delete secret_key;
  delete public_key;
  delete fixed_rotation_key;
  delete plaintext;
  delete ciphertext;
  delete decomposed;
  delete rotate_key_switcher;
}

TEST_P(CKKSCore, KeySwitchModDown) {
  const auto [config, prime_count, partition_count] = GetParam();
  auto core = desilo::fhe::CKKSCore(config);
  auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  const auto secret_key = core.create_secret_key(max_level);
  const auto public_key = core.create_public_key(secret_key, max_level);
  const int delta = 2;
  const auto fixed_rotation_key =
      core.create_fixed_rotation_key(secret_key, max_level, delta);

  const auto slot_count = core.get_slot_count();
  std::vector<double> message(slot_count);
  initiate_message(message, 3);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key);
  const auto decomposed = core.decompose(ciphertext);
  const auto key_switcher = core.create_key_switcher_for_rotate(
      ciphertext, decomposed, fixed_rotation_key);
  const auto mod_down = core.key_switch_mod_down(ciphertext, key_switcher);

  EXPECT_EQ(mod_down->level_, max_level - 1);
  EXPECT_EQ(mod_down->flag_, desilo::fhe::DataFlag::NONE);
  EXPECT_EQ(mod_down->polynomial_count(), 2);

  delete secret_key;
  delete public_key;
  delete fixed_rotation_key;
  delete plaintext;
  delete ciphertext;
  delete decomposed;
  delete key_switcher;
  delete mod_down;
}

TEST(CKKSCorePad, DoubleVector) {
  const auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  auto core = desilo::fhe::CKKSCore(config);
  std::vector<double> input(4, 1);
  std::vector<double> output = core.pad(input, 8);

  std::vector<double> expected = {1, 1, 1, 1, 0, 0, 0, 0};

  expect_vector_equals<double>(output, expected, 8);
}

TEST(CKKSCorePad, ComplexVector) {
  const auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
  auto core = desilo::fhe::CKKSCore(config);
  std::vector<std::complex<double>> input = {
      std::complex(1.0, 1.0), std::complex(1.0, 1.0), std::complex(1.0, 1.0),
      std::complex(1.0, 1.0)};
  std::vector<std::complex<double>> output = core.pad(input, 8);

  std::vector<std::complex<double>> expected = {
      std::complex(1.0, 1.0), std::complex(1.0, 1.0), std::complex(1.0, 1.0),
      std::complex(1.0, 1.0), std::complex(0.0, 0.0), std::complex(0.0, 0.0),
      std::complex(0.0, 0.0), std::complex(0.0, 0.0)};

  expect_vector_equals<std::complex<double>>(output, expected, 8);
}
