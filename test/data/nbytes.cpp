#include "common/common.h"
#include "common/test.h"
#include "data/bootstrap.h"
#include "data/data.h"
#include "data/polynomial.h"
#include "parameter/permutation.h"

TEST(NBytes, Polynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const auto chain_count = 2;
  const auto coeff_count = 50;
  std::vector<int64_t *> chains(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    chains[chain_index] = new int64_t[coeff_count];
  }

  const auto polynomial =
      new desilo::fhe::Polynomial(chains, flag, moduli_id, coeff_count);

  EXPECT_EQ(polynomial->nbytes(), 856);

  delete polynomial;
}

TEST(NBytes, DoublePolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const auto coeff_count = 50;

  const auto buffer = new double[coeff_count];
  const auto polynomial =
      new desilo::fhe::DoublePolynomial(buffer, flag, moduli_id, coeff_count);

  EXPECT_EQ(polynomial->nbytes(), 456);

  delete polynomial;
}

TEST(NBytes, Data) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 3;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(109, 110, 111, 112);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1, polynomial2,
                                                     polynomial3};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  EXPECT_EQ(data->nbytes(), 336);

  delete data;
}

TEST(NBytes, RelinearizationKey) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 3;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(109, 110, 111, 112);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1, polynomial2,
                                                     polynomial3};

  auto key_switching_key = new desilo::fhe::KeySwitchingKey(
      polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
  auto relinearization_key =
      new desilo::fhe::RelinearizationKey(key_switching_key);

  EXPECT_EQ(relinearization_key->nbytes(), 352);

  delete relinearization_key;
}

TEST(NBytes, PermutationParameter) {
  auto parameters = desilo::fhe::PermutationParameters();

  parameters.values_.resize(4);

  EXPECT_EQ(parameters.nbytes(), 40);
}

TEST(NBytes, FixedRotationKey) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 3;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(109, 110, 111, 112);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1, polynomial2,
                                                     polynomial3};

  auto permutation = new desilo::fhe::PermutationParameters();
  auto sign = new desilo::fhe::PermutationParameters();

  permutation->values_.resize(coeff_count);
  sign->values_.resize(coeff_count);

  auto key_switching_key = new desilo::fhe::KeySwitchingKey(
      polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
  auto delta = 1;
  auto fixed_rotation_key = new desilo::fhe::FixedRotationKey(
      key_switching_key, permutation, sign, delta);

  EXPECT_EQ(fixed_rotation_key->nbytes(), 432);

  delete fixed_rotation_key;
}

TEST(NBytes, RotationKey) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 6;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(109, 110, 111, 112);
  auto polynomial4 = MAKE_POLYNOMIAL(201, 202, 203, 204);
  auto polynomial5 = MAKE_POLYNOMIAL(205, 206, 207, 208);
  auto polynomial6 = MAKE_POLYNOMIAL(209, 210, 211, 212);
  std::vector<desilo::fhe::Polynomial *> polynomials1 = {
      polynomial1, polynomial2, polynomial3};
  std::vector<desilo::fhe::Polynomial *> polynomials2 = {
      polynomial4, polynomial5, polynomial6};

  auto permutation1 = new desilo::fhe::PermutationParameters();
  auto sign1 = new desilo::fhe::PermutationParameters();

  auto permutation2 = new desilo::fhe::PermutationParameters();
  auto sign2 = new desilo::fhe::PermutationParameters();

  permutation1->values_.resize(coeff_count);
  sign1->values_.resize(coeff_count);
  permutation2->values_.resize(coeff_count);
  sign2->values_.resize(coeff_count);

  auto key_switching_key1 = new desilo::fhe::KeySwitchingKey(
      polynomials1, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
  int delta = 1;
  auto fixed_rotation_key1 = new desilo::fhe::FixedRotationKey(
      key_switching_key1, permutation1, sign1, delta);
  auto key_switching_key2 = new desilo::fhe::KeySwitchingKey(
      polynomials2, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
  delta = 2;
  auto fixed_rotation_key2 = new desilo::fhe::FixedRotationKey(
      key_switching_key2, permutation2, sign2, delta);
  std::vector<desilo::fhe::FixedRotationKey *> fixed_rotation_keys{
      fixed_rotation_key1, fixed_rotation_key2};

  auto rotation_key = new desilo::fhe::RotationKey(fixed_rotation_keys);

  EXPECT_EQ(rotation_key->nbytes(), 912);

  delete rotation_key;
}

TEST(NBytes, ConjugationKey) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 3;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(109, 110, 111, 112);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1, polynomial2,
                                                     polynomial3};

  auto permutation = new desilo::fhe::PermutationParameters();
  auto sign = new desilo::fhe::PermutationParameters();

  permutation->values_.resize(coeff_count);
  sign->values_.resize(coeff_count);

  auto key_switching_key = new desilo::fhe::KeySwitchingKey(
      polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
  auto conjugation_key =
      new desilo::fhe::ConjugationKey(key_switching_key, permutation, sign);

  EXPECT_EQ(conjugation_key->nbytes(), 432);

  delete conjugation_key;
}

TEST(NBytes, UnitPlaintext) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 1;
  long double ckks_scale = 1.23;
  auto polynomial = MAKE_POLYNOMIAL(101, 102, 103, 104);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial};

  auto unit_plaintext = new desilo::fhe::UnitPlaintext(
      polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);

  EXPECT_EQ(unit_plaintext->nbytes(), 176);

  delete unit_plaintext;
}

TEST(NBytes, UnitCiphertext) {
  std::string file_path = "/tmp/data_test_file";
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 4;
  int coeff_count = 2;
  int polynomial_count = 3;
  long double ckks_scale = 1.23;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104, 105, 106, 107, 108);
  auto polynomial2 = MAKE_POLYNOMIAL(201, 202, 203, 204, 205, 206, 207, 208);
  auto polynomial3 = MAKE_POLYNOMIAL(301, 302, 303, 304, 305, 306, 307, 308);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1, polynomial2,
                                                     polynomial3};

  auto unit_ciphertext = new desilo::fhe::UnitCiphertext(
      polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);

  EXPECT_EQ(unit_ciphertext->nbytes(), 464);

  delete unit_ciphertext;
}

TEST(NBytes, Plaintext) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 1;
  long double ckks_scale = 1.23;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(109, 110, 111, 112);
  std::vector<desilo::fhe::Polynomial *> polynomials1{polynomial1};
  std::vector<desilo::fhe::Polynomial *> polynomials2{polynomial2};
  std::vector<desilo::fhe::Polynomial *> polynomials3{polynomial3};

  auto unit_plaintext1 = new desilo::fhe::UnitPlaintext(
      polynomials1, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);
  auto unit_plaintext2 = new desilo::fhe::UnitPlaintext(
      polynomials2, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);
  auto unit_plaintext3 = new desilo::fhe::UnitPlaintext(
      polynomials3, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);
  auto plaintext = new desilo::fhe::Plaintext(
      {unit_plaintext1, unit_plaintext2, unit_plaintext3});

  EXPECT_EQ(plaintext->nbytes(), 632);

  delete plaintext;
}

TEST(NBytes, Ciphertext) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 2;
  long double ckks_scale = 1.23;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(201, 202, 203, 204);
  auto polynomial4 = MAKE_POLYNOMIAL(205, 206, 207, 208);
  auto polynomial5 = MAKE_POLYNOMIAL(301, 302, 303, 304);
  auto polynomial6 = MAKE_POLYNOMIAL(305, 306, 307, 308);
  std::vector<desilo::fhe::Polynomial *> polynomials1{polynomial1, polynomial2};
  std::vector<desilo::fhe::Polynomial *> polynomials2{polynomial3, polynomial4};
  std::vector<desilo::fhe::Polynomial *> polynomials3{polynomial5, polynomial6};

  auto unit_ciphertext1 = new desilo::fhe::UnitCiphertext(
      polynomials1, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);
  auto unit_ciphertext2 = new desilo::fhe::UnitCiphertext(
      polynomials2, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);
  auto unit_ciphertext3 = new desilo::fhe::UnitCiphertext(
      polynomials3, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count,
      ckks_scale);
  auto ciphertext = new desilo::fhe::Ciphertext(
      {unit_ciphertext1, unit_ciphertext2, unit_ciphertext3});

  EXPECT_EQ(ciphertext->nbytes(), 920);

  delete ciphertext;
}

TEST(NBytes, SmallBootstrapKey) {
  std::string file_path = "/tmp/data_test_file";
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 2;
  int coeff_count = 2;
  int polynomial_count = 6;
  auto polynomial1 = MAKE_POLYNOMIAL(101, 102, 103, 104);
  auto polynomial2 = MAKE_POLYNOMIAL(105, 106, 107, 108);
  auto polynomial3 = MAKE_POLYNOMIAL(109, 110, 111, 112);
  auto polynomial4 = MAKE_POLYNOMIAL(201, 202, 203, 204);
  auto polynomial5 = MAKE_POLYNOMIAL(205, 206, 207, 208);
  auto polynomial6 = MAKE_POLYNOMIAL(209, 210, 211, 212);
  std::vector<desilo::fhe::Polynomial *> polynomials1 = {
      polynomial1, polynomial2, polynomial3};
  std::vector<desilo::fhe::Polynomial *> polynomials2 = {
      polynomial4, polynomial5, polynomial6};

  auto key_switching_key1 = new desilo::fhe::KeySwitchingKey(
      polynomials1, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
  auto key_switching_key2 = new desilo::fhe::KeySwitchingKey(
      polynomials2, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);

  auto small_bootstrap_key = new desilo::fhe::SmallBootstrapKey(
      key_switching_key1, key_switching_key2);

  EXPECT_EQ(small_bootstrap_key->nbytes(), 688);

  delete small_bootstrap_key;
}
