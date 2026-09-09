#include <algorithm>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "common/common.h"
#include "common/test.h"
#include "data/bootstrap.h"
#include "data/bytearray.h"
#include "data/data.h"

TEST(Data, ConstructSinglePolynomial) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 1;
  int coeff_count = 8192;
  auto polynomial = MAKE_POLYNOMIAL(101);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  EXPECT_EQ(data->get(0, 0), polynomial->get(0));

  delete data;
}

TEST(Data, ConstructMultiplePolynomials) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 1;
  int coeff_count = 8192;
  auto polynomial1 = MAKE_POLYNOMIAL(101);
  auto polynomial2 = MAKE_POLYNOMIAL(102);
  auto polynomial3 = MAKE_POLYNOMIAL(103);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1, polynomial2,
                                                     polynomial3};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  EXPECT_EQ(data->get(0, 0), polynomial1->get(0));
  EXPECT_EQ(data->get(1, 0), polynomial2->get(0));
  EXPECT_EQ(data->get(2, 0), polynomial3->get(0));

  delete data;
}

TEST(Data, ConstructVector) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 1;
  int coeff_count = 8192;
  auto polynomial1 = MAKE_POLYNOMIAL(101);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  EXPECT_EQ(data->get(0, 0), polynomial1->get(0));

  delete data;
}

TEST(Data, GetChainStart) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 3;
  int coeff_count = 8192;
  auto polynomial = MAKE_POLYNOMIAL();
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  int polynomial_index = 0;
  EXPECT_EQ(data->get(polynomial_index, 0), polynomial->get(0));

  EXPECT_EQ(data->get(polynomial_index, 1), polynomial->get(1));

  EXPECT_EQ(data->get(polynomial_index, 2), polynomial->get(2));

  delete data;
}

#ifdef DESILO_FHE_DEBUG
TEST(Data, GetPolynomialOutOfBoundsTooLarge) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 3;
  int coeff_count = 8192;
  auto polynomial = MAKE_POLYNOMIAL();
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  try {
    data->get(3);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Data polynomial index out of bounds", e.what());
  }

  delete data;
}

TEST(Data, GetPolynomialOutOfBoundsTooSmall) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 3;
  int coeff_count = 8192;
  auto polynomial = MAKE_POLYNOMIAL();
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  try {
    data->get(-1);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Data polynomial index out of bounds", e.what());
  }

  delete data;
}

TEST(Data, GetChainStartOutOfBoundsTooLarge) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 3;
  int coeff_count = 8192;
  auto polynomial = MAKE_POLYNOMIAL();
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  try {
    data->get(0, 3);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Data chain start out of bounds", e.what());
  }

  delete data;
}

TEST(Data, GetChainStartOutOfBoundsTooSmall) {
  desilo::fhe::DataFlag flag = desilo::fhe::DataFlag::NONE;
  auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
  int log_slot_count = 0;
  int log_coeff_count = 1;
  int special_prime_count = 0;
  int moduli_id = 10;
  int level = 11;
  int chain_count = 3;
  int coeff_count = 8192;
  auto polynomial = MAKE_POLYNOMIAL();
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial};

  auto data = new desilo::fhe::Data(polynomials, desilo::fhe::DataType::NONE,
                                    flag, scheme_preset, log_slot_count,
                                    log_coeff_count, special_prime_count,
                                    moduli_id, level, chain_count, coeff_count);

  try {
    data->get(0, -1);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Data chain start out of bounds", e.what());
  }

  delete data;
}
#endif
