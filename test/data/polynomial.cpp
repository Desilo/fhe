#include <gtest/gtest.h>

#include "data/polynomial.h"

TEST(Polynomial, Interface) {
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

  EXPECT_EQ(polynomial->id(), static_cast<void *>(chains[0]));

  EXPECT_EQ(polynomial->flag(), flag);
  EXPECT_EQ(polynomial->moduli_id(), moduli_id);
  EXPECT_EQ(polynomial->chain_count(), chain_count);
  EXPECT_EQ(polynomial->coeff_count(), coeff_count);

  EXPECT_EQ(polynomial->get(0), chains[0]);
  EXPECT_EQ(polynomial->get(1), chains[1]);

  delete polynomial;
}

TEST(Polynomial, AllocateFree) {
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

  delete polynomial;
}

TEST(DoublePolynomial, AllocateFree) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const auto coeff_count = 50;

  const auto buffer = new double[coeff_count];
  const auto polynomial =
      new desilo::fhe::DoublePolynomial(buffer, flag, moduli_id, coeff_count);

  delete polynomial;
}

TEST(ComplexDoublePolynomial, AllocateFree) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const auto coeff_count = 50;

  const auto buffer = new std::complex<double>[coeff_count];
  const auto polynomial = new desilo::fhe::ComplexDoublePolynomial(
      buffer, flag, moduli_id, coeff_count);

  delete polynomial;
}
