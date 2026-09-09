#include <gtest/gtest.h>

#include "data/polynomial.h"

TEST(PolynomialView, Construct) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const auto chain_count = 2;
  const auto coeff_count = 3;

  std::vector<int64_t *> chains(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    chains[chain_index] = new int64_t[coeff_count];
  }

  const auto polynomial_view = new desilo::fhe::PolynomialView(
      static_cast<void *>(chains[0]), chains, flag, moduli_id, coeff_count);

  EXPECT_EQ(polynomial_view->id(), static_cast<void *>(chains[0]));

  EXPECT_EQ(polynomial_view->flag(), flag);
  EXPECT_EQ(polynomial_view->moduli_id(), moduli_id);
  EXPECT_EQ(polynomial_view->chain_count(), chain_count);
  EXPECT_EQ(polynomial_view->coeff_count(), coeff_count);

  EXPECT_EQ(polynomial_view->get(0), chains[0]);
  EXPECT_EQ(polynomial_view->get(1), chains[1]);

  delete polynomial_view;

  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    delete[] chains[chain_index];
  }
}

TEST(PolynomialView, ConstructFromPolynomial) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  const auto moduli_id = 0;
  const auto chain_count = 4;
  const auto coeff_count = 3;

  std::vector<int64_t *> chains(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    chains[chain_index] = new int64_t[coeff_count];
  }

  const auto polynomial =
      new desilo::fhe::Polynomial(chains, flag, moduli_id, coeff_count);

  int offset = 1;
  auto polynomial_view = new desilo::fhe::PolynomialView(polynomial, offset);

  EXPECT_EQ(polynomial_view->id(), static_cast<void *>(chains[0]));
  EXPECT_EQ(polynomial_view->id(), polynomial->id());

  EXPECT_EQ(polynomial_view->flag(), flag);
  EXPECT_EQ(polynomial_view->moduli_id(), moduli_id);
  EXPECT_EQ(polynomial_view->chain_count(), chain_count - 1);
  EXPECT_EQ(polynomial_view->coeff_count(), coeff_count);

  EXPECT_EQ(polynomial_view->get(0), chains[1]);
  EXPECT_EQ(polynomial_view->get(1), chains[2]);
  EXPECT_EQ(polynomial_view->get(2), chains[3]);

  delete polynomial_view;

  offset = 2;
  polynomial_view = new desilo::fhe::PolynomialView(polynomial, offset);

  EXPECT_EQ(polynomial_view->id(), static_cast<void *>(chains[0]));
  EXPECT_EQ(polynomial_view->id(), polynomial->id());

  EXPECT_EQ(polynomial_view->flag(), flag);
  EXPECT_EQ(polynomial_view->moduli_id(), moduli_id);
  EXPECT_EQ(polynomial_view->chain_count(), chain_count - 2);
  EXPECT_EQ(polynomial_view->coeff_count(), coeff_count);

  EXPECT_EQ(polynomial_view->get(0), chains[2]);
  EXPECT_EQ(polynomial_view->get(1), chains[3]);

  delete polynomial_view;
  delete polynomial;
}
