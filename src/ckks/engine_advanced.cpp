#include <algorithm>

#include "ckks/engine.h"

namespace desilo::fhe {

template <class T>
void CKKSEngine::require_make_power_basis_(
    const std::string &function_name, T *text, int max_power,
    RelinearizationKey *relinearization_key) {
  bool for_multiply = true;
  require(function_name, text,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});
  const int required_level = std::ceil(std::log2(max_power));
  validate_target_level(function_name, text, required_level);
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text, relinearization_key,
                            for_multiply);
}

std::vector<UnitCiphertext *>
CKKSEngine::make_power_basis(UnitCiphertext *unit_ciphertext, int max_power,
                             RelinearizationKey *relinearization_key) {
  const std::string function_name = "Make Power Basis With Unit Ciphertext";
  require_make_power_basis_(function_name, unit_ciphertext, max_power,
                            relinearization_key);
  std::vector<UnitCiphertext *> power_basis(max_power + 1, nullptr);
  power_basis[1] = clone(unit_ciphertext);

  int current_power_of_two = 2;
  auto current = unit_ciphertext;
  while (current_power_of_two <= max_power) {
    auto squared = square(current, relinearization_key);
    power_basis[current_power_of_two] = squared;
    current = squared;
    current_power_of_two <<= 1;
  }

  for (int power_index = 2; power_index <= max_power; power_index++) {

    if (power_basis[power_index] != nullptr) {
      continue;
    }

    const auto highest_power_of_two =
        1 << static_cast<int>(std::floor(std::log2(power_index)));

    auto product = multiply(power_basis[highest_power_of_two],
                            power_basis[power_index - highest_power_of_two],
                            relinearization_key);
    power_basis[power_index] = product;
  }

  power_basis.erase(power_basis.begin());

  return power_basis;
}

std::vector<Ciphertext *>
CKKSEngine::make_power_basis(Ciphertext *ciphertext, int max_power,
                             RelinearizationKey *relinearization_key) {
  const std::string function_name = "Make Power Basis With Ciphertext";
  require_make_power_basis_(function_name, ciphertext, max_power,
                            relinearization_key);

  std::vector<Ciphertext *> ciphertexts;
  std::vector<std::vector<UnitCiphertext *>> unit_basis;

  for (int index = 0; index < ciphertext->size(); index++) {
    unit_basis.push_back(make_power_basis(ciphertext->get(index), max_power,
                                          relinearization_key));
  }

  for (int power_index = 0; power_index < max_power; power_index++) {
    std::vector<UnitCiphertext *> unit_ciphertexts;
    for (int index = 0; index < ciphertext->size(); index++) {
      unit_ciphertexts.push_back(unit_basis[index][power_index]);
    }
    ciphertexts.push_back(new Ciphertext(unit_ciphertexts));
  }

  clear_temp_data();

  return ciphertexts;
}

template <class T>
void CKKSEngine::require_make_chebyshev_basis_(
    const std::string &function_name, T *text, int max_power,
    RelinearizationKey *relinearization_key) {
  bool for_multiply = true;
  require(function_name, text,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});
  const int required_level = std::ceil(std::log2(max_power));
  validate_target_level(function_name, text, required_level);
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text, relinearization_key,
                            for_multiply);
}

std::vector<UnitCiphertext *>
CKKSEngine::make_chebyshev_basis(UnitCiphertext *unit_ciphertext, int max_power,
                                 RelinearizationKey *relinearization_key) {
  const std::string function_name = "Make Chebyshev Basis With Unit Ciphertext";
  require_make_chebyshev_basis_(function_name, unit_ciphertext, max_power,
                                relinearization_key);
  std::vector<UnitCiphertext *> chebyshev_basis(max_power + 1, nullptr);
  chebyshev_basis[1] = clone(unit_ciphertext);

  int current_power_of_two = 2;
  auto current = unit_ciphertext;
  while (current_power_of_two <= max_power) {
    auto squared = square(current, relinearization_key);
    add_inplace(squared, squared);

    current = add(squared, -1);
    chebyshev_basis[current_power_of_two] = current;
    current_power_of_two <<= 1;

    delete squared;
  }

  for (int power_index = 2; power_index <= max_power; power_index++) {

    if (chebyshev_basis[power_index] != nullptr) {
      continue;
    }

    const auto highest_power_of_two =
        1 << static_cast<int>(std::floor(std::log2(power_index)));

    auto product = multiply(chebyshev_basis[highest_power_of_two],
                            chebyshev_basis[power_index - highest_power_of_two],
                            relinearization_key);
    add_inplace(product, product);
    auto subtracted = subtract(
        product, chebyshev_basis[(2 * highest_power_of_two) - power_index]);

    chebyshev_basis[power_index] = subtracted;

    delete product;
  }

  chebyshev_basis.erase(chebyshev_basis.begin());

  return chebyshev_basis;
}

std::vector<Ciphertext *>
CKKSEngine::make_chebyshev_basis(Ciphertext *ciphertext, int max_power,
                                 RelinearizationKey *relinearization_key) {
  const std::string function_name = "Make Chebyshev Basis With Ciphertext";
  require_make_chebyshev_basis_(function_name, ciphertext, max_power,
                                relinearization_key);

  std::vector<Ciphertext *> ciphertexts;
  std::vector<std::vector<UnitCiphertext *>> unit_basis;

  for (int index = 0; index < ciphertext->size(); index++) {
    unit_basis.push_back(make_chebyshev_basis(ciphertext->get(index), max_power,
                                              relinearization_key));
  }

  for (int power_index = 0; power_index < max_power; power_index++) {
    std::vector<UnitCiphertext *> unit_ciphertexts;
    for (int index = 0; index < ciphertext->size(); index++) {
      unit_ciphertexts.push_back(unit_basis[index][power_index]);
    }
    ciphertexts.push_back(new Ciphertext(unit_ciphertexts));
  }

  clear_temp_data();

  return ciphertexts;
}

template <class T>
void CKKSEngine::require_weighted_sum_(const std::string &function_name,
                                       std::vector<T> &texts,
                                       const std::vector<int64_t> &weights) {
  if (weights.size() < 2) {
    throw std::runtime_error(function_name +
                             ": the input weight is too short.");
  }
  require(function_name, texts,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED,
           Requirement::MATCH_CKKS_SCALE, Requirement::MATCH_SIZE});
  bool zero_degree = std::all_of(weights.begin() + 1, weights.end(),
                                 [](int weight) { return weight == 0; });
  if (zero_degree) {
    throw std::runtime_error(
        function_name + ": the input weights have only a constant weight.");
  }
  if (weights.size() > texts.size() + 1) {
    throw std::runtime_error(
        function_name +
        ": the size of basis is smaller than the degree of polynomial.");
  }
}

template <class T>
void CKKSEngine::require_weighted_sum_(const std::string &function_name,
                                       std::vector<T> &texts,
                                       const std::vector<double> &weights) {
  if (weights.size() < 2) {
    throw std::runtime_error(function_name +
                             ": the input weight is too short.");
  }
  require(function_name, texts,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED,
           Requirement::MATCH_CKKS_SCALE, Requirement::MATCH_SIZE,
           Requirement::POSITIVE_LEVEL});
  bool zero_degree = std::all_of(weights.begin() + 1, weights.end(),
                                 [](double weight) { return weight == 0; });
  if (zero_degree) {
    throw std::runtime_error(
        function_name + ": the input weights have only a constant weight.");
  }
  if (weights.size() > texts.size() + 1) {
    throw std::runtime_error(
        function_name +
        ": the size of basis is smaller than the degree of polynomial.");
  }
}

template <typename T>

UnitCiphertext *
CKKSEngine::weighted_sum_(std::vector<UnitCiphertext *> &unit_ciphertexts,
                          const std::vector<T> &weights) {
  const std::string function_name = "Weighted Sum Unit Ciphertexts";
  require_weighted_sum_(function_name, unit_ciphertexts, weights);
  const int degree = weights.size() - 1;

  UnitCiphertext *result = nullptr;

  for (int index = degree; index > 0; index--) {
    const auto weight = weights[index];

    if (weight == 0) {
      continue;
    }

    auto product = multiply(unit_ciphertexts[index - 1], weight);

    if (result == nullptr) {
      result = product;
      continue;
    }

    auto added = add(result, product);

    delete result;
    delete product;

    result = added;
  }

  if (weights[0] != 0) {

    auto added = add(result, weights[0]);

    delete result;

    result = added;
  }

  return result;
}

UnitCiphertext *
CKKSEngine::weighted_sum(std::vector<UnitCiphertext *> &unit_ciphertexts,
                         const std::vector<int64_t> &weights) {
  return weighted_sum_(unit_ciphertexts, weights);
}
UnitCiphertext *
CKKSEngine::weighted_sum(std::vector<UnitCiphertext *> &unit_ciphertexts,
                         const std::vector<double> &weights) {
  return weighted_sum_(unit_ciphertexts, weights);
}

template <typename T>
Ciphertext *CKKSEngine::weighted_sum_(std::vector<Ciphertext *> &ciphertexts,
                                      std::vector<T> &weights) {
  const std::string function_name = "Weighted Sum Ciphertexts";
  require_weighted_sum_(function_name, ciphertexts, weights);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertexts[0]->size(); index++) {
    std::vector<UnitCiphertext *> power_basis_ciphertexts;
    for (int power_index = 0; power_index < ciphertexts.size(); power_index++) {
      power_basis_ciphertexts.push_back(ciphertexts[power_index]->get(index));
    }
    unit_ciphertexts.push_back(weighted_sum_(power_basis_ciphertexts, weights));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::weighted_sum(std::vector<Ciphertext *> &ciphertexts,
                                     std::vector<int64_t> &weights) {
  return weighted_sum_(ciphertexts, weights);
}

Ciphertext *CKKSEngine::weighted_sum(std::vector<Ciphertext *> &ciphertexts,
                                     std::vector<double> &weights) {
  return weighted_sum_(ciphertexts, weights);
}

template <class T>
void CKKSEngine::require_evaluate_polynomial_(
    const std::string &function_name, T *text,
    std::vector<int64_t> &coefficients,
    RelinearizationKey *relinearization_key) {
  bool for_multiply = true;
  require(function_name, text,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});
  if (coefficients.size() < 2) {
    throw std::runtime_error(function_name +
                             ": the input coefficient is too short.");
  }
  bool zero_degree =
      std::all_of(coefficients.begin() + 1, coefficients.end(),
                  [](int coefficient) { return coefficient == 0; });
  if (zero_degree) {
    throw std::runtime_error(
        function_name +
        ": the input coefficients have only a constant coefficient.");
  }
  const int required_level = std::ceil(std::log2(coefficients.size() - 1));
  validate_target_level(function_name, text, required_level);
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text, relinearization_key,
                            for_multiply);
}

template <class T>
void CKKSEngine::require_evaluate_polynomial_(
    const std::string &function_name, T *text,
    std::vector<double> &coefficients,
    RelinearizationKey *relinearization_key) {
  bool for_multiply = true;
  require(function_name, text,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});
  if (coefficients.size() < 2) {
    throw std::runtime_error(function_name +
                             ": the input coefficient is too short.");
  }
  bool zero_degree =
      std::all_of(coefficients.begin() + 1, coefficients.end(),
                  [](double coefficient) { return coefficient == 0; });
  if (zero_degree) {
    throw std::runtime_error(
        function_name +
        ": the input coefficients have only a constant coefficient.");
  }
  const int required_level = std::ceil(std::log2(coefficients.size() - 1)) + 1;
  validate_target_level(function_name, text, required_level);
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text, relinearization_key,
                            for_multiply);
}

template <typename T>
UnitCiphertext *
CKKSEngine::evaluate_polynomial_(UnitCiphertext *unit_ciphertext,
                                 std::vector<T> &coefficients,
                                 RelinearizationKey *relinearization_key) {
  const std::string function_name = "Evaluate Polynomial With Unit Ciphertext";
  require_evaluate_polynomial_(function_name, unit_ciphertext, coefficients,
                               relinearization_key);

  const auto max_power = coefficients.size() - 1;
  std::vector<UnitCiphertext *> power_basis =
      make_power_basis(unit_ciphertext, max_power, relinearization_key);

  auto polynomial = weighted_sum(power_basis, coefficients);

  for (auto basis : power_basis) {
    delete basis;
  }

  return polynomial;
}

UnitCiphertext *
CKKSEngine::evaluate_polynomial(UnitCiphertext *unit_ciphertext,
                                std::vector<int64_t> &coefficients,
                                RelinearizationKey *relinearization_key) {
  return evaluate_polynomial_(unit_ciphertext, coefficients,
                              relinearization_key);
}

UnitCiphertext *
CKKSEngine::evaluate_polynomial(UnitCiphertext *unit_ciphertext,
                                std::vector<double> &coefficients,
                                RelinearizationKey *relinearization_key) {
  return evaluate_polynomial_(unit_ciphertext, coefficients,
                              relinearization_key);
}

template <typename T>
Ciphertext *
CKKSEngine::evaluate_polynomial_(Ciphertext *ciphertext,
                                 std::vector<T> &coefficients,
                                 RelinearizationKey *relinearization_key) {
  const std::string function_name = "Evaluate Polynomial With Ciphertext";
  require_evaluate_polynomial_(function_name, ciphertext, coefficients,
                               relinearization_key);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(evaluate_polynomial_(
        ciphertext->get(index), coefficients, relinearization_key));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *
CKKSEngine::evaluate_polynomial(Ciphertext *ciphertext,
                                std::vector<int64_t> &coefficients,
                                RelinearizationKey *relinearization_key) {
  return evaluate_polynomial_(ciphertext, coefficients, relinearization_key);
}

Ciphertext *
CKKSEngine::evaluate_polynomial(Ciphertext *ciphertext,
                                std::vector<double> &coefficients,
                                RelinearizationKey *relinearization_key) {
  return evaluate_polynomial_(ciphertext, coefficients, relinearization_key);
}

template <class T, class U>
void CKKSEngine::require_evaluate_chebyshev_polynomial_(
    const std::string &function_name, T *text, std::vector<U> &coefficients,
    RelinearizationKey *relinearization_key) {
  bool for_multiply = true;
  require(function_name, text,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});
  if (coefficients.size() < 2) {
    throw std::runtime_error(function_name +
                             ": the input coefficient is too short.");
  }
  bool zero_degree =
      std::all_of(coefficients.begin() + 1, coefficients.end(),
                  [](int coefficient) { return coefficient == 0; });
  if (zero_degree) {
    throw std::runtime_error(
        function_name +
        ": the input coefficients have only a constant coefficient.");
  }

  int required_level = std::ceil(std::log2(coefficients.size() - 1));
  if constexpr (std::is_same_v<U, double>) {
    required_level++;
  }

  validate_target_level(function_name, text, required_level);
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, text, relinearization_key,
                            for_multiply);
}

template <typename T>
UnitCiphertext *CKKSEngine::evaluate_chebyshev_polynomial_(
    UnitCiphertext *unit_ciphertext, std::vector<T> &coefficients,
    RelinearizationKey *relinearization_key) {
  const std::string function_name =
      "Evaluate Chebyshev Polynomial With Unit Ciphertext";
  require_evaluate_chebyshev_polynomial_(function_name, unit_ciphertext,
                                         coefficients, relinearization_key);

  const auto max_power = coefficients.size() - 1;
  std::vector<UnitCiphertext *> chebyshev_basis =
      make_chebyshev_basis(unit_ciphertext, max_power, relinearization_key);

  auto polynomial = weighted_sum(chebyshev_basis, coefficients);

  for (auto basis : chebyshev_basis) {
    delete basis;
  }

  return polynomial;
}

UnitCiphertext *CKKSEngine::evaluate_chebyshev_polynomial(
    UnitCiphertext *unit_ciphertext, std::vector<int64_t> &coefficients,
    RelinearizationKey *relinearization_key) {
  return evaluate_chebyshev_polynomial_(unit_ciphertext, coefficients,
                                        relinearization_key);
}

UnitCiphertext *CKKSEngine::evaluate_chebyshev_polynomial(
    UnitCiphertext *unit_ciphertext, std::vector<double> &coefficients,
    RelinearizationKey *relinearization_key) {
  return evaluate_chebyshev_polynomial_(unit_ciphertext, coefficients,
                                        relinearization_key);
}

template <typename T>
Ciphertext *CKKSEngine::evaluate_chebyshev_polynomial_(
    Ciphertext *ciphertext, std::vector<T> &coefficients,
    RelinearizationKey *relinearization_key) {
  const std::string function_name =
      "Evaluate Chebyshev Polynomial With Ciphertext";
  require_evaluate_chebyshev_polynomial_(function_name, ciphertext,
                                         coefficients, relinearization_key);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(evaluate_chebyshev_polynomial_(
        ciphertext->get(index), coefficients, relinearization_key));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::evaluate_chebyshev_polynomial(
    Ciphertext *ciphertext, std::vector<int64_t> &coefficients,
    RelinearizationKey *relinearization_key) {
  return evaluate_chebyshev_polynomial_(ciphertext, coefficients,
                                        relinearization_key);
}

Ciphertext *CKKSEngine::evaluate_chebyshev_polynomial(
    Ciphertext *ciphertext, std::vector<double> &coefficients,
    RelinearizationKey *relinearization_key) {
  return evaluate_chebyshev_polynomial_(ciphertext, coefficients,
                                        relinearization_key);
}

void CKKSEngine::require_rotate_sum_(const std::string &function_name,
                                     Ciphertext *ciphertext,
                                     RotationKey *rotation_key) {

  require(function_name, ciphertext,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});
  require_engine_compatibility(function_name, rotation_key);
  require_key_compatibility(function_name, ciphertext, rotation_key);
}

Ciphertext *CKKSEngine::sum_1d_by_row(Ciphertext *ciphertext,
                                      RotationKey *rotation_key) {
  const std::string function_name = "Sum Ciphertext Along Axis 1";
  require_rotate_sum_(function_name, ciphertext, rotation_key);

  const auto slot_count = get_slot_count();
  if (slot_count == 1) {
    return clone(ciphertext);
  }

  auto current = ciphertext;

  if (parameters_.get_use_one_more_level() && ciphertext->moduli_id() == 0) {
    current = level_down(ciphertext, ciphertext->level() - 1);
  }

  for (int delta = 1; delta < slot_count; delta <<= 1) {
    auto rotated = rotate(current, rotation_key, delta);
    add_inplace(rotated, current);

    if (current != ciphertext && delta < slot_count) {
      delete current;
    }

    current = rotated;
  }

  return current;
}

Ciphertext *CKKSEngine::sum_1d_by_column(Ciphertext *ciphertext) {
  const std::string function_name = "Sum Ciphertext Along Axis 0";

  require(function_name, ciphertext,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});

  if (ciphertext->size() == 1) {

    return clone(ciphertext);
  }

  auto current = add(ciphertext->get(0), ciphertext->get(1));

  for (int index = 2; index < ciphertext->size(); index++) {
    add_inplace(current, ciphertext->get(index));
  }

  return new Ciphertext({current});
}

Ciphertext *CKKSEngine::sum_2d(Ciphertext *ciphertext,
                               RotationKey *rotation_key) {
  const std::string function_name = "Sum Ciphertext Along All Axes";
  require_rotate_sum_(function_name, ciphertext, rotation_key);

  auto summed_by_column = sum_1d_by_column(ciphertext);
  auto summed_by_row = sum_1d_by_row(summed_by_column, rotation_key);

  delete summed_by_column;

  return summed_by_row;
}

Ciphertext *CKKSEngine::stack_by_row(std::vector<Ciphertext *> &ciphertexts) {
  const std::string function_name = "Stack Ciphertexts Vertically";
  if (ciphertexts.size() < 1) {
    throw std::runtime_error(function_name +
                             ": the input ciphertext vector is empty.");
  }
  require(function_name, ciphertexts,
          {Requirement::MATCH_LEVEL, Requirement::MATCH_POLYNOMIAL_COUNT,
           Requirement::MATCH_NTT, Requirement::MATCH_RESCALED});

  std::vector<UnitCiphertext *> unit_ciphertexts;

  for (auto ciphertext : ciphertexts) {
    for (int index = 0; index < ciphertext->size(); index++) {
      unit_ciphertexts.push_back(clone(ciphertext->get(index)));
    }
  }

  return new Ciphertext(unit_ciphertexts);
}

}
