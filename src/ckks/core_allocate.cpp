#include <cstring>

#include "ckks/core.h"

namespace desilo::fhe {

template <class T>
T *CKKSCore::allocate_data(const DataFlag flag, int moduli_id,
                           int polynomial_count) {
  const auto scheme_preset = parameters_.get_scheme_preset();
  const auto level = parameters_.get_level(moduli_id, is_rescaled(flag));
  const auto include_special = includes_special(flag);
  const auto chain_count = get_chain_count(moduli_id, include_special);
  const auto coeff_count = precomputed_.coeff_count_;
  const auto log_slot_count = precomputed_.log_slot_count_;
  const auto log_coeff_count = precomputed_.log_coeff_count_;
  const auto special_prime_count = precomputed_.special_prime_count_;
  std::vector<Polynomial *> polynomials;

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    polynomials.push_back(
        new Polynomial(flag, moduli_id, chain_count, coeff_count));
  }

  auto data =
      new T(polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
            special_prime_count, moduli_id, level, chain_count, coeff_count);

  return data;
}

template <class T>
T *CKKSCore::allocate_text(const DataFlag flag, int moduli_id,
                           int polynomial_count, long double ckks_scale) {
  const auto scheme_preset = parameters_.get_scheme_preset();
  const auto level = parameters_.get_level(moduli_id, is_rescaled(flag));
  const auto include_special = includes_special(flag);
  const auto chain_count = get_chain_count(moduli_id, include_special);
  const auto coeff_count = precomputed_.coeff_count_;
  const auto log_slot_count = precomputed_.log_slot_count_;
  const auto log_coeff_count = precomputed_.log_coeff_count_;
  const auto special_prime_count = precomputed_.special_prime_count_;
  std::vector<Polynomial *> polynomials;

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    polynomials.push_back(
        new Polynomial(flag, moduli_id, chain_count, coeff_count));
  }

  auto data = new T(polynomials, flag, scheme_preset, log_slot_count,
                    log_coeff_count, special_prime_count, moduli_id, level,
                    chain_count, coeff_count, ckks_scale);

  return data;
}

Polynomial *CKKSCore::allocate_polynomial_(int moduli_id, int chain_count,
                                           DataFlag flag, int coeff_count) {
  return new Polynomial(flag, moduli_id, chain_count, coeff_count);
}

Polynomial *CKKSCore::allocate_polynomial_(int moduli_id, int chain_count,
                                           DataFlag flag) {
  const auto coeff_count = precomputed_.coeff_count_;
  return allocate_polynomial_(moduli_id, chain_count, flag, coeff_count);
}

Polynomial *CKKSCore::allocate_polynomial(int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  auto flag = DataFlag::NONE;
  return allocate_polynomial_(moduli_id, chain_count, flag);
}

Polynomial *CKKSCore::allocate_extended_polynomial(int moduli_id) {
  const auto chain_count = get_prime_count(moduli_id);
  auto flag = DataFlag::INCLUDE_SPECIAL;
  return allocate_polynomial_(moduli_id, chain_count, flag);
}

Polynomial *CKKSCore::allocate_mrs_polynomial() {
  int moduli_id = 0;
  int chain_count = precomputed_.special_prime_count_;
  auto flag = DataFlag::NONE;
  return allocate_polynomial_(moduli_id, chain_count, flag);
}

Polynomial *CKKSCore::allocate_polynomial() {
  int moduli_id = 0;
  int chain_count = 1;
  auto flag = DataFlag::NONE;
  return allocate_polynomial_(moduli_id, chain_count, flag);
}

DoublePolynomial *CKKSCore::allocate_double_polynomial(int coeff_count) {
  const auto moduli_id = 0;
  const auto flag = DataFlag::NONE;

  return new DoublePolynomial(new double[coeff_count], flag, moduli_id,
                              coeff_count);
}

DoublePolynomial *CKKSCore::allocate_double_polynomial() {
  const auto coeff_count = precomputed_.coeff_count_;
  return allocate_double_polynomial(coeff_count);
}

ComplexDoublePolynomial *
CKKSCore::allocate_complex_double_polynomial(int coeff_count) {
  const auto moduli_id = 0;
  const auto flag = DataFlag::NONE;

  return new ComplexDoublePolynomial(new std::complex<double>[coeff_count],
                                     flag, moduli_id, coeff_count);
}

template <class T> void CKKSCore::release(T *resource) { delete resource; }

template void CKKSCore::release(ComplexDoublePolynomial *resource);
template void CKKSCore::release(DecodeParameters *resource);
template void CKKSCore::release(DecomposedUnitCiphertext *resource);
template void CKKSCore::release(DoublePolynomial *resource);
template void CKKSCore::release(KeySwitcher *resource);
template void CKKSCore::release(Multiplier *resource);
template void CKKSCore::release(PermutationParameters *resource);
template void CKKSCore::release(Polynomial *resource);
template void CKKSCore::release(PolynomialInterface *resource);
template void CKKSCore::release(PolynomialView *resource);
template void CKKSCore::release(PublicKey *resource);
template void CKKSCore::release(SecretKey *resource);
template void CKKSCore::release(std::vector<CKKSPartitionParameters> *resource);
template void CKKSCore::release(UnitCiphertext *resource);
template void CKKSCore::release(UnitPlaintext *resource);

void CKKSCore::copy_single_chain_to_polynomial(int64_t *x, Polynomial *y) {
  const auto chain_count = 1;

  if (parallel_enabled_) {
    parallel_processor_->copy_to_polynomial(x, y, chain_count);
  } else {
    single_processor_->copy_to_polynomial(x, y, chain_count);
  }
}

void CKKSCore::copy(PolynomialInterface *x, PolynomialInterface *y,
                    int chain_count, int x_offset, int y_offset) {
  if (parallel_enabled_) {
    parallel_processor_->copy(x, y, chain_count, x_offset, y_offset);
  } else {
    single_processor_->copy(x, y, chain_count, x_offset, y_offset);
  }
}

void CKKSCore::decompress_polynomial(PolynomialInterface *x,
                                     PolynomialInterface *y, int chain_count) {
  if (parallel_enabled_) {
    parallel_processor_->decompress_polynomial(x, y, chain_count);
  } else {
    single_processor_->decompress_polynomial(x, y, chain_count);
  }
}

void CKKSCore::compress_polynomial(PolynomialInterface *x,
                                   PolynomialInterface *y, int chain_count) {
  if (parallel_enabled_) {
    parallel_processor_->compress_polynomial(x, y, chain_count);
  } else {
    single_processor_->compress_polynomial(x, y, chain_count);
  }
}

UnitPlaintext *CKKSCore::clone(UnitPlaintext *plaintext) {
  auto polynomial_count = plaintext->polynomial_count();
  auto chain_count = plaintext->chain_count_;
  auto coeff_count = plaintext->coeff_count_;

  auto cloned =
      allocate_text<UnitPlaintext>(plaintext->flag_, plaintext->moduli_id_,
                                   polynomial_count, plaintext->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    copy(get_polynomial(plaintext, polynomial_index),
         get_polynomial(cloned, polynomial_index), chain_count);
  }

  return cloned;
}

UnitCiphertext *CKKSCore::clone(UnitCiphertext *ciphertext) {
  auto polynomial_count = ciphertext->polynomial_count();
  auto chain_count = ciphertext->chain_count_;
  auto coeff_count = ciphertext->coeff_count_;
  auto cloned =
      allocate_text<UnitCiphertext>(ciphertext->flag_, ciphertext->moduli_id_,
                                    polynomial_count, ciphertext->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    copy(get_polynomial(ciphertext, polynomial_index),
         get_polynomial(cloned, polynomial_index), chain_count);
  }

  return cloned;
}

template SecretKey *CKKSCore::allocate_data<SecretKey>(const DataFlag flag,
                                                       int moduli_id,
                                                       int polynomial_count);
template PublicKey *CKKSCore::allocate_data<PublicKey>(const DataFlag flag,
                                                       int moduli_id,
                                                       int polynomial_count);
template KeySwitchingKey *
CKKSCore::allocate_data<KeySwitchingKey>(const DataFlag flag, int moduli_id,
                                         int polynomial_count);
template UnitPlaintext *
CKKSCore::allocate_text<UnitPlaintext>(const DataFlag flag, int moduli_id,
                                       int polynomial_count,
                                       long double ckks_scale);
template UnitCiphertext *
CKKSCore::allocate_text<UnitCiphertext>(const DataFlag flag, int moduli_id,
                                        int polynomial_count,
                                        long double ckks_scale);
template KeySwitcher *
CKKSCore::allocate_data<KeySwitcher>(const DataFlag flag, int moduli_id,
                                     int polynomial_count);
template DecomposedUnitCiphertext *
CKKSCore::allocate_data<DecomposedUnitCiphertext>(const DataFlag flag,
                                                  int moduli_id,
                                                  int polynomial_count);

}
