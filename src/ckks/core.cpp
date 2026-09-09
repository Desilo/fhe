#include "ckks/core.h"
#include "arithmetic/arithmetic.h"
#include "ckks/encode.h"
#include "operation/scalar.h"

namespace desilo::fhe {

CKKSCore::CKKSCore(const CKKSConfig &config)
    : parameters_(config), precomputed_(config),

      rng_(1, precomputed_.coeff_count_), partitions_cache_(&precomputed_) {
  single_processor_ = std::make_unique<SingleProcessor>(
      precomputed_.log_coeff_count_, precomputed_.log_codec_coeff_count_);

  if (parallel_enabled_) {
    parallel_processor_ = std::make_unique<ParallelProcessor>(
        parameters_.get_thread_count(), precomputed_.log_coeff_count_,
        precomputed_.log_codec_coeff_count_);
  }
}

template <typename T> DataFlag CKKSCore::get_complex_flag() {
  return DataFlag::NONE;
}

template <> DataFlag CKKSCore::get_complex_flag<std::complex<double>>() {
  return DataFlag::COMPLEX;
}
template <> DataFlag CKKSCore::get_complex_flag<ComplexDoublePolynomial *>() {
  return DataFlag::COMPLEX;
}
template DataFlag CKKSCore::get_complex_flag<double>();
template DataFlag CKKSCore::get_complex_flag<DoublePolynomial *>();

UnitCiphertext *CKKSCore::encrypt(UnitPlaintext *input_plaintext,
                                  PublicKey *public_key) {
  DataFlag flag = input_plaintext->flag_;
  const auto moduli_id = input_plaintext->moduli_id_;
  const int polynomial_count = 2;
  auto ciphertext = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, input_plaintext->ckks_scale_);

  const auto single_error0 = get_single_error();
  const auto single_error1 = get_single_error();
  const auto single_binary = get_binary();
  const auto error0 = allocate_polynomial(moduli_id);
  const auto error1 = allocate_polynomial(moduli_id);

  const auto plaintext = get_polynomial(input_plaintext, 0);
  const auto [ciphertext0, ciphertext1] = get_duo_polynomials(ciphertext);

  tile_unsigned_reduce_2q_to_q_(single_error0, error0, moduli_id);
  tile_unsigned_reduce_2q_to_q_(single_error1, error1, moduli_id);

  mont_add_reduce_2q_to_q_(plaintext, error0, error0, moduli_id);

  const auto binary = allocate_polynomial(moduli_id);

  tile_unsigned_reduce_2q_to_q_(single_binary, binary, moduli_id);
  to_ntt_(binary, binary, moduli_id);

  const auto [public_key0, public_key1] =
      get_duo_polynomial_views(public_key, moduli_id);

  mont_mult_(binary, public_key0, ciphertext0, moduli_id);
  mont_mult_(binary, public_key1, ciphertext1, moduli_id);

  to_intt_(ciphertext0, ciphertext0, moduli_id);
  to_intt_(ciphertext1, ciphertext1, moduli_id);

  release(binary);
  release(public_key0);
  release(public_key1);

  mont_add_reduce_2q_to_q_(ciphertext0, error0, ciphertext0, moduli_id);
  mont_add_reduce_2q_to_q_(ciphertext1, error1, ciphertext1, moduli_id);

  release(single_error0);
  release(single_error1);
  release(single_binary);
  release(error0);
  release(error1);

  return ciphertext;
}

UnitCiphertext *CKKSCore::encrypt(UnitPlaintext *input_plaintext,
                                  SecretKey *secret_key) {
  DataFlag flag = input_plaintext->flag_;
  const auto moduli_id = input_plaintext->moduli_id_;
  const int polynomial_count = 2;
  auto ciphertext = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, input_plaintext->ckks_scale_);

  const auto plaintext0 = get_polynomial(input_plaintext, 0);
  const auto [ciphertext0, ciphertext1] = get_duo_polynomials(ciphertext);

  const auto single_error = get_single_error();
  const auto error = allocate_polynomial(moduli_id);

  tile_unsigned_reduce_2q_to_q_(single_error, error, moduli_id);
  mont_add_reduce_2q_to_q_(plaintext0, error, error, moduli_id);

  const auto secret_key0 = get_polynomial_view(secret_key, 0, moduli_id);

  assign_a(ciphertext1, moduli_id);

  mont_mult_(ciphertext1, secret_key0, ciphertext0, moduli_id);
  reduce_2q_to_q_(ciphertext0, ciphertext0, moduli_id);

  to_intt_(ciphertext0, ciphertext0, moduli_id);
  to_intt_(ciphertext1, ciphertext1, moduli_id);

  release(secret_key0);

  mont_sub_reduce_2q_to_q_(error, ciphertext0, ciphertext0, moduli_id);

  release(single_error);
  release(error);

  return ciphertext;
}

UnitPlaintext *CKKSCore::decrypt_trio(UnitCiphertext *ciphertext,
                                      SecretKey *secret_key) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(moduli_id);

  const DataFlag flag = ciphertext->flag_ & DataFlag::COMPLEX;
  const int polynomial_count = 1;
  auto plaintext = allocate_text<UnitPlaintext>(
      flag, intt_moduli_id, polynomial_count, ciphertext->ckks_scale_);

  const auto plaintext0 = get_polynomial(plaintext, 0);
  const auto [ntt_ciphertext0, ntt_ciphertext1, ntt_ciphertext2] =
      get_trio_polynomials(ciphertext);

  const auto chain_count = ciphertext->chain_count_;

  const auto secret_key0 = get_polynomial_view(secret_key, 0, moduli_id);

  const auto intt_ciphertext0 = allocate_polynomial(moduli_id);
  const auto s_squared_a = allocate_polynomial(moduli_id);
  const auto secret_key_squared = allocate_polynomial(moduli_id);

  const int ciphertext_offset = 0;
  mont_mult_(secret_key0, secret_key0, secret_key_squared, moduli_id);
  mont_mult_(ntt_ciphertext1, secret_key0, plaintext0, moduli_id);
  intt_inplace_(plaintext0, moduli_id);
  mont_enter_exit_(plaintext0, plaintext0, moduli_id);

  intt_(ntt_ciphertext0, intt_ciphertext0, moduli_id, chain_count);
  mont_enter_exit_(intt_ciphertext0, intt_ciphertext0, moduli_id);
  mont_add_reduce_2q_to_q_(intt_ciphertext0, plaintext0, plaintext0, moduli_id);

  mont_mult_(ntt_ciphertext2, secret_key_squared, s_squared_a, moduli_id);
  intt_inplace_(s_squared_a, moduli_id);
  mont_enter_exit_(s_squared_a, s_squared_a, moduli_id);
  mont_add_reduce_2q_to_q_(plaintext0, s_squared_a, plaintext0, moduli_id);

  release(secret_key0);
  release(intt_ciphertext0);
  release(s_squared_a);
  release(secret_key_squared);

  return plaintext;
}

UnitPlaintext *CKKSCore::decrypt_duo(UnitCiphertext *ciphertext,
                                     SecretKey *secret_key) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto ntt_moduli_id = parameters_.get_ntt_moduli_id(moduli_id);
  const auto chain_count = ciphertext->chain_count_;

  const DataFlag flag = ciphertext->flag_ & DataFlag::COMPLEX;
  const int polynomial_count = 1;
  auto plaintext = allocate_text<UnitPlaintext>(
      flag, moduli_id, polynomial_count, ciphertext->ckks_scale_);

  const auto plaintext0 = get_polynomial(plaintext, 0);
  const auto [ciphertext0, ciphertext1] = get_duo_polynomials(ciphertext);

  const auto secret_key0 = get_polynomial_view(secret_key, 0, moduli_id);

  to_ntt_(ciphertext1, plaintext0, moduli_id);
  mont_mult_(plaintext0, secret_key0, plaintext0, moduli_id);
  to_intt_(plaintext0, plaintext0, moduli_id);

  mont_add_reduce_2q_to_q_(ciphertext0, plaintext0, plaintext0, moduli_id);

  release(secret_key0);

  return plaintext;
}

UnitCiphertext *CKKSCore::multiply(UnitCiphertext *ciphertext, double value) {
  const auto level = ciphertext->level_;
  const auto moduli_id = ciphertext->moduli_id_;
  const auto next_moduli_id = to_moduli_id(level - 1);
  const auto flag = ciphertext->flag_;
  bool include_special = includes_special(flag);

  auto multiplier = precomputed_.make_mult_multiplier(value, level);

  auto scalar = multiplier->get();

  int polynomial_count = ciphertext->polynomial_count();
  const auto rescaled_scale = get_rescaled_scale(ciphertext);

  auto rescaled = allocate_text<UnitCiphertext>(
      flag, next_moduli_id, polynomial_count, rescaled_scale * rescaled_scale);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(ciphertext, polynomial_index);
    const auto y = allocate_polynomial(moduli_id);
    const auto z = get_polynomial(rescaled, polynomial_index);

    mont_enter_scalar_(x, y, scalar, moduli_id);
    reduce_2q_to_q_(y, y, moduli_id);
    rescale_(y, z, moduli_id, include_special);

    release(y);
  }

  release(multiplier);

  return rescaled;
}

UnitCiphertext *CKKSCore::multiply(UnitCiphertext *ciphertext, int64_t value) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto flag = ciphertext->flag_;

  auto multiplier = precomputed_.make_mult_multiplier(value, moduli_id);

  auto scalar = multiplier->get();

  int polynomial_count = ciphertext->polynomial_count();
  auto multiplied = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, ciphertext->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(ciphertext, polynomial_index);
    const auto y = get_polynomial(multiplied, polynomial_index);

    mont_enter_scalar_(x, y, scalar, moduli_id);
    reduce_2q_to_q_(y, y, moduli_id);
  }

  release(multiplier);

  return multiplied;
}

UnitCiphertext *CKKSCore::multiply(UnitCiphertext *ciphertext,
                                   UnitPlaintext *plaintext) {
  DataFlag flag = (ciphertext->flag_ | plaintext->flag_) & ~DataFlag::RESCALED;
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = ciphertext->chain_count_;
  const int polynomial_count = ciphertext->polynomial_count();

  const auto multiplied_scale =
      ciphertext->ckks_scale_ * plaintext->ckks_scale_;
  auto multiplied = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, multiplied_scale);

  const int x_offset = 0;
  const int y_offset = 0;

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(ciphertext, polynomial_index);
    const auto y = get_polynomial(plaintext, 0);
    const auto z = get_polynomial(multiplied, polynomial_index);

    mont_mult_(x, y, z, moduli_id, chain_count, x_offset, y_offset);
  }

  return multiplied;
}

UnitCiphertext *CKKSCore::multiply(UnitCiphertext *ciphertext1,
                                   UnitCiphertext *ciphertext2) {
  const auto moduli_id = ciphertext1->moduli_id_;

  DataFlag flag = ciphertext1->flag_ | ciphertext2->flag_;
  flag &= ~DataFlag::RESCALED;

  const int polynomial_count = 3;
  const auto multiplied_scale =
      ciphertext1->ckks_scale_ * ciphertext2->ckks_scale_;
  auto multiplied = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, multiplied_scale);

  auto x0 = get_polynomial(ciphertext1, 0);
  auto x1 = get_polynomial(ciphertext1, 1);
  auto y0 = get_polynomial(ciphertext2, 0);
  auto y1 = get_polynomial(ciphertext2, 1);

  const auto [z0, z1, z2] = get_trio_polynomials(multiplied);
  const auto z3 = allocate_polynomial(moduli_id);

  mont_mult_(x0, y0, z0, moduli_id);
  mont_mult_(x0, y1, z1, moduli_id);
  mont_mult_(x1, y0, z3, moduli_id);
  mont_add_reduce_2q_to_q_(z1, z3, z1, moduli_id);
  mont_mult_(x1, y1, z2, moduli_id);

  release(z3);

  return multiplied;
}

UnitCiphertext *CKKSCore::square(UnitCiphertext *ciphertext) {
  const auto moduli_id = ciphertext->moduli_id_;

  DataFlag flag = ciphertext->flag_;
  flag &= ~DataFlag::RESCALED;

  const int polynomial_count = 3;
  const auto squared_scale = ciphertext->ckks_scale_ * ciphertext->ckks_scale_;
  auto squared = allocate_text<UnitCiphertext>(flag, moduli_id,
                                               polynomial_count, squared_scale);

  const auto x0 = get_polynomial(ciphertext, 0);
  const auto x1 = get_polynomial(ciphertext, 1);

  const auto [y0, y1, y2] = get_trio_polynomials(squared);

  mont_mult_(x0, x0, y0, moduli_id);
  mont_mult_(x0, x1, y1, moduli_id);
  mont_add_reduce_2q_to_q_(y1, y1, y1, moduli_id);
  mont_mult_(x1, x1, y2, moduli_id);

  return squared;
}

UnitCiphertext *CKKSCore::add(UnitCiphertext *ciphertext, double value) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto flag = ciphertext->flag_;
  const auto chain_count = get_chain_count(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;

  auto multiplier = precomputed_.make_add_multiplier(value, ciphertext->level_);

  auto scalar = multiplier->get();

  int polynomial_count = ciphertext->polynomial_count();
  auto added = allocate_text<UnitCiphertext>(flag, moduli_id, polynomial_count,
                                             ciphertext->ckks_scale_);

  const auto ciphertext0 = get_polynomial(ciphertext, 0);
  const auto z0 = get_polynomial(added, 0);

  add_scalar_(ciphertext0, z0, scalar, chain_count, coeff_count);
  reduce_2q_to_q_(z0, z0, moduli_id);

  for (int polynomial_index = 1; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto ciphertext_polynomial =
        get_polynomial(ciphertext, polynomial_index);
    const auto added_polynomial = get_polynomial(added, polynomial_index);

    copy(ciphertext_polynomial, added_polynomial, chain_count);
  }

  release(multiplier);

  return added;
}

UnitCiphertext *CKKSCore::add(UnitCiphertext *ciphertext,
                              UnitPlaintext *plaintext) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;

  const DataFlag flag = ciphertext->flag_;
  const int polynomial_count = ciphertext->polynomial_count();
  auto added = allocate_text<UnitCiphertext>(flag, moduli_id, polynomial_count,
                                             ciphertext->ckks_scale_);

  const auto ciphertext0 = get_polynomial(ciphertext, 0);

  UnitPlaintext *plaintext_ntt_form = nullptr;
  auto plaintext0 = get_polynomial(plaintext, 0);

  if (is_ntt_form(flag)) {
    plaintext_ntt_form = to_ntt_form(plaintext);
    plaintext0 = get_polynomial(plaintext_ntt_form, 0);
  }

  const auto z0 = get_polynomial(added, 0);

  mont_add_reduce_2q_to_q_(ciphertext0, plaintext0, z0, moduli_id);

  for (int polynomial_index = 1; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto ciphertext_polynomial =
        get_polynomial(ciphertext, polynomial_index);
    const auto added_polynomial = get_polynomial(added, polynomial_index);

    copy(ciphertext_polynomial, added_polynomial, chain_count);
  }

  if (plaintext_ntt_form) {
    release(plaintext_ntt_form);
  }

  return added;
}

UnitCiphertext *CKKSCore::add(UnitCiphertext *ciphertext1,
                              UnitCiphertext *ciphertext2) {
  const auto moduli_id = ciphertext1->moduli_id_;
  const auto chain_count = ciphertext1->chain_count_;

  const DataFlag flag = ciphertext1->flag_ | ciphertext2->flag_;
  const int polynomial_count = ciphertext1->polynomial_count();
  auto added = allocate_text<UnitCiphertext>(flag, moduli_id, polynomial_count,
                                             ciphertext1->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x1 = get_polynomial(ciphertext1, polynomial_index);
    const auto x2 = get_polynomial(ciphertext2, polynomial_index);
    const auto y = get_polynomial(added, polynomial_index);

    mont_add_reduce_2q_to_q_(x1, x2, y, moduli_id, chain_count);
  }

  return added;
}

UnitCiphertext *CKKSCore::add_trio_and_duo(UnitCiphertext *trio_ciphertext,
                                           UnitCiphertext *duo_ciphertext) {
  const auto moduli_id = trio_ciphertext->moduli_id_;
  const auto chain_count = trio_ciphertext->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;

  const DataFlag flag = trio_ciphertext->flag_ | duo_ciphertext->flag_;
  const int polynomial_count = 3;
  auto added = allocate_text<UnitCiphertext>(flag, moduli_id, polynomial_count,
                                             trio_ciphertext->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < 2; polynomial_index++) {
    const auto x1 = get_polynomial(trio_ciphertext, polynomial_index);
    const auto x2 = get_polynomial(duo_ciphertext, polynomial_index);
    const auto y = get_polynomial(added, polynomial_index);

    mont_add_reduce_2q_to_q_(x1, x2, y, moduli_id);
  }

  const auto x1 = get_polynomial(trio_ciphertext, 2);
  const auto y = get_polynomial(added, 2);
  copy(x1, y, chain_count);

  return added;
}

void CKKSCore::add_inplace(UnitCiphertext *ciphertext, double value) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;

  auto multiplier = precomputed_.make_add_multiplier(value, ciphertext->level_);

  auto scalar = multiplier->get();

  const auto ciphertext0 = get_polynomial(ciphertext, 0);

  add_scalar_(ciphertext0, ciphertext0, scalar, chain_count, coeff_count);
  reduce_2q_to_q_(ciphertext0, ciphertext0, moduli_id);

  release(multiplier);
}

void CKKSCore::add_inplace(UnitCiphertext *ciphertext,
                           UnitPlaintext *plaintext) {
  const auto moduli_id = ciphertext->moduli_id_;

  const DataFlag flag = ciphertext->flag_;

  const auto ciphertext0 = get_polynomial(ciphertext, 0);

  UnitPlaintext *plaintext_ntt_form = nullptr;
  auto plaintext0 = get_polynomial(plaintext, 0);

  mont_add_reduce_2q_to_q_(ciphertext0, plaintext0, ciphertext0, moduli_id);

  if (plaintext_ntt_form) {
    release(plaintext_ntt_form);
  }
}

void CKKSCore::add_inplace(UnitCiphertext *ciphertext1,
                           UnitCiphertext *ciphertext2) {
  const auto moduli_id = ciphertext1->moduli_id_;
  const auto chain_count = ciphertext1->chain_count_;

  const int polynomial_count = ciphertext1->polynomial_count();

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x1 = get_polynomial(ciphertext1, polynomial_index);
    const auto x2 = get_polynomial(ciphertext2, polynomial_index);

    mont_add_reduce_2q_to_q_(x1, x2, x1, moduli_id, chain_count);
  }
}

UnitCiphertext *CKKSCore::subtract(UnitPlaintext *plaintext,
                                   UnitCiphertext *ciphertext) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);

  const DataFlag flag = ciphertext->flag_;
  const int polynomial_count = ciphertext->polynomial_count();
  auto subtracted = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, ciphertext->ckks_scale_);

  const auto ciphertext0 = get_polynomial(ciphertext, 0);
  UnitPlaintext *plaintext_ntt_form = nullptr;
  auto plaintext0 = get_polynomial(plaintext, 0);

  if (is_ntt_form(flag)) {
    plaintext_ntt_form = to_ntt_form(plaintext);
    plaintext0 = get_polynomial(plaintext_ntt_form, 0);
  }

  const auto z0 = get_polynomial(subtracted, 0);

  mont_sub_reduce_2q_to_q_(plaintext0, ciphertext0, z0, moduli_id, chain_count);

  for (int polynomial_index = 1; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto ciphertext_polynomial =
        get_polynomial(ciphertext, polynomial_index);
    const auto subtracted_polynomial =
        get_polynomial(subtracted, polynomial_index);

    if (is_ntt_form(flag)) {
      reduce_2q_to_q_(ciphertext_polynomial, ciphertext_polynomial, moduli_id);
    }
    negate_make_unsigned_(ciphertext_polynomial, subtracted_polynomial,
                          moduli_id);
  }

  if (plaintext_ntt_form) {
    release(plaintext_ntt_form);
  }

  return subtracted;
}

UnitCiphertext *CKKSCore::subtract(UnitCiphertext *ciphertext,
                                   UnitPlaintext *plaintext) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;

  const DataFlag flag = ciphertext->flag_;
  const int polynomial_count = ciphertext->polynomial_count();
  auto subtracted = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, ciphertext->ckks_scale_);

  const auto ciphertext0 = get_polynomial(ciphertext, 0);
  UnitPlaintext *plaintext_ntt_form = nullptr;
  auto plaintext0 = get_polynomial(plaintext, 0);

  if (is_ntt_form(flag)) {
    plaintext_ntt_form = to_ntt_form(plaintext);
    plaintext0 = get_polynomial(plaintext_ntt_form, 0);
  }

  const auto z0 = get_polynomial(subtracted, 0);

  mont_sub_reduce_2q_to_q_(ciphertext0, plaintext0, z0, moduli_id, chain_count);

  for (int polynomial_index = 1; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto ciphertext_polynomial =
        get_polynomial(ciphertext, polynomial_index);
    const auto subtracted_polynomial =
        get_polynomial(subtracted, polynomial_index);
    copy(ciphertext_polynomial, subtracted_polynomial, chain_count);
  }

  if (plaintext_ntt_form) {
    release(plaintext_ntt_form);
  }

  return subtracted;
}

UnitCiphertext *CKKSCore::subtract(UnitCiphertext *ciphertext1,
                                   UnitCiphertext *ciphertext2) {
  const auto moduli_id = ciphertext1->moduli_id_;

  const DataFlag flag = ciphertext1->flag_ | ciphertext2->flag_;
  const int polynomial_count = ciphertext1->polynomial_count();
  auto subtracted = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, ciphertext1->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x1 = get_polynomial(ciphertext1, polynomial_index);
    const auto x2 = get_polynomial(ciphertext2, polynomial_index);
    const auto y = get_polynomial(subtracted, polynomial_index);

    mont_sub_reduce_2q_to_q_(x1, x2, y, moduli_id);
  }

  return subtracted;
}

UnitCiphertext *CKKSCore::subtract_trio_by_duo(UnitCiphertext *trio_ciphertext,
                                               UnitCiphertext *duo_ciphertext) {
  const auto moduli_id = trio_ciphertext->moduli_id_;
  const auto chain_count = trio_ciphertext->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;

  const DataFlag flag = trio_ciphertext->flag_ | duo_ciphertext->flag_;
  const int polynomial_count = 3;
  auto subtracted = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, trio_ciphertext->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < 2; polynomial_index++) {
    const auto x1 = get_polynomial(trio_ciphertext, polynomial_index);
    const auto x2 = get_polynomial(duo_ciphertext, polynomial_index);
    const auto y = get_polynomial(subtracted, polynomial_index);

    mont_sub_reduce_2q_to_q_(x1, x2, y, moduli_id);
  }

  const auto x1 = get_polynomial(trio_ciphertext, 2);
  const auto y = get_polynomial(subtracted, 2);

  copy(x1, y, chain_count);

  return subtracted;
}

UnitCiphertext *
CKKSCore::subtract_duo_by_trio(UnitCiphertext *duo_ciphertext,
                               UnitCiphertext *trio_ciphertext) {
  const auto moduli_id = trio_ciphertext->moduli_id_;
  const auto chain_count = trio_ciphertext->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;

  const DataFlag flag = duo_ciphertext->flag_ | trio_ciphertext->flag_;
  const int polynomial_count = 3;
  auto subtracted = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, trio_ciphertext->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < 2; polynomial_index++) {
    const auto x1 = get_polynomial(duo_ciphertext, polynomial_index);
    const auto x2 = get_polynomial(trio_ciphertext, polynomial_index);
    const auto y = get_polynomial(subtracted, polynomial_index);

    mont_sub_reduce_2q_to_q_(x1, x2, y, moduli_id);
  }

  const auto x1 = get_polynomial(trio_ciphertext, 2);
  const auto y = get_polynomial(subtracted, 2);
  reduce_2q_to_q_(x1, y, moduli_id);
  negate_make_unsigned_(y, y, moduli_id);

  return subtracted;
}

void CKKSCore::subtract_inplace(UnitCiphertext *ciphertext,
                                UnitPlaintext *plaintext) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);

  const DataFlag flag = ciphertext->flag_;

  const auto ciphertext0 = get_polynomial(ciphertext, 0);
  UnitPlaintext *plaintext_ntt_form = nullptr;
  auto plaintext0 = get_polynomial(plaintext, 0);

  if (is_ntt_form(flag)) {
    plaintext_ntt_form = to_ntt_form(plaintext);
    plaintext0 = get_polynomial(plaintext_ntt_form, 0);
  }

  mont_sub_reduce_2q_to_q_(ciphertext0, plaintext0, ciphertext0, moduli_id,
                           chain_count);

  if (plaintext_ntt_form) {
    release(plaintext_ntt_form);
  }
}

void CKKSCore::subtract_inplace(UnitCiphertext *ciphertext1,
                                UnitCiphertext *ciphertext2) {
  const auto moduli_id = ciphertext1->moduli_id_;

  const int polynomial_count = ciphertext1->polynomial_count();

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x1 = get_polynomial(ciphertext1, polynomial_index);
    const auto x2 = get_polynomial(ciphertext2, polynomial_index);

    mont_sub_reduce_2q_to_q_(x1, x2, x1, moduli_id);
  }
}

UnitCiphertext *CKKSCore::relinearize(UnitCiphertext *ciphertext,
                                      RelinearizationKey *relinearization_key) {
  const auto ntt_moduli_id = ciphertext->moduli_id_;
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(ntt_moduli_id);

  const auto [x0, x1, x2] = get_trio_polynomials(ciphertext);

  const DataFlag flag = ciphertext->flag_ & ~DataFlag::NTT_FORM;
  const int polynomial_count = 2;
  auto relinearized = allocate_text<UnitCiphertext>(
      flag, intt_moduli_id, polynomial_count, ciphertext->ckks_scale_);

  const auto [y0, y1] = get_duo_polynomials(relinearized);

  to_intt_(x0, y0, intt_moduli_id);
  to_intt_(x1, y1, intt_moduli_id);

  const auto key_switcher = create_key_switcher_from_ntt(
      x2, relinearization_key->key_switching_key_, ntt_moduli_id);

  const auto [key_switcher0, key_switcher1] = get_duo_polynomials(key_switcher);

  mont_add_reduce_2q_to_q_(y0, key_switcher0, y0, intt_moduli_id);
  mont_add_reduce_2q_to_q_(y1, key_switcher1, y1, intt_moduli_id);

  release(key_switcher);

  return relinearized;
}

template <class T> T *CKKSCore::level_down_after_rescale(T *text, int level) {
  const auto source_level = text->level_;
  const auto source_moduli_id = text->moduli_id_;
  const auto destination_moduli_id = to_moduli_id(level);
  const auto destination_deviation = precomputed_.deviation_[level];
  const long double scale = precomputed_.scale_;

  long double default_scale = destination_deviation * scale * scale;

  auto level_down_multiplier =
      precomputed_.make_level_down_multiplier_after_rescale(source_level,
                                                            level);

  auto multiplier = level_down_multiplier->get();

  const auto flag = text->flag_ & ~DataFlag::RESCALED;
  const int polynomial_count = text->polynomial_count();
  auto leveled_down = allocate_text<T>(flag, destination_moduli_id,
                                       polynomial_count, default_scale);
  const auto x_offset =
      get_chain_offset(source_moduli_id, destination_moduli_id);

  for (auto polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(text, polynomial_index);
    const auto y = get_polynomial(leveled_down, polynomial_index);

    mont_enter_scalar_(x, y, multiplier, destination_moduli_id, x_offset);
    reduce_2q_to_q_(y, y, destination_moduli_id);
  }

  release(level_down_multiplier);

  return leveled_down;
}

template UnitPlaintext *
CKKSCore::level_down_after_rescale<UnitPlaintext>(UnitPlaintext *plaintext,
                                                  int level);
template UnitCiphertext *
CKKSCore::level_down_after_rescale<UnitCiphertext>(UnitCiphertext *ciphertext,
                                                   int level);

template <class T> T *CKKSCore::level_down(T *text, int level) {
  const auto flag = text->flag_;
  const auto source_level = text->level_;
  const auto source_moduli_id = text->moduli_id_;
  const auto next_moduli_id = to_moduli_id(source_level - 1);
  const int destination_moduli_id = to_moduli_id(level);
  const auto destination_deviation = precomputed_.deviation_[level];
  const long double scale = precomputed_.scale_;

  long double default_scale = destination_deviation * scale * scale;

  auto level_down_multiplier =
      precomputed_.make_level_down_multiplier(source_level, level);

  auto multiplier = level_down_multiplier->get();
  const int polynomial_count = text->polynomial_count();
  bool include_special = false;
  auto leveled_down = allocate_text<T>(flag, destination_moduli_id,
                                       polynomial_count, default_scale);

  for (auto polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {

    const auto x = get_polynomial(text, polynomial_index);
    const auto multiplied_multiplier = allocate_polynomial(source_moduli_id);

    const auto chain_count = get_chain_count(source_moduli_id);

    mont_enter_scalar_(x, multiplied_multiplier, multiplier, source_moduli_id);
    reduce_2q_to_q_(multiplied_multiplier, multiplied_multiplier,
                    source_moduli_id);

    const auto multiplied_multiplier_rescaled =
        allocate_polynomial(next_moduli_id);

    rescale_(multiplied_multiplier, multiplied_multiplier_rescaled,
             source_moduli_id, include_special);

    const auto next_chain_count = get_chain_count(destination_moduli_id);
    const auto x_offset = destination_moduli_id - next_moduli_id;

    const auto y = get_polynomial(leveled_down, polynomial_index);

    copy(multiplied_multiplier_rescaled, y, next_chain_count, x_offset);

    release(multiplied_multiplier);
    release(multiplied_multiplier_rescaled);
  }

  release(level_down_multiplier);

  return leveled_down;
}

template UnitPlaintext *
CKKSCore::level_down<UnitPlaintext>(UnitPlaintext *plaintext, int level);
template UnitCiphertext *
CKKSCore::level_down<UnitCiphertext>(UnitCiphertext *ciphertext, int level);

template <class T>
T *CKKSCore::rotate_(T *text, const PermutationParameters *permutation,
                     const PermutationParameters *sign) {
  const auto flag = text->flag_;
  const auto moduli_id = text->moduli_id_;
  const auto polynomial_count = text->polynomial_count();
  const auto chain_count = text->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;
  auto rotated =
      allocate_text<T>(flag, moduli_id, polynomial_count, text->ckks_scale_);

  const auto permutation_values = permutation->get();
  const auto sign_values = sign->get();

  for (auto polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(text, polynomial_index);
    const auto y = get_polynomial(rotated, polynomial_index);
    rotate_polynomial_(x, y, permutation_values, sign_values, chain_count,
                       coeff_count);
    make_unsigned_reduce_2q_to_q_(y, y, moduli_id);
  }

  return rotated;
}

template <class T> T *CKKSCore::rotate_intt_form_(T *text, int delta) {
  auto [permutation, sign] = precomputed_.make_permutation_parameters(delta);

  auto rotated = rotate_(text, permutation, sign);

  release(permutation);
  release(sign);

  return rotated;
}

UnitPlaintext *CKKSCore::rotate_intt_form(UnitPlaintext *plaintext, int delta) {
  return rotate_intt_form_(plaintext, delta);
}

template <class T> T *CKKSCore::rotate_ntt_form_(T *text, int delta) {
  const auto moduli_id = text->moduli_id_;
  const auto polynomial_count = text->polynomial_count();
  const auto chain_count = get_chain_count(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;

  auto ntt_permutation = precomputed_.make_ntt_permutation_parameters(delta);

  const auto permutation_values = ntt_permutation->get();

  auto permuted = allocate_text<T>(text->flag_, moduli_id, polynomial_count,
                                   text->ckks_scale_);

  for (auto polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(text, polynomial_index);
    const auto y = get_polynomial(permuted, polynomial_index);

    permute_polynomial_(x, y, permutation_values, chain_count, coeff_count);
  }

  release(ntt_permutation);

  return permuted;
}

UnitPlaintext *CKKSCore::rotate_ntt_form(UnitPlaintext *plaintext, int delta) {
  return rotate_ntt_form_(plaintext, delta);
}

UnitCiphertext *CKKSCore::key_switch_mod_down(UnitCiphertext *ciphertext,
                                              KeySwitcher *key_switcher) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto prime_count = key_switcher->chain_count_;
  const auto special_prime_count = precomputed_.special_prime_count_;

  const int polynomial_count = 2;
  auto key_switched = allocate_text<UnitCiphertext>(
      ciphertext->flag_, moduli_id, polynomial_count, ciphertext->ckks_scale_);

  auto p_inverse_mult_r = precomputed_.get_p_inverse_mult_r(moduli_id);

  const auto [x0, x1] = get_duo_polynomials(key_switcher);
  const auto [y0, y1] = get_duo_polynomials(key_switched);

  bool can_modify_x = true;
  mod_down(x0, y0, p_inverse_mult_r, can_modify_x);
  mod_down(x1, y1, p_inverse_mult_r, can_modify_x);

  return key_switched;
}

UnitCiphertext *
CKKSCore::rotate(UnitCiphertext *ciphertext,
                 DecomposedUnitCiphertext *decomposed_ciphertext,
                 const FixedRotationKey *fixed_rotation_key) {
  const auto key_switcher = create_key_switcher_for_rotate(
      ciphertext, decomposed_ciphertext, fixed_rotation_key);
  const auto mod_down = key_switch_mod_down(ciphertext, key_switcher);
  const auto rotated = rotate_(mod_down, fixed_rotation_key->permutation_,
                               fixed_rotation_key->sign_);

  release(key_switcher);
  release(mod_down);

  return rotated;
}

UnitCiphertext *CKKSCore::rotate(UnitCiphertext *ciphertext,
                                 const FixedRotationKey *fixed_rotation_key) {
  const auto decomposed = decompose(ciphertext);
  const auto rotated = rotate(ciphertext, decomposed, fixed_rotation_key);

  release(decomposed);

  return rotated;
}

UnitCiphertext *
CKKSCore::ntt_rotate(UnitCiphertext *ciphertext,
                     DecomposedUnitCiphertext *decomposed_ciphertext,
                     const FixedRotationKey *fixed_rotation_key,
                     PermutationParameters *ntt_permutation_parameters) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = ciphertext->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;

  const auto x0 = get_polynomial(ciphertext, 0);

  const auto key_switcher = create_key_switcher(
      decomposed_ciphertext, fixed_rotation_key->key_switching_key_);

  const auto y0 = get_polynomial(key_switcher, 0);

  mont_add_(x0, y0, y0, moduli_id, chain_count);

  const auto permutation = ntt_permutation_parameters->get();

  auto polynomial_count = ciphertext->polynomial_count();
  auto permuted =
      allocate_text<UnitCiphertext>(key_switcher->flag_, moduli_id,
                                    polynomial_count, ciphertext->ckks_scale_);

  for (auto polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(key_switcher, polynomial_index);
    const auto y = get_polynomial(permuted, polynomial_index);

    permute_polynomial_(x, y, permutation, chain_count, coeff_count);
  }

  release(key_switcher);

  return permuted;
}

UnitCiphertext *CKKSCore::negate(UnitCiphertext *ciphertext) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto polynomial_count = ciphertext->polynomial_count();
  const auto flag = ciphertext->flag_;

  auto negated = allocate_text<UnitCiphertext>(
      ciphertext->flag_, moduli_id, polynomial_count, ciphertext->ckks_scale_);

  for (auto polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto ciphertext_polynomial =
        get_polynomial(ciphertext, polynomial_index);
    const auto negated_polynomial = get_polynomial(negated, polynomial_index);

    if (is_ntt_form(flag)) {
      reduce_2q_to_q_(ciphertext_polynomial, ciphertext_polynomial, moduli_id);
    }
    negate_make_unsigned_(ciphertext_polynomial, negated_polynomial, moduli_id);
  }

  return negated;
}

UnitPlaintext *CKKSCore::conjugate_intt_form(UnitPlaintext *plaintext) {
  const int delta = -1;
  return rotate_intt_form(plaintext, delta);
}

UnitPlaintext *CKKSCore::conjugate_ntt_form(UnitPlaintext *plaintext) {
  const int delta = -1;
  return rotate_ntt_form(plaintext, delta);
}

UnitCiphertext *CKKSCore::conjugate(UnitCiphertext *ciphertext,
                                    const ConjugationKey *conjugation_key) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;

  const auto conjugated = rotate_(ciphertext, conjugation_key->permutation_,
                                  conjugation_key->sign_);
  const auto [conjugated0, conjugated1] = get_duo_polynomials(conjugated);

  const auto key_switcher = create_key_switcher_from_intt(
      conjugated1, conjugation_key->key_switching_key_, moduli_id);

  const auto [key_switcher0, key_switcher1] = get_duo_polynomials(key_switcher);

  mont_add_reduce_2q_to_q_(key_switcher0, conjugated0, conjugated0, moduli_id);
  copy(key_switcher1, conjugated1, chain_count);

  release(key_switcher);

  return conjugated;
}

UnitCiphertext *CKKSCore::switch_key(UnitCiphertext *ciphertext,
                                     KeySwitchingKey *key_switching_key) {
  const DataFlag flag = ciphertext->flag_;
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;
  const int polynomial_count = 2;

  auto switched = allocate_text<UnitCiphertext>(
      flag, moduli_id, polynomial_count, ciphertext->ckks_scale_);

  const auto [ciphertext0, ciphertext1] = get_duo_polynomials(ciphertext);
  const auto [switched0, switched1] = get_duo_polynomials(switched);

  const auto key_switcher =
      create_key_switcher_from_intt(ciphertext1, key_switching_key, moduli_id);

  const auto [key_switcher0, key_switcher1] = get_duo_polynomials(key_switcher);

  mont_add_reduce_2q_to_q_(key_switcher0, ciphertext0, switched0, moduli_id);
  copy(key_switcher1, switched1, chain_count);

  release(key_switcher);

  return switched;
}

UnitCiphertext *CKKSCore::make_signed_tile(UnitCiphertext *ciphertext) {

  const DataFlag flag = ciphertext->flag_ & ~DataFlag::RESCALED;
  int moduli_id = to_moduli_id(parameters_.get_max_key_switching_level());
  const int polynomial_count = 2;

  auto tiled =
      allocate_text<UnitCiphertext>(flag, moduli_id, polynomial_count,
                                    precomputed_.scale_ * precomputed_.scale_);

  const auto [x0, x1] = get_duo_polynomials(ciphertext);
  const auto [y0, y1] = get_duo_polynomials(tiled);
  const auto signed0 = allocate_polynomial(moduli_id);
  const auto signed1 = allocate_polynomial(moduli_id);

  make_signed_(x0, signed0, ciphertext->moduli_id_);
  make_signed_(x1, signed1, ciphertext->moduli_id_);

  tile_unsigned_reduce_2q_to_q_(signed0, y0, moduli_id);
  tile_unsigned_reduce_2q_to_q_(signed1, y1, moduli_id);

  release(signed0);
  release(signed1);

  return tiled;
}

int64_t CKKSCore::get_mod_raise_ratio() {
  const double scale = precomputed_.scale_;
  const auto [log_slot_count, log_coeff_count, special_prime] = get_parameter();
  const double partial_sum_ratio = 1 << (log_coeff_count - log_slot_count - 1);
  const double base_prime = static_cast<double>(parameters_.get_base_prime());
  return static_cast<int64_t>(
      std::round(scale * scale / (partial_sum_ratio * base_prime)));
}

int64_t CKKSCore::get_normalize_ratio() {
  const double scale = precomputed_.scale_;
  const double base_prime = static_cast<double>(parameters_.get_base_prime());
  return static_cast<int64_t>(std::round(base_prime / scale));
}

template <typename T> T *CKKSCore::attach_special_prime_chains_(T *input) {
  const auto flag =
      input->flag_ | DataFlag::NTT_FORM | DataFlag::INCLUDE_SPECIAL;
  const auto intt_moduli_id = input->moduli_id_;
  const auto ntt_moduli_id = parameters_.get_ntt_moduli_id(intt_moduli_id);
  const auto polynomial_count = input->polynomial_count();

  auto output = allocate_text<T>(flag, ntt_moduli_id, polynomial_count,
                                 input->ckks_scale_);

  auto p_product_mult_r = precomputed_.get_p_product_mult_r(intt_moduli_id);

  const auto chain_count = input->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;
  const auto special_prime_count = precomputed_.special_prime_count_;

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(input, polynomial_index);
    const auto y = get_polynomial(output, polynomial_index);

    const auto y_offset = chain_count;

    mont_enter_scalar_(x, y, p_product_mult_r, intt_moduli_id);
    zero_fill(y, special_prime_count, y_offset);
    to_ntt_(y, y, ntt_moduli_id);
  }
  return output;
}

UnitPlaintext *CKKSCore::attach_special_prime_chains(UnitPlaintext *input) {
  return attach_special_prime_chains_(input);
}

UnitCiphertext *CKKSCore::attach_special_prime_chains(UnitCiphertext *input) {
  return attach_special_prime_chains_(input);
}

template <typename T> T *CKKSCore::remove_special_prime_chains_(T *input) {
  const auto flag =
      input->flag_ & ~(DataFlag::NTT_FORM | DataFlag::INCLUDE_SPECIAL);
  const auto ntt_moduli_id = input->moduli_id_;
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(ntt_moduli_id);
  const auto polynomial_count = input->polynomial_count();

  auto output = allocate_text<T>(flag, intt_moduli_id, polynomial_count,
                                 input->ckks_scale_);

  auto p_inverse_mult_r = precomputed_.get_p_inverse_mult_r(intt_moduli_id);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(input, polynomial_index);
    const auto y = get_polynomial(output, polynomial_index);

    bool can_modify_x = false;
    mod_down(x, y, p_inverse_mult_r, can_modify_x);
  }

  return output;
}

UnitCiphertext *CKKSCore::remove_special_prime_chains(UnitCiphertext *input) {
  return remove_special_prime_chains_(input);
}

UnitPlaintext *CKKSCore::remove_special_prime_chains(UnitPlaintext *input) {
  return remove_special_prime_chains_(input);
}

PermutationParameters *CKKSCore::make_ntt_permutation_parameters(int delta) {
  auto ntt_permutation_parameters =
      precomputed_.make_ntt_permutation_parameters(delta);

  return ntt_permutation_parameters;
};

}
