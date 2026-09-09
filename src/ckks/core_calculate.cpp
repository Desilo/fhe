#include "arithmetic/arithmetic.h"
#include "arithmetic/pi.h"
#include "ckks/core.h"
#include "ckks/encode.h"
#include "data/polynomial.h"
#include "montgomery/compound.h"
#include "montgomery/unit.h"
#include "operation/fft.h"
#include "operation/ntt.h"
#include "operation/scalar.h"

namespace desilo::fhe {

void CKKSCore::run() { run_parallel(); }

void CKKSCore::run_parallel() {
  if (parallel_enabled_) {
    parallel_processor_->run();
  }

  reset_stream();
}

void CKKSCore::reset_stream() {
  if (parallel_enabled_) {
    parallel_processor_->reset_stream();
  }

  set_stream(0);
}

void CKKSCore::set_stream(int stream_index) {
  stream_index_ = stream_index;

  if (parallel_enabled_) {
    parallel_processor_->set_stream(stream_index);
  }
}

int CKKSCore::to_moduli_id(int level) const {
  return parameters_.get_moduli_id(level);
}

int CKKSCore::to_ntt_moduli_id(int level) const {
  auto intt_moduli_id = parameters_.get_moduli_id(level);
  return parameters_.get_ntt_moduli_id(intt_moduli_id);
}

int CKKSCore::to_key_moduli_id(int level) const {
  auto intt_moduli_id = parameters_.get_moduli_id(level);
  return parameters_.get_key_moduli_id(intt_moduli_id);
}

int CKKSCore::to_key_ntt_moduli_id(int level) const {
  auto key_moduli_id = to_key_moduli_id(level);
  return parameters_.get_ntt_moduli_id(key_moduli_id);
}

int CKKSCore::get_chain_offset(int from_moduli_id, int to_moduli_id) const {
  return parameters_.get_chain_offset(from_moduli_id, to_moduli_id);
}

void CKKSCore::mont_enter_with_coeff_count_(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *constant,
    int moduli_id, int chain_count, int x_coeff_count, int x_offset,
    int y_offset, int parameter_offset) {
  auto q = precomputed_.get_q(moduli_id, parameter_offset);
  auto k = precomputed_.get_k(moduli_id, parameter_offset);
  auto shifted_constant = &constant[parameter_offset];

  if (parallel_enabled_) {
    parallel_processor_->mont_enter(x, y, shifted_constant, q, k, chain_count,
                                    x_coeff_count, x_offset, y_offset);
  } else {
    single_processor_->mont_enter(x, y, shifted_constant, q, k, chain_count,
                                  x_coeff_count, x_offset, y_offset);
  }
}

void CKKSCore::mont_enter_(PolynomialInterface *x, PolynomialInterface *y,
                           const int64_t *constant, int moduli_id,
                           int chain_count, int x_offset, int y_offset,
                           int parameter_offset) {
  const auto coeff_count = precomputed_.coeff_count_;

  mont_enter_with_coeff_count_(x, y, constant, moduli_id, chain_count,
                               coeff_count, x_offset, y_offset,
                               parameter_offset);
}

void CKKSCore::mont_enter_(PolynomialInterface *x, PolynomialInterface *y,
                           int moduli_id, int chain_count) {
  auto r_squared = precomputed_.get_r_squared(moduli_id);
  mont_enter_(x, y, r_squared, moduli_id, chain_count);
}

void CKKSCore::mont_enter_(PolynomialInterface *x, PolynomialInterface *y,
                           int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);

  mont_enter_(x, y, moduli_id, chain_count);
}

void CKKSCore::mont_enter_scalar_(PolynomialInterface *x,
                                  PolynomialInterface *y, const int64_t *scalar,
                                  int moduli_id, int x_offset) {
  const auto chain_count = get_chain_count(moduli_id);

  mont_enter_(x, y, scalar, moduli_id, chain_count, x_offset);
}

void CKKSCore::mont_enter_rescale_(PolynomialInterface *x,
                                   PolynomialInterface *y, int moduli_id,
                                   int chain_count) {
  auto rescale_scale = precomputed_.get_rescale_scale(moduli_id);
  mont_enter_(x, y, rescale_scale, moduli_id, chain_count);
}

void CKKSCore::make_signed_with_coeff_count_(PolynomialInterface *x,
                                             PolynomialInterface *y,
                                             int moduli_id, int x_coeff_count) {
  auto q = precomputed_.get_q(moduli_id);
  auto q_half = precomputed_.get_q_half(moduli_id);
  const auto chain_count = get_chain_count(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->make_signed(x, y, q, q_half, chain_count,
                                     x_coeff_count);
  } else {
    single_processor_->make_signed(x, y, q, q_half, chain_count, x_coeff_count);
  }
}

void CKKSCore::make_signed_(PolynomialInterface *x, PolynomialInterface *y,
                            int moduli_id) {
  const auto coeff_count = precomputed_.coeff_count_;

  make_signed_with_coeff_count_(x, y, moduli_id, coeff_count);
}

void CKKSCore::mont_add_(PolynomialInterface *x1, PolynomialInterface *x2,
                         PolynomialInterface *y, int moduli_id,
                         int chain_count) {
  auto q_double = precomputed_.get_q_double(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->mont_add(x1, x2, y, q_double, chain_count);
  } else {
    single_processor_->mont_add(x1, x2, y, q_double, chain_count);
  }
}

void CKKSCore::mont_mult_(PolynomialInterface *x1, PolynomialInterface *x2,
                          PolynomialInterface *y, int moduli_id,
                          int chain_count, int x1_offset, int x2_offset) {
  auto q = precomputed_.get_q(moduli_id);
  auto k = precomputed_.get_k(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->mont_mult(x1, x2, y, q, k, chain_count, x1_offset,
                                   x2_offset);
  } else {
    single_processor_->mont_mult(x1, x2, y, q, k, chain_count, x1_offset,
                                 x2_offset);
  }
}

void CKKSCore::mont_mult_(PolynomialInterface *x1, PolynomialInterface *x2,
                          PolynomialInterface *y, int moduli_id, int x1_offset,
                          int x2_offset) {
  const auto chain_count = get_chain_count(moduli_id);
  mont_mult_(x1, x2, y, moduli_id, chain_count, x1_offset, x2_offset);
}

void CKKSCore::reduce_2q_to_q_(PolynomialInterface *x, PolynomialInterface *y,
                               int moduli_id, int chain_count) {
  auto q = precomputed_.get_q(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->reduce_2q_to_q(x, y, q, chain_count);
  } else {
    single_processor_->reduce_2q_to_q(x, y, q, chain_count);
  }
}

void CKKSCore::reduce_2q_to_q_(PolynomialInterface *x, PolynomialInterface *y,
                               int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  reduce_2q_to_q_(x, y, moduli_id, chain_count);
}

void CKKSCore::get_rounder_(PolynomialInterface *x, PolynomialInterface *y,
                            int moduli_id, int x_offset, int parameter_offset) {
  auto q_half = precomputed_.get_q_half(moduli_id)[parameter_offset];

  if (parallel_enabled_) {
    parallel_processor_->get_rounder(x, y, q_half, x_offset);
  } else {
    single_processor_->get_rounder(x, y, q_half, x_offset);
  }
}

void CKKSCore::add_tiled_(PolynomialInterface *x1, PolynomialInterface *x2,
                          PolynomialInterface *y, int moduli_id,
                          int chain_count) {
  auto q_double = precomputed_.get_q_double(moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;

  if (parallel_enabled_) {
    parallel_processor_->add_tiled(x1, x2, y, q_double, chain_count);
  } else {
    single_processor_->add_tiled(x1, x2, y, q_double, chain_count);
  }
}

void CKKSCore::sub_tiled_(PolynomialInterface *x1, PolynomialInterface *x2,
                          PolynomialInterface *y, int moduli_id,
                          int chain_count, int x1_offset, int y_offset,
                          int parameter_offset) {
  auto q_double = precomputed_.get_q_double(moduli_id, parameter_offset);
  const auto coeff_count = precomputed_.coeff_count_;

  if (parallel_enabled_) {
    parallel_processor_->sub_tiled(x1, x2, y, q_double, chain_count, x1_offset,
                                   y_offset);
  } else {
    single_processor_->sub_tiled(x1, x2, y, q_double, chain_count, x1_offset,
                                 y_offset);
  }
}

void CKKSCore::mont_enter_tiled_from_(PolynomialInterface *x,
                                      PolynomialInterface *y, int moduli_id,
                                      int chain_start, int chain_count,
                                      int x_offset, int y_offset) {
  auto r_squared = precomputed_.get_r_squared(moduli_id, chain_start);
  auto q = precomputed_.get_q(moduli_id, chain_start);
  auto k = precomputed_.get_k(moduli_id, chain_start);

  if (parallel_enabled_) {
    parallel_processor_->mont_enter_tiled(x, y, r_squared, q, k, chain_count,
                                          x_offset, y_offset);
  } else {
    single_processor_->mont_enter_tiled(x, y, r_squared, q, k, chain_count,
                                        x_offset, y_offset);
  }
}

void CKKSCore::mont_enter_tiled_(PolynomialInterface *x, PolynomialInterface *y,
                                 int moduli_id, int chain_count, int x_offset,
                                 int y_offset) {
  int chain_start = 0;
  mont_enter_tiled_from_(x, y, moduli_id, chain_start, chain_count, x_offset,
                         y_offset);
}

void CKKSCore::mont_enter_tiled_add_from_(PolynomialInterface *x,
                                          PolynomialInterface *y,
                                          const int64_t *constant,
                                          int moduli_id, int chain_start,
                                          int chain_count, int x_offset,
                                          int y_offset) {
  auto q_double = precomputed_.get_q_double(moduli_id, chain_start);
  auto q = precomputed_.get_q(moduli_id, chain_start);
  auto k = precomputed_.get_k(moduli_id, chain_start);
  auto shifted_constant = &constant[chain_start];

  if (parallel_enabled_) {
    parallel_processor_->mont_enter_tiled_add(x, y, shifted_constant, q_double,
                                              q, k, chain_count, x_offset,
                                              y_offset);
  } else {
    single_processor_->mont_enter_tiled_add(x, y, shifted_constant, q_double, q,
                                            k, chain_count, x_offset, y_offset);
  }
}

void CKKSCore::mont_enter_tiled_add_(PolynomialInterface *x,
                                     PolynomialInterface *y,
                                     const int64_t *constant, int moduli_id,
                                     int chain_count, int x_offset,
                                     int y_offset) {
  int chain_start = 0;
  mont_enter_tiled_add_from_(x, y, constant, moduli_id, chain_start,
                             chain_count, x_offset, y_offset);
}

void CKKSCore::mont_enter_tiled_add_reduce_2q_to_q_from_(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *constant,
    int moduli_id, int chain_start, int chain_count, int x_offset,
    int y_offset) {
  auto q_double = precomputed_.get_q_double(moduli_id, chain_start);
  auto q = precomputed_.get_q(moduli_id, chain_start);
  auto k = precomputed_.get_k(moduli_id, chain_start);

  if (parallel_enabled_) {
    parallel_processor_->mont_enter_tiled_add_reduce_2q_to_q(
        x, y, constant, q_double, q, k, chain_count, x_offset, y_offset);
  } else {
    single_processor_->mont_enter_tiled_add_reduce_2q_to_q(
        x, y, constant, q_double, q, k, chain_count, x_offset, y_offset);
  }
}

void CKKSCore::mont_mult_add_(PolynomialInterface *x1, PolynomialInterface *x2,
                              PolynomialInterface *y, int moduli_id,
                              int chain_count, int x1_offset, int x2_offset) {
  auto q_double = precomputed_.get_q_double(moduli_id);
  auto q = precomputed_.get_q(moduli_id);
  auto k = precomputed_.get_k(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->mont_mult_add(x1, x2, y, q_double, q, k, chain_count,
                                       x1_offset, x2_offset);
  } else {
    single_processor_->mont_mult_add(x1, x2, y, q_double, q, k, chain_count,
                                     x1_offset, x2_offset);
  }
}

void CKKSCore::mont_sub_enter_reduce_2q_to_q_from_(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const int64_t *constant, int moduli_id, int chain_start, int chain_count,
    int x1_offset, int x2_offset, int y_offset) {
  auto q_double = precomputed_.get_q_double(moduli_id, chain_start);
  auto q = precomputed_.get_q(moduli_id, chain_start);
  auto k = precomputed_.get_k(moduli_id, chain_start);

  if (parallel_enabled_) {
    parallel_processor_->mont_sub_enter_reduce_2q_to_q(
        x1, x2, y, constant, q_double, q, k, chain_count, x1_offset, x2_offset,
        y_offset);
  } else {
    single_processor_->mont_sub_enter_reduce_2q_to_q(
        x1, x2, y, constant, q_double, q, k, chain_count, x1_offset, x2_offset,
        y_offset);
  }
}

void CKKSCore::mont_sub_tiled_enter_(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const int64_t *constant, int moduli_id, int chain_count, int x1_offset,
    int x2_offset, int y_offset, int parameter_offset) {
  auto q_double = precomputed_.get_q_double(moduli_id, parameter_offset);
  auto q = precomputed_.get_q(moduli_id, parameter_offset);
  auto k = precomputed_.get_k(moduli_id, parameter_offset);
  auto shifted_constant = &constant[parameter_offset];

  if (parallel_enabled_) {
    parallel_processor_->mont_sub_tiled_enter(x1, x2, y, shifted_constant,
                                              q_double, q, k, chain_count,
                                              x1_offset, x2_offset, y_offset);
  } else {
    single_processor_->mont_sub_tiled_enter(x1, x2, y, shifted_constant,
                                            q_double, q, k, chain_count,
                                            x1_offset, x2_offset, y_offset);
  }
}

void CKKSCore::mont_enter_exit_(PolynomialInterface *x, PolynomialInterface *y,
                                int moduli_id, int chain_count) {
  auto coeff_count_inverse = precomputed_.get_coeff_count_inverse(moduli_id);
  auto q = precomputed_.get_q(moduli_id);
  auto k = precomputed_.get_k(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->mont_enter_exit(x, y, coeff_count_inverse, q, k,
                                         chain_count);
  } else {
    single_processor_->mont_enter_exit(x, y, coeff_count_inverse, q, k,
                                       chain_count);
  }
}

void CKKSCore::mont_enter_exit_(PolynomialInterface *x, PolynomialInterface *y,
                                int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  mont_enter_exit_(x, y, moduli_id, chain_count);
}

void CKKSCore::mont_enter_exit_reduce_2q_to_q_(PolynomialInterface *x,
                                               PolynomialInterface *y,
                                               int moduli_id, int chain_count) {
  auto coeff_count_inverse = precomputed_.get_coeff_count_inverse(moduli_id);
  auto q = precomputed_.get_q(moduli_id);
  auto k = precomputed_.get_k(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->mont_enter_exit_reduce_2q_to_q(
        x, y, coeff_count_inverse, q, k, chain_count);
  } else {
    single_processor_->mont_enter_exit_reduce_2q_to_q(x, y, coeff_count_inverse,
                                                      q, k, chain_count);
  }
}

void CKKSCore::mont_add_reduce_2q_to_q_from_(PolynomialInterface *x1,
                                             PolynomialInterface *x2,
                                             PolynomialInterface *y,
                                             int moduli_id, int chain_start,
                                             int chain_count, int x1_offset,
                                             int x2_offset, int y_offset) {
  auto q_double = precomputed_.get_q_double(moduli_id, chain_start);
  auto q = precomputed_.get_q(moduli_id, chain_start);

  if (parallel_enabled_) {
    parallel_processor_->mont_add_reduce_2q_to_q(
        x1, x2, y, q_double, q, chain_count, x1_offset, x2_offset, y_offset);
  } else {
    single_processor_->mont_add_reduce_2q_to_q(
        x1, x2, y, q_double, q, chain_count, x1_offset, x2_offset, y_offset);
  }
}

void CKKSCore::mont_add_reduce_2q_to_q_(PolynomialInterface *x1,
                                        PolynomialInterface *x2,
                                        PolynomialInterface *y, int moduli_id,
                                        int chain_count, int x1_offset,
                                        int x2_offset, int y_offset) {
  const auto chain_start = 0;
  mont_add_reduce_2q_to_q_from_(x1, x2, y, moduli_id, chain_start, chain_count,
                                x1_offset, x2_offset, y_offset);
}

void CKKSCore::mont_add_reduce_2q_to_q_(PolynomialInterface *x1,
                                        PolynomialInterface *x2,
                                        PolynomialInterface *y, int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  mont_add_reduce_2q_to_q_(x1, x2, y, moduli_id, chain_count);
}

void CKKSCore::mont_sub_reduce_2q_to_q_(PolynomialInterface *x1,
                                        PolynomialInterface *x2,
                                        PolynomialInterface *y, int moduli_id,
                                        int chain_count) {
  auto q_double = precomputed_.get_q_double(moduli_id);
  auto q = precomputed_.get_q(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q,
                                                 chain_count);
  } else {
    single_processor_->mont_sub_reduce_2q_to_q(x1, x2, y, q_double, q,
                                               chain_count);
  }
}

void CKKSCore::mont_sub_reduce_2q_to_q_(PolynomialInterface *x1,
                                        PolynomialInterface *x2,
                                        PolynomialInterface *y, int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  mont_sub_reduce_2q_to_q_(x1, x2, y, moduli_id, chain_count);
}

void CKKSCore::make_unsigned_reduce_2q_to_q_with_coeff_count_(
    PolynomialInterface *x, PolynomialInterface *y, int moduli_id,
    int chain_count, int x_coeff_count) {
  auto q = precomputed_.get_q(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->make_unsigned_reduce_2q_to_q(x, y, q, chain_count,
                                                      x_coeff_count);
  } else {
    single_processor_->make_unsigned_reduce_2q_to_q(x, y, q, chain_count,
                                                    x_coeff_count);
  }
}

void CKKSCore::make_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                             PolynomialInterface *y,
                                             int moduli_id, int chain_count) {
  const auto coeff_count = precomputed_.coeff_count_;

  make_unsigned_reduce_2q_to_q_with_coeff_count_(x, y, moduli_id, chain_count,
                                                 coeff_count);
}

void CKKSCore::make_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                             PolynomialInterface *y,
                                             int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  make_unsigned_reduce_2q_to_q_(x, y, moduli_id, chain_count);
}

void CKKSCore::tile_unsigned_reduce_2q_to_q_with_coeff_count_(
    PolynomialInterface *x, PolynomialInterface *y, int moduli_id,
    int chain_count, int x_coeff_count, int x_offset, int y_offset) {
  auto q = precomputed_.get_q(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->tile_unsigned_reduce_2q_to_q(
        x, y, q, chain_count, x_coeff_count, x_offset, y_offset);
  } else {
    single_processor_->tile_unsigned_reduce_2q_to_q(
        x, y, q, chain_count, x_coeff_count, x_offset, y_offset);
  }
}

void CKKSCore::tile_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                             PolynomialInterface *y,
                                             int moduli_id, int chain_count,
                                             int x_offset, int y_offset) {
  const auto coeff_count = precomputed_.coeff_count_;
  tile_unsigned_reduce_2q_to_q_with_coeff_count_(
      x, y, moduli_id, chain_count, coeff_count, x_offset, y_offset);
}

void CKKSCore::tile_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                             PolynomialInterface *y,
                                             int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  tile_unsigned_reduce_2q_to_q_(x, y, moduli_id, chain_count);
}

template <typename T> DoublePolynomial *CKKSCore::permute_for_fft_(T *x) {
  const auto slot_count = precomputed_.slot_count_;
  const auto y_count = slot_count * 4;
  auto y = allocate_double_polynomial(y_count);
  const auto pre_permutation = precomputed_.get_pre_permutation();

  const auto x_buffer = x->buffer_;
  const auto y_buffer = y->buffer_;

  pre_permute(x_buffer, y_buffer, pre_permutation, y_count, 0, slot_count);

  return y;
}

template DoublePolynomial *CKKSCore::permute_for_fft_(DoublePolynomial *x);
template DoublePolynomial *
CKKSCore::permute_for_fft_(ComplexDoublePolynomial *x);

void CKKSCore::bit_reversal_permute_(std::complex<double> *x) {
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;

  bit_reversal_permute(x, x, codec_coeff_count);
}

DoublePolynomial *CKKSCore::apply_twister_(DoublePolynomial *x, double scale) {
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;
  const auto y_count = codec_coeff_count * 2;
  const double step = -pi / y_count;
  auto y = allocate_double_polynomial(y_count);

  const auto x_buffer = x->buffer_;
  const auto y_buffer = y->buffer_;

  apply_twister(x_buffer, y_buffer, codec_coeff_count, 0, step, scale);

  return y;
}

DoublePolynomial *CKKSCore::apply_skewer_(DoublePolynomial *x) {
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;
  const auto y_count = codec_coeff_count * 2;
  const double step = pi / y_count;
  auto y = allocate_double_polynomial(y_count);

  if (parallel_enabled_) {
    parallel_processor_->apply_skewer(x, y, step, codec_coeff_count);
  } else {
    single_processor_->apply_skewer(x, y, step, codec_coeff_count);
  }

  return y;
}

void CKKSCore::double_to_rns_(double *x, Polynomial *y, int moduli_id,
                              int chain_count, int y_offset) {
  auto q = precomputed_.get_q(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->double_to_rns(x, y, q, chain_count, y_offset);
  } else {
    single_processor_->double_to_rns(x, y, q, chain_count, y_offset);
  }
}

void CKKSCore::rns_to_double_(Polynomial *x, double *y,
                              DecodeParameters &decode_parameters,
                              int moduli_id, int chain_count) {
  auto q = precomputed_.get_q(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->rns_to_double(x, y, q, decode_parameters.q_product_,
                                       decode_parameters.q_product_half_,
                                       decode_parameters.rns_reverser_.data(),
                                       decode_parameters.r_minus_k_product_,
                                       chain_count);
  } else {
    single_processor_->rns_to_double(x, y, q, decode_parameters.q_product_,
                                     decode_parameters.q_product_half_,
                                     decode_parameters.rns_reverser_.data(),
                                     decode_parameters.r_minus_k_product_,
                                     chain_count);
  }
}

template <typename T>
void CKKSCore::permute_after_ifft_(double *x, T *y, long double scale) {
  const auto slot_count = precomputed_.slot_count_;
  const double scale_inverse = static_cast<double>(1.0 / scale);
  const auto permutation = precomputed_.get_post_permutation();

  permute_after_ifft(x, y, permutation, slot_count, scale_inverse, 0,
                     slot_count * 2);
}

template void CKKSCore::permute_after_ifft_(double *x, double *y,
                                            long double scale);
template void CKKSCore::permute_after_ifft_(double *x, std::complex<double> *y,
                                            long double scale);

void CKKSCore::fft_(std::complex<double> *x, std::complex<double> *y) {
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;
  const auto fft_twiddle_factor = precomputed_.fft_twiddle_factor_.data();

  if (parallel_enabled_) {
    parallel_processor_->fft(x, y, fft_twiddle_factor, codec_coeff_count);
  } else {
    single_processor_->fft(x, y, fft_twiddle_factor, codec_coeff_count);
  }
}

void CKKSCore::ifft_(std::complex<double> *x, std::complex<double> *y) {
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;
  const auto ifft_twiddle_factor = precomputed_.ifft_twiddle_factor_.data();

  if (parallel_enabled_) {
    parallel_processor_->ifft(x, y, ifft_twiddle_factor, codec_coeff_count);
  } else {
    single_processor_->ifft(x, y, ifft_twiddle_factor, codec_coeff_count);
  }
}

void CKKSCore::normalize_(double *x, double *y) {
  const auto codec_coeff_count = precomputed_.codec_coeff_count_;

  normalize(x, y, codec_coeff_count);
}

double *CKKSCore::extract_diagonals(double *matrix, int outer_loop_count,
                                    int inner_loop_count) {
  const auto slot_count = outer_loop_count * inner_loop_count;
  double *diagonals;
  int diagonals_size = slot_count * slot_count;

  diagonals = new double[diagonals_size]{};
  if (parallel_enabled_) {
    parallel_processor_->extract_diagonals(matrix, diagonals, outer_loop_count,
                                           inner_loop_count);
  } else {
    single_processor_->extract_diagonals(matrix, diagonals, outer_loop_count,
                                         inner_loop_count);
  }

  return diagonals;
}

double *CKKSCore::extract_diagonals(std::vector<double> &matrix,
                                    int outer_loop_count,
                                    int inner_loop_count) {
  double *buffer = matrix.data();

  auto diagonals =
      extract_diagonals(buffer, outer_loop_count, inner_loop_count);

  return diagonals;
}

std::complex<double> *CKKSCore::extract_diagonals(std::complex<double> *matrix,
                                                  int outer_loop_count,
                                                  int inner_loop_count) {
  const auto slot_count = outer_loop_count * inner_loop_count;
  std::complex<double> *diagonals;
  int diagonals_size = slot_count * slot_count;

  diagonals = new std::complex<double>[diagonals_size] {};
  if (parallel_enabled_) {
    parallel_processor_->extract_diagonals(matrix, diagonals, outer_loop_count,
                                           inner_loop_count);
  } else {
    single_processor_->extract_diagonals(matrix, diagonals, outer_loop_count,
                                         inner_loop_count);
  }

  return diagonals;
}

std::complex<double> *
CKKSCore::extract_diagonals(std::vector<std::complex<double>> &matrix,
                            int outer_loop_count, int inner_loop_count) {
  std::complex<double> *buffer = matrix.data();

  auto diagonals =
      extract_diagonals(buffer, outer_loop_count, inner_loop_count);

  return diagonals;
}

void CKKSCore::ntt_from_(PolynomialInterface *x, PolynomialInterface *y,
                         int moduli_id, int chain_start, int chain_count,
                         int x_offset, int y_offset) {
  auto root = precomputed_.get_root(moduli_id, chain_start);
  auto q_double = precomputed_.get_q_double(moduli_id, chain_start);
  auto q = precomputed_.get_q(moduli_id, chain_start);
  auto k = precomputed_.get_k(moduli_id, chain_start);

  if (parallel_enabled_) {
    parallel_processor_->ntt(x, y, root, q_double, q, k, chain_count, x_offset,
                             y_offset);
  } else {
    single_processor_->ntt(x, y, root, q_double, q, k, chain_count, x_offset,
                           y_offset);
  }
}

void CKKSCore::ntt_(PolynomialInterface *x, PolynomialInterface *y,
                    int moduli_id, int chain_count, int x_offset,
                    int y_offset) {
  int chain_start = 0;
  ntt_from_(x, y, moduli_id, chain_start, chain_count, x_offset, y_offset);
}

void CKKSCore::ntt_(PolynomialInterface *x, PolynomialInterface *y,
                    int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  ntt_(x, y, moduli_id, chain_count);
}

void CKKSCore::intt_(PolynomialInterface *x, PolynomialInterface *y,
                     int moduli_id, int chain_count, int x_offset,
                     int y_offset) {
  auto root_inverse = precomputed_.get_root_inverse(moduli_id);
  auto q_double = precomputed_.get_q_double(moduli_id);
  auto q = precomputed_.get_q(moduli_id);
  auto k = precomputed_.get_k(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->intt(x, y, root_inverse, q_double, q, k, chain_count,
                              x_offset, y_offset);
  } else {
    single_processor_->intt(x, y, root_inverse, q_double, q, k, chain_count,
                            x_offset, y_offset);
  }
}

void CKKSCore::intt_(PolynomialInterface *x, PolynomialInterface *y,
                     int moduli_id) {
  const auto chain_count = get_chain_count(moduli_id);
  intt_(x, y, moduli_id, chain_count);
}

void CKKSCore::rotate_polynomial_(Polynomial *x, Polynomial *y,
                                  const int32_t *permutation,
                                  const int32_t *sign, int chain_count,
                                  int coeff_count) {
  if (parallel_enabled_) {
    parallel_processor_->rotate_polynomial(x, y, permutation, sign,
                                           chain_count);
  } else {
    single_processor_->rotate_polynomial(x, y, permutation, sign, chain_count);
  }
}

void CKKSCore::permute_polynomial_(Polynomial *x, Polynomial *y,
                                   const int32_t *permutation, int chain_count,
                                   int coeff_count) {
  if (parallel_enabled_) {
    parallel_processor_->permute_polynomial(x, y, permutation, chain_count);
  } else {
    single_processor_->permute_polynomial(x, y, permutation, chain_count);
  }
}

void CKKSCore::negate_make_unsigned_(PolynomialInterface *x,
                                     PolynomialInterface *y, int moduli_id) {
  auto q = precomputed_.get_q(moduli_id);
  const auto chain_count = get_chain_count(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->negate_make_unsigned(x, y, q, chain_count);
  } else {
    single_processor_->negate_make_unsigned(x, y, q, chain_count);
  }
}

void CKKSCore::concatenate_tile_unsigned_(PolynomialInterface *x1,
                                          PolynomialInterface *x2,
                                          PolynomialInterface *y,
                                          int moduli_id) {
  auto q = precomputed_.get_q(moduli_id);
  const auto chain_count = get_chain_count(moduli_id);

  if (parallel_enabled_) {
    parallel_processor_->concatenate_tile_unsigned(x1, x2, y, q, chain_count);
  } else {
    single_processor_->concatenate_tile_unsigned(x1, x2, y, q, chain_count);
  }
}

void CKKSCore::add_scalar_(PolynomialInterface *x, PolynomialInterface *y,
                           const int64_t *scalar, int chain_count,
                           int coeff_count) {
  if (parallel_enabled_) {
    parallel_processor_->add_scalar(x, y, scalar, chain_count);
  } else {
    single_processor_->add_scalar(x, y, scalar, chain_count);
  }
}

void CKKSCore::zero_fill_with_coeff_count(PolynomialInterface *x,
                                          int chain_count, int x_coeff_count,
                                          int x_offset) {
  if (parallel_enabled_) {
    parallel_processor_->zero_fill(x, chain_count, x_coeff_count, x_offset);
  } else {
    single_processor_->zero_fill(x, chain_count, x_coeff_count, x_offset);
  }
}

void CKKSCore::zero_fill(PolynomialInterface *x, int chain_count,
                         int x_offset) {
  const auto coeff_count = precomputed_.coeff_count_;
  zero_fill_with_coeff_count(x, chain_count, coeff_count, x_offset);
}

void CKKSCore::round_(DoublePolynomial *x, Polynomial *y, int chain_count) {
  if (parallel_enabled_) {
    parallel_processor_->round(x, y, chain_count);
  } else {
    single_processor_->round(x, y, chain_count);
  }
}

void CKKSCore::max_absolute_(DoublePolynomial *x, double *y) {
  if (parallel_enabled_) {
    parallel_processor_->max_absolute(x, y);
  } else {
    single_processor_->max_absolute(x, y);
  }
}

void CKKSCore::cast_int64_to_double_(Polynomial *x, DoublePolynomial *y,
                                     int chain_count) {
  if (parallel_enabled_) {
    parallel_processor_->cast_int64_to_double(x, y, chain_count);
  } else {
    single_processor_->cast_int64_to_double(x, y, chain_count);
  }
}

}
