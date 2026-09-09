#include <algorithm>
#include <vector>

#include "arithmetic/arithmetic.h"
#include "ckks/encode.h"
#include "montgomery/compound.h"
#include "montgomery/unit.h"
#include "operation/fft.h"
#include "operation/ntt.h"
#include "operation/scalar.h"
#include "processor/single.h"

namespace desilo::fhe {

void SingleProcessor::mont_enter(PolynomialInterface *x, PolynomialInterface *y,
                                 const int64_t *constant, const uint64_t *q,
                                 const uint64_t *k, int chain_count,
                                 int coeff_count, int x_offset, int y_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(x_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_constant = constant[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_enter(chain_x, chain_y, chain_constant, chain_q, chain_k,
                            coeff_count);
  }
}

void SingleProcessor::make_signed(PolynomialInterface *x,
                                  PolynomialInterface *y, const uint64_t *q,
                                  const uint64_t *q_half, int chain_count,
                                  int coeff_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q = q[chain_index];
    const auto chain_q_half = q_half[chain_index];

    desilo::fhe::make_signed(chain_x, chain_y, chain_q, chain_q_half,
                             coeff_count);
  }
}

void SingleProcessor::mont_add(PolynomialInterface *x1, PolynomialInterface *x2,
                               PolynomialInterface *y, const uint64_t *q_double,
                               int chain_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(chain_index);
    const auto chain_x2 = x2->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q_double = q_double[chain_index];

    desilo::fhe::mont_add(chain_x1, chain_x2, chain_y, chain_q_double,
                          coeff_count_);
  }
}

void SingleProcessor::mont_mult(PolynomialInterface *x1,
                                PolynomialInterface *x2, PolynomialInterface *y,
                                const uint64_t *q, const uint64_t *k,
                                int chain_count, int x1_offset, int x2_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(x1_offset + chain_index);
    const auto chain_x2 = x2->get(x2_offset + chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_mult(chain_x1, chain_x2, chain_y, chain_q, chain_k,
                           coeff_count_);
  }
}

void SingleProcessor::reduce_2q_to_q(PolynomialInterface *x,
                                     PolynomialInterface *y, const uint64_t *q,
                                     int chain_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q = q[chain_index];

    desilo::fhe::reduce_2q_to_q(chain_x, chain_y, chain_q, coeff_count_);
  }
}

void SingleProcessor::add_tiled(PolynomialInterface *x1,
                                PolynomialInterface *x2, PolynomialInterface *y,
                                const uint64_t *q_double, int chain_count) {
  const auto chain_x2 = x2->get(0);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q_double = q_double[chain_index];

    desilo::fhe::mont_add(chain_x1, chain_x2, chain_y, chain_q_double,
                          coeff_count_);
  }
}

void SingleProcessor::sub_tiled(PolynomialInterface *x1,
                                PolynomialInterface *x2, PolynomialInterface *y,
                                const uint64_t *q_double, int chain_count,
                                int x1_offset, int y_offset) {
  const auto chain_x2 = x2->get(0);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(x1_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_q_double = q_double[chain_index];

    desilo::fhe::mont_subtract(chain_x1, chain_x2, chain_y, chain_q_double,
                               coeff_count_);
  }
}

void SingleProcessor::get_rounder(PolynomialInterface *x,
                                  PolynomialInterface *y, uint64_t q_half,
                                  int x_offset) {
  const auto chain_x = x->get(x_offset);
  const auto chain_y = y->get(0);

  desilo::fhe::get_rounder(chain_x, chain_y, q_half, coeff_count_);
}

void SingleProcessor::mont_enter_tiled(PolynomialInterface *x,
                                       PolynomialInterface *y,
                                       const int64_t *r_squared,
                                       const uint64_t *q, const uint64_t *k,
                                       int chain_count, int x_offset,
                                       int y_offset) {
  const auto chain_x = x->get(x_offset);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_r_squared = r_squared[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_enter(chain_x, chain_y, chain_r_squared, chain_q, chain_k,
                            coeff_count_);
  }
}

void SingleProcessor::mont_enter_tiled_add(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *r_squared,
    const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
    int chain_count, int x_offset, int y_offset) {
  const auto chain_x = x->get(x_offset);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_r_squared = r_squared[chain_index];
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_enter_add(chain_x, chain_y, chain_r_squared,
                                chain_q_double, chain_q, chain_k, coeff_count_);
  }
}

void SingleProcessor::mont_enter_tiled_add_reduce_2q_to_q(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *r_squared,
    const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
    int chain_count, int x_offset, int y_offset) {
  const auto chain_x = x->get(x_offset);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_r_squared = r_squared[chain_index];
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_enter_add_reduce_2q_to_q(chain_x, chain_y,
                                               chain_r_squared, chain_q_double,
                                               chain_q, chain_k, coeff_count_);
  }
}

void SingleProcessor::mont_mult_add(PolynomialInterface *x1,
                                    PolynomialInterface *x2,
                                    PolynomialInterface *y,
                                    const uint64_t *q_double, const uint64_t *q,
                                    const uint64_t *k, int chain_count,
                                    int x1_offset, int x2_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(x1_offset + chain_index);
    const auto chain_x2 = x2->get(x2_offset + chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_mult_add(chain_x1, chain_x2, chain_y, chain_q_double,
                               chain_q, chain_k, coeff_count_);
  }
}

void SingleProcessor::mont_sub_enter_reduce_2q_to_q(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const int64_t *constant, const uint64_t *q_double, const uint64_t *q,
    const uint64_t *k, int chain_count, int x1_offset, int x2_offset,
    int y_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(x1_offset + chain_index);
    const auto chain_x2 = x2->get(x2_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_constant = constant[chain_index];
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_sub_enter_reduce_2q_to_q(chain_x1, chain_x2, chain_y,
                                               chain_constant, chain_q_double,
                                               chain_q, chain_k, coeff_count_);
  }
}

void SingleProcessor::mont_sub_tiled_enter(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const int64_t *constant, const uint64_t *q_double, const uint64_t *q,
    const uint64_t *k, int chain_count, int x1_offset, int x2_offset,
    int y_offset) {
  const auto chain_x2 = x2->get(x2_offset);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(x1_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_constant = constant[chain_index];
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_sub_enter(chain_x1, chain_x2, chain_y, chain_constant,
                                chain_q_double, chain_q, chain_k, coeff_count_);
  }
}

void SingleProcessor::mont_enter_exit(PolynomialInterface *x,
                                      PolynomialInterface *y,
                                      const int64_t *constant,
                                      const uint64_t *q, const uint64_t *k,
                                      int chain_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_constant = constant[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_enter_exit(chain_x, chain_y, chain_constant, chain_q,
                                 chain_k, coeff_count_);
  }
}

void SingleProcessor::mont_enter_exit_reduce_2q_to_q(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *constant,
    const uint64_t *q, const uint64_t *k, int chain_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_constant = constant[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::mont_enter_exit_reduce_2q_to_q(
        chain_x, chain_y, chain_constant, chain_q, chain_k, coeff_count_);
  }
}

void SingleProcessor::mont_add_reduce_2q_to_q(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const uint64_t *q_double, const uint64_t *q, int chain_count, int x1_offset,
    int x2_offset, int y_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(x1_offset + chain_index);
    const auto chain_x2 = x2->get(x2_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];

    desilo::fhe::mont_add_reduce_2q_to_q(chain_x1, chain_x2, chain_y,
                                         chain_q_double, chain_q, coeff_count_);
  }
}

void SingleProcessor::mont_sub_reduce_2q_to_q(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const uint64_t *q_double, const uint64_t *q, int chain_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x1 = x1->get(chain_index);
    const auto chain_x2 = x2->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];

    desilo::fhe::mont_sub_reduce_2q_to_q(chain_x1, chain_x2, chain_y,
                                         chain_q_double, chain_q, coeff_count_);
  }
}

void SingleProcessor::make_unsigned_reduce_2q_to_q(PolynomialInterface *x,
                                                   PolynomialInterface *y,
                                                   const uint64_t *q,
                                                   int chain_count,
                                                   int coeff_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q = q[chain_index];

    desilo::fhe::make_unsigned_reduce_2q_to_q(chain_x, chain_y, chain_q,
                                              coeff_count);
  }
}

void SingleProcessor::tile_unsigned_reduce_2q_to_q(
    PolynomialInterface *x, PolynomialInterface *y, const uint64_t *q,
    int chain_count, int coeff_count, int x_offset, int y_offset) {
  const auto chain_x = x->get(x_offset);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_q = q[chain_index];

    desilo::fhe::make_unsigned_reduce_2q_to_q(chain_x, chain_y, chain_q,
                                              coeff_count);
  }
}

void SingleProcessor::negate_make_unsigned(PolynomialInterface *x,
                                           PolynomialInterface *y,
                                           const uint64_t *q, int chain_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_q = q[chain_index];

    desilo::fhe::negate_make_unsigned(chain_x, chain_y, chain_q, coeff_count_);
  }
}

void SingleProcessor::concatenate_tile_unsigned(PolynomialInterface *x1,
                                                PolynomialInterface *x2,
                                                PolynomialInterface *y,
                                                const uint64_t *q,
                                                int chain_count) {
  const auto chain_x1 = x1->get(0);
  const auto chain_x2 = x2->get(0);
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_y = y->get(chain_index);
    const auto chain_q = q[chain_index];

    desilo::fhe::concatenate_make_unsigned(chain_x1, chain_x2, chain_y, chain_q,
                                           coeff_count_);
  }
}

void SingleProcessor::apply_skewer(DoublePolynomial *x, DoublePolynomial *y,
                                   double step, int size) {
  desilo::fhe::apply_skewer(x->buffer_, y->buffer_, size, 0, step);
}

void SingleProcessor::fft(std::complex<double> *x, std::complex<double> *y,
                          const std::complex<double> *twiddle_factor,
                          int size) {
  desilo::fhe::fft(x, y, twiddle_factor, size);
}

void SingleProcessor::ifft(std::complex<double> *x, std::complex<double> *y,
                           const std::complex<double> *twiddle_factor,
                           int size) {

  desilo::fhe::fft(x, y, twiddle_factor, size);
}

template <typename T>
void SingleProcessor::extract_diagonals(T *x, T *y, int outer_loop_count,
                                        int inner_loop_count) {
  const auto slot_count = outer_loop_count * inner_loop_count;

  const auto modulo_mask = slot_count - 1;

  const auto double_slot_count = 2 * slot_count;

  for (int outer_loop_index = 0; outer_loop_index < outer_loop_count;
       outer_loop_index++) {
    const auto normalized_outer_loop_index =
        outer_loop_index - outer_loop_count / 2;
    int delta = -(normalized_outer_loop_index * inner_loop_count);

    delta = (delta + double_slot_count) & modulo_mask;

    for (int inner_loop_index = 0; inner_loop_index < inner_loop_count;
         inner_loop_index++) {
      auto diagonal_index =
          inner_loop_count * normalized_outer_loop_index + inner_loop_index;
      diagonal_index = (diagonal_index + double_slot_count) & modulo_mask;

      auto loop_index = outer_loop_index * inner_loop_count + inner_loop_index;
      auto diagonal_y = &y[loop_index * slot_count];

      for (int data_index = 0; data_index < slot_count; data_index++) {
        auto row_index = data_index - delta;
        auto column_index = row_index - diagonal_index;

        row_index = (row_index + double_slot_count) & modulo_mask;
        column_index = (column_index + double_slot_count) & modulo_mask;

        diagonal_y[data_index] = x[row_index * slot_count + column_index];
      }
    }
  }
}

template void SingleProcessor::extract_diagonals<double>(double *x, double *y,
                                                         int outer_loop_count,
                                                         int inner_loop_count);
template void SingleProcessor::extract_diagonals<std::complex<double>>(
    std::complex<double> *x, std::complex<double> *y, int outer_loop_count,
    int inner_loop_count);

void SingleProcessor::ntt(PolynomialInterface *x, PolynomialInterface *y,
                          const int64_t *root, const uint64_t *q_double,
                          const uint64_t *q, const uint64_t *k, int chain_count,
                          int x_offset, int y_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(x_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_root = &root[chain_index * (coeff_count_ - 1)];
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::ntt(chain_x, chain_y, chain_root, chain_q_double, chain_q,
                     chain_k, coeff_count_, log_coeff_count_);
  }
}

void SingleProcessor::intt(PolynomialInterface *x, PolynomialInterface *y,
                           const int64_t *root_inverse,
                           const uint64_t *q_double, const uint64_t *q,
                           const uint64_t *k, int chain_count, int x_offset,
                           int y_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(x_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);
    const auto chain_root_inverse =
        &root_inverse[chain_index * (coeff_count_ - 1)];
    const auto chain_q_double = q_double[chain_index];
    const auto chain_q = q[chain_index];
    const auto chain_k = k[chain_index];

    desilo::fhe::intt(chain_x, chain_y, chain_root_inverse, chain_q_double,
                      chain_q, chain_k, coeff_count_, log_coeff_count_);
  }
}

void SingleProcessor::rotate_polynomial(Polynomial *x, Polynomial *y,
                                        const int32_t *permutation,
                                        const int32_t *sign, int chain_count) {
  const std::vector<int64_t *> &x_chains = x->chains_;
  const std::vector<int64_t *> &y_chains = y->chains_;

  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x_chains[chain_index];
    const auto chain_y = y_chains[chain_index];
    desilo::fhe::rotate_polynomial(chain_x, chain_y, permutation, sign,
                                   coeff_count_);
  }
}

void SingleProcessor::permute_polynomial(Polynomial *x, Polynomial *y,
                                         const int32_t *permutation,
                                         int chain_count) {
  const std::vector<int64_t *> &x_chains = x->chains_;
  const std::vector<int64_t *> &y_chains = y->chains_;

  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x_chains[chain_index];
    const auto chain_y = y_chains[chain_index];

    desilo::fhe::permute_polynomial(chain_x, chain_y, permutation,
                                    coeff_count_);
  }
}

void SingleProcessor::add_scalar(PolynomialInterface *x, PolynomialInterface *y,
                                 const int64_t *scalar, int chain_count) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);
    const auto chain_scalar = scalar[chain_index];

    desilo::fhe::add_scalar(chain_x, chain_y, chain_scalar, coeff_count_);
  }
}

void SingleProcessor::zero_fill(PolynomialInterface *y, int chain_count,
                                int coeff_count, int y_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_y = y->get(y_offset + chain_index);

    std::fill(chain_y, chain_y + coeff_count, 0);
  }
}

void SingleProcessor::copy(PolynomialInterface *x, PolynomialInterface *y,
                           int chain_count, int x_offset, int y_offset) {
  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(x_offset + chain_index);
    const auto chain_y = y->get(y_offset + chain_index);

    std::memcpy(chain_y, chain_x, sizeof(int64_t) * coeff_count_);
  }
}

void SingleProcessor::decompress_polynomial(PolynomialInterface *x,
                                            PolynomialInterface *y,
                                            int chain_count) {
  const int jump = coeff_count_ / codec_coeff_count_;

  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);

    desilo::fhe::decompress_polynomial(chain_x, chain_y, codec_coeff_count_,
                                       jump);
  }
}

void SingleProcessor::compress_polynomial(PolynomialInterface *x,
                                          PolynomialInterface *y,
                                          int chain_count) {
  const auto jump = coeff_count_ / codec_coeff_count_;

  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = x->get(chain_index);
    const auto chain_y = y->get(chain_index);

    desilo::fhe::compress_polynomial(chain_x, chain_y, codec_coeff_count_,
                                     jump);
  }
}

void SingleProcessor::copy_to_polynomial(int64_t *x, Polynomial *y,
                                         int chain_count) {
  const std::vector<int64_t *> &y_chains = y->chains_;

  for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
    const auto chain_x = &x[chain_index * coeff_count_];
    const auto chain_y = y_chains[chain_index];

    std::memcpy(chain_y, chain_x, sizeof(int64_t) * coeff_count_);
  }
}

void SingleProcessor::round(DoublePolynomial *x, Polynomial *y,
                            int chain_count) {
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    auto chain_x = &x->buffer_[chain_index * codec_coeff_count_];
    auto chain_y = y->get(chain_index);

    for (int coeff_index = 0; coeff_index < codec_coeff_count_; coeff_index++) {
      chain_y[coeff_index] = std::llround(chain_x[coeff_index]);
    }
  }
}

void SingleProcessor::max_absolute(DoublePolynomial *x, double *y) {
  auto buffer = x->buffer_;

  double *max_elem_iter = std::max_element(
      buffer, buffer + codec_coeff_count_,
      [](double a, double b) { return std::abs(a) < std::abs(b); });

  *y = max_elem_iter ? std::abs(*max_elem_iter) : 0.0;
}

void SingleProcessor::double_to_rns(double *x, Polynomial *y, const uint64_t *q,
                                    int chain_count, int y_offset) {
  const auto y_chains = &y->chains_.data()[y_offset];

  desilo::fhe::double_to_rns(x, y_chains, q, chain_count, codec_coeff_count_, 0,
                             codec_coeff_count_);
}

void SingleProcessor::rns_to_double(Polynomial *x, double *y, const uint64_t *q,
                                    BigInt q_product, BigInt q_product_half,
                                    const BigInt *rns_reverser,
                                    uint64_t r_minus_k_product,
                                    int chain_count) {
  const auto x_chains = x->chains_.data();

  desilo::fhe::rns_to_double(x_chains, y, q, q_product, q_product_half,
                             rns_reverser, r_minus_k_product, chain_count,
                             codec_coeff_count_, 0, codec_coeff_count_);
}

void SingleProcessor::cast_int64_to_double(Polynomial *x, DoublePolynomial *y,
                                           int chain_count) {
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    auto chain_x = x->get(chain_index);
    auto chain_y = &y->buffer_[chain_index * codec_coeff_count_];

    for (int coeff_index = 0; coeff_index < codec_coeff_count_; coeff_index++) {
      chain_y[coeff_index] = static_cast<double>(chain_x[coeff_index]);
    }
  }
}

}
