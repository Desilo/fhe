#include <memory>

#include "arithmetic/big_int.h"
#include "data/polynomial.h"

#pragma once

namespace desilo::fhe {

class SingleProcessor {
public:
  SingleProcessor(int log_coeff_count, int log_codec_coeff_count)
      : coeff_count_(int(1) << log_coeff_count),
        log_coeff_count_(log_coeff_count),
        codec_coeff_count_(int(1) << log_codec_coeff_count),
        log_codec_coeff_count_(log_codec_coeff_count){};

  void mont_enter(PolynomialInterface *x, PolynomialInterface *y,
                  const int64_t *constant, const uint64_t *q, const uint64_t *k,
                  int chain_count, int coeff_count, int x_offset, int y_offset);
  void make_signed(PolynomialInterface *x, PolynomialInterface *y,
                   const uint64_t *q, const uint64_t *q_half, int chain_count,
                   int coeff_count);
  void mont_add(PolynomialInterface *x1, PolynomialInterface *x2,
                PolynomialInterface *y, const uint64_t *q_double,
                int chain_count);
  void mont_mult(PolynomialInterface *x1, PolynomialInterface *x2,
                 PolynomialInterface *y, const uint64_t *q, const uint64_t *k,
                 int chain_count, int x1_offset, int x2_offset);
  void reduce_2q_to_q(PolynomialInterface *x, PolynomialInterface *y,
                      const uint64_t *q, int chain_count);
  void sub_tiled(PolynomialInterface *x1, PolynomialInterface *x2,
                 PolynomialInterface *y, const uint64_t *q_double,
                 int chain_count, int x1_offset, int y_offset);
  void add_tiled(PolynomialInterface *x1, PolynomialInterface *x2,
                 PolynomialInterface *y, const uint64_t *q_double,
                 int chain_count);
  void get_rounder(PolynomialInterface *x, PolynomialInterface *y,
                   uint64_t q_half, int x_offset);

  void mont_enter_tiled(PolynomialInterface *x, PolynomialInterface *y,
                        const int64_t *r_squared, const uint64_t *q,
                        const uint64_t *k, int chain_count, int x_offset,
                        int y_offset);
  void mont_enter_tiled_add(PolynomialInterface *x, PolynomialInterface *y,
                            const int64_t *r_squared, const uint64_t *q_double,
                            const uint64_t *q, const uint64_t *k,
                            int chain_count, int x_offset, int y_offset);
  void mont_enter_tiled_add_reduce_2q_to_q(
      PolynomialInterface *x, PolynomialInterface *y, const int64_t *r_squared,
      const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
      int chain_count, int x_offset, int y_offset);
  void mont_mult_add(PolynomialInterface *x1, PolynomialInterface *x2,
                     PolynomialInterface *y, const uint64_t *q_double,
                     const uint64_t *q, const uint64_t *k, int chain_count,
                     int x1_offset, int x2_offset);
  void mont_sub_enter_reduce_2q_to_q(
      PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
      const int64_t *constant, const uint64_t *q_double, const uint64_t *q,
      const uint64_t *k, int chain_count, int x1_offset, int x2_offset,
      int y_offset);
  void mont_sub_tiled_enter(PolynomialInterface *x1, PolynomialInterface *x2,
                            PolynomialInterface *y, const int64_t *constant,
                            const uint64_t *q_double, const uint64_t *q,
                            const uint64_t *k, int chain_count, int x1_offset,
                            int x2_offset, int y_offset);
  void mont_enter_exit(PolynomialInterface *x, PolynomialInterface *y,
                       const int64_t *constant, const uint64_t *q,
                       const uint64_t *k, int chain_count);
  void mont_enter_exit_reduce_2q_to_q(PolynomialInterface *x,
                                      PolynomialInterface *y,
                                      const int64_t *constant,
                                      const uint64_t *q, const uint64_t *k,
                                      int chain_count);
  void mont_add_reduce_2q_to_q(PolynomialInterface *x1, PolynomialInterface *x2,
                               PolynomialInterface *y, const uint64_t *q_double,
                               const uint64_t *q, int chain_count,
                               int x1_offset, int x2_offset, int y_offset);
  void mont_sub_reduce_2q_to_q(PolynomialInterface *x1, PolynomialInterface *x2,
                               PolynomialInterface *y, const uint64_t *q_double,
                               const uint64_t *q, int chain_count);
  void make_unsigned_reduce_2q_to_q(PolynomialInterface *x,
                                    PolynomialInterface *y, const uint64_t *q,
                                    int chain_count, int coeff_count);
  void tile_unsigned_reduce_2q_to_q(PolynomialInterface *x,
                                    PolynomialInterface *y, const uint64_t *q,
                                    int chain_count, int coeff_count,
                                    int x_offset, int y_offset);
  void negate_make_unsigned(PolynomialInterface *x, PolynomialInterface *y,
                            const uint64_t *q, int chain_count);
  void concatenate_tile_unsigned(PolynomialInterface *x1,
                                 PolynomialInterface *x2,
                                 PolynomialInterface *y, const uint64_t *q,
                                 int chain_count);

  void apply_skewer(DoublePolynomial *x, DoublePolynomial *y, double step,
                    int size);

  void fft(std::complex<double> *x, std::complex<double> *y,
           const std::complex<double> *twiddle_factor, int size);
  void ifft(std::complex<double> *x, std::complex<double> *y,
            const std::complex<double> *twiddle_factor, int size);

  template <typename T>
  void extract_diagonals(T *x, T *y, int outer_loop_count,
                         int inner_loop_count);

  void ntt(PolynomialInterface *x, PolynomialInterface *y, const int64_t *root,
           const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
           int chain_count, int x_offset, int y_offset);
  void intt(PolynomialInterface *x, PolynomialInterface *y,
            const int64_t *root_inverse, const uint64_t *q_double,
            const uint64_t *q, const uint64_t *k, int chain_count, int x_offset,
            int y_offset);

  void rotate_polynomial(Polynomial *x, Polynomial *y,
                         const int32_t *permutation, const int32_t *sign,
                         int chain_count);
  void permute_polynomial(Polynomial *x, Polynomial *y,
                          const int32_t *permutation, int chain_count);

  void add_scalar(PolynomialInterface *x, PolynomialInterface *y,
                  const int64_t *scalar, int chain_count);

  void zero_fill(PolynomialInterface *y, int chain_count, int coeff_count,
                 int y_offset);
  void copy_to_polynomial(int64_t *x, Polynomial *y, int chain_count);
  void copy(PolynomialInterface *x, PolynomialInterface *y, int chain_count,
            int x_offset, int y_offset);
  void compress_polynomial(PolynomialInterface *x, PolynomialInterface *y,
                           int chain_count);
  void decompress_polynomial(PolynomialInterface *x, PolynomialInterface *y,
                             int chain_count);
  void round(DoublePolynomial *x, Polynomial *y, int chain_count);
  void max_absolute(DoublePolynomial *x, double *y);
  void cast_int64_to_double(Polynomial *x, DoublePolynomial *y,
                            int chain_count);

  void double_to_rns(double *x, Polynomial *y, const uint64_t *q,
                     int chain_count, int y_offset);

  void rns_to_double(Polynomial *x, double *y, const uint64_t *q,
                     BigInt q_product, BigInt q_product_half,
                     const BigInt *rns_reverser, uint64_t r_minus_k_product,
                     int chain_count);

private:
  const int coeff_count_;
  const int log_coeff_count_;
  const int codec_coeff_count_;
  const int log_codec_coeff_count_;
};

}
