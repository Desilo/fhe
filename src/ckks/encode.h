#include <complex>
#include <cstdint>
#include <vector>

#pragma once

namespace desilo::fhe {

int reverse_integer_bits(int input, int length);
uint64_t *circular_shift_permutation(int size);

uint64_t *canon_permutation(int size, int k);
uint64_t *fold_canon_permutation(int size);
uint64_t *get_permutation_cycles(const uint64_t *permutation, int size);
uint64_t *conjugate_permutations(const uint64_t *permutation1,
                                 const uint64_t *permutation2, int size);
uint64_t *invert_permutation(const uint64_t *permutation, int size);

void pre_permute(const double *input, double *output,
                 const uint64_t *permutation, int output_count, int start,
                 int end);
void pre_permute(const std::complex<double> *input, double *output,
                 const uint64_t *permutation, int output_count, int start,
                 int end);
double *post_permute(const double *input, const uint64_t *permutation,
                     int size);
double *generate_skewer(int size);
double *generate_twister(int size);

template <typename T>
double *permute_for_fft(T *input, int input_count, double scale);
double *apply_twister(double *ffted, int input_count, double scale);
void apply_twister(double *ffted, double *output, int count, int start_index,
                   double step, double scale);
void apply_skewer(double *x, double *y, int count, int start_index,
                  double step);
double *encode_real(const double *input,
                    const std::complex<double> *fft_twiddle_factor,
                    int input_count, double scale);
double *encode_complex(const std::complex<double> *input,
                       const std::complex<double> *fft_twiddle_factor,
                       int input_count, double scale);
int64_t *encode_imaginary(int64_t input, int size);
double *decode_real(const double *input, int input_count, long double scale);
std::complex<double> *decode_complex(const double *input, int input_count,
                                     long double scale);
void permute_after_ifft(double *iffted, double *output,
                        const uint64_t *post_permutation, int output_count,
                        double scale_inverse, int start, int end);
void permute_after_ifft(double *iffted, std::complex<double> *output,
                        const uint64_t *post_permutation, int output_count,
                        double scale_inverse, int start, int end);
void get_bit_reversal_permutation_and_sign(int32_t *permutation, int size);
void get_permutation_and_sign(int32_t *permutation, int32_t *sign,
                              int coeff_count, int delta);
void get_ntt_permutation(int32_t *permutation, int coeff_count, int delta);
void rotate_chain(const int64_t *input, int64_t *ouput,
                  const int32_t *permutation, const int32_t *sign,
                  int coeff_count);
void rotate_polynomial(const int64_t *input, int64_t *output,
                       const int32_t *permutation, const int32_t *sign,
                       int coeff_count);
void permute_chain(const int64_t *input, int64_t *ouput,
                   const int32_t *permutation, int coeff_count);
void permute_polynomial(const int64_t *input, int64_t *output,
                        const int32_t *permutation, int coeff_count);
void pack_double_polynomial(double *input, double *output, int input_size,
                            int output_size);
void unpack_double_polynomial(double *input, double *output, int input_size,
                              int output_size);

}
