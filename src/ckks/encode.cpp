#include <cmath>
#include <cstring>

#include "arithmetic/arithmetic.h"
#include "arithmetic/pi.h"
#include "ckks/encode.h"
#include "operation/fft.h"

namespace desilo::fhe {

int reverse_integer_bits(int input, int length) {
  int left_mask = 1;
  int right_mask = 1 << (length - 1);
  int output = 0;
  for (int index = 0; index < length; index++) {
    if (input & left_mask) {
      output |= right_mask;
    }
    left_mask <<= 1;
    right_mask >>= 1;
  }
  return output;
}

uint64_t *circular_shift_permutation(int size) {
  const int half_size = size / 2;
  auto output = new uint64_t[size];

  output[0] = half_size - 1;

  for (int left_index = 1; left_index < half_size; left_index++) {
    output[left_index] = left_index - 1;
  }

  for (int right_index = half_size; right_index < size - 1; right_index++) {
    output[right_index] = right_index + 1;
  }

  output[size - 1] = half_size;

  return output;
}

int32_t get_jump(const unsigned shift, const int double_size) {
  if (shift == (double_size - 1)) {
    return shift;
  }

  int64_t jump = 1;
  for (int power = 0; power < double_size - shift; power++) {
    jump *= 5;

    jump &= double_size - 1;
  }
  return jump;
}

uint64_t *canon_permutation(int size, int k) {
  if (k < 1) {
    throw std::runtime_error("Input of canon_permutation must be positive.");
  }

  const int double_size = size * 2;
  const unsigned shift = k % size;
  auto output = new uint64_t[double_size];

  const auto jump = get_jump(shift, double_size);

  for (int index = 0; index < double_size; index++) {
    output[index] = jump * index % double_size;
  }

  return output;
}

uint64_t *fold_canon_permutation(int size) {
  const int double_size = size * 2;
  auto output = new uint64_t[size];

  const auto jump = get_jump(1, double_size);

  auto jump_mult_index = jump;
  for (int index = 0; index < size; index++) {
    output[index] = (jump_mult_index - 1) >> 1;
    jump_mult_index = (jump_mult_index + jump * 2) % double_size;
  }

  return output;
}

uint64_t *get_permutation_cycles(const uint64_t *permutation, int size) {
  auto visited = new bool[size];
  auto output = new uint64_t[size];
  auto output_pointer = output;

  for (int index = 0; index < size; index++) {
    visited[index] = false;
  }

  int start_index = 0, cur, next;

  while (start_index < size) {
    cur = permutation[start_index];
    next = permutation[cur];

    while (true) {
      *output_pointer++ = cur;
      visited[cur] = true;
      cur = next;

      if (visited[next]) {
        break;
      }

      next = permutation[cur];
    }

    start_index++;
    while (start_index < size && visited[start_index]) {
      start_index++;
    }
  }

  delete[] visited;

  return output;
}

uint64_t *conjugate_permutations(const uint64_t *permutation1,
                                 const uint64_t *permutation2, int size) {
  auto output = new uint64_t[size];

  auto cycle1 = get_permutation_cycles(permutation1, size);
  auto cycle2 = get_permutation_cycles(permutation2, size);

  for (int index = 0; index < size; index++) {
    output[cycle1[index]] = cycle2[index];
  }

  delete[] cycle1;
  delete[] cycle2;

  return output;
}

uint64_t *invert_permutation(const uint64_t *permutation, int size) {
  auto output = new uint64_t[size];

  for (int index = 0; index < size; index++) {
    output[permutation[index]] = index;
  }

  return output;
}

void pre_permute(const double *input, double *output,
                 const uint64_t *permutation, int output_count, int start,
                 int end) {
  for (int index = start; index < end; index++) {
    const auto permute_index = permutation[index] * 2;
    const auto input_value = input[index];

    output[permute_index] = input_value;
    output[permute_index + 1] = 0.0;

    output[output_count - permute_index - 2] = input_value;
    output[output_count - permute_index - 1] = 0.0;
  }
}

void pre_permute(const std::complex<double> *input, double *output,
                 const uint64_t *permutation, int output_count, int start,
                 int end) {
  for (int index = start; index < end; index++) {
    const auto permute_index = permutation[index] * 2;
    const auto input_value_real = input[index].real();
    const auto input_value_imag = input[index].imag();

    output[permute_index] = input_value_real;
    output[permute_index + 1] = input_value_imag;
    output[output_count - permute_index - 2] = input_value_real;

    output[output_count - permute_index - 1] = -input_value_imag;
  }
}

double *post_permute(const double *input, const uint64_t *permutation,
                     int size) {
  auto output = new double[size];

  for (int index = 0; index < size; index++) {
    output[permutation[index]] = input[index];
  }

  return output;
}

double *generate_skewer(const int size) {
  const int double_size = size * 2;
  auto output = new double[double_size];
  const double step = pi / double_size;

  output[0] = 1.0;
  output[1] = 0.0;

  for (int index = 2; index < double_size; index += 2) {
    output[index] = std::cos(index * step);
    output[index + 1] = std::sin(index * step);
  }

  return output;
}

double *generate_twister(const int size) {
  const int double_size = size * 2;
  auto output = new double[double_size];
  const double step = -pi / double_size;

  output[0] = 1.0;
  output[1] = 0.0;

  for (int index = 2; index < double_size; index += 2) {
    output[index] = std::cos(index * step);
    output[index + 1] = std::sin(index * step);
  }

  return output;
}

template <typename T>
double *permute_for_fft(T *input, int input_count, double scale) {
  const int double_size = input_count * 2;

  const auto circular_shift = circular_shift_permutation(double_size);
  const auto fold_canon = fold_canon_permutation(double_size);
  const auto post_permutation =
      conjugate_permutations(fold_canon, circular_shift, double_size);

  const auto pre_permutation =
      invert_permutation(post_permutation, double_size);

  auto output_count = input_count * 4;
  auto output = new double[output_count];
  pre_permute(input, output, pre_permutation, output_count, 0, input_count);

  delete[] circular_shift;
  delete[] fold_canon;
  delete[] post_permutation;
  delete[] pre_permutation;

  return output;
}

template double *permute_for_fft(double *input, int input_count, double scale);
template double *permute_for_fft(std::complex<double> *input, int input_count,
                                 double scale);

double *apply_twister(double *ffted, int input_count, double scale) {
  const int double_size = input_count * 2;

  const auto twister = generate_twister(double_size);

  auto output = new double[double_size];

  for (int index = 0; index < double_size; index++) {

    const int real_index = 2 * index;
    const int imag_index = 2 * index + 1;
    output[index] = (ffted[real_index] * twister[real_index] -
                     ffted[imag_index] * twister[imag_index]) *
                    scale;
  }

  delete[] twister;

  return output;
}

void apply_twister(double *ffted, double *output, int count, int start_index,
                   double step, double scale) {

  for (int index = start_index; index < start_index + count; index++) {
    const int real_index = 2 * index;
    const int imag_index = 2 * index + 1;

    output[index] = (ffted[real_index] * std::cos(real_index * step) -
                     ffted[imag_index] * std::sin(real_index * step)) *
                    scale;
  }
}

void apply_skewer(double *x, double *y, int count, int start_index,
                  double step) {
  for (int index = start_index; index < start_index + count; index++) {
    const int real_index = 2 * index;
    const int imag_index = 2 * index + 1;

    y[real_index] = x[index] * std::cos(real_index * step);
    y[imag_index] = x[index] * std::sin(real_index * step);
  }
}

double *encode_real(const double *input,
                    const std::complex<double> *fft_twiddle_factor,
                    int input_count, double scale) {
  const int double_size = input_count * 2;

  const auto circular_shift = circular_shift_permutation(double_size);
  const auto fold_canon = fold_canon_permutation(double_size);
  const auto post_permutation =
      conjugate_permutations(fold_canon, circular_shift, double_size);

  const auto pre_permutation =
      invert_permutation(post_permutation, double_size);

  int permuted_count = input_count * 4;
  auto permuted = new double[permuted_count];

  pre_permute(input, permuted, pre_permutation, permuted_count, 0, input_count);
  const auto ffted = permuted;
  normalized_fft(permuted, ffted, fft_twiddle_factor, double_size);

  const auto twister = generate_twister(double_size);

  auto output = new double[double_size];
  for (int index = 0; index < double_size; index++) {

    const int real_index = 2 * index;
    const int imag_index = 2 * index + 1;
    output[index] = (ffted[real_index] * twister[real_index] -
                     ffted[imag_index] * twister[imag_index]) *
                    scale;
  }

  delete[] circular_shift;
  delete[] fold_canon;
  delete[] post_permutation;
  delete[] pre_permutation;
  delete[] permuted;
  delete[] twister;

  return output;
}

double *encode_complex(const std::complex<double> *input,
                       const std::complex<double> *fft_twiddle_factor,
                       int input_count, double scale) {
  const int double_size = input_count * 2;

  const auto circular_shift = circular_shift_permutation(double_size);
  const auto fold_canon = fold_canon_permutation(double_size);
  const auto post_permutation =
      conjugate_permutations(fold_canon, circular_shift, double_size);

  const auto pre_permutation =
      invert_permutation(post_permutation, double_size);

  int permuted_count = input_count * 4;
  auto permuted = new double[permuted_count];

  pre_permute(input, permuted, pre_permutation, permuted_count, 0, input_count);
  const auto ffted = permuted;
  normalized_fft(permuted, ffted, fft_twiddle_factor, double_size);

  const auto twister = generate_twister(double_size);

  auto output = new double[double_size];
  for (int index = 0; index < double_size; index++) {

    const int real_index = 2 * index;
    const int imag_index = 2 * index + 1;
    output[index] = (ffted[real_index] * twister[real_index] -
                     ffted[imag_index] * twister[imag_index]) *
                    scale;
  }

  delete[] circular_shift;
  delete[] fold_canon;
  delete[] post_permutation;
  delete[] pre_permutation;
  delete[] permuted;
  delete[] twister;

  return output;
}

int64_t *encode_imaginary(int64_t input, int size) {
  const int half_size = size / 2;

  auto output = new int64_t[size]{};
  output[half_size] = input;

  return output;
}

double *decode_real(const double *input, int input_count, long double scale) {
  const int double_size = input_count * 2;

  const auto circular_shift = circular_shift_permutation(input_count);
  const auto fold_canon = fold_canon_permutation(input_count);
  const auto post_permutation =
      conjugate_permutations(fold_canon, circular_shift, input_count);

  const auto skewer = generate_skewer(input_count);

  const auto skewed = new double[double_size];
  for (int index = 0; index < input_count; index++) {
    const int real_index = 2 * index;
    const int imag_index = 2 * index + 1;
    skewed[real_index] = input[index] * skewer[real_index];
    skewed[imag_index] = input[index] * skewer[imag_index];
  }

  const auto iffted = skewed;
  normalized_ifft(skewed, iffted, input_count);

  const int half_size = input_count / 2;
  auto output = new double[half_size];
  const auto scale_inverse = static_cast<double>(1.0 / scale);

  for (int index = 0; index < input_count; index++) {
    const int permuted_index = post_permutation[index];
    if (permuted_index < half_size) {
      output[permuted_index] = iffted[2 * index] * scale_inverse;
    }
  }

  delete[] circular_shift;
  delete[] fold_canon;
  delete[] post_permutation;
  delete[] skewer;
  delete[] skewed;

  return output;
}

std::complex<double> *decode_complex(const double *input, int input_count,
                                     long double scale) {
  const int double_size = input_count * 2;

  const auto circular_shift = circular_shift_permutation(input_count);
  const auto fold_canon = fold_canon_permutation(input_count);
  const auto post_permutation =
      conjugate_permutations(fold_canon, circular_shift, input_count);

  const auto skewer = generate_skewer(input_count);

  const auto skewed = new double[double_size];
  for (int index = 0; index < input_count; index++) {
    const int real_index = 2 * index;
    const int imag_index = 2 * index + 1;
    skewed[real_index] = input[index] * skewer[real_index];
    skewed[imag_index] = input[index] * skewer[imag_index];
  }

  const auto iffted = skewed;
  normalized_ifft(skewed, iffted, input_count);

  const int half_size = input_count / 2;
  auto output = new std::complex<double>[half_size];
  const auto scale_inverse = static_cast<double>(1.0 / scale);

  for (int index = 0; index < input_count; index++) {
    const int permuted_index = post_permutation[index];
    if (permuted_index < half_size) {
      output[permuted_index] =
          std::complex<double>(iffted[2 * index] * scale_inverse,
                               iffted[2 * index + 1] * scale_inverse);
    }
  }

  delete[] circular_shift;
  delete[] fold_canon;
  delete[] post_permutation;
  delete[] skewer;
  delete[] skewed;

  return output;
}

void permute_after_ifft(double *iffted, double *output,
                        const uint64_t *post_permutation, int output_count,
                        double scale_inverse, int start, int end) {
  for (int index = start; index < end; index++) {
    const int permuted_index = post_permutation[index];
    if (permuted_index < output_count) {
      output[permuted_index] = iffted[2 * index] * scale_inverse;
    }
  }
}

void permute_after_ifft(double *iffted, std::complex<double> *output,
                        const uint64_t *post_permutation, int output_count,
                        double scale_inverse, int start, int end) {
  for (int index = start; index < end; index++) {
    const int permuted_index = post_permutation[index];
    if (permuted_index < output_count) {
      output[permuted_index] =
          std::complex<double>(iffted[2 * index] * scale_inverse,
                               iffted[2 * index + 1] * scale_inverse);
    }
  }
}

void get_bit_reversal_permutation_and_sign(int32_t *permutation, int size) {
  const int log_size = std::log2(size);

  for (int index = 0; index < size; index++) {
    permutation[index] = reverse_integer_bits(index, log_size);
  }
}

void get_permutation_and_sign(int32_t *permutation, int32_t *sign,
                              int coeff_count, int delta) {
  const int size = coeff_count;
  const unsigned long double_size = size * 2;
  const unsigned long shift = (delta + double_size) % double_size;

  const auto jump = get_jump(shift, double_size);

  for (int index = 0; index < size; index++) {
    const auto permutation_index = jump * index % double_size;
    permutation[index] = permutation_index % size;
    sign[index] = ((permutation_index / size) & 1) ? -1 : 1;
  }
}

void get_ntt_permutation(int32_t *permutation, int coeff_count, int delta) {
  const int size = coeff_count;
  const uint32_t five = 5;
  const int mask = size - 1;

  const auto power_of_five_larger =
      modulus_power<uint32_t>(five, delta, size * 2);
  const auto power_of_five = power_of_five_larger & mask;
  const int diff = delta == -1 ? -1 : ((power_of_five_larger - 1) >> 1) & mask;
  const auto power_of_five_inverse =
      delta == -1 ? size - 1 : modulus_invert(power_of_five, size);

  const auto temp_permutation = new int32_t[coeff_count];
  for (int index = 0; index < size; index++) {
    auto permutation_index = positive_modulo(index - diff, size);
    temp_permutation[index] =
        modulus_multiply(permutation_index, power_of_five_inverse, size);
  }

  const auto bit_reversal_permutation = new int32_t[coeff_count];
  get_bit_reversal_permutation_and_sign(bit_reversal_permutation, size);

  for (int index = 0; index < size; index++) {
    permutation[index] = bit_reversal_permutation
        [temp_permutation[bit_reversal_permutation[index]]];
  }

  delete[] bit_reversal_permutation;
  delete[] temp_permutation;
}

void rotate_chain(const int64_t *input, int64_t *output,
                  const int32_t *permutation, const int32_t *sign,
                  int coeff_count) {
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    output[permutation[coeff_index]] = sign[coeff_index] * input[coeff_index];
  }
}

void rotate_polynomial(const int64_t *input, int64_t *output,
                       const int32_t *permutation, const int32_t *sign,
                       int coeff_count) {
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    output[permutation[coeff_index]] = sign[coeff_index] * input[coeff_index];
  }
}

void permute_chain(const int64_t *input, int64_t *output,
                   const int32_t *permutation, int coeff_count) {
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    *output++ = input[permutation[coeff_index]];
  }
}

void permute_polynomial(const int64_t *input, int64_t *output,
                        const int32_t *permutation, int coeff_count) {
  for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    output[coeff_index] = input[permutation[coeff_index]];
  }
}

}
