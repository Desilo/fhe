#include <complex>

#pragma once

namespace desilo::fhe {

void split_fft(std::complex<double> *x, std::complex<double> *y,
               std::complex<double> *twiddle_factor, int step_size,
               int step_count, int slot_start, int slot_end);

void unit_fft(std::complex<double> *x, std::complex<double> *y,
              std::complex<double> *twiddle_factor, int step_size,
              int step_count);
void normalize(double *x, double *y, int size);

void fft(std::complex<double> *x, std::complex<double> *y,
         const std::complex<double> *twiddle_factor, int size);
void bit_reversal_permute(std::complex<double> *x, std::complex<double> *y,
                          int size);
void normalized_fft(double *x, double *y,
                    const std::complex<double> *twiddle_factor, int size);
void normalized_ifft(double *x, double *y, int size);

}
