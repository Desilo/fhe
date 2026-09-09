#include <complex>
#include <cstring>

#include "arithmetic/pi.h"

namespace desilo::fhe {

void split_fft(std::complex<double> *x, std::complex<double> *y,
               std::complex<double> *twiddle_factor, int step_size,
               int step_count, int slot_start, int slot_end) {
  auto x_jumped = x + step_size;
  auto y_jumped = y + step_size;
  auto twiddle_index = 0;

  for (int slot_index = slot_start; slot_index < slot_end; slot_index++) {
    const auto left_value = *x++;
    const auto right_value = twiddle_factor[twiddle_index] * *x_jumped++;

    *y++ = left_value + right_value;
    *y_jumped++ = left_value - right_value;

    twiddle_index += step_count;
  }
}

void unit_fft(std::complex<double> *x, std::complex<double> *y,
              std::complex<double> *twiddle_factor, int step_size,
              int step_count) {
  for (int step_index = 0; step_index < step_count; step_index++) {
    auto x_jumped = x + step_size;
    auto y_jumped = y + step_size;

    auto twiddle_index = 0;

    for (int slot_index = 0; slot_index < step_size; slot_index++) {
      const auto left_value = *x++;
      const auto right_value = twiddle_factor[twiddle_index] * *x_jumped++;

      *y++ = left_value + right_value;
      *y_jumped++ = left_value - right_value;

      twiddle_index += step_count;
    }

    x += step_size;
    y += step_size;
  }
}

void normalize(double *x, double *y, int size) {
  for (int index = 0; index < size; index++) {
    *y++ = *x++ / size;
    *y++ = *x++ / size;
  }
}

void bit_reversal_permute(std::complex<double> *x, std::complex<double> *y,
                          int size) {
  if (x != y) {
    std::memcpy(y, x, sizeof(std::complex<double>) * size);
  }

  for (int data_index = 1, swap_index = 0; data_index < size; data_index++) {
    int bit = size >> 1;
    while (swap_index & bit) {
      swap_index ^= bit;
      bit >>= 1;
    }
    swap_index ^= bit;
    if (data_index < swap_index) {
      std::swap(y[data_index], y[swap_index]);
    }
  }
}

void fft(std::complex<double> *x, std::complex<double> *y,
         const std::complex<double> *twiddle_factor, int size) {

  if (x != y) {
    std::memcpy(y, x, sizeof(double) * size * 2);
  }

  for (int step_size = 2, twiddle_step = size / 2; step_size <= size;
       step_size <<= 1, twiddle_step >>= 1) {
    const auto half_step_size = step_size >> 1;

    for (int data_offset = 0; data_offset < size; data_offset += step_size) {
      int twiddle_index = 0;
      for (int data_index = data_offset;
           data_index < data_offset + half_step_size; data_index++) {
        const auto left_value = y[data_index];
        const auto right_value =
            twiddle_factor[twiddle_index] * y[data_index + half_step_size];

        y[data_index] = left_value + right_value;
        y[data_index + half_step_size] = left_value - right_value;

        twiddle_index += twiddle_step;
      }
    }
  }
}

void ifft(std::complex<double> *x, std::complex<double> *y, int size) {
  if (x != y) {
    std::memcpy(y, x, sizeof(std::complex<double>) * size);
  }

  for (int data_index = 1, swap_index = 0; data_index < size; data_index++) {
    int bit = size >> 1;
    while (swap_index & bit) {
      swap_index ^= bit;
      bit >>= 1;
    }
    swap_index ^= bit;
    if (data_index < swap_index) {
      std::swap(y[data_index], y[swap_index]);
    }
  }

  std::complex<double> twiddle_factor[size];
  for (int index = 0; index < size; index++) {
    const double angle = 2 * index * pi / size;
    twiddle_factor[index] =
        std::complex<double>(std::cos(angle), std::sin(angle));
  }

  for (int step_size = 2, twiddle_step = size / 2; step_size <= size;
       step_size <<= 1, twiddle_step >>= 1) {
    const auto half_step_size = step_size >> 1;

    for (int data_offset = 0; data_offset < size; data_offset += step_size) {
      int twiddle_index = 0;
      for (int data_index = data_offset;
           data_index < data_offset + half_step_size; data_index++) {
        const auto left_value = y[data_index];
        const auto right_value =
            twiddle_factor[twiddle_index] * y[data_index + half_step_size];

        y[data_index] = left_value + right_value;
        y[data_index + half_step_size] = left_value - right_value;

        twiddle_index += twiddle_step;
      }
    }
  }
}

void normalized_fft(double *x, double *y,
                    const std::complex<double> *twiddle_factor, int size) {
  if (x != y) {
    std::memcpy(y, x, sizeof(std::complex<double>) * size);
  }

  auto data = reinterpret_cast<std::complex<double> *>(y);

  bit_reversal_permute(data, data, size);
  fft(data, data, twiddle_factor, size);

  for (int index = 0; index < size; index++) {
    *y++ /= size;
    *y++ /= size;
  }
}

void normalized_ifft(double *x, double *y, const int size) {
  if (x != y) {
    std::memcpy(y, x, sizeof(std::complex<double>) * size);
  }

  auto data = reinterpret_cast<std::complex<double> *>(y);

  ifft(data, data, size);
}
}
