#include "operation/fft.h"
#include "common/test.h"

TEST(FFT, NormalizedFFT1) {
  double x[8]{1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0};
  double y[8];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  desilo::fhe::normalized_fft(x, y, twiddle_factor, 4);

  double expected[8]{1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, NormalizedIFFT1) {
  double x[8]{1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
  double y[8];

  desilo::fhe::normalized_ifft(x, y, 4);

  double expected[8]{1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, NormalizedFFT2) {
  double x[8]{0.0, 0.0, 0.0, 0.0, 4.0, 0.0, 0.0, 0.0};
  double y[8];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  desilo::fhe::normalized_fft(x, y, twiddle_factor, 4);

  double expected[8]{1.0, 0.0, -1.0, 0.0, 1.0, 0.0, -1.0, 0.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, NormalizedIFFT2) {
  double x[8]{1.0, 0.0, -1.0, 0.0, 1.0, 0.0, -1.0, 0.0};
  double y[8];

  desilo::fhe::normalized_ifft(x, y, 4);

  double expected[8]{0.0, 0.0, 0.0, 0.0, 4.0, 0.0, 0.0, 0.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, NormalizedFFT3) {
  double x[8]{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
  double y[8];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  desilo::fhe::normalized_fft(x, y, twiddle_factor, 4);

  double expected[8]{3.0, 4.0, -2.0, 0.0, -1.0, -1.0, 0.0, -2.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, NormalizedIFFT3) {
  double x[8]{3.0, 4.0, -2.0, 0.0, -1.0, -1.0, 0.0, -2.0};
  double y[8];

  desilo::fhe::normalized_ifft(x, y, 4);

  double expected[8]{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, NormalizedFFTInplace) {
  double x[8]{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  desilo::fhe::normalized_fft(x, x, twiddle_factor, 4);

  double expected[8]{3.0, 4.0, -2.0, 0.0, -1.0, -1.0, 0.0, -2.0};

  expect_array_near(x, expected, 8, 1e-9);
}

TEST(FFT, NormalizedIFFTInplace) {
  double x[8]{3.0, 4.0, -2.0, 0.0, -1.0, -1.0, 0.0, -2.0};

  desilo::fhe::normalized_ifft(x, x, 4);

  double expected[8]{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};

  expect_array_near(x, expected, 8, 1e-9);
}

TEST(FFT, FFTThenIFFT) {
  double x[8]{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
  double y[8];
  double z[8];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  desilo::fhe::normalized_fft(x, y, twiddle_factor, 4);
  desilo::fhe::normalized_ifft(y, z, 4);

  expect_array_near(x, z, 8, 1e-9);
}

TEST(FFT, FFTThenIFFTLarge) {
  const int slot_count = 1 << 16;
  double x[slot_count]{};
  double y[slot_count]{};
  double z[slot_count]{};

  for (int index = 0; index < slot_count / 2; index += 2) {
    x[2 * index] = index;
  }

  std::complex<double> twiddle_factor[slot_count / 2];
  const double unit_angle = -4 * std::numbers::pi / slot_count;
  for (int index = 0; index < slot_count / 2; index++) {
    const double angle = index * unit_angle;
    twiddle_factor[index] =
        std::complex<double>(std::cos(angle), std::sin(angle));
  }

  desilo::fhe::normalized_fft(x, y, twiddle_factor, slot_count / 2);
  desilo::fhe::normalized_ifft(y, z, slot_count / 2);

  expect_array_near(x, z, slot_count, 1e-9);
}

TEST(FFT, UnitFFT1) {
  std::complex<double> x[4]{std::complex(1.0, 0.0), std::complex(1.0, 0.0),
                            std::complex(1.0, 0.0), std::complex(1.0, 0.0)};
  std::complex<double> y[4];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  int step_size = 1, step_count = 2;
  desilo::fhe::unit_fft(x, y, twiddle_factor, step_size, step_count);

  std::complex<double> expected0[4]{
      std::complex(2.0, 0.0), std::complex(0.0, 0.0), std::complex(2.0, 0.0),
      std::complex(0.0, 0.0)};
  expect_complex_array_near(y, expected0, 4, 1e-9);

  step_size = 2, step_count = 1;
  desilo::fhe::unit_fft(y, y, twiddle_factor, step_size, step_count);

  std::complex<double> expected1[4]{
      std::complex(4.0, 0.0), std::complex(0.0, 0.0), std::complex(0.0, 0.0),
      std::complex(0.0, 0.0)};
  expect_complex_array_near(y, expected1, 4, 1e-9);
}

TEST(FFT, UnitFFT2) {
  std::complex<double> x[4]{std::complex(0.0, 0.0), std::complex(0.0, 0.0),
                            std::complex(4.0, 0.0), std::complex(0.0, 0.0)};
  std::complex<double> y[4];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  int step_size = 1, step_count = 2;
  desilo::fhe::unit_fft(x, y, twiddle_factor, step_size, step_count);

  std::complex<double> expected0[4]{
      std::complex(0.0, 0.0), std::complex(0.0, 0.0), std::complex(4.0, 0.0),
      std::complex(4.0, 0.0)};
  expect_complex_array_near(y, expected0, 4, 1e-9);

  step_size = 2, step_count = 1;
  desilo::fhe::unit_fft(y, y, twiddle_factor, step_size, step_count);

  std::complex<double> expected1[4]{
      std::complex(4.0, 0.0), std::complex(0.0, -4.0), std::complex(-4.0, 0.0),
      std::complex(0.0, 4.0)};
  expect_complex_array_near(y, expected1, 4, 1e-9);
}

TEST(FFT, UnitFFT3) {
  std::complex<double> x[4]{std::complex(0.0, 1.0), std::complex(2.0, 3.0),
                            std::complex(4.0, 5.0), std::complex(6.0, 7.0)};
  std::complex<double> y[4];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  int step_size = 1, step_count = 2;
  desilo::fhe::unit_fft(x, y, twiddle_factor, step_size, step_count);

  std::complex<double> expected0[4]{
      std::complex(2.0, 4.0), std::complex(-2.0, -2.0),
      std::complex(10.0, 12.0), std::complex(-2.0, -2.0)};
  expect_complex_array_near(y, expected0, 4, 1e-9);

  step_size = 2, step_count = 1;
  desilo::fhe::unit_fft(y, y, twiddle_factor, step_size, step_count);

  std::complex<double> expected1[4]{
      std::complex(12.0, 16.0), std::complex(-4.0, 0.0),
      std::complex(-8.0, -8.0), std::complex(0.0, -4.0)};
  expect_complex_array_near(y, expected1, 4, 1e-9);
}

TEST(FFT, UnitFFTSplit1) {
  std::complex<double> x[4]{std::complex(1.0, 0.0), std::complex(1.0, 0.0),
                            std::complex(1.0, 0.0), std::complex(1.0, 0.0)};
  std::complex<double> y[4];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  int step_size = 1, step_count = 1;
  desilo::fhe::unit_fft(x, y, twiddle_factor, step_size, step_count);
  desilo::fhe::unit_fft(&x[2], &y[2], twiddle_factor, step_size, step_count);

  std::complex<double> expected0[4]{
      std::complex(2.0, 0.0), std::complex(0.0, 0.0), std::complex(2.0, 0.0),
      std::complex(0.0, 0.0)};
  expect_complex_array_near(y, expected0, 4, 1e-9);

  step_size = 2, step_count = 1;
  desilo::fhe::split_fft(y, y, twiddle_factor, step_size, step_count, 0, 1);
  desilo::fhe::split_fft(&y[1], &y[1], &twiddle_factor[1], step_size,
                         step_count, 1, 2);

  std::complex<double> expected1[4]{
      std::complex(4.0, 0.0), std::complex(0.0, 0.0), std::complex(0.0, 0.0),
      std::complex(0.0, 0.0)};
  expect_complex_array_near(y, expected1, 4, 1e-9);
}

TEST(FFT, UnitFFTSplit2) {
  std::complex<double> x[4]{std::complex(0.0, 0.0), std::complex(0.0, 0.0),
                            std::complex(4.0, 0.0), std::complex(0.0, 0.0)};
  std::complex<double> y[4];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  int step_size = 1, step_count = 1;
  desilo::fhe::unit_fft(x, y, twiddle_factor, step_size, step_count);
  desilo::fhe::unit_fft(&x[2], &y[2], twiddle_factor, step_size, step_count);

  std::complex<double> expected0[4]{
      std::complex(0.0, 0.0), std::complex(0.0, 0.0), std::complex(4.0, 0.0),
      std::complex(4.0, 0.0)};
  expect_complex_array_near(y, expected0, 4, 1e-9);

  step_size = 2, step_count = 1;
  desilo::fhe::split_fft(y, y, twiddle_factor, step_size, step_count, 0, 1);
  desilo::fhe::split_fft(&y[1], &y[1], &twiddle_factor[1], step_size,
                         step_count, 1, 2);

  std::complex<double> expected1[4]{
      std::complex(4.0, 0.0), std::complex(0.0, -4.0), std::complex(-4.0, 0.0),
      std::complex(0.0, 4.0)};
  expect_complex_array_near(y, expected1, 4, 1e-9);
}

TEST(FFT, UnitFFTSplit3) {
  std::complex<double> x[4]{std::complex(0.0, 1.0), std::complex(2.0, 3.0),
                            std::complex(4.0, 5.0), std::complex(6.0, 7.0)};
  std::complex<double> y[4];

  std::complex<double> twiddle_factor[4]{
      std::complex(1.0, 0.0), std::complex(0.0, -1.0), std::complex(-1.0, 0.0),
      std::complex(0.0, 1.0)};

  int step_size = 1, step_count = 1;
  desilo::fhe::unit_fft(x, y, twiddle_factor, step_size, step_count);
  desilo::fhe::unit_fft(&x[2], &y[2], twiddle_factor, step_size, step_count);

  std::complex<double> expected0[4]{
      std::complex(2.0, 4.0), std::complex(-2.0, -2.0),
      std::complex(10.0, 12.0), std::complex(-2.0, -2.0)};
  expect_complex_array_near(y, expected0, 4, 1e-9);

  step_size = 2, step_count = 1;
  desilo::fhe::split_fft(y, y, twiddle_factor, step_size, step_count, 0, 1);
  desilo::fhe::split_fft(&y[1], &y[1], &twiddle_factor[1], step_size,
                         step_count, 1, 2);

  std::complex<double> expected1[4]{
      std::complex(12.0, 16.0), std::complex(-4.0, 0.0),
      std::complex(-8.0, -8.0), std::complex(0.0, -4.0)};
  expect_complex_array_near(y, expected1, 4, 1e-9);
}

TEST(FFT, Normalize1) {
  double x[8]{1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0};
  double y[8];

  desilo::fhe::normalize(x, y, 4);

  double expected[8]{0.25, 0.0, 0.25, 0.0, 0.25, 0.0, 0.25, 0.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, Normalize2) {
  double x[8]{0.0, 0.0, 0.0, 0.0, 4.0, 0.0, 0.0, 0.0};
  double y[8];

  desilo::fhe::normalize(x, y, 4);

  double expected[8]{0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, Normalize3) {
  double x[8]{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0};
  double y[8];

  desilo::fhe::normalize(x, y, 4);

  double expected[8]{0.0, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75};

  expect_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, BitReversalPermute4) {
  std::complex<double> x[4]{std::complex(0.0, 1.0), std::complex(2.0, 3.0),
                            std::complex(4.0, 5.0), std::complex(6.0, 7.0)};
  std::complex<double> y[4];

  desilo::fhe::bit_reversal_permute(x, y, 4);

  std::complex<double> expected[4]{
      std::complex(0.0, 1.0), std::complex(4.0, 5.0), std::complex(2.0, 3.0),
      std::complex(6.0, 7.0)};

  expect_complex_array_near(y, expected, 4, 1e-9);
}

TEST(FFT, BitReversalPermute8) {
  std::complex<double> x[8]{std::complex(0.0, 1.0),   std::complex(2.0, 3.0),
                            std::complex(4.0, 5.0),   std::complex(6.0, 7.0),
                            std::complex(8.0, 9.0),   std::complex(10.0, 11.0),
                            std::complex(12.0, 13.0), std::complex(14.0, 15.0)};
  std::complex<double> y[8];

  desilo::fhe::bit_reversal_permute(x, y, 8);

  std::complex<double> expected[8]{
      std::complex(0.0, 1.0), std::complex(8.0, 9.0),
      std::complex(4.0, 5.0), std::complex(12.0, 13.0),
      std::complex(2.0, 3.0), std::complex(10.0, 11.0),
      std::complex(6.0, 7.0), std::complex(14.0, 15.0)};

  expect_complex_array_near(y, expected, 8, 1e-9);
}

TEST(FFT, FFT) {
  std::complex<double> x[8]{std::complex(0.0, 1.0),   std::complex(2.0, 3.0),
                            std::complex(4.0, 5.0),   std::complex(6.0, 7.0),
                            std::complex(8.0, 9.0),   std::complex(10.0, 11.0),
                            std::complex(12.0, 13.0), std::complex(14.0, 15.0)};
  std::complex<double> y[8]{};
  std::complex<double> twiddle_factor[8]{
      std::complex<double>(1.0, 0.0),
      std::complex<double>(0.7071067811865476, -0.7071067811865475),
      std::complex<double>(0.0, -1.0),
      std::complex<double>(-0.7071067811865475, -0.7071067811865476),
      std::complex<double>(-1.0, 0.0),
      std::complex<double>(-0.7071067811865477, 0.7071067811865475),
      std::complex<double>(0.0, 1.0),
      std::complex<double>(0.7071067811865474, 0.7071067811865477)};

  desilo::fhe::fft(x, y, twiddle_factor, 8);

  std::complex<double> expected[8]{
      std::complex<double>(56.0, 64.0),
      std::complex<double>(-6.828427124746190, 2.828427124746190),
      std::complex<double>(-16.0, 0.0),
      std::complex<double>(-2.828427124746190, -1.171572875253810),
      std::complex<double>(-32.0, -32.0),
      std::complex<double>(-1.171572875253810, -2.828427124746190),
      std::complex<double>(0.0, -16.0),
      std::complex<double>(2.828427124746190, -6.828427124746190)};

  expect_complex_array_near(y, expected, 8, 1e-10);
}
