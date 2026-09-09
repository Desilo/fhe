#include <random>

#include "random/gaussian_sampler.h"

#define MASK32 0xffffffff

#define ROLL16(x) x = (((x) << 16) | ((x) >> 16)) & MASK32
#define ROLL12(x) x = (((x) << 12) | ((x) >> 20)) & MASK32
#define ROLL8(x) x = (((x) << 8) | ((x) >> 24)) & MASK32
#define ROLL7(x) x = (((x) << 7) | ((x) >> 25)) & MASK32

#define QR(x, a, b, c, d)                                                      \
  x[a] += x[b];                                                                \
  x[a] &= MASK32;                                                              \
  x[d] ^= x[a];                                                                \
  ROLL16(x[d]);                                                                \
  x[c] += x[d];                                                                \
  x[c] &= MASK32;                                                              \
  x[b] ^= x[c];                                                                \
  ROLL12(x[b]);                                                                \
  x[a] += x[b];                                                                \
  x[a] &= MASK32;                                                              \
  x[d] ^= x[a];                                                                \
  ROLL8(x[d]);                                                                 \
  x[c] += x[d];                                                                \
  x[c] &= MASK32;                                                              \
  x[b] ^= x[c];                                                                \
  ROLL7(x[b])

#define ONE_ROUND(x)                                                           \
  QR(x, 0, 4, 8, 12);                                                          \
  QR(x, 1, 5, 9, 13);                                                          \
  QR(x, 2, 6, 10, 14);                                                         \
  QR(x, 3, 7, 11, 15);                                                         \
  QR(x, 0, 5, 10, 15);                                                         \
  QR(x, 1, 6, 11, 12);                                                         \
  QR(x, 2, 7, 8, 13);                                                          \
  QR(x, 3, 4, 9, 14)

#define GE(x_high, x_low, y_high, y_low)                                       \
  (((x_high) > (y_high)) | (((x_high) == (y_high)) & ((x_low) >= (y_low))))

#define COMBINE_TWO(high, low) (((high) << 32) | (low))

namespace desilo::fhe {

inline uint64_t umult64hi(uint64_t a, uint64_t b) {
  uint64_t alpha = a >> 32;
  uint64_t beta = a & MASK32;
  uint64_t gamma = b >> 32;
  uint64_t delta = b & MASK32;

  uint64_t low = (beta * delta) >> 32;
  uint64_t mid1 = beta * gamma;
  uint64_t mid2 = alpha * delta;

  uint64_t mid1h = mid1 >> 32;
  uint64_t mid1l = mid1 & MASK32;
  uint64_t mid2h = mid2 >> 32;
  uint64_t mid2l = mid2 & MASK32;

  uint64_t midl = mid1l + mid2l + low;
  uint64_t carry = midl >> 32;

  return alpha * gamma + mid1h + mid2h + carry;
}

void chacha20(int64_t *state, uint64_t *x, int thread_count) {

  for (size_t index = 0; index < 16; index++) {
    x[index] = state[index];
  }

  for (int index = 0; index < 10; index++) {
    ONE_ROUND(x);
  }

  for (int index = 0; index < 16; index++) {
    x[index] = (x[index] + state[index]) & MASK32;
  }

  state[12] += thread_count;
  state[13] += (state[12] >> 32);
  state[12] &= MASK32;
}

void rand_int(int64_t *state, int64_t *output, uint64_t max_value,
              int64_t shift, int output_count, int thread_count) {
  uint64_t x[16];
  int stride = thread_count * 4;
  int64_t *thread_output;

  for (auto index = 0; index < output_count; index += stride) {
    chacha20(state, x, thread_count);
    thread_output = &output[index];

    for (int output_index = 0; output_index < 4; output_index++) {
      const auto local_x = &x[output_index * 4];

      uint64_t x_low = COMBINE_TWO(local_x[0], local_x[1]);

      auto alpha = umult64hi(max_value, x_low);

      auto xhh = local_x[2];
      auto xhl = local_x[3];
      auto pl = max_value & MASK32;
      auto ph = max_value >> 32;

      auto plxhl = pl * xhl;
      auto plxhh = pl * xhh;
      auto phxhl = ph * xhl;
      auto phxhh = ph * xhh;

      auto carry = ((plxhl & MASK32) + (alpha & MASK32)) >> 32;
      carry = (carry + (plxhl >> 32) + (alpha >> 32) + (phxhl & MASK32) +
               (plxhh & MASK32)) >>
              32;
      auto sample = (carry + (phxhl >> 32) + (plxhh >> 32) + phxhh);

      *thread_output++ = sample + shift;
    }
  }
}

void discrete_gaussian(int64_t *state, int64_t *output, const uint64_t *tree,
                       int tree_size, int tree_depth, int output_count,
                       int thread_count) {
  uint64_t x[16];
  int stride = thread_count * 4;
  int64_t *thread_output;

  for (auto index = 0; index < output_count; index += stride) {
    chacha20(state, x, thread_count);
    thread_output = &output[index];

    for (int output_index = 0; output_index < 4; output_index++) {
      const auto local_x = &x[output_index * 4];

      uint64_t x_low = COMBINE_TWO(local_x[0], local_x[1]);
      uint64_t x_high = COMBINE_TWO(local_x[2], local_x[3]);

      int64_t sign_bit = x_high & 1;
      x_high >>= 1;

      int jump = 1;
      int current = 0;
      int counter = 0;

      for (int depth = 0; depth < tree_depth; depth++) {
        auto tree_high = tree[counter + current + tree_size];
        auto tree_low = tree[counter + current];
        int ge_flag = GE(x_high, x_low, tree_high, tree_low);

        current = 2 * current + ge_flag;

        counter += jump;

        jump *= 2;
      }
      int64_t sample = (sign_bit * 2 - 1) * static_cast<int64_t>(current);

      *thread_output++ = sample;
    }
  }
}

void generate_initial_bytes(int64_t *output, int bytes, int count) {
  constexpr int64_t one = 1;
  const int64_t max_value = (one << bytes) - 1;

  for (int index = 0; index < count; index++) {
    std::random_device random_device;
    std::uniform_int_distribution<int64_t> distribution(0, max_value);
    *output++ = distribution(random_device);
  }
}

}
