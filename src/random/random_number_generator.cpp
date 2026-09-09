#include <cmath>

#include "gaussian_sampler.h"
#include "random/random.h"
#include "random/random_number_generator.h"

namespace desilo::fhe {

RandomNumberGenerator::RandomNumberGenerator(int thread_count, int coeff_count,
                                             const uint32_t *seed,
                                             const uint8_t *nonce)
    : thread_count_(std::max(thread_count, 1)), coeff_count_(coeff_count),
      tree_() {
  int64_t seed64[8];
  int64_t nonce64[2];

  if (seed == nullptr) {
    generate_initial_bytes(seed64, 32, 8);
  } else {
    for (size_t index = 0; index < 8; index++) {
      seed64[index] = static_cast<int64_t>(seed[index]);
    }
  }

  if (nonce == nullptr) {
    generate_initial_bytes(nonce64, 8, 2);
  } else {
    for (size_t index = 0; index < 2; index++) {
      nonce64[index] = static_cast<int64_t>(nonce[index]);
    }
  }

  const int state_size = thread_count_ * 16;

  state_ = new int64_t[state_size];

  for (auto thread_index = 0; thread_index < thread_count_; thread_index++) {
    const auto thread_state = &state_[thread_index * 16];

    thread_state[0] = 1634760805;
    thread_state[1] = 857760878;
    thread_state[2] = 2036477234;
    thread_state[3] = 1797285236;

    for (auto seed_index = 0; seed_index < 8; seed_index++) {
      thread_state[4 + seed_index] = seed64[seed_index];
    }

    thread_state[12] = thread_index;
    thread_state[13] = 0;

    for (auto nonce_index = 0; nonce_index < 2; nonce_index++) {
      thread_state[14 + nonce_index] = nonce64[nonce_index];
    }
  }
}

RandomNumberGenerator::~RandomNumberGenerator() { delete[] state_; }

void RandomNumberGenerator::assign_uniform_distribution_integer_chain(
    int64_t *output, uint64_t max_value, int shift) {
  rand_int(state_, output, max_value, shift, coeff_count_, thread_count_);
}

void RandomNumberGenerator::assign_sparse_ternary_chain(int64_t *output,
                                                        int64_t *random_index,
                                                        int hamming_weight) {
  auto max_value = coeff_count_;
  auto shift = 0;

  auto output_count = hamming_weight + 1;

  auto thread_count = 1;
  rand_int(state_, random_index, max_value, shift, output_count, thread_count);
  update_thread_states();

  const auto negative_count = *random_index++ % hamming_weight;

  for (int index = 0; index < negative_count; index++) {
    output[index] = -1;
  }
  for (int index = negative_count; index < hamming_weight; index++) {
    output[index] = 1;
  }
  for (int index = hamming_weight; index < coeff_count_; index++) {
    output[index] = 0;
  }

  for (int index = 0; index < hamming_weight; index++) {
    std::swap(output[index], output[*random_index++]);
  }
}

int64_t *RandomNumberGenerator::get_discrete_gaussian_integer_chain() {
  auto *output = new int64_t[coeff_count_];

  discrete_gaussian(state_, output, tree_.data_, tree_.size_, tree_.depth_,
                    coeff_count_, thread_count_);

  return output;
}

void RandomNumberGenerator::update_thread_states() {
  auto value_12 = state_[12];
  auto value_13 = state_[13];
  for (auto thread_index = 1; thread_index < thread_count_; thread_index++) {
    const auto thread_state = &state_[thread_index * 16];

    thread_state[12] = value_12 + thread_index;
    thread_state[13] = value_13 + (thread_state[12] >> 32);
    thread_state[12] &= 0xffffffff;
  }
}

}
