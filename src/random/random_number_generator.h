#include <cstdint>
#include <memory>

#include "gaussian_sampler.h"

#pragma once

namespace desilo::fhe {

class RandomNumberGenerator {
public:
  RandomNumberGenerator(int thread_count, int coeff_count,
                        const uint32_t *seed = nullptr,
                        const uint8_t *nonce = nullptr);
  ~RandomNumberGenerator();

  void assign_uniform_distribution_integer_chain(int64_t *output,
                                                 uint64_t max_value, int shift);
  void assign_sparse_ternary_chain(int64_t *output, int64_t *random_index,
                                   int hamming_weight);
  int64_t *get_discrete_gaussian_integer_chain();

private:
  const int thread_count_;
  const int coeff_count_;
  int64_t *state_;

  GaussianSamplingTree tree_;

  void update_thread_states();
};

}
