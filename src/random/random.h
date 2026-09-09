#include <cstdint>

#pragma once

namespace desilo::fhe {

void generate_initial_bytes(int64_t *output, int bytes, int count);

void chacha20(int64_t *state, uint64_t *x, int thread_count);
void rand_int(int64_t *state, int64_t *output, uint64_t max_value,
              int64_t shift, int output_count, int thread_count);
void discrete_gaussian(int64_t *state, int64_t *output, const uint64_t *tree,
                       int tree_size, int tree_depth, int output_count,
                       int thread_count);

}
