#include <cmath>
#include <cstdint>
#include <memory>

#pragma once

namespace desilo::fhe {

#ifdef DESILO_FHE_CHECK_HARDCODED
void build_gaussian_sampling_tree(uint64_t *tree, int security_bits,
                                  double sigma, int tree_depth, int tree_size,
                                  int chop_count);
#endif

struct GaussianSamplingTree {

  GaussianSamplingTree();

  const int security_bits_;
  const double sigma_;
  const int depth_;
  const int size_;
  const int chop_count_;
  const int data_size_;

  std::unique_ptr<uint64_t[]> data_handle_;
  uint64_t *data_;

private:
  GaussianSamplingTree(int security_bits, double sigma);
};

}
