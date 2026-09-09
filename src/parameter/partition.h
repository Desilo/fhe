#include <cstdint>
#include <memory>
#include <tuple>
#include <unordered_map>
#include <vector>

#pragma once

namespace desilo::fhe {

class Partition {
public:
  Partition(std::vector<int> &indices, int moduli_id, int partition_index)
      : moduli_id_(moduli_id), partition_index_(partition_index),
        start_(indices[0]), size_(indices.size()),
        chain_indices_(std::move(indices)) {}

  const int moduli_id_;
  const int partition_index_;

  const int start_;
  const int size_;

  int operator[](int index) const { return chain_indices_[index]; }

private:
  std::vector<int> chain_indices_;
};

struct CKKSPartitionParameters {
  CKKSPartitionParameters(){};
  CKKSPartitionParameters(CKKSPartitionParameters &&other) noexcept;

  std::vector<int64_t> q_product_inverse_mult_r_;
  std::vector<std::vector<int64_t>> q_product_mult_r_;

  std::vector<std::vector<int64_t>> q_product_mult_r_squared_;

  int64_t *get_q_product_inverse_mult_r(int chain_index);
  int64_t *get_q_product_mult_r(int chain_index);
  int64_t *get_q_product_mult_r_squared(int chain_index);
};

}
