#include "parameter/partition.h"

namespace desilo::fhe {

CKKSPartitionParameters::CKKSPartitionParameters(
    CKKSPartitionParameters &&other) noexcept
    : q_product_inverse_mult_r_(std::move(other.q_product_inverse_mult_r_)),
      q_product_mult_r_(std::move(other.q_product_mult_r_)),
      q_product_mult_r_squared_(std::move(other.q_product_mult_r_squared_)) {}

int64_t *
CKKSPartitionParameters::get_q_product_inverse_mult_r(int chain_index) {
  return &q_product_inverse_mult_r_[chain_index];
}

int64_t *CKKSPartitionParameters::get_q_product_mult_r(int chain_index) {
  return q_product_mult_r_[chain_index].data();
}

int64_t *
CKKSPartitionParameters::get_q_product_mult_r_squared(int chain_index) {
  return q_product_mult_r_squared_[chain_index].data();
}

}
