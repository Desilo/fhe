#include "data/plain_matrix.h"

namespace desilo::fhe {

PlainMatrix::~PlainMatrix() {
  for (const auto &[outer_index, outer_map] : encoded_diagonals_) {
    for (const auto &[inner_index, encoded_diagonal] : outer_map) {
      delete encoded_diagonal;
    }
  }
}

size_t PlainMatrix::nbytes() const {
  auto size = sizeof(PlainMatrix);
  size += sizeof(*inner_loop_deltas_.data()) * inner_loop_deltas_.capacity();
  size += sizeof(*outer_loop_deltas_.data()) * outer_loop_deltas_.capacity();
  for (const auto &outer_loop_process_order : outer_loop_process_order_) {
    size += sizeof(outer_loop_process_order);
    auto process_order = outer_loop_process_order.second;
    size += sizeof(*process_order.data()) * process_order.capacity();
  }
  for (const auto &outer_encoded_diagonals : encoded_diagonals_) {
    size += sizeof(outer_encoded_diagonals);
    for (const auto &inner_encoded_diagonals : outer_encoded_diagonals.second) {
      size += sizeof(inner_encoded_diagonals);
      size += inner_encoded_diagonals.second->nbytes();
    }
  }

  return size;
}

}
