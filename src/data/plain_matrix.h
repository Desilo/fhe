#include <map>
#include <vector>

#include "data/data.h"

#pragma once

namespace desilo::fhe {

struct PlainMatrix {
  ~PlainMatrix();

  size_t nbytes() const;

  int level_;
  int inner_loop_count_;
  int outer_loop_count_;
  std::vector<int> inner_loop_deltas_;
  std::vector<int> outer_loop_deltas_;

  std::vector<std::pair<int, std::vector<int>>> outer_loop_process_order_;

  std::map<int, std::map<int, UnitPlaintext *>> encoded_diagonals_;
};

}
