#include <cstdint>

#pragma once

namespace desilo::fhe {

enum class DataFlag : uint16_t {
  NONE = 0,
  COMPLEX = 1,
  NTT_FORM = 2,
  RESCALED = 4,
  SPARSE = 8,
  INCLUDE_SPECIAL = 16,
};

DataFlag operator~(DataFlag rhs);
DataFlag operator|(DataFlag lhs, DataFlag rhs);
DataFlag operator&(DataFlag lhs, DataFlag rhs);
DataFlag &operator|=(DataFlag &lhs, DataFlag rhs);
DataFlag &operator&=(DataFlag &lhs, DataFlag rhs);

bool is_complex(DataFlag flag);
bool is_ntt_form(DataFlag flag);
bool is_rescaled(DataFlag flag);
bool is_sparse(DataFlag flag);
bool includes_special(DataFlag flag);

}
