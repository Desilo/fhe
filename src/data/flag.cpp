#include "data/flag.h"

namespace desilo::fhe {

bool is_complex(DataFlag flag) {
  return (flag & DataFlag::COMPLEX) == DataFlag::COMPLEX;
}

bool is_ntt_form(DataFlag flag) {
  return (flag & DataFlag::NTT_FORM) == DataFlag::NTT_FORM;
}

bool is_rescaled(DataFlag flag) {
  return (flag & DataFlag::RESCALED) == DataFlag::RESCALED;
}

bool is_sparse(DataFlag flag) {
  return (flag & DataFlag::SPARSE) == DataFlag::SPARSE;
}

bool includes_special(DataFlag flag) {
  return (flag & DataFlag::INCLUDE_SPECIAL) == DataFlag::INCLUDE_SPECIAL;
}

}
