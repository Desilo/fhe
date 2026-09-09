#include <cstdint>

#pragma once

namespace desilo::fhe {

enum class ModuliType : uint8_t {
  LEVEL = 0,
  IN_RESCALE = 1,
  NTT = 2,
  KEY = 3,
  KEY_NTT = 4,
};

}
