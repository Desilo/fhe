#include <cstddef>

#pragma once

namespace desilo::fhe {

struct Bytearray {
  char *buffer_;
  size_t size_;

  Bytearray(char *buffer, size_t size) : buffer_(buffer), size_(size){};
};

}
