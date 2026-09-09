#include <vector>

#include "arithmetic/type.h"

#pragma once

namespace desilo::fhe {

class BigInt {
public:
  BigInt(){};
  BigInt(std::vector<uint128_t> numbers);
  BigInt(uint64_t number) : data_({number}){};

  static BigInt power_of_two(int exponent);
  static BigInt from_double(double number);

  BigInt operator*(uint64_t other) const;
  BigInt &operator*=(uint64_t other);
  BigInt operator/(uint64_t other);
  uint64_t operator%(uint64_t other) const;
  BigInt operator+(BigInt &other);
  BigInt operator-(BigInt &other);
  bool operator==(const BigInt &other) const;
  bool operator>=(BigInt &other);
  BigInt montgomery_modulus(BigInt &modulus, uint64_t k);
  double get_double() const;

  std::vector<uint128_t> data_;
};

}
