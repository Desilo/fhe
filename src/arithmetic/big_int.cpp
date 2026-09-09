#include <cmath>
#include <stdexcept>

#include "arithmetic/big_int.h"
#include "big_int.h"

namespace desilo::fhe {

BigInt::BigInt(std::vector<uint128_t> numbers) : data_(std::move(numbers)) {
  while (data_.size() > 1 && data_.back() == 0) {
    data_.pop_back();
  }
}

BigInt BigInt::power_of_two(int exponent) {
  std::vector<uint128_t> numbers;

  while (exponent >= 64) {
    numbers.push_back(0);
    exponent -= 64;
  }

  uint128_t one = 1;
  numbers.push_back(one << exponent);

  return BigInt(numbers);
}

BigInt BigInt::from_double(double number) {
  std::vector<uint128_t> numbers;
  const double base = std::pow(2, 64);

  while (number > 0) {
    auto quotient = std::floor(number / base);
    auto remainder = number - quotient * base;
    number = quotient;

    numbers.push_back(static_cast<uint128_t>(remainder));
  }

  return BigInt(numbers);
}

BigInt BigInt::operator*(uint64_t other) const {
  if (other == 0) {
    return BigInt(UINT64_C(0));
  }

  const auto size = data_.size();
  std::vector<uint128_t> product_data(size);

  const uint128_t other_value = static_cast<uint128_t>(other);
  uint128_t carry = 0;
  for (int index = 0; index < size; index++) {
    uint128_t product = data_[index] * other_value + carry;
    carry = product >> 64;

    product_data[index] = product & UINT64_MAX;
  }

  if (carry != 0) {
    product_data.emplace_back(carry);
  }

  return BigInt(product_data);
}

BigInt &BigInt::operator*=(uint64_t other) {
  *this = *this * other;
  return *this;
}

BigInt BigInt::operator/(uint64_t other) {
  if (other == 0) {
    throw std::runtime_error("Divide: can not divide with 0.");
  }

  const auto size = data_.size();
  std::vector<uint128_t> quotient_data(size);

  const uint128_t other_value = static_cast<uint128_t>(other);
  uint128_t carry = 0;
  for (int index = size - 1; index >= 0; index--) {
    carry = (carry << 64) + data_[index];
    uint128_t quotient = carry / other_value;
    carry -= quotient * other_value;

    quotient_data[index] = quotient;
  }

  return BigInt(quotient_data);
}

uint64_t BigInt::operator%(uint64_t other) const {
  if (other == 0) {
    throw std::runtime_error("Divide: can not divide with 0.");
  }

  const auto size = data_.size();

  const uint128_t other_value = static_cast<uint128_t>(other);
  uint128_t carry = 0;
  for (int index = size - 1; index >= 0; index--) {
    carry = (carry << 64) + data_[index];
    carry -= (carry / other_value) * other_value;
  }

  return static_cast<uint64_t>(carry);
}

BigInt BigInt::operator+(BigInt &other) {
  const auto other_data = other.data_;
  const auto size = std::max(data_.size(), other_data.size());
  std::vector<uint128_t> sum_data(size);

  uint128_t carry = 0;
  for (int index = 0; index < size; index++) {
    uint128_t sum = carry;
    if (index < data_.size()) {
      sum += data_[index];
    }
    if (index < other_data.size()) {
      sum += other_data[index];
    }

    sum_data[index] = sum & UINT64_MAX;
    carry = sum >> 64;
  }

  if (carry != 0) {
    sum_data.emplace_back(carry);
  }

  return BigInt(sum_data);
}

BigInt BigInt::operator-(BigInt &other) {
  const auto other_data = other.data_;
  const auto size = data_.size();
  std::vector<uint128_t> difference_data(size);

  uint128_t borrow = 0;
  const uint128_t one = static_cast<uint128_t>(1);
  for (int index = 0; index < size; index++) {
    uint128_t difference = data_[index];

    uint128_t subtractor = borrow;
    if (index < other_data.size()) {
      subtractor += other_data[index];
    }

    if (difference < subtractor) {
      difference += (one << 64);
      borrow = 1;
    } else {
      borrow = 0;
    }
    difference -= subtractor;

    difference_data[index] = difference;
  }

  return BigInt(difference_data);
}

bool BigInt::operator==(const BigInt &other) const {
  const auto other_data = other.data_;
  if (data_.size() != other_data.size()) {
    return false;
  }

  for (int index = 0; index < data_.size(); index++) {
    if (data_[index] != other_data[index]) {
      return false;
    }
  }

  return true;
}

bool BigInt::operator>=(BigInt &other) {
  const auto other_data = other.data_;
  if (data_.size() != other_data.size()) {
    return data_.size() > other_data.size();
  }

  for (int index = data_.size() - 1; index >= 0; index--) {
    if (data_[index] != other_data[index]) {
      return data_[index] > other_data[index];
    }
  }

  return true;
}

BigInt BigInt::montgomery_modulus(BigInt &modulus, uint64_t k) {
  constexpr int64_t one = 1;
  constexpr int64_t nbits = sizeof(int64_t) * 8 - 2;
  constexpr int64_t r = one << nbits;
  constexpr int64_t fb_mask = (r - one);

  auto upper_bound = modulus * r;
  auto this_value = *this;
  while (this_value >= upper_bound) {
    this_value = this_value - upper_bound;
  }

  auto product = modulus * ((data_[0] * k) & fb_mask);
  auto added = this_value + product;
  auto quotient = added / r;

  if (quotient >= modulus) {
    return quotient - modulus;
  }

  return quotient;
}

double BigInt::get_double() const {
  double y = 0;
  for (int index = 0; index < data_.size(); index++) {
    y += static_cast<double>(data_[index]) * std::pow(2.0, 64 * index);
  }
  return y;
}

}
