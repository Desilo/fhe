#include <complex>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "data/flag.h"

#pragma once

namespace desilo::fhe {

template <typename T> struct PolynomialBaseInterface {

  virtual void *id() const = 0;

  virtual DataFlag flag() const = 0;
  virtual uint16_t moduli_id() const = 0;
  virtual uint8_t chain_count() const = 0;
  virtual uint32_t coeff_count() const = 0;

  virtual inline T *get(int index) = 0;
};

typedef PolynomialBaseInterface<int64_t> PolynomialInterface;

template <typename T> struct PolynomialBase : PolynomialBaseInterface<T> {
  PolynomialBase(T *buffer, const DataFlag flag, int moduli_id, int coeff_count)
      : buffer_(buffer), flag_(flag), moduli_id_(moduli_id), chain_count_(1),
        coeff_count_(coeff_count) {}

  PolynomialBase(std::vector<T *> &chains, const DataFlag flag, int moduli_id,
                 int coeff_count)
      : chains_(chains), flag_(flag), moduli_id_(moduli_id),
        chain_count_(chains.size()), coeff_count_(coeff_count) {}

  PolynomialBase(const DataFlag flag, int moduli_id, int chain_count,
                 int coeff_count)
      : chains_(chain_count), flag_(flag), moduli_id_(moduli_id),
        chain_count_(chain_count), coeff_count_(coeff_count) {
    for (int chain_index = 0; chain_index < chain_count; chain_index++) {
      chains_[chain_index] = new T[coeff_count];
    };
  }

  virtual ~PolynomialBase() {

    if (buffer_ != nullptr) {
      delete[] buffer_;
      buffer_ = nullptr;
    }

    for (auto chain : chains_) {
      delete[] chain;
    }
  };

  inline T *get(int index) { return chains_[index]; }

  void *id() const {
    return static_cast<void *>(buffer_ != nullptr ? buffer_ : chains_[0]);
  }
  DataFlag flag() const { return flag_; }
  uint16_t moduli_id() const { return moduli_id_; }
  uint8_t chain_count() const { return chain_count_; }
  uint32_t coeff_count() const { return coeff_count_; }

  virtual size_t nbytes() = 0;

  T *buffer_ = nullptr;
  std::vector<T *> chains_;

  DataFlag flag_;
  const int moduli_id_;
  const uint8_t chain_count_;
  const uint32_t coeff_count_;
};

struct Polynomial : PolynomialBase<int64_t> {
  Polynomial(std::vector<int64_t *> &chains, const DataFlag flag, int moduli_id,
             int coeff_count)
      : PolynomialBase<int64_t>(chains, flag, moduli_id, coeff_count) {}

  Polynomial(const DataFlag flag, int moduli_id, int chain_count,
             int coeff_count)
      : PolynomialBase<int64_t>(flag, moduli_id, chain_count, coeff_count) {}

  size_t nbytes() override {
    return sizeof(Polynomial) + sizeof(*buffer_) * chain_count_ * coeff_count_;
  };
};

struct DoublePolynomial : PolynomialBase<double> {
  DoublePolynomial(double *buffer, const DataFlag flag, int moduli_id,
                   int coeff_count)
      : PolynomialBase<double>(buffer, flag, moduli_id, coeff_count) {}

  DoublePolynomial(const DataFlag flag, int moduli_id, int coeff_count)
      : PolynomialBase<double>(new double[coeff_count], flag, moduli_id,
                               coeff_count) {}

  size_t nbytes() override {
    return sizeof(DoublePolynomial) + sizeof(*buffer_) * coeff_count_;
  };
};

struct ComplexDoublePolynomial : PolynomialBase<std::complex<double>> {
  ComplexDoublePolynomial(std::complex<double> *buffer, const DataFlag flag,
                          int moduli_id, int coeff_count)
      : PolynomialBase<std::complex<double>>(buffer, flag, moduli_id,
                                             coeff_count) {}

  ComplexDoublePolynomial(const DataFlag flag, int moduli_id, int coeff_count)
      : PolynomialBase<std::complex<double>>(
            new std::complex<double>[coeff_count], flag, moduli_id,
            coeff_count) {}

  size_t nbytes() override {
    return sizeof(ComplexDoublePolynomial) + sizeof(*buffer_) * coeff_count_;
  };
};

struct PolynomialView : PolynomialBaseInterface<int64_t> {
  PolynomialView(void *id, const std::vector<int64_t *> &chains, DataFlag flag,
                 int moduli_id, int coeff_count);
  PolynomialView(Polynomial *polynomial, int offset);

  void *id() const { return id_; }
  DataFlag flag() const { return flag_; }
  uint16_t moduli_id() const { return moduli_id_; }
  uint8_t chain_count() const { return chain_count_; }
  uint32_t coeff_count() const { return coeff_count_; }

  inline int64_t *get(int index) { return chains_[index]; }

  void *id_;
  std::vector<int64_t *> chains_;
  const DataFlag flag_;
  const int moduli_id_;
  const uint8_t chain_count_;
  const uint32_t coeff_count_;
};

}
