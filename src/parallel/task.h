#pragma once

#include <complex>
#include <cstdint>
#include <initializer_list>
#include <vector>

#include "arithmetic/big_int.h"

namespace desilo::fhe {

class Task {
public:
  virtual ~Task() = default;

  virtual bool process() { return true; }

  int affinity_ = 0;
  virtual std::vector<void *> get_sources() = 0;
  virtual void *get_destination() = 0;
};

template <typename T> class TypedTask : public Task {
public:
  TypedTask(std::initializer_list<T *> sources, T *destination)
      : sources_(sources), destination_(destination){};

  std::vector<void *> get_sources() override {
    return std::vector<void *>(sources_.begin(), sources_.end());
  }
  void *get_destination() override { return static_cast<void *>(destination_); }

  const std::vector<T *> sources_;
  T *const destination_;
};

template <typename T> class StopTask : public TypedTask<T> {
public:
  StopTask() : TypedTask<T>({}, nullptr){};
  bool process() override { return false; }
};

template <typename U, typename V> class TypeConversionTask : public Task {
public:
  TypeConversionTask(std::initializer_list<U *> sources, V *destination)
      : sources_(sources), destination_(destination) {}

  std::vector<void *> get_sources() override {
    return std::vector<void *>(sources_.begin(), sources_.end());
  }

  void *get_destination() override { return static_cast<void *>(destination_); }

  const std::vector<U *> sources_;
  V *const destination_;
};

class MontEnterTask : public TypedTask<int64_t> {
public:
  MontEnterTask(int64_t *x, int64_t *y, int64_t constant, uint64_t q,
                uint64_t k, int coeff_count)
      : TypedTask({x}, y), constant_(constant), q_(q), k_(k),
        coeff_count_(coeff_count){};

  bool process() override;

  const int64_t constant_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MakeSignedTask : public TypedTask<int64_t> {
public:
  MakeSignedTask(int64_t *x, int64_t *y, uint64_t q, uint64_t q_half,
                 int coeff_count)
      : TypedTask({x}, y), q_(q), q_half_(q_half), coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_;
  const uint64_t q_half_;
  const int coeff_count_;
};

class MontAddTask : public TypedTask<int64_t> {
public:
  MontAddTask(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
              int coeff_count)
      : TypedTask({x1, x2}, y), q_double_(q_double),
        coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_double_;
  const int coeff_count_;
};

class MontMultTask : public TypedTask<int64_t> {
public:
  MontMultTask(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q, uint64_t k,
               int coeff_count)
      : TypedTask({x1, x2}, y), q_(q), k_(k), coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class Reduce2QToQTask : public TypedTask<int64_t> {
public:
  Reduce2QToQTask(int64_t *x, int64_t *y, uint64_t q, int coeff_count)
      : TypedTask({x}, y), q_(q), coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_;
  const int coeff_count_;
};

class MontSubtractTask : public TypedTask<int64_t> {
public:
  MontSubtractTask(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
                   int coeff_count)
      : TypedTask({x1, x2}, y), q_double_(q_double),
        coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_double_;
  const int coeff_count_;
};

class GetRounderTask : public TypedTask<int64_t> {
public:
  GetRounderTask(int64_t *x, int64_t *y, uint64_t q_half, int coeff_count)
      : TypedTask({x}, y), q_half_(q_half), coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_half_;
  const int coeff_count_;
};

class MontEnterAddTask : public TypedTask<int64_t> {
public:
  MontEnterAddTask(int64_t *x, int64_t *y, int64_t constant, uint64_t q_double,
                   uint64_t q, uint64_t k, int coeff_count)
      : TypedTask({x}, y), constant_(constant), q_double_(q_double), q_(q),
        k_(k), coeff_count_(coeff_count){};

  bool process() override;

  const int64_t constant_;
  const uint64_t q_double_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MontEnterAddReduce2QToQTask : public TypedTask<int64_t> {
public:
  MontEnterAddReduce2QToQTask(int64_t *x, int64_t *y, int64_t constant,
                              uint64_t q_double, uint64_t q, uint64_t k,
                              int coeff_count)
      : TypedTask({x}, y), constant_(constant), q_double_(q_double), q_(q),
        k_(k), coeff_count_(coeff_count){};

  bool process() override;

  const int64_t constant_;
  const uint64_t q_double_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MontMultAddTask : public TypedTask<int64_t> {
public:
  MontMultAddTask(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q_double,
                  uint64_t q, uint64_t k, int coeff_count)
      : TypedTask({x1, x2}, y), q_double_(q_double), q_(q), k_(k),
        coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_double_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MontSubEnterReduce2QToQTask : public TypedTask<int64_t> {
public:
  MontSubEnterReduce2QToQTask(int64_t *x1, int64_t *x2, int64_t *y,
                              int64_t constant, uint64_t q_double, uint64_t q,
                              uint64_t k, int coeff_count)
      : TypedTask({x1, x2}, y), constant_(constant), q_double_(q_double), q_(q),
        k_(k), coeff_count_(coeff_count){};

  bool process() override;

  const int64_t constant_;
  const uint64_t q_double_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MontSubEnterTask : public TypedTask<int64_t> {
public:
  MontSubEnterTask(int64_t *x1, int64_t *x2, int64_t *y, int64_t constant,
                   uint64_t q_double, uint64_t q, uint64_t k, int coeff_count)
      : TypedTask({x1, x2}, y), constant_(constant), q_double_(q_double), q_(q),
        k_(k), coeff_count_(coeff_count){};

  bool process() override;

  const int64_t constant_;
  const uint64_t q_double_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MontEnterExitTask : public TypedTask<int64_t> {
public:
  MontEnterExitTask(int64_t *x, int64_t *y, int64_t constant, uint64_t q,
                    uint64_t k, int coeff_count)
      : TypedTask({x}, y), constant_(constant), q_(q), k_(k),
        coeff_count_(coeff_count){};

  bool process() override;

  const int64_t constant_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MontEnterExitReduce2QToQTask : public TypedTask<int64_t> {
public:
  MontEnterExitReduce2QToQTask(int64_t *x, int64_t *y, int64_t constant,
                               uint64_t q, uint64_t k, int coeff_count)
      : TypedTask({x}, y), constant_(constant), q_(q), k_(k),
        coeff_count_(coeff_count){};

  bool process() override;

  const int64_t constant_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
};

class MontAddReduce2QToQTask : public TypedTask<int64_t> {
public:
  MontAddReduce2QToQTask(int64_t *x1, int64_t *x2, int64_t *y,
                         uint64_t q_double, uint64_t q, int coeff_count)
      : TypedTask({x1, x2}, y), q_double_(q_double), q_(q),
        coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_double_;
  const uint64_t q_;
  const int coeff_count_;
};

class MontSubReduce2QToQTask : public TypedTask<int64_t> {
public:
  MontSubReduce2QToQTask(int64_t *x1, int64_t *x2, int64_t *y,
                         uint64_t q_double, uint64_t q, int coeff_count)
      : TypedTask({x1, x2}, y), q_double_(q_double), q_(q),
        coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_double_;
  const uint64_t q_;
  const int coeff_count_;
};

class MakeUnsignedReduce2QToQTask : public TypedTask<int64_t> {
public:
  MakeUnsignedReduce2QToQTask(int64_t *x, int64_t *y, uint64_t q,
                              int coeff_count)
      : TypedTask({x}, y), q_(q), coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_;
  const int coeff_count_;
};

class NegateMakeUnsignedTask : public TypedTask<int64_t> {
public:
  NegateMakeUnsignedTask(int64_t *x, int64_t *y, uint64_t q, int coeff_count)
      : TypedTask({x}, y), q_(q), coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_;
  const int coeff_count_;
};

class ConcatenateMakeUnsignedTask : public TypedTask<int64_t> {
public:
  ConcatenateMakeUnsignedTask(int64_t *x1, int64_t *x2, int64_t *y, uint64_t q,
                              int coeff_count)
      : TypedTask({x1, x2}, y), q_(q), coeff_count_(coeff_count){};

  bool process() override;

  const uint64_t q_;
  const int coeff_count_;
};

class NttTask : public TypedTask<int64_t> {
public:
  NttTask(int64_t *x, int64_t *y, const int64_t *root, uint64_t q_double,
          uint64_t q, uint64_t k, int coeff_count, int log_coeff_count)
      : TypedTask({x}, y), root_(root), q_double_(q_double), q_(q), k_(k),
        coeff_count_(coeff_count), log_coeff_count_(log_coeff_count){};

  bool process() override;

  const int64_t *root_;
  const uint64_t q_double_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
  const int log_coeff_count_;
};

class InttTask : public TypedTask<int64_t> {
public:
  InttTask(int64_t *x, int64_t *y, const int64_t *root_inverse,
           uint64_t q_double, uint64_t q, uint64_t k, int coeff_count,
           int log_coeff_count)
      : TypedTask({x}, y), root_inverse_(root_inverse), q_double_(q_double),
        q_(q), k_(k), coeff_count_(coeff_count),
        log_coeff_count_(log_coeff_count){};

  bool process() override;

  const int64_t *root_inverse_;
  const uint64_t q_double_;
  const uint64_t q_;
  const uint64_t k_;
  const int coeff_count_;
  const int log_coeff_count_;
};

class RotatePolynomialTask : public TypedTask<int64_t> {
public:
  RotatePolynomialTask(int64_t *x, int64_t *y, const int32_t *permutation,
                       const int32_t *sign, int coeff_count)
      : TypedTask({x}, y), permutation_(permutation), sign_(sign),
        coeff_count_(coeff_count){};

  bool process() override;

  const int32_t *permutation_;
  const int32_t *sign_;
  const int coeff_count_;
};

class PermutePolynomialTask : public TypedTask<int64_t> {
public:
  PermutePolynomialTask(int64_t *x, int64_t *y, const int32_t *permutation,
                        int coeff_count)
      : TypedTask({x}, y), permutation_(permutation),
        coeff_count_(coeff_count){};

  bool process() override;

  const int32_t *permutation_;
  const int coeff_count_;
};

class AddScalarTask : public TypedTask<int64_t> {
public:
  AddScalarTask(int64_t *x, int64_t *y, int64_t scalar, int coeff_count)
      : TypedTask({x}, y), scalar_(scalar), coeff_count_(coeff_count){};

  bool process() override;

  const int64_t scalar_;
  const int coeff_count_;
};

class CopyTask : public TypedTask<int64_t> {
public:
  CopyTask(int64_t *x, int64_t *y, int coeff_count)
      : TypedTask({x}, y), coeff_count_(coeff_count){};

  bool process() override;

  const int coeff_count_;
};

class ZeroFillTask : public TypedTask<int64_t> {
public:
  ZeroFillTask(int64_t *y, int coeff_count)
      : TypedTask({}, y), coeff_count_(coeff_count){};

  bool process() override;

  const int coeff_count_;
};

class CompressPolynomialTask : public TypedTask<int64_t> {
public:
  CompressPolynomialTask(int64_t *x, int64_t *y, int y_count, int jump)
      : TypedTask({x}, y), y_count_(y_count), jump_(jump){};

  bool process() override;

  const int y_count_;
  const int jump_;
};

class DecompressPolynomialTask : public TypedTask<int64_t> {
public:
  DecompressPolynomialTask(int64_t *x, int64_t *y, int x_count, int jump)
      : TypedTask({x}, y), x_count_(x_count), jump_(jump){};

  bool process() override;

  const int x_count_;
  const int jump_;
};

class RoundTask : public TypeConversionTask<double, int64_t> {
public:
  RoundTask(double *x, int64_t *y, int coeff_count)
      : TypeConversionTask({x}, y), coeff_count_(coeff_count){};

  bool process() override;

  const int coeff_count_;
};

class MaxAbsoluteTask : public TypedTask<double> {
public:
  MaxAbsoluteTask(double *x, double *y, int coeff_count)
      : TypedTask({x}, y), coeff_count_(coeff_count){};

  bool process() override;

  const int coeff_count_;
};

class CastInt64ToDoubleTask : public TypeConversionTask<int64_t, double> {
public:
  CastInt64ToDoubleTask(int64_t *x, double *y, int coeff_count)
      : TypeConversionTask({x}, y), coeff_count_(coeff_count){};

  bool process() override;

  const int coeff_count_;
};

class ApplySkewerTask : public TypedTask<double> {
public:
  ApplySkewerTask(double *x, double *y, int count, int start_index, double step)
      : TypedTask({x}, y), count_(count), start_index_(start_index),
        step_(step){};

  bool process() override;

  const int count_;
  const int start_index_;
  const double step_;
};

class FftTask : public TypedTask<std::complex<double>> {
public:
  FftTask(std::complex<double> *x, std::complex<double> *y,
          const std::complex<double> *twiddle_factor, int size)
      : TypedTask({x}, y), twiddle_factor_(twiddle_factor), size_(size){};

  bool process() override;

  const std::complex<double> *twiddle_factor_;
  const int size_;
};

class DoubleToRNSTask : public TypeConversionTask<double, int64_t *> {
public:
  DoubleToRNSTask(double *x, int64_t **y, const uint64_t *q, int chain_count,
                  int coeff_count, int coeff_start, int coeff_end)
      : TypeConversionTask({x}, y), q_(q), chain_count_(chain_count),
        coeff_count_(coeff_count), coeff_start_(coeff_start),
        coeff_end_(coeff_end){};

  bool process() override;

  const uint64_t *q_;
  const int chain_count_;
  const int coeff_count_;
  const int coeff_start_;
  const int coeff_end_;
};

class RNSToDoubleTask : public TypeConversionTask<int64_t *, double> {
public:
  RNSToDoubleTask(int64_t **x, double *y, const uint64_t *q, BigInt q_product,
                  BigInt q_product_half, const BigInt *rns_reverser,
                  uint64_t r_minus_k_product, int chain_count, int coeff_count,
                  int coeff_start, int coeff_end)
      : TypeConversionTask({x}, y), q_(q), q_product_(q_product),
        q_product_half_(q_product_half), rns_reverser_(rns_reverser),
        r_minus_k_product_(r_minus_k_product), chain_count_(chain_count),
        coeff_count_(coeff_count), coeff_start_(coeff_start),
        coeff_end_(coeff_end){};

  bool process() override;

  const uint64_t *q_;
  const BigInt q_product_;
  const BigInt q_product_half_;
  const BigInt *rns_reverser_;
  const uint64_t r_minus_k_product_;
  const int chain_count_;
  const int coeff_count_;
  const int coeff_start_;
  const int coeff_end_;
};

}
