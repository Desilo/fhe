#pragma once

#include <complex>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <type_traits>
#include <vector>

#include "arithmetic/big_int.h"
#include "data/polynomial.h"
#include "parallel/task.h"
#include "parallel/task_balancer.h"
#include "parallel/worker.h"

namespace desilo::fhe {

enum class StageType : uint8_t {
  COMPUTE = 0,
  RELEASE = 1,
};

struct Stage {
  Stage(int order, StageType type) : order_(order), type_(type){};

  const int order_;
  const StageType type_;
  std::vector<std::unique_ptr<Task>> tasks_;
  std::vector<std::function<void()>> releases_;
};

template <typename T> class ExtractDiagonalsTask : public TypedTask<T> {
public:
  ExtractDiagonalsTask(T *x, T *y, int outer_loop_count, int inner_loop_count)
      : TypedTask<T>({x}, y), outer_loop_count_(outer_loop_count),
        inner_loop_count_(inner_loop_count){};
  bool process() override {
    T *x = this->sources_[0];
    T *y = this->destination_;
    const auto slot_count = outer_loop_count_ * inner_loop_count_;
    const auto modulo_mask = slot_count - 1;
    const auto double_slot_count = 2 * slot_count;

    for (int outer_loop_index = 0; outer_loop_index < outer_loop_count_;
         outer_loop_index++) {
      const auto normalized_outer_loop_index =
          outer_loop_index - outer_loop_count_ / 2;
      int delta = -(normalized_outer_loop_index * inner_loop_count_);
      delta = (delta + double_slot_count) & modulo_mask;

      for (int inner_loop_index = 0; inner_loop_index < inner_loop_count_;
           inner_loop_index++) {
        auto diagonal_index =
            inner_loop_count_ * normalized_outer_loop_index + inner_loop_index;
        diagonal_index = (diagonal_index + double_slot_count) & modulo_mask;

        auto loop_index =
            outer_loop_index * inner_loop_count_ + inner_loop_index;
        auto diagonal_y = &y[loop_index * slot_count];

        for (int data_index = 0; data_index < slot_count; data_index++) {
          auto row_index = data_index - delta;
          auto column_index = row_index - diagonal_index;

          row_index = (row_index + double_slot_count) & modulo_mask;
          column_index = (column_index + double_slot_count) & modulo_mask;

          diagonal_y[data_index] = x[row_index * slot_count + column_index];
        }
      }
    }
    return true;
  }

private:
  const int outer_loop_count_;
  const int inner_loop_count_;
};

class ParallelProcessor {
public:
  ParallelProcessor(int thread_count, int log_coeff_count,
                    int log_codec_coeff_count)
      : pool_(thread_count), thread_count_(thread_count),
        coeff_count_(int(1) << log_coeff_count),
        log_coeff_count_(log_coeff_count),
        codec_coeff_count_(int(1) << log_codec_coeff_count),
        log_codec_coeff_count_(log_codec_coeff_count){};

  void run();
  void add_barrier();
  void reset_stream();
  void set_stream(int stream_index);

  template <class T> void release(T *resource) {
    void *dest = id_of(resource);
    Stage *stage = find_stage({dest}, dest, StageType::RELEASE);
    destination_to_stage_map_[dest] = stage->order_;
    stage->releases_.emplace_back([resource] { delete resource; });
    run();
  }

  void mont_enter(PolynomialInterface *x, PolynomialInterface *y,
                  const int64_t *constant, const uint64_t *q, const uint64_t *k,
                  int chain_count, int coeff_count, int x_offset, int y_offset);
  void make_signed(PolynomialInterface *x, PolynomialInterface *y,
                   const uint64_t *q, const uint64_t *q_half, int chain_count,
                   int coeff_count);
  void mont_add(PolynomialInterface *x1, PolynomialInterface *x2,
                PolynomialInterface *y, const uint64_t *q_double,
                int chain_count);
  void mont_mult(PolynomialInterface *x1, PolynomialInterface *x2,
                 PolynomialInterface *y, const uint64_t *q, const uint64_t *k,
                 int chain_count, int x1_offset, int x2_offset);
  void reduce_2q_to_q(PolynomialInterface *x, PolynomialInterface *y,
                      const uint64_t *q, int chain_count);
  void sub_tiled(PolynomialInterface *x1, PolynomialInterface *x2,
                 PolynomialInterface *y, const uint64_t *q_double,
                 int chain_count, int x1_offset, int y_offset);
  void add_tiled(PolynomialInterface *x1, PolynomialInterface *x2,
                 PolynomialInterface *y, const uint64_t *q_double,
                 int chain_count);
  void get_rounder(PolynomialInterface *x, PolynomialInterface *y,
                   uint64_t q_half, int x_offset);

  void mont_enter_tiled(PolynomialInterface *x, PolynomialInterface *y,
                        const int64_t *r_squared, const uint64_t *q,
                        const uint64_t *k, int chain_count, int x_offset,
                        int y_offset);
  void mont_enter_tiled_add(PolynomialInterface *x, PolynomialInterface *y,
                            const int64_t *r_squared, const uint64_t *q_double,
                            const uint64_t *q, const uint64_t *k,
                            int chain_count, int x_offset, int y_offset);
  void mont_enter_tiled_add_reduce_2q_to_q(
      PolynomialInterface *x, PolynomialInterface *y, const int64_t *r_squared,
      const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
      int chain_count, int x_offset, int y_offset);
  void mont_mult_add(PolynomialInterface *x1, PolynomialInterface *x2,
                     PolynomialInterface *y, const uint64_t *q_double,
                     const uint64_t *q, const uint64_t *k, int chain_count,
                     int x1_offset, int x2_offset);
  void mont_sub_enter_reduce_2q_to_q(
      PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
      const int64_t *constant, const uint64_t *q_double, const uint64_t *q,
      const uint64_t *k, int chain_count, int x1_offset, int x2_offset,
      int y_offset);
  void mont_sub_tiled_enter(PolynomialInterface *x1, PolynomialInterface *x2,
                            PolynomialInterface *y, const int64_t *constant,
                            const uint64_t *q_double, const uint64_t *q,
                            const uint64_t *k, int chain_count, int x1_offset,
                            int x2_offset, int y_offset);
  void mont_enter_exit(PolynomialInterface *x, PolynomialInterface *y,
                       const int64_t *constant, const uint64_t *q,
                       const uint64_t *k, int chain_count);
  void mont_enter_exit_reduce_2q_to_q(PolynomialInterface *x,
                                      PolynomialInterface *y,
                                      const int64_t *constant,
                                      const uint64_t *q, const uint64_t *k,
                                      int chain_count);
  void mont_add_reduce_2q_to_q(PolynomialInterface *x1, PolynomialInterface *x2,
                               PolynomialInterface *y, const uint64_t *q_double,
                               const uint64_t *q, int chain_count,
                               int x1_offset, int x2_offset, int y_offset);
  void mont_sub_reduce_2q_to_q(PolynomialInterface *x1, PolynomialInterface *x2,
                               PolynomialInterface *y, const uint64_t *q_double,
                               const uint64_t *q, int chain_count);
  void make_unsigned_reduce_2q_to_q(PolynomialInterface *x,
                                    PolynomialInterface *y, const uint64_t *q,
                                    int chain_count, int coeff_count);
  void tile_unsigned_reduce_2q_to_q(PolynomialInterface *x,
                                    PolynomialInterface *y, const uint64_t *q,
                                    int chain_count, int coeff_count,
                                    int x_offset, int y_offset);
  void negate_make_unsigned(PolynomialInterface *x, PolynomialInterface *y,
                            const uint64_t *q, int chain_count);
  void concatenate_tile_unsigned(PolynomialInterface *x1,
                                 PolynomialInterface *x2,
                                 PolynomialInterface *y, const uint64_t *q,
                                 int chain_count);

  void apply_skewer(DoublePolynomial *x, DoublePolynomial *y, double step,
                    int size);

  void fft(std::complex<double> *x, std::complex<double> *y,
           const std::complex<double> *twiddle_factor, int size);
  void ifft(std::complex<double> *x, std::complex<double> *y,
            const std::complex<double> *twiddle_factor, int size);

  template <typename T>
  void extract_diagonals(T *x, T *y, int outer_loop_count,
                         int inner_loop_count) {
    std::vector<std::unique_ptr<Task>> tasks;
    tasks.emplace_back(std::make_unique<ExtractDiagonalsTask<T>>(
        x, y, outer_loop_count, inner_loop_count));
    register_compute({static_cast<void *>(x)}, static_cast<void *>(y),
                     std::move(tasks));
  }

  void ntt(PolynomialInterface *x, PolynomialInterface *y, const int64_t *root,
           const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
           int chain_count, int x_offset, int y_offset);
  void intt(PolynomialInterface *x, PolynomialInterface *y,
            const int64_t *root_inverse, const uint64_t *q_double,
            const uint64_t *q, const uint64_t *k, int chain_count, int x_offset,
            int y_offset);

  void rotate_polynomial(Polynomial *x, Polynomial *y,
                         const int32_t *permutation, const int32_t *sign,
                         int chain_count);
  void permute_polynomial(Polynomial *x, Polynomial *y,
                          const int32_t *permutation, int chain_count);

  void add_scalar(PolynomialInterface *x, PolynomialInterface *y,
                  const int64_t *scalar, int chain_count);

  void zero_fill(PolynomialInterface *y, int chain_count, int coeff_count,
                 int y_offset);
  void copy_to_polynomial(int64_t *x, Polynomial *y, int chain_count);
  void copy(PolynomialInterface *x, PolynomialInterface *y, int chain_count,
            int x_offset, int y_offset);
  void compress_polynomial(PolynomialInterface *x, PolynomialInterface *y,
                           int chain_count);
  void decompress_polynomial(PolynomialInterface *x, PolynomialInterface *y,
                             int chain_count);
  void round(DoublePolynomial *x, Polynomial *y, int chain_count);
  void max_absolute(DoublePolynomial *x, double *y);
  void cast_int64_to_double(Polynomial *x, DoublePolynomial *y,
                            int chain_count);

  void double_to_rns(double *x, Polynomial *y, const uint64_t *q,
                     int chain_count, int y_offset);
  void rns_to_double(Polynomial *x, double *y, const uint64_t *q,
                     BigInt q_product, BigInt q_product_half,
                     const BigInt *rns_reverser, uint64_t r_minus_k_product,
                     int chain_count);

private:
  Stage *find_stage(const std::vector<void *> &source_ids, void *dest_id,
                    StageType type);
  void register_compute(std::vector<void *> source_ids, void *dest_id,
                        std::vector<std::unique_ptr<Task>> tasks);

  template <class T> static void *id_of(T *resource) {
    if constexpr (std::is_base_of_v<PolynomialInterface, T> &&
                  !std::is_base_of_v<PolynomialView, T>) {
      return resource->id();
    }
    return static_cast<void *>(resource);
  }

  TaskBalancer balancer_;
  WorkerPool pool_;
  const int thread_count_;
  const int coeff_count_;
  const int log_coeff_count_;
  const int codec_coeff_count_;
  const int log_codec_coeff_count_;

  std::vector<Stage> stages_;
  std::map<void *, int> destination_to_stage_map_;

  int stream_index_ = 0;
  int start_index_ = 0;
  std::map<int, int> stream_barriers_;
  std::map<int, int> stream_last_stage_indices_;
};

}
