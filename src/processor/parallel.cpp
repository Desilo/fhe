#include <algorithm>
#include <complex>
#include <vector>

#include "processor/parallel.h"

namespace desilo::fhe {

void ParallelProcessor::run() {
  for (auto &stage : stages_) {
    if (stage.type_ == StageType::RELEASE) {
      for (auto &release : stage.releases_) {
        release();
      }
    } else {
      for (auto &task : stage.tasks_) {
        balancer_.add(std::move(task));
      }
      std::vector<std::unique_ptr<Task>> tasks = balancer_.pop_all();
      pool_.send_tasks(tasks);
      pool_.wait();
    }
  }

  stages_.clear();
  destination_to_stage_map_.clear();
  stream_barriers_.clear();
  stream_last_stage_indices_.clear();
  stream_index_ = 0;
  start_index_ = 0;
}

void ParallelProcessor::add_barrier() { start_index_ = stages_.size(); }

void ParallelProcessor::reset_stream() {
  add_barrier();
  for (auto [index, barrier] : stream_barriers_) {
    stream_barriers_[index] = start_index_;
  }
}

void ParallelProcessor::set_stream(int stream_index) {
  stream_barriers_[stream_index_] = start_index_;
  stream_index_ = stream_index;
  start_index_ = stream_barriers_.contains(stream_index)
                     ? stream_barriers_[stream_index]
                     : 0;
}

Stage *ParallelProcessor::find_stage(const std::vector<void *> &source_ids,
                                     void *dest_id, StageType type) {
  int start_index = start_index_;

  for (const auto source_id : source_ids) {
    if (destination_to_stage_map_.contains(source_id)) {
      if (source_id == dest_id) {
        start_index =
            std::max(start_index, destination_to_stage_map_[source_id]);
      } else {
        start_index =
            std::max(start_index, destination_to_stage_map_[source_id] + 1);
      }
    }
  }

  Stage *stage = nullptr;
  for (int stage_index = start_index; stage_index < (int)stages_.size();
       stage_index++) {
    if (stages_[stage_index].type_ == type) {
      stage = &stages_[stage_index];
      break;
    }
  }

  if (stage == nullptr) {
    int order = stages_.size();
    stages_.emplace_back(order, type);
    stage = &stages_[order];
  }

  if (!stream_last_stage_indices_.contains(stream_index_) ||
      stage->order_ > stream_last_stage_indices_[stream_index_]) {
    stream_last_stage_indices_[stream_index_] = stage->order_;
  }

  return stage;
}

void ParallelProcessor::register_compute(
    std::vector<void *> source_ids, void *dest_id,
    std::vector<std::unique_ptr<Task>> tasks) {
  Stage *stage = find_stage(source_ids, dest_id, StageType::COMPUTE);
  destination_to_stage_map_[dest_id] = stage->order_;
  for (auto &task : tasks) {
    stage->tasks_.emplace_back(std::move(task));
  }
  run();
}

void ParallelProcessor::mont_enter(PolynomialInterface *x,
                                   PolynomialInterface *y,
                                   const int64_t *constant, const uint64_t *q,
                                   const uint64_t *k, int chain_count,
                                   int coeff_count, int x_offset,
                                   int y_offset) {
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(x_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t chain_constant = constant[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontEnterTask>(
        chain_x, chain_y, chain_constant, chain_q, chain_k, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::make_signed(PolynomialInterface *x,
                                    PolynomialInterface *y, const uint64_t *q,
                                    const uint64_t *q_half, int chain_count,
                                    int coeff_count) {
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_q_half = q_half[chain_index];
    tasks.emplace_back(std::make_unique<MakeSignedTask>(
        chain_x, chain_y, chain_q, chain_q_half, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_add(PolynomialInterface *x1,
                                 PolynomialInterface *x2,
                                 PolynomialInterface *y,
                                 const uint64_t *q_double, int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(chain_index);
    int64_t *chain_x2 = x2->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q_double = q_double[chain_index];
    tasks.emplace_back(std::make_unique<MontAddTask>(
        chain_x1, chain_x2, chain_y, chain_q_double, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_mult(PolynomialInterface *x1,
                                  PolynomialInterface *x2,
                                  PolynomialInterface *y, const uint64_t *q,
                                  const uint64_t *k, int chain_count,
                                  int x1_offset, int x2_offset) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(x1_offset + chain_index);
    int64_t *chain_x2 = x2->get(x2_offset + chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontMultTask>(
        chain_x1, chain_x2, chain_y, chain_q, chain_k, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::reduce_2q_to_q(PolynomialInterface *x,
                                       PolynomialInterface *y,
                                       const uint64_t *q, int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q = q[chain_index];
    tasks.emplace_back(std::make_unique<Reduce2QToQTask>(chain_x, chain_y,
                                                         chain_q, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::add_tiled(PolynomialInterface *x1,
                                  PolynomialInterface *x2,
                                  PolynomialInterface *y,
                                  const uint64_t *q_double, int chain_count) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x2 = x2->get(0);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q_double = q_double[chain_index];
    tasks.emplace_back(std::make_unique<MontAddTask>(
        chain_x1, chain_x2, chain_y, chain_q_double, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::sub_tiled(PolynomialInterface *x1,
                                  PolynomialInterface *x2,
                                  PolynomialInterface *y,
                                  const uint64_t *q_double, int chain_count,
                                  int x1_offset, int y_offset) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x2 = x2->get(0);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(x1_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    const uint64_t chain_q_double = q_double[chain_index];
    tasks.emplace_back(std::make_unique<MontSubtractTask>(
        chain_x1, chain_x2, chain_y, chain_q_double, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::get_rounder(PolynomialInterface *x,
                                    PolynomialInterface *y, uint64_t q_half,
                                    int x_offset) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x = x->get(x_offset);
  int64_t *chain_y = y->get(0);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.emplace_back(
      std::make_unique<GetRounderTask>(chain_x, chain_y, q_half, coeff_count));
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_enter_tiled(PolynomialInterface *x,
                                         PolynomialInterface *y,
                                         const int64_t *r_squared,
                                         const uint64_t *q, const uint64_t *k,
                                         int chain_count, int x_offset,
                                         int y_offset) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x = x->get(x_offset);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t chain_r_squared = r_squared[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontEnterTask>(
        chain_x, chain_y, chain_r_squared, chain_q, chain_k, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_enter_tiled_add(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *r_squared,
    const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
    int chain_count, int x_offset, int y_offset) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x = x->get(x_offset);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t chain_r_squared = r_squared[chain_index];
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontEnterAddTask>(
        chain_x, chain_y, chain_r_squared, chain_q_double, chain_q, chain_k,
        coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_enter_tiled_add_reduce_2q_to_q(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *r_squared,
    const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
    int chain_count, int x_offset, int y_offset) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x = x->get(x_offset);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t chain_r_squared = r_squared[chain_index];
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontEnterAddReduce2QToQTask>(
        chain_x, chain_y, chain_r_squared, chain_q_double, chain_q, chain_k,
        coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_mult_add(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const uint64_t *q_double, const uint64_t *q, const uint64_t *k,
    int chain_count, int x1_offset, int x2_offset) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(x1_offset + chain_index);
    int64_t *chain_x2 = x2->get(x2_offset + chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontMultAddTask>(
        chain_x1, chain_x2, chain_y, chain_q_double, chain_q, chain_k,
        coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_sub_enter_reduce_2q_to_q(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const int64_t *constant, const uint64_t *q_double, const uint64_t *q,
    const uint64_t *k, int chain_count, int x1_offset, int x2_offset,
    int y_offset) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(x1_offset + chain_index);
    int64_t *chain_x2 = x2->get(x2_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t chain_constant = constant[chain_index];
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontSubEnterReduce2QToQTask>(
        chain_x1, chain_x2, chain_y, chain_constant, chain_q_double, chain_q,
        chain_k, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_sub_tiled_enter(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const int64_t *constant, const uint64_t *q_double, const uint64_t *q,
    const uint64_t *k, int chain_count, int x1_offset, int x2_offset,
    int y_offset) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x2 = x2->get(x2_offset);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(x1_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t chain_constant = constant[chain_index];
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontSubEnterTask>(
        chain_x1, chain_x2, chain_y, chain_constant, chain_q_double, chain_q,
        chain_k, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_enter_exit(PolynomialInterface *x,
                                        PolynomialInterface *y,
                                        const int64_t *constant,
                                        const uint64_t *q, const uint64_t *k,
                                        int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const int64_t chain_constant = constant[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontEnterExitTask>(
        chain_x, chain_y, chain_constant, chain_q, chain_k, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_enter_exit_reduce_2q_to_q(
    PolynomialInterface *x, PolynomialInterface *y, const int64_t *constant,
    const uint64_t *q, const uint64_t *k, int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const int64_t chain_constant = constant[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<MontEnterExitReduce2QToQTask>(
        chain_x, chain_y, chain_constant, chain_q, chain_k, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_add_reduce_2q_to_q(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const uint64_t *q_double, const uint64_t *q, int chain_count, int x1_offset,
    int x2_offset, int y_offset) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(x1_offset + chain_index);
    int64_t *chain_x2 = x2->get(x2_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    tasks.emplace_back(std::make_unique<MontAddReduce2QToQTask>(
        chain_x1, chain_x2, chain_y, chain_q_double, chain_q, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::mont_sub_reduce_2q_to_q(
    PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
    const uint64_t *q_double, const uint64_t *q, int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x1 = x1->get(chain_index);
    int64_t *chain_x2 = x2->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    tasks.emplace_back(std::make_unique<MontSubReduce2QToQTask>(
        chain_x1, chain_x2, chain_y, chain_q_double, chain_q, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::make_unsigned_reduce_2q_to_q(PolynomialInterface *x,
                                                     PolynomialInterface *y,
                                                     const uint64_t *q,
                                                     int chain_count,
                                                     int coeff_count) {
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q = q[chain_index];
    tasks.emplace_back(std::make_unique<MakeUnsignedReduce2QToQTask>(
        chain_x, chain_y, chain_q, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::tile_unsigned_reduce_2q_to_q(
    PolynomialInterface *x, PolynomialInterface *y, const uint64_t *q,
    int chain_count, int coeff_count, int x_offset, int y_offset) {
  int64_t *chain_x = x->get(x_offset);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_y = y->get(y_offset + chain_index);
    const uint64_t chain_q = q[chain_index];
    tasks.emplace_back(std::make_unique<MakeUnsignedReduce2QToQTask>(
        chain_x, chain_y, chain_q, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::negate_make_unsigned(PolynomialInterface *x,
                                             PolynomialInterface *y,
                                             const uint64_t *q,
                                             int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q = q[chain_index];
    tasks.emplace_back(std::make_unique<NegateMakeUnsignedTask>(
        chain_x, chain_y, chain_q, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::concatenate_tile_unsigned(PolynomialInterface *x1,
                                                  PolynomialInterface *x2,
                                                  PolynomialInterface *y,
                                                  const uint64_t *q,
                                                  int chain_count) {
  const int coeff_count = coeff_count_;
  int64_t *chain_x1 = x1->get(0);
  int64_t *chain_x2 = x2->get(0);
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_y = y->get(chain_index);
    const uint64_t chain_q = q[chain_index];
    tasks.emplace_back(std::make_unique<ConcatenateMakeUnsignedTask>(
        chain_x1, chain_x2, chain_y, chain_q, coeff_count));
  }
  register_compute({x1->id(), x2->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::ntt(PolynomialInterface *x, PolynomialInterface *y,
                            const int64_t *root, const uint64_t *q_double,
                            const uint64_t *q, const uint64_t *k,
                            int chain_count, int x_offset, int y_offset) {
  const int coeff_count = coeff_count_;
  const int log_coeff_count = log_coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(x_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t *chain_root = &root[chain_index * (coeff_count - 1)];
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<NttTask>(
        chain_x, chain_y, chain_root, chain_q_double, chain_q, chain_k,
        coeff_count, log_coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::intt(PolynomialInterface *x, PolynomialInterface *y,
                             const int64_t *root_inverse,
                             const uint64_t *q_double, const uint64_t *q,
                             const uint64_t *k, int chain_count, int x_offset,
                             int y_offset) {
  const int coeff_count = coeff_count_;
  const int log_coeff_count = log_coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(x_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    const int64_t *chain_root_inverse =
        &root_inverse[chain_index * (coeff_count - 1)];
    const uint64_t chain_q_double = q_double[chain_index];
    const uint64_t chain_q = q[chain_index];
    const uint64_t chain_k = k[chain_index];
    tasks.emplace_back(std::make_unique<InttTask>(
        chain_x, chain_y, chain_root_inverse, chain_q_double, chain_q, chain_k,
        coeff_count, log_coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::zero_fill(PolynomialInterface *y, int chain_count,
                                  int coeff_count, int y_offset) {
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_y = y->get(y_offset + chain_index);
    tasks.emplace_back(std::make_unique<ZeroFillTask>(chain_y, coeff_count));
  }
  register_compute({}, y->id(), std::move(tasks));
}

void ParallelProcessor::copy(PolynomialInterface *x, PolynomialInterface *y,
                             int chain_count, int x_offset, int y_offset) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(x_offset + chain_index);
    int64_t *chain_y = y->get(y_offset + chain_index);
    tasks.emplace_back(
        std::make_unique<CopyTask>(chain_x, chain_y, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::copy_to_polynomial(int64_t *x, Polynomial *y,
                                           int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = &x[chain_index * coeff_count];
    int64_t *chain_y = y->chains_[chain_index];
    tasks.emplace_back(
        std::make_unique<CopyTask>(chain_x, chain_y, coeff_count));
  }
  register_compute({static_cast<void *>(x)}, y->id(), std::move(tasks));
}

void ParallelProcessor::compress_polynomial(PolynomialInterface *x,
                                            PolynomialInterface *y,
                                            int chain_count) {
  const int codec_coeff_count = codec_coeff_count_;
  const int jump = coeff_count_ / codec_coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    tasks.emplace_back(std::make_unique<CompressPolynomialTask>(
        chain_x, chain_y, codec_coeff_count, jump));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::decompress_polynomial(PolynomialInterface *x,
                                              PolynomialInterface *y,
                                              int chain_count) {
  const int codec_coeff_count = codec_coeff_count_;
  const int jump = coeff_count_ / codec_coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    tasks.emplace_back(std::make_unique<DecompressPolynomialTask>(
        chain_x, chain_y, codec_coeff_count, jump));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::round(DoublePolynomial *x, Polynomial *y,
                              int chain_count) {
  const int codec_coeff_count = codec_coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    double *chain_x = &x->buffer_[chain_index * codec_coeff_count];
    int64_t *chain_y = y->get(chain_index);
    tasks.emplace_back(
        std::make_unique<RoundTask>(chain_x, chain_y, codec_coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::max_absolute(DoublePolynomial *x, double *y) {
  const int codec_coeff_count = codec_coeff_count_;
  double *buffer = x->buffer_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.emplace_back(
      std::make_unique<MaxAbsoluteTask>(buffer, y, codec_coeff_count));
  register_compute({x->id()}, static_cast<void *>(y), std::move(tasks));
}

void ParallelProcessor::cast_int64_to_double(Polynomial *x, DoublePolynomial *y,
                                             int chain_count) {
  const int codec_coeff_count = codec_coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    double *chain_y = &y->buffer_[chain_index * codec_coeff_count];
    tasks.emplace_back(std::make_unique<CastInt64ToDoubleTask>(
        chain_x, chain_y, codec_coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::rotate_polynomial(Polynomial *x, Polynomial *y,
                                          const int32_t *permutation,
                                          const int32_t *sign,
                                          int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->chains_[chain_index];
    int64_t *chain_y = y->chains_[chain_index];
    tasks.emplace_back(std::make_unique<RotatePolynomialTask>(
        chain_x, chain_y, permutation, sign, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::permute_polynomial(Polynomial *x, Polynomial *y,
                                           const int32_t *permutation,
                                           int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->chains_[chain_index];
    int64_t *chain_y = y->chains_[chain_index];
    tasks.emplace_back(std::make_unique<PermutePolynomialTask>(
        chain_x, chain_y, permutation, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::add_scalar(PolynomialInterface *x,
                                   PolynomialInterface *y,
                                   const int64_t *scalar, int chain_count) {
  const int coeff_count = coeff_count_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.reserve(chain_count);
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {
    int64_t *chain_x = x->get(chain_index);
    int64_t *chain_y = y->get(chain_index);
    const int64_t chain_scalar = scalar[chain_index];
    tasks.emplace_back(std::make_unique<AddScalarTask>(
        chain_x, chain_y, chain_scalar, coeff_count));
  }
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::apply_skewer(DoublePolynomial *x, DoublePolynomial *y,
                                     double step, int size) {
  double *x_buffer = x->buffer_;
  double *y_buffer = y->buffer_;
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.emplace_back(
      std::make_unique<ApplySkewerTask>(x_buffer, y_buffer, size, 0, step));
  register_compute({x->id()}, y->id(), std::move(tasks));
}

void ParallelProcessor::fft(std::complex<double> *x, std::complex<double> *y,
                            const std::complex<double> *twiddle_factor,
                            int size) {
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.emplace_back(std::make_unique<FftTask>(x, y, twiddle_factor, size));
  register_compute({static_cast<void *>(x)}, static_cast<void *>(y),
                   std::move(tasks));
}

void ParallelProcessor::ifft(std::complex<double> *x, std::complex<double> *y,
                             const std::complex<double> *twiddle_factor,
                             int size) {
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.emplace_back(std::make_unique<FftTask>(x, y, twiddle_factor, size));
  register_compute({static_cast<void *>(x)}, static_cast<void *>(y),
                   std::move(tasks));
}

void ParallelProcessor::double_to_rns(double *x, Polynomial *y,
                                      const uint64_t *q, int chain_count,
                                      int y_offset) {
  const int codec_coeff_count = codec_coeff_count_;
  int64_t **y_chains = &y->chains_.data()[y_offset];
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.emplace_back(std::make_unique<DoubleToRNSTask>(
      x, y_chains, q, chain_count, codec_coeff_count, 0, codec_coeff_count));
  register_compute({static_cast<void *>(x)}, y->id(), std::move(tasks));
}

void ParallelProcessor::rns_to_double(Polynomial *x, double *y,
                                      const uint64_t *q, BigInt q_product,
                                      BigInt q_product_half,
                                      const BigInt *rns_reverser,
                                      uint64_t r_minus_k_product,
                                      int chain_count) {
  const int codec_coeff_count = codec_coeff_count_;
  int64_t **x_chains = x->chains_.data();
  std::vector<std::unique_ptr<Task>> tasks;
  tasks.emplace_back(std::make_unique<RNSToDoubleTask>(
      x_chains, y, q, q_product, q_product_half, rns_reverser,
      r_minus_k_product, chain_count, codec_coeff_count, 0, codec_coeff_count));
  register_compute({x->id()}, static_cast<void *>(y), std::move(tasks));
}

}
