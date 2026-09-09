#include "parallel/task_balancer.h"

namespace desilo::fhe {

void TaskBalancer::add(std::unique_ptr<Task> task) {
  const void *destination = task->get_destination();

  if (!affinity_map_.contains(destination)) {
    affinity_map_[destination] = affinity_map_.size();
  }

  task->affinity_ = affinity_map_[destination];
  tasks_.emplace_back(std::move(task));
}

std::vector<std::unique_ptr<Task>> TaskBalancer::pop_all() {
  affinity_map_.clear();
  return std::move(tasks_);
}

}
