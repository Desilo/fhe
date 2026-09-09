#include <algorithm>
#include <cxxabi.h>
#include <regex>
#include <typeinfo>

#include "parallel/worker.h"

namespace desilo::fhe {

void Worker::run() {
  std::vector<std::unique_ptr<Task>> tasks;
  while (true) {
    semaphore_start_.acquire();
    tasks = std::move(tasks_);

    bool can_continue = true;
    for (auto &task : tasks) {
#ifdef DESILO_FHE_DEBUG_PARALLEL
      std::string task_name = typeid(*task).name();
      int status = 0;
      char *demangled =
          abi::__cxa_demangle(task_name.c_str(), nullptr, nullptr, &status);

      task_name = (status == 0 && demangled) ? demangled : task_name;

      task_name =
          std::regex_replace(task_name, std::regex("^desilo::fhe::"), "");
      task_name = std::regex_replace(task_name, std::regex("Task.*$"), "");

      free(demangled);

      printf("%-20s (id: %d)\n", task_name.c_str(), id_);
#endif
      can_continue = task->process();
      if (!can_continue) {
        break;
      }
    }

    semaphore_done_.release();
    tasks.clear();

    if (!can_continue) {
      break;
    }
  }
}

void Worker::send_stop() {
  tasks_.emplace_back(std::make_unique<StopTask<int64_t>>());
  semaphore_start_.release();
}

void Worker::assign_tasks(std::vector<std::unique_ptr<Task>> &tasks) {
  std::swap(tasks_, tasks);
  semaphore_start_.release();
}

void Worker::join() { thread_.join(); }

WorkerPool::WorkerPool(int thread_count) {
  for (int thread_index = 0; thread_index < thread_count; thread_index++) {
    workers_.emplace_back(std::unique_ptr<Worker>(new Worker(thread_index)));
  }
}

WorkerPool::~WorkerPool() {
  for (auto &worker : workers_) {
    worker->send_stop();
  }

  for (auto &worker : workers_) {
    worker->join();
  }
}

void WorkerPool::send_tasks(std::vector<std::unique_ptr<Task>> &tasks) {
  const int task_count = tasks.size();
  const int worker_count = workers_.size();

  std::vector<std::vector<std::unique_ptr<Task>>> worker_tasks(worker_count);

  for (auto &task : tasks) {
    const int worker_index = task->affinity_ % worker_count;
    worker_tasks[worker_index].emplace_back(std::move(task));
  }

  for (int worker_index = 0; worker_index < worker_count; worker_index++) {
    const auto &worker = workers_[worker_index];
    auto &tasks = worker_tasks[worker_index];
    if (tasks.size() > 0) {
      worker->assign_tasks(tasks);
      worker->assigned_ = true;
    }
  }
}

void WorkerPool::wait() {
  for (auto &worker : workers_) {
    if (worker->assigned_) {
      worker->semaphore_done_.acquire();
      worker->assigned_ = false;
    }
  }
}

}
