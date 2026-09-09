#include <memory>
#include <semaphore>
#include <thread>
#include <vector>

#include "parallel/task.h"

#pragma once

namespace desilo::fhe {

class Worker {
public:
  Worker(const int id) : id_(id), thread_(&Worker::run, this){};

  void run();
  void send_stop();
  void assign_tasks(std::vector<std::unique_ptr<Task>> &tasks);
  void join();

  const int id_;
  bool assigned_ = false;
  std::binary_semaphore semaphore_start_{0};
  std::binary_semaphore semaphore_done_{0};
  std::vector<std::unique_ptr<Task>> tasks_;

private:
  std::thread thread_;
};

class WorkerPool {
public:
  WorkerPool(const int thread_count);
  ~WorkerPool();

  void send_tasks(std::vector<std::unique_ptr<Task>> &tasks);
  void wait();

private:
  std::vector<std::unique_ptr<Worker>> workers_;
};

}
