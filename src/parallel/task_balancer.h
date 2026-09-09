#include <map>
#include <memory>
#include <vector>

#include "parallel/task.h"

#pragma once

namespace desilo::fhe {

class TaskBalancer {
public:
  void add(std::unique_ptr<Task> task);
  std::vector<std::unique_ptr<Task>> pop_all();

private:
  std::map<const void *, int> affinity_map_;
  std::vector<std::unique_ptr<Task>> tasks_;
};

}
