#include "ckks/precomputed.h"
#include "parameter/partition.h"

#pragma once

namespace desilo::fhe {

class PartitionsCache {
public:
  PartitionsCache(CKKSPrecomputed *precomputed) : precomputed_(precomputed) {}
  ~PartitionsCache();
  std::vector<Partition> &get(int ciphertext_moduli_id, int key_moduli_id);
  std::vector<CKKSPartitionParameters> *get_parameters(int ciphertext_moduli_id,
                                                       int key_moduli_id);
  void clear();

private:
  int64_t moduli_id_to_key(int ciphertext_moduli_id, int key_moduli_id);
  void set(int64_t key, std::vector<Partition> partitions);
  void set(int64_t key,
           std::vector<CKKSPartitionParameters> *partition_parameters);

  std::unordered_map<int64_t, std::vector<Partition>> partitions_cache_;
  std::unordered_map<int64_t, std::vector<CKKSPartitionParameters> *>
      parameters_cache_;
  CKKSPrecomputed *precomputed_;
};

}
