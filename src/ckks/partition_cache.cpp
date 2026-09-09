#include "ckks/partition_cache.h"

namespace desilo::fhe {

PartitionsCache::~PartitionsCache() {
  for (const auto [key, partition_parameters] : parameters_cache_) {
    delete partition_parameters;
  }
}

std::vector<Partition> &PartitionsCache::get(int ciphertext_moduli_id,
                                             int key_moduli_id) {
  const auto key = moduli_id_to_key(ciphertext_moduli_id, key_moduli_id);
  if (!partitions_cache_.contains(key)) {
    set(key, precomputed_->parameters_.get_partitions(ciphertext_moduli_id,
                                                      key_moduli_id));
  }

  return partitions_cache_.find(key)->second;
}

std::vector<CKKSPartitionParameters> *
PartitionsCache::get_parameters(int ciphertext_moduli_id, int key_moduli_id) {
  const auto key = moduli_id_to_key(ciphertext_moduli_id, key_moduli_id);
  if (!parameters_cache_.contains(key)) {
    auto partitions = get(ciphertext_moduli_id, key_moduli_id);
    auto partition_parameters = new std::vector<CKKSPartitionParameters>();
    for (auto &partition : partitions) {
      partition_parameters->push_back(
          precomputed_->make_partition_parameters(partition));
    }
    set(key, partition_parameters);
  }

  return parameters_cache_.find(key)->second;
}

void PartitionsCache::clear() { partitions_cache_.clear(); }

int64_t PartitionsCache::moduli_id_to_key(int ciphertext_moduli_id,
                                          int key_moduli_id) {
  return (static_cast<int64_t>(ciphertext_moduli_id) << 32) | key_moduli_id;
}

void PartitionsCache::set(int64_t key, std::vector<Partition> partitions) {
  partitions_cache_.insert({key, std::move(partitions)});
}

void PartitionsCache::set(int64_t key,
                          std::vector<CKKSPartitionParameters> *parameters) {
  parameters_cache_.insert({key, parameters});
}

}
