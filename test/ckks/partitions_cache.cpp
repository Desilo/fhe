#include "ckks/partition_cache.h"
#include "ckks/precomputed.h"
#include "common/common.h"
#include "common/test.h"

TEST(PartitionsCache, Get) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  auto parameters = desilo::fhe::CKKSPrecomputed(config);
  auto partitions_cache = desilo::fhe::PartitionsCache(&parameters);
  int ciphertext_moduli_id = 1;
  int key_moduli_id = 1;

  auto partitions = partitions_cache.get(ciphertext_moduli_id, key_moduli_id);
  ASSERT_EQ(partitions.size(), 3);

  partitions_cache.clear();

  auto partitions2 = partitions_cache.get(ciphertext_moduli_id, key_moduli_id);
  ASSERT_EQ(partitions2.size(), 3);
}

TEST(PartitionsCache, GetParameters) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  auto parameters = desilo::fhe::CKKSPrecomputed(config);
  auto partitions_cache = desilo::fhe::PartitionsCache(&parameters);
  int ciphertext_moduli_id = 1;
  int key_moduli_id = 1;

  auto partition_parameters =
      partitions_cache.get_parameters(ciphertext_moduli_id, key_moduli_id);
  ASSERT_EQ(partition_parameters->size(), 3);

  partitions_cache.clear();

  partition_parameters =
      partitions_cache.get_parameters(ciphertext_moduli_id, key_moduli_id);
  ASSERT_EQ(partition_parameters->size(), 3);
}
