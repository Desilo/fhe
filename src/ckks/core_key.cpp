#include "ckks/encode.h"
#include "ckks/engine.h"
#include "montgomery/unit.h"

#include <algorithm>

namespace desilo::fhe {

SecretKey *CKKSCore::create_secret_key(int level) {
  const int intt_moduli_id = to_key_moduli_id(level);
  const int ntt_moduli_id = to_key_ntt_moduli_id(level);

  const DataFlag flag = DataFlag::NTT_FORM | DataFlag::INCLUDE_SPECIAL;
  const int polynomial_count = 1;
  auto secret_key =
      allocate_data<SecretKey>(flag, ntt_moduli_id, polynomial_count);

  const auto uniform_ternary = get_ternary();
  const auto key = get_polynomial(secret_key, 0);

  tile_unsigned_reduce_2q_to_q_(uniform_ternary, key, ntt_moduli_id,
                                key->chain_count_);
  to_ntt_(key, key, ntt_moduli_id);

  release(uniform_ternary);

  return secret_key;
}

SecretKey *CKKSCore::create_secret_key(std::vector<int64_t> &secret,
                                       int level) {
  const int moduli_id = to_moduli_id(level);

  const DataFlag flag = DataFlag::NTT_FORM | DataFlag::INCLUDE_SPECIAL;
  const int polynomial_count = 1;
  auto secret_key = allocate_data<SecretKey>(flag, moduli_id, polynomial_count);
  const auto chain_count = secret_key->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;

  const auto secret_polynomial = allocate_polynomial();
  const auto key = get_polynomial(secret_key, 0);

  copy_single_chain_to_polynomial(secret.data(), secret_polynomial);
  tile_unsigned_reduce_2q_to_q_(secret_polynomial, key, moduli_id, chain_count);
  mont_enter_(key, key, moduli_id, chain_count);
  ntt_(key, key, moduli_id, chain_count);

  release(secret_polynomial);

  return secret_key;
}

SecretKey *CKKSCore::create_sparse_secret_key(int hamming_weight, int level) {
  if (hamming_weight > precomputed_.coeff_count_) {
    throw std::runtime_error("Create Sparse Secret Key: the given hamming "
                             "weight is bigger than the coefficient count.");
  }

  const int moduli_id = to_moduli_id(level);

  const DataFlag flag =
      DataFlag::NTT_FORM | DataFlag::SPARSE | DataFlag::INCLUDE_SPECIAL;
  const int polynomial_count = 1;
  auto secret_key = allocate_data<SecretKey>(flag, moduli_id, polynomial_count);
  const auto chain_count = secret_key->chain_count_;

  const auto sparse_ternary = get_sparse_ternary(hamming_weight);
  const auto key = get_polynomial(secret_key, 0);

  tile_unsigned_reduce_2q_to_q_(sparse_ternary, key, moduli_id, chain_count);
  mont_enter_(key, key, moduli_id, chain_count);
  ntt_(key, key, moduli_id, chain_count);

  release(sparse_ternary);

  return secret_key;
}

PublicKey *CKKSCore::create_public_key(SecretKey *secret_key, int level) {
  const int polynomial_count = 2;
  PublicKey *public_key;

  const auto single_error = get_single_error();

  const int moduli_id = to_moduli_id(level);

  public_key =
      allocate_data<PublicKey>(DataFlag::NTT_FORM, moduli_id, polynomial_count);

  const auto secret_key0 = get_polynomial_view(secret_key, 0, moduli_id);
  const auto [b, a] = get_duo_polynomials(public_key);

  const auto error = allocate_polynomial(moduli_id);

  tile_unsigned_reduce_2q_to_q_(single_error, error, moduli_id);
  to_ntt_(error, error, moduli_id);

  assign_a(a, moduli_id);

  mont_mult_(a, secret_key0, b, moduli_id);
  mont_sub_reduce_2q_to_q_(error, b, b, moduli_id);

  release(secret_key0);
  release(error);

  release(single_error);

  return public_key;
}

KeySwitchingKey *CKKSCore::create_key_switching_key(SecretKey *secret_key_from,
                                                    SecretKey *secret_key_to,
                                                    int level) {
  const auto coeff_count = precomputed_.coeff_count_;
  const auto include_special = true;
  DataFlag flag = DataFlag::NTT_FORM | DataFlag::INCLUDE_SPECIAL;

  const int moduli_id = to_moduli_id(level);
  auto p_product_mult_r = precomputed_.get_p_product_mult_r(moduli_id);
  const int prime_count = get_prime_count(moduli_id);
  const int chain_count = get_chain_count(moduli_id);
  const auto partitions = get_partitions(moduli_id);

  const auto p_mult_secret_key_from = allocate_polynomial(moduli_id);
  const int secret_key_from_offset =
      get_chain_offset(secret_key_from->moduli_id_, moduli_id);

  mont_enter_(get_polynomial(secret_key_from, 0), p_mult_secret_key_from,
              p_product_mult_r, moduli_id, chain_count, secret_key_from_offset);

  const auto secret_key_to0 = get_polynomial_view(secret_key_to, 0, moduli_id);

  auto key_switching_key =
      allocate_data<KeySwitchingKey>(flag, moduli_id, partitions.size() * 2);

  for (size_t partition_index = 0; partition_index < partitions.size();
       partition_index++) {
    const auto &partition = partitions[partition_index];

    const auto key_index = partition_index * 2;
    const auto b = get_polynomial(key_switching_key, key_index);
    const auto a = get_polynomial(key_switching_key, key_index + 1);

    const auto single_error = get_single_error();
    const auto error = allocate_extended_polynomial(moduli_id);

    tile_unsigned_reduce_2q_to_q_(single_error, error, moduli_id, prime_count);
    to_ntt_(error, error, moduli_id);

    assign_a(a, moduli_id, include_special);

    mont_mult_(a, secret_key_to0, b, moduli_id, prime_count, 0, 0);
    mont_sub_reduce_2q_to_q_(error, b, b, moduli_id, prime_count);

    release(single_error);
    release(error);

    const int p_mult_secret_key_from_offset = partition.start_;
    const int b_offset = partition.start_;

    mont_add_reduce_2q_to_q_from_(
        p_mult_secret_key_from, b, b, moduli_id, partition.start_,
        partition.size_, p_mult_secret_key_from_offset, b_offset, b_offset);
  }

  release(p_mult_secret_key_from);
  release(secret_key_to0);

  return key_switching_key;
}

RelinearizationKey *CKKSCore::create_relinearization_key(SecretKey *secret_key,
                                                         int level) {
  const int chain_count = secret_key->chain_count_;

  const int polynomial_count = 1;
  const int moduli_id = secret_key->moduli_id_;
  auto squared_key =
      allocate_data<SecretKey>(secret_key->flag_, moduli_id, polynomial_count);

  const auto secret_key0 = get_polynomial(secret_key, 0);
  const auto squared_key0 = get_polynomial(squared_key, 0);

  const int secret_key_offset = 0;
  mont_mult_(secret_key0, secret_key0, squared_key0, moduli_id, chain_count,
             secret_key_offset, secret_key_offset);

  auto relinearization_key = new RelinearizationKey(
      create_key_switching_key(squared_key, secret_key, level));

  release(squared_key);

  return relinearization_key;
}

template <class T>
std::tuple<T *, PermutationParameters *, PermutationParameters *>
CKKSCore::rotate(T *key, int delta, bool invert_delta) {
  const int chain_count = key->chain_count_;
  const int coeff_count = key->coeff_count_;
  const auto coeff_count_half = coeff_count / 2;
  const int moduli_id = key->moduli_id_;

  auto [right_permutation, right_sign] =
      precomputed_.make_permutation_parameters(delta);
  auto rotation_delta = invert_delta ? coeff_count_half - delta : delta;
  auto ntt_permutation =
      precomputed_.make_ntt_permutation_parameters(rotation_delta);

  const auto ntt_permutation_values = ntt_permutation->get();

  const int polynomial_count = key->polynomial_count();
  auto rotated_key = allocate_data<T>(key->flag_, moduli_id, polynomial_count);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    auto key_data = get_polynomial(key, polynomial_index);
    auto rotated_key_data = get_polynomial(rotated_key, polynomial_index);

    permute_polynomial_(key_data, rotated_key_data, ntt_permutation_values,
                        chain_count, coeff_count);
  }

  release(ntt_permutation);

  return std::make_tuple(rotated_key, right_permutation, right_sign);
}

FixedRotationKey *CKKSCore::create_fixed_rotation_key(SecretKey *secret_key,
                                                      int level, int delta) {
  bool invert_delta = true;
  auto [left_rotated_secret_key, right_permutation, right_sign] =
      rotate(secret_key, delta, invert_delta);

  auto fixed_rotation_key = new FixedRotationKey(
      create_key_switching_key(secret_key, left_rotated_secret_key, level),
      right_permutation, right_sign, delta);

  release(left_rotated_secret_key);

  return fixed_rotation_key;
}

ConjugationKey *CKKSCore::create_conjugation_key(SecretKey *secret_key,
                                                 int level) {
  const auto delta = -1;
  auto [conjugated_key, permutation, sign] = rotate(secret_key, delta);

  auto conjugation_key = new ConjugationKey(
      create_key_switching_key(conjugated_key, secret_key, level), permutation,
      sign);

  release(conjugated_key);

  return conjugation_key;
}

RotationKey *CKKSCore::create_rotation_key(SecretKey *secret_key, int level) {
  const auto coeff_count = precomputed_.coeff_count_;
  const auto half_coeff_count = coeff_count / 2;
  std::vector<FixedRotationKey *> keys;

  for (int delta = 1; delta < half_coeff_count; delta <<= 1) {
    keys.push_back(create_fixed_rotation_key(secret_key, level, delta));
  }

  return new RotationKey(keys);
}

}
