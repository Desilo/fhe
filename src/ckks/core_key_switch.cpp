#include "ckks/engine.h"
#include "montgomery/compound.h"
#include "montgomery/unit.h"
#include "operation/ntt.h"

namespace desilo::fhe {

std::vector<Partition> &CKKSCore::get_partitions(int ciphertext_moduli_id,
                                                 int key_moduli_id) {
  return partitions_cache_.get(ciphertext_moduli_id, key_moduli_id);
}

std::vector<CKKSPartitionParameters> *
CKKSCore::get_partition_parameters(int ciphertext_moduli_id,
                                   int key_moduli_id) {
  return partitions_cache_.get_parameters(ciphertext_moduli_id, key_moduli_id);
}

#define INVALID_CKKS_SCALE 0.L

void CKKSCore::rns_to_mrs(Polynomial *x, Polynomial *y,
                          const Partition *partition,
                          CKKSPartitionParameters &parameter, int moduli_id) {
  const auto partition_start = partition->start_;
  const auto partition_size = partition->size_;
  const int x_offset = partition_start;

  for (int chain_index = 0; chain_index < partition_size; chain_index++) {
    const int y_offset = chain_index;
    copy(x, y, 1, x_offset, y_offset);
  }

  for (int chain_index = 0; chain_index < partition_size - 1; chain_index++) {
    const auto y_offset = chain_index + 1;
    const auto x_offset = (*partition)[y_offset];
    const auto chain_count = 1;
    const auto chain_start = x_offset;

    auto q_product_inverse_mult_r =
        parameter.get_q_product_inverse_mult_r(chain_index);

    mont_sub_enter_reduce_2q_to_q_from_(x, y, y, q_product_inverse_mult_r,
                                        moduli_id, chain_start, chain_count,
                                        x_offset, y_offset, y_offset);

    if (chain_index + 2 < partition_size) {
      auto q_product_mult_r = parameter.get_q_product_mult_r(chain_index);
      const auto chain_count = partition_size - (chain_index + 2);

      const auto chain_start = (*partition)[y_offset + 1];
      mont_enter_tiled_add_reduce_2q_to_q_from_(
          y, y, q_product_mult_r, moduli_id, chain_start, chain_count, y_offset,
          y_offset + 1);
    }
  }
}

void CKKSCore::mod_up_single(Polynomial *x_ntt, Polynomial *x_intt,
                             Polynomial *y, int partition_start, int moduli_id,
                             int chain_count) {
  const int x_offset = partition_start;

  if (partition_start > 0) {
    mont_enter_tiled_(x_intt, y, moduli_id, partition_start, x_offset);
    ntt_(y, y, moduli_id, partition_start);
  }

  const int y_offset = partition_start;
  copy(x_ntt, y, 1, x_offset, y_offset);

  const auto partition_end = partition_start + 1;
  const auto trailing_chain_count = chain_count - partition_end;
  if (trailing_chain_count > 0) {
    const int y_offset = partition_end;
    mont_enter_tiled_from_(x_intt, y, moduli_id, partition_end,
                           trailing_chain_count, x_offset, y_offset);
    ntt_from_(y, y, moduli_id, partition_end, trailing_chain_count, y_offset,
              y_offset);
  }
}

void CKKSCore::mod_up_single(Polynomial *x, Polynomial *y, int partition_start,
                             int key_moduli_id) {
  const auto key_ntt_moduli_id = parameters_.get_ntt_moduli_id(key_moduli_id);
  const auto key_ntt_chain_count = get_prime_count(key_ntt_moduli_id);
  int x_offset = partition_start;

  mont_enter_tiled_(x, y, key_ntt_moduli_id, key_ntt_chain_count, x_offset);
  ntt_(y, y, key_ntt_moduli_id, key_ntt_chain_count);
}

void CKKSCore::mod_up(Polynomial *x, Polynomial *y, int partition_start,
                      int partition_size, CKKSPartitionParameters &parameter,
                      int key_moduli_id) {
  const auto key_ntt_moduli_id = parameters_.get_ntt_moduli_id(key_moduli_id);
  const auto key_ntt_chain_count = get_prime_count(key_ntt_moduli_id);

  mont_enter_tiled_(x, y, key_ntt_moduli_id, key_ntt_chain_count);

  for (auto chain_index = 0; chain_index < partition_size - 1; chain_index++) {
    auto q_product_mult_r_squared =
        parameter.get_q_product_mult_r_squared(chain_index);
    const auto x_offset = chain_index + 1;
    mont_enter_tiled_add_(x, y, q_product_mult_r_squared, key_ntt_moduli_id,
                          key_ntt_chain_count, x_offset);
  }
  ntt_(y, y, key_ntt_moduli_id, key_ntt_chain_count);
}

void CKKSCore::mod_down(Polynomial *x, Polynomial *y,
                        std::vector<const int64_t *> &p_inverse_mult_r,
                        bool can_modify_x) {
  const auto ntt_moduli_id = x->moduli_id_;
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(ntt_moduli_id);
  Polynomial *x_intt = x;

  if (!can_modify_x || ntt_moduli_id != intt_moduli_id) {
    x_intt = allocate_extended_polynomial(intt_moduli_id);
  }

  to_intt_(x, x_intt, intt_moduli_id);
  reduce_2q_to_q_(x_intt, x_intt, intt_moduli_id, x_intt->chain_count_);

  auto reduced_chain_count = x_intt->chain_count_;
  const auto coeff_count = precomputed_.coeff_count_;
  const auto special_prime_count = precomputed_.special_prime_count_;

  for (int special_prime_index = 0; special_prime_index < special_prime_count;
       special_prime_index++) {
    reduced_chain_count--;
    const int x2_offset = reduced_chain_count;

    if (parameters_.has_flexible_chain(intt_moduli_id)) {

      const auto q0 = precomputed_.get_q(intt_moduli_id)[0];
      const auto q0_double = q0 << 1;
      for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
        const auto diff =
            guard(x_intt->get(0)[coeff_index] + q0_double -
                      x_intt->get(reduced_chain_count)[coeff_index],
                  q0_double);
        x_intt->get(0)[coeff_index] = modulus_multiply(
            diff, p_inverse_mult_r[special_prime_index][0], q0);
      }
      mont_sub_tiled_enter_(
          x_intt, x_intt, x_intt, p_inverse_mult_r[special_prime_index],
          intt_moduli_id, reduced_chain_count - 1, 1, x2_offset, 1, 1);
    } else {
      mont_sub_tiled_enter_(x_intt, x_intt, x_intt,
                            p_inverse_mult_r[special_prime_index],
                            intt_moduli_id, reduced_chain_count, 0, x2_offset);
    }
  }

  make_unsigned_reduce_2q_to_q_(x_intt, y, intt_moduli_id, reduced_chain_count);

  if (x != x_intt) {
    release(x_intt);
  }
}

KeySwitcher *CKKSCore::create_key_switcher_single(
    Polynomial *x_ntt, Polynomial *x_intt, KeySwitchingKey *key,
    std::vector<Partition> &partitions, int moduli_id,
    std::vector<const int64_t *> &p_inverse_mult_r, int chain_count) {

  const auto x0 = allocate_extended_polynomial(moduli_id);
  const auto x1 = allocate_extended_polynomial(moduli_id);
  const auto extended = allocate_extended_polynomial(moduli_id);

  const auto partition = &partitions[0];

  mod_up_single(x_ntt, x_intt, extended, partition->start_, moduli_id,
                chain_count);

  const auto key0 =
      get_polynomial_view(key, key->get_key_index(partition, 0), moduli_id);
  const auto key1 =
      get_polynomial_view(key, key->get_key_index(partition, 1), moduli_id);

  mont_mult_(extended, key0, x0, moduli_id, chain_count, 0, 0);
  mont_mult_(extended, key1, x1, moduli_id, chain_count, 0, 0);

  release(key0);
  release(key1);

  for (int partition_index = 1; partition_index < partitions.size();
       partition_index++) {
    const auto partition = &partitions[partition_index];
    mod_up_single(x_ntt, x_intt, extended, partition->start_, moduli_id,
                  chain_count);

    const auto key0 =
        get_polynomial_view(key, key->get_key_index(partition, 0), moduli_id);
    const auto key1 =
        get_polynomial_view(key, key->get_key_index(partition, 1), moduli_id);

    mont_mult_add_(extended, key0, x0, moduli_id, chain_count, 0, 0);
    mont_mult_add_(extended, key1, x1, moduli_id, chain_count, 0, 0);
    reduce_2q_to_q_(x0, x0, moduli_id, chain_count);
    reduce_2q_to_q_(x1, x1, moduli_id, chain_count);

    release(key0);
    release(key1);
  }

  const int polynomial_count = 2;
  auto key_switcher =
      allocate_data<KeySwitcher>(DataFlag::NONE, moduli_id, polynomial_count);

  const auto y0 = get_polynomial(key_switcher, 0);
  const auto y1 = get_polynomial(key_switcher, 1);
  const auto can_modify_x = true;

  mod_down(x0, y0, p_inverse_mult_r, can_modify_x);
  mod_down(x1, y1, p_inverse_mult_r, can_modify_x);

  release(x0);
  release(x1);
  release(extended);

  return key_switcher;
}

KeySwitcher *CKKSCore::create_key_switcher_single(
    Polynomial *x, KeySwitchingKey *key, std::vector<Partition> &partitions,
    int key_moduli_id, std::vector<const int64_t *> &p_inverse_mult_r) {
  const auto key_ntt_moduli_id = parameters_.get_ntt_moduli_id(key_moduli_id);
  const auto key_ntt_chain_count = get_prime_count(key_ntt_moduli_id);

  const auto x0 = allocate_extended_polynomial(key_ntt_moduli_id);
  const auto x1 = allocate_extended_polynomial(key_ntt_moduli_id);
  const auto extended = allocate_extended_polynomial(key_ntt_moduli_id);
  const int extended_offset = 0;

  const auto partition = &partitions[0];

  mod_up_single(x, extended, partition->start_, key_moduli_id);

  PolynomialView *key0, *key1;
  key0 = get_polynomial_view(key, key->get_key_index(partition, 0),
                             key_ntt_moduli_id);
  key1 = get_polynomial_view(key, key->get_key_index(partition, 1),
                             key_ntt_moduli_id);

  mont_mult_(extended, key0, x0, key_ntt_moduli_id, key_ntt_chain_count, 0, 0);
  mont_mult_(extended, key1, x1, key_ntt_moduli_id, key_ntt_chain_count, 0, 0);

  release(key0);
  release(key1);

  for (int partition_index = 1; partition_index < partitions.size();
       partition_index++) {
    const auto partition = &partitions[partition_index];

    const auto local_extended = allocate_extended_polynomial(key_ntt_moduli_id);

    mod_up_single(x, local_extended, partition->start_, key_moduli_id);

    key0 = get_polynomial_view(key, key->get_key_index(partition, 0),
                               key_ntt_moduli_id);
    key1 = get_polynomial_view(key, key->get_key_index(partition, 1),
                               key_ntt_moduli_id);
    mont_mult_add_(local_extended, key0, x0, key_ntt_moduli_id,
                   key_ntt_chain_count, 0, 0);
    mont_mult_add_(local_extended, key1, x1, key_ntt_moduli_id,
                   key_ntt_chain_count, 0, 0);
    reduce_2q_to_q_(x0, x0, key_ntt_moduli_id, key_ntt_chain_count);
    reduce_2q_to_q_(x1, x1, key_ntt_moduli_id, key_ntt_chain_count);

    release(local_extended);
    release(key0);
    release(key1);
  }

  const int polynomial_count = 2;
  auto key_switcher = allocate_data<KeySwitcher>(DataFlag::NONE, key_moduli_id,
                                                 polynomial_count);

  const auto [y0, y1] = get_duo_polynomials(key_switcher);
  const auto can_modify_x = true;

  mod_down(x0, y0, p_inverse_mult_r, can_modify_x);
  mod_down(x1, y1, p_inverse_mult_r, can_modify_x);

  release(x0);
  release(x1);
  release(extended);

  return key_switcher;
}

KeySwitcher *CKKSCore::create_key_switcher(
    Polynomial *x, KeySwitchingKey *key, std::vector<Partition> &partitions,
    int key_moduli_id, std::vector<const int64_t *> &p_inverse_mult_r,
    int chain_count,
    std::vector<CKKSPartitionParameters> *partition_parameters) {
  const auto key_ntt_moduli_id = parameters_.get_ntt_moduli_id(key_moduli_id);
  const auto key_ntt_chain_count = get_prime_count(key_ntt_moduli_id);

  const auto x0 = allocate_extended_polynomial(key_ntt_moduli_id);
  const auto x1 = allocate_extended_polynomial(key_ntt_moduli_id);
  const int extended_offset = 0;

  for (int partition_index = 0; partition_index < partitions.size();
       partition_index++) {

    const auto partition = &partitions[partition_index];
    auto &parameter = partition_parameters->at(partition_index);

    const auto mrs_polynomial = allocate_mrs_polynomial();
    const auto extended = allocate_extended_polynomial(key_ntt_moduli_id);

    rns_to_mrs(x, mrs_polynomial, partition, parameter, key_moduli_id);
    mod_up(mrs_polynomial, extended, partition->start_, partition->size_,
           parameter, key_moduli_id);

    PolynomialView *key0, *key1;
    key0 = get_polynomial_view(key, key->get_key_index(partition, 0),
                               key_ntt_moduli_id);
    key1 = get_polynomial_view(key, key->get_key_index(partition, 1),
                               key_ntt_moduli_id);

    if (partition_index == 0) {
      mont_mult_(extended, key0, x0, key_ntt_moduli_id, key_ntt_chain_count, 0,
                 0);
      mont_mult_(extended, key1, x1, key_ntt_moduli_id, key_ntt_chain_count, 0,
                 0);
    } else {
      mont_mult_add_(extended, key0, x0, key_ntt_moduli_id, key_ntt_chain_count,
                     0, 0);
      mont_mult_add_(extended, key1, x1, key_ntt_moduli_id, key_ntt_chain_count,
                     0, 0);
      reduce_2q_to_q_(x0, x0, key_ntt_moduli_id, key_ntt_chain_count);
      reduce_2q_to_q_(x1, x1, key_ntt_moduli_id, key_ntt_chain_count);
    }

    release(mrs_polynomial);
    release(extended);
    release(key0);
    release(key1);
  }

  const int polynomial_count = 2;
  auto key_switcher = allocate_data<KeySwitcher>(DataFlag::NONE, key_moduli_id,
                                                 polynomial_count);

  const auto [y0, y1] = get_duo_polynomials(key_switcher);

  bool can_modify_x = true;
  mod_down(x0, y0, p_inverse_mult_r, can_modify_x);
  mod_down(x1, y1, p_inverse_mult_r, can_modify_x);

  release(x0);
  release(x1);

  return key_switcher;
}

KeySwitcher *CKKSCore::create_key_switcher_single_from_ntt(
    Polynomial *x_ntt, KeySwitchingKey *key_switching_key, int moduli_id) {
  const auto x_intt = allocate_polynomial(moduli_id);

  to_intt_(x_ntt, x_intt, moduli_id);

  auto p_inverse_mult_r = precomputed_.get_p_inverse_mult_r(moduli_id);
  auto partitions = get_partitions(moduli_id, key_switching_key->moduli_id_);

  KeySwitcher *key_switcher;

  const auto prime_count = get_prime_count(moduli_id);
  key_switcher =
      create_key_switcher_single(x_ntt, x_intt, key_switching_key, partitions,
                                 moduli_id, p_inverse_mult_r, prime_count);

  release(x_intt);

  return key_switcher;
}

KeySwitcher *CKKSCore::create_key_switcher_single_from_key(
    Polynomial *x_key, KeySwitchingKey *key_switching_key, int key_moduli_id) {
  auto p_inverse_mult_r = precomputed_.get_p_inverse_mult_r(key_moduli_id);
  auto partitions =
      get_partitions(key_moduli_id, key_switching_key->moduli_id_);

  const auto key_switcher = create_key_switcher_single(
      x_key, key_switching_key, partitions, key_moduli_id, p_inverse_mult_r);

  return key_switcher;
}

KeySwitcher *CKKSCore::create_key_switcher_from_ntt(
    Polynomial *x_ntt, KeySwitchingKey *key_switch_key, int ntt_moduli_id) {
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(ntt_moduli_id);
  const auto special_prime_count = precomputed_.special_prime_count_;

  const auto x_intt = allocate_polynomial(intt_moduli_id);

  to_intt_(x_ntt, x_intt, intt_moduli_id);

  const auto key_switcher =
      create_key_switcher_from_intt(x_intt, key_switch_key, intt_moduli_id);

  release(x_intt);

  return key_switcher;
}

KeySwitcher *CKKSCore::create_key_switcher_from_intt(
    Polynomial *x_intt, KeySwitchingKey *key_switch_key, int intt_moduli_id) {
  const auto special_prime_count = precomputed_.special_prime_count_;

  KeySwitcher *key_switcher = nullptr;

  if (special_prime_count == 1) {
    key_switcher = create_key_switcher_single_from_key(x_intt, key_switch_key,
                                                       intt_moduli_id);
  } else {
    auto p_inverse_mult_r = precomputed_.get_p_inverse_mult_r(intt_moduli_id);
    auto key_switch_key_moduli_id = key_switch_key->moduli_id_;
    auto partitions = get_partitions(intt_moduli_id, key_switch_key_moduli_id);
    auto partition_parameters =
        get_partition_parameters(intt_moduli_id, key_switch_key_moduli_id);

    key_switcher = create_key_switcher(
        x_intt, key_switch_key, partitions, intt_moduli_id, p_inverse_mult_r,
        get_prime_count(intt_moduli_id), partition_parameters);
  }

  return key_switcher;
}

DecomposedUnitCiphertext *CKKSCore::decompose(UnitCiphertext *ciphertext) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto special_prime_count = precomputed_.special_prime_count_;
  const auto x = get_polynomial(ciphertext, 1);

  auto partitions = get_partitions(moduli_id);
  auto partition_parameters = get_partition_parameters(moduli_id, moduli_id);

  const auto flag =
      ciphertext->flag_ | DataFlag::NTT_FORM | DataFlag::INCLUDE_SPECIAL;
  const auto decomposed = allocate_data<DecomposedUnitCiphertext>(
      flag, moduli_id, partitions.size());
  const auto chain_count = decomposed->chain_count_;

  for (int partition_index = 0; partition_index < partitions.size();
       partition_index++) {

    const auto partition = &partitions[partition_index];
    auto &parameter = partition_parameters->at(partition_index);

    const auto mrs_polynomial = allocate_mrs_polynomial();
    const auto extended = get_polynomial(decomposed, partition_index);

    rns_to_mrs(x, mrs_polynomial, partition, parameter, moduli_id);
    mod_up(mrs_polynomial, extended, partition->start_, partition->size_,
           parameter, moduli_id);

    release(mrs_polynomial);
  }

  return decomposed;
}

DecomposedUnitCiphertext *
CKKSCore::mod_down_then_decompose(UnitCiphertext *ciphertext) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto special_prime_count = precomputed_.special_prime_count_;

  auto partitions = get_partitions(moduli_id);
  auto partition_parameters = get_partition_parameters(moduli_id, moduli_id);

  const auto flag = ciphertext->flag_;
  const auto decomposed = allocate_data<DecomposedUnitCiphertext>(
      flag, moduli_id, partitions.size());
  const auto chain_count = decomposed->chain_count_;

  const auto x = get_polynomial(ciphertext, 1);
  const auto reduced_ciphertext = allocate_polynomial(moduli_id);
  auto p_inverse_mult_r = precomputed_.get_p_inverse_mult_r(moduli_id);

  bool can_modify_x = false;
  mod_down(x, reduced_ciphertext, p_inverse_mult_r, can_modify_x);

  for (int partition_index = 0; partition_index < partitions.size();
       partition_index++) {

    const auto partition = &partitions[partition_index];
    auto &parameter = partition_parameters->at(partition_index);

    const auto mrs_polynomial = allocate_mrs_polynomial();
    const auto extended = get_polynomial(decomposed, partition_index);

    rns_to_mrs(reduced_ciphertext, mrs_polynomial, partition, parameter,
               moduli_id);
    mod_up(mrs_polynomial, extended, partition->start_, partition->size_,
           parameter, moduli_id);

    release(mrs_polynomial);
  }

  release(reduced_ciphertext);

  return decomposed;
}

KeySwitcher *
CKKSCore::create_key_switcher(DecomposedUnitCiphertext *decomposed_ciphertext,
                              KeySwitchingKey *key) {
  const auto moduli_id = decomposed_ciphertext->moduli_id_;
  const auto polynomial_count = 2;
  const auto key_switcher = allocate_data<KeySwitcher>(
      decomposed_ciphertext->flag_, moduli_id, polynomial_count);
  const auto chain_count = key_switcher->chain_count_;

  const auto [y0, y1] = get_duo_polynomials(key_switcher);

  auto partitions = get_partitions(moduli_id, key->moduli_id_);
  for (int partition_index = 0; partition_index < partitions.size();
       partition_index++) {

    const auto partition = &partitions[partition_index];

    const auto extended =
        get_polynomial(decomposed_ciphertext, partition_index);
    const auto key0 =
        get_polynomial_view(key, key->get_key_index(partition, 0), moduli_id);
    const auto key1 =
        get_polynomial_view(key, key->get_key_index(partition, 1), moduli_id);

    if (partition_index == 0) {
      mont_mult_(extended, key0, y0, moduli_id, chain_count, 0, 0);
      mont_mult_(extended, key1, y1, moduli_id, chain_count, 0, 0);
    } else {
      mont_mult_add_(extended, key0, y0, moduli_id, chain_count, 0, 0);
      mont_mult_add_(extended, key1, y1, moduli_id, chain_count, 0, 0);
      reduce_2q_to_q_(y0, y0, moduli_id, chain_count);
      reduce_2q_to_q_(y1, y1, moduli_id, chain_count);
    }

    release(key0);
    release(key1);
  }

  return key_switcher;
}

KeySwitcher *CKKSCore::create_key_switcher_for_rotate(
    UnitCiphertext *ciphertext, DecomposedUnitCiphertext *decomposed_ciphertext,
    const FixedRotationKey *fixed_rotation_key) {
  const auto moduli_id = ciphertext->moduli_id_;
  const auto chain_count = get_chain_count(moduli_id);

  const auto b = get_polynomial(ciphertext, 0);
  const auto b_mult_p = allocate_polynomial(moduli_id);

  auto p_product_mult_r = precomputed_.get_p_product_mult_r(moduli_id);

  mont_enter_(b, b_mult_p, p_product_mult_r, moduli_id, chain_count);

  const auto key_switcher = create_key_switcher(
      decomposed_ciphertext, fixed_rotation_key->key_switching_key_);

  const auto y0 = get_polynomial(key_switcher, 0);

  mont_enter_(b_mult_p, b_mult_p, moduli_id);
  ntt_(b_mult_p, b_mult_p, moduli_id);
  mont_add_reduce_2q_to_q_(y0, b_mult_p, y0, moduli_id);

  release(b_mult_p);

  return key_switcher;
}

}
