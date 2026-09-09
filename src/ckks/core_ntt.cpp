#include "arithmetic/arithmetic.h"
#include "ckks/core.h"

namespace desilo::fhe {

void CKKSCore::spread_flexible_chain_(Polynomial *x, Polynomial *y,
                                      int ntt_moduli_id, bool copy_other_chains,
                                      int x_offset, int y_offset) {
  const auto ntt_flexible_chain_count =
      parameters_.get_ntt_flexible_chain_count(ntt_moduli_id);

  tile_unsigned_reduce_2q_to_q_(x, y, ntt_moduli_id, ntt_flexible_chain_count,
                                x_offset, y_offset);

  if (copy_other_chains) {
    const auto chain_count = y->chain_count_;
    copy(x, y, chain_count - ntt_flexible_chain_count, x_offset + 1,
         y_offset + ntt_flexible_chain_count);
  }
}

void CKKSCore::gather_flexible_chain_(Polynomial *x, Polynomial *y,
                                      int ntt_moduli_id, bool copy_other_chains,
                                      int x_offset, int y_offset) {
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(ntt_moduli_id);
  const auto coeff_count = precomputed_.coeff_count_;
  const auto ntt_flexible_chain_count =
      parameters_.get_ntt_flexible_chain_count(ntt_moduli_id);

  auto ntt_q = precomputed_.get_q(ntt_moduli_id);
  auto ntt_k = precomputed_.get_k(ntt_moduli_id);
  auto intt_q_0 = precomputed_.get_q(intt_moduli_id)[0];
  auto mask = intt_q_0 - 1;

  auto q_0_inverse_1 = modulus_invert(ntt_q[0], ntt_q[1]);
  auto q_0_inverse_2 = modulus_invert(ntt_q[0], ntt_q[2]);
  auto q_1_inverse_2 = modulus_invert(ntt_q[1], ntt_q[2]);
  auto q_0_inverse_3 = modulus_invert(ntt_q[0], ntt_q[3]);
  auto q_1_inverse_3 = modulus_invert(ntt_q[1], ntt_q[3]);
  auto q_2_inverse_3 = modulus_invert(ntt_q[2], ntt_q[3]);
  int64_t digit_1 = ntt_q[0] & mask;
  int64_t digit_2 = modulus_multiply(ntt_q[0], ntt_q[1], intt_q_0);
  int64_t digit_3 = modulus_multiply(digit_2, ntt_q[2], intt_q_0);
  std::vector<std::vector<int64_t>> q_inverse = {
      {},
      {q_0_inverse_1},
      {q_0_inverse_2, q_1_inverse_2},
      {q_0_inverse_3, q_1_inverse_3, q_2_inverse_3}};
  std::vector<int64_t> digit = {1, digit_1, digit_2, digit_3};

  int64_t ntt_coeff[ntt_flexible_chain_count];
  for (auto coeff_index = 0; coeff_index < coeff_count; coeff_index++) {
    int64_t y_value = 0;

    for (auto chain_index = 0; chain_index < ntt_flexible_chain_count;
         chain_index++) {
      ntt_coeff[chain_index] = x->get(chain_index + x_offset)[coeff_index];

      for (auto prev_chain_index = 0; prev_chain_index < chain_index;
           prev_chain_index++) {
        ntt_coeff[chain_index] = modulus_multiply(
            ntt_coeff[chain_index] - ntt_coeff[prev_chain_index],
            q_inverse[chain_index][prev_chain_index], ntt_q[chain_index]);
      }

      if (chain_index + 1 == ntt_flexible_chain_count) {
        int64_t last_ntt_q = ntt_q[chain_index];
        int64_t last_ntt_q_half = last_ntt_q >> 1;

        if (ntt_coeff[chain_index] <= -last_ntt_q_half) {
          ntt_coeff[chain_index] += last_ntt_q;
        } else if (ntt_coeff[chain_index] > last_ntt_q_half) {
          ntt_coeff[chain_index] -= last_ntt_q;
        }
      }

      y_value += modulus_multiply(ntt_coeff[chain_index], digit[chain_index],
                                  intt_q_0);
    }

    y->get(y_offset)[coeff_index] = y_value & mask;
  }

  if (copy_other_chains) {
    const auto chain_count = y->chain_count_;
    copy(x, y, chain_count - 1, x_offset + ntt_flexible_chain_count,
         y_offset + 1);
  }
}

void CKKSCore::to_ntt_(Polynomial *x, Polynomial *y, int ntt_moduli_id) {
  const auto chain_count = y->chain_count_;

  if (x->moduli_id_ != y->moduli_id_) {
    spread_flexible_chain_(x, y, ntt_moduli_id, true);
    mont_enter_(y, y, ntt_moduli_id, chain_count);
  } else {
    mont_enter_(x, y, ntt_moduli_id, chain_count);
  }

  ntt_(y, y, ntt_moduli_id, chain_count);
}

template <class T> T *CKKSCore::to_ntt_form_(T *input) {
  const auto flag = input->flag_ | DataFlag::NTT_FORM;
  const auto intt_moduli_id = input->moduli_id_;
  const auto ntt_moduli_id = parameters_.get_ntt_moduli_id(intt_moduli_id);
  const auto polynomial_count = input->polynomial_count();

  auto output = allocate_text<T>(flag, ntt_moduli_id, polynomial_count,
                                 input->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(input, polynomial_index);
    const auto y = get_polynomial(output, polynomial_index);
    to_ntt_(x, y, ntt_moduli_id);
  }

  return output;
}

UnitCiphertext *CKKSCore::to_ntt_form(UnitCiphertext *ciphertext) {
  return to_ntt_form_(ciphertext);
}

UnitPlaintext *CKKSCore::to_ntt_form(UnitPlaintext *plaintext) {
  return to_ntt_form_(plaintext);
}

void CKKSCore::to_intt_(Polynomial *x, Polynomial *y, int intt_moduli_id) {
  const auto intt_chain_count = y->chain_count_;

  if (x->moduli_id_ != y->moduli_id_) {
    const auto ntt_moduli_id = x->moduli_id_;
    const auto ntt_chain_count = x->chain_count_;

    auto z = y;
    y = allocate_polynomial_(ntt_moduli_id, ntt_chain_count, y->flag_);

    intt_(x, y, ntt_moduli_id, ntt_chain_count);
    mont_enter_exit_(y, y, ntt_moduli_id, ntt_chain_count);
    gather_flexible_chain_(y, z, ntt_moduli_id, true);

    release(y);
  } else {
    intt_(x, y, intt_moduli_id, intt_chain_count);
    mont_enter_exit_(y, y, intt_moduli_id, intt_chain_count);
  }
}

template <class T> T *CKKSCore::to_intt_form_(T *input) {
  const auto flag = input->flag_ & ~DataFlag::NTT_FORM;
  const auto ntt_moduli_id = input->moduli_id_;
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(ntt_moduli_id);
  const auto polynomial_count = input->polynomial_count();

  auto output = allocate_text<T>(flag, intt_moduli_id, polynomial_count,
                                 input->ckks_scale_);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    const auto x = get_polynomial(input, polynomial_index);
    const auto y = get_polynomial(output, polynomial_index);
    to_intt_(x, y, intt_moduli_id);
  }

  return output;
}

UnitCiphertext *CKKSCore::to_intt_form(UnitCiphertext *ciphertext) {
  return to_intt_form_(ciphertext);
}

UnitPlaintext *CKKSCore::to_intt_form(UnitPlaintext *plaintext) {
  return to_intt_form_(plaintext);
}

void CKKSCore::reset_ntt_flexible_chain_(Polynomial *x, int ntt_moduli_id) {
  const auto intt_moduli_id = parameters_.get_intt_moduli_id(ntt_moduli_id);
  const auto ntt_flexible_chain_count =
      parameters_.get_ntt_flexible_chain_count(ntt_moduli_id);

  if (intt_moduli_id == ntt_moduli_id) {

    return;
  }

  intt_(x, x, ntt_moduli_id, ntt_flexible_chain_count);
  mont_enter_exit_(x, x, ntt_moduli_id, ntt_flexible_chain_count);

  bool copy_other_chains = false;
  int x_offset = 0;
  int y_offset = ntt_flexible_chain_count - 1;
  gather_flexible_chain_(x, x, ntt_moduli_id, copy_other_chains, x_offset,
                         y_offset);
  spread_flexible_chain_(x, x, ntt_moduli_id, copy_other_chains, y_offset,
                         x_offset);

  mont_enter_(x, x, ntt_moduli_id, ntt_flexible_chain_count);
  ntt_(x, x, ntt_moduli_id, ntt_flexible_chain_count);
}

}
