#include "ckks/core.h"

namespace desilo::fhe {

void CKKSCore::rescale_once_(Polynomial *x, Polynomial *y, int moduli_id,
                             bool include_special) {
  const auto next_moduli_id =
      parameters_.get_next_moduli_id_at_rescale(moduli_id);
  const auto next_chain_count =
      parameters_.get_chain_count(next_moduli_id, include_special);

  const auto rounder = allocate_polynomial();

  const auto x_offset = 1;

  get_rounder_(x, rounder, moduli_id);
  sub_tiled_(x, x, y, next_moduli_id, next_chain_count, x_offset);
  reduce_2q_to_q_(y, y, next_moduli_id, next_chain_count);

  mont_enter_rescale_(y, y, next_moduli_id, next_chain_count);
  add_tiled_(y, rounder, y, next_moduli_id, next_chain_count);
  reduce_2q_to_q_(y, y, next_moduli_id, next_chain_count);

  release(rounder);
}

void CKKSCore::rescale_twice_(Polynomial *x, Polynomial *y, int moduli_id,
                              bool include_special) {
  const auto next_moduli_id =
      parameters_.get_next_moduli_id_at_rescale(moduli_id);

  const auto temp = include_special
                        ? allocate_extended_polynomial(next_moduli_id)
                        : allocate_polynomial(next_moduli_id);

  rescale_once_(x, temp, moduli_id, include_special);
  rescale_once_(temp, y, next_moduli_id, include_special);

  release(temp);
}

void CKKSCore::rescale_(Polynomial *x, Polynomial *y, int moduli_id,
                        bool include_special) {

  rescale_once_(x, y, moduli_id, include_special);
}

template <class T> long double CKKSCore::get_rescaled_scale(T *input) {
  return precomputed_.get_rescaled_scale(input->ckks_scale_, input->moduli_id_);
}

template long double CKKSCore::get_rescaled_scale(UnitPlaintext *input);
template long double CKKSCore::get_rescaled_scale(UnitCiphertext *input);

template <class T> T *CKKSCore::rescale_(T *input) {
  const int level = input->level_;
  const int moduli_id = input->moduli_id_;
  const auto next_moduli_id = parameters_.get_moduli_id(level - 1);

  const DataFlag flag = input->flag_ | DataFlag::RESCALED;
  bool include_special = includes_special(flag);
  const int polynomial_count = input->polynomial_count();
  const auto rescaled_scale = get_rescaled_scale(input);

  auto rescaled =
      allocate_text<T>(flag, next_moduli_id, polynomial_count, rescaled_scale);

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {
    rescale_(get_polynomial(input, polynomial_index),
             get_polynomial(rescaled, polynomial_index), moduli_id,
             include_special);
  }

  return rescaled;
}

UnitPlaintext *CKKSCore::rescale(UnitPlaintext *plaintext) {
  return rescale_(plaintext);
}

UnitCiphertext *CKKSCore::rescale(UnitCiphertext *ciphertext) {
  UnitCiphertext *rescaled;

  if (is_ntt_form(ciphertext->flag_)) {
    const auto intt_form = to_intt_form(ciphertext);
    const auto rescaled_intt_form = rescale_(intt_form);
    release(intt_form);
    rescaled = to_ntt_form(rescaled_intt_form);
    release(rescaled_intt_form);
  } else {
    rescaled = rescale_(ciphertext);
  }

  return rescaled;
}

}
