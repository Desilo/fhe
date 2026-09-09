#include "parameter/decode.h"

namespace desilo::fhe {

DecodeParameters::DecodeParameters(const uint64_t *q, const uint64_t *k,
                                   const int64_t r, int chain_count) {
  int chain_start = 0;

  if ((q[0] & 1) == 0) {
    chain_start++;
  }

  q_product_ = BigInt(UINT64_C(1));
  for (int chain_index = chain_start; chain_index < chain_count;
       chain_index++) {
    q_product_ *= q[chain_index];
  }

  q_product_half_ = q_product_ / 2;

  for (int chain_index = chain_start; chain_index < chain_count;
       chain_index++) {
    const auto chain_q = q[chain_index];
    auto q_product_divided_by_q = q_product_ / chain_q;

    uint64_t inverse_of_q_product_divided_by_q = 1;
    for (int inverse_index = chain_start; inverse_index < chain_count;
         inverse_index++) {
      if (inverse_index == chain_index) {
        continue;
      }

      const auto q_inverse = modulus_invert(q[inverse_index], chain_q);

      inverse_of_q_product_divided_by_q = modulus_multiply(
          inverse_of_q_product_divided_by_q, q_inverse, chain_q);
    }

    rns_reverser_.push_back(q_product_divided_by_q *
                            inverse_of_q_product_divided_by_q);
  }

  uint64_t r_minus_k_product = 1;
  for (int chain_index = chain_start; chain_index < chain_count;
       chain_index++) {
    const auto chain_k = k[chain_index];
    r_minus_k_product = modulus_multiply(r_minus_k_product, r - chain_k, r);
  }

  r_minus_k_product_ = r - r_minus_k_product;
};

}
