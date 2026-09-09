#include <cstdint>
#include <vector>

#include "arithmetic/big_int.h"

#pragma once

namespace desilo::fhe {

int64_t modulus_invert(int64_t x, int64_t modulus);
template <typename T> T modulus_power(T base, T exponent, T modulus);
int64_t modulus_multiply(int64_t x1, int64_t x2, int64_t modulus);
void scale_modulo(int64_t *output, double value, double scale, double deviation,
                  const uint64_t *q, int chain_count);
void scale_enter_modulo(int64_t *output, double value, double scale,
                        double deviation, int64_t r, const uint64_t *q,
                        int chain_count);
int64_t find_root(int64_t prime, int coeff_count);
int64_t find_cyclic_root(int64_t prime, int root_count);
int64_t find_generator(int64_t prime);
std::vector<int64_t> get_power_series(int64_t root, int64_t prime,
                                      int coeff_count);
uint64_t calculate_k(int64_t r, int64_t modulus);
void rns_to_double(int64_t **x, double *y, const uint64_t *q, BigInt q_product,
                   BigInt q_product_half, const BigInt *rns_reverser,
                   uint64_t r_minus_k_product, int chain_count, int coeff_count,
                   int coeff_start, int coeff_end);
void rns_to_double_with_power_of_two(int64_t **x, double *y, const uint64_t *q,
                                     BigInt q_product,
                                     const BigInt *rns_reverser,
                                     uint64_t r_minus_k_product,
                                     int chain_count, int coeff_count,
                                     int coeff_start, int coeff_end);
void double_to_rns(double *x, int64_t **y, const uint64_t *q, int chain_count,
                   int coeff_count, int coeff_start, int coeff_end);
template <typename T> T positive_modulo(T x, T modulus);

}
