#include <tuple>
#include <vector>

#include "arithmetic/type.h"

#pragma once

namespace desilo::fhe {

bool is_prime(uint64_t number);
bool is_ntt_prime(uint64_t search_start, uint64_t ntt_prime_modulus);
int jacobi_symbol(int64_t input, uint64_t modulus);
bool lucas_probable_prime_test(uint64_t number);
bool miller_rabin_test(uint64_t number, uint64_t base);

#ifdef DESILO_FHE_CHECK_HARDCODED
std::vector<uint64_t> make_alternating_primes(int message_bit,
                                              int ntt_prime_modulus,
                                              int prime_count);
#endif
std::vector<uint64_t> make_alternating_primes_2(int message_bit,
                                                int ntt_prime_modulus,
                                                int prime_count);
std::vector<uint64_t>
make_decreasing_primes(int message_bit, int ntt_prime_modulus, int prime_count);

std::tuple<uint64_t *, int> get_cached_small_primes(int coeff_count);
std::tuple<uint64_t *, int> get_cached_bootstrap_primes(int coeff_count);
std::tuple<uint64_t *, int> get_cached_large_primes(int coeff_count);

std::vector<uint64_t> get_small_primes(int coeff_count, int prime_count);
std::vector<uint64_t> get_bootstrap_primes(int coeff_count, int prime_count);
std::vector<uint64_t> get_large_primes(int coeff_count, int prime_count);

}
