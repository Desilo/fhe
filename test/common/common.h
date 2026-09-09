#include <complex>
#include <string>
#include <vector>

#include "ckks/config.h"
#include "data/data.h"

#pragma once

#define MAKE_POLYNOMIAL(...)                                                   \
  ({                                                                           \
    int64_t flat[chain_count * coeff_count]{__VA_ARGS__};                      \
    std::vector<int64_t *> chains(chain_count);                                \
    for (int chain_index = 0; chain_index < chain_count; chain_index++) {      \
      auto chain = new int64_t[coeff_count];                                   \
      for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {    \
        chain[coeff_index] = flat[chain_index * coeff_count + coeff_index];    \
      }                                                                        \
      chains[chain_index] = chain;                                             \
    }                                                                          \
    auto polynomial =                                                          \
        new desilo::fhe::Polynomial(chains, flag, moduli_id, coeff_count);     \
    polynomial;                                                                \
  })

#define MAKE_REDUCED_POLYNOMIAL(...)                                           \
  ({                                                                           \
    int64_t flat[chain_count * reduced_coeff_count]{__VA_ARGS__};              \
    std::vector<int64_t *> chains(chain_count);                                \
    for (int chain_index = 0; chain_index < chain_count; chain_index++) {      \
      auto chain = new int64_t[reduced_coeff_count];                           \
      for (int coeff_index = 0; coeff_index < reduced_coeff_count;             \
           coeff_index++) {                                                    \
        chain[coeff_index] =                                                   \
            flat[chain_index * reduced_coeff_count + coeff_index];             \
      }                                                                        \
      chains[chain_index] = chain;                                             \
    }                                                                          \
    auto polynomial = new desilo::fhe::Polynomial(chains, flag, moduli_id,     \
                                                  reduced_coeff_count);        \
    polynomial;                                                                \
  })

#define MAKE_DOUBLE_POLYNOMIAL(coeff_count, ...)                               \
  ({                                                                           \
    auto buffer = new double[coeff_count]{__VA_ARGS__};                        \
    auto polynomial = new desilo::fhe::DoublePolynomial(                       \
        buffer, flag, moduli_id, coeff_count);                                 \
    polynomial;                                                                \
  })

#define MAKE_COMPLEX_DOUBLE_POLYNOMIAL(coeff_count, ...)                       \
  ({                                                                           \
    auto buffer = new std::complex<double>[coeff_count] { __VA_ARGS__ };       \
    auto polynomial = new desilo::fhe::ComplexDoublePolynomial(                \
        buffer, flag, moduli_id, coeff_count);                                 \
    polynomial;                                                                \
  })

#define MAKE_2D_ARRAY(chain_count, coeff_count, x, ...)                        \
  int64_t x##_flat[chain_count * coeff_count]{__VA_ARGS__};                    \
  int64_t x##_data[chain_count][coeff_count];                                  \
  int64_t *x[chain_count];                                                     \
  for (int chain_index = 0; chain_index < chain_count; chain_index++) {        \
    for (int coeff_index = 0; coeff_index < coeff_count; coeff_index++) {      \
      x##_data[chain_index][coeff_index] =                                     \
          x##_flat[chain_index * coeff_count + coeff_index];                   \
    }                                                                          \
    x[chain_index] = x##_data[chain_index];                                    \
  }

void initiate_message(double *message, int slot_count, int message_type);
void initiate_message(std::vector<double> &message, int message_type);
void initiate_message(std::complex<double> *message, int slot_count,
                      int message_type);
void initiate_message(std::vector<std::complex<double>> &message,
                      int message_type);
void initiate_4d_message(std::vector<std::complex<double>> &message,
                         int message_type, int bound);
void apply_modulo_to_message(std::vector<std::complex<double>> &message,
                             int64_t modulus);
void initiate_sliced_message(double *message, int slice_count, int slot_count,
                             double multiplier = 1.0);
void initiate_sliced_message(std::vector<double> &message, int slice_count,
                             int slot_count, double multiplier = 1.0);
void initiate_sliced_message(std::complex<double> *message, int slice_count,
                             int slot_count, double multiplier = 1.0);
void initiate_sliced_message(std::vector<std::complex<double>> &message,
                             int slice_count, int slot_count,
                             double multiplier = 1.0);

void initialize_random_state(int64_t *state, int thread_count);

std::string print_tier(int log_coeff_count);
std::string print_container_type(int container_type);
std::string print_message_type(int message_type);
std::string print_level(int level);
std::string print_level_depth(int level_depth);
std::string print_moduli_id(int modui_id);
std::string print_delta(int delta);
std::string print_scalar(int scalar);
std::string print_ckks_scale(int ckks_scale);
std::string print_stream_count(int stream_count);
std::string print_slice_count(int slice_count);
std::string print_long_extended(bool extended);
std::string print_include_special(bool include_special);
std::string print_ciphertext_first(bool ciphertext_first);
std::string print_ntt_flag(bool flag_type);
std::string print_rescaled_flag(bool flag_type);
std::string print_trio_first(bool trio_first);
std::string print_input_order(int input_order);
std::string print_level_order(int level_order);
std::string print_process_type(int process_type);
std::string print_rescale_flags(int flag_type);
std::string print_scheme_preset(desilo::fhe::SchemePreset scheme_preset);
std::string print_max_power(int max_power);
std::string print_polynomial(int polynomial_type);
std::string print_log_slot_count(int log_slot_count);

bool get_use_bootstrap(const desilo::fhe::CKKSConfig &config);
bool get_use_one_more_level(const desilo::fhe::CKKSConfig &config);
