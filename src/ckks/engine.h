#include <complex>
#include <initializer_list>
#include <map>
#include <string>
#include <vector>

#include "ckks/config.h"
#include "ckks/core.h"
#include "ckks/parameters.h"
#include "data/bootstrap.h"
#include "data/data.h"
#include "engine/abstract_engine.h"
#include "engine/processor.h"

#pragma once

namespace desilo::fhe {

class CKKSEngine : public AbstractEngine {
public:
  CKKSEngine(const CKKSConfig &config = {});

  SecretKey *create_secret_key();
  SecretKey *create_secret_key(int level);
  SecretKey *create_secret_key(std::vector<int64_t> &secret);
  SecretKey *create_secret_key(std::vector<int64_t> &secret, int level);
  PublicKey *create_public_key(SecretKey *secret_key);
  PublicKey *create_public_key(SecretKey *secret_key, int level);

  ConjugationKey *create_conjugation_key(SecretKey *secret_key);
  ConjugationKey *create_conjugation_key(SecretKey *secret_key, int level);

  RelinearizationKey *create_relinearization_key(SecretKey *secret_key);
  RelinearizationKey *create_relinearization_key(SecretKey *secret_key,
                                                 int level);

  FixedRotationKey *create_fixed_rotation_key(SecretKey *secret_key, int delta);
  FixedRotationKey *create_fixed_rotation_key(SecretKey *secret_key, int delta,
                                              int level);
  FixedRotationKey *create_fixed_rotation_key(SecretKey *secret_key, int delta,
                                              int level,
                                              bool normalize_by_slot_count);

  RotationKey *create_rotation_key(SecretKey *secret_key);
  RotationKey *create_rotation_key(SecretKey *secret_key, int level);
  SmallBootstrapKey *create_small_bootstrap_key(SecretKey *secret_key);
  BootstrapKey *create_bootstrap_key(SecretKey *secret_key, int stage_count,
                                     const std::string &size);

  UnitPlaintext *encode_unit(std::vector<double> &input);
  UnitPlaintext *encode_unit(std::vector<double> &input, int level);
  UnitPlaintext *encode_unit(std::vector<std::complex<double>> &input);
  UnitPlaintext *encode_unit(std::vector<std::complex<double>> &input,
                             int level);

  Plaintext *encode(std::vector<double> &input);
  Plaintext *encode(std::vector<double> &input, int level);
  Plaintext *encode(std::vector<std::complex<double>> &input);
  Plaintext *encode(std::vector<std::complex<double>> &input, int level);
  Plaintext *encode(double *input, int input_size);
  Plaintext *encode(double *input, int input_size, int level);
  Plaintext *encode(std::complex<double> *input, int input_size);
  Plaintext *encode(std::complex<double> *input, int input_size, int level);

  PlainMatrix *encode_matrix(double *matrix, int level);
  PlainMatrix *encode_matrix(double *matrix);
  PlainMatrix *encode_matrix(std::complex<double> *matrix, int level);
  PlainMatrix *encode_matrix(std::complex<double> *matrix);
  PlainMatrix *encode_matrix(std::vector<double> &matrix, int level);
  PlainMatrix *encode_matrix(std::vector<double> &matrix);
  PlainMatrix *encode_matrix(std::vector<std::complex<double>> &matrix,
                             int level);
  PlainMatrix *encode_matrix(std::vector<std::complex<double>> &matrix);

  std::vector<double> decode_unit(UnitPlaintext *plaintext);
  std::vector<std::complex<double>>
  decode_complex_unit_plaintext(UnitPlaintext *plaintext);

  std::vector<double> decode(Plaintext *plaintext);
  void decode_to_buffer(Plaintext *plaintext, double *output);
  std::vector<std::complex<double>>
  decode_complex_plaintext(Plaintext *plaintext);
  void decode_complex_plaintext_to_buffer(Plaintext *plaintext,
                                          std::complex<double> *output);

  UnitCiphertext *encrypt_unit(std::vector<double> &input,
                               PublicKey *public_key);
  UnitCiphertext *encrypt_unit(std::vector<double> &input,
                               PublicKey *public_key, int level);
  UnitCiphertext *encrypt_unit(std::vector<std::complex<double>> &input,
                               PublicKey *public_key);
  UnitCiphertext *encrypt_unit(std::vector<std::complex<double>> &input,
                               PublicKey *public_key, int level);
  UnitCiphertext *encrypt_unit(UnitPlaintext *unit_plaintext,
                               PublicKey *public_key);

  Ciphertext *encrypt(std::vector<double> &input, PublicKey *public_key);
  Ciphertext *encrypt(std::vector<double> &input, PublicKey *public_key,
                      int level);
  Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                      PublicKey *public_key);
  Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                      PublicKey *public_key, int level);
  Ciphertext *encrypt(double *input, PublicKey *public_key, int input_size);
  Ciphertext *encrypt(double *input, PublicKey *public_key, int input_size,
                      int level);
  Ciphertext *encrypt(std::complex<double> *input, PublicKey *public_key,
                      int input_size);
  Ciphertext *encrypt(std::complex<double> *input, PublicKey *public_key,
                      int input_size, int level);
  Ciphertext *encrypt(Plaintext *plaintext, PublicKey *public_key);

  UnitCiphertext *encrypt_unit(std::vector<double> &input,
                               SecretKey *secret_key);
  UnitCiphertext *encrypt_unit(std::vector<double> &input,
                               SecretKey *secret_key, int level);
  UnitCiphertext *encrypt_unit(std::vector<std::complex<double>> &input,
                               SecretKey *secret_key);
  UnitCiphertext *encrypt_unit(std::vector<std::complex<double>> &input,
                               SecretKey *secret_key, int level);
  UnitCiphertext *encrypt_unit(UnitPlaintext *unit_plaintext,
                               SecretKey *secret_key);

  Ciphertext *encrypt(std::vector<double> &input, SecretKey *secret_key);
  Ciphertext *encrypt(std::vector<double> &input, SecretKey *secret_key,
                      int level);
  Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                      SecretKey *secret_key);
  Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                      SecretKey *secret_key, int level);
  Ciphertext *encrypt(double *input, SecretKey *secret_key, int input_size);
  Ciphertext *encrypt(double *input, SecretKey *secret_key, int input_size,
                      int level);
  Ciphertext *encrypt(std::complex<double> *input, SecretKey *secret_key,
                      int input_size);
  Ciphertext *encrypt(std::complex<double> *input, SecretKey *secret_key,
                      int input_size, int level);
  Ciphertext *encrypt(Plaintext *plaintext, SecretKey *secret_key);

  std::vector<double> decrypt(UnitCiphertext *unit_ciphertext,
                              SecretKey *secret_key);
  std::vector<std::complex<double>>
  decrypt_complex(UnitCiphertext *unit_ciphertext, SecretKey *secret_key);
  UnitPlaintext *decrypt_to_unit_plaintext(UnitCiphertext *unit_ciphertext,
                                           SecretKey *secret_key);

  std::vector<double> decrypt(Ciphertext *ciphertext, SecretKey *secret_key);
  std::vector<std::complex<double>> decrypt_complex(Ciphertext *ciphertext,
                                                    SecretKey *secret_key);
  void decrypt_to_buffer(Ciphertext *ciphertext, double *output,
                         SecretKey *secret_key);
  void decrypt_to_complex_buffer(Ciphertext *ciphertext,
                                 std::complex<double> *output,
                                 SecretKey *secret_key);
  Plaintext *decrypt_to_plaintext(Ciphertext *ciphertext,
                                  SecretKey *secret_key);

  UnitCiphertext *add(UnitCiphertext *unit_ciphertext1,
                      UnitCiphertext *unit_ciphertext2);
  UnitCiphertext *add(UnitCiphertext *unit_ciphertext,
                      UnitPlaintext *unit_plaintext);
  UnitCiphertext *add(UnitPlaintext *unit_plaintext,
                      UnitCiphertext *unit_ciphertext);
  UnitCiphertext *add(UnitCiphertext *unit_ciphertext,
                      std::vector<double> &message);
  UnitCiphertext *add(std::vector<double> &message,
                      UnitCiphertext *unit_ciphertext);
  UnitCiphertext *add(UnitCiphertext *unit_ciphertext,
                      std::vector<std::complex<double>> &message);
  UnitCiphertext *add(std::vector<std::complex<double>> &message,
                      UnitCiphertext *unit_ciphertext);
  UnitCiphertext *add(UnitCiphertext *unit_ciphertext, double value);
  UnitCiphertext *add(double value, UnitCiphertext *unit_ciphertext);

  void add_inplace(UnitCiphertext *unit_ciphertext1,
                   UnitCiphertext *unit_ciphertext2);
  void add_inplace(UnitCiphertext *unit_ciphertext,
                   UnitPlaintext *unit_plaintext);
  void add_inplace(UnitPlaintext *unit_plaintext,
                   UnitCiphertext *unit_ciphertext);

  Ciphertext *add(Ciphertext *ciphertext1, Ciphertext *ciphertext2);
  Ciphertext *add(Ciphertext *ciphertext, Plaintext *plaintext);
  Ciphertext *add(Plaintext *plaintext, Ciphertext *ciphertext);
  Ciphertext *add(Ciphertext *ciphertext, std::vector<double> &message);
  Ciphertext *add(std::vector<double> &message, Ciphertext *ciphertext);
  Ciphertext *add(Ciphertext *ciphertext,
                  std::vector<std::complex<double>> &message);
  Ciphertext *add(std::vector<std::complex<double>> &message,
                  Ciphertext *ciphertext);
  Ciphertext *add(Ciphertext *ciphertext, double value);
  Ciphertext *add(Ciphertext *ciphertext, double *message, int message_size);
  Ciphertext *add(double *message, Ciphertext *ciphertext, int message_size);
  Ciphertext *add(Ciphertext *ciphertext, std::complex<double> *message,
                  int message_size);
  Ciphertext *add(std::complex<double> *message, Ciphertext *ciphertext,
                  int message_size);
  Ciphertext *add(double value, Ciphertext *ciphertext);

  void add_inplace(Ciphertext *ciphertext1, Ciphertext *ciphertext2);
  void add_inplace(Ciphertext *ciphertext, Plaintext *plaintext);
  void add_inplace(Plaintext *plaintext, Ciphertext *ciphertext);

  UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext1,
                           UnitCiphertext *unit_ciphertext2);
  UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext,
                           UnitPlaintext *unit_plaintext);
  UnitCiphertext *subtract(UnitPlaintext *unit_plaintext,
                           UnitCiphertext *unit_ciphertext);
  UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext,
                           std::vector<double> &message);
  UnitCiphertext *subtract(std::vector<double> &message,
                           UnitCiphertext *unit_ciphertext);
  UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext,
                           std::vector<std::complex<double>> &message);
  UnitCiphertext *subtract(std::vector<std::complex<double>> &message,
                           UnitCiphertext *unit_ciphertext);
  UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext, double value);
  UnitCiphertext *subtract(double value, UnitCiphertext *unit_ciphertext);

  void subtract_inplace(UnitCiphertext *unit_ciphertext1,
                        UnitCiphertext *unit_ciphertext2);

  Ciphertext *subtract(Ciphertext *ciphertext1, Ciphertext *ciphertext2);
  Ciphertext *subtract(Ciphertext *ciphertext, Plaintext *plaintext);
  Ciphertext *subtract(Plaintext *plaintext, Ciphertext *ciphertext);
  Ciphertext *subtract(Ciphertext *ciphertext, std::vector<double> &message);
  Ciphertext *subtract(std::vector<double> &message, Ciphertext *ciphertext);
  Ciphertext *subtract(Ciphertext *ciphertext,
                       std::vector<std::complex<double>> &message);
  Ciphertext *subtract(std::vector<std::complex<double>> &message,
                       Ciphertext *ciphertext);
  Ciphertext *subtract(Ciphertext *ciphertext, double *message,
                       int message_size);
  Ciphertext *subtract(double *message, Ciphertext *ciphertext,
                       int message_size);
  Ciphertext *subtract(Ciphertext *ciphertext, std::complex<double> *message,
                       int message_size);
  Ciphertext *subtract(std::complex<double> *message, Ciphertext *ciphertext,
                       int message_size);
  Ciphertext *subtract(Ciphertext *ciphertext, double value);
  Ciphertext *subtract(double value, Ciphertext *ciphertext);

  void subtract_inplace(Ciphertext *ciphertext1, Ciphertext *ciphertext2);

  UnitCiphertext *multiply(UnitCiphertext *unit_ciphertext1,
                           UnitCiphertext *unit_ciphertext2);
  UnitCiphertext *multiply(UnitCiphertext *unit_ciphertext1,
                           UnitCiphertext *unit_ciphertext2,
                           RelinearizationKey *relinearization_key);
  UnitCiphertext *square(UnitCiphertext *unit_ciphertext);
  UnitCiphertext *square(UnitCiphertext *unit_ciphertext,
                         RelinearizationKey *relinearization_key);
  UnitCiphertext *multiply(UnitCiphertext *unit_ciphertext,
                           UnitPlaintext *unit_plaintext);
  UnitCiphertext *multiply(UnitPlaintext *unit_plaintext,
                           UnitCiphertext *unit_ciphertext);
  UnitCiphertext *multiply(UnitCiphertext *unit_ciphertext,
                           std::vector<double> &message);
  UnitCiphertext *multiply(std::vector<double> &message,
                           UnitCiphertext *unit_ciphertext);
  UnitCiphertext *multiply(UnitCiphertext *unit_ciphertext,
                           std::vector<std::complex<double>> &message);
  UnitCiphertext *multiply(std::vector<std::complex<double>> &message,
                           UnitCiphertext *unit_ciphertext);
  UnitCiphertext *multiply(UnitCiphertext *unit_ciphertext, double value);
  UnitCiphertext *multiply(double value, UnitCiphertext *unit_ciphertext);
  UnitCiphertext *multiply(UnitCiphertext *unit_ciphertext, int64_t value);
  UnitCiphertext *multiply(int64_t value, UnitCiphertext *unit_ciphertext);
  UnitCiphertext *multiply_imaginary(UnitCiphertext *unit_ciphertext,
                                     int64_t value);
  UnitCiphertext *multiply_imaginary(int64_t value,
                                     UnitCiphertext *unit_ciphertext);

  Ciphertext *multiply(Ciphertext *ciphertext1, Ciphertext *ciphertext2);
  Ciphertext *multiply(Ciphertext *ciphertext1, Ciphertext *ciphertext2,
                       RelinearizationKey *relinearization_key);
  Ciphertext *square(Ciphertext *ciphertext);
  Ciphertext *square(Ciphertext *ciphertext,
                     RelinearizationKey *relinearization_key);
  Ciphertext *multiply(Ciphertext *ciphertext, Plaintext *plaintext);
  Ciphertext *multiply(Plaintext *plaintext, Ciphertext *ciphertext);
  Ciphertext *multiply(Ciphertext *ciphertext, std::vector<double> &message);
  Ciphertext *multiply(std::vector<double> &message, Ciphertext *ciphertext);
  Ciphertext *multiply(Ciphertext *ciphertext,
                       std::vector<std::complex<double>> &message);
  Ciphertext *multiply(std::vector<std::complex<double>> &message,
                       Ciphertext *ciphertext);
  Ciphertext *multiply(Ciphertext *ciphertext, double *message,
                       int message_size);
  Ciphertext *multiply(double *message, Ciphertext *ciphertext,
                       int message_size);
  Ciphertext *multiply(Ciphertext *ciphertext, std::complex<double> *message,
                       int message_size);
  Ciphertext *multiply(std::complex<double> *message, Ciphertext *ciphertext,
                       int message_size);
  Ciphertext *multiply(Ciphertext *ciphertext, double value);
  Ciphertext *multiply(double value, Ciphertext *ciphertext);
  Ciphertext *multiply(Ciphertext *ciphertext, int64_t value);
  Ciphertext *multiply(int64_t value, Ciphertext *ciphertext);
  Ciphertext *multiply_imaginary(Ciphertext *ciphertext, int64_t value);
  Ciphertext *multiply_imaginary(int64_t value, Ciphertext *ciphertext);

  UnitCiphertext *multiply_matrix(double *matrix,
                                  UnitCiphertext *unit_ciphertext,
                                  RotationKey *rotation_key);
  UnitCiphertext *multiply_matrix(std::complex<double> *matrix,
                                  UnitCiphertext *unit_ciphertext,
                                  RotationKey *rotation_key);
  UnitCiphertext *multiply_matrix(std::vector<double> &matrix,
                                  UnitCiphertext *unit_ciphertext,
                                  RotationKey *rotation_key);
  UnitCiphertext *multiply_matrix(std::vector<std::complex<double>> &matrix,
                                  UnitCiphertext *unit_ciphertext,
                                  RotationKey *rotation_key);
  Ciphertext *multiply_matrix(double *matrix, Ciphertext *ciphertext,
                              RotationKey *rotation_key);
  Ciphertext *multiply_matrix(std::complex<double> *matrix,
                              Ciphertext *ciphertext,
                              RotationKey *rotation_key);
  Ciphertext *multiply_matrix(std::vector<double> &matrix,
                              Ciphertext *ciphertext,
                              RotationKey *rotation_key);
  Ciphertext *multiply_matrix(std::vector<std::complex<double>> &matrix,
                              Ciphertext *ciphertext,
                              RotationKey *rotation_key);

  UnitCiphertext *relinearize(UnitCiphertext *unit_ciphertext,
                              RelinearizationKey *relinearization_key);
  Ciphertext *relinearize(Ciphertext *ciphertext,
                          RelinearizationKey *relinearization_key);

  UnitPlaintext *conjugate(UnitPlaintext *unit_plaintext);
  UnitCiphertext *conjugate(UnitCiphertext *unit_ciphertext,
                            ConjugationKey *conjugation_key);
  Plaintext *conjugate(Plaintext *plaintext);
  Ciphertext *conjugate(Ciphertext *ciphertext,
                        ConjugationKey *conjugation_key);

  UnitPlaintext *rotate(UnitPlaintext *unit_plaintext, int delta);
  UnitCiphertext *rotate(UnitCiphertext *unit_ciphertext,
                         FixedRotationKey *fixed_rotation_key);
  UnitCiphertext *rotate(UnitCiphertext *unit_ciphertext,
                         RotationKey *rotation_key, int delta,
                         bool normalize_by_slot_count = true);
  UnitCiphertext *rotate(UnitCiphertext *unit_ciphertext,
                         BootstrapKey *bootstrap_key, int delta,
                         bool normalize_by_slot_count = true);
  UnitCiphertext *
  ntt_rotate(UnitCiphertext *unit_ciphertext,
             DecomposedUnitCiphertext *decomposed_unit_ciphertext,
             BootstrapKey *bootstrap_key, int delta);
  Plaintext *rotate(Plaintext *plaintext, int delta);
  Ciphertext *rotate(Ciphertext *ciphertext,
                     FixedRotationKey *fixed_rotation_key);
  Ciphertext *rotate(Ciphertext *ciphertext, RotationKey *rotation_key,
                     int delta);
  Ciphertext *rotate(Ciphertext *ciphertext, BootstrapKey *bootstrap_key,
                     int delta);
  std::vector<Ciphertext *>
  rotate_batch(Ciphertext *ciphertext,
               std::vector<FixedRotationKey *> fixed_rotation_keys);
  std::vector<UnitCiphertext *> rotate_batch(UnitCiphertext *unit_ciphertext,
                                             RotationKey *rotation_key,
                                             std::vector<int> deltas);
  std::vector<Ciphertext *> rotate_batch(Ciphertext *ciphertext,
                                         RotationKey *rotation_key,
                                         std::vector<int> deltas);

  int to_normalized_delta(int delta, bool normalize_by_slot_count = true);

  UnitPlaintext *ntt(UnitPlaintext *unit_plaintext);
  UnitCiphertext *ntt(UnitCiphertext *unit_ciphertext);
  Plaintext *ntt(Plaintext *plaintext);
  Ciphertext *ntt(Ciphertext *ciphertext);

  UnitPlaintext *intt(UnitPlaintext *unit_plaintext);
  UnitCiphertext *intt(UnitCiphertext *unit_ciphertext);
  Plaintext *intt(Plaintext *plaintext);
  Ciphertext *intt(Ciphertext *ciphertext);

  UnitPlaintext *rescale(UnitPlaintext *unit_plaintext);
  UnitCiphertext *rescale(UnitCiphertext *unit_ciphertext);
  Plaintext *rescale(Plaintext *plaintext);
  Ciphertext *rescale(Ciphertext *ciphertext);

  UnitPlaintext *level_down(UnitPlaintext *unit_plaintext, int level);
  UnitCiphertext *level_down(UnitCiphertext *unit_ciphertext, int level);
  Plaintext *level_down(Plaintext *plaintext, int level);
  Ciphertext *level_down(Ciphertext *ciphertext, int level);

  UnitCiphertext *negate(UnitCiphertext *unit_ciphertext);
  Ciphertext *negate(Ciphertext *ciphertext);

  UnitPlaintext *clone(UnitPlaintext *unit_plaintext);
  UnitCiphertext *clone(UnitCiphertext *unit_ciphertext);
  Plaintext *clone(Plaintext *plaintext);
  Ciphertext *clone(Ciphertext *ciphertext);

  std::vector<PlainMatrix *>
  make_coeff_to_slot_stages(int stage_count, int inner_loop_shift, int level);
  std::vector<PlainMatrix *>
  make_slot_to_coeff_stages(int stage_count, int inner_loop_shift, int level);
  std::vector<int> make_partial_sum_deltas();
  UnitCiphertext *mod_raise_(UnitCiphertext *unit_ciphertext,
                             SmallBootstrapKey *small_bootstrap_key,
                             bool for_ciphertext = false);
  Ciphertext *mod_raise(Ciphertext *ciphertext,
                        SmallBootstrapKey *small_bootstrap_key);
  Ciphertext *mod_raise(Ciphertext *ciphertext, BootstrapKey *bootstrap_key);
  template <class T>
  void partial_sum_inplace(UnitCiphertext *unit_ciphertext, T *bootstrap_key);
  void partial_sum_inplace(UnitCiphertext *unit_ciphertext,
                           RotationKey *rotation_key);
  std::pair<UnitCiphertext *, UnitCiphertext *>
  coeff_to_slot(UnitCiphertext *unit_ciphertext,
                ConjugationKey *conjugation_key, RotationKey *rotation_key,
                int stage_count);
  template <class T>
  std::pair<UnitCiphertext *, UnitCiphertext *>
  coeff_to_slot(UnitCiphertext *unit_ciphertext,
                ConjugationKey *conjugation_key, T *bootstrap_key);
  UnitCiphertext *slot_to_coeff(UnitCiphertext *unit_ciphertext_real,
                                UnitCiphertext *unit_ciphertext_imag,
                                ConjugationKey *conjugation_key,
                                RotationKey *rotation_key, int stage_count);
  UnitCiphertext *slot_to_coeff(UnitCiphertext *unit_ciphertext_real,
                                UnitCiphertext *unit_ciphertext_imag,
                                ConjugationKey *conjugation_key,
                                BootstrapKey *bootstrap_key);
  UnitCiphertext *round(UnitCiphertext *unit_ciphertext,
                        RelinearizationKey *relinearization_key);
  UnitCiphertext *bootstrap(UnitCiphertext *unit_ciphertext,
                            RelinearizationKey *relinearization_key,
                            ConjugationKey *conjugation_key,
                            RotationKey *rotation_key,
                            SmallBootstrapKey *small_bootsstrap_key,
                            int stage_count = 3);
  UnitCiphertext *bootstrap(UnitCiphertext *unit_ciphertext,
                            RelinearizationKey *relinearization_key,
                            ConjugationKey *conjugation_key,
                            BootstrapKey *bootstrap_key);
  Ciphertext *
  bootstrap(Ciphertext *ciphertext, RelinearizationKey *relinearization_key,
            ConjugationKey *conjugation_key, RotationKey *rotation_key,
            SmallBootstrapKey *small_bootstrap_key, int stage_count = 3);
  Ciphertext *bootstrap(Ciphertext *ciphertext,
                        RelinearizationKey *relinearization_key,
                        ConjugationKey *conjugation_key,
                        BootstrapKey *bootstrap_key);
  template <typename T>
  std::vector<T> rotate_vector(const std::vector<T> &input, int delta);

  std::vector<UnitCiphertext *>
  make_power_basis(UnitCiphertext *unit_ciphertext, int max_power,
                   RelinearizationKey *relinearization_key);
  std::vector<Ciphertext *>
  make_power_basis(Ciphertext *ciphertext, int max_power,
                   RelinearizationKey *relinearization_key);
  std::vector<UnitCiphertext *>
  make_chebyshev_basis(UnitCiphertext *unit_ciphertext, int max_power,
                       RelinearizationKey *relinearization_key);
  std::vector<Ciphertext *>
  make_chebyshev_basis(Ciphertext *ciphertext, int max_power,
                       RelinearizationKey *relinearization_key);
  UnitCiphertext *weighted_sum(std::vector<UnitCiphertext *> &unit_ciphertexts,
                               const std::vector<int64_t> &weights);
  UnitCiphertext *weighted_sum(std::vector<UnitCiphertext *> &unit_ciphertexts,
                               const std::vector<double> &weights);
  Ciphertext *weighted_sum(std::vector<Ciphertext *> &ciphertexts,
                           std::vector<int64_t> &weights);
  Ciphertext *weighted_sum(std::vector<Ciphertext *> &ciphertexts,
                           std::vector<double> &weights);
  UnitCiphertext *evaluate_polynomial(UnitCiphertext *unit_ciphertext,
                                      std::vector<int64_t> &coefficients,
                                      RelinearizationKey *relinearization_key);
  UnitCiphertext *evaluate_polynomial(UnitCiphertext *unit_ciphertext,
                                      std::vector<double> &coefficients,
                                      RelinearizationKey *relinearization_key);
  Ciphertext *evaluate_polynomial(Ciphertext *ciphertext,
                                  std::vector<int64_t> &coefficients,
                                  RelinearizationKey *relinearization_key);
  Ciphertext *evaluate_polynomial(Ciphertext *ciphertext,
                                  std::vector<double> &coefficients,
                                  RelinearizationKey *relinearization_key);
  UnitCiphertext *
  evaluate_chebyshev_polynomial(UnitCiphertext *unit_ciphertext,
                                std::vector<int64_t> &coefficients,
                                RelinearizationKey *relinearization_key);
  UnitCiphertext *
  evaluate_chebyshev_polynomial(UnitCiphertext *unit_ciphertext,
                                std::vector<double> &coefficients,
                                RelinearizationKey *relinearization_key);
  Ciphertext *
  evaluate_chebyshev_polynomial(Ciphertext *ciphertext,
                                std::vector<int64_t> &coefficients,
                                RelinearizationKey *relinearization_key);
  Ciphertext *
  evaluate_chebyshev_polynomial(Ciphertext *ciphertext,
                                std::vector<double> &coefficients,
                                RelinearizationKey *relinearization_key);
  Ciphertext *sum_1d_by_row(Ciphertext *ciphertext, RotationKey *rotation_key);
  Ciphertext *sum_1d_by_column(Ciphertext *ciphertext);
  Ciphertext *sum_2d(Ciphertext *ciphertext, RotationKey *rotation_key);
  Ciphertext *stack_by_row(std::vector<Ciphertext *> &ciphertexts);

  std::pair<int, int> get_bootstrap_stage_levels(int stage_count) const;
  int get_slot_count() const { return core_->get_slot_count(); };
  int get_coeff_count() const { return core_->get_coeff_count(); };
  int get_max_level() const;
  std::string get_mode() const;

  const CKKSParameters parameters_;

private:
  CKKSEngine(CKKSCore *core);

  SecretKey *create_sparse_secret_key();

  std::vector<Data *> temp_data_;
  std::vector<TextInterface *> temp_text_;

  template <typename T> Plaintext *encode_(std::vector<T> &input, int level);
  template <typename T> Plaintext *encode_(T *input, int input_size, int level);
  template <typename T>
  void require_encrypt_(const std::string &function_name, std::vector<T> &input,
                        PublicKey *public_key, int level, bool for_unit = true);
  template <typename T>
  void require_encrypt_(const std::string &function_name, std::vector<T> &input,
                        SecretKey *secret_key, int level, bool for_unit = true);
  template <typename T>
  void require_encrypt_(const std::string &function_name, T *input,
                        PublicKey *public_key, int level);
  template <typename T>
  void require_encrypt_(const std::string &function_name, T *input,
                        SecretKey *secret_key, int level);
  template <typename T>
  UnitCiphertext *encrypt_unit_(std::vector<T> &input, PublicKey *public_key,
                                int level);
  template <typename T>
  UnitCiphertext *encrypt_unit_(std::vector<T> &input, SecretKey *secret_key,
                                int level);
  template <typename T>
  Ciphertext *encrypt_(std::vector<T> &input, PublicKey *public_key, int level);
  template <typename T>
  Ciphertext *encrypt_(std::vector<T> &input, SecretKey *secret_key, int level);
  template <typename T>
  Ciphertext *encrypt_(T *input, PublicKey *public_key, int input_size,
                       int level);
  template <typename T>
  Ciphertext *encrypt_(T *input, SecretKey *secret_key, int input_size,
                       int level);
  template <typename T>
  void require_encrypt_(const std::string &function_name, T *text,
                        PublicKey *public_key);
  template <typename T>
  void require_encrypt_(const std::string &function_name, T *text,
                        SecretKey *secret_key);
  template <class T>
  void require_decrypt_(const std::string &function_name, T *text,
                        SecretKey *secret_key);
  template <class T>
  void require_add_subtract_(const std::string &function_name, T *text1,
                             T *text2);
  template <class T, class U>
  void require_add_subtract_(const std::string &function_name,
                             T *unit_ciphertext, U *unit_plaintext);
  template <class T, typename U>
  void require_add_subtract_(const std::string &function_name, T *text,
                             std::vector<U> &message);
  void require_add_subtract_(const std::string &function_name,
                             Ciphertext *ciphertext, int message_size);
  template <class T>
  void require_add_subtract_(const std::string &function_name, T *text);
  template <class T>
  void require_add_subtract_inplace_(const std::string &function_name, T *text1,
                                     T *text2);
  template <class T, class U>
  void require_add_subtract_inplace_(const std::string &function_name,
                                     T *ciphertext, U *plaintext);

  template <class T>
  void require_multiply_(const std::string &function_name, T *text1, T *text2);
  template <class T>
  void require_square_(const std::string &function_name, T *text);
  template <class T>
  void require_multiply_(const std::string &function_name, T *text1, T *text2,
                         RelinearizationKey *relinearization_key);
  template <class T>
  void require_square_(const std::string &function_name, T *text,
                       RelinearizationKey *relinearization_key);
  template <class T, class U>
  void require_multiply_(const std::string &function_name, T *unit_ciphertext,
                         U *unit_plaintext);
  template <class T, typename U>
  void require_multiply_(const std::string &function_name, T *text,
                         std::vector<U> &message);
  void require_multiply_(const std::string &function_name,
                         Ciphertext *ciphertext, int message_size);
  template <class T>
  void require_multiply_(const std::string &function_name, T *text,
                         bool allow_level_zero);
  template <typename T>
  void require_multiply_matrix_(const std::string &function_name, T *text,
                                RotationKey *rotation_key);
  template <class T>
  void require_relinearize_(const std::string &function_name, T *text,
                            RelinearizationKey *relinearization_key);
  template <class T>
  void require_conjugate_(const std::string &function_name, T *text);
  template <class T>
  void require_conjugate_(const std::string &function_name, T *text,
                          ConjugationKey *conjugation_key);
  template <class T>
  void require_rotate_(const std::string &function_name, T *text);
  template <class T>
  void require_rotate_(const std::string &function_name, T *text,
                       FixedRotationKey *fixed_rotation_key);
  template <class T>
  void require_rotate_(const std::string &function_name, T *text,
                       RotationKey *rotation_key);
  template <class T> T *rescale_(T *text, bool temp);
  template <class T, class U> T *rescale_(T *text, bool temp);
  Plaintext *rescale_(Plaintext *unit_plaintext, bool temp);
  Ciphertext *rescale_(Ciphertext *unit_ciphertext, bool temp);
  template <class T> T *level_down_(T *text, int level, bool temp);
  template <class T, class U>
  T *level_down_(T *long_text, int level, bool temp);
  Plaintext *level_down_(Plaintext *plaintext, int level, bool temp);

  Ciphertext *level_down_(Ciphertext *ciphertext, int level, bool temp);
  template <class T> T *ntt_(T *text, bool temp);
  template <class T, class U> T *ntt_(T *text, bool temp);
  Plaintext *ntt_(Plaintext *unit_plaintext, bool temp);
  Ciphertext *ntt_(Ciphertext *unit_ciphertext, bool temp);
  template <class T> T *intt_(T *text, bool temp);
  template <class T, class U> T *intt_(T *text, bool temp);
  Plaintext *intt_(Plaintext *unit_plaintext, bool temp);
  Ciphertext *intt_(Ciphertext *unit_ciphertext, bool temp);

  template <class T> std::tuple<T *, T *> match_form(T *text1, T *text2);
  template <class T, class U>
  std::tuple<T *, U *> match_form(T *text1, U *text2);
  template <class T, class U>
  std::tuple<T *, U *> match_form_inplace(T *text1, U *text2);
  template <class T> T *prepare_for_multiply(T *text, int level);

  void clear_temp_data();

  void require_bootstrap_engine(const std::string &function_name);
  bool is_compatible(const DataInterface *data);
  bool is_key_compatible(const DataInterface *data, const Data *key);
  void require_engine_compatibility(const std::string &function_name,
                                    const SecretKey *secret_key);
  void
  require_engine_compatibility(const std::string &function_name,
                               const std::vector<SecretKey *> &secret_keys);
  void require_engine_compatibility(const std::string &function_name,
                                    const PublicKey *public_key);
  void require_engine_compatibility(const std::string &function_name,
                                    const FixedRotationKey *fixed_rotation_key);
  void require_engine_compatibility(
      const std::string &function_name,
      const std::vector<FixedRotationKey *> &fixed_rotation_keys,
      const std::initializer_list<Requirement> requirements);
  void require_engine_compatibility(const std::string &function_name,
                                    const ConjugationKey *conjugation_key);
  void require_engine_compatibility(const std::string &function_name,
                                    const ConjugationKey *conjugation_key,
                                    int minimum_level);
  void require_engine_compatibility(
      const std::string &function_name,
      const std::vector<ConjugationKey *> &conjugation_keys);
  void
  require_engine_compatibility(const std::string &function_name,
                               const RelinearizationKey *relinearization_key);
  void
  require_engine_compatibility(const std::string &function_name,
                               const RelinearizationKey *relinearization_key,
                               int minimum_level);
  void require_engine_compatibility(
      const std::string &function_name,
      const std::vector<RelinearizationKey *> &relinearization_keys);
  void require_engine_compatibility(const std::string &function_name,
                                    const RotationKey *rotation_key);
  void require_engine_compatibility(const std::string &function_name,
                                    const RotationKey *rotation_key,
                                    int minimum_level);
  void
  require_engine_compatibility(const std::string &function_name,
                               const std::vector<RotationKey *> &rotation_keys);
  void
  require_engine_compatibility(const std::string &function_name,
                               const SmallBootstrapKey *small_bootstrap_key);
  void require_engine_compatibility(const std::string &function_name,
                                    const BootstrapKey *bootstrap_key);
  template <typename T>
  void require_engine_compatibility(const std::string &function_name,
                                    const std::vector<T> &input);
  template <typename T>
  void require_engine_compatibility(const std::string &function_name,
                                    const TextInterface *text,
                                    const std::vector<T> &input);
  void require_engine_compatibility(const std::string &function_name,
                                    const TextInterface *text,
                                    const int input_size);
  void require(const std::string &function_name,
               const std::initializer_list<const TextInterface *> texts,
               const std::initializer_list<Requirement> requirements);
  template <class T>
  void require(const std::string &function_name, std::vector<T *> &texts,
               const std::initializer_list<Requirement> requirements);
  void require(const std::string &function_name, const TextInterface *text,
               const std::initializer_list<Requirement> requirements);
  void require(const std::string &function_name,
               const TextInterface *unit_ciphertext,
               const TextInterface *unit_plaintext,
               const std::initializer_list<Requirement> requirements);
  void require(const std::string &function_name,
               const UnitCiphertext *unit_ciphertext,
               const DecomposedUnitCiphertext *decomposed_unit_ciphertext,
               const std::initializer_list<Requirement> requirements);
  void require_key_compatibility(const std::string &function_name,
                                 const TextInterface *text,
                                 const SecretKey *secret_key);
  void require_key_compatibility(const std::string &function_name,
                                 const TextInterface *text,
                                 const PublicKey *public_key);
  void require_key_compatibility(const std::string &function_name,
                                 const TextInterface *text,
                                 const RelinearizationKey *relinearization_key,
                                 bool for_multiply = false);
  void require_key_compatibility(const std::string &function_name,
                                 const TextInterface *text,
                                 const FixedRotationKey *fixed_rotation_key);
  void require_key_compatibility(
      const std::string &function_name, const TextInterface *text,
      const std::vector<FixedRotationKey *> fixed_rotation_keys);
  void require_key_compatibility(const std::string &function_name,
                                 const TextInterface *text,
                                 const RotationKey *rotation_key);
  void require_key_compatibility(
      const std::string &function_name,
      const std::initializer_list<const UnitCiphertext *> unit_ciphertexts,
      const RotationKey *rotation_key);
  void require_key_compatibility(const std::string &function_name,
                                 const TextInterface *text,
                                 const ConjugationKey *conjugation_key);
  void require_key_compatibility(
      const std::string &function_name,
      const std::initializer_list<const UnitCiphertext *> unit_ciphertexts,
      const ConjugationKey *conjugation_key);
  void require_bootstrap_stage_count(const std::string &function_name,
                                     int stage_count, int inner_loop_shift = 0);
  int require_bootstrap_key_size(const std::string &function_name,
                                 const std::string &size);
  template <typename T>
  void require_matrix_compatibility(const std::string &function_name,
                                    const std::vector<T> &input);
  void validate_target_level(const std::string &function_name, int level);
  void validate_target_level(const std::string &function_name,
                             int destination_level, int source_level);
  void validate_target_level(const std::string &function_name,
                             const TextInterface *ciphertext, int level);
  void validate_target_level(const std::string &function_name,
                             const std::initializer_list<Data *> keys,
                             int level);
  template <typename T>
  void validate_target_level(const std::string &function_name,
                             const std::vector<T> &keys, int level);
  void validate_key_switching_key_level(const std::string &function_name,
                                        int level);
  void validate_matrix_target_level(const std::string &function_name,
                                    int level);

  template <typename T> PlainMatrix *make_plain_matrix(T matrix, int level);
  UnitCiphertext *multiply_plain_matrix(UnitCiphertext *unit_ciphertext,
                                        PlainMatrix *plain_matrix,
                                        RotationKey *rotation_key);
  template <typename T> PlainMatrix *encode_matrix_(T matrix, int level);
  template <typename T>
  UnitCiphertext *multiply_matrix_(T matrix, UnitCiphertext *unit_ciphertext,
                                   RotationKey *rotation_key);
  template <typename T>
  Ciphertext *multiply_matrix_(T matrix, Ciphertext *ciphertext,
                               RotationKey *rotation_key);

  std::pair<FixedRotationKey *, PermutationParameters *>
  get_rotation_context(const std::string &function_name,
                       BootstrapKey *bootstrap_key, int delta);
  FixedRotationKey *get_fixed_rotation_key(const std::string &function_name,
                                           BootstrapKey *bootstrap_key,
                                           int delta);
  template <class T>
  UnitCiphertext *
  ntt_rotate_(const std::string &function_name, UnitCiphertext *unit_ciphertext,
              DecomposedUnitCiphertext *decomposed_unit_ciphertext,
              T *bootstrap_key, int delta);
  PlainMatrix *make_bootstrap_stage(
      const std::vector<std::vector<std::complex<double>>> &twiddles,
      int rotate_count, int level, int inner_loop_shift);
  UnitCiphertext *multiply_for_butterfly(UnitCiphertext *unit_ciphertext,
                                         UnitPlaintext *unit_plaintext);
  UnitCiphertext *
  apply_butterfly(UnitCiphertext *unit_ciphertext,
                  const std::vector<std::vector<std::complex<double>>> &twiddle,
                  RotationKey *rotation_key, int rotate_count);
  template <class T>
  UnitCiphertext *apply_butterfly(UnitCiphertext *unit_ciphertext,
                                  T *bootstrap_key, PlainMatrix *stage);
  UnitCiphertext *chebyshev_paterson_stockmeyer(
      std::vector<UnitCiphertext *> &baby_basis, UnitCiphertext *giant,
      RelinearizationKey *relinearization_key,
      const std::vector<std::vector<double>> coefficients);
  UnitCiphertext *chebyshev_paterson_stockmeyer(
      std::vector<UnitCiphertext *> &baby_basis, UnitCiphertext *giant,
      const std::vector<std::vector<double>> coefficients);
  UnitCiphertext *sine(UnitCiphertext *unit_ciphertext,
                       RelinearizationKey *relinearization_key);
  UnitCiphertext *
  apply_double_angle_iterations(UnitCiphertext *unit_ciphertext,
                                RelinearizationKey *relinearization_key,
                                int iter_count = 3);
  UnitCiphertext *modulo(UnitCiphertext *unit_ciphertext,
                         RelinearizationKey *relinearization_key);
  template <class T>
  void
  require_bootstrap_(const std::string &function_name, T *text,
                     RelinearizationKey *relinearization_key,
                     ConjugationKey *conjugation_key, RotationKey *rotation_key,
                     SmallBootstrapKey *small_bootstrap_key, int stage_count);
  template <class T>
  void require_bootstrap_(const std::string &function_name, T *text,
                          RelinearizationKey *relinearization_key,
                          ConjugationKey *conjugation_key,
                          BootstrapKey *bootstrap_key);

  template <class T>
  void require_make_power_basis_(const std::string &function_name, T *text,
                                 int max_power,
                                 RelinearizationKey *relinearization_key);
  template <class T>
  void require_make_chebyshev_basis_(const std::string &function_name, T *text,
                                     int max_power,
                                     RelinearizationKey *relinearization_key);
  template <typename T>
  UnitCiphertext *weighted_sum_(std::vector<UnitCiphertext *> &unit_ciphertexts,
                                const std::vector<T> &weights);
  template <typename T>
  Ciphertext *weighted_sum_(std::vector<Ciphertext *> &ciphertexts,
                            std::vector<T> &weights);
  template <class T>
  void require_weighted_sum_(const std::string &function_name,
                             std::vector<T> &texts,
                             const std::vector<int64_t> &weights);
  template <class T>
  void require_weighted_sum_(const std::string &function_name,
                             std::vector<T> &texts,
                             const std::vector<double> &weights);
  template <typename T>
  UnitCiphertext *evaluate_polynomial_(UnitCiphertext *unit_ciphertext,
                                       std::vector<T> &coefficients,
                                       RelinearizationKey *relinearization_key);
  template <typename T>
  Ciphertext *evaluate_polynomial_(Ciphertext *ciphertext,
                                   std::vector<T> &coefficients,
                                   RelinearizationKey *relinearization_key);
  template <class T>
  void require_evaluate_polynomial_(const std::string &function_name, T *text,
                                    std::vector<int64_t> &coefficients,
                                    RelinearizationKey *relinearization_key);
  template <class T>
  void require_evaluate_polynomial_(const std::string &function_name, T *text,
                                    std::vector<double> &coefficients,
                                    RelinearizationKey *relinearization_key);
  template <typename T>
  UnitCiphertext *
  evaluate_chebyshev_polynomial_(UnitCiphertext *unit_ciphertext,
                                 std::vector<T> &coefficients,
                                 RelinearizationKey *relinearization_key);
  template <typename T>
  Ciphertext *
  evaluate_chebyshev_polynomial_(Ciphertext *ciphertext,
                                 std::vector<T> &coefficients,
                                 RelinearizationKey *relinearization_key);
  template <class T, class U>
  void require_evaluate_chebyshev_polynomial_(
      const std::string &function_name, T *text, std::vector<U> &coefficients,
      RelinearizationKey *relinearization_key);

  void require_rotate_sum_(const std::string &function_name,
                           Ciphertext *ciphertext, RotationKey *rotation_key);

  int get_max_key_switching_level() const;

  std::unique_ptr<CKKSCore> core_;
};

}
