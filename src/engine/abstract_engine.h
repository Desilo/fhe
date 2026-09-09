#include <complex>
#include <string>
#include <vector>

#include "data/bootstrap.h"
#include "data/data.h"

#pragma once

namespace desilo::fhe {

class AbstractEngine {
public:
  virtual ~AbstractEngine() = default;

  virtual SecretKey *create_secret_key() = 0;
  virtual SecretKey *create_secret_key(int level) = 0;
  virtual SecretKey *create_secret_key(std::vector<int64_t> &secret) = 0;
  virtual SecretKey *create_secret_key(std::vector<int64_t> &secret,
                                       int level) = 0;
  virtual PublicKey *create_public_key(SecretKey *secret_key) = 0;
  virtual PublicKey *create_public_key(SecretKey *secret_key, int level) = 0;

  virtual ConjugationKey *create_conjugation_key(SecretKey *secret_key) = 0;
  virtual ConjugationKey *create_conjugation_key(SecretKey *secret_key,
                                                 int level) = 0;

  virtual RelinearizationKey *
  create_relinearization_key(SecretKey *secret_key) = 0;
  virtual RelinearizationKey *create_relinearization_key(SecretKey *secret_key,
                                                         int level) = 0;

  virtual FixedRotationKey *create_fixed_rotation_key(SecretKey *secret_key,
                                                      int delta) = 0;
  virtual FixedRotationKey *create_fixed_rotation_key(SecretKey *secret_key,
                                                      int level, int delta) = 0;

  virtual RotationKey *create_rotation_key(SecretKey *secret_key) = 0;
  virtual RotationKey *create_rotation_key(SecretKey *secret_key,
                                           int level) = 0;
  virtual BootstrapKey *create_bootstrap_key(SecretKey *secret_key,
                                             int stage_count,
                                             const std::string &size) = 0;
  virtual SmallBootstrapKey *
  create_small_bootstrap_key(SecretKey *secret_key) = 0;

  virtual Plaintext *encode(std::vector<double> &input) = 0;
  virtual Plaintext *encode(std::vector<double> &input, int level) = 0;
  virtual Plaintext *encode(std::vector<std::complex<double>> &input) = 0;
  virtual Plaintext *encode(std::vector<std::complex<double>> &input,
                            int level) = 0;

  virtual std::vector<double> decode(Plaintext *plaintext) = 0;
  virtual std::vector<std::complex<double>>
  decode_complex_plaintext(Plaintext *plaintext) = 0;

  virtual Ciphertext *encrypt(std::vector<double> &input,
                              PublicKey *public_key) = 0;
  virtual Ciphertext *encrypt(std::vector<double> &input, PublicKey *public_key,
                              int level) = 0;
  virtual Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                              PublicKey *public_key) = 0;
  virtual Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                              PublicKey *public_key, int level) = 0;
  virtual Ciphertext *encrypt(Plaintext *plaintext, PublicKey *public_key) = 0;

  virtual Ciphertext *encrypt(std::vector<double> &input,
                              SecretKey *secret_key) = 0;
  virtual Ciphertext *encrypt(std::vector<double> &input, SecretKey *secret_key,
                              int level) = 0;
  virtual Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                              SecretKey *secret_key) = 0;
  virtual Ciphertext *encrypt(std::vector<std::complex<double>> &input,
                              SecretKey *secret_key, int level) = 0;
  virtual Ciphertext *encrypt(Plaintext *plaintext, SecretKey *secret_key) = 0;

  virtual std::vector<double> decrypt(Ciphertext *ciphertext,
                                      SecretKey *secret_key) = 0;
  virtual std::vector<std::complex<double>>
  decrypt_complex(Ciphertext *ciphertext, SecretKey *secret_key) = 0;
  virtual void decrypt_to_buffer(Ciphertext *ciphertext, double *output,
                                 SecretKey *secret_key) = 0;
  virtual void decrypt_to_complex_buffer(Ciphertext *ciphertext,
                                         std::complex<double> *output,
                                         SecretKey *secret_key) = 0;
  virtual Plaintext *decrypt_to_plaintext(Ciphertext *ciphertext,
                                          SecretKey *secret_key) = 0;

  virtual Ciphertext *add(Ciphertext *ciphertext1, Ciphertext *ciphertext2) = 0;
  virtual Ciphertext *add(Ciphertext *ciphertext, Plaintext *plaintext) = 0;
  virtual Ciphertext *add(Plaintext *plaintext, Ciphertext *ciphertext) = 0;
  virtual Ciphertext *add(Ciphertext *ciphertext,
                          std::vector<double> &message) = 0;
  virtual Ciphertext *add(std::vector<double> &message,
                          Ciphertext *ciphertext) = 0;
  virtual Ciphertext *add(Ciphertext *ciphertext,
                          std::vector<std::complex<double>> &message) = 0;
  virtual Ciphertext *add(std::vector<std::complex<double>> &message,
                          Ciphertext *ciphertext) = 0;
  virtual Ciphertext *add(Ciphertext *ciphertext, double *message,
                          int message_size) = 0;
  virtual Ciphertext *add(double *message, Ciphertext *ciphertext,
                          int message_size) = 0;
  virtual Ciphertext *add(Ciphertext *ciphertext, std::complex<double> *message,
                          int message_size) = 0;
  virtual Ciphertext *add(std::complex<double> *message, Ciphertext *ciphertext,
                          int message_size) = 0;
  virtual Ciphertext *add(Ciphertext *ciphertext, double value) = 0;
  virtual Ciphertext *add(double value, Ciphertext *ciphertext) = 0;
  virtual void add_inplace(Ciphertext *ciphertext1,
                           Ciphertext *ciphertext2) = 0;
  virtual void add_inplace(Ciphertext *ciphertext, Plaintext *plaintext) = 0;
  virtual void add_inplace(Plaintext *plaintext, Ciphertext *ciphertext) = 0;

  virtual UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext1,
                                   UnitCiphertext *unit_ciphertext2) = 0;
  virtual UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext,
                                   UnitPlaintext *unit_plaintext) = 0;
  virtual UnitCiphertext *subtract(UnitPlaintext *unit_plaintext,
                                   UnitCiphertext *unit_ciphertext) = 0;
  virtual UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext,
                                   std::vector<double> &message) = 0;
  virtual UnitCiphertext *subtract(std::vector<double> &message,
                                   UnitCiphertext *unit_ciphertext) = 0;
  virtual UnitCiphertext *
  subtract(UnitCiphertext *unit_ciphertext,
           std::vector<std::complex<double>> &message) = 0;
  virtual UnitCiphertext *subtract(std::vector<std::complex<double>> &message,
                                   UnitCiphertext *unit_ciphertext) = 0;
  virtual UnitCiphertext *subtract(UnitCiphertext *unit_ciphertext,
                                   double value) = 0;
  virtual UnitCiphertext *subtract(double value,
                                   UnitCiphertext *unit_ciphertext) = 0;

  virtual Ciphertext *subtract(Ciphertext *ciphertext1,
                               Ciphertext *ciphertext2) = 0;
  virtual Ciphertext *subtract(Ciphertext *ciphertext,
                               Plaintext *plaintext) = 0;
  virtual Ciphertext *subtract(Plaintext *plaintext,
                               Ciphertext *ciphertext) = 0;
  virtual Ciphertext *subtract(Ciphertext *ciphertext,
                               std::vector<double> &message) = 0;
  virtual Ciphertext *subtract(std::vector<double> &message,
                               Ciphertext *ciphertext) = 0;
  virtual Ciphertext *subtract(Ciphertext *ciphertext,
                               std::vector<std::complex<double>> &message) = 0;
  virtual Ciphertext *subtract(std::vector<std::complex<double>> &message,
                               Ciphertext *ciphertext) = 0;
  virtual Ciphertext *subtract(Ciphertext *ciphertext, double *message,
                               int message_size) = 0;
  virtual Ciphertext *subtract(double *message, Ciphertext *ciphertext,
                               int message_size) = 0;
  virtual Ciphertext *subtract(Ciphertext *ciphertext,
                               std::complex<double> *message,
                               int message_size) = 0;
  virtual Ciphertext *subtract(std::complex<double> *message,
                               Ciphertext *ciphertext, int message_size) = 0;
  virtual Ciphertext *subtract(Ciphertext *ciphertext, double value) = 0;
  virtual Ciphertext *subtract(double value, Ciphertext *ciphertext) = 0;
  virtual void subtract_inplace(Ciphertext *ciphertext1,
                                Ciphertext *ciphertext2) = 0;

  virtual Ciphertext *multiply(Ciphertext *ciphertext1,
                               Ciphertext *ciphertext2) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext1, Ciphertext *ciphertext2,
                               RelinearizationKey *relinearization_key) = 0;
  virtual Ciphertext *square(Ciphertext *ciphertext) = 0;
  virtual Ciphertext *square(Ciphertext *ciphertext,
                             RelinearizationKey *relinearization_key) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext,
                               Plaintext *plaintext) = 0;
  virtual Ciphertext *multiply(Plaintext *plaintext,
                               Ciphertext *ciphertext) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext,
                               std::vector<double> &message) = 0;
  virtual Ciphertext *multiply(std::vector<double> &message,
                               Ciphertext *ciphertext) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext,
                               std::vector<std::complex<double>> &message) = 0;
  virtual Ciphertext *multiply(std::vector<std::complex<double>> &message,
                               Ciphertext *ciphertext) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext, double *message,
                               int message_size) = 0;
  virtual Ciphertext *multiply(double *message, Ciphertext *ciphertext,
                               int message_size) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext,
                               std::complex<double> *message,
                               int message_size) = 0;
  virtual Ciphertext *multiply(std::complex<double> *message,
                               Ciphertext *ciphertext, int message_size) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext, double value) = 0;
  virtual Ciphertext *multiply(double value, Ciphertext *ciphertext) = 0;
  virtual Ciphertext *multiply(Ciphertext *ciphertext, int64_t value) = 0;
  virtual Ciphertext *multiply(int64_t value, Ciphertext *ciphertext) = 0;
  virtual Ciphertext *multiply_imaginary(Ciphertext *ciphertext,
                                         int64_t value) = 0;
  virtual Ciphertext *multiply_imaginary(int64_t value,
                                         Ciphertext *ciphertext) = 0;

  virtual Ciphertext *multiply_matrix(double *matrix, Ciphertext *ciphertext,
                                      RotationKey *rotation_key) = 0;
  virtual Ciphertext *multiply_matrix(std::complex<double> *matrix,
                                      Ciphertext *ciphertext,
                                      RotationKey *rotation_key) = 0;
  virtual Ciphertext *multiply_matrix(std::vector<double> &matrix,
                                      Ciphertext *ciphertext,
                                      RotationKey *rotation_key) = 0;
  virtual Ciphertext *
  multiply_matrix(std ::vector<std::complex<double>> &matrix,
                  Ciphertext *ciphertext, RotationKey *rotation_key) = 0;

  virtual Ciphertext *relinearize(Ciphertext *ciphertext,
                                  RelinearizationKey *relinearization_key) = 0;

  virtual UnitPlaintext *conjugate(UnitPlaintext *unit_plaintext) = 0;
  virtual UnitCiphertext *conjugate(UnitCiphertext *unit_ciphertext,
                                    ConjugationKey *conjugation_key) = 0;
  virtual Plaintext *conjugate(Plaintext *plaintext) = 0;
  virtual Ciphertext *conjugate(Ciphertext *ciphertext,
                                ConjugationKey *conjugation_key) = 0;

  virtual Plaintext *rotate(Plaintext *plaintext, int delta) = 0;
  virtual Ciphertext *rotate(Ciphertext *ciphertext,
                             FixedRotationKey *fixed_rotation_key) = 0;
  virtual Ciphertext *rotate(Ciphertext *ciphertext, RotationKey *rotation_key,
                             int delta) = 0;
  virtual std::vector<Ciphertext *>
  rotate_batch(Ciphertext *ciphertext,
               std::vector<FixedRotationKey *> fixed_rotation_keys) = 0;
  virtual std::vector<Ciphertext *> rotate_batch(Ciphertext *ciphertext,
                                                 RotationKey *rotation_key,
                                                 std::vector<int> deltas) = 0;

  virtual Plaintext *ntt(Plaintext *plaintext) = 0;
  virtual Ciphertext *ntt(Ciphertext *ciphertext) = 0;

  virtual Plaintext *intt(Plaintext *plaintext) = 0;
  virtual Ciphertext *intt(Ciphertext *ciphertext) = 0;

  virtual Plaintext *rescale(Plaintext *plaintext) = 0;
  virtual Ciphertext *rescale(Ciphertext *ciphertext) = 0;

  virtual Plaintext *level_down(Plaintext *plaintext, int level) = 0;
  virtual Ciphertext *level_down(Ciphertext *ciphertext, int level) = 0;

  virtual Ciphertext *negate(Ciphertext *ciphertext) = 0;

  virtual Plaintext *clone(Plaintext *plaintext) = 0;
  virtual Ciphertext *clone(Ciphertext *ciphertext) = 0;

  virtual Ciphertext *
  bootstrap(Ciphertext *ciphertext, RelinearizationKey *relinearization_key,
            ConjugationKey *conjugation_key, RotationKey *rotation_key,
            SmallBootstrapKey *small_bootstrap_key, int stage_count) = 0;
  virtual Ciphertext *bootstrap(Ciphertext *ciphertext,
                                RelinearizationKey *relinearization_key,
                                ConjugationKey *conjugation_key,
                                BootstrapKey *bootstrap_key) = 0;
  virtual Ciphertext *mod_raise(Ciphertext *ciphertext,
                                SmallBootstrapKey *small_bootstrap_key) = 0;
  virtual Ciphertext *mod_raise(Ciphertext *ciphertext,
                                BootstrapKey *bootstrap_key) = 0;

  virtual std::vector<Ciphertext *>
  make_power_basis(Ciphertext *ciphertext, int max_power,
                   RelinearizationKey *relinearization_key) = 0;
  virtual std::vector<Ciphertext *>
  make_chebyshev_basis(Ciphertext *ciphertext, int max_power,
                       RelinearizationKey *relinearization_key) = 0;
  virtual Ciphertext *weighted_sum(std::vector<Ciphertext *> &ciphertexts,
                                   std::vector<int64_t> &weights) = 0;
  virtual Ciphertext *weighted_sum(std::vector<Ciphertext *> &ciphertexts,
                                   std::vector<double> &weights) = 0;
  virtual Ciphertext *
  evaluate_polynomial(Ciphertext *ciphertext,
                      std::vector<int64_t> &coefficients,
                      RelinearizationKey *relinearization_key) = 0;
  virtual Ciphertext *
  evaluate_polynomial(Ciphertext *ciphertext, std::vector<double> &coefficients,
                      RelinearizationKey *relinearization_key) = 0;
  virtual Ciphertext *
  evaluate_chebyshev_polynomial(Ciphertext *ciphertext,
                                std::vector<int64_t> &coefficients,
                                RelinearizationKey *relinearization_key) = 0;
  virtual Ciphertext *
  evaluate_chebyshev_polynomial(Ciphertext *ciphertext,
                                std::vector<double> &coefficients,
                                RelinearizationKey *relinearization_key) = 0;
  virtual Ciphertext *sum_1d_by_row(Ciphertext *ciphertext,
                                    RotationKey *rotation_key) = 0;
  virtual Ciphertext *sum_1d_by_column(Ciphertext *ciphertext) = 0;
  virtual Ciphertext *sum_2d(Ciphertext *ciphertext,
                             RotationKey *rotation_key) = 0;
  virtual Ciphertext *stack_by_row(std::vector<Ciphertext *> &ciphertexts) = 0;

  virtual int get_slot_count() const = 0;
  virtual int get_max_level() const = 0;
  virtual std::string get_mode() const = 0;
};

}
