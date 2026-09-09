#include <complex>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <tuple>
#include <vector>

#ifdef DESILO_FHE_DEBUG
#include <stdio.h>
#endif

#include "ckks/config.h"
#include "ckks/parameters.h"
#include "ckks/partition_cache.h"
#include "ckks/precomputed.h"
#include "ckks/requirement.h"
#include "data/data.h"
#include "data/polynomial.h"
#include "parameter/partition.h"
#include "processor/parallel.h"
#include "processor/single.h"
#include "random/random_number_generator.h"

#pragma once

namespace desilo::fhe {

class CKKSCore {
public:
  CKKSCore(const CKKSConfig &config = {});

  void run();
  void reset_stream();

  SecretKey *create_secret_key(int level);
  SecretKey *create_secret_key(std::vector<int64_t> &secret, int level);
  SecretKey *create_sparse_secret_key(int hamming_weight, int level);

  PublicKey *create_public_key(SecretKey *secret_key, int level);

  ConjugationKey *create_conjugation_key(SecretKey *secret_key, int level);

  RelinearizationKey *create_relinearization_key(SecretKey *secret_key,
                                                 int level);

  FixedRotationKey *create_fixed_rotation_key(SecretKey *secret_key, int level,
                                              int delta);

  RotationKey *create_rotation_key(SecretKey *secret_key, int level);

  KeySwitchingKey *create_key_switching_key(SecretKey *secret_key_from,
                                            SecretKey *secret_key_to,
                                            int level);

  UnitPlaintext *encode(double *input, int level, bool include_special);
  UnitPlaintext *encode(std::complex<double> *input, int level,
                        bool include_special);
  UnitPlaintext *encode(std::vector<double> &input, int level,
                        bool include_special);
  UnitPlaintext *encode(std::vector<std::complex<double>> &input, int level,
                        bool include_special);

  UnitPlaintext *encode_imaginary(int64_t input, int level);

  template <typename T>
  std::vector<T> pad(std::vector<T> &input, int slot_count);

  template <typename T> std::vector<T> pad(std::vector<T> &input);
  double *pad(double *input, int input_size);
  std::complex<double> *pad(std::complex<double> *input, int input_size);
  void decode_to_buffer(UnitPlaintext *input, double *output);
  std::vector<double> decode(UnitPlaintext *input);
  void decode_complex_plaintext_to_buffer(UnitPlaintext *input,
                                          std::complex<double> *output);
  std::vector<std::complex<double>>
  decode_complex_plaintext(UnitPlaintext *input);

  UnitCiphertext *encrypt(UnitPlaintext *plaintext, PublicKey *public_key);
  UnitCiphertext *encrypt(UnitPlaintext *plaintext, SecretKey *secret_key);
  UnitPlaintext *decrypt_duo(UnitCiphertext *ciphertext, SecretKey *secret_key);
  UnitPlaintext *decrypt_trio(UnitCiphertext *ciphertext,
                              SecretKey *secret_key);
  UnitCiphertext *add(UnitCiphertext *ciphertext1, UnitCiphertext *ciphertext2);
  UnitCiphertext *add_trio_and_duo(UnitCiphertext *trio_ciphertext,
                                   UnitCiphertext *duo_ciphertext);
  UnitCiphertext *add(UnitCiphertext *ciphertext, double value);
  UnitCiphertext *add(UnitCiphertext *ciphertext, UnitPlaintext *plaintext);
  void add_inplace(UnitCiphertext *ciphertext1, UnitCiphertext *ciphertext2);
  void add_inplace(UnitCiphertext *ciphertext, double value);
  void add_inplace(UnitCiphertext *ciphertext, UnitPlaintext *plaintext);

  UnitCiphertext *subtract(UnitCiphertext *ciphertext1,
                           UnitCiphertext *ciphertext2);
  UnitCiphertext *subtract_trio_by_duo(UnitCiphertext *trio_ciphertext,
                                       UnitCiphertext *duo_ciphertext);
  UnitCiphertext *subtract_duo_by_trio(UnitCiphertext *duo_ciphertext,
                                       UnitCiphertext *trio_ciphertext);
  UnitCiphertext *subtract(UnitCiphertext *ciphertext,
                           UnitPlaintext *plaintext);
  UnitCiphertext *subtract(UnitPlaintext *plaintext,
                           UnitCiphertext *ciphertext);
  void subtract_inplace(UnitCiphertext *ciphertext1,
                        UnitCiphertext *ciphertext2);
  void subtract_inplace(UnitCiphertext *ciphertext, UnitPlaintext *plaintext);

  UnitCiphertext *multiply(UnitCiphertext *ciphertext, double value);
  UnitCiphertext *multiply(UnitCiphertext *ciphertext, int64_t value);
  UnitCiphertext *multiply(UnitCiphertext *ciphertext,
                           UnitPlaintext *plaintext);
  UnitCiphertext *multiply(UnitCiphertext *ciphertext1,
                           UnitCiphertext *ciphertext2);
  UnitCiphertext *square(UnitCiphertext *ciphertext);

  double *extract_diagonals(double *matrix, int outer_loop_count,
                            int inner_loop_count);
  double *extract_diagonals(std::vector<double> &matrix, int outer_loop_count,
                            int inner_loop_count);
  std::complex<double> *extract_diagonals(std::complex<double> *matrix,
                                          int outer_loop_count,
                                          int inner_loop_count);
  std::complex<double> *
  extract_diagonals(std::vector<std::complex<double>> &matrix,
                    int outer_loop_count, int inner_loop_count);

  UnitPlaintext *rescale(UnitPlaintext *plaintext);
  UnitCiphertext *rescale(UnitCiphertext *ciphertext);
  UnitCiphertext *relinearize(UnitCiphertext *ciphertext,
                              RelinearizationKey *relinearization_key);

  UnitPlaintext *conjugate_intt_form(UnitPlaintext *plaintext);
  UnitPlaintext *conjugate_ntt_form(UnitPlaintext *plaintext);
  UnitCiphertext *conjugate(UnitCiphertext *ciphertext,
                            const ConjugationKey *conjugation_key);
  UnitPlaintext *rotate_intt_form(UnitPlaintext *plaintext, int delta);
  UnitPlaintext *rotate_ntt_form(UnitPlaintext *plaintext, int delta);
  UnitCiphertext *rotate(UnitCiphertext *ciphertext,
                         const FixedRotationKey *fixed_rotation_key);
  UnitCiphertext *rotate(UnitCiphertext *ciphertext,
                         DecomposedUnitCiphertext *decomposed_ciphertext,
                         const FixedRotationKey *fixed_rotation_key);
  UnitCiphertext *ntt_rotate(UnitCiphertext *ciphertext,
                             DecomposedUnitCiphertext *decomposed_ciphertext,
                             const FixedRotationKey *fixed_rotation_key,
                             PermutationParameters *ntt_permutation_parameters);
  UnitCiphertext *switch_key(UnitCiphertext *ciphertext,
                             KeySwitchingKey *key_switching_key);

  KeySwitcher *create_key_switcher_for_rotate(
      UnitCiphertext *ciphertext,
      DecomposedUnitCiphertext *decomposed_ciphertext,
      const FixedRotationKey *fixed_rotation_key);
  UnitCiphertext *key_switch_mod_down(UnitCiphertext *ciphertext,
                                      KeySwitcher *key_switcher);

  template <class T> T *level_down_after_rescale(T *text, int level);
  template <class T> T *level_down(T *text, int level);
  UnitCiphertext *negate(UnitCiphertext *ciphertext);

  UnitPlaintext *clone(UnitPlaintext *plaintext);
  UnitCiphertext *clone(UnitCiphertext *ciphertext);

  UnitCiphertext *to_ntt_form(UnitCiphertext *ciphertext);
  UnitPlaintext *to_ntt_form(UnitPlaintext *plaintext);
  UnitCiphertext *to_intt_form(UnitCiphertext *ciphertext);
  UnitPlaintext *to_intt_form(UnitPlaintext *plaintext);

  UnitPlaintext *attach_special_prime_chains(UnitPlaintext *plaintext);
  UnitCiphertext *attach_special_prime_chains(UnitCiphertext *ciphertext);
  UnitPlaintext *remove_special_prime_chains(UnitPlaintext *plaintext);
  UnitCiphertext *remove_special_prime_chains(UnitCiphertext *ciphertext);

  DecomposedUnitCiphertext *decompose(UnitCiphertext *ciphertext);
  DecomposedUnitCiphertext *mod_down_then_decompose(UnitCiphertext *ciphertext);
  KeySwitcher *
  create_key_switcher(DecomposedUnitCiphertext *decomposed_ciphertext,
                      KeySwitchingKey *key_switching_key);
  PermutationParameters *make_ntt_permutation_parameters(int delta);

  UnitCiphertext *make_signed_tile(UnitCiphertext *ciphertext);
  int64_t get_mod_raise_ratio();
  int64_t get_normalize_ratio();

  int get_slot_count() const { return precomputed_.slot_count_; };
  int get_log_slot_count() const { return precomputed_.log_slot_count_; };
  int get_coeff_count() const { return precomputed_.coeff_count_; };
  int get_chain_count(int moduli_id = 0, bool include_special = false) const {
    return parameters_.get_chain_count(moduli_id, include_special);
  };
  std::tuple<int, int, int> get_parameter() const {
    return std::make_tuple(precomputed_.log_slot_count_,
                           precomputed_.log_coeff_count_,
                           precomputed_.special_prime_count_);
  };
  int get_prime_count(int moduli_id = 0) const {
    bool include_special = true;
    return get_chain_count(moduli_id, include_special);
  };

  const CKKSParameters parameters_;

private:
  CKKSPrecomputed precomputed_;
  PartitionsCache partitions_cache_;
  RandomNumberGenerator rng_;

  std::unique_ptr<SingleProcessor> single_processor_ = nullptr;
  std::unique_ptr<ParallelProcessor> parallel_processor_ = nullptr;
  const bool parallel_enabled_ =
      parameters_.get_processor() == EngineProcessor::CPU_PARALLEL &&
      parameters_.get_thread_count() > 1;
  int stream_index_ = 0;

  void run_parallel();
  void set_stream(int stream_index);

  int to_moduli_id(int level) const;
  int to_ntt_moduli_id(int level) const;
  int to_key_moduli_id(int level) const;
  int to_key_ntt_moduli_id(int level) const;
  int get_chain_offset(int from_moduli_id, int to_moduli_id) const;

  template <class T>
  std::tuple<T *, PermutationParameters *, PermutationParameters *>
  rotate(T *secret_key, int delta, bool invert_delta = false);

  template <typename T>
  DoublePolynomial *encode_to_double_(T &input, double deviation);
  template <typename T> DataFlag get_complex_flag();
  template <typename T>
  UnitPlaintext *encode_polynomial(T &input, int level, bool include_special);
  std::tuple<DoublePolynomial *, long double>
  convert_plaintext_to_double(UnitPlaintext *input);
  template <typename T>
  void decode_(DoublePolynomial *input, T *output, long double scale);

  template <typename T> T *rescale_(T *input);
  template <class T>
  T *rotate_(T *text, const PermutationParameters *permutation,
             const PermutationParameters *sign);
  template <class T> T *rotate_intt_form_(T *text, int delta);
  template <class T> T *rotate_ntt_form_(T *text, int delta);

  template <typename T> T *to_ntt_form_(T *input);
  template <typename T> T *to_intt_form_(T *input);

  template <typename T> T *attach_special_prime_chains_(T *input);
  template <typename T> T *remove_special_prime_chains_(T *input);

  void mont_enter_(PolynomialInterface *x, PolynomialInterface *y,
                   const int64_t *constant, int moduli_id, int chain_count,
                   int x_offset = 0, int y_offset = 0,
                   int parameter_offset = 0);
  void mont_enter_(PolynomialInterface *x, PolynomialInterface *y,
                   int moduli_id, int chain_count);
  void mont_enter_(PolynomialInterface *x, PolynomialInterface *y,
                   int moduli_id);
  void mont_enter_with_coeff_count_(PolynomialInterface *x,
                                    PolynomialInterface *y,
                                    const int64_t *constant, int moduli_id,
                                    int chain_count, int x_coeff_count,
                                    int x_offset, int y_offset,
                                    int parameter_offset);
  void mont_enter_scalar_(PolynomialInterface *x, PolynomialInterface *y,
                          const int64_t *scalar, int moduli_id,
                          int x_offset = 0);
  void mont_enter_rescale_(PolynomialInterface *x, PolynomialInterface *y,
                           int moduli_id, int chain_count);
  void make_signed_(PolynomialInterface *x, PolynomialInterface *y,
                    int moduli_id);
  void make_signed_with_coeff_count_(PolynomialInterface *x,
                                     PolynomialInterface *y, int moduli_id,
                                     int x_coeff_count);
  void mont_add_(PolynomialInterface *x1, PolynomialInterface *x2,
                 PolynomialInterface *y, int moduli_id, int chain_count);
  void mont_mult_(PolynomialInterface *x1, PolynomialInterface *x2,
                  PolynomialInterface *y, int moduli_id, int chain_count,
                  int x1_offset, int x2_offset);
  void mont_mult_(PolynomialInterface *x1, PolynomialInterface *x2,
                  PolynomialInterface *y, int moduli_id, int x1_offset = 0,
                  int x2_offset = 0);
  void reduce_2q_to_q_(PolynomialInterface *x, PolynomialInterface *y,
                       int moduli_id, int chain_count);
  void reduce_2q_to_q_(PolynomialInterface *x, PolynomialInterface *y,
                       int moduli_id);
  void get_rounder_(PolynomialInterface *x, PolynomialInterface *y,
                    int moduli_id, int x_offset = 0, int parameter_offset = 0);
  void sub_tiled_(PolynomialInterface *x1, PolynomialInterface *x2,
                  PolynomialInterface *y, int moduli_id, int chain_count,
                  int x1_offset, int y_offset = 0, int parameter_offset = 0);
  void add_tiled_(PolynomialInterface *x1, PolynomialInterface *x2,
                  PolynomialInterface *y, int moduli_id, int chain_count);

  void mont_enter_tiled_from_(PolynomialInterface *x, PolynomialInterface *y,
                              int moduli_id, int chain_start, int chain_count,
                              int x_offset, int y_offset);
  void mont_enter_tiled_(PolynomialInterface *x, PolynomialInterface *y,
                         int moduli_id, int chain_count, int x_offset = 0,
                         int y_offset = 0);
  void mont_enter_tiled_add_from_(PolynomialInterface *x,
                                  PolynomialInterface *y,
                                  const int64_t *constant, int moduli_id,
                                  int chain_start, int chain_count,
                                  int x_offset, int y_offset);
  void mont_enter_tiled_add_(PolynomialInterface *x, PolynomialInterface *y,
                             const int64_t *constant, int moduli_id,
                             int chain_count, int x_offset, int y_offset = 0);
  void mont_enter_tiled_add_reduce_2q_to_q_from_(PolynomialInterface *x,
                                                 PolynomialInterface *y,
                                                 const int64_t *constant,
                                                 int moduli_id, int chain_start,
                                                 int chain_count, int x_offset,
                                                 int y_offset);
  void mont_mult_add_(PolynomialInterface *x1, PolynomialInterface *x2,
                      PolynomialInterface *y, int moduli_id, int chain_count,
                      int x1_offset, int x2_offset);
  void mont_sub_enter_reduce_2q_to_q_from_(
      PolynomialInterface *x1, PolynomialInterface *x2, PolynomialInterface *y,
      const int64_t *constant, int moduli_id, int chain_start, int chain_count,
      int x1_offset, int x2_offset, int y_offset);
  void mont_sub_tiled_enter_(PolynomialInterface *x1, PolynomialInterface *x2,
                             PolynomialInterface *y, const int64_t *constant,
                             int moduli_id, int chain_count, int x1_offset,
                             int x2_offset, int y_offset = 0,
                             int parameter_offset = 0);
  void mont_enter_exit_(PolynomialInterface *x, PolynomialInterface *y,
                        int moduli_id, int chain_count);
  void mont_enter_exit_(PolynomialInterface *x, PolynomialInterface *y,
                        int moduli_id);
  void mont_enter_exit_reduce_2q_to_q_(PolynomialInterface *x,
                                       PolynomialInterface *y, int moduli_id,
                                       int chain_count);
  void mont_add_reduce_2q_to_q_from_(PolynomialInterface *x1,
                                     PolynomialInterface *x2,
                                     PolynomialInterface *y, int moduli_id,
                                     int chain_start, int chain_count,
                                     int x1_offset, int x2_offset,
                                     int y_offset);
  void mont_add_reduce_2q_to_q_(PolynomialInterface *x1,
                                PolynomialInterface *x2, PolynomialInterface *y,
                                int moduli_id, int chain_count,
                                int x1_offset = 0, int x2_offset = 0,
                                int y_offset = 0);
  void mont_add_reduce_2q_to_q_(PolynomialInterface *x1,
                                PolynomialInterface *x2, PolynomialInterface *y,
                                int moduli_id);
  void mont_sub_reduce_2q_to_q_(PolynomialInterface *x1,
                                PolynomialInterface *x2, PolynomialInterface *y,
                                int moduli_id, int chain_count);
  void mont_sub_reduce_2q_to_q_(PolynomialInterface *x1,
                                PolynomialInterface *x2, PolynomialInterface *y,
                                int moduli_id);
  void make_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                     PolynomialInterface *y, int moduli_id,
                                     int chain_count);
  void make_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                     PolynomialInterface *y, int moduli_id);
  void make_unsigned_reduce_2q_to_q_with_coeff_count_(PolynomialInterface *x,
                                                      PolynomialInterface *y,
                                                      int moduli_id,
                                                      int chain_count,
                                                      int x_coeff_count);
  void tile_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                     PolynomialInterface *y, int moduli_id,
                                     int chain_count, int x_offset = 0,
                                     int y_offset = 0);
  void tile_unsigned_reduce_2q_to_q_(PolynomialInterface *x,
                                     PolynomialInterface *y, int moduli_id);
  void tile_unsigned_reduce_2q_to_q_with_coeff_count_(
      PolynomialInterface *x, PolynomialInterface *y, int moduli_id,
      int chain_count, int x_coeff_count, int x_offset, int y_offset);

  template <typename T> DoublePolynomial *permute_for_fft_(T *x);
  void bit_reversal_permute_(std::complex<double> *x);
  DoublePolynomial *apply_twister_(DoublePolynomial *x, double scale);
  DoublePolynomial *apply_skewer_(DoublePolynomial *x);
  void double_to_rns_(double *x, Polynomial *y, int moduli_id, int chain_count,
                      int y_offset);
  void rns_to_double_(Polynomial *x, double *y,
                      DecodeParameters &decode_parameters, int moduli_id,
                      int chain_count);
  template <typename T>
  void permute_after_ifft_(double *x, T *y, long double scale);

  void fft_(std::complex<double> *x, std::complex<double> *y);
  void ifft_(std::complex<double> *x, std::complex<double> *y);
  void normalize_(double *x, double *y);

  void ntt_from_(PolynomialInterface *x, PolynomialInterface *y, int moduli_id,
                 int chain_start, int chain_count, int x_offset, int y_offset);
  void ntt_(PolynomialInterface *x, PolynomialInterface *y, int moduli_id,
            int chain_count, int x_offset = 0, int y_offset = 0);
  void ntt_(PolynomialInterface *x, PolynomialInterface *y, int moduli_id);
  void ntt_inplace_(PolynomialInterface *x, int moduli_id) {
    ntt_(x, x, moduli_id);
  };
  void intt_(PolynomialInterface *x, PolynomialInterface *y, int moduli_id,
             int chain_count, int x_offset = 0, int y_offset = 0);
  void intt_(PolynomialInterface *x, PolynomialInterface *y, int moduli_id);
  void intt_inplace_(PolynomialInterface *x, int moduli_id) {
    intt_(x, x, moduli_id);
  };

  void to_ntt_(Polynomial *x, Polynomial *y, int ntt_moduli_id);
  void to_intt_(Polynomial *x, Polynomial *y, int intt_moduli_id);

  void spread_flexible_chain_(Polynomial *x, Polynomial *y, int ntt_moduli_id,
                              bool copy_other_chains, int x_offset = 0,
                              int y_offset = 0);
  void gather_flexible_chain_(Polynomial *x, Polynomial *y, int ntt_moduli_id,
                              bool copy_other_chains, int x_offset = 0,
                              int y_offset = 0);
  void reset_ntt_flexible_chain_(Polynomial *x, int ntt_moduli_id);

  void rotate_polynomial_(Polynomial *x, Polynomial *y,
                          const int32_t *permutation, const int32_t *sign,
                          int chain_count, int coeff_count);
  void permute_polynomial_(Polynomial *x, Polynomial *y,
                           const int32_t *permutation, int chain_count,
                           int coeff_count);
  void negate_make_unsigned_(PolynomialInterface *x, PolynomialInterface *y,
                             int moduli_id);
  void concatenate_tile_unsigned_(PolynomialInterface *x1,
                                  PolynomialInterface *x2,
                                  PolynomialInterface *y, int moduli_id);

  void add_scalar_(PolynomialInterface *x, PolynomialInterface *y,
                   const int64_t *scalar, int chain_count, int coeff_count);

  Polynomial *get_single_error();
  Polynomial *get_integer_chain(int64_t max_value, int shift);
  Polynomial *get_binary();
  Polynomial *get_ternary();
  Polynomial *get_sparse_ternary(const int hamming_weight);
  void assign_a(Polynomial *output, int moduli_id,
                bool include_special = false);

  template <class T>
  T *allocate_data(const DataFlag flag, int moduli_id, int polynomial_count);
  template <class T>
  T *allocate_text(const DataFlag flag, int moduli_id, int polynomial_count,
                   long double ckks_scale);
  Polynomial *allocate_polynomial_(int moduli_id, int chain_count,
                                   DataFlag flag, int coeff_count);
  Polynomial *allocate_polynomial_(int moduli_id, int chain_count,
                                   DataFlag flag);
  Polynomial *allocate_polynomial(int moduli_id);
  Polynomial *allocate_extended_polynomial(int moduli_id);
  Polynomial *allocate_mrs_polynomial();
  Polynomial *allocate_polynomial();
  DoublePolynomial *allocate_double_polynomial(int coeff_count);
  DoublePolynomial *allocate_double_polynomial();
  ComplexDoublePolynomial *allocate_complex_double_polynomial(int coeff_count);
  void copy_single_chain_to_polynomial(int64_t *x, Polynomial *y);

  template <class T> void release(T *resource);
  void copy(PolynomialInterface *x, PolynomialInterface *y, int chain_count,
            int x_offset = 0, int y_offset = 0);
  void decompress_polynomial(PolynomialInterface *x, PolynomialInterface *y,
                             int chain_count);
  void compress_polynomial(PolynomialInterface *x, PolynomialInterface *y,
                           int chain_count);
  void zero_fill(PolynomialInterface *x, int chain_count, int x_offset = 0);
  void zero_fill_with_coeff_count(PolynomialInterface *x, int chain_count,
                                  int coeff_count, int x_offset);
  void round_(DoublePolynomial *x, Polynomial *y, int chain_count = 1);
  void max_absolute_(DoublePolynomial *x, double *y);
  void cast_int64_to_double_(Polynomial *x, DoublePolynomial *y,
                             int chain_count);
  Polynomial *get_polynomial(Data *data, int index);
  PolynomialView *get_polynomial_view(Data *data, int index, int moduli_id);
  std::tuple<Polynomial *, Polynomial *> get_duo_polynomials(Data *data);
  std::tuple<PolynomialView *, PolynomialView *>
  get_duo_polynomial_views(Data *data, int moduli_id);
  std::tuple<Polynomial *, Polynomial *, Polynomial *>
  get_trio_polynomials(Data *data);
  PolynomialView *get_key_polynomial_view(Data *key, int index, int moduli_id);

  void rescale_once_(Polynomial *x, Polynomial *y, int moduli_id,
                     bool include_special);
  void rescale_twice_(Polynomial *x, Polynomial *y, int moduli_id,
                      bool include_special);
  void rescale_(Polynomial *x, Polynomial *y, int moduli_id,
                bool include_special);
  template <typename T> long double get_rescaled_scale(T *input);

  std::vector<Partition> &get_partitions(int ciphertext_moduli_id,
                                         int key_moduli_id);

  std::vector<Partition> &get_partitions(int moduli_id) {
    return get_partitions(moduli_id, moduli_id);
  };
  std::vector<CKKSPartitionParameters> *
  get_partition_parameters(int ciphertext_moduli_id, int key_moduli_id);
  void rns_to_mrs(Polynomial *x, Polynomial *y, const Partition *partition,
                  CKKSPartitionParameters &parameter, int moduli_id);
  void mod_up_single(Polynomial *x_ntt, Polynomial *x_intt, Polynomial *y,
                     int partition_start, int moduli_id, int chain_count);
  void mod_up_single(Polynomial *x, Polynomial *y, int partition_start,
                     int key_moduli_id);
  void mod_up(Polynomial *x, Polynomial *y, int partition_start,
              int partition_size, CKKSPartitionParameters &parameter,
              int key_moduli_id);
  void mod_down(Polynomial *x, Polynomial *y,
                std::vector<const int64_t *> &p_inverse_mult_r,
                bool can_modify_x);
  KeySwitcher *create_key_switcher(
      Polynomial *x, KeySwitchingKey *key_switch_key,
      std::vector<Partition> &partitions, int key_moduli_id,
      std::vector<const int64_t *> &p_inverse_mult_r, int chain_count,
      std::vector<CKKSPartitionParameters> *partition_parameters);
  KeySwitcher *create_key_switcher_single(
      Polynomial *x_ntt, Polynomial *x_intt, KeySwitchingKey *key_switching_key,
      std::vector<Partition> &partitions, int key_moduli_id,
      std::vector<const int64_t *> &p_inverse_mult_r, int chain_count);
  KeySwitcher *
  create_key_switcher_single(Polynomial *x, KeySwitchingKey *key_switching_key,
                             std::vector<Partition> &partitions,
                             int key_moduli_id,
                             std::vector<const int64_t *> &p_inverse_mult_r);
  KeySwitcher *create_key_switcher_single_from_ntt(
      Polynomial *x_ntt, KeySwitchingKey *key_switching_key, int moduli_id);
  KeySwitcher *create_key_switcher_single_from_key(
      Polynomial *x_key, KeySwitchingKey *key_switching_key, int key_moduli_id);
  KeySwitcher *create_key_switcher_from_ntt(Polynomial *x_ntt,
                                            KeySwitchingKey *key_switch_key,
                                            int ntt_moduli_id);
  KeySwitcher *create_key_switcher_from_intt(Polynomial *x_intt,
                                             KeySwitchingKey *key_switch_key,
                                             int intt_moduli_id);

#ifdef DESILO_FHE_DEBUG
  inline void print_data_buffer(const int64_t *buffer, int chain_count = 2) {
    const auto coeff_count = precomputed_.coeff_count_;

    for (auto chain_index = 0; chain_index < chain_count; chain_index++) {
      const auto chain_buffer = &buffer[chain_index * coeff_count];
      printf("%20ld %20ld %20ld %20ld\n", chain_buffer[0], chain_buffer[1],
             chain_buffer[2], chain_buffer[3]);
    }
  }
#endif
};

}
