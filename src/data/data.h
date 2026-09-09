#include <cstddef>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <map>
#include <vector>

#include "arithmetic/arithmetic.h"
#include "data/bytearray.h"
#include "data/flag.h"
#include "data/polynomial.h"
#include "data/type.h"
#include "engine/scheme_preset.h"
#include "parameter/partition.h"
#include "parameter/permutation.h"

#pragma once

namespace desilo::fhe {

inline uint32_t to_level(SchemePreset scheme_preset, DataFlag flag,
                         int chain_count, int special_prime_count) {
  if (includes_special(flag)) {
    chain_count -= special_prime_count;
  }

  if (!is_rescaled(flag)) {
    return chain_count - 2;
  } else {
    return chain_count - 1;
  }
}

class DataInterface {
public:
  virtual DataFlag flag() const = 0;
  virtual SchemePreset scheme_preset() const = 0;
  virtual uint8_t log_slot_count() const = 0;
  virtual uint8_t log_coeff_count() const = 0;
  virtual uint8_t special_prime_count() const = 0;
  virtual uint16_t moduli_id() const = 0;
  virtual uint8_t level() const = 0;
  virtual uint32_t polynomial_count() const = 0;
};

class TextInterface : virtual public DataInterface {
public:
  virtual ~TextInterface() = default;
  virtual long double ckks_scale() const = 0;
  virtual std::string type_name() const = 0;
  virtual int size() const = 0;
};

class Data : virtual public DataInterface {
public:
  Data(std::vector<Polynomial *> &polynomials, const DataType type,
       const DataFlag flag, const SchemePreset scheme_preset,
       uint8_t log_slot_count, uint8_t log_coeff_count,
       uint8_t special_prime_count, uint16_t moduli_id, uint8_t level,
       uint8_t chain_count, uint32_t coeff_count);
  virtual ~Data();

  int64_t *get(const int index, const int chain_start = 0);
  Polynomial *get_polynomial(int index);

  template <typename T> void write(T &destination);

  DataFlag flag() const { return flag_; };
  SchemePreset scheme_preset() const { return scheme_preset_; };
  uint8_t log_slot_count() const { return log_slot_count_; };
  uint8_t log_coeff_count() const { return log_coeff_count_; };
  uint8_t special_prime_count() const { return special_prime_count_; };
  uint16_t moduli_id() const { return moduli_id_; };
  uint8_t level() const { return level_; };
  uint32_t polynomial_count() const;

  virtual size_t nbytes() const;

  const DataType type_ = DataType::NONE;
  const DataFlag flag_;
  const SchemePreset scheme_preset_;
  const uint8_t log_slot_count_;
  const uint8_t log_coeff_count_;
  const uint8_t special_prime_count_;
  const uint16_t moduli_id_;
  const uint8_t level_;
  const uint8_t chain_count_;
  const uint32_t coeff_count_;

private:
  const std::vector<Polynomial *> polynomials_;
};

class SecretKey : public Data {
public:
  SecretKey(std::vector<Polynomial *> &polynomials, const DataFlag flag,
            const SchemePreset scheme_preset, const uint8_t log_slot_count,
            const uint8_t log_coeff_count, uint8_t special_prime_count,
            uint16_t moduli_id, uint8_t level, uint8_t chain_count,
            uint32_t coeff_count)
      : Data(polynomials, DataType::SECRET_KEY, flag, scheme_preset,
             log_slot_count, log_coeff_count, special_prime_count, moduli_id,
             level, chain_count, coeff_count){};
};

class PublicKey : public Data {
public:
  PublicKey(std::vector<Polynomial *> &polynomials, const DataFlag flag,
            const SchemePreset scheme_preset, const uint8_t log_slot_count,
            const uint8_t log_coeff_count, uint8_t special_prime_count,
            uint16_t moduli_id, uint8_t level, uint8_t chain_count,
            uint32_t coeff_count)
      : Data(polynomials, DataType::PUBLIC_KEY, flag, scheme_preset,
             log_slot_count, log_coeff_count, special_prime_count, moduli_id,
             level, chain_count, coeff_count){};
};

class KeySwitchingKey : public Data {
public:
  KeySwitchingKey(std::vector<Polynomial *> &polynomials, const DataFlag flag,
                  const SchemePreset scheme_preset,
                  const uint8_t log_slot_count, const uint8_t log_coeff_count,
                  uint8_t special_prime_count, uint16_t moduli_id,
                  uint8_t level, uint8_t chain_count, uint32_t coeff_count)
      : Data(polynomials, DataType::KEY_SWITCHING_KEY, flag, scheme_preset,
             log_slot_count, log_coeff_count, special_prime_count, moduli_id,
             level, chain_count, coeff_count){};

  int get_key_index(const Partition *partition, const int index);
};

class RelinearizationKey {
public:
  RelinearizationKey(KeySwitchingKey *key_switching_key)
      : key_switching_key_(key_switching_key),
        level_(key_switching_key->level_){};
  ~RelinearizationKey();

  size_t nbytes() const;

  KeySwitchingKey *const key_switching_key_;
  const int level_;
};

class FixedRotationKey {
public:
  FixedRotationKey(KeySwitchingKey *key_switching_key,
                   PermutationParameters *permutation,
                   PermutationParameters *sign, int delta)
      : key_switching_key_(key_switching_key), permutation_(permutation),
        sign_(sign), delta_(delta), level_(key_switching_key_->level_){};
  ~FixedRotationKey();

  size_t nbytes() const;

  KeySwitchingKey *const key_switching_key_;
  PermutationParameters *const permutation_;
  PermutationParameters *const sign_;
  const int delta_;
  const int level_;
};

class RotationKey {
public:
  RotationKey(std::vector<FixedRotationKey *> &fixed_rotation_keys)
      : fixed_rotation_keys_(std::move(fixed_rotation_keys)),
        level_(fixed_rotation_keys_[0]->level_){};
  ~RotationKey();

  size_t nbytes() const;

  std::vector<FixedRotationKey *> fixed_rotation_keys_;
  const int level_;
};

class ConjugationKey {
public:
  ConjugationKey(KeySwitchingKey *key_switching_key,
                 PermutationParameters *permutation,
                 PermutationParameters *sign)
      : key_switching_key_(key_switching_key), permutation_(permutation),
        sign_(sign), level_(key_switching_key_->level_){};
  ~ConjugationKey();

  size_t nbytes() const;

  KeySwitchingKey *const key_switching_key_;
  PermutationParameters *const permutation_;
  PermutationParameters *const sign_;
  const int level_;
};

class UnitPlaintext : public Data, public TextInterface {
public:
  UnitPlaintext(std::vector<Polynomial *> &polynomials, const DataFlag flag,
                const SchemePreset scheme_preset, uint8_t log_slot_count,
                uint8_t log_coeff_count, uint8_t special_prime_count,
                uint16_t moduli_id, uint8_t level, uint8_t chain_count,
                uint32_t coeff_count, long double ckks_scale = 1.)
      : Data(polynomials, DataType::UNIT_PLAINTEXT, flag, scheme_preset,
             log_slot_count, log_coeff_count, special_prime_count, moduli_id,
             level, chain_count, coeff_count),
        ckks_scale_(ckks_scale){};

  long double ckks_scale() const { return ckks_scale_; };
  std::string type_name() const { return "unit plaintext"; };
  int size() const { return 1; };

  size_t nbytes() const override;

  const long double ckks_scale_;
};

class UnitCiphertext : public Data, public TextInterface {
public:
  UnitCiphertext(std::vector<Polynomial *> &polynomials, const DataFlag flag,
                 const SchemePreset scheme_preset, uint8_t log_slot_count,
                 uint8_t log_coeff_count, uint8_t special_prime_count,
                 uint16_t moduli_id, uint8_t level, uint8_t chain_count,
                 uint32_t coeff_count, long double ckks_scale = 1.)
      : Data(polynomials, DataType::UNIT_CIPHERTEXT, flag, scheme_preset,
             log_slot_count, log_coeff_count, special_prime_count, moduli_id,
             level, chain_count, coeff_count),
        ckks_scale_(ckks_scale){};

  long double ckks_scale() const { return ckks_scale_; };
  std::string type_name() const { return "unit ciphertext"; };
  int size() const { return 1; };

  size_t nbytes() const override;

  const long double ckks_scale_;
};

template <class T> class LongText : public TextInterface {
public:
  LongText(std::initializer_list<T *> texts);
  LongText(std::vector<T *> texts);
  ~LongText();

  DataFlag flag() const { return texts_[0]->flag_; };
  SchemePreset scheme_preset() const { return texts_[0]->scheme_preset_; };
  uint8_t log_slot_count() const { return texts_[0]->log_slot_count_; };
  uint8_t log_coeff_count() const { return texts_[0]->log_coeff_count_; };
  uint8_t special_prime_count() const {
    return texts_[0]->special_prime_count_;
  };
  uint16_t moduli_id() const { return texts_[0]->moduli_id_; };
  uint8_t level() const { return texts_[0]->level_; };
  uint32_t polynomial_count() const { return texts_[0]->polynomial_count(); };
  long double ckks_scale() const { return texts_[0]->ckks_scale_; };
  std::string type_name() const;

  T *get(int index) const;
  int size() const;

  size_t nbytes() const;

private:
  std::vector<T *> texts_;
  static const DataType type_;
};

template class LongText<UnitPlaintext>;
template class LongText<UnitCiphertext>;
using Plaintext = LongText<UnitPlaintext>;
using Ciphertext = LongText<UnitCiphertext>;

template <class T> std::string get_data_name(T *data);

class KeySwitcher : public Data {
public:
  KeySwitcher(std::vector<Polynomial *> &polynomial, const DataFlag flag,
              const SchemePreset scheme_preset, uint8_t log_slot_count,
              uint8_t log_coeff_count, uint8_t special_prime_count,
              uint16_t moduli_id, uint8_t level, uint8_t chain_count,
              uint32_t coeff_count)
      : Data(polynomial, DataType::KEY_SWITCHER, flag, scheme_preset,
             log_slot_count, log_coeff_count, special_prime_count, moduli_id,
             level, chain_count, coeff_count){};
};

class DecomposedUnitCiphertext : public Data {
public:
  DecomposedUnitCiphertext(std::vector<Polynomial *> &polynomial,
                           const DataFlag flag,
                           const SchemePreset scheme_preset,
                           uint8_t log_slot_count, uint8_t log_coeff_count,
                           uint8_t special_prime_count, uint16_t moduli_id,
                           uint8_t level, uint8_t chain_count,
                           uint32_t coeff_count)
      : Data(polynomial, DataType::UNIT_DECOMPOSED_CIPHERTEXT, flag,
             scheme_preset, log_slot_count, log_coeff_count,
             special_prime_count, moduli_id, level, chain_count, coeff_count){};
};

}
