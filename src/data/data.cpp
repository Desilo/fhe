#include <filesystem>

#include "ckks/encode.h"
#include "data/data.h"
#include "parameter/partition.h"

namespace desilo::fhe {

#define SCALE_LENGTH 64

DataFlag operator~(DataFlag rhs) {
  return static_cast<DataFlag>(
      ~static_cast<std::underlying_type<DataFlag>::type>(rhs));
}

DataFlag operator|(DataFlag lhs, DataFlag rhs) {
  return static_cast<DataFlag>(
      static_cast<std::underlying_type<DataFlag>::type>(lhs) |
      static_cast<std::underlying_type<DataFlag>::type>(rhs));
}

DataFlag operator&(DataFlag lhs, DataFlag rhs) {
  return static_cast<DataFlag>(
      static_cast<std::underlying_type<DataFlag>::type>(lhs) &
      static_cast<std::underlying_type<DataFlag>::type>(rhs));
}

DataFlag &operator|=(DataFlag &lhs, DataFlag rhs) { return lhs = lhs | rhs; }

DataFlag &operator&=(DataFlag &lhs, DataFlag rhs) { return lhs = lhs & rhs; }

Data::Data(std::vector<Polynomial *> &polynomials, const DataType type,
           const DataFlag flag, const SchemePreset scheme_preset,
           uint8_t log_slot_count, uint8_t log_coeff_count,
           uint8_t special_prime_count, uint16_t moduli_id, uint8_t level,
           uint8_t chain_count, uint32_t coeff_count)
    : polynomials_(std::move(polynomials)), type_(type), flag_(flag),
      scheme_preset_(scheme_preset), log_slot_count_(log_slot_count),
      log_coeff_count_(log_coeff_count),
      special_prime_count_(special_prime_count), moduli_id_(moduli_id),
      level_(level), chain_count_(chain_count), coeff_count_(coeff_count) {}

Data::~Data() {
  for (const auto polynomial : polynomials_) {
    delete polynomial;
  }
}

int64_t *Data::get(int index, int chain_start) {
#ifdef DESILO_FHE_DEBUG
  if (index < 0 || index >= polynomials_.size()) {
    throw std::runtime_error("Data polynomial index out of bounds");
  }
  if (chain_start < 0 || chain_start >= chain_count_) {
    throw std::runtime_error("Data chain start out of bounds");
  }
#endif
  const auto chains = polynomials_[index]->chains_;
  return chains[chain_start];
}

Polynomial *Data::get_polynomial(int index) {
#ifdef DESILO_FHE_DEBUG
  if (index < 0 || index >= polynomials_.size()) {
    throw std::runtime_error("Data polynomial index out of bounds");
  }
#endif
  return polynomials_[index];
}

uint32_t Data::polynomial_count() const { return polynomials_.size(); }

size_t Data::nbytes() const {
  auto size = sizeof(Data);
  for (auto polynomial : polynomials_) {
    size += sizeof(polynomial) + polynomial->nbytes();
  }

  return size;
}

int KeySwitchingKey::get_key_index(const Partition *partition,
                                   const int index) {
  const auto partition_index = partition->partition_index_;
  return partition_index * 2 + index;
}

RelinearizationKey::~RelinearizationKey() { delete key_switching_key_; }

size_t RelinearizationKey::nbytes() const {
  auto size = sizeof(RelinearizationKey);
  size += key_switching_key_->nbytes();

  return size;
}

FixedRotationKey::~FixedRotationKey() {
  delete key_switching_key_;
  delete permutation_;
  delete sign_;
}

size_t FixedRotationKey::nbytes() const {
  auto size = sizeof(FixedRotationKey);
  size += key_switching_key_->nbytes();
  size += permutation_->nbytes();
  size += sign_->nbytes();

  return size;
}

RotationKey::~RotationKey() {
  for (const auto fixed_rotation_key : fixed_rotation_keys_) {
    delete fixed_rotation_key;
  }
}

size_t RotationKey::nbytes() const {
  auto size = sizeof(RotationKey);
  for (auto fixed_rotation_key : fixed_rotation_keys_) {
    size += sizeof(fixed_rotation_key) + fixed_rotation_key->nbytes();
  }

  return size;
}

ConjugationKey::~ConjugationKey() {
  delete key_switching_key_;
  delete permutation_;
  delete sign_;
}

size_t ConjugationKey::nbytes() const {
  auto size = sizeof(ConjugationKey);
  size += key_switching_key_->nbytes();
  size += permutation_->nbytes();
  size += sign_->nbytes();

  return size;
}

size_t UnitPlaintext::nbytes() const {
  return Data::nbytes() - sizeof(Data) + sizeof(UnitPlaintext);
}

size_t UnitCiphertext::nbytes() const {
  return Data::nbytes() - sizeof(Data) + sizeof(UnitCiphertext);
}

template <class T>
LongText<T>::LongText(std::initializer_list<T *> texts) : texts_(texts){};

template <class T>
LongText<T>::LongText(std::vector<T *> texts) : texts_(texts){};

template <class T> LongText<T>::~LongText() {
  for (auto text : texts_) {
    delete text;
  }
}

template <class T> T *LongText<T>::get(int index) const {
  return texts_[index];
}

template <class T> int LongText<T>::size() const { return texts_.size(); }

template <class T> size_t LongText<T>::nbytes() const {
  auto size = sizeof(T);
  for (auto text : texts_) {
    size += sizeof(text) + text->nbytes();
  }

  return size;
}

template <> const DataType LongText<UnitPlaintext>::type_ = DataType::PLAINTEXT;
template <>
const DataType LongText<UnitCiphertext>::type_ = DataType::CIPHERTEXT;

template <> std::string LongText<UnitPlaintext>::type_name() const {
  return "plaintext";
}

template <> std::string LongText<UnitCiphertext>::type_name() const {
  return "ciphertext";
}

template LongText<UnitPlaintext>::LongText(
    std::initializer_list<UnitPlaintext *> texts);
template LongText<UnitCiphertext>::LongText(
    std::initializer_list<UnitCiphertext *> texts);

template LongText<UnitPlaintext>::LongText(std::vector<UnitPlaintext *> texts);
template LongText<UnitCiphertext>::LongText(
    std::vector<UnitCiphertext *> texts);

template LongText<UnitPlaintext>::~LongText();
template LongText<UnitCiphertext>::~LongText();

template UnitPlaintext *LongText<UnitPlaintext>::get(int index) const;
template UnitCiphertext *LongText<UnitCiphertext>::get(int index) const;

template int LongText<UnitPlaintext>::size() const;
template int LongText<UnitCiphertext>::size() const;

template size_t LongText<UnitPlaintext>::nbytes() const;
template size_t LongText<UnitCiphertext>::nbytes() const;

}
