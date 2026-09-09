#include "ckks/engine.h"

inline desilo::fhe::SecretKey *
get_dummy_secret_key(desilo::fhe::SchemePreset scheme_preset,
                     int log_slot_count, int log_coeff_count,
                     int special_prime_count, int level = 7) {
  const auto flag = desilo::fhe::DataFlag::NTT_FORM;
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;
  const auto polynomial1 =
      new desilo::fhe::Polynomial(flag, moduli_id, chain_count, coeff_count);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1};

  return new desilo::fhe::SecretKey(
      polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
}

inline desilo::fhe::PublicKey *
get_dummy_public_key(desilo::fhe::SchemePreset scheme_preset,
                     int log_slot_count, int log_coeff_count,
                     int special_prime_count, int level = 7) {
  const auto flag = desilo::fhe::DataFlag::NTT_FORM;
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;
  const auto polynomial1 =
      new desilo::fhe::Polynomial(flag, moduli_id, chain_count, coeff_count);
  std::vector<desilo::fhe::Polynomial *> polynomials{polynomial1};

  return new desilo::fhe::PublicKey(
      polynomials, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
}

inline desilo::fhe::KeySwitchingKey *
get_dummy_key_switching_key(desilo::fhe::SchemePreset scheme_preset,
                            int log_slot_count, int log_coeff_count,
                            int special_prime_count, int level = 7) {
  const auto flag = desilo::fhe::DataFlag::NTT_FORM;
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;

  std::vector<desilo::fhe::Polynomial *> keys;
  return new desilo::fhe::KeySwitchingKey(
      keys, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);
}

inline desilo::fhe::ConjugationKey *
get_dummy_conjugation_key(desilo::fhe::SchemePreset scheme_preset,
                          int log_slot_count, int log_coeff_count,
                          int special_prime_count, int level = 7) {
  const auto flag = desilo::fhe::DataFlag::NTT_FORM;
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;

  std::vector<desilo::fhe::Polynomial *> keys;
  auto key_switching_key = new desilo::fhe::KeySwitchingKey(
      keys, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);

  auto permutation = new desilo::fhe::PermutationParameters();
  auto sign = new desilo::fhe::PermutationParameters();
  return new desilo::fhe::ConjugationKey(key_switching_key, permutation, sign);
}

inline desilo::fhe::FixedRotationKey *get_dummy_fixed_rotation_key(
    desilo::fhe::SchemePreset scheme_preset, int log_slot_count,
    int log_coeff_count, int special_prime_count, int delta, int level = 7) {
  const auto flag = desilo::fhe::DataFlag::NTT_FORM;
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;

  std::vector<desilo::fhe::Polynomial *> keys;
  auto key_switching_key = new desilo::fhe::KeySwitchingKey(
      keys, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);

  auto permutation = new desilo::fhe::PermutationParameters();
  auto sign = new desilo::fhe::PermutationParameters();
  return new desilo::fhe::FixedRotationKey(key_switching_key, permutation, sign,
                                           delta);
}

inline desilo::fhe::RelinearizationKey *
get_dummy_relinearization_key(desilo::fhe::SchemePreset scheme_preset,
                              int log_slot_count, int log_coeff_count,
                              int special_prime_count, int level = 7) {
  const auto flag = desilo::fhe::DataFlag::NTT_FORM;
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;

  std::vector<desilo::fhe::Polynomial *> keys;
  auto key_switching_key = new desilo::fhe::KeySwitchingKey(
      keys, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);

  return new desilo::fhe::RelinearizationKey(key_switching_key);
}

inline desilo::fhe::RotationKey *
get_dummy_rotation_key(desilo::fhe::SchemePreset scheme_preset,
                       int log_slot_count, int log_coeff_count,
                       int special_prime_count, int level = 7) {
  const auto flag = desilo::fhe::DataFlag::NTT_FORM;
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;

  std::vector<desilo::fhe::Polynomial *> keys;
  auto key_switching_key = new desilo::fhe::KeySwitchingKey(
      keys, flag, scheme_preset, log_slot_count, log_coeff_count,
      special_prime_count, moduli_id, level, chain_count, coeff_count);

  int delta = 1;
  auto permutation = new desilo::fhe::PermutationParameters();
  auto sign = new desilo::fhe::PermutationParameters();
  std::vector<desilo::fhe::FixedRotationKey *> fixed_rotation_keys{
      new desilo::fhe::FixedRotationKey(key_switching_key, permutation, sign,
                                        delta)};
  return new desilo::fhe::RotationKey(fixed_rotation_keys);
}

inline desilo::fhe::UnitPlaintext *get_dummy_flagged_unit_plaintext(
    desilo::fhe::DataFlag flag, desilo::fhe::SchemePreset scheme_preset,
    int log_slot_count, int log_coeff_count, int special_prime_count,
    int level = 7, long double ckks_scale = 1.0) {
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;
  std::vector<desilo::fhe::Polynomial *> polynomials;

  return new desilo::fhe::UnitPlaintext(polynomials, flag, scheme_preset,
                                        log_slot_count, log_coeff_count,
                                        special_prime_count, moduli_id, level,
                                        chain_count, coeff_count, ckks_scale);
}

inline desilo::fhe::UnitPlaintext *
get_dummy_unit_plaintext(desilo::fhe::SchemePreset scheme_preset,
                         int log_slot_count, int log_coeff_count,
                         int special_prime_count, int level = 7,
                         long double ckks_scale = 1.0) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  return get_dummy_flagged_unit_plaintext(flag, scheme_preset, log_slot_count,
                                          log_coeff_count, special_prime_count,
                                          level, ckks_scale);
}

inline desilo::fhe::UnitCiphertext *get_dummy_flagged_unit_ciphertext(
    desilo::fhe::DataFlag flag, desilo::fhe::SchemePreset scheme_preset,
    int log_slot_count, int log_coeff_count, int special_prime_count,
    int polynomial_count = 2, int level = 7, long double ckks_scale = 1.0) {
  int moduli_id = 7 - level;
  int chain_count = 2;
  int coeff_count = 1 << log_coeff_count;
  std::vector<desilo::fhe::Polynomial *> polynomials;

  for (int polynomial_index = 0; polynomial_index < polynomial_count;
       polynomial_index++) {

    polynomials.emplace_back(
        new desilo::fhe::Polynomial(flag, moduli_id, chain_count, coeff_count));
  }

  return new desilo::fhe::UnitCiphertext(polynomials, flag, scheme_preset,
                                         log_slot_count, log_coeff_count,
                                         special_prime_count, moduli_id, level,
                                         chain_count, coeff_count, ckks_scale);
}

inline desilo::fhe::UnitCiphertext *
get_dummy_unit_ciphertext(desilo::fhe::SchemePreset scheme_preset,
                          int log_slot_count, int log_coeff_count,
                          int special_prime_count, int polynomial_count = 2,
                          int level = 7, long double ckks_scale = 1.0) {
  const auto flag = desilo::fhe::DataFlag::NONE;
  return get_dummy_flagged_unit_ciphertext(flag, scheme_preset, log_slot_count,
                                           log_coeff_count, special_prime_count,
                                           polynomial_count, level, ckks_scale);
}
