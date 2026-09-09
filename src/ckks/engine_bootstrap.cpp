#include "arithmetic/arithmetic.h"
#include "arithmetic/pi.h"
#include "ckks/engine.h"
#include "operation/bootstrap.h"

namespace desilo::fhe {

PlainMatrix *CKKSEngine::make_bootstrap_stage(
    const std::vector<std::vector<std::complex<double>>> &twiddles,
    int rotate_count, int level, int inner_loop_shift) {
  auto stage = new PlainMatrix();

  const int twiddle_count = twiddles.size();
  const auto [inner_loop_count, outer_loop_count] =
      get_stage_loop_counts(twiddle_count, inner_loop_shift);

  stage->level_ = level;
  stage->inner_loop_count_ = inner_loop_count;
  stage->outer_loop_count_ = outer_loop_count;

  stage->inner_loop_deltas_.push_back(0);
  for (int inner_loop_index = 1; inner_loop_index < inner_loop_count;
       inner_loop_index++) {
    int delta = to_normalized_delta(inner_loop_index * rotate_count);
    stage->inner_loop_deltas_.push_back(delta);
  }

  for (int outer_loop_index = 0; outer_loop_index < outer_loop_count;
       outer_loop_index++) {
    const auto normalized_outer_loop_index =
        outer_loop_index - outer_loop_count / 2;

    const auto delta = to_normalized_delta(
        inner_loop_count * normalized_outer_loop_index * rotate_count);
    stage->outer_loop_deltas_.push_back(delta);

    bool need_new_process_order = true;
    for (auto &[prev_delta, process_order] : stage->outer_loop_process_order_) {
      if (prev_delta == delta) {
        process_order.push_back(outer_loop_index);
        need_new_process_order = false;
        break;
      }
    }
    if (need_new_process_order) {
      stage->outer_loop_process_order_.push_back({delta, {outer_loop_index}});
    }

    stage->encoded_diagonals_[outer_loop_index] = {};
    for (int inner_loop_index = (outer_loop_index == 0 ? 1 : 0);
         inner_loop_index < inner_loop_count; inner_loop_index++) {
      const auto twiddle_index =
          inner_loop_count * normalized_outer_loop_index + inner_loop_index;

      auto twiddle_factor = rotate_vector(
          twiddles[positive_modulo(twiddle_index, twiddle_count)], -delta);

      bool include_special = true;
      auto encoded = core_->encode(twiddle_factor, level, include_special);
      auto rescaled = rescale(encoded);
      auto ntt_form = ntt(rescaled);
      stage->encoded_diagonals_[outer_loop_index][inner_loop_index] = ntt_form;
      delete encoded;
      delete rescaled;
    }
  }

  return stage;
}

std::vector<PlainMatrix *>
CKKSEngine::make_coeff_to_slot_stages(int stage_count, int inner_loop_shift,
                                      int level) {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  const int slot_count = core_->get_slot_count();

  std::vector<PlainMatrix *> stages;

  const auto twiddles =
      get_coeff_to_slot_twiddles(slot_count, log_slot_count, stage_count);

  auto rotate_count = slot_count;
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    const int log_radix_count = get_coeff_to_slot_log_radix_count(
        stage_index, stage_count, log_slot_count);
    rotate_count >>= log_radix_count;
    stages.push_back(make_bootstrap_stage(twiddles[stage_index], rotate_count,
                                          level, inner_loop_shift));
    level -= 1;
  }

  return stages;
}

std::vector<PlainMatrix *>
CKKSEngine::make_slot_to_coeff_stages(int stage_count, int inner_loop_shift,
                                      int level) {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  const int slot_count = core_->get_slot_count();

  std::vector<PlainMatrix *> stages;

  const auto twiddles =
      get_slot_to_coeff_twiddles(slot_count, log_slot_count, stage_count);

  auto rotate_count = 1;
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    const int log_radix_count = get_slot_to_coeff_log_radix_count(
        stage_index, stage_count, log_slot_count);
    stages.push_back(make_bootstrap_stage(twiddles[stage_index], rotate_count,
                                          level, inner_loop_shift));
    rotate_count <<= log_radix_count;
    level -= 1;
  }

  return stages;
}

std::pair<int, int>
CKKSEngine::get_bootstrap_stage_levels(int stage_count) const {
  const int mod_raised_level = get_max_key_switching_level();
  const int levels_for_eval_round = 9;
  const int coeff_to_slot_stage_level = mod_raised_level;
  const int slot_to_coeff_stage_level =
      mod_raised_level - stage_count - levels_for_eval_round;

  return {coeff_to_slot_stage_level, slot_to_coeff_stage_level};
}

std::vector<int> CKKSEngine::make_partial_sum_deltas() {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  const int coeff_count_half = 1 << (log_coeff_count - 1);
  const int slot_count = core_->get_slot_count();

  std::vector<int> deltas;

  for (int rotate_delta = slot_count; rotate_delta < coeff_count_half;
       rotate_delta <<= 1) {
    deltas.push_back(rotate_delta);
  }

  return deltas;
}

UnitCiphertext *
CKKSEngine::multiply_for_butterfly(UnitCiphertext *unit_ciphertext,
                                   UnitPlaintext *unit_plaintext) {
  auto multiplied = core_->multiply(unit_ciphertext, unit_plaintext);
  return multiplied;
}

UnitCiphertext *CKKSEngine::apply_butterfly(
    UnitCiphertext *unit_ciphertext,
    const std::vector<std::vector<std::complex<double>>> &twiddle,
    RotationKey *rotation_key, int rotate_count) {
  const int twiddle_count = twiddle.size();
  const auto [inner_loop_count, outer_loop_count] =
      get_stage_loop_counts(twiddle_count);

  std::vector<int> inner_loop_deltas;
  for (int index = 0; index < inner_loop_count; index++) {
    inner_loop_deltas.push_back(rotate_count * index);
  }
  auto inner_rotated_unit_ciphertexts =
      rotate_batch(unit_ciphertext, rotation_key, inner_loop_deltas);

  UnitCiphertext *outer_sum = nullptr;
  for (int outer_loop_index = 0; outer_loop_index < outer_loop_count;
       outer_loop_index++) {
    const auto normalized_outer_loop_index =
        outer_loop_index - outer_loop_count / 2;

    const auto twiddle_factor_delta =
        inner_loop_count * normalized_outer_loop_index * rotate_count;

    UnitCiphertext *inner_sum = nullptr;
    for (int inner_loop_index = (outer_loop_index == 0 ? 1 : 0);
         inner_loop_index < inner_loop_count; inner_loop_index++) {

      const auto twiddle_index =
          inner_loop_count * normalized_outer_loop_index + inner_loop_index;
      const auto delta = twiddle_index;
      auto twiddle_factor =
          rotate_vector(twiddle[positive_modulo(delta, twiddle_count)],
                        -twiddle_factor_delta);
      auto multiplied = multiply(
          inner_rotated_unit_ciphertexts[inner_loop_index], twiddle_factor);

      if (inner_sum == nullptr) {
        inner_sum = multiplied;
      } else {
        add_inplace(inner_sum, multiplied);
        delete multiplied;
      }
    }

    const auto rotated = rotate(inner_sum, rotation_key, twiddle_factor_delta);
    delete inner_sum;

    if (outer_sum == nullptr) {
      outer_sum = rotated;
    } else {
      add_inplace(outer_sum, rotated);
      delete rotated;
    }
  }

  for (auto rotated : inner_rotated_unit_ciphertexts) {
    delete rotated;
  }
  return outer_sum;
}

template <class T>
UnitCiphertext *CKKSEngine::apply_butterfly(UnitCiphertext *unit_ciphertext,
                                            T *bootstrap_key,
                                            PlainMatrix *stage) {
  const auto inner_loop_count = stage->inner_loop_count_;
  const auto outer_loop_count = stage->outer_loop_count_;

  const auto rescaled_unit_ciphertext = rescale(unit_ciphertext);
  const auto decomposed = core_->decompose(rescaled_unit_ciphertext);

  std::vector<UnitCiphertext *> inner_rotated_unit_ciphertexts;
  auto inner_unit_ciphertext0 =
      core_->attach_special_prime_chains(rescaled_unit_ciphertext);
  inner_rotated_unit_ciphertexts.push_back(inner_unit_ciphertext0);

  delete rescaled_unit_ciphertext;

  for (int delta : stage->inner_loop_deltas_) {
    if (delta == 0) {
      continue;
    }
    const auto rotated =
        ntt_rotate(inner_unit_ciphertext0, decomposed, bootstrap_key, delta);
    inner_rotated_unit_ciphertexts.push_back(rotated);
  }

  delete decomposed;

  UnitCiphertext *outer_sum = nullptr;
  for (auto &[delta, outer_loop_indices] : stage->outer_loop_process_order_) {
    UnitCiphertext *inner_sum = nullptr;
    for (auto outer_loop_index : outer_loop_indices) {
      for (int inner_loop_index = (outer_loop_index == 0 ? 1 : 0);
           inner_loop_index < inner_loop_count; inner_loop_index++) {
        auto twiddle_factor =
            stage->encoded_diagonals_[outer_loop_index][inner_loop_index];
        auto multiplied = multiply_for_butterfly(
            inner_rotated_unit_ciphertexts[inner_loop_index], twiddle_factor);

        if (inner_sum == nullptr) {
          inner_sum = multiplied;
        } else {
          core_->add_inplace(inner_sum, multiplied);
          delete multiplied;
        }
      }
    }

    UnitCiphertext *rotated = inner_sum;
    if (delta != 0) {
      const auto inner_sum_decomposed =
          core_->mod_down_then_decompose(inner_sum);
      rotated =
          ntt_rotate(inner_sum, inner_sum_decomposed, bootstrap_key, delta);
      delete inner_sum;
      delete inner_sum_decomposed;
    }

    if (outer_sum == nullptr) {
      outer_sum = rotated;
    } else {
      core_->add_inplace(outer_sum, rotated);
      delete rotated;
    }
  }

  for (auto rotated : inner_rotated_unit_ciphertexts) {
    delete rotated;
  }
  const auto outer_sum_removed = core_->remove_special_prime_chains(outer_sum);
  delete outer_sum;
  return outer_sum_removed;
}

template UnitCiphertext *
CKKSEngine::apply_butterfly(UnitCiphertext *unit_ciphertext,
                            BootstrapKey *bootstrap_key, PlainMatrix *stage);

template <class T>
void CKKSEngine::partial_sum_inplace(UnitCiphertext *unit_ciphertext,
                                     T *bootstrap_key) {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  const int coeff_count_half = 1 << (log_coeff_count - 1);
  const int slot_count = core_->get_slot_count();

  UnitCiphertext *current = unit_ciphertext;

  for (int delta = slot_count; delta < coeff_count_half; delta <<= 1) {
    const auto rotated = rotate(current, bootstrap_key, delta, false);
    add_inplace(current, rotated);
    delete rotated;
  }
}

template void CKKSEngine::partial_sum_inplace(UnitCiphertext *unit_ciphertext,
                                              BootstrapKey *bootstrap_key);

void CKKSEngine::partial_sum_inplace(UnitCiphertext *unit_ciphertext,
                                     RotationKey *rotation_key) {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  const int coeff_count_half = 1 << (log_coeff_count - 1);
  const int slot_count = core_->get_slot_count();

  UnitCiphertext *current = unit_ciphertext;

  for (int delta = slot_count; delta < coeff_count_half; delta <<= 1) {
    const auto rotated = rotate(current, rotation_key, delta, false);
    add_inplace(current, rotated);
    delete rotated;
  }
}

std::pair<UnitCiphertext *, UnitCiphertext *>
CKKSEngine::coeff_to_slot(UnitCiphertext *unit_ciphertext,
                          ConjugationKey *conjugation_key,
                          RotationKey *rotation_key, int stage_count) {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  const int slot_count = core_->get_slot_count();

  const auto twiddles =
      get_coeff_to_slot_twiddles(slot_count, log_slot_count, stage_count);

  auto rotate_count = slot_count;
  auto current = unit_ciphertext;
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    auto stage_twiddle = twiddles[stage_index];
    const int log_radix_count = get_coeff_to_slot_log_radix_count(
        stage_index, stage_count, log_slot_count);
    rotate_count >>= log_radix_count;

    auto applied = apply_butterfly(current, twiddles[stage_index], rotation_key,
                                   rotate_count);
    if (stage_index > 0) {
      delete current;
    }
    current = applied;
  }

  const auto conjugated = conjugate(current, conjugation_key);
  const auto real_part = add(current, conjugated);

  const auto subtracted = subtract(current, conjugated);
  const auto imaginary_part = multiply_imaginary(subtracted, -1);

  delete current;
  delete conjugated;
  delete subtracted;

  return {real_part, imaginary_part};
}

template <class T>
std::pair<UnitCiphertext *, UnitCiphertext *>
CKKSEngine::coeff_to_slot(UnitCiphertext *unit_ciphertext,
                          ConjugationKey *conjugation_key, T *bootstrap_key) {
  auto current = unit_ciphertext;
  auto stage_count = bootstrap_key->coeff_to_slot_stages_.size();
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    auto stage = bootstrap_key->coeff_to_slot_stages_[stage_index];
    auto applied = apply_butterfly(current, bootstrap_key, stage);

    if (stage_index > 0) {
      delete current;
    }
    current = applied;
  }

  const auto conjugated = conjugate(current, conjugation_key);
  const auto real_part = add(current, conjugated);

  const auto subtracted = subtract(current, conjugated);
  const auto imaginary_part = multiply_imaginary(subtracted, -1);

  delete current;
  delete conjugated;
  delete subtracted;

  return {real_part, imaginary_part};
}

template std::pair<UnitCiphertext *, UnitCiphertext *>
CKKSEngine::coeff_to_slot(UnitCiphertext *unit_ciphertext,
                          ConjugationKey *conjugation_key,
                          BootstrapKey *bootstrap_key);

UnitCiphertext *CKKSEngine::slot_to_coeff(UnitCiphertext *unit_ciphertext_real,
                                          UnitCiphertext *unit_ciphertext_imag,
                                          ConjugationKey *conjugation_key,
                                          RotationKey *rotation_key,
                                          int stage_count) {
  const auto [log_slot_count, log_coeff_count, special_prime_count] =
      core_->get_parameter();
  const int slot_count = core_->get_slot_count();

  const auto multiplied = multiply_imaginary(unit_ciphertext_imag, 1);
  auto current = add(unit_ciphertext_real, multiplied);
  delete multiplied;

  const auto twiddles =
      get_slot_to_coeff_twiddles(slot_count, log_slot_count, stage_count);

  auto rotate_count = 1;
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    auto applied = apply_butterfly(current, twiddles[stage_index], rotation_key,
                                   rotate_count);
    delete current;
    current = applied;

    const int log_radix_count = get_slot_to_coeff_log_radix_count(
        stage_index, stage_count, log_slot_count);
    rotate_count <<= log_radix_count;
  }

  return current;
}

UnitCiphertext *CKKSEngine::slot_to_coeff(UnitCiphertext *unit_ciphertext_real,
                                          UnitCiphertext *unit_ciphertext_imag,
                                          ConjugationKey *conjugation_key,
                                          BootstrapKey *bootstrap_key) {
  const auto multiplied = multiply_imaginary(unit_ciphertext_imag, 1);
  auto current = add(unit_ciphertext_real, multiplied);
  delete multiplied;

  auto stage_count = bootstrap_key->slot_to_coeff_stages_.size();
  for (int stage_index = 0; stage_index < stage_count; stage_index++) {
    auto stage = bootstrap_key->slot_to_coeff_stages_[stage_index];
    auto applied = apply_butterfly(current, bootstrap_key, stage);

    delete current;
    current = applied;
  }

  return current;
}

constexpr int BABY_DEGREE = 7;
constexpr int GIANT_DEGREE = 3;

UnitCiphertext *CKKSEngine::chebyshev_paterson_stockmeyer(
    std::vector<UnitCiphertext *> &baby_basis, UnitCiphertext *giant,
    RelinearizationKey *relinearization_key,
    const std::vector<std::vector<double>> coefficients) {
  auto baby0 = weighted_sum(baby_basis, coefficients[0]);
  auto added = add(giant, baby0);
  delete baby0;

  auto baby1 = weighted_sum(baby_basis, coefficients[1]);
  auto multiplied = multiply(added, baby1, relinearization_key);
  delete added;
  delete baby1;

  auto baby2 = weighted_sum(baby_basis, coefficients[2]);
  added = add(multiplied, baby2);
  delete multiplied;
  delete baby2;

  return added;
}

UnitCiphertext *CKKSEngine::chebyshev_paterson_stockmeyer(
    std::vector<UnitCiphertext *> &baby_basis, UnitCiphertext *giant,
    const std::vector<std::vector<double>> coefficients) {
  auto baby0 = weighted_sum(baby_basis, coefficients[0]);
  auto added = add(giant, baby0);
  delete baby0;

  auto baby1 = weighted_sum(baby_basis, coefficients[1]);
  auto multiplied = multiply(added, baby1);
  delete added;
  delete baby1;

  auto baby2 = weighted_sum(baby_basis, coefficients[2]);
  added = add(multiplied, baby2);
  delete multiplied;
  delete baby2;

  return added;
}

const std::vector<double> auxiliary_coefficients = {
    -0.4674215360340989,   -0.24807246365084598,
    -0.03360736343811264,  0.10485552200765141,
    0.012171628025753911,  -0.031034212401993305,
    -0.003985828764410408, 0.0};
const std::vector<std::vector<double>> quotient_coefficients = {
    {-0.7500012154934053, 4.148627473785995e-06, 2.707983311367457e-07,
     -4.324538856989888e-07, -2.648274421485692e-08, 3.9515438249932484e-08,
     2.4720260690299275e-09, 0.0},
    {-6.511205244110998e-09, -7.076428529570776e-10, 1.0183620860162692e-09,
     0.0000000000000000, 0.0000000000000000, 0.0000000000000000,
     0.0000000000000000, 4.0000000000000000},
    {0.007868944223231958, 0.0014193060148561195, -0.003081157124604844,
     -0.00025275745577540515, 0.0005030348400875631, 3.734766164626263e-05,
     -7.780382338014487e-05, 1.00000000000000000}};
const std::vector<std::vector<double>> remainder_coefficients = {
    {-1.1324455480972702, -0.8116709016985189, -0.20294197180913795,
     0.5290215620326779, -0.32084902738708476, 0.43458317383580536,
     -0.06303880005650665, 0.0},
    {0.23316927298939902, 0.12938749185636858, -0.3042902283756468,
     -0.008967445477730096, -0.6955791340472846, -0.07562064123442451,
     1.2510854562849574, 2.00000000000000000},
    {0.1429148264191405, 0.4544397978460022, -0.8401926425765848,
     -0.4292803758141986, -1.495563076527614, 0.3580084476476745,
     1.7971594278092713, 1.00000000000000000}};

UnitCiphertext *CKKSEngine::sine(UnitCiphertext *unit_ciphertext,
                                 RelinearizationKey *relinearization_key) {

  std::vector<UnitCiphertext *> baby_chebyshev_basis(BABY_DEGREE);
  baby_chebyshev_basis.front() = clone(unit_ciphertext);
  for (int baby_index = 2; baby_index <= BABY_DEGREE; baby_index++) {
    const int basis_index = baby_index - 1;
    const int half_basis_index = baby_index / 2 - 1;
    if ((baby_index & 1) == 0) {

      auto multiplied =
          square(baby_chebyshev_basis[half_basis_index], relinearization_key);
      add_inplace(multiplied, multiplied);
      baby_chebyshev_basis[basis_index] = add(multiplied, -1);

      delete multiplied;
    } else {

      auto multiplied = multiply(baby_chebyshev_basis[half_basis_index],
                                 baby_chebyshev_basis[half_basis_index + 1],
                                 relinearization_key);
      add_inplace(multiplied, multiplied);
      baby_chebyshev_basis[basis_index] =
          subtract(multiplied, baby_chebyshev_basis.front());

      delete multiplied;
    }
  }

  const int destination_level = baby_chebyshev_basis.back()->level_;
  for (int baby_index = 0; baby_index < BABY_DEGREE - 2; baby_index++) {
    if (baby_chebyshev_basis[baby_index]->level_ > destination_level) {
      auto leveled_down =
          level_down(baby_chebyshev_basis[baby_index], destination_level);
      delete baby_chebyshev_basis[baby_index];
      baby_chebyshev_basis[baby_index] = leveled_down;
    }
  }

  std::vector<UnitCiphertext *> giant_chebyshev_basis(GIANT_DEGREE);
  giant_chebyshev_basis.front() = clone(baby_chebyshev_basis.back());
  for (int giant_index = 1; giant_index < GIANT_DEGREE; giant_index++) {
    const int basis_index = giant_index - 1;
    auto multiplied =
        square(giant_chebyshev_basis[basis_index], relinearization_key);
    add_inplace(multiplied, multiplied);
    giant_chebyshev_basis[giant_index] = add(multiplied, -1);

    delete multiplied;
  }

  auto paterson_stockmeyer_unit_ciphertext =
      clone(giant_chebyshev_basis.front());

  for (int giant_index = 1; giant_index < GIANT_DEGREE - 1; giant_index++) {
    auto current = giant_chebyshev_basis[giant_index];
    auto multiplied = multiply(paterson_stockmeyer_unit_ciphertext, current,
                               relinearization_key);
    add_inplace(multiplied, multiplied);

    delete paterson_stockmeyer_unit_ciphertext;

    paterson_stockmeyer_unit_ciphertext =
        subtract(multiplied, giant_chebyshev_basis.front());

    delete multiplied;
  }
  auto current = giant_chebyshev_basis[GIANT_DEGREE - 1];
  auto multiplied = multiply(paterson_stockmeyer_unit_ciphertext, current);
  add_inplace(multiplied, multiplied);

  delete paterson_stockmeyer_unit_ciphertext;

  paterson_stockmeyer_unit_ciphertext =
      subtract(multiplied, giant_chebyshev_basis.front());

  delete multiplied;

  auto auxiliary_unit_ciphertext =
      weighted_sum(baby_chebyshev_basis, auxiliary_coefficients);
  auto added = add(auxiliary_unit_ciphertext, giant_chebyshev_basis.back());
  delete auxiliary_unit_ciphertext;

  auto quotient = chebyshev_paterson_stockmeyer(
      baby_chebyshev_basis, giant_chebyshev_basis[GIANT_DEGREE - 2],
      relinearization_key, quotient_coefficients);
  multiplied = multiply(added, quotient);
  delete added;
  delete quotient;

  auto remainder = chebyshev_paterson_stockmeyer(
      baby_chebyshev_basis, giant_chebyshev_basis[GIANT_DEGREE - 2],
      remainder_coefficients);
  added = add(multiplied, remainder);
  auto subtracted = subtract(added, paterson_stockmeyer_unit_ciphertext);
  auto relinearized = relinearize(subtracted, relinearization_key);

  delete subtracted;

  delete remainder;
  delete multiplied;
  delete added;
  delete paterson_stockmeyer_unit_ciphertext;

  for (auto &unit_ciphertext : baby_chebyshev_basis) {
    delete unit_ciphertext;
  }
  for (auto &unit_ciphertext : giant_chebyshev_basis) {
    delete unit_ciphertext;
  }

  return relinearized;
}

UnitCiphertext *CKKSEngine::apply_double_angle_iterations(
    UnitCiphertext *unit_ciphertext, RelinearizationKey *relinearization_key,
    int iter_count) {
  auto current = clone(unit_ciphertext);
  const auto two_pi = 2 * pi;

  for (int iter_index = 1; iter_index <= iter_count; iter_index++) {
    auto multiplied = square(current, relinearization_key);
    delete current;

    add_inplace(multiplied, multiplied);

    const auto scalar =
        -std::pow(two_pi, -std::pow(2, iter_index - iter_count));
    current = add(multiplied, scalar);
    delete multiplied;
  }

  return current;
}

UnitCiphertext *CKKSEngine::modulo(UnitCiphertext *unit_ciphertext,
                                   RelinearizationKey *relinearization_key) {
  auto sine_approximated = sine(unit_ciphertext, relinearization_key);
  auto doubled_angle =
      apply_double_angle_iterations(sine_approximated, relinearization_key);

  delete sine_approximated;

  return doubled_angle;
}

UnitCiphertext *CKKSEngine::round(UnitCiphertext *unit_ciphertext,
                                  RelinearizationKey *relinearization_key) {
#ifdef DESILO_FHE_DEBUG
  constexpr auto function_name = "Round";
  require(function_name, unit_ciphertext,
          {Requirement::DUO, Requirement::INTT, Requirement::NOT_RESCALED});
  require_engine_compatibility(function_name, relinearization_key);
  require_key_compatibility(function_name, unit_ciphertext,
                            relinearization_key);
#endif

  auto decimal_part = modulo(unit_ciphertext, relinearization_key);
  auto multiplied = multiply(unit_ciphertext, ROUND_BOUND);
  auto subtracted = subtract(multiplied, decimal_part);

  delete decimal_part;
  delete multiplied;

  return subtracted;
}

template <class T>
void CKKSEngine::require_bootstrap_(const std::string &function_name, T *text,
                                    RelinearizationKey *relinearization_key,
                                    ConjugationKey *conjugation_key,
                                    RotationKey *rotation_key,
                                    SmallBootstrapKey *small_bootstrap_key,
                                    int stage_count) {
  require_bootstrap_engine(function_name);
  require(function_name, text, {Requirement::DUO, Requirement::INTT});
  require_engine_compatibility(function_name, relinearization_key,
                               get_max_level() - 1 - stage_count);
  require_engine_compatibility(function_name, conjugation_key,
                               get_max_level() - 1 - stage_count);
  require_engine_compatibility(function_name, rotation_key,
                               get_max_level() - 1);
  require_engine_compatibility(function_name, small_bootstrap_key);
  require_bootstrap_stage_count(function_name, stage_count);
}

UnitCiphertext *CKKSEngine::bootstrap(UnitCiphertext *unit_ciphertext,
                                      RelinearizationKey *relinearization_key,
                                      ConjugationKey *conjugation_key,
                                      RotationKey *rotation_key,
                                      SmallBootstrapKey *small_bootstrap_key,
                                      int stage_count) {
  const std::string function_name =
      "Bootstrap Unit Ciphertext With Rotation Key";
  require_bootstrap_(function_name, unit_ciphertext, relinearization_key,
                     conjugation_key, rotation_key, small_bootstrap_key,
                     stage_count);

  const auto [log_slot_count, log_coeff_count, special_prime] =
      core_->get_parameter();

  auto leveled_down = level_down(unit_ciphertext, 0);
  auto raised = mod_raise_(leveled_down, small_bootstrap_key);

  if (log_slot_count != log_coeff_count - 1) {
    partial_sum_inplace(raised, rotation_key);
  }

  auto [slot_real, slot_imag] =
      coeff_to_slot(raised, conjugation_key, rotation_key, stage_count);
  auto rounded_real = round(slot_real, relinearization_key);
  auto rounded_imag = round(slot_imag, relinearization_key);
  auto coeff = slot_to_coeff(rounded_real, rounded_imag, conjugation_key,
                             rotation_key, stage_count);
  auto bootstrapped = subtract(raised, coeff);
  auto ratio = core_->get_normalize_ratio();
  auto multiplied = multiply(bootstrapped, ratio);

  delete leveled_down;
  delete raised;
  delete slot_real;
  delete slot_imag;
  delete rounded_real;
  delete rounded_imag;
  delete coeff;
  delete bootstrapped;

  return multiplied;
}

Ciphertext *CKKSEngine::bootstrap(Ciphertext *ciphertext,
                                  RelinearizationKey *relinearization_key,
                                  ConjugationKey *conjugation_key,
                                  RotationKey *rotation_key,
                                  SmallBootstrapKey *small_bootstrap_key,
                                  int stage_count) {
  const std::string function_name = "Bootstrap Ciphertext With Rotation Key";
  require_bootstrap_(function_name, ciphertext, relinearization_key,
                     conjugation_key, rotation_key, small_bootstrap_key,
                     stage_count);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(
        bootstrap(ciphertext->get(index), relinearization_key, conjugation_key,
                  rotation_key, small_bootstrap_key, stage_count));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

template <class T>
void CKKSEngine::require_bootstrap_(const std::string &function_name, T *text,
                                    RelinearizationKey *relinearization_key,
                                    ConjugationKey *conjugation_key,
                                    BootstrapKey *bootstrap_key) {
  int stage_count = bootstrap_key->coeff_to_slot_stages_.size();
  require_bootstrap_engine(function_name);
  require(function_name, text, {Requirement::DUO, Requirement::INTT});
  require_engine_compatibility(function_name, relinearization_key,
                               get_max_level() - 1 - stage_count);
  require_engine_compatibility(function_name, conjugation_key,
                               get_max_level() - 1 - stage_count);
  require_engine_compatibility(function_name, bootstrap_key);
}

UnitCiphertext *CKKSEngine::bootstrap(UnitCiphertext *unit_ciphertext,
                                      RelinearizationKey *relinearization_key,
                                      ConjugationKey *conjugation_key,
                                      BootstrapKey *bootstrap_key) {
  int stage_count = bootstrap_key->coeff_to_slot_stages_.size();
  const std::string function_name =
      "Bootstrap Unit Ciphertext With Bootstrap Key";
  require_bootstrap_(function_name, unit_ciphertext, relinearization_key,
                     conjugation_key, bootstrap_key);

  const auto [log_slot_count, log_coeff_count, special_prime] =
      core_->get_parameter();

  auto leveled_down = level_down(unit_ciphertext, 0);
  auto raised = mod_raise_(leveled_down, bootstrap_key->small_bootstrap_key_);

  if (log_slot_count != log_coeff_count - 1) {
    partial_sum_inplace(raised, bootstrap_key);
  }

  auto [slot_real, slot_imag] =
      coeff_to_slot(raised, conjugation_key, bootstrap_key);
  auto rounded_real = round(slot_real, relinearization_key);
  auto rounded_imag = round(slot_imag, relinearization_key);
  auto coeff =
      slot_to_coeff(rounded_real, rounded_imag, conjugation_key, bootstrap_key);
  auto bootstrapped = subtract(raised, coeff);
  auto ratio = core_->get_normalize_ratio();
  auto multiplied = multiply(bootstrapped, ratio);

  delete leveled_down;
  delete raised;
  delete slot_real;
  delete slot_imag;
  delete rounded_real;
  delete rounded_imag;
  delete coeff;
  delete bootstrapped;

  return multiplied;
}

Ciphertext *CKKSEngine::bootstrap(Ciphertext *ciphertext,
                                  RelinearizationKey *relinearization_key,
                                  ConjugationKey *conjugation_key,
                                  BootstrapKey *bootstrap_key) {
  const std::string function_name = "Bootstrap Ciphertext With Bootstrap Key";
  require_bootstrap_(function_name, ciphertext, relinearization_key,
                     conjugation_key, bootstrap_key);

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(bootstrap(ciphertext->get(index),
                                         relinearization_key, conjugation_key,
                                         bootstrap_key));
  }

  clear_temp_data();

  return new Ciphertext(unit_ciphertexts);
}

template <typename T>
std::vector<T> CKKSEngine::rotate_vector(const std::vector<T> &input,
                                         int delta) {
  if (input.empty())
    return input;

  int count = input.size();
  const auto normalized_delta = (delta + 2 * count) % count;

  std::vector<T> result(count);
  for (int index = 0; index < count; index++) {
    result[(index + normalized_delta) % count] = input[index];
  }
  return result;
}

}
