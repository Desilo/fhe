#include <algorithm>
#include <cmath>
#include <cstring>

#include "arithmetic/arithmetic.h"
#include "ckks/encode.h"
#include "montgomery/compound.h"
#include "montgomery/unit.h"
#include "operation/fft.h"
#include "operation/ntt.h"
#include "operation/scalar.h"
#include "parallel/task.h"

namespace desilo::fhe {

bool MontEnterTask::process() {
  mont_enter(sources_[0], destination_, constant_, q_, k_, coeff_count_);

  return true;
}

bool MakeSignedTask::process() {
  make_signed(sources_[0], destination_, q_, q_half_, coeff_count_);

  return true;
}

bool MontAddTask::process() {
  mont_add(sources_[0], sources_[1], destination_, q_double_, coeff_count_);

  return true;
}

bool MontMultTask::process() {
  mont_mult(sources_[0], sources_[1], destination_, q_, k_, coeff_count_);

  return true;
}

bool Reduce2QToQTask::process() {
  reduce_2q_to_q(sources_[0], destination_, q_, coeff_count_);

  return true;
}

bool MontSubtractTask::process() {
  mont_subtract(sources_[0], sources_[1], destination_, q_double_,
                coeff_count_);

  return true;
}

bool GetRounderTask::process() {
  get_rounder(sources_[0], destination_, q_half_, coeff_count_);

  return true;
}

bool MontEnterAddTask::process() {
  mont_enter_add(sources_[0], destination_, constant_, q_double_, q_, k_,
                 coeff_count_);

  return true;
}

bool MontEnterAddReduce2QToQTask::process() {
  mont_enter_add_reduce_2q_to_q(sources_[0], destination_, constant_, q_double_,
                                q_, k_, coeff_count_);

  return true;
}

bool MontMultAddTask::process() {
  mont_mult_add(sources_[0], sources_[1], destination_, q_double_, q_, k_,
                coeff_count_);

  return true;
}

bool MontSubEnterReduce2QToQTask::process() {
  mont_sub_enter_reduce_2q_to_q(sources_[0], sources_[1], destination_,
                                constant_, q_double_, q_, k_, coeff_count_);

  return true;
}

bool MontSubEnterTask::process() {
  mont_sub_enter(sources_[0], sources_[1], destination_, constant_, q_double_,
                 q_, k_, coeff_count_);

  return true;
}

bool MontEnterExitTask::process() {
  mont_enter_exit(sources_[0], destination_, constant_, q_, k_, coeff_count_);

  return true;
}

bool MontEnterExitReduce2QToQTask::process() {
  mont_enter_exit_reduce_2q_to_q(sources_[0], destination_, constant_, q_, k_,
                                 coeff_count_);

  return true;
}

bool MontAddReduce2QToQTask::process() {
  mont_add_reduce_2q_to_q(sources_[0], sources_[1], destination_, q_double_, q_,
                          coeff_count_);

  return true;
}

bool MontSubReduce2QToQTask::process() {
  mont_sub_reduce_2q_to_q(sources_[0], sources_[1], destination_, q_double_, q_,
                          coeff_count_);

  return true;
}

bool MakeUnsignedReduce2QToQTask::process() {
  make_unsigned_reduce_2q_to_q(sources_[0], destination_, q_, coeff_count_);

  return true;
}

bool NegateMakeUnsignedTask::process() {
  negate_make_unsigned(sources_[0], destination_, q_, coeff_count_);

  return true;
}

bool ConcatenateMakeUnsignedTask::process() {
  concatenate_make_unsigned(sources_[0], sources_[1], destination_, q_,
                            coeff_count_);

  return true;
}

bool NttTask::process() {
  ntt(sources_[0], destination_, root_, q_double_, q_, k_, coeff_count_,
      log_coeff_count_);

  return true;
}

bool InttTask::process() {
  intt(sources_[0], destination_, root_inverse_, q_double_, q_, k_,
       coeff_count_, log_coeff_count_);

  return true;
}

bool RotatePolynomialTask::process() {
  rotate_polynomial(sources_[0], destination_, permutation_, sign_,
                    coeff_count_);

  return true;
}

bool PermutePolynomialTask::process() {
  permute_polynomial(sources_[0], destination_, permutation_, coeff_count_);

  return true;
}

bool AddScalarTask::process() {
  add_scalar(sources_[0], destination_, scalar_, coeff_count_);

  return true;
}

bool CopyTask::process() {
  std::memcpy(destination_, sources_[0], sizeof(int64_t) * coeff_count_);

  return true;
}

bool ZeroFillTask::process() {
  std::fill(destination_, destination_ + coeff_count_, 0);

  return true;
}

bool CompressPolynomialTask::process() {
  compress_polynomial(sources_[0], destination_, y_count_, jump_);

  return true;
}

bool DecompressPolynomialTask::process() {
  decompress_polynomial(sources_[0], destination_, x_count_, jump_);

  return true;
}

bool RoundTask::process() {
  for (int coeff_index = 0; coeff_index < coeff_count_; ++coeff_index) {
    destination_[coeff_index] = std::llround(sources_[0][coeff_index]);
  }

  return true;
}

bool MaxAbsoluteTask::process() {
  double *max_elem_iter = std::max_element(
      sources_[0], sources_[0] + coeff_count_,
      [](double a, double b) { return std::abs(a) < std::abs(b); });
  *destination_ = max_elem_iter ? std::abs(*max_elem_iter) : 0.0;

  return true;
}

bool CastInt64ToDoubleTask::process() {
  for (int coeff_index = 0; coeff_index < coeff_count_; ++coeff_index) {
    destination_[coeff_index] = static_cast<double>(sources_[0][coeff_index]);
  }

  return true;
}

bool ApplySkewerTask::process() {
  apply_skewer(sources_[0], destination_, count_, start_index_, step_);

  return true;
}

bool FftTask::process() {
  fft(sources_[0], destination_, twiddle_factor_, size_);

  return true;
}

bool DoubleToRNSTask::process() {
  double_to_rns(sources_[0], destination_, q_, chain_count_, coeff_count_,
                coeff_start_, coeff_end_);

  return true;
}

bool RNSToDoubleTask::process() {
  rns_to_double(sources_[0], destination_, q_, q_product_, q_product_half_,
                rns_reverser_, r_minus_k_product_, chain_count_, coeff_count_,
                coeff_start_, coeff_end_);

  return true;
}

}
