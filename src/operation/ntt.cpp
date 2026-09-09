#include "operation/ntt.h"
#include "montgomery/unit.h"

namespace desilo::fhe {

void split_ntt(int64_t *x, int64_t *y, const int64_t *root, uint64_t q_double,
               uint64_t q, uint64_t k, int jump_size, int coeff_start,
               int coeff_end) {
  auto x_jumped = x + jump_size;
  auto y_jumped = y + jump_size;
  const auto root_value = *root++;

  for (auto coeff_index = coeff_start; coeff_index < coeff_end; coeff_index++) {
    const auto x_value = *x++;
    const auto x_jumped_value = *x_jumped++;

    const auto product = mont_mult_scalar(root_value, x_jumped_value, q, k);

    *y++ = guard(x_value + product, q_double);
    *y_jumped++ = guard(x_value + q_double - product, q_double);
  }
}

void unit_ntt(int64_t *x, int64_t *y, const int64_t *root, uint64_t q_double,
              uint64_t q, uint64_t k, int jump_size, int jump_count) {
  for (auto jump_index = 0; jump_index < jump_count; jump_index++) {
    auto x_jumped = x + jump_size;
    auto y_jumped = y + jump_size;
    const auto root_value = *root++;

    for (auto coeff_index = 0; coeff_index < jump_size; coeff_index++) {
      const auto x_value = *x++;
      const auto x_jumped_value = *x_jumped++;

      const auto product = mont_mult_scalar(root_value, x_jumped_value, q, k);

      *y++ = guard(x_value + product, q_double);
      *y_jumped++ = guard(x_value + q_double - product, q_double);
    }

    x += jump_size;
    y += jump_size;
  }
}

void ntt(int64_t *x, int64_t *y, const int64_t *root, uint64_t q_double,
         uint64_t q, uint64_t k, int coeff_count, int log_coeff_count) {
  if (x != y) {
    memcpy(y, x, sizeof(int64_t) * coeff_count);
  }

  auto jump_size = coeff_count;

  for (auto log_coeff_index = 0; log_coeff_index < log_coeff_count - 1;
       log_coeff_index++) {
    auto jump_count = 1 << log_coeff_index;
    jump_size >>= 1;
    auto local_y = y;

    if (jump_size < 4) {
      for (auto jump_index = 0; jump_index < jump_count; jump_index++) {
        auto local_y_jumped = local_y + jump_size;
        const auto root_value = *root++;

        for (auto coeff_index = 0; coeff_index < jump_size; coeff_index++) {
          const auto y_value = *local_y;
          const auto y_jumped_value = *local_y_jumped;

          const auto product =
              mont_mult_scalar(root_value, y_jumped_value, q, k);

          *local_y++ = guard(y_value + product, q_double);
          *local_y_jumped++ = guard(y_value + q_double - product, q_double);
        }

        local_y = local_y_jumped;
      }
    } else {
      for (auto jump_index = 0; jump_index < jump_count; jump_index++) {
        auto local_y_jumped = local_y + jump_size;
        const auto root_value = *root++;

        for (auto coeff_index = 0; coeff_index < jump_size; coeff_index += 4) {
          auto y_value = *local_y;
          auto y_jumped_value = *local_y_jumped;

          auto product = mont_mult_scalar(root_value, y_jumped_value, q, k);

          *local_y++ = guard(y_value + product, q_double);
          *local_y_jumped++ = guard(y_value + q_double - product, q_double);

          y_value = *local_y;
          y_jumped_value = *local_y_jumped;

          product = mont_mult_scalar(root_value, y_jumped_value, q, k);

          *local_y++ = guard(y_value + product, q_double);
          *local_y_jumped++ = guard(y_value + q_double - product, q_double);

          y_value = *local_y;
          y_jumped_value = *local_y_jumped;

          product = mont_mult_scalar(root_value, y_jumped_value, q, k);

          *local_y++ = guard(y_value + product, q_double);
          *local_y_jumped++ = guard(y_value + q_double - product, q_double);

          y_value = *local_y;
          y_jumped_value = *local_y_jumped;

          product = mont_mult_scalar(root_value, y_jumped_value, q, k);

          *local_y++ = guard(y_value + product, q_double);
          *local_y_jumped++ = guard(y_value + q_double - product, q_double);
        }

        local_y = local_y_jumped;
      }
    }
  }

  const auto coeff_count_half = coeff_count >> 1;
  auto local_y = y;
  for (auto coeff_index = 0; coeff_index < coeff_count_half; coeff_index++) {
    const auto root_value = *root++;
    const auto y_value = local_y[0];
    const auto y_jumped_value = local_y[1];

    const auto product = mont_mult_scalar(root_value, y_jumped_value, q, k);

    *local_y++ = guard(y_value + product, q_double);
    *local_y++ = guard(y_value + q_double - product, q_double);
  }
}

void split_intt(int64_t *x, int64_t *y, const int64_t *root_inverse,
                uint64_t q_double, uint64_t q, uint64_t k, int jump_size,
                int coeff_start, int coeff_end) {
  auto x_jumped = x + jump_size;
  auto y_jumped = y + jump_size;
  const auto root_inverse_value = *root_inverse++;

  for (auto coeff_index = coeff_start; coeff_index < coeff_end; coeff_index++) {
    const auto x_value = *x++;
    const auto x_jumped_value = *x_jumped++;

    *y++ = guard(x_value + x_jumped_value, q_double);
    *y_jumped++ = mont_mult_scalar(
        root_inverse_value,
        guard(x_value + q_double - x_jumped_value, q_double), q, k);
  }
}

void unit_intt(int64_t *x, int64_t *y, const int64_t *root_inverse,
               uint64_t q_double, uint64_t q, uint64_t k, int jump_size,
               int jump_count) {
  for (auto jump_index = 0; jump_index < jump_count; jump_index++) {
    auto x_jumped = x + jump_size;
    auto y_jumped = y + jump_size;
    const auto root_inverse_value = *root_inverse++;

    for (auto coeff_index = 0; coeff_index < jump_size; coeff_index++) {
      const auto x_value = *x++;
      const auto x_jumped_value = *x_jumped++;

      *y++ = guard(x_value + x_jumped_value, q_double);
      *y_jumped++ = mont_mult_scalar(
          root_inverse_value,
          guard(x_value + q_double - x_jumped_value, q_double), q, k);
    }

    x += jump_size;
    y += jump_size;
  }
}

void intt(int64_t *x, int64_t *y, const int64_t *root_inverse,
          uint64_t q_double, uint64_t q, uint64_t k, int coeff_count,
          int log_coeff_count) {
  if (x != y) {
    memcpy(y, x, sizeof(int64_t) * coeff_count);
  }

  auto local_y = y;

  const auto coeff_count_half = coeff_count >> 1;

  for (auto coeff_index = 0; coeff_index < coeff_count_half; coeff_index++) {
    const auto local_root_inverse_value = *root_inverse++;
    const auto local_y_value = local_y[0];
    const auto local_y_jumped_value = local_y[1];

    *local_y++ = guard(local_y_value + local_y_jumped_value, q_double);
    *local_y++ = mont_mult_scalar(
        local_root_inverse_value,
        guard(local_y_value + q_double - local_y_jumped_value, q_double), q, k);
  }

  auto jump_size = 2;

  for (auto log_coeff_index = log_coeff_count - 2; log_coeff_index >= 0;
       log_coeff_index--) {
    auto jump_count = 1 << log_coeff_index;
    auto local_y = y;

    if (jump_size < 4) {
      for (auto jump_index = 0; jump_index < jump_count; jump_index++) {
        auto local_y_jumped = local_y + jump_size;
        const auto local_root_inverse_value = *root_inverse++;

        for (auto coeff_index = 0; coeff_index < jump_size; coeff_index++) {
          const auto local_y_value = *local_y;
          const auto local_y_jumped_value = *local_y_jumped;

          *local_y++ = guard(local_y_value + local_y_jumped_value, q_double);
          *local_y_jumped++ = mont_mult_scalar(
              local_root_inverse_value,
              guard(local_y_value + q_double - local_y_jumped_value, q_double),
              q, k);
        }

        local_y = local_y_jumped;
      }
    } else {
      for (auto jump_index = 0; jump_index < jump_count; jump_index++) {
        auto local_y_jumped = local_y + jump_size;
        const auto local_root_inverse_value = *root_inverse++;

        for (auto coeff_index = 0; coeff_index < jump_size; coeff_index += 4) {
          auto local_y_value = *local_y;
          auto local_y_jumped_value = *local_y_jumped;

          *local_y++ = guard(local_y_value + local_y_jumped_value, q_double);
          *local_y_jumped++ = mont_mult_scalar(
              local_root_inverse_value,
              guard(local_y_value + q_double - local_y_jumped_value, q_double),
              q, k);

          local_y_value = *local_y;
          local_y_jumped_value = *local_y_jumped;

          *local_y++ = guard(local_y_value + local_y_jumped_value, q_double);
          *local_y_jumped++ = mont_mult_scalar(
              local_root_inverse_value,
              guard(local_y_value + q_double - local_y_jumped_value, q_double),
              q, k);

          local_y_value = *local_y;
          local_y_jumped_value = *local_y_jumped;

          *local_y++ = guard(local_y_value + local_y_jumped_value, q_double);
          *local_y_jumped++ = mont_mult_scalar(
              local_root_inverse_value,
              guard(local_y_value + q_double - local_y_jumped_value, q_double),
              q, k);

          local_y_value = *local_y;
          local_y_jumped_value = *local_y_jumped;

          *local_y++ = guard(local_y_value + local_y_jumped_value, q_double);
          *local_y_jumped++ = mont_mult_scalar(
              local_root_inverse_value,
              guard(local_y_value + q_double - local_y_jumped_value, q_double),
              q, k);
        }

        local_y = local_y_jumped;
      }
    }
    jump_size <<= 1;
  }
}

}
