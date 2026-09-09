#include <regex>
#include <stdexcept>
#include <vector>

#include "common/common.h"
#include "common/test.h"
#include "engine/scheme_preset.h"

void initiate_message(double *message, int slot_count, int message_type) {
  switch (message_type) {
  case 1:
    for (int i = 0; i < slot_count; i++) {
      message[i] = 0;
    }
    break;
  case 2:
    for (int i = 0; i < slot_count; i++) {
      message[i] = 1;
    }
    break;
  case 3:
    for (int i = 0; i < slot_count; i++) {
      message[i] = i;
    }
    break;
  case 4:
    for (int i = 0; i < slot_count; i++) {
      message[i] = 2;
    }
    break;
  case 5:
    for (int i = 0; i < slot_count; i++) {
      message[i] = i * (1 << 20);
    }
    break;
  default:
    throw std::invalid_argument("Invalid Message Type.");
  }
}

void initiate_message(std::vector<double> &message, int message_type) {
  initiate_message(message.data(), message.size(), message_type);
}

void initiate_message(std::complex<double> *message, int slot_count,
                      int message_type) {
  switch (message_type) {
  case 1:
    for (int i = 0; i < slot_count; i++) {
      message[i] = std::complex(0.0, 0.0);
    }
    break;
  case 2:
    for (int i = 0; i < slot_count; i++) {
      message[i] = std::complex(1.0, 1.0);
    }
    break;
  case 3:
    for (int i = 0; i < slot_count; i++) {
      message[i] = std::complex(static_cast<double>(i), static_cast<double>(i));
    }
    break;
  case 4:
    for (int i = 0; i < slot_count; i++) {
      message[i] = std::complex(2.0, 2.0);
    }
    break;
  case 5:
    for (int i = 0; i < slot_count; i++) {
      message[i] = std::complex(static_cast<double>(i) * (1 << 20),
                                static_cast<double>(i) * (1 << 20));
    }
    break;
  default:
    throw std::invalid_argument("Invalid Message Type.");
  }
}

void initiate_message(std::vector<std::complex<double>> &message,
                      int message_type) {
  initiate_message(message.data(), message.size(), message_type);
}

void initiate_4d_message(std::vector<std::complex<double>> &message,
                         int message_type, int bound) {
  initiate_message(message.data(), message.size(), message_type);

  if (message_type == 3) {
    apply_modulo_to_message(message, bound);
  }
}

void apply_modulo_to_message(std::vector<std::complex<double>> &message,
                             int64_t modulus) {
  for (int index = 0; index < message.size(); index++) {
    int64_t real_value = message[index].real();
    int64_t imag_value = message[index].imag();
    message[index] = {static_cast<double>(real_value % modulus),
                      static_cast<double>(imag_value % modulus)};
  }
}
void initiate_sliced_message(double *message, int slice_count, int slot_count,
                             double multiplier) {
  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      int index = slice_index * slot_count + slot_index;
      message[index] =
          (slice_index + static_cast<double>(slot_index) / slot_count) *
          multiplier;
    }
  }
}

void initiate_sliced_message(std::vector<double> &message, int slice_count,
                             int slot_count, double multiplier) {
  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      int index = slice_index * slot_count + slot_index;
      message[index] =
          (slice_index + static_cast<double>(slot_index) / slot_count) *
          multiplier;
    }
  }
}

void initiate_sliced_message(std::complex<double> *message, int slice_count,
                             int slot_count, double multiplier) {
  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      int index = slice_index * slot_count + slot_index;
      double value =
          (slice_index + static_cast<double>(slot_index) / slot_count) *
          multiplier;
      message[index] = std::complex(value, value);
    }
  }
}

void initiate_sliced_message(std::vector<std::complex<double>> &message,
                             int slice_count, int slot_count,
                             double multiplier) {
  for (int slice_index = 0; slice_index < slice_count; slice_index++) {
    for (int slot_index = 0; slot_index < slot_count; slot_index++) {
      int index = slice_index * slot_count + slot_index;
      double value =
          (slice_index + static_cast<double>(slot_index) / slot_count) *
          multiplier;
      message[index] = std::complex(value, value);
    }
  }
}

void initialize_random_state(int64_t *state, int thread_count) {
  for (auto thread_index = 0; thread_index < thread_count; thread_index++) {
    const auto thread_state = &state[thread_index * 16];

    thread_state[0] = 1634760805;
    thread_state[1] = 857760878;
    thread_state[2] = 2036477234;
    thread_state[3] = 1797285236;

    thread_state[4] = 1;
    thread_state[5] = 2;
    thread_state[6] = 3;
    thread_state[7] = 4;
    thread_state[8] = 5;
    thread_state[9] = 6;
    thread_state[10] = 7;
    thread_state[11] = 8;

    thread_state[12] = thread_index;
    thread_state[13] = 0;

    thread_state[14] = 9;
    thread_state[15] = 10;
  }
}

std::string print_tier(int log_coeff_count) {
  std::string tier_name;
  switch (log_coeff_count) {
  case 3:
    tier_name = "Sand";
    break;
  case 4:
    tier_name = "Pebble";
    break;
  case 13:
    tier_name = "Iron";
    break;
  case 14:
    tier_name = "Bronze";
    break;
  case 15:
    tier_name = "Silver";
    break;
  case 16:
    tier_name = "Gold";
    break;
  case 17:
    tier_name = "Platinum";
    break;
  default:
    throw std::invalid_argument("Undefined Tier.");
  }
  return tier_name;
}

std::string print_message_type(int message_type) {
  std::string message_type_name;
  switch (message_type) {
  case 1:
    message_type_name = "Zeros";
    break;
  case 2:
    message_type_name = "Ones";
    break;
  case 3:
    message_type_name = "Arange";
    break;
  case 4:
    message_type_name = "Twos";
    break;
  default:
    throw std::invalid_argument("Undefined Message Type.");
  }
  return message_type_name;
}

std::string print_container_type(int container_type) {
  std::string container_type_name;
  switch (container_type) {
  case 1:
    container_type_name = "Buffer";
    break;
  case 2:
    container_type_name = "Vector";
    break;
  default:
    throw std::invalid_argument("Undefined Container Type.");
  }
  return container_type_name;
}

std::string print_level(int level) {
  return "Level" +
         std::regex_replace(std::to_string(level), std::regex("-"), "Minus");
}

std::string print_level_depth(int level_depth) {
  return "LevelDepth" + std::to_string(level_depth);
}

std::string print_moduli_id(int moduli_id) {
  return "ModuliID" + std::to_string(moduli_id);
}

std::string print_delta(int delta) {
  return "Delta" +
         std::regex_replace(std::to_string(delta), std::regex("-"), "Minus");
}

std::string print_scalar(int scalar) {
  return "Scalar" +
         std::regex_replace(std::to_string(scalar), std::regex("-"), "Minus");
}

std::string print_ckks_scale(int log_ckks_scale) {
  return "CKKSScale" + std::to_string(log_ckks_scale);
}

std::string print_stream_count(int stream_count) {
  return std::to_string(stream_count) + "Stream";
}

std::string print_slice_count(int slice_count) {
  return std::to_string(slice_count) + "Slice";
}

std::string print_long_extended(const bool extended) {
  return print_slice_count(extended ? 2 : 1);
}

std::string print_include_special(const bool include_special) {
  return include_special ? "IncludeSpecial" : "";
}

std::string print_ciphertext_first(const bool ciphertext_first) {
  return ciphertext_first ? "CiphertextFirst" : "CiphertextLast";
}

std::string print_ntt_flag(const bool flag_type) {
  return flag_type ? "NTT" : "INTT";
}

std::string print_rescaled_flag(const bool flag_type) {
  return flag_type ? "Rescaled" : "";
}

std::string print_trio_first(const bool trio_first) {
  return trio_first ? "TrioFirst" : "TrioLast";
}

std::string print_input_order(int input_order) {
  switch (input_order) {
  case 1:
    return "";
  case 2:
    return "InputReversed";
  default:
    throw std::invalid_argument("Undefined Input Order.");
  }
}

std::string print_level_order(int level_order) {
  switch (level_order) {
  case 1:
    return "";
  case 2:
    return "LevelReversed";
  default:
    throw std::invalid_argument("Undefined Level Order.");
  }
}

std::string print_process_type(int process_type) {
  switch (process_type) {
  case 1:
    return "CPU";
  case 2:
    return "CPUParallel";
  default:
    throw std::invalid_argument("Undefined Parallel Type.");
  }
}

std::string print_rescale_flags(int flag_type) {
  switch (flag_type) {
  case 1:
    return "NotRescaledAndNotRescaled";
  case 2:
    return "NotRescaledAndRescaled";
  case 3:
    return "RescaledAndNotRescaled";
  case 4:
    return "RescaledAndRescaled";
  default:
    throw std::invalid_argument("Undefined Type.");
  }
}

std::string print_scheme_preset(desilo::fhe::SchemePreset scheme_preset) {
  switch (scheme_preset) {
  case desilo::fhe::SchemePreset::NONE:
    return "InvalidScheme";
  case desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT:
  case desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT_ENGINE_TEST:
    return "CKKS";
  case desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP:
  case desilo::fhe::SchemePreset::CKKS_54_60_BOOTSTRAP_ENGINE_TEST:
    return "CKKSBootstrap54";
  default:
    throw std::invalid_argument("Undefined Scheme.");
  }
}

std::string print_max_power(int max_power) {
  return "MaxPower" + std::to_string(max_power);
}

std::string print_polynomial(int polynomial_type) {
  return "Polynomial" + std::to_string(polynomial_type);
}

std::string print_log_slot_count(int log_slot_count) {
  return "LogSlotCount" + std::regex_replace(std::to_string(log_slot_count),
                                             std::regex("-"), "Minus");
}

bool get_use_bootstrap(const desilo::fhe::CKKSConfig &config) {
  return desilo::fhe::scheme_preset::get_use_bootstrap(config.scheme_preset_);
}

bool get_use_one_more_level(const desilo::fhe::CKKSConfig &config) {
  return desilo::fhe::scheme_preset::get_use_one_more_level(
      config.scheme_preset_);
}
