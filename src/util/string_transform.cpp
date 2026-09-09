#include <algorithm>
#include <cctype>
#include <stdexcept>

#include "string_transform.h"

namespace desilo::fhe {

std::string get_ordinalized_prefix(const std::string &initial_prefix, int count,
                                   int index) {
  if (count < 1) {
    throw std::invalid_argument("Count must be greater than or equal to 1.");
  }

  auto prefix = initial_prefix;
  if (count > 1) {
    prefix += " ";
    switch (index) {
    case 0:
      prefix += "first";
      break;
    case 1:
      prefix += "second";
      break;
    case 2:
      prefix += "third";
      break;
    default:
      prefix += std::to_string(index + 1) + "th";
      break;
    }
  }

  return prefix;
}

std::string to_lowercase(const std::string &string) {
  std::string lowercase = string;
  std::transform(string.cbegin(), string.cend(), lowercase.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  return lowercase;
}

}
