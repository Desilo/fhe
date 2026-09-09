#include <string>

#pragma once

namespace desilo::fhe {

std::string get_ordinalized_prefix(const std::string &initial_prefix, int count,
                                   int index);
std::string to_lowercase(const std::string &string);

}
