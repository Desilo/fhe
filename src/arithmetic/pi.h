#include <numbers>

#pragma once

namespace desilo::fhe {

#if defined(__APPLE__) && __cplusplus >= 202002L
constexpr double pi = 3.14159265358979323846;
#else
using std::numbers::pi;
#endif

}
