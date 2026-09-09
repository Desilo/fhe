#include "parameter/multiplier.h"

namespace desilo::fhe {

Multiplier::Multiplier(Multiplier &&other) noexcept
    : multiplier_(std::move(other.multiplier_)) {}

int64_t *Multiplier::get() { return multiplier_.data(); }

}
