#pragma once

namespace desilo::fhe {

enum class Requirement : int {
  DUO = 1,
  TRIO = 2,
  NTT = 3,
  INTT = 4,
  MATCH_NTT = 5,
  NOT_RESCALED = 6,
  DUOS_OR_TRIOS = 7,
  LEVEL_ZERO = 8,
  SAME_DELTA = 9,
  MATCH_CKKS_SCALE = 10,
  MATCH_SIZE = 11,
  NOT_ONE_MORE_LEVEL = 12,
  MATCH_LEVEL = 13,
  DUO_OR_TRIO = 14,
  POSITIVE_LEVEL = 15,
  NOT_LEVEL_ZERO_RESCALED = 16,
  MATCH_RESCALED = 17,
  MATCH_POLYNOMIAL_COUNT = 18,
};

}
