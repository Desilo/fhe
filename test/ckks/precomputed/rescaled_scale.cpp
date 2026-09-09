#include <cmath>

#include "ckks/config.h"
#include "ckks/precomputed.h"
#include "common/common.h"
#include "common/test.h"

TEST(GetRescaledScale, Iron) {
  auto config = desilo::fhe::CKKSConfig::from_tier("iron");
  auto precomputed = desilo::fhe::CKKSPrecomputed(config);

  long double scale = std::pow(2.0L, 60);
  EXPECT_NEAR(precomputed.get_rescaled_scale(scale, 0), 1.0000000000000853,
              1e-15);

  scale = std::pow(2.0L, 40);
  EXPECT_NEAR(precomputed.get_rescaled_scale(scale, 1), 0.9999997317782610,
              1e-15);

  scale = std::pow(2.0L, 40);
  EXPECT_NEAR(precomputed.get_rescaled_scale(scale, 2), 1.0000006705517939,
              1e-15);
}
