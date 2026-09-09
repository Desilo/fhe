#include "ckks/config.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"
#include "engine/scheme_preset.h"

class CKKSCoreUtil : public testing::TestWithParam<
                         std::tuple<desilo::fhe::SchemePreset, int, int, int>> {
};

INSTANTIATE_TEST_CASE_P(
    , CKKSCoreUtil,
    testing::Values(

        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 2, 2, 5),
        std::make_tuple(desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT, 7, 7,
                        10)),
    [](const testing::TestParamInfo<CKKSCoreUtil::ParamType> &info) {
      return print_scheme_preset(std::get<0>(info.param)) +
             print_level(std::get<1>(info.param));
    });

TEST_P(CKKSCoreUtil, GetConstants) {
  const auto [scheme_preset, level, max_level, prime_count] = GetParam();

  desilo::fhe::CKKSConfig config;

  if (scheme_preset == desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT) {
    config = desilo::fhe::CKKSConfig::from_max_level(level);
  }

  config.scheme_preset_ = scheme_preset;
  auto core = desilo::fhe::CKKSCore(config);

  EXPECT_EQ(core.parameters_.get_max_level(), max_level);
  EXPECT_EQ(core.get_prime_count(), prime_count);
}
