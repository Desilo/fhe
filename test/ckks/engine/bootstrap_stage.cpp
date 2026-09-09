#include <gtest/gtest.h>

#include "ckks/config.h"
#include "ckks/engine.h"
#include "ckks/engine/common.h"
#include "common/common.h"
#include "common/test.h"

class BootstrapStage : public testing::TestWithParam<std::tuple<int, int>> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::for_bootstrap();
    engine_ = new desilo::fhe::CKKSEngine(config);
  }

  static void TearDownTestSuite() { delete engine_; }

  static desilo::fhe::CKKSEngine *engine_;
};

desilo::fhe::CKKSEngine *BootstrapStage::engine_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    Gold, BootstrapStage,
    testing::Combine(testing::Values(3, 4, 5), testing::Values(0, 1)),
    [](const testing::TestParamInfo<BootstrapStage::ParamType> &info) {
      return std::to_string(std::get<0>(info.param)) + "Stages" +
             (std::get<1>(info.param) == 0 ? "Medium" : "Large");
    });

std::map<int, std::map<int, std::vector<std::pair<int, int>>>> loops = {
    {0,
     {{3, {{8, 8}, {8, 8}, {8, 8}}},
      {4, {{4, 4}, {8, 4}, {8, 4}, {8, 4}}},
      {5, {{4, 4}, {4, 4}, {4, 4}, {4, 4}, {4, 4}}}}},
    {1,
     {{3, {{16, 4}, {16, 4}, {16, 4}}},
      {4, {{8, 2}, {16, 2}, {16, 2}, {16, 2}}},
      {5, {{8, 2}, {8, 2}, {8, 2}, {8, 2}, {8, 2}}}}}};

std::map<int, std::map<int, std::vector<std::vector<int>>>> inner_deltas = {
    {0,
     {{3,
       {
           {0, 1024, 2048, 3072, 4096, 5120, 6144, 7168},
           {0, 32, 64, 96, 128, 160, 192, 224},
           {0, 1, 2, 3, 4, 5, 6, 7},
       }},
      {4,
       {
           {0, 4096, 8192, 12288},
           {0, 256, 512, 768, 1024, 1280, 1536, 1792},
           {0, 16, 32, 48, 64, 80, 96, 112},
           {0, 1, 2, 3, 4, 5, 6, 7},
       }},
      {5,
       {
           {0, 4096, 8192, 12288},
           {0, 512, 1024, 1536},
           {0, 64, 128, 192},
           {0, 8, 16, 24},
           {0, 1, 2, 3},
       }}}},
    {1,
     {{3,
       {
           {0, 1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192, 9216, 10240,
            11264, 12288, 13312, 14336, 15360},
           {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416,
            448, 480},
           {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
       }},
      {4,
       {
           {0, 4096, 8192, 12288, 16384, 20480, 24576, 28672},
           {0, 256, 512, 768, 1024, 1280, 1536, 1792, 2048, 2304, 2560, 2816,
            3072, 3328, 3584, 3840},
           {0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224,
            240},
           {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
       }},
      {5,
       {
           {0, 4096, 8192, 12288, 16384, 20480, 24576, 28672},
           {0, 512, 1024, 1536, 2048, 2560, 3072, 3584},
           {0, 64, 128, 192, 256, 320, 384, 448},
           {0, 8, 16, 24, 32, 40, 48, 56},
           {0, 1, 2, 3, 4, 5, 6, 7},
       }}}}};

std::map<int, std::map<int, std::vector<std::vector<int>>>> outer_deltas = {
    {0,
     {{3,
       {

           {0, 8192, 16384, 24576, 0, 8192, 16384, 24576},

           {31744, 32000, 32256, 32512, 0, 256, 512, 768},

           {32736, 32744, 32752, 32760, 0, 8, 16, 24},
       }},
      {4,
       {

           {0, 16384, 0, 16384},

           {28672, 30720, 0, 2048},

           {32512, 32640, 0, 128},

           {32752, 32760, 0, 8},
       }},
      {5,
       {

           {0, 16384, 0, 16384},

           {28672, 30720, 0, 2048},

           {32256, 32512, 0, 256},

           {32704, 32736, 0, 32},

           {32760, 32764, 0, 4},
       }}}},
    {1,
     {{3,
       {

           {0, 16384, 0, 16384},

           {31744, 32256, 0, 512},

           {32736, 32752, 0, 16},
       }},
      {4,
       {

           {0, 0},

           {28672, 0},

           {32512, 0},

           {32752, 0},
       }},
      {5,
       {

           {0, 0},

           {28672, 0},

           {32256, 0},

           {32704, 0},

           {32760, 0},
       }}}}};

TEST_P(BootstrapStage, MakeCoeffToSlot) {
  const auto [stage_count, inner_loop_shift] = GetParam();

  const int coeff_to_slot_stage_level = 25;
  auto stages = engine_->make_coeff_to_slot_stages(
      stage_count, inner_loop_shift, coeff_to_slot_stage_level);

  ASSERT_EQ(stages.size(), stage_count);

  int stage_level_base = coeff_to_slot_stage_level;
  for (int stage_index = 0; stage_index < stages.size(); stage_index++) {
    auto stage = stages[stage_index];
    auto [expected_inner_loop_count, expected_outer_loop_count] =
        loops[inner_loop_shift][stage_count][stage_index];

    EXPECT_EQ(stage->level_, stage_level_base - stage_index);
    EXPECT_EQ(stage->inner_loop_count_, expected_inner_loop_count);
    EXPECT_EQ(stage->outer_loop_count_, expected_outer_loop_count);
    EXPECT_EQ(stage->inner_loop_deltas_.size(), stage->inner_loop_count_);
    EXPECT_EQ(stage->outer_loop_deltas_.size(), stage->outer_loop_count_);

    for (int delta_index = 0; delta_index < stage->inner_loop_deltas_.size();
         delta_index++) {
      EXPECT_EQ(
          stage->inner_loop_deltas_[delta_index],
          inner_deltas[inner_loop_shift][stage_count][stage_index][delta_index])
          << "values different at index (" << stage_index << ", " << delta_index
          << ")";
    }

    for (int delta_index = 0; delta_index < stage->outer_loop_deltas_.size();
         delta_index++) {
      EXPECT_EQ(
          stage->outer_loop_deltas_[delta_index],
          outer_deltas[inner_loop_shift][stage_count][stage_index][delta_index])
          << "values different at index (" << stage_index << ", " << delta_index
          << ")";
    }
  }

  for (auto stage : stages) {
    delete stage;
  }
}

TEST_P(BootstrapStage, MakeSlotToCoeff) {
  const auto [stage_count, inner_loop_shift] = GetParam();

  const int slot_to_coeff_stage_level = 25 - 9 - stage_count;
  auto stages = engine_->make_slot_to_coeff_stages(
      stage_count, inner_loop_shift, slot_to_coeff_stage_level);

  ASSERT_EQ(stages.size(), stage_count);

  int stage_level_base = slot_to_coeff_stage_level;
  for (int stage_index = 0; stage_index < stages.size(); stage_index++) {
    auto stage = stages[stage_index];

    auto inverse_stage_index = stage_count - 1 - stage_index;
    auto [expected_inner_loop_count, expected_outer_loop_count] =
        loops[inner_loop_shift][stage_count][inverse_stage_index];

    EXPECT_EQ(stage->level_, stage_level_base - stage_index);
    EXPECT_EQ(stage->inner_loop_count_, expected_inner_loop_count);
    EXPECT_EQ(stage->outer_loop_count_, expected_outer_loop_count);
    EXPECT_EQ(stage->inner_loop_deltas_.size(), stage->inner_loop_count_);
    EXPECT_EQ(stage->outer_loop_deltas_.size(), stage->outer_loop_count_);

    for (int delta_index = 0; delta_index < stage->inner_loop_deltas_.size();
         delta_index++) {
      EXPECT_EQ(stage->inner_loop_deltas_[delta_index],
                inner_deltas[inner_loop_shift][stage_count][inverse_stage_index]
                            [delta_index])
          << "values different at index (" << stage_index << ", " << delta_index
          << ")";
    }

    for (int delta_index = 0; delta_index < stage->outer_loop_deltas_.size();
         delta_index++) {
      EXPECT_EQ(stage->outer_loop_deltas_[delta_index],
                outer_deltas[inner_loop_shift][stage_count][inverse_stage_index]
                            [delta_index])
          << "values different at index (" << stage_index << ", " << delta_index
          << ")";
    }
  }

  for (auto stage : stages) {
    delete stage;
  }
}
