#include "ckks/config.h"
#include "ckks/parameters.h"
#include "common/common.h"
#include "common/test.h"
#include "engine/scheme_preset.h"

#define MATRIX std::vector<std::vector<int>>

class GetPartitionsSand1
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::from_tier("sand");
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsSand1::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsSand1,
    testing::Values(
        std::make_tuple(1, 1, 0,
                        MATRIX{{0},  {1},  {2},  {3},  {4},  {5},  {6},  {7},
                               {8},  {9},  {10}, {11}, {12}, {13}, {14}, {15},
                               {16}, {17}, {18}, {19}, {20}, {21}, {22}}),
        std::make_tuple(2, 1, 1,
                        MATRIX{{0},  {1},  {2},  {3},  {4},  {5},  {6},  {7},
                               {8},  {9},  {10}, {11}, {12}, {13}, {14}, {15},
                               {16}, {17}, {18}, {19}, {20}, {21}}),
        std::make_tuple(22, 1, 21, MATRIX{{0}, {1}})),
    [](const testing::TestParamInfo<GetPartitionsSand1::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsSand1, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsSand2
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::from_tier("sand");
    config.special_prime_count_ = 2;
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsSand2::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsSand2,
    testing::Values(std::make_tuple(1, 1, 0,
                                    MATRIX{{0},
                                           {1, 2},
                                           {3, 4},
                                           {5, 6},
                                           {7, 8},
                                           {9, 10},
                                           {11, 12},
                                           {13, 14},
                                           {15, 16},
                                           {17, 18},
                                           {19, 20}}),
                    std::make_tuple(2, 1, 1,
                                    MATRIX{{0, 1},
                                           {2, 3},
                                           {4, 5},
                                           {6, 7},
                                           {8, 9},
                                           {10, 11},
                                           {12, 13},
                                           {14, 15},
                                           {16, 17},
                                           {18, 19}}),
                    std::make_tuple(3, 1, 1,
                                    MATRIX{{0},
                                           {1, 2},
                                           {3, 4},
                                           {5, 6},
                                           {7, 8},
                                           {9, 10},
                                           {11, 12},
                                           {13, 14},
                                           {15, 16},
                                           {17, 18}}),
                    std::make_tuple(19, 1, 9, MATRIX{{0}, {1, 2}}),
                    std::make_tuple(20, 1, 10, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsSand2::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsSand2, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsSand4
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::from_tier("sand");
    config.special_prime_count_ = 4;
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsSand4::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsSand4,
    testing::Values(
        std::make_tuple(1, 1, 0,
                        MATRIX{{0, 1},
                               {2, 3, 4, 5},
                               {6, 7, 8, 9},
                               {10, 11, 12, 13},
                               {14, 15, 16, 17}}),
        std::make_tuple(2, 1, 0,
                        MATRIX{{0},
                               {1, 2, 3, 4},
                               {5, 6, 7, 8},
                               {9, 10, 11, 12},
                               {13, 14, 15, 16}}),
        std::make_tuple(3, 1, 1,
                        MATRIX{{0, 1, 2, 3},
                               {4, 5, 6, 7},
                               {8, 9, 10, 11},
                               {12, 13, 14, 15}}),
        std::make_tuple(
            4, 1, 1,
            MATRIX{{0, 1, 2}, {3, 4, 5, 6}, {7, 8, 9, 10}, {11, 12, 13, 14}}),
        std::make_tuple(
            5, 1, 1,
            MATRIX{{0, 1}, {2, 3, 4, 5}, {6, 7, 8, 9}, {10, 11, 12, 13}}),
        std::make_tuple(13, 1, 3, MATRIX{{0, 1}, {2, 3, 4, 5}}),
        std::make_tuple(14, 1, 3, MATRIX{{0}, {1, 2, 3, 4}}),
        std::make_tuple(15, 1, 4, MATRIX{{0, 1, 2, 3}}),
        std::make_tuple(16, 1, 4, MATRIX{{0, 1, 2}}),
        std::make_tuple(16, 5, 3, MATRIX{{0, 1, 2}}),
        std::make_tuple(17, 15, 0, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsSand4::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsSand4, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsPebble1
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsPebble1::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsPebble1,
    testing::Values(
        std::make_tuple(1, 1, 0,
                        MATRIX{{0},  {1},  {2},  {3},  {4},  {5},  {6},  {7},
                               {8},  {9},  {10}, {11}, {12}, {13}, {14}, {15},
                               {16}, {17}, {18}, {19}, {20}, {21}, {22}}),
        std::make_tuple(2, 1, 1,
                        MATRIX{{0},  {1},  {2},  {3},  {4},  {5},  {6},  {7},
                               {8},  {9},  {10}, {11}, {12}, {13}, {14}, {15},
                               {16}, {17}, {18}, {19}, {20}, {21}}),
        std::make_tuple(22, 1, 21, MATRIX{{0}, {1}})),
    [](const testing::TestParamInfo<GetPartitionsPebble1::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsPebble1, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsPebble2
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
    config.special_prime_count_ = 2;
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsPebble2::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsPebble2,
    testing::Values(std::make_tuple(1, 1, 0,
                                    MATRIX{{0},
                                           {1, 2},
                                           {3, 4},
                                           {5, 6},
                                           {7, 8},
                                           {9, 10},
                                           {11, 12},
                                           {13, 14},
                                           {15, 16},
                                           {17, 18},
                                           {19, 20}}),
                    std::make_tuple(2, 1, 1,
                                    MATRIX{{0, 1},
                                           {2, 3},
                                           {4, 5},
                                           {6, 7},
                                           {8, 9},
                                           {10, 11},
                                           {12, 13},
                                           {14, 15},
                                           {16, 17},
                                           {18, 19}}),
                    std::make_tuple(3, 1, 1,
                                    MATRIX{{0},
                                           {1, 2},
                                           {3, 4},
                                           {5, 6},
                                           {7, 8},
                                           {9, 10},
                                           {11, 12},
                                           {13, 14},
                                           {15, 16},
                                           {17, 18}}),
                    std::make_tuple(19, 1, 9, MATRIX{{0}, {1, 2}}),
                    std::make_tuple(20, 1, 10, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsPebble2::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsPebble2, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsPebble4
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    auto config = desilo::fhe::CKKSConfig::from_tier("pebble");
    config.special_prime_count_ = 4;
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsPebble4::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsPebble4,
    testing::Values(
        std::make_tuple(1, 1, 0,
                        MATRIX{{0, 1},
                               {2, 3, 4, 5},
                               {6, 7, 8, 9},
                               {10, 11, 12, 13},
                               {14, 15, 16, 17}}),
        std::make_tuple(2, 1, 0,
                        MATRIX{{0},
                               {1, 2, 3, 4},
                               {5, 6, 7, 8},
                               {9, 10, 11, 12},
                               {13, 14, 15, 16}}),
        std::make_tuple(3, 1, 1,
                        MATRIX{{0, 1, 2, 3},
                               {4, 5, 6, 7},
                               {8, 9, 10, 11},
                               {12, 13, 14, 15}}),
        std::make_tuple(
            4, 1, 1,
            MATRIX{{0, 1, 2}, {3, 4, 5, 6}, {7, 8, 9, 10}, {11, 12, 13, 14}}),
        std::make_tuple(
            5, 1, 1,
            MATRIX{{0, 1}, {2, 3, 4, 5}, {6, 7, 8, 9}, {10, 11, 12, 13}}),
        std::make_tuple(13, 1, 3, MATRIX{{0, 1}, {2, 3, 4, 5}}),
        std::make_tuple(14, 1, 3, MATRIX{{0}, {1, 2, 3, 4}}),
        std::make_tuple(15, 1, 4, MATRIX{{0, 1, 2, 3}}),
        std::make_tuple(16, 1, 4, MATRIX{{0, 1, 2}}),
        std::make_tuple(16, 5, 3, MATRIX{{0, 1, 2}}),
        std::make_tuple(17, 15, 0, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsPebble4::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsPebble4, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsIron
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::from_tier("iron");
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsIron::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsIron,
    testing::Values(std::make_tuple(1, 1, 0, MATRIX{{0}, {1}, {2}}),
                    std::make_tuple(2, 1, 1, MATRIX{{0}, {1}}),
                    std::make_tuple(2, 2, 0, MATRIX{{0}, {1}})),
    [](const testing::TestParamInfo<GetPartitionsIron::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsIron, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsBronze
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::from_tier("bronze");
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsBronze::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsBronze,
    testing::Values(
        std::make_tuple(1, 1, 0,
                        MATRIX{{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}}),
        std::make_tuple(2, 1, 1, MATRIX{{0}, {1}, {2}, {3}, {4}, {5}, {6}}),
        std::make_tuple(7, 1, 6, MATRIX{{0}, {1}})),
    [](const testing::TestParamInfo<GetPartitionsBronze::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsBronze, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsSilver
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::from_tier("silver");
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsSilver::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsSilver,
    testing::Values(std::make_tuple(1, 1, 0,
                                    MATRIX{{0, 1},
                                           {2, 3},
                                           {4, 5},
                                           {6, 7},
                                           {8, 9},
                                           {10, 11},
                                           {12, 13},
                                           {14, 15},
                                           {16, 17}}),
                    std::make_tuple(2, 1, 0,
                                    MATRIX{{0},
                                           {1, 2},
                                           {3, 4},
                                           {5, 6},
                                           {7, 8},
                                           {9, 10},
                                           {11, 12},
                                           {13, 14},
                                           {15, 16}}),
                    std::make_tuple(3, 1, 1,
                                    MATRIX{{0, 1},
                                           {2, 3},
                                           {4, 5},
                                           {6, 7},
                                           {8, 9},
                                           {10, 11},
                                           {12, 13},
                                           {14, 15}}),
                    std::make_tuple(16, 1, 7, MATRIX{{0}, {1, 2}}),
                    std::make_tuple(17, 1, 8, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsSilver::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsSilver, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsGold
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::from_tier("gold");
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsGold::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsGold,
    testing::Values(std::make_tuple(1, 1, 0,
                                    MATRIX{{0},
                                           {1, 2, 3, 4},
                                           {5, 6, 7, 8},
                                           {9, 10, 11, 12},
                                           {13, 14, 15, 16},
                                           {17, 18, 19, 20},
                                           {21, 22, 23, 24},
                                           {25, 26, 27, 28},
                                           {29, 30, 31, 32},
                                           {33, 34, 35, 36}}),
                    std::make_tuple(2, 1, 1,
                                    MATRIX{{0, 1, 2, 3},
                                           {4, 5, 6, 7},
                                           {8, 9, 10, 11},
                                           {12, 13, 14, 15},
                                           {16, 17, 18, 19},
                                           {20, 21, 22, 23},
                                           {24, 25, 26, 27},
                                           {28, 29, 30, 31},
                                           {32, 33, 34, 35}}),
                    std::make_tuple(3, 1, 1,
                                    MATRIX{{0, 1, 2},
                                           {3, 4, 5, 6},
                                           {7, 8, 9, 10},
                                           {11, 12, 13, 14},
                                           {15, 16, 17, 18},
                                           {19, 20, 21, 22},
                                           {23, 24, 25, 26},
                                           {27, 28, 29, 30},
                                           {31, 32, 33, 34}}),
                    std::make_tuple(4, 1, 1,
                                    MATRIX{{0, 1},
                                           {2, 3, 4, 5},
                                           {6, 7, 8, 9},
                                           {10, 11, 12, 13},
                                           {14, 15, 16, 17},
                                           {18, 19, 20, 21},
                                           {22, 23, 24, 25},
                                           {26, 27, 28, 29},
                                           {30, 31, 32, 33}}),
                    std::make_tuple(5, 1, 1,
                                    MATRIX{{0},
                                           {1, 2, 3, 4},
                                           {5, 6, 7, 8},
                                           {9, 10, 11, 12},
                                           {13, 14, 15, 16},
                                           {17, 18, 19, 20},
                                           {21, 22, 23, 24},
                                           {25, 26, 27, 28},
                                           {29, 30, 31, 32}}),
                    std::make_tuple(33, 1, 8, MATRIX{{0}, {1, 2, 3, 4}}),
                    std::make_tuple(34, 1, 9, MATRIX{{0, 1, 2, 3}}),
                    std::make_tuple(35, 1, 9, MATRIX{{0, 1, 2}}),
                    std::make_tuple(36, 1, 9, MATRIX{{0, 1}}),
                    std::make_tuple(36, 5, 8, MATRIX{{0, 1}}),
                    std::make_tuple(36, 34, 0, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsGold::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsGold, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsPlatinum
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::from_tier("platinum");
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsPlatinum::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsPlatinum,
    testing::Values(std::make_tuple(1, 1, 0,
                                    MATRIX{{0, 1, 2, 3, 4, 5},
                                           {6, 7, 8, 9, 10, 11},
                                           {12, 13, 14, 15, 16, 17},
                                           {18, 19, 20, 21, 22, 23},
                                           {24, 25, 26, 27, 28, 29},
                                           {30, 31, 32, 33, 34, 35},
                                           {36, 37, 38, 39, 40, 41},
                                           {42, 43, 44, 45, 46, 47},
                                           {48, 49, 50, 51, 52, 53},
                                           {54, 55, 56, 57, 58, 59},
                                           {60, 61, 62, 63, 64, 65},
                                           {66, 67, 68, 69, 70, 71},
                                           {72, 73, 74, 75, 76, 77}}),
                    std::make_tuple(2, 1, 0,
                                    MATRIX{{0, 1, 2, 3, 4},
                                           {5, 6, 7, 8, 9, 10},
                                           {11, 12, 13, 14, 15, 16},
                                           {17, 18, 19, 20, 21, 22},
                                           {23, 24, 25, 26, 27, 28},
                                           {29, 30, 31, 32, 33, 34},
                                           {35, 36, 37, 38, 39, 40},
                                           {41, 42, 43, 44, 45, 46},
                                           {47, 48, 49, 50, 51, 52},
                                           {53, 54, 55, 56, 57, 58},
                                           {59, 60, 61, 62, 63, 64},
                                           {65, 66, 67, 68, 69, 70},
                                           {71, 72, 73, 74, 75, 76}}),
                    std::make_tuple(3, 1, 0,
                                    MATRIX{{0, 1, 2, 3},
                                           {4, 5, 6, 7, 8, 9},
                                           {10, 11, 12, 13, 14, 15},
                                           {16, 17, 18, 19, 20, 21},
                                           {22, 23, 24, 25, 26, 27},
                                           {28, 29, 30, 31, 32, 33},
                                           {34, 35, 36, 37, 38, 39},
                                           {40, 41, 42, 43, 44, 45},
                                           {46, 47, 48, 49, 50, 51},
                                           {52, 53, 54, 55, 56, 57},
                                           {58, 59, 60, 61, 62, 63},
                                           {64, 65, 66, 67, 68, 69},
                                           {70, 71, 72, 73, 74, 75}}),
                    std::make_tuple(4, 1, 0,
                                    MATRIX{{0, 1, 2},
                                           {3, 4, 5, 6, 7, 8},
                                           {9, 10, 11, 12, 13, 14},
                                           {15, 16, 17, 18, 19, 20},
                                           {21, 22, 23, 24, 25, 26},
                                           {27, 28, 29, 30, 31, 32},
                                           {33, 34, 35, 36, 37, 38},
                                           {39, 40, 41, 42, 43, 44},
                                           {45, 46, 47, 48, 49, 50},
                                           {51, 52, 53, 54, 55, 56},
                                           {57, 58, 59, 60, 61, 62},
                                           {63, 64, 65, 66, 67, 68},
                                           {69, 70, 71, 72, 73, 74}}),
                    std::make_tuple(5, 1, 0,
                                    MATRIX{{0, 1},
                                           {2, 3, 4, 5, 6, 7},
                                           {8, 9, 10, 11, 12, 13},
                                           {14, 15, 16, 17, 18, 19},
                                           {20, 21, 22, 23, 24, 25},
                                           {26, 27, 28, 29, 30, 31},
                                           {32, 33, 34, 35, 36, 37},
                                           {38, 39, 40, 41, 42, 43},
                                           {44, 45, 46, 47, 48, 49},
                                           {50, 51, 52, 53, 54, 55},
                                           {56, 57, 58, 59, 60, 61},
                                           {62, 63, 64, 65, 66, 67},
                                           {68, 69, 70, 71, 72, 73}}),
                    std::make_tuple(6, 1, 0,
                                    MATRIX{{0},
                                           {1, 2, 3, 4, 5, 6},
                                           {7, 8, 9, 10, 11, 12},
                                           {13, 14, 15, 16, 17, 18},
                                           {19, 20, 21, 22, 23, 24},
                                           {25, 26, 27, 28, 29, 30},
                                           {31, 32, 33, 34, 35, 36},
                                           {37, 38, 39, 40, 41, 42},
                                           {43, 44, 45, 46, 47, 48},
                                           {49, 50, 51, 52, 53, 54},
                                           {55, 56, 57, 58, 59, 60},
                                           {61, 62, 63, 64, 65, 66},
                                           {67, 68, 69, 70, 71, 72}}),
                    std::make_tuple(7, 1, 1,
                                    MATRIX{{0, 1, 2, 3, 4, 5},
                                           {6, 7, 8, 9, 10, 11},
                                           {12, 13, 14, 15, 16, 17},
                                           {18, 19, 20, 21, 22, 23},
                                           {24, 25, 26, 27, 28, 29},
                                           {30, 31, 32, 33, 34, 35},
                                           {36, 37, 38, 39, 40, 41},
                                           {42, 43, 44, 45, 46, 47},
                                           {48, 49, 50, 51, 52, 53},
                                           {54, 55, 56, 57, 58, 59},
                                           {60, 61, 62, 63, 64, 65},
                                           {66, 67, 68, 69, 70, 71}}),
                    std::make_tuple(72, 1, 11, MATRIX{{0}, {1, 2, 3, 4, 5, 6}}),
                    std::make_tuple(73, 1, 12, MATRIX{{0, 1, 2, 3, 4, 5}}),
                    std::make_tuple(74, 1, 12, MATRIX{{0, 1, 2, 3, 4}}),
                    std::make_tuple(75, 1, 12, MATRIX{{0, 1, 2, 3}}),
                    std::make_tuple(76, 1, 12, MATRIX{{0, 1, 2}}),
                    std::make_tuple(77, 1, 12, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsPlatinum::ParamType> &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsPlatinum, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};

class GetPartitionsGoldBootstrap
    : public testing::TestWithParam<
          std::tuple<int, int, int, std::vector<std::vector<int>>>> {
public:
  static void SetUpTestSuite() {
    const auto config = desilo::fhe::CKKSConfig::for_bootstrap();
    parameters_ = new desilo::fhe::CKKSParameters(config);
  }

  static void TearDownTestSuite() { delete parameters_; }

  static desilo::fhe::CKKSParameters *parameters_;
};

desilo::fhe::CKKSParameters *GetPartitionsGoldBootstrap::parameters_ = nullptr;

INSTANTIATE_TEST_CASE_P(
    CKKSParameters, GetPartitionsGoldBootstrap,
    testing::Values(std::make_tuple(1, 1, 0,
                                    MATRIX{{0, 1, 2},
                                           {3, 4, 5, 6},
                                           {7, 8, 9, 10},
                                           {11, 12, 13, 14},
                                           {15, 16, 17, 18},
                                           {19, 20, 21, 22},
                                           {23, 24, 25, 26}}),
                    std::make_tuple(2, 1, 0,
                                    MATRIX{{0, 1},
                                           {2, 3, 4, 5},
                                           {6, 7, 8, 9},
                                           {10, 11, 12, 13},
                                           {14, 15, 16, 17},
                                           {18, 19, 20, 21},
                                           {22, 23, 24, 25}}),
                    std::make_tuple(3, 1, 0,
                                    MATRIX{{0},
                                           {1, 2, 3, 4},
                                           {5, 6, 7, 8},
                                           {9, 10, 11, 12},
                                           {13, 14, 15, 16},
                                           {17, 18, 19, 20},
                                           {21, 22, 23, 24}}),
                    std::make_tuple(4, 1, 1,
                                    MATRIX{{0, 1, 2, 3},
                                           {4, 5, 6, 7},
                                           {8, 9, 10, 11},
                                           {12, 13, 14, 15},
                                           {16, 17, 18, 19},
                                           {20, 21, 22, 23}}),
                    std::make_tuple(5, 1, 1,
                                    MATRIX{{0, 1, 2},
                                           {3, 4, 5, 6},
                                           {7, 8, 9, 10},
                                           {11, 12, 13, 14},
                                           {15, 16, 17, 18},
                                           {19, 20, 21, 22}}),
                    std::make_tuple(23, 1, 5, MATRIX{{0}, {1, 2, 3, 4}}),
                    std::make_tuple(24, 1, 6, MATRIX{{0, 1, 2, 3}}),
                    std::make_tuple(25, 1, 6, MATRIX{{0, 1, 2}}),
                    std::make_tuple(26, 1, 6, MATRIX{{0, 1}}),
                    std::make_tuple(26, 5, 5, MATRIX{{0, 1}}),
                    std::make_tuple(26, 24, 0, MATRIX{{0, 1}})),
    [](const testing::TestParamInfo<GetPartitionsGoldBootstrap::ParamType>
           &info) {
      const auto ciphertext_moduli_id = std::get<0>(info.param);
      const auto key_moduli_id = std::get<1>(info.param);

      return "Ciphertext" + print_moduli_id(ciphertext_moduli_id) + "Key" +
             print_moduli_id(key_moduli_id);
    });

TEST_P(GetPartitionsGoldBootstrap, ) {
  const auto ciphertext_moduli_id = std::get<0>(GetParam());
  const auto key_moduli_id = std::get<1>(GetParam());
  const auto partition_index_offset = std::get<2>(GetParam());
  const auto expected = std::get<3>(GetParam());

  const auto partitions =
      parameters_->get_partitions(ciphertext_moduli_id, key_moduli_id);

  ASSERT_EQ(partitions.size(), expected.size());
  for (int partition_index = 0; partition_index < expected.size();
       partition_index++) {
    const auto partition = partitions[partition_index];
    ASSERT_EQ(partition.size_, expected[partition_index].size());
    EXPECT_EQ(partition.moduli_id_, ciphertext_moduli_id);
    EXPECT_EQ(partition.partition_index_,
              partition_index + partition_index_offset);

    for (int chain_index = 0; chain_index < partition.size_; chain_index++) {
      EXPECT_EQ(partition[chain_index], expected[partition_index][chain_index]);
    }
  }
};
