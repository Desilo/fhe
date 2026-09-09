#include "parameter/decode.h"
#include "arithmetic/arithmetic.h"
#include "ckks/config.h"
#include "ckks/precomputed.h"
#include "common/test.h"

TEST(DecodeParameters, ConstructorWith2Qs) {

  uint64_t q[2]{1099506515969, 1152921504606748673};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[2]{desilo::fhe::calculate_k(r, q[0]),
                desilo::fhe::calculate_k(r, q[1])};
  int chain_count = 2;

  const auto decode_parameters =
      desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto expected_q_product =
      desilo::fhe::BigInt({1044836715567546369, 68719157248});
  auto expected_q_product_half = expected_q_product / 2;

  auto expected_rns_reverser = std::vector<desilo::fhe::BigInt>{
      desilo::fhe::BigInt({14948726076072858941ULL, 24956946771}),
      desilo::fhe::BigInt({4542854713204239045, 43762210476})};

  auto expected_r_minus_k_product = 4282651411775258623;

  for (auto data_index = 0; data_index < chain_count; data_index++) {
    EXPECT_EQ(decode_parameters.q_product_.data_[data_index],
              expected_q_product.data_[data_index]);
    EXPECT_EQ(decode_parameters.q_product_half_.data_[data_index],
              expected_q_product_half.data_[data_index]);

    for (auto reverser_index = 0; reverser_index < chain_count;
         reverser_index++) {
      EXPECT_EQ(
          decode_parameters.rns_reverser_[data_index].data_[reverser_index],
          expected_rns_reverser[data_index].data_[reverser_index]);
    }
  }

  EXPECT_EQ(decode_parameters.r_minus_k_product_, expected_r_minus_k_product);
}

TEST(DecodeParameters, ConstructorWith3Qs) {
  uint64_t q[3]{1099516280833, 1099506515969, 1152921504606748673};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[3]{desilo::fhe::calculate_k(r, q[0]),
                desilo::fhe::calculate_k(r, q[1]),
                desilo::fhe::calculate_k(r, q[2])};
  int chain_count = 3;

  const auto decode_parameters =
      desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto expected_q_product =
      desilo::fhe::BigInt({2770536654353956865, 18415217520718944896ULL, 4095});
  auto expected_q_product_half = expected_q_product / 2;

  auto expected_rns_reverser = std::vector<desilo::fhe::BigInt>{
      desilo::fhe::BigInt({4049850535966055288, 5981243189460679637, 3492}),
      desilo::fhe::BigInt({10121752891864936781ULL, 6564253971010925172, 3035}),
      desilo::fhe::BigInt({9816213954586473278ULL, 5838193807256733366, 1664})};

  auto expected_r_minus_k_product = 2809485443944906751;

  for (auto data_index = 0; data_index < chain_count; data_index++) {
    EXPECT_EQ(decode_parameters.q_product_.data_[data_index],
              expected_q_product.data_[data_index]);
    EXPECT_EQ(decode_parameters.q_product_half_.data_[data_index],
              expected_q_product_half.data_[data_index]);

    for (auto reverser_index = 0; reverser_index < chain_count;
         reverser_index++) {
      EXPECT_EQ(
          decode_parameters.rns_reverser_[data_index].data_[reverser_index],
          expected_rns_reverser[data_index].data_[reverser_index]);
    }
  }

  EXPECT_EQ(decode_parameters.r_minus_k_product_, expected_r_minus_k_product);
}

TEST(DecodeParameters, ConstructorWith2SmallQs) {
  uint64_t q[2]{5, 7};
  int64_t r = 128;

  uint64_t k[2]{51, 57};
  int chain_count = 2;

  const auto decode_parameters =
      desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto expected_q_product = desilo::fhe::BigInt({35});

  auto expected_q_product_half = desilo::fhe::BigInt({17});

  auto expected_rns_reverser = std::vector<desilo::fhe::BigInt>{
      desilo::fhe::BigInt({21}), desilo::fhe::BigInt({15})};

  auto expected_r_minus_k_product = 37;

  EXPECT_EQ(decode_parameters.q_product_.data_[0], expected_q_product.data_[0]);
  EXPECT_EQ(decode_parameters.q_product_half_.data_[0],
            expected_q_product_half.data_[0]);
  for (auto reverser_index = 0; reverser_index < chain_count;
       reverser_index++) {
    EXPECT_EQ(decode_parameters.rns_reverser_[reverser_index].data_[0],
              expected_rns_reverser[reverser_index].data_[0]);
  }
  EXPECT_EQ(decode_parameters.r_minus_k_product_, expected_r_minus_k_product);
}

TEST(DecodeParameters, ConstructorWith3SmallQs) {
  uint64_t q[3]{5, 7, 11};
  int64_t r = 128;

  uint64_t k[3]{51, 57, 93};
  int chain_count = 3;

  const auto decode_parameters =
      desilo::fhe::DecodeParameters(q, k, r, chain_count);

  auto expected_q_product = desilo::fhe::BigInt({385});

  auto expected_q_product_half = desilo::fhe::BigInt({192});

  auto expected_rns_reverser = std::vector<desilo::fhe::BigInt>{
      desilo::fhe::BigInt({231}), desilo::fhe::BigInt({330}),
      desilo::fhe::BigInt({210})};

  auto expected_r_minus_k_product = 15;

  EXPECT_EQ(decode_parameters.q_product_.data_[0], expected_q_product.data_[0]);
  EXPECT_EQ(decode_parameters.q_product_half_.data_[0],
            expected_q_product_half.data_[0]);

  for (auto reverser_index = 0; reverser_index < chain_count;
       reverser_index++) {
    EXPECT_EQ(decode_parameters.rns_reverser_[reverser_index].data_[0],
              expected_rns_reverser[reverser_index].data_[0]);
  }

  EXPECT_EQ(decode_parameters.r_minus_k_product_, expected_r_minus_k_product);
}

TEST(DecodeParameters, Make_CKKS) {
  const auto config = desilo::fhe::CKKSConfig();
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);
  const auto chain_count = 4;
  const auto decode_parameters =
      precomputed.make_decode_parameters(chain_count);

  EXPECT_EQ(decode_parameters->q_product_.data_.size(), 3);

  const uint128_t expected_q_product[3]{4817291831298359297,
                                        1343831217454287637, 4503595466576240};

  for (auto data_index = 0; data_index < 3; data_index++) {
    EXPECT_EQ(decode_parameters->q_product_.data_[data_index],
              expected_q_product[data_index]);
  }

  const uint128_t expected_q_product_half[3]{
      11632017952503955456ULL, 671915608727143818, 2251797733288120};

  for (auto data_index = 0; data_index < 3; data_index++) {
    EXPECT_EQ(decode_parameters->q_product_half_.data_[data_index],
              expected_q_product_half[data_index]);
  }

  EXPECT_EQ(decode_parameters->rns_reverser_.size(), chain_count);

  EXPECT_EQ(decode_parameters->r_minus_k_product_, 2189158582181560319);

  delete decode_parameters;
}

TEST(DecodeParameters, MakeWithDepth_CKKS) {
  const auto config = desilo::fhe::CKKSConfig();
  const auto precomputed = desilo::fhe::CKKSPrecomputed(config);
  const auto chain_count = 3;
  const auto moduli_id = 1;
  const auto decode_parameters =
      precomputed.make_decode_parameters(chain_count, moduli_id);

  EXPECT_EQ(decode_parameters->q_product_.data_.size(), 2);

  const uint128_t expected_q_product[2]{1727118633050603521, 72057527465230081};

  for (auto data_index = 0; data_index < 2; data_index++) {
    EXPECT_EQ(decode_parameters->q_product_.data_[data_index],
              expected_q_product[data_index]);
  }

  const uint128_t expected_q_product_half[2]{10086931353380077568ULL,
                                             36028763732615040};

  for (auto data_index = 0; data_index < 2; data_index++) {
    EXPECT_EQ(decode_parameters->q_product_half_.data_[data_index],
              expected_q_product_half[data_index]);
  }

  EXPECT_EQ(decode_parameters->rns_reverser_.size(), chain_count);

  EXPECT_EQ(decode_parameters->r_minus_k_product_, 3174215640826281983);

  delete decode_parameters;
}

TEST(DecodeParameters, MakeSmall2_CKKS) {
  const auto config = desilo::fhe::CKKSConfig();

  uint64_t q[2]{3, 7};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[2]{desilo::fhe::calculate_k(r, q[0]),
                desilo::fhe::calculate_k(r, q[1])};
  const auto chain_count = 2;

  auto decode_parameters = desilo::fhe::DecodeParameters(q, k, r, chain_count);

  EXPECT_EQ(decode_parameters.q_product_, desilo::fhe::BigInt(3 * 7));
  EXPECT_EQ(decode_parameters.q_product_half_, desilo::fhe::BigInt(10));
  EXPECT_EQ(decode_parameters.rns_reverser_.size(), chain_count);

  EXPECT_EQ(decode_parameters.rns_reverser_[0], desilo::fhe::BigInt(7));

  EXPECT_EQ(decode_parameters.rns_reverser_[1], desilo::fhe::BigInt(15));
  EXPECT_EQ(decode_parameters.r_minus_k_product_, 3513665537849438403);
}

TEST(DecodeParameters, MakeSmall3_CKKS) {
  const auto config = desilo::fhe::CKKSConfig();

  uint64_t q[3]{3, 5, 7};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[3]{desilo::fhe::calculate_k(r, q[0]),
                desilo::fhe::calculate_k(r, q[1]),
                desilo::fhe::calculate_k(r, q[2])};
  const auto chain_count = 3;

  auto decode_parameters = desilo::fhe::DecodeParameters(q, k, r, chain_count);

  EXPECT_EQ(decode_parameters.q_product_, desilo::fhe::BigInt(3 * 5 * 7));
  EXPECT_EQ(decode_parameters.q_product_half_, desilo::fhe::BigInt(52));
  EXPECT_EQ(decode_parameters.rns_reverser_.size(), chain_count);

  EXPECT_EQ(decode_parameters.rns_reverser_[0], desilo::fhe::BigInt(70));

  EXPECT_EQ(decode_parameters.rns_reverser_[1], desilo::fhe::BigInt(21));

  EXPECT_EQ(decode_parameters.rns_reverser_[2], desilo::fhe::BigInt(15));
  EXPECT_EQ(decode_parameters.r_minus_k_product_, 3469744718626320423);
}

TEST(DecodeParameters, MakeSmallWithPowerOfTwo_CKKS) {
  const auto config = desilo::fhe::CKKSConfig();

  uint64_t q[3]{4, 3, 7};
  int64_t r = INT64_C(1) << 62;
  uint64_t k[3]{0, desilo::fhe::calculate_k(r, q[1]),
                desilo::fhe::calculate_k(r, q[2])};
  const auto chain_count = 3;

  auto decode_parameters = desilo::fhe::DecodeParameters(q, k, r, chain_count);

  EXPECT_EQ(decode_parameters.q_product_, desilo::fhe::BigInt(3 * 7));
  EXPECT_EQ(decode_parameters.q_product_half_, desilo::fhe::BigInt(10));
  EXPECT_EQ(decode_parameters.rns_reverser_.size(), chain_count - 1);
  EXPECT_EQ(decode_parameters.rns_reverser_[0], desilo::fhe::BigInt(7));
  EXPECT_EQ(decode_parameters.rns_reverser_[1], desilo::fhe::BigInt(15));
  EXPECT_EQ(decode_parameters.r_minus_k_product_, 3513665537849438403);
}
