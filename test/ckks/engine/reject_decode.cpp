#include <gtest/gtest.h>

#include "ckks/core/dummy.h"
#include "ckks/engine.h"
#include "common/common.h"
#include "common/test.h"

class RejectDecode : public testing::TestWithParam<int> {
public:
  static void SetUpTestSuite() {
    engine_ = new desilo::fhe::CKKSEngine();

    const auto scheme_preset = desilo::fhe::SchemePreset::CKKS_40_60_DEFAULT;
    const auto log_slot_count = 13;
    const auto log_coeff_count = 14;
    const auto special_prime_count = 1;

    const auto bad_scheme_preset = desilo::fhe::SchemePreset::NONE;
    const auto bad_log_slot_count = 12;
    const auto bad_log_coeff_count = 13;
    const auto bad_special_prime_count = 2;

    rescaled_unit_plaintext_ = get_dummy_flagged_unit_plaintext(
        desilo::fhe::DataFlag::RESCALED, scheme_preset, log_slot_count,
        log_coeff_count, special_prime_count);
    rescaled_plaintext_ =
        new desilo::fhe::Plaintext({rescaled_unit_plaintext_});
    incompatible_unit_plaintexts_ = {
        get_dummy_unit_plaintext(bad_scheme_preset, log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, bad_log_slot_count,
                                 log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count,
                                 bad_log_coeff_count, special_prime_count),
        get_dummy_unit_plaintext(scheme_preset, log_slot_count, log_coeff_count,
                                 bad_special_prime_count)};
    incompatible_plaintexts_ = {
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[0]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[1]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[2]}),
        new desilo::fhe::Plaintext({incompatible_unit_plaintexts_[3]}),
    };
  }

  static void TearDownTestSuite() {
    delete engine_;
    delete rescaled_plaintext_;
    for (auto plaintext : incompatible_plaintexts_) {
      delete plaintext;
    }
  }

  static desilo::fhe::CKKSEngine *engine_;
  static desilo::fhe::UnitPlaintext *rescaled_unit_plaintext_;
  static std::vector<desilo::fhe::UnitPlaintext *>
      incompatible_unit_plaintexts_;
  static desilo::fhe::Plaintext *rescaled_plaintext_;
  static std::vector<desilo::fhe::Plaintext *> incompatible_plaintexts_;
};

desilo::fhe::CKKSEngine *RejectDecode::engine_ = nullptr;
desilo::fhe::UnitPlaintext *RejectDecode::rescaled_unit_plaintext_ = nullptr;
std::vector<desilo::fhe::UnitPlaintext *>
    RejectDecode::incompatible_unit_plaintexts_;
desilo::fhe::Plaintext *RejectDecode::rescaled_plaintext_ = nullptr;
std::vector<desilo::fhe::Plaintext *> RejectDecode::incompatible_plaintexts_;

INSTANTIATE_TEST_CASE_P(, RejectDecode, testing::Values(0, 1, 2, 3));

TEST_F(RejectDecode, UnitPlaintextRescaled) {
  try {
    engine_->decode_unit(rescaled_unit_plaintext_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Unit Plaintext To Double Vector: the input unit "
                 "plaintext should not be rescaled.",
                 e.what());
  }
}

TEST_P(RejectDecode, UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  try {
    engine_->decode_unit(incompatible_unit_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Unit Plaintext To Double Vector: the input unit "
                 "plaintext is not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectDecode, Complex_UnitPlaintextRescaled) {
  try {
    engine_->decode_complex_unit_plaintext(rescaled_unit_plaintext_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Unit Plaintext To Complex Vector: the input unit "
                 "plaintext should not be rescaled.",
                 e.what());
  }
}

TEST_P(RejectDecode, Complex_UnitPlaintextNotCompatible) {
  auto incompatible_unit_plaintext = incompatible_unit_plaintexts_[GetParam()];

  try {
    engine_->decode_complex_unit_plaintext(incompatible_unit_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Unit Plaintext To Complex Vector: the input unit "
                 "plaintext is not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectDecode, PlaintextRescaled) {
  try {
    engine_->decode(rescaled_plaintext_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Plaintext: the input plaintext should not "
                 "be rescaled.",
                 e.what());
  }
}

TEST_P(RejectDecode, PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  try {
    engine_->decode(incompatible_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Plaintext: the input plaintext is not "
                 "compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectDecode, Complex_PlaintextRescaled) {
  try {
    engine_->decode_complex_plaintext(rescaled_plaintext_);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Complex Plaintext: the input plaintext "
                 "should not be rescaled.",
                 e.what());
  }
}

TEST_P(RejectDecode, Complex_PlaintextNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];

  try {
    engine_->decode_complex_plaintext(incompatible_plaintext);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Complex Plaintext: the input plaintext is "
                 "not compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectDecode, PlaintextToBufferRescaled) {
  auto slot_count = engine_->get_slot_count();
  double output[slot_count];

  try {
    engine_->decode_to_buffer(rescaled_plaintext_, output);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Plaintext To Buffer: the input plaintext should not "
                 "be rescaled.",
                 e.what());
  }
}

TEST_P(RejectDecode, PlaintextToBufferNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];
  auto slot_count = engine_->get_slot_count();
  double output[slot_count];

  try {
    engine_->decode_to_buffer(incompatible_plaintext, output);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Plaintext To Buffer: the input plaintext is not "
                 "compatible with this engine.",
                 e.what());
  }
}

TEST_F(RejectDecode, Complex_PlaintextToBufferRescaled) {
  auto slot_count = engine_->get_slot_count();
  std::complex<double> output[slot_count];

  try {
    engine_->decode_complex_plaintext_to_buffer(rescaled_plaintext_, output);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Complex Plaintext To Buffer: the input plaintext "
                 "should not be rescaled.",
                 e.what());
  }
}

TEST_P(RejectDecode, Complex_PlaintextToBufferNotCompatible) {
  auto incompatible_plaintext = incompatible_plaintexts_[GetParam()];
  auto slot_count = engine_->get_slot_count();
  std::complex<double> output[slot_count];

  try {
    engine_->decode_complex_plaintext_to_buffer(incompatible_plaintext, output);
    FAIL();
  } catch (std::runtime_error &e) {
    EXPECT_STREQ("Decode Complex Plaintext To Buffer: the input plaintext is "
                 "not compatible with this engine.",
                 e.what());
  }
}
