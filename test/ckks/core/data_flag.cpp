#include "ckks/core/macro.h"
#include "common/common.h"
#include "common/test.h"

DEFINE_TIER_TEST_CLASS_SP(Iron, Flag);

TEST_F(IronCKKSCoreFlag, MultiplyRealAndReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled1 = core.rescale(ciphertext1);
  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);

  ASSERT_EQ(multiplied->flag_, desilo::fhe::DataFlag::NTT_FORM);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
}

TEST_F(IronCKKSCoreFlag, MultiplyComplexAndReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled1 = core.rescale(ciphertext1);
  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);

  ASSERT_EQ(multiplied->flag_,
            desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
}

TEST_F(IronCKKSCoreFlag, MultiplyRealAndComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled1 = core.rescale(ciphertext1);
  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);

  ASSERT_EQ(multiplied->flag_,
            desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
}

TEST_F(IronCKKSCoreFlag, MultiplyComplexAndComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto rescaled1 = core.rescale(ciphertext1);
  const auto rescaled2 = core.rescale(ciphertext2);
  const auto ntt_form1 = core.to_ntt_form(rescaled1);
  const auto ntt_form2 = core.to_ntt_form(rescaled2);
  const auto multiplied = core.multiply(ntt_form1, ntt_form2);

  ASSERT_EQ(multiplied->flag_,
            desilo::fhe::DataFlag::NTT_FORM | desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete rescaled1;
  delete rescaled2;
  delete ntt_form1;
  delete ntt_form2;
  delete multiplied;
}

TEST_F(IronCKKSCoreFlag, AddRealAndReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto added = core.add(ciphertext1, ciphertext2);

  ASSERT_EQ(added->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete added;
}

TEST_F(IronCKKSCoreFlag, AddComplexAndReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto added = core.add(ciphertext1, ciphertext2);

  ASSERT_EQ(added->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete added;
}

TEST_F(IronCKKSCoreFlag, AddRealAndComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto added = core.add(ciphertext1, ciphertext2);

  ASSERT_EQ(added->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete added;
}

TEST_F(IronCKKSCoreFlag, AddComplexAndComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto added = core.add(ciphertext1, ciphertext2);

  ASSERT_EQ(added->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete added;
}

TEST_F(IronCKKSCoreFlag, SubRealMinusReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto subtracted = core.subtract(ciphertext1, ciphertext2);

  ASSERT_EQ(subtracted->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete subtracted;
}

TEST_F(IronCKKSCoreFlag, SubComplexMinusReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message1(slot_count);
  std::vector<double> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto subtracted = core.subtract(ciphertext1, ciphertext2);

  ASSERT_EQ(subtracted->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete subtracted;
}

TEST_F(IronCKKSCoreFlag, SubRealMinusComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto subtracted = core.subtract(ciphertext1, ciphertext2);

  ASSERT_EQ(subtracted->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete subtracted;
}

TEST_F(IronCKKSCoreFlag, SubComplexMinusComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message1(slot_count);
  std::vector<std::complex<double>> message2(slot_count);
  initiate_message(message1, 1);
  initiate_message(message2, 1);

  const auto plaintext1 = core.encode(message1, max_level, include_special);
  const auto plaintext2 = core.encode(message2, max_level, include_special);
  const auto ciphertext1 = core.encrypt(plaintext1, public_key_);
  const auto ciphertext2 = core.encrypt(plaintext2, public_key_);
  const auto subtracted = core.subtract(ciphertext1, ciphertext2);

  ASSERT_EQ(subtracted->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext1;
  delete plaintext2;
  delete ciphertext1;
  delete ciphertext2;
  delete subtracted;
}

TEST_F(IronCKKSCoreFlag, RescaleReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);

  EXPECT_EQ(rescaled->flag_, desilo::fhe::DataFlag::RESCALED);

  delete plaintext;
  delete ciphertext;
  delete rescaled;
}

TEST_F(IronCKKSCoreFlag, RescaleComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);

  EXPECT_EQ(rescaled->flag_,
            desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::RESCALED);

  delete plaintext;
  delete ciphertext;
  delete rescaled;
}

TEST_F(IronCKKSCoreFlag, RelinearizeReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  auto relinearization_key =
      core.create_relinearization_key(secret_key_, max_level);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto ntt_form = core.to_ntt_form(rescaled);
  const auto multiplied = core.square(ntt_form);
  const auto relinearized = core.relinearize(multiplied, relinearization_key);

  EXPECT_EQ(relinearized->flag_, desilo::fhe::DataFlag::NONE);

  delete relinearization_key;
  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete ntt_form;
  delete multiplied;
  delete relinearized;
}

TEST_F(IronCKKSCoreFlag, RelinearizeComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  auto relinearization_key =
      core.create_relinearization_key(secret_key_, max_level);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto ntt_form = core.to_ntt_form(rescaled);
  const auto multiplied = core.square(ntt_form);
  const auto relinearized = core.relinearize(multiplied, relinearization_key);

  EXPECT_EQ(relinearized->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete relinearization_key;
  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete ntt_form;
  delete multiplied;
  delete relinearized;
}

TEST_F(IronCKKSCoreFlag, LevelDownReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto leveled =
      core.level_down_after_rescale(ciphertext, ciphertext->level_ - 1);

  EXPECT_EQ(leveled->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext;
  delete ciphertext;
  delete leveled;
}

TEST_F(IronCKKSCoreFlag, LevelDownComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto leveled =
      core.level_down_after_rescale(ciphertext, ciphertext->level_ - 1);

  EXPECT_EQ(leveled->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext;
  delete ciphertext;
  delete leveled;
}

TEST_F(IronCKKSCoreFlag, LevelDownRescaled) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto leveled =
      core.level_down_after_rescale(rescaled, ciphertext->level_ - 1);

  EXPECT_EQ(leveled->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete leveled;
}

TEST_F(IronCKKSCoreFlag, LevelDownRescaledComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rescaled = core.rescale(ciphertext);
  const auto leveled =
      core.level_down_after_rescale(rescaled, ciphertext->level_ - 1);

  EXPECT_EQ(leveled->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext;
  delete ciphertext;
  delete rescaled;
  delete leveled;
}

TEST_F(IronCKKSCoreFlag, RotateUnitPlaintextReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto rotated = core.rotate_intt_form(plaintext, 1);

  EXPECT_EQ(rotated->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext;
  delete rotated;
}

TEST_F(IronCKKSCoreFlag, RotateUnitPlaintextComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto rotated = core.rotate_intt_form(plaintext, 1);

  EXPECT_EQ(rotated->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext;
  delete rotated;
}

TEST_F(IronCKKSCoreFlag, RotateCiphertextReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  auto fixed_rotation_key =
      core.create_fixed_rotation_key(secret_key_, max_level, 1);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rotated = core.rotate(ciphertext, fixed_rotation_key);

  EXPECT_EQ(rotated->flag_, desilo::fhe::DataFlag::NONE);

  delete fixed_rotation_key;
  delete plaintext;
  delete ciphertext;
  delete rotated;
}

TEST_F(IronCKKSCoreFlag, RotateCiphertextComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  auto fixed_rotation_key =
      core.create_fixed_rotation_key(secret_key_, max_level, 1);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto rotated = core.rotate(ciphertext, fixed_rotation_key);

  EXPECT_EQ(rotated->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete fixed_rotation_key;
  delete plaintext;
  delete ciphertext;
  delete rotated;
}

TEST_F(IronCKKSCoreFlag, NegateReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto negated = core.negate(ciphertext);

  EXPECT_EQ(negated->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext;
  delete ciphertext;
  delete negated;
}

TEST_F(IronCKKSCoreFlag, NegateComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto negated = core.negate(ciphertext);

  EXPECT_EQ(negated->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext;
  delete ciphertext;
  delete negated;
}

TEST_F(IronCKKSCoreFlag, ConjugateUnitPlaintextReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto conjugated = core.conjugate_intt_form(plaintext);

  EXPECT_EQ(conjugated->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext;
  delete conjugated;
}

TEST_F(IronCKKSCoreFlag, ConjugateUnitPlaintextComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto conjugated = core.conjugate_intt_form(plaintext);

  EXPECT_EQ(conjugated->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext;
  delete conjugated;
}

TEST_F(IronCKKSCoreFlag, ConjugateCiphertextReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto conjugation_key =
      core.create_conjugation_key(secret_key_, max_level);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto conjugated = core.conjugate(ciphertext, conjugation_key);

  EXPECT_EQ(conjugated->flag_, desilo::fhe::DataFlag::NONE);

  delete conjugation_key;
  delete plaintext;
  delete ciphertext;
  delete conjugated;
}

TEST_F(IronCKKSCoreFlag, ConjugateCiphertextComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto conjugation_key =
      core.create_conjugation_key(secret_key_, max_level);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto conjugated = core.conjugate(ciphertext, conjugation_key);

  EXPECT_EQ(conjugated->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete conjugation_key;
  delete plaintext;
  delete ciphertext;
  delete conjugated;
}

TEST_F(IronCKKSCoreFlag, ToNTTFormReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto ntt_form = core.to_ntt_form(ciphertext);

  EXPECT_EQ(ntt_form->flag_, desilo::fhe::DataFlag::NTT_FORM);

  delete plaintext;
  delete ciphertext;
  delete ntt_form;
}

TEST_F(IronCKKSCoreFlag, ToNTTFormComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto ntt_form = core.to_ntt_form(ciphertext);

  EXPECT_EQ(ntt_form->flag_,
            desilo::fhe::DataFlag::COMPLEX | desilo::fhe::DataFlag::NTT_FORM);

  delete plaintext;
  delete ciphertext;
  delete ntt_form;
}

TEST_F(IronCKKSCoreFlag, ToINTTFormReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto ntt_form = core.to_intt_form(ciphertext);
  const auto intt_form = core.to_intt_form(ntt_form);

  EXPECT_EQ(intt_form->flag_, desilo::fhe::DataFlag::NONE);

  delete plaintext;
  delete ciphertext;
  delete ntt_form;
  delete intt_form;
}

TEST_F(IronCKKSCoreFlag, ToINTTFormComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto plaintext = core.encode(message, max_level, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto ntt_form = core.to_intt_form(ciphertext);
  const auto intt_form = core.to_intt_form(ntt_form);

  EXPECT_EQ(intt_form->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete plaintext;
  delete ciphertext;
  delete ntt_form;
  delete intt_form;
}

TEST_F(IronCKKSCoreFlag, SwitchKeyReal) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<double> message(slot_count);
  initiate_message(message, 1);

  const auto secret_key_to = core.create_secret_key(max_level);
  const auto key_switching_key =
      core.create_key_switching_key(secret_key_, secret_key_to, max_level);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto switched = core.switch_key(ciphertext, key_switching_key);

  EXPECT_EQ(switched->flag_, desilo::fhe::DataFlag::NONE);

  delete secret_key_to;
  delete key_switching_key;
  delete plaintext;
  delete ciphertext;
  delete switched;
}

TEST_F(IronCKKSCoreFlag, SwitchKeyComplex) {
  auto core = desilo::fhe::CKKSCore(config_);
  const auto slot_count = core.get_slot_count();
  const auto max_level = core.parameters_.get_max_level();
  const bool include_special = false;

  std::vector<std::complex<double>> message(slot_count);
  initiate_message(message, 1);

  const auto secret_key_to = core.create_secret_key(max_level);
  const auto key_switching_key =
      core.create_key_switching_key(secret_key_, secret_key_to, max_level);

  const auto plaintext = core.encode(message, max_level - 1, include_special);
  const auto ciphertext = core.encrypt(plaintext, public_key_);
  const auto switched = core.switch_key(ciphertext, key_switching_key);

  EXPECT_EQ(switched->flag_, desilo::fhe::DataFlag::COMPLEX);

  delete secret_key_to;
  delete key_switching_key;
  delete plaintext;
  delete ciphertext;
  delete switched;
}
