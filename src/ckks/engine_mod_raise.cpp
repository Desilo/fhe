#include "ckks/engine.h"

namespace desilo::fhe {

UnitCiphertext *CKKSEngine::mod_raise_(UnitCiphertext *unit_ciphertext,
                                       SmallBootstrapKey *small_bootstrap_key,
                                       bool for_ciphertext) {
#ifdef DESILO_FHE_DEBUG
  require("Mod Raise Unit Ciphertext", unit_ciphertext,
          {Requirement::DUO, Requirement::INTT, Requirement::LEVEL_ZERO});
#endif
  auto rescaled = rescale_(unit_ciphertext, for_ciphertext);

  auto switched_to_sparse =
      core_->switch_key(rescaled, small_bootstrap_key->to_sparse_);
  auto tiled = core_->make_signed_tile(switched_to_sparse);
  auto switched_back_to_dense =
      core_->switch_key(tiled, small_bootstrap_key->to_dense_);
  auto ratio = core_->get_mod_raise_ratio();
  auto scaled = multiply(switched_back_to_dense, ratio);

  if (for_ciphertext) {
    temp_data_.push_back(switched_to_sparse);
    temp_data_.push_back(tiled);
    temp_data_.push_back(switched_back_to_dense);
  } else {
    delete rescaled;
    delete switched_to_sparse;
    delete tiled;
    delete switched_back_to_dense;
  }

  return scaled;
}

Ciphertext *CKKSEngine::mod_raise(Ciphertext *ciphertext,
                                  SmallBootstrapKey *small_bootstrap_key) {
  const auto function_name = "Mod Raise With Small Bootstrap Key";
  require_bootstrap_engine(function_name);
  require(function_name, ciphertext, {Requirement::DUO, Requirement::INTT});
  require_engine_compatibility(function_name, small_bootstrap_key);

  auto leveled_down = level_down(ciphertext, 0);

  auto for_ciphertext = true;

  std::vector<UnitCiphertext *> unit_ciphertexts;
  for (int index = 0; index < ciphertext->size(); index++) {
    unit_ciphertexts.push_back(mod_raise_(leveled_down->get(index),
                                          small_bootstrap_key, for_ciphertext));
  }

  clear_temp_data();

  delete leveled_down;

  return new Ciphertext(unit_ciphertexts);
}

Ciphertext *CKKSEngine::mod_raise(Ciphertext *ciphertext,
                                  BootstrapKey *bootstrap_key) {
  const auto function_name = "Mod Raise With Bootstrap Key";
  require_bootstrap_engine(function_name);
  require(function_name, ciphertext, {Requirement::DUO, Requirement::INTT});
  require_engine_compatibility(function_name, bootstrap_key);

  return mod_raise(ciphertext, bootstrap_key->small_bootstrap_key_);
}

}
