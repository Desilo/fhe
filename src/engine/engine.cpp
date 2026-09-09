#include "engine/engine.h"
#include "ckks/engine.h"
#include "util/string_transform.h"

namespace desilo::fhe {

AbstractEngine *create_default_engine(const std::string &scheme_preset) {
  const std::string scheme_preset_lowercase = to_lowercase(scheme_preset);

  if (scheme_preset_lowercase == "ckks") {
    return create_ckks_engine(CKKSConfig{});
  }

  throw std::invalid_argument("The given scheme is not supported.");
}

AbstractEngine *create_ckks_engine(CKKSConfig config) {
  config.validate();
  return new CKKSEngine(config);
}

}
