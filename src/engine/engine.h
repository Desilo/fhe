#include "ckks/config.h"
#include "engine/abstract_engine.h"

namespace desilo::fhe {

AbstractEngine *
create_default_engine(const std::string &scheme_preset = "ckks");
AbstractEngine *create_ckks_engine(CKKSConfig config);

}
