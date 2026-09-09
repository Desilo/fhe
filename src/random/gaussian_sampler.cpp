#include <cmath>
#include <string>

#ifdef DESILO_FHE_CHECK_HARDCODED
#include <mpfr.h>
#else
#include <cstring>
#endif

#include "random/gaussian_sampler.h"

namespace desilo::fhe {

#ifdef DESILO_FHE_CHECK_HARDCODED

void build_gaussian_sampling_tree(uint64_t *tree, int security_bits,
                                  double sigma, int tree_depth, int tree_size,
                                  int chop_count) {
  int precision = security_bits * 2;
  int sampling_power = static_cast<int>(std::ceil(std::log2(6 * sigma)));
  int sample_count = std::pow(2, sampling_power);

  mpfr_t mp_sigma, mp_two, mp_s, mp_two_sigma_squared;

  mpfr_inits2(precision, mp_sigma, mp_two, mp_s, mp_two_sigma_squared, NULL);

  mpfr_set_str(mp_sigma, std::to_string(sigma).c_str(), 10, MPFR_RNDD);
  mpfr_set_si(mp_two, 2, MPFR_RNDD);

  mpfr_const_pi(mp_s, MPFR_RNDD);
  mpfr_mul(mp_s, mp_s, mp_two, MPFR_RNDD);
  mpfr_sqrt(mp_s, mp_s, MPFR_RNDD);
  mpfr_mul(mp_s, mp_sigma, mp_s, MPFR_RNDD);

  mpfr_sqr(mp_two_sigma_squared, mp_sigma, MPFR_RNDD);
  mpfr_mul(mp_two_sigma_squared, mp_two, mp_two_sigma_squared, MPFR_RNDD);

  mpfr_t cdt[sample_count];
  for (int index = 0; index < sample_count; index++) {
    const auto x = cdt[index];

    mpfr_init2(x, precision);
    mpfr_set_si(x, index, MPFR_RNDD);
    mpfr_sqr(x, x, MPFR_RNDD);
    mpfr_div(x, x, mp_two_sigma_squared, MPFR_RNDD);
    mpfr_neg(x, x, MPFR_RNDD);
    mpfr_exp(x, x, MPFR_RNDD);
    mpfr_div(x, x, mp_s, MPFR_RNDD);
  }

  mpfr_div(cdt[0], cdt[0], mp_two, MPFR_RNDD);

  for (int index = 1; index < sample_count; index++) {
    mpfr_add(cdt[index], cdt[index], cdt[index - 1], MPFR_RNDD);
  }

  uint64_t chopped_cdt[sample_count][chop_count];
  mpfr_pow_si(mp_two, mp_two, 64, MPFR_RNDD);
  for (int sample_index = 0; sample_index < sample_count; sample_index++) {
    const auto x = cdt[sample_index];

    for (int chop_index = chop_count - 1; chop_index >= 0; chop_index--) {
      mpfr_mul(x, x, mp_two, MPFR_RNDD);

      chopped_cdt[sample_index][chop_index] = mpfr_get_ui(x, MPFR_RNDD);

      mpfr_frac(x, x, MPFR_RNDD);
    }
  }

  for (int depth = 0; depth < tree_depth; depth++) {
    int start_index = sample_count >> (depth + 1);
    int jump = sample_count >> depth;

    for (int index = start_index; index < sample_count; index += jump) {
      for (int chop_index = 0; chop_index < chop_count; chop_index++) {
        tree[chop_index * tree_size] = chopped_cdt[index - 1][chop_index];
      }
      tree++;
    }
  }

  mpfr_clears(mp_sigma, mp_two, mp_s, mp_two_sigma_squared, NULL);
  for (int index = 0; index < sample_count; index++) {
    mpfr_clear(cdt[index]);
  }
  mpfr_free_cache();
}
#else
uint64_t tree_128_3_2[62]{
    14054721526932470965u, 5229670270514668292,   11795367255171122523u,
    16225018202957135102u, 10904085551212653252u, 1608592601852423253u,
    17295746352736097760u, 14762230926727438697u, 16958356234993389628u,
    4458455883871664541,   15597004759004417286u, 10033552496278783699u,
    6889694368828158212,   15692008637546801699u, 14774327189065705981u,
    3017136537546209501,   157966372990756779,    9650038227050607071u,
    9106740691926161227,   2610337742401091421,   1442194912923388445,
    14928133994544364263u, 6088390944644486251,   16629468444506381461u,
    7101239476704967533,   5705078198431199473,   7045120933381250180,
    16329901129154247795u, 13372570196707154065u, 7951248449777691486,
    18260852386409164144u, 9223361386320111732,   9051758678878186096,
    9223372036853232777,   6713673034491318533,   9220529764022708440,
    9223372028116140532,   9223372036854775749,   3340023666152832877,
    8445050402542556633,   9196859074767746705,   9223161995634596963,
    9223371667508612690,   9223372036713969870,   9223372036854764319,
    9223372036854775807,   1149872835429266008,   5231742854224525755,
    7766573326200196558,   8841576285654612683,   9152802451769415979,
    9214281206174004120,   9222562339745873205,   9223322447917711088,
    9223369956674611011,   9223371977254386295,   9223372035690845298,
    9223372036839307001,   9223372036854636067,   9223372036854774950,
    9223372036854775804,   9223372036854775807,
};
#endif

GaussianSamplingTree::GaussianSamplingTree(int security_bits, double sigma)
    : security_bits_(security_bits), sigma_(sigma),
      depth_(std::round(std::ceil(std::log2(6 * sigma)))),
      size_((1 << depth_) - 1), chop_count_(security_bits / 64),
      data_size_(size_ * chop_count_), data_handle_(new uint64_t[data_size_]),
      data_(data_handle_.get()) {
#ifdef DESILO_FHE_CHECK_HARDCODED
  build_gaussian_sampling_tree(data_, security_bits_, sigma_, depth_, size_,
                               chop_count_);
#else

  memcpy(data_, tree_128_3_2, sizeof tree_128_3_2);
#endif
};

GaussianSamplingTree::GaussianSamplingTree() : GaussianSamplingTree(128, 3.2){};

}
