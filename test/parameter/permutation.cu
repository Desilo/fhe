#include "cuda/cuda.cuh"

namespace desilo::fhe {

extern "C" void cuda_copy_parameter_from_device(const int32_t *device_parameter,
                                                int32_t *host_parameter,
                                                int size) {
  cudaError_t error =
      cudaMemcpy(host_parameter, device_parameter, sizeof(int32_t) * size,
                 cudaMemcpyDeviceToHost);
  check_cuda_error(error);
}

}
