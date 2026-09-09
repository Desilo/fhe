cmake_minimum_required(VERSION 3.25.2)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

# custom flags
option(BUILD_GMOCK "Build Google Mock" OFF)
option(DESILO_FHE_CHECK_HARDCODED "Enable Check Hardcoded" OFF)
option(DESILO_FHE_COVERAGE "Enable Coverage" OFF)
option(DESILO_FHE_DEBUG "Enable Debug mode" OFF)
option(DESILO_FHE_EXAMPLES "Enable Examples" OFF)
option(DESILO_FHE_GOOGLE_TEST "Enable Google Test" OFF)
option(DESILO_FHE_INCREMENTAL_BUILD "Enable Incremental Build" OFF)
option(DESILO_FHE_UNIT_TEST "Enable Unit Test" OFF)
option(DESILO_FHE_CKKS_CORE_TEST "Enable CKKS Core Test" OFF)
option(DESILO_FHE_CKKS_ENGINE_BASE_TEST "Enable CKKS Engine Base Test" OFF)
option(DESILO_FHE_CKKS_ENGINE_SP_TEST "Enable CKKS Engine SP Test" OFF)
option(DESILO_FHE_CKKS_ENGINE_SPE_TEST "Enable CKKS Engine SPE Test" OFF)
option(DESILO_FHE_CKKS_ENGINE_SPX_TEST "Enable CKKS Engine SPX Test" OFF)
option(DESILO_FHE_CKKS_ENGINE_REJECT_TEST "Enable CKKS Engine Reject Test" OFF)
option(DESILO_FHE_LARGE_TEST "Enable Large Test" OFF)

# compiler 최적화
set(CMAKE_CXX_FLAGS "-Wno-everything ${CMAKE_CXX_FLAGS}")

if(DESILO_FHE_DEBUG)
  set(CMAKE_BUILD_TYPE Debug)
else()
  set(CMAKE_BUILD_TYPE Release)
endif()

project(desilo_fhe LANGUAGES CXX)

if(DESILO_FHE_COVERAGE)
  set(CMAKE_CXX_FLAGS --coverage)
endif()

if(DESILO_FHE_INCREMENTAL_BUILD)
  find_program(CCACHE_PROGRAM ccache)
  if (CCACHE_PROGRAM)
    set(CCACHE_ENV "CCACHE_DIR=${CMAKE_BINARY_DIR}/.ccache")
    set(CMAKE_C_COMPILER_LAUNCHER
        "${CMAKE_COMMAND}" -E env ${CCACHE_ENV} ${CCACHE_PROGRAM})
    set(CMAKE_CXX_COMPILER_LAUNCHER
        "${CMAKE_COMMAND}" -E env ${CCACHE_ENV} ${CCACHE_PROGRAM})
  endif()

  # Force ANSI colors in the compiler output
  add_compile_options(-fdiagnostics-color=always)
endif()

set(VERSION "1.6.0")

include_directories(src)

add_library(desilo_fhe
  src/arithmetic/arithmetic.cpp
  src/arithmetic/big_int.cpp
  src/arithmetic/prime.cpp
  src/ckks/config.cpp
  src/ckks/core.cpp
  src/ckks/core_allocate.cpp
  src/ckks/core_calculate.cpp
  src/ckks/core_decode.cpp
  src/ckks/core_encode.cpp
  src/ckks/core_key.cpp
  src/ckks/core_key_switch.cpp
  src/ckks/core_ntt.cpp
  src/ckks/core_polynomial.cpp
  src/ckks/core_random.cpp
  src/ckks/core_rescale.cpp
  src/ckks/derived_parameters.cpp
  src/ckks/encode.cpp
  src/ckks/engine.cpp
  src/ckks/engine_add.cpp
  src/ckks/engine_advanced.cpp
  src/ckks/engine_bootstrap.cpp
  src/ckks/engine_clone.cpp
  src/ckks/engine_conjugate.cpp
  src/ckks/engine_decode.cpp
  src/ckks/engine_decrypt.cpp
  src/ckks/engine_encode.cpp
  src/ckks/engine_encode_matrix.cpp
  src/ckks/engine_encrypt.cpp
  src/ckks/engine_intt.cpp
  src/ckks/engine_level_down.cpp
  src/ckks/engine_mod_raise.cpp
  src/ckks/engine_multiply.cpp
  src/ckks/engine_multiply_matrix.cpp
  src/ckks/engine_negate.cpp
  src/ckks/engine_ntt.cpp
  src/ckks/engine_relinearize.cpp
  src/ckks/engine_rescale.cpp
  src/ckks/engine_require.cpp
  src/ckks/engine_rotate.cpp
  src/ckks/engine_subtract.cpp
  src/ckks/parameters.cpp
  src/ckks/partition_cache.cpp
  src/ckks/precomputed.cpp
  src/data/bootstrap.cpp
  src/data/data.cpp
  src/data/flag.cpp
  src/data/plain_matrix.cpp
  src/data/polynomial.cpp
  src/engine/engine.cpp
  src/engine/scheme_preset.cpp
  src/montgomery/compound.cpp
  src/montgomery/unit.cpp
  src/operation/bootstrap.cpp
  src/operation/fft.cpp
  src/operation/ntt.cpp
  src/operation/scalar.cpp
  src/parallel/task.cpp
  src/parallel/task_balancer.cpp
  src/parallel/worker.cpp
  src/processor/parallel.cpp
  src/parameter/decode.cpp
  src/parameter/multiplier.cpp
  src/parameter/partition.cpp
  src/parameter/permutation.cpp
  src/processor/single.cpp
  src/random/gaussian_sampler.cpp
  src/random/random.cpp
  src/random/random_number_generator.cpp
  src/util/string_transform.cpp
)

find_package(Threads REQUIRED)
target_link_libraries(desilo_fhe Threads::Threads)

if(DESILO_FHE_DEBUG)
  target_compile_definitions(desilo_fhe PUBLIC DESILO_FHE_DEBUG)
endif()

if(DESILO_FHE_GOOGLE_TEST)
  enable_testing()
  add_subdirectory(extern/googletest)
  add_library(desilo_fhe_test_common
    test/common/common.cpp
    test/common/test.cpp
  )

  # DESILO_FHE_GOOGLE_TEST flag exposes extra scheme presets for testing.
  target_compile_definitions(desilo_fhe PUBLIC DESILO_FHE_GOOGLE_TEST)
  target_include_directories(desilo_fhe_test_common PUBLIC test)
  target_link_libraries(desilo_fhe_test_common GTest::gtest_main desilo_fhe)

  if(DESILO_FHE_LARGE_TEST)
    target_compile_definitions(desilo_fhe PUBLIC DESILO_FHE_LARGE_TEST)
  endif()

  include(GoogleTest)

  if(DESILO_FHE_UNIT_TEST)
    add_executable(
      unit_test
      test/arithmetic/arithmetic.cpp
      test/arithmetic/big_int.cpp
      test/ckks/bit_reverse_order.cpp
      test/ckks/config.cpp
      test/ckks/derived_parameters.cpp
      test/ckks/encode.cpp
      test/ckks/parameters/can_rescale_from.cpp
      test/ckks/parameters/chain_offset.cpp
      test/ckks/parameters/deviations.cpp
      test/ckks/parameters/get_partitions.cpp
      test/ckks/parameters/key_moduli_id.cpp
      test/ckks/parameters/level.cpp
      test/ckks/parameters/moduli_type.cpp
      test/ckks/parameters/next_moduli_id_at_rescale.cpp
      test/ckks/parameters/ntt_moduli_id.cpp
      test/ckks/parameters/parameters.cpp
      test/ckks/parameters/scale.cpp
      test/ckks/partitions_cache.cpp
      test/ckks/precomputed/default.cpp
      test/ckks/precomputed/encode.cpp
      test/ckks/precomputed/precomputed.cpp
      test/ckks/precomputed/rescaled_scale.cpp
      test/data/data.cpp
      test/data/nbytes.cpp
      test/data/polynomial.cpp
      test/data/polynomial_view.cpp
      test/engine/engine.cpp
      test/engine/scheme_preset.cpp
      test/montgomery/compound.cpp
      test/montgomery/unit.cpp
      test/operation/bootstrap.cpp
      test/operation/fft.cpp
      test/operation/ntt.cpp
      test/operation/scalar.cpp
      test/parameter/decode.cpp
      test/parameter/multiplier.cpp
      test/parameter/permutation.cpp
      test/processor/single.cpp
      test/random/gaussian_sampler.cpp
      test/random/random.cpp
      test/random/random_number_generator.cpp
      test/util/string_transform.cpp
    )

    target_link_libraries(unit_test desilo_fhe_test_common)
  endif()

  if(DESILO_FHE_CKKS_CORE_TEST)
    file(GLOB CKKS_CORE_TEST_SOURCES test/ckks/core/*.cpp)

    foreach (test_source_file ${CKKS_CORE_TEST_SOURCES})
      get_filename_component(test_name ${test_source_file} NAME_WLE)
      set(test_executable "ckks_core_${test_name}_test")
      add_executable(${test_executable} ${test_source_file})
      target_link_libraries(${test_executable} desilo_fhe_test_common)

      gtest_discover_tests(${test_executable})
    endforeach (test_source_file ${CKKS_CORE_TEST_SOURCES})
  endif()

  if(DESILO_FHE_CKKS_ENGINE_BASE_TEST)
    file(GLOB CKKS_ENGINE_BASE_TEST_SOURCES test/ckks/engine/*.cpp)
    list(FILTER CKKS_ENGINE_BASE_TEST_SOURCES EXCLUDE REGEX ".*/(sp|cuda|not|reject).*.cpp")

    foreach (test_source_file ${CKKS_ENGINE_BASE_TEST_SOURCES})
      get_filename_component(test_name ${test_source_file} NAME_WLE)
      set(test_executable "ckks_engine_${test_name}_test")
      add_executable(${test_executable} ${test_source_file})
      target_link_libraries(${test_executable} desilo_fhe_test_common)

      gtest_discover_tests(${test_executable})
    endforeach (test_source_file ${CKKS_ENGINE_BASE_TEST_SOURCES})
  endif()

  if(DESILO_FHE_CKKS_ENGINE_REJECT_TEST)
    file(GLOB CKKS_ENGINE_REJECT_TEST_SOURCES
      test/ckks/engine/not_*.cpp
      test/ckks/engine/reject_*.cpp
    )

    foreach (test_source_file ${CKKS_ENGINE_REJECT_TEST_SOURCES})
      get_filename_component(test_name ${test_source_file} NAME_WLE)
      set(test_executable "ckks_engine_${test_name}_test")
      add_executable(${test_executable} ${test_source_file})
      target_link_libraries(${test_executable} desilo_fhe_test_common)

      gtest_discover_tests(${test_executable})
    endforeach (test_source_file ${CKKS_ENGINE_REJECT_TEST_SOURCES})
  endif()

  if(DESILO_FHE_CKKS_ENGINE_SP_TEST)
    file(GLOB CKKS_ENGINE_SP_TEST_SOURCES
      test/ckks/engine/sp[0-9]*.cpp
    )

    foreach (test_source_file ${CKKS_ENGINE_SP_TEST_SOURCES})
      get_filename_component(test_name ${test_source_file} NAME_WLE)
      set(test_executable "ckks_engine_${test_name}_test")
      add_executable(${test_executable} ${test_source_file})
      target_link_libraries(${test_executable} desilo_fhe_test_common)

      gtest_discover_tests(${test_executable})
    endforeach (test_source_file ${CKKS_ENGINE_SP_TEST_SOURCES})
  endif()

  if(DESILO_FHE_CKKS_ENGINE_SPE_TEST)
    file(GLOB CKKS_ENGINE_SPE_TEST_SOURCES
      test/ckks/engine/spe*.cpp
    )

    foreach (test_source_file ${CKKS_ENGINE_SPE_TEST_SOURCES})
      get_filename_component(test_name ${test_source_file} NAME_WLE)
      set(test_executable "ckks_engine_${test_name}_test")
      add_executable(${test_executable} ${test_source_file})
      target_link_libraries(${test_executable} desilo_fhe_test_common)

      gtest_discover_tests(${test_executable})
    endforeach (test_source_file ${CKKS_ENGINE_SPE_TEST_SOURCES})
  endif()

  if(DESILO_FHE_CKKS_ENGINE_SPX_TEST)
    file(GLOB CKKS_ENGINE_SPX_TEST_SOURCES
      test/ckks/engine/sp[a-df-z]*.cpp
    )

    foreach (test_source_file ${CKKS_ENGINE_SPX_TEST_SOURCES})
      get_filename_component(test_name ${test_source_file} NAME_WLE)
      set(test_executable "ckks_engine_${test_name}_test")
      add_executable(${test_executable} ${test_source_file})
      target_link_libraries(${test_executable} desilo_fhe_test_common)

      gtest_discover_tests(${test_executable})
    endforeach (test_source_file ${CKKS_ENGINE_SPX_TEST_SOURCES})
  endif()

  if(DESILO_FHE_UNIT_TEST)
    if(DESILO_FHE_CHECK_HARDCODED)
      find_library(gmp gmp)
      find_library(mpfr mpfr)

      target_compile_definitions(desilo_fhe PUBLIC DESILO_FHE_CHECK_HARDCODED)
      target_link_libraries(desilo_fhe gmp mpfr)

      target_sources(unit_test
        PRIVATE
        test/arithmetic/prime.cpp
      )
    endif()
  endif()
  if(DESILO_FHE_UNIT_TEST)
    gtest_discover_tests(unit_test)
  endif()
endif()

# examples 폴더 아래의 각 파일에 대해 실행 파일을 생성합니다.
if(DESILO_FHE_EXAMPLES)
file(GLOB EXAMPLES_SOURCE_FILES examples/*.cpp)
  foreach(EXAMPLE_SOURCE_FILE ${EXAMPLES_SOURCE_FILES})
    get_filename_component(EXAMPLE_NAME ${EXAMPLE_SOURCE_FILE} NAME_WE)
    add_executable(
      ${EXAMPLE_NAME}
      ${EXAMPLE_SOURCE_FILE}
    )
    target_link_libraries(${EXAMPLE_NAME} desilo_fhe)
    set_property(
      TARGET
      ${EXAMPLE_NAME}
      PROPERTY
      RUNTIME_OUTPUT_DIRECTORY
      ${CMAKE_BINARY_DIR}/bin/examples
    )
  endforeach()
endif()
