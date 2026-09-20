cmake_minimum_required(VERSION 3.20)
project(ed25519_batch_research LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.8.3
)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(benchmark)

add_library(ed25519_core
    src/field/field.cpp
)
target_include_directories(ed25519_core PUBLIC include)

enable_testing()

add_executable(unit_tests tests/field_test.cpp)
target_link_libraries(unit_tests PRIVATE ed25519_core GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(unit_tests)

add_executable(benchmarks benchmarks/bench_verify.cpp)
target_link_libraries(benchmarks PRIVATE ed25519_core benchmark::benchmark_main)