#include <benchmark/benchmark.h>
#include "ed25519/fields.hpp"

static void BM_Sanity(benchmark::State& state) {
    for (auto _ : state) {
        benchmark::DoNotOptimize(ed25519::sanity_check());
    }
}
BENCHMARK(BM_Sanity);