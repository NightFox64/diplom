#include <benchmark/benchmark.h>
#include "ed25519/fields.hpp"

using namespace ed25519;

static void BM_Sanity(benchmark::State& state) {
    for (auto _ : state) {
        benchmark::DoNotOptimize(ed25519::sanity_check());
    }
}
BENCHMARK(BM_Sanity);

static void BM_FieldMul(benchmark::State& state) {
    FieldElement a = FieldElement::ONE;
    FieldElement b = FieldElement::ONE;
    b.limbs[0] = 123456789;

    for (auto _ : state) {
        a = field_mul(a, b);
        benchmark::DoNotOptimize(a);
    }
}
BENCHMARK(BM_FieldMul);

static void BM_FieldInv(benchmark::State& state) {
    FieldElement a = FieldElement::ONE;
    a.limbs[0] = 987654321;

    for (auto _ : state) {
        FieldElement res = field_inv(a);
        benchmark::DoNotOptimize(res);
        a.limbs[0]++;
    }
}
BENCHMARK(BM_FieldInv);