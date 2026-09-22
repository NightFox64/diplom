#include <gtest/gtest.h>
#include "ed25519/fields.hpp"
#include <array>
#include <cstring>
#include <random>

using namespace ed25519;

static std::array<uint8_t, 32> prime_bytes() {
    std::array<uint8_t, 32> p{};
    p[0] = 0xED;
    for (int i = 1; i < 31; ++i) p[i] = 0xFF;
    p[31] = 0x7F;
    return p;
}

TEST(FieldConstants, Zero) {
    auto b = field_to_bytes(FieldElement::ZERO);
    for (uint8_t x : b) EXPECT_EQ(x, 0);
}

TEST(FieldConstants, One) {
    auto b = field_to_bytes(FieldElement::ONE);
    EXPECT_EQ(b[0], 1);
    for (size_t i = 1; i < 32; ++i) EXPECT_EQ(b[i], 0);
}

TEST(FieldRoundtrip, Zero) {
    std::array<uint8_t, 32> z{};
    auto fe = field_from_bytes(z);
    EXPECT_EQ(field_to_bytes(fe), z);
}

TEST(FieldRoundtrip, One) {
    std::array<uint8_t, 32> one{};
    one[0] = 1;
    auto fe = field_from_bytes(one);
    EXPECT_EQ(field_to_bytes(fe), one);
}

TEST(FieldRoundtrip, SmallValue) {
    // 0x42 в младшем байте
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x42;
    raw[15] = 0xAB;
    auto fe = field_from_bytes(raw);
    EXPECT_EQ(field_to_bytes(fe), raw);
}

TEST(FieldRoundtrip, MaxValidValue) {
    std::array<uint8_t, 32> pm1 = prime_bytes();
    pm1[0] -= 1; // ED - 1 = EC
    auto fe = field_from_bytes(pm1);
    EXPECT_EQ(field_to_bytes(fe), pm1);
}

TEST(FieldRoundtrip, HighBitIgnored) {
    std::array<uint8_t, 32> a{};
    a[0] = 0x55;
    std::array<uint8_t, 32> b = a;
    auto fa = field_from_bytes(a);
    auto fb = field_from_bytes(b);
    EXPECT_EQ(field_to_bytes(fa), field_to_bytes(fb));
}

TEST(FieldRoundtrip, PReducesToCanonical) {
    auto p = prime_bytes();
    auto fe = field_from_bytes(p);
    auto out = field_to_bytes(fe);
    std::array<uint8_t, 32> zero{};
    EXPECT_EQ(out, zero);
}

TEST(FieldRoundtrip, Random100) {
    std::mt19937_64 rng(0xDEADBEEF);
    for (int i = 0; i < 100; ++i) {
        std::array<uint8_t, 32> raw{};
        for (size_t j = 0; j < 4; ++j) {
            uint64_t v = rng();
            std::memcpy(raw.data() + j * 8, &v, 8);
        }
        raw[31] &= 0x7F;
        auto fe = field_from_bytes(raw);
        EXPECT_EQ(field_to_bytes(fe), raw);
    }
}

TEST(FieldCarryReduce, NoOverflowUnchanged) {
    FieldElement fe;
    fe.limbs[0] = 1;
    fe.limbs[1] = 2;
    fe.limbs[2] = 3;
    fe.limbs[3] = 4;
    fe.limbs[4] = 5;
    FieldElement r = field_carry_and_reduce(fe);
    EXPECT_EQ(field_to_bytes(r), field_to_bytes(fe));
}

TEST(FieldCarryReduce, OverflowLimb0) {
    FieldElement fe = FieldElement::ZERO;
    fe.limbs[0] = (1ULL << 52);
    FieldElement r = field_carry_and_reduce(fe);
    EXPECT_EQ(r.limbs[1], 2);
    EXPECT_EQ(r.limbs[0], 0);
}

TEST(FieldCarryReduce, OverflowLimb4WrapsTo0) {
    FieldElement fe = FieldElement::ZERO;
    fe.limbs[4] = (1ULL << 51);
    FieldElement r = field_carry_and_reduce(fe);
    EXPECT_EQ(r.limbs[4], 0);
    EXPECT_EQ(r.limbs[0], 19);
}

TEST(FieldAdd, ZeroIsIdentity) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x42; raw[10] = 0x77;
    FieldElement a = field_from_bytes(raw);
    FieldElement s = field_add(a, FieldElement::ZERO);
    EXPECT_EQ(field_to_bytes(s), raw);
}

TEST(FieldAdd, Commutativity) {
    std::array<uint8_t, 32> ra{}, rb{};
    ra[0] = 0x11; ra[5] = 0x22;
    rb[0] = 0x33; rb[7] = 0x44;
    FieldElement a = field_from_bytes(ra);
    FieldElement b = field_from_bytes(rb);
    EXPECT_EQ(field_to_bytes(field_add(a, b)),
              field_to_bytes(field_add(b, a)));
}

TEST(FieldAdd, Associativity) {
    std::array<uint8_t, 32> ra{}, rb{}, rc{};
    ra[0] = 5; rb[0] = 7; rc[0] = 11;
    FieldElement a = field_from_bytes(ra);
    FieldElement b = field_from_bytes(rb);
    FieldElement c = field_from_bytes(rc);
    FieldElement lhs = field_add(field_add(a, b), c);
    FieldElement rhs = field_add(a, field_add(b, c));
    EXPECT_EQ(field_to_bytes(lhs), field_to_bytes(rhs));
}

TEST(FieldAdd, WrapAroundPrime) {
    auto pm1_bytes = prime_bytes();
    pm1_bytes[0] -= 1;
    FieldElement pm1 = field_from_bytes(pm1_bytes);
    FieldElement sum = field_add(pm1, FieldElement::ONE);
    EXPECT_EQ(field_to_bytes(sum), field_to_bytes(FieldElement::ZERO));
}

TEST(FieldAdd, KnownResult) {
    auto make_small = [](uint64_t v) {
        std::array<uint8_t, 32> b{};
        std::memcpy(b.data(), &v, 8);
        return field_from_bytes(b);
    };
    FieldElement a = make_small(100);
    FieldElement b = make_small(200);
    FieldElement s = field_add(a, b);
    std::array<uint8_t, 32> expect300{};
    uint64_t v = 300;
    std::memcpy(expect300.data(), &v, 8);
    EXPECT_EQ(field_to_bytes(s), expect300);
}

TEST(FieldSub, ZeroIsIdentity) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x42; raw[10] = 0x77;
    FieldElement a = field_from_bytes(raw);
    FieldElement d = field_sub(a, FieldElement::ZERO);
    EXPECT_EQ(field_to_bytes(d), raw);
}

TEST(FieldSub, SelfIsZero) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x99; raw[20] = 0x11;
    FieldElement a = field_from_bytes(raw);
    FieldElement d = field_sub(a, a);
    EXPECT_EQ(field_to_bytes(d), field_to_bytes(FieldElement::ZERO));
}

TEST(FieldSub, AddSubRoundtrip) {
    std::array<uint8_t, 32> ra{}, rb{};
    ra[0] = 0x55; ra[8] = 0x12;
    rb[0] = 0x33; rb[8] = 0x05;
    FieldElement a = field_from_bytes(ra);
    FieldElement b = field_from_bytes(rb);
    FieldElement sum = field_add(a, b);
    FieldElement diff = field_sub(sum, b);
    EXPECT_EQ(field_to_bytes(diff), field_to_bytes(a));
}

TEST(FieldSub, Underflow) {
    FieldElement d = field_sub(FieldElement::ZERO, FieldElement::ONE);
    auto pm1_bytes = prime_bytes();
    pm1_bytes[0] -= 1;
    EXPECT_EQ(field_to_bytes(d), pm1_bytes);
}

TEST(FieldSub, KnownResult) {
    auto make_small = [](uint64_t v) {
        std::array<uint8_t, 32> b{};
        std::memcpy(b.data(), &v, 8);
        return field_from_bytes(b);
    };
    FieldElement a = make_small(300);
    FieldElement b = make_small(100);
    FieldElement d = field_sub(a, b);
    std::array<uint8_t, 32> expect200{};
    uint64_t v = 200;
    std::memcpy(expect200.data(), &v, 8);
    EXPECT_EQ(field_to_bytes(d), expect200);
}

TEST(FieldAddSub, RandomRoundtrip100) {
    std::mt19937_64 rng(1337);
    for (int iter = 0; iter < 100; ++iter) {
        std::array<uint8_t, 32> b1{}, b2{};
        for (size_t j = 0; j < 4; ++j) {
            uint64_t r1 = rng(), r2 = rng();
            std::memcpy(b1.data() + j * 8, &r1, 8);
            std::memcpy(b2.data() + j * 8, &r2, 8);
        }
        b1[31] &= 0x7F;
        b2[31] &= 0x7F;

        FieldElement a = field_from_bytes(b1);
        FieldElement b = field_from_bytes(b2);

        FieldElement diff = field_sub(field_add(a, b), b);
        EXPECT_EQ(field_to_bytes(diff), field_to_bytes(a));
    }
}

TEST(FieldAddSub, CommutativeRandom50) {
    std::mt19937_64 rng(42);
    for (int iter = 0; iter < 50; ++iter) {
        std::array<uint8_t, 32> b1{}, b2{};
        for (size_t j = 0; j < 4; ++j) {
            uint64_t r1 = rng(), r2 = rng();
            std::memcpy(b1.data() + j * 8, &r1, 8);
            std::memcpy(b2.data() + j * 8, &r2, 8);
        }
        b1[31] &= 0x7F;
        b2[31] &= 0x7F;
        FieldElement a = field_from_bytes(b1);
        FieldElement b = field_from_bytes(b2);
        EXPECT_EQ(field_to_bytes(field_add(a, b)),
                  field_to_bytes(field_add(b, a)));
    }
}

TEST(FieldEquals, SameIsEqual) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 7;
    FieldElement a = field_from_bytes(raw);
    FieldElement b = field_from_bytes(raw);
    EXPECT_TRUE(a == b);
}

TEST(FieldEquals, DifferentIsNotEqual) {
    std::array<uint8_t, 32> r1{}, r2{};
    r1[0] = 1; r2[0] = 2;
    FieldElement a = field_from_bytes(r1);
    FieldElement b = field_from_bytes(r2);
    EXPECT_FALSE(a == b);
}

TEST(FieldEquals, ZeroEqualsZero) {
    EXPECT_TRUE(FieldElement::ZERO == FieldElement::ZERO);
}

TEST(FieldEquals, OneEqualsOne) {
    EXPECT_TRUE(FieldElement::ONE == FieldElement::ONE);
}

TEST(FieldEquals, ZeroNotEqualOne) {
    EXPECT_FALSE(FieldElement::ZERO == FieldElement::ONE);
}

// ============================================================
// field_mul
// ============================================================

TEST(FieldMul, ZeroAnnihilates) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x42; raw[15] = 0xAB;
    FieldElement a = field_from_bytes(raw);
    EXPECT_EQ(field_to_bytes(field_mul(a, FieldElement::ZERO)),
              field_to_bytes(FieldElement::ZERO));
    EXPECT_EQ(field_to_bytes(field_mul(FieldElement::ZERO, a)),
              field_to_bytes(FieldElement::ZERO));
}

TEST(FieldMul, OneIsIdentity) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x37; raw[8] = 0x11;
    FieldElement a = field_from_bytes(raw);
    EXPECT_EQ(field_to_bytes(field_mul(a, FieldElement::ONE)), field_to_bytes(a));
    EXPECT_EQ(field_to_bytes(field_mul(FieldElement::ONE, a)), field_to_bytes(a));
}

TEST(FieldMul, Commutativity) {
    std::array<uint8_t, 32> ra{}, rb{};
    ra[0] = 0x13; ra[3] = 0x7F;
    rb[0] = 0x29; rb[5] = 0x55;
    FieldElement a = field_from_bytes(ra);
    FieldElement b = field_from_bytes(rb);
    EXPECT_EQ(field_to_bytes(field_mul(a, b)),
              field_to_bytes(field_mul(b, a)));
}

TEST(FieldMul, Associativity) {
    std::array<uint8_t, 32> ra{}, rb{}, rc{};
    ra[0] = 3; rb[0] = 5; rc[0] = 7;
    FieldElement a = field_from_bytes(ra);
    FieldElement b = field_from_bytes(rb);
    FieldElement c = field_from_bytes(rc);
    FieldElement lhs = field_mul(field_mul(a, b), c);
    FieldElement rhs = field_mul(a, field_mul(b, c));
    EXPECT_EQ(field_to_bytes(lhs), field_to_bytes(rhs));
}

TEST(FieldMul, Distributivity) {
    // a * (b + c) == a*b + a*c
    std::array<uint8_t, 32> ra{}, rb{}, rc{};
    ra[0] = 11; rb[0] = 13; rc[0] = 17;
    FieldElement a = field_from_bytes(ra);
    FieldElement b = field_from_bytes(rb);
    FieldElement c = field_from_bytes(rc);
    FieldElement lhs = field_mul(a, field_add(b, c));
    FieldElement rhs = field_add(field_mul(a, b), field_mul(a, c));
    EXPECT_EQ(field_to_bytes(lhs), field_to_bytes(rhs));
}

TEST(FieldMul, KnownSmallResult) {
    // 6 * 7 = 42
    auto make_small = [](uint64_t v) {
        std::array<uint8_t, 32> b{};
        std::memcpy(b.data(), &v, 8);
        return field_from_bytes(b);
    };
    FieldElement a = make_small(6);
    FieldElement b = make_small(7);
    FieldElement p = field_mul(a, b);
    std::array<uint8_t, 32> expect42{};
    uint64_t v = 42;
    std::memcpy(expect42.data(), &v, 8);
    EXPECT_EQ(field_to_bytes(p), expect42);
}

TEST(FieldMul, Random100Commutative) {
    std::mt19937_64 rng(0xCAFEBABE);
    for (int iter = 0; iter < 100; ++iter) {
        std::array<uint8_t, 32> b1{}, b2{};
        for (size_t j = 0; j < 4; ++j) {
            uint64_t r1 = rng(), r2 = rng();
            std::memcpy(b1.data() + j * 8, &r1, 8);
            std::memcpy(b2.data() + j * 8, &r2, 8);
        }
        b1[31] &= 0x7F;
        b2[31] &= 0x7F;
        FieldElement a = field_from_bytes(b1);
        FieldElement b = field_from_bytes(b2);
        EXPECT_EQ(field_to_bytes(field_mul(a, b)),
                  field_to_bytes(field_mul(b, a)));
    }
}

// ============================================================
// field_sqr
// ============================================================

TEST(FieldSqr, ZeroIsZero) {
    EXPECT_EQ(field_to_bytes(field_sqr(FieldElement::ZERO)),
              field_to_bytes(FieldElement::ZERO));
}

TEST(FieldSqr, OneIsOne) {
    EXPECT_EQ(field_to_bytes(field_sqr(FieldElement::ONE)),
              field_to_bytes(FieldElement::ONE));
}

TEST(FieldSqr, EquivalentToMulSelf) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x2B; raw[7] = 0x4E;
    FieldElement a = field_from_bytes(raw);
    EXPECT_EQ(field_to_bytes(field_sqr(a)),
              field_to_bytes(field_mul(a, a)));
}

TEST(FieldSqr, KnownSmallResult) {
    // 9^2 = 81
    auto make_small = [](uint64_t v) {
        std::array<uint8_t, 32> b{};
        std::memcpy(b.data(), &v, 8);
        return field_from_bytes(b);
    };
    FieldElement nine = make_small(9);
    FieldElement sq = field_sqr(nine);
    std::array<uint8_t, 32> expect81{};
    uint64_t v = 81;
    std::memcpy(expect81.data(), &v, 8);
    EXPECT_EQ(field_to_bytes(sq), expect81);
}

TEST(FieldSqr, Random50EquivMulSelf) {
    std::mt19937_64 rng(0xBEEFDEAD);
    for (int iter = 0; iter < 50; ++iter) {
        std::array<uint8_t, 32> raw{};
        for (size_t j = 0; j < 4; ++j) {
            uint64_t r = rng();
            std::memcpy(raw.data() + j * 8, &r, 8);
        }
        raw[31] &= 0x7F;
        FieldElement a = field_from_bytes(raw);
        EXPECT_EQ(field_to_bytes(field_sqr(a)),
                  field_to_bytes(field_mul(a, a)));
    }
}

// ============================================================
// field_inv
// ============================================================

TEST(FieldInv, OneInvIsOne) {
    FieldElement inv1 = field_inv(FieldElement::ONE);
    EXPECT_EQ(field_to_bytes(inv1), field_to_bytes(FieldElement::ONE));
}

TEST(FieldInv, ATimesInvAIsOne) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x05;
    FieldElement a = field_from_bytes(raw);
    FieldElement inv_a = field_inv(a);
    FieldElement prod = field_mul(a, inv_a);
    EXPECT_EQ(field_to_bytes(prod), field_to_bytes(FieldElement::ONE));
}

TEST(FieldInv, InvInvIsOriginal) {
    std::array<uint8_t, 32> raw{};
    raw[0] = 0x17; raw[4] = 0xAA;
    FieldElement a = field_from_bytes(raw);
    FieldElement inv_inv_a = field_inv(field_inv(a));
    EXPECT_EQ(field_to_bytes(inv_inv_a), field_to_bytes(a));
}

TEST(FieldInv, SmallValues) {
    // Для нескольких малых значений: a * inv(a) == 1
    auto make_small = [](uint64_t v) {
        std::array<uint8_t, 32> b{};
        std::memcpy(b.data(), &v, 8);
        return field_from_bytes(b);
    };
    for (uint64_t v : {2ULL, 3ULL, 7ULL, 100ULL, 255ULL}) {
        FieldElement a = make_small(v);
        FieldElement prod = field_mul(a, field_inv(a));
        EXPECT_EQ(field_to_bytes(prod), field_to_bytes(FieldElement::ONE))
            << "Failed for v=" << v;
    }
}

TEST(FieldInv, Random20ATimesInvIsOne) {
    std::mt19937_64 rng(0xABCDEF01);
    for (int iter = 0; iter < 20; ++iter) {
        std::array<uint8_t, 32> raw{};
        for (size_t j = 0; j < 4; ++j) {
            uint64_t r = rng();
            std::memcpy(raw.data() + j * 8, &r, 8);
        }
        raw[31] &= 0x7F;
        // Убедимся, что значение ненулевое
        if (raw[0] == 0 && raw[8] == 0 && raw[16] == 0 && raw[24] == 0) {
            raw[0] = 1;
        }
        FieldElement a = field_from_bytes(raw);
        FieldElement prod = field_mul(a, field_inv(a));
        EXPECT_EQ(field_to_bytes(prod), field_to_bytes(FieldElement::ONE));
    }
}

TEST(FieldInv, DebugFive) {
    for (uint64_t v : {1ULL, 2ULL, 3ULL, 5ULL, 7ULL}) {
        std::array<uint8_t, 32> raw{};
        std::memcpy(raw.data(), &v, 8);

        FieldElement a = field_from_bytes(raw);
        FieldElement inv = field_inv(a);
        FieldElement prod = field_mul(a, inv);

        auto result = field_to_bytes(prod);

        std::cout << "v = " << v
                  << ", result = "
                  << static_cast<int>(result[0])
                  << '\n';
    }
}
