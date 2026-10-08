#include <gtest/gtest.h>
#include "ed25519/point.hpp"
#include <array>
#include <cstring>

using namespace ed25519;

static std::array<uint8_t, 32> scalar_from_u64(uint64_t v) {
    std::array<uint8_t, 32> s{};
    std::memcpy(s.data(), &v, 8);
    return s;
}

static constexpr std::array<uint8_t, 32> BASE_BYTES = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static constexpr std::array<uint8_t, 32> ORDER_L = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

TEST(PointIdentity, AddIdentityIsIdentity) {
    Point r = point_add(Point::IDENTITY, Point::IDENTITY);
    EXPECT_EQ(r, Point::IDENTITY);
}

TEST(PointIdentity, DoubleIdentityIsIdentity) {
    Point r = point_double(Point::IDENTITY);
    EXPECT_EQ(r, Point::IDENTITY);
}

TEST(PointIdentity, NegateIdentityIsIdentity) {
    Point r = point_negate(Point::IDENTITY);
    EXPECT_EQ(r, Point::IDENTITY);
}

TEST(PointIdentity, AddBaseIdentityLeftIsBase) {
    Point r = point_add(Point::IDENTITY, Point::BASE);
    EXPECT_EQ(r, Point::BASE);
}

TEST(PointIdentity, AddBaseIdentityRightIsBase) {
    Point r = point_add(Point::BASE, Point::IDENTITY);
    EXPECT_EQ(r, Point::BASE);
}

TEST(PointBase, DeserializesCorrectly) {
    auto pt_opt = point_from_bytes(BASE_BYTES);
    ASSERT_TRUE(pt_opt.has_value());
    EXPECT_EQ(*pt_opt, Point::BASE);
}

TEST(PointBase, SerializesCorrectly) {
    auto out = point_to_bytes(Point::BASE);
    EXPECT_EQ(out, BASE_BYTES);
}

TEST(PointRoundtrip, BaseRoundtrip) {
    auto serialized = point_to_bytes(Point::BASE);
    auto pt_opt = point_from_bytes(serialized);
    ASSERT_TRUE(pt_opt.has_value());
    EXPECT_EQ(*pt_opt, Point::BASE);
}

TEST(PointRoundtrip, InvalidPointReturnsNullopt) {
    std::array<uint8_t, 32> bad{};
    auto result = point_from_bytes(bad);
    EXPECT_FALSE(result.has_value());
}

TEST(PointNegate, BaseAndNegateAddToIdentity) {
    Point neg_B = point_negate(Point::BASE);
    Point r = point_add(Point::BASE, neg_B);
    EXPECT_EQ(r, Point::IDENTITY);
}

TEST(PointNegate, DoubleNegateIsOriginal) {
    Point r = point_negate(point_negate(Point::BASE));
    EXPECT_EQ(r, Point::BASE);
}

TEST(PointAdd, Commutativity) {
    Point two_B = point_double(Point::BASE);
    Point lhs = point_add(Point::BASE, two_B);
    Point rhs = point_add(two_B, Point::BASE);
    EXPECT_EQ(lhs, rhs);
}

TEST(PointAdd, Associativity) {
    Point two_B   = point_double(Point::BASE);
    Point three_B = point_add(two_B, Point::BASE);
    Point lhs = point_add(point_add(Point::BASE, two_B), three_B);
    Point rhs = point_add(Point::BASE, point_add(two_B, three_B));
    EXPECT_EQ(lhs, rhs);
}

TEST(PointAdd, DoubleViaAddSelf) {
    Point via_add    = point_add(Point::BASE, Point::BASE);
    Point via_double = point_double(Point::BASE);
    EXPECT_EQ(via_add, via_double);
}

TEST(PointAdd, ThreeTimesConsistency) {
    Point add3 = point_add(point_add(Point::BASE, Point::BASE), Point::BASE);
    auto s3 = scalar_from_u64(3);
    Point scalar3 = point_scalar(Point::BASE, s3);
    EXPECT_EQ(add3, scalar3);
}

TEST(PointDouble, TwoTimesBase) {
    Point via_double = point_double(Point::BASE);
    auto s2 = scalar_from_u64(2);
    Point via_scalar = point_scalar(Point::BASE, s2);
    EXPECT_EQ(via_double, via_scalar);
}

TEST(PointDouble, FourTimesBase) {
    Point four_B_double = point_double(point_double(Point::BASE));
    auto s4 = scalar_from_u64(4);
    Point four_B_scalar = point_scalar(Point::BASE, s4);
    EXPECT_EQ(four_B_double, four_B_scalar);
}

TEST(PointScalarMul, ScalarZeroIsIdentity) {
    auto s0 = scalar_from_u64(0);
    Point r = point_scalar(Point::BASE, s0);
    EXPECT_EQ(r, Point::IDENTITY);
}

TEST(PointScalarMul, ScalarOneIsBase) {
    auto s1 = scalar_from_u64(1);
    Point r = point_scalar(Point::BASE, s1);
    EXPECT_EQ(r, Point::BASE);
}

TEST(PointScalarMul, ScalarTwoIsDouble) {
    auto s2 = scalar_from_u64(2);
    Point r = point_scalar(Point::BASE, s2);
    EXPECT_EQ(r, point_double(Point::BASE));
}

TEST(PointScalarMul, OrderLIsIdentity) {
    Point r = point_scalar(Point::BASE, ORDER_L);
    EXPECT_EQ(r, Point::IDENTITY);
}

TEST(PointScalarMul, LinearitySmall) {
    auto s3  = scalar_from_u64(3);
    auto s5  = scalar_from_u64(5);
    auto s8  = scalar_from_u64(8);
    Point lhs = point_scalar(Point::BASE, s8);
    Point rhs = point_add(
        point_scalar(Point::BASE, s3),
        point_scalar(Point::BASE, s5)
    );
    EXPECT_EQ(lhs, rhs);
}

TEST(PointScalarMul, ScalarMulThenAdd) {
    auto s10 = scalar_from_u64(10);
    auto s7  = scalar_from_u64(7);
    auto s3  = scalar_from_u64(3);
    Point lhs = point_scalar(Point::BASE, s10);
    Point rhs = point_add(
        point_scalar(Point::BASE, s7),
        point_scalar(Point::BASE, s3)
    );
    EXPECT_EQ(lhs, rhs);
}

TEST(PointScalarMul, ScalarMulAssociativity) {
    Point three_B = point_scalar(Point::BASE, scalar_from_u64(3));
    Point six_B_via_double = point_scalar(three_B, scalar_from_u64(2));
    Point six_B_direct     = point_scalar(Point::BASE, scalar_from_u64(6));
    EXPECT_EQ(six_B_via_double, six_B_direct);
}

TEST(PointEquals, SameIsEqual) {
    EXPECT_EQ(Point::BASE, Point::BASE);
    EXPECT_EQ(Point::IDENTITY, Point::IDENTITY);
}

TEST(PointEquals, DifferentIsNotEqual) {
    EXPECT_NE(Point::BASE, Point::IDENTITY);
}

TEST(PointEquals, AddedAndDirectScalarAreEqual) {
    Point r1 = point_scalar(Point::BASE, scalar_from_u64(5));
    Point r2 = point_add(
        point_scalar(Point::BASE, scalar_from_u64(4)),
        Point::BASE
    );
    EXPECT_EQ(r1, r2);
}
