#pragma once

#include "ed25519/fields.hpp"
#include <optional>
#include <span>

namespace ed25519 {

    struct Point {
        FieldElement X;
        FieldElement Y;
        FieldElement Z;
        FieldElement T;

        static const Point IDENTITY;
        static const Point BASE;

        bool operator==(const Point& other) const;
    };

    Point point_add(const Point& P, const Point& Q);
    Point point_double(const Point& P);
    Point point_negate(const Point& P);

    Point point_scalar_mul(const Point& P, std::span<const uint8_t, 32> scalar);

    std::optional<Point> point_from_bytes(std::span<const uint8_t, 32> bytes);
    std::array<uint8_t, 32> point_to_bytes(const Point& P);
} 