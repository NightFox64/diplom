#include "ed25519/point.hpp"
#include <cstring>

namespace ed25519 {
    
    const Point Point ::IDENTITY = {
        FieldElement::ZERO,
        FieldElement::ONE,
        FieldElement::ONE,
        FieldElement::ZERO,
    };

    // d = - 121665 / 121666
    static const FieldElement _D = []() {
        constexpr std::array<uint8_t, 32> d_bytes = {
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
            0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
            0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
            0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6e, 0xd3, 0x52
        };
        return field_from_bytes(d_bytes);
    }();

    static const FieldElement TWO_D = field_add(_D, _D);

    // RFC 8032
    const Point Point::BASE = []() {
        constexpr std::array<uint8_t, 32> b_y_bytes = {
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
        };
        auto pt = point_from_bytes(b_y_bytes);
        return pt.value();
    }();

    bool operator==(const Point& P, const Point& Q) {
        // В проективных координатах P == Q <=> X1*Z2 == X2*Z1 и Y1*Z2 == Y2*Z1
        FieldElement x1z2 = field_mul(P.X, Q.Z);
        FieldElement x2z1 = field_mul(Q.X, P.Z);
        FieldElement y1z2 = field_mul(P.Y, Q.Z);
        FieldElement y2z1 = field_mul(P.Z, Q.Y);

        return (field_to_bytes(x1z2) == field_to_bytes(x2z1)) &&
                (field_to_bytes(y1z2) == field_to_bytes(y2z1));
    }

    Point point_add(const Point& P, const Point& Q) {
        FieldElement A = field_mul(field_sub(P.Y, P.X), field_sub(Q.Y, Q.X));
        FieldElement B = field_mul(field_add(P.Y, P.X), field_add(Q.Y, Q.X));
        FieldElement C = field_mul(field_mul(TWO_D, P.T), Q.T);
        FieldElement D = field_mul(field_mul(P.Z, P.Z), Q.Z);
        FieldElement E = field_sub(B, A);
        FieldElement F = field_sub(D, C);
        FieldElement G = field_add(D, C);
        FieldElement H = field_add(B, A);

        return Point{
            field_mul(E, F),
            field_mul(G, H),
            field_mul(F, G),
            field_mul(E, H),
        };

    }

    Point point_double(const Point& P) {
        FieldElement A = field_sqr(P.X);
        FieldElement B = field_sqr(P.Y);
        FieldElement C = field_sqr(P.Z);
        C = field_add(C, C);

        FieldElement D = field_inv(A);
        FieldElement E = field_sub(field_sqr(field_add(P.X, P.Y)), field_add(A, B));
        FieldElement G = field_sub(D, B);
        FieldElement F = field_sub(G, C);
        FieldElement H = field_sub(D, B);

        return Point{
            field_mul(E, F),
            field_mul(G, H),
            field_mul(F, G),
            field_mul(E, H),
        };
    }

    Point point_negate(const Point& P) {
        return Point{
            field_sub(FieldElement::ZERO, P.X),
            P.Y,
            P.Z,
            field_sub(FieldElement::ZERO, P.T),
        };
    }

    Point point_scalar(const Point& P, std::span<const uint8_t, 32> scalar) {
        Point result = Point::IDENTITY;
        Point current = P;

        for (size_t byte_idx = 0; byte_idx < 32; ++byte_idx) {
            uint8_t byte = scalar[byte_idx];
            for (int bit = 0; bit < 8; ++bit) {
                if ((byte >> bit) & 1) {
                    result = point_add(result, current);
                }
                current = point_double(current);
            }
        }
        return result;
    }

    static std::optional<FieldElement> recover_x(const FieldElement& y, uint8_t sign_x) {
        FieldElement y2 = field_sqr(y);
        FieldElement u = field_sub(y2, FieldElement::ONE);
        FieldElement v = field_add(field_mul(_D, y2), FieldElement::ONE);

        FieldElement v3 = field_mul(field_sqr(v), v);
        FieldElement v7 = field_mul(field_sqr(v3), v);
        FieldElement uv7 = field_mul(u, v7);

        auto pow_2_252_3 = [](FieldElement z) {
            auto sq_n = [](FieldElement x, int n) {
                for (int i = 0; i < n; ++i) {
                    x = field_sqr(x);
                }
                return x;
            };

            FieldElement t0 = field_sqr(z);
            FieldElement t1 = sq_n(t0, 2);
            t1 = field_mul(z, t1);
            t0 = field_mul(t0, t1);
            FieldElement t2 = field_sqr(t0);
            t1 = field_mul(t1, t2);
            t2 = sq_n(t1, 5);
            t1 = field_mul(t2, t1);
            t2 = sq_n(t1, 10);
            t2 = field_mul(t2, t1);
            FieldElement t3 = sq_n(t2, 20);
            t2 = field_mul(t3, t2);
            t2 = sq_n(t2, 10);
            t1 = field_mul(t2, t1);
            t2 = sq_n(t1, 50);
            t2 = field_mul(t2, t1);
            t3 = sq_n(t2, 100);
            t2 = field_mul(t3, t2);
            t2 = sq_n(t2, 50);
            t1 = field_mul(t2, t1);
            t1 = sq_n(t1, 2);

            return field_mul(t1, z);
        };

        FieldElement x = field_mul(field_mul(u, v3), pow_2_252_3(uv7));
        FieldElement check = field_mul(field_sqr(x), v);

        if (field_to_bytes(check) != field_to_bytes(u)) {
            static const FieldElement SQRT_M1 = []() {
                constexpr std::array<uint8_t, 32> sm1_bytes = {
                    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
                    0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2fa,
                    0xa7, 0xd7, 0xfb, 0x61, 0xd2, 0x47, 0xb2, 0xa3,
                    0xaa, 0x61, 0x41, 0x4f, 0x1a, 0xbf, 0x4d, 0x2b
                };
                return field_from_bytes(sm1_bytes);
            }();

            x = field_mul(x, SQRT_M1);
            check = field_mul(field_sqr(x), v);
            if (field_to_bytes(check) != field_to_bytes(u)) {
                return std::nullopt;
            }
        }

        auto x_bytes = field_to_bytes(x);
        if ((x_bytes[0] & 1) != sign_x) {
            x = field_sub(FieldElement::ZERO, x);
        }

        return x;
    }

    std::optional<Point> point_from_bytes(std::span<const uint8_t, 32> bytes) {
        uint8_t sign_x = (bytes[31] >> 7) & 1;
        FieldElement y = field_from_bytes(bytes);

        auto x_opt = recover_x(y, sign_x);
        if (!x_opt) {
            return std::nullopt;
        }

        FieldElement X = *x_opt;
        FieldElement Y = y;
        FieldElement Z = FieldElement::ONE;
        FieldElement T = field_mul(X, Y);

        return Point{X, Y, Z, T};
    }

    std::array<uint8_t, 32> point_to_bytes(const Point& P) {
        FieldElement inv_Z = field_inv(P.Z);
        FieldElement x = field_mul(P.X, inv_Z);
        FieldElement y = field_mul(P.Y, inv_Z);

        auto out = field_to_bytes(y);
        auto x_bytes = field_to_bytes(x);
        out[31] |= ((x_bytes[0] & 1) << 7);
        return out;
    }


    
}