#include "ed25519/fields.hpp"
#include <cstring>

using uint128_t = unsigned __int128;

namespace ed25519 {

    const FieldElement FieldElement::ZERO{0, 0, 0, 0, 0};
    const FieldElement FieldElement::ONE{1, 0, 0, 0, 0};

    constexpr uint64_t MASK_51BIT = (1ULL << 51) - 1;

    FieldElement field_from_bytes(std::span<const uint8_t, 32> bytes) {
    
        uint64_t w[4] = {0, 0, 0, 0};
        std::memcpy(w, bytes.data(), 32);

        //RFC 8032 требует игнорировать 255-й бит при десериализации
        w[3] &= 0x7FFFFFFFFFFFFFFFULL;

        FieldElement res;

        res.limbs[0] = w[0] & MASK_51BIT;
        res.limbs[1] = ((w[0] >> 51) | (w[1] << 13)) & MASK_51BIT;
        res.limbs[2] = ((w[1] >> 38) | (w[2] << 26)) & MASK_51BIT;
        res.limbs[3] = ((w[2] >> 25) | (w[3] << 39)) & MASK_51BIT;
        res.limbs[4] = ((w[3] >> 12)) & MASK_51BIT;

        return res;
    }

    std::array<uint8_t, 32> field_to_bytes(const FieldElement& fe) {

        FieldElement t = field_carry_and_reduce(fe);

        FieldElement cand = t;
        cand.limbs[0] += 19;
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            carry = cand.limbs[i] >> 51;
            cand.limbs[i] &= MASK_51BIT;
            cand.limbs[i + 1] += carry; 
        }
        carry = cand.limbs[4] >> 51;
        cand.limbs[4] &= MASK_51BIT;

        if (carry) {
            t = cand;
        }

        uint64_t w[4];
        w[0] = t.limbs[0] | (t.limbs[1] << 51);
        w[1] = (t.limbs[1] >> 13) | (t.limbs[2] << 38);
        w[2] = (t.limbs[2] >> 26) | (t.limbs[3] << 25);
        w[3] = (t.limbs[3] >> 39) | (t.limbs[4] << 12);

        std::array<uint8_t, 32> out;
        std::memcpy(out.data(), w, 32);
        return out;
    }
    
    FieldElement field_carry_and_reduce(const FieldElement& fe) {
        FieldElement res = fe;

        for (int i = 0; i < 4; i++) {
            uint64_t carry = res.limbs[i] >> 51;
            res.limbs[i] &= MASK_51BIT;
            res.limbs[i + 1] += carry;
        }

        uint64_t carry = res.limbs[4] >> 51;
        res.limbs[4] &= MASK_51BIT;
        res.limbs[0] += carry * 19;

        for (int i = 0; i < 4; i++) {
            carry = res.limbs[i] >> 51;
            res.limbs[i] &= MASK_51BIT;
            res.limbs[i + 1] += carry;
        }

        carry = res.limbs[4] >> 51;
        res.limbs[4] &= MASK_51BIT;
        res.limbs[0] += carry * 19;

        carry = res.limbs[0] >> 51;
        res.limbs[0] &= MASK_51BIT;
        res.limbs[1] += carry;

        return res;
    }

    FieldElement field_add(const FieldElement& a, const FieldElement& b) {
        FieldElement res;

        for (int i = 0; i < 5; i++) {
            res.limbs[i] = a.limbs[i] + b.limbs[i];
        }

        return field_carry_and_reduce(res);
    }

    FieldElement field_sub(const FieldElement& a, const FieldElement& b) {
        FieldElement res;

        constexpr uint64_t BASE = 1ULL << 51;

        uint64_t borrow = 0;

        for (int i = 0; i < 5; ++i) {
            const uint64_t ai = a.limbs[i];
            const uint64_t bi = b.limbs[i];

            const uint64_t sub = bi + borrow;

            if (ai < sub) {
                res.limbs[i] = ai + BASE - sub;
                borrow = 1;
            } else {
                res.limbs[i] = ai - sub;
                borrow = 0;
            }
        }

        if (borrow) {
            // a < b.
            //
            // Текущее представление:
            // a - b + 2^255
            //
            // Нужно:
            // a - b + (2^255 - 19)
            //
            // Поэтому вычитаем 19.

            if (res.limbs[0] >= 19) {
                res.limbs[0] -= 19;
            } else {
                res.limbs[0] += BASE - 19;

                int i = 1;
                while (i < 5) {
                    if (res.limbs[i] != 0) {
                        --res.limbs[i];
                        break;
                    }

                    res.limbs[i] = MASK_51BIT;
                    ++i;
                }
            }
        }

        return field_carry_and_reduce(res);
    }

    FieldElement field_mul(const FieldElement& a, const FieldElement& b) {

        uint64_t b1_19 = b.limbs[1] * 19;
        uint64_t b2_19 = b.limbs[2] * 19;
        uint64_t b3_19 = b.limbs[3] * 19;
        uint64_t b4_19 = b.limbs[4] * 19;

        uint128_t c0 = (uint128_t)a.limbs[0] * b.limbs[0]
                        + (uint128_t)a.limbs[1] * b4_19
                        + (uint128_t)a.limbs[2] * b3_19
                        + (uint128_t)a.limbs[3] * b2_19
                        + (uint128_t)a.limbs[4] * b1_19;

        uint128_t c1 = (uint128_t)a.limbs[0] * b.limbs[1]
                        + (uint128_t)a.limbs[1] * b.limbs[0]
                        + (uint128_t)a.limbs[2] * b4_19
                        + (uint128_t)a.limbs[3] * b3_19
                        + (uint128_t)a.limbs[4] * b2_19;

        uint128_t c2 = (uint128_t)a.limbs[0] * b.limbs[2]
                        + (uint128_t)a.limbs[1] * b.limbs[1]
                        + (uint128_t)a.limbs[2] * b.limbs[0]
                        + (uint128_t)a.limbs[3] * b4_19
                        + (uint128_t)a.limbs[4] * b3_19;

        uint128_t c3 = (uint128_t)a.limbs[0] * b.limbs[3]
                        + (uint128_t)a.limbs[1] * b.limbs[2]
                        + (uint128_t)a.limbs[2] * b.limbs[1]
                        + (uint128_t)a.limbs[3] * b.limbs[0]
                        + (uint128_t)a.limbs[4] * b4_19;

        uint128_t c4 = (uint128_t)a.limbs[0] * b.limbs[4]
                        + (uint128_t)a.limbs[1] * b.limbs[3]
                        + (uint128_t)a.limbs[2] * b.limbs[2]
                        + (uint128_t)a.limbs[3] * b.limbs[1]
                        + (uint128_t)a.limbs[4] * b.limbs[0];

        FieldElement res;
        uint128_t carry = 0;

        res.limbs[0] = (uint64_t)c0 & MASK_51BIT;
        carry = c0 >> 51;
        c1 += carry;

        res.limbs[1] = (uint64_t)c1 & MASK_51BIT;
        carry = c1 >> 51;
        c2 += carry;

        res.limbs[2] = (uint64_t)c2 & MASK_51BIT;
        carry = c2 >> 51;
        c3 += carry;

        res.limbs[3] = (uint64_t)c3 & MASK_51BIT;
        carry = c3 >> 51;
        c4 += carry;

        res.limbs[4] = (uint64_t)c4 & MASK_51BIT;
        carry = c4 >> 51;
        
        res.limbs[0] += (uint64_t)carry * 19;
        carry = res.limbs[0] >> 51;
        res.limbs[0] &= MASK_51BIT;
        res.limbs[1] += (uint64_t)carry;

        return res;

    }

    FieldElement field_sqr(const FieldElement& a) {
        return field_mul(a, a);
    }

    FieldElement field_inv(const FieldElement& a) {
        auto sqr_n = [](FieldElement x, int n) {
            for (int i = 0; i < n; i++) {
                x = field_sqr(x);
            }
            return x;
        };

        FieldElement t0, t1, t2, t3;

        t0 = field_sqr(a);

        // a^4
        t1 = field_sqr(t0);

        // a^8
        t1 = field_sqr(t1);

        // a^9
        t1 = field_mul(a, t1);

        // a^11
        t0 = field_mul(t0, t1);

        // a^22
        t2 = field_sqr(t0);

        // a^31
        t1 = field_mul(t2, t1);

        // a^(2^10 - 1) = a^1023
        t2 = sqr_n(t1, 5);
        t1 = field_mul(t2, t1);

        // a^(2^20 - 1)
        t2 = sqr_n(t1, 10);
        t2 = field_mul(t2, t1);

        // a^(2^40 - 1)
        t3 = sqr_n(t2, 20);
        t2 = field_mul(t3, t2);

        // a^(2^50 - 1)
        t3 = sqr_n(t2, 10);
        t1 = field_mul(t3, t1);

        // a^(2^100 - 1)
        t3 = sqr_n(t1, 50);
        t2 = field_mul(t3, t1);

        // a^(2^200 - 1)
        t3 = sqr_n(t2, 100);
        t2 = field_mul(t3, t2);

        // a^(2^250 - 1)
        t3 = sqr_n(t2, 50);
        t1 = field_mul(t3, t1);

        // a^(2^255 - 21)
        t1 = sqr_n(t1, 5);

        return field_mul(t1, t0);
    }
}