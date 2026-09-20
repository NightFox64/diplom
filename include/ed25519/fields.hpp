#pragma once

#include <span>
#include <array>
#include <cstdint>

namespace ed25519 {

    inline uint64_t sanity_check() {
        return 69;
    }

    struct FieldElement {
        uint64_t limbs[5]{0, 0, 0, 0, 0};

        static const FieldElement ZERO;
        static const FieldElement ONE;

        bool operator==(const FieldElement& other) const = default;
    };

    FieldElement field_from_bytes(std::span<const uint8_t, 32> bytes);
    std::array<uint8_t, 32> field_to_bytes(const FieldElement& fe);


    FieldElement field_add(const FieldElement& a, const FieldElement& b);
    FieldElement field_sub(const FieldElement& a, const FieldElement& b);
    FieldElement field_carry_and_reduce(const FieldElement& fe);



}