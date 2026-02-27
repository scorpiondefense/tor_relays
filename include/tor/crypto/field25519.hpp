#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace tor::crypto {

// GF(2^255-19) field element using 5x51-bit radix-2^51 limb representation.
// All operations are constant-time to prevent timing side-channels.
// Uses __int128 for 102-bit multiply intermediates.
class FieldElement {
public:
    static constexpr int LIMBS = 5;
    static constexpr uint64_t MASK51 = (1ULL << 51) - 1;

    // Default: zero
    FieldElement() : limbs_{} {}

    // From 5 limbs (reduced or unreduced)
    explicit FieldElement(uint64_t l0, uint64_t l1, uint64_t l2,
                          uint64_t l3, uint64_t l4)
        : limbs_{l0, l1, l2, l3, l4} {}

    // Deserialize from 32 little-endian bytes
    static FieldElement from_bytes(std::span<const uint8_t, 32> bytes);

    // Serialize to 32 little-endian bytes (fully reduces first)
    void to_bytes(std::span<uint8_t, 32> out) const;
    [[nodiscard]] std::array<uint8_t, 32> to_bytes() const;

    // Arithmetic (return new elements, no mutation)
    [[nodiscard]] FieldElement operator+(const FieldElement& rhs) const;
    [[nodiscard]] FieldElement operator-(const FieldElement& rhs) const;
    [[nodiscard]] FieldElement operator*(const FieldElement& rhs) const;
    [[nodiscard]] FieldElement operator-() const;

    FieldElement& operator+=(const FieldElement& rhs);
    FieldElement& operator-=(const FieldElement& rhs);
    FieldElement& operator*=(const FieldElement& rhs);

    [[nodiscard]] bool operator==(const FieldElement& rhs) const;
    [[nodiscard]] bool operator!=(const FieldElement& rhs) const { return !(*this == rhs); }

    // Square (slightly faster than mul)
    [[nodiscard]] FieldElement square() const;

    // Repeated squaring: square n times
    [[nodiscard]] FieldElement square_n(int n) const;

    // Modular inverse via Fermat's little theorem: a^(p-2) mod p
    [[nodiscard]] FieldElement invert() const;

    // Square root: returns {sqrt, exists} pair.
    // If exists==true, value is the square root. Otherwise value is zero.
    // Uses std::pair to avoid incomplete-type issue with nested struct.
    [[nodiscard]] std::pair<FieldElement, bool> sqrt() const;

    // Raise to power (p-5)/8 = 2^252-3
    [[nodiscard]] FieldElement pow_p58() const;

    // Is this element "negative"? (least significant bit of canonical form)
    [[nodiscard]] bool is_negative() const;

    // Is zero?
    [[nodiscard]] bool is_zero() const;

    // Conditional negate: negate if flag is true (constant-time)
    [[nodiscard]] FieldElement conditional_negate(bool negate) const;

    // Conditional select: return a if flag==0, b if flag==1 (constant-time)
    static FieldElement conditional_select(const FieldElement& a,
                                            const FieldElement& b,
                                            bool flag);

    // Conditional swap (constant-time)
    static void conditional_swap(FieldElement& a, FieldElement& b, bool flag);

    // Named constants
    static FieldElement zero();
    static FieldElement one();
    static FieldElement A();       // 486662 (Montgomery curve constant)
    static FieldElement sqrt_m1(); // sqrt(-1) mod p

    // Raw access (for Elligator2 implementation)
    [[nodiscard]] const uint64_t* data() const { return limbs_; }
    [[nodiscard]] uint64_t limb(int i) const { return limbs_[i]; }

private:
    uint64_t limbs_[LIMBS];

    // Internal: carry propagation (reduce limbs to 51-bit)
    void carry();

    // Internal: full reduction to canonical [0, p) range
    void reduce();
};

}  // namespace tor::crypto
