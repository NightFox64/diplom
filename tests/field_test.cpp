#include <gtest/gtest.h>
#include "ed25519/fields.hpp"

TEST(SanityTest, BasicAssertion) {
    EXPECT_EQ(ed25519::sanity_check(), 69);
}