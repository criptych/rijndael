#include "rijndael.h"
#include "catch.hpp"

extern "C" int rijndael_self_test(void);

TEST_CASE("self-test", "[self]") {
    CHECK(rijndael_self_test() == 0);
}

