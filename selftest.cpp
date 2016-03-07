#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

extern "C" void rijndael_init_tables(void);
extern "C" void rijndael_addroundkey(void *block, size_t block_size, const void *key);
extern "C" void rijndael_subbytes(void *block, size_t block_size);
extern "C" void rijndael_rsubbytes(void *block, size_t block_size);
extern "C" void rijndael_shiftrows(void *block, size_t block_size);
extern "C" void rijndael_rshiftrows(void *block, size_t block_size);
extern "C" void rijndael_mixcolumns(void *block, size_t block_size);
extern "C" void rijndael_rmixcolumns(void *block, size_t block_size);

// Sanity check for the functions above to make sure that they properly invert
// one another, i.e. F'(F(x)) == x
// TODO: Does NOT currently check that each individual function is correct.

TEST_CASE("self-test-128", "[self]") {
    static const uint32_t key[4] = { 0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef };
    static const uint32_t block[4] = { 0x11111111, 0x33333333, 0x77777777, 0xffffffff };
    uint32_t test[4];

    rijndael_init_tables();

    SECTION("AddRoundKey") {
        memcpy(test, block, sizeof test);
        rijndael_addroundkey(test, sizeof test/sizeof(uint32_t), key);
        rijndael_addroundkey(test, sizeof test/sizeof(uint32_t), key);

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("SubBytes") {
        memcpy(test, block, sizeof test);
        rijndael_subbytes(test, sizeof test/sizeof(uint32_t));
        rijndael_rsubbytes(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("MixColumns") {
        memcpy(test, block, sizeof test);
        rijndael_mixcolumns(test, sizeof test/sizeof(uint32_t));
        rijndael_rmixcolumns(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("ShiftRows") {
        memcpy(test, block, sizeof test);
        rijndael_shiftrows(test, sizeof test/sizeof(uint32_t));
        rijndael_rshiftrows(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }
}

TEST_CASE("self-test-192", "[self]") {
    static const uint32_t key[6] = { 0x01234567, 0x89abcdef, 0x02468ace, 0x13579bdf, 0x048c159d, 0x26ae37bf };
    static const uint32_t block[6] = { 0x11111111, 0x33333333, 0x55555555, 0x77777777, 0xaaaaaaaa, 0xffffffff };
    uint32_t test[6];

    rijndael_init_tables();

    SECTION("AddRoundKey") {
        memcpy(test, block, sizeof test);
        rijndael_addroundkey(test, sizeof test/sizeof(uint32_t), key);
        rijndael_addroundkey(test, sizeof test/sizeof(uint32_t), key);

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("SubBytes") {
        memcpy(test, block, sizeof test);
        rijndael_subbytes(test, sizeof test/sizeof(uint32_t));
        rijndael_rsubbytes(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("MixColumns") {
        memcpy(test, block, sizeof test);
        rijndael_mixcolumns(test, sizeof test/sizeof(uint32_t));
        rijndael_rmixcolumns(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("ShiftRows") {
        memcpy(test, block, sizeof test);
        rijndael_shiftrows(test, sizeof test/sizeof(uint32_t));
        rijndael_rshiftrows(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }
}

TEST_CASE("self-test-256", "[self]") {
    static const uint32_t key[8] = { 0x01010101, 0x30303030, 0x5a5a5a5a, 0xa5a5a5a5, 0x96969696, 0xfbfbfbfb, 0x03030303, 0x10101010 };
    static const uint32_t block[8] = { 0x11111111, 0x33333333, 0x55555555, 0x77777777, 0x99999999, 0xbbbbbbbb, 0xdddddddd, 0xffffffff };
    uint32_t test[8];

    rijndael_init_tables();

    SECTION("AddRoundKey") {
        memcpy(test, block, sizeof test);
        rijndael_addroundkey(test, sizeof test/sizeof(uint32_t), key);
        rijndael_addroundkey(test, sizeof test/sizeof(uint32_t), key);

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("SubBytes") {
        memcpy(test, block, sizeof test);
        rijndael_subbytes(test, sizeof test/sizeof(uint32_t));
        rijndael_rsubbytes(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("MixColumns") {
        memcpy(test, block, sizeof test);
        rijndael_mixcolumns(test, sizeof test/sizeof(uint32_t));
        rijndael_rmixcolumns(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }

    SECTION("ShiftRows") {
        memcpy(test, block, sizeof test);
        rijndael_shiftrows(test, sizeof test/sizeof(uint32_t));
        rijndael_rshiftrows(test, sizeof test/sizeof(uint32_t));

        for (size_t i = 0; i < sizeof test/sizeof(uint32_t); ++i) {
            CAPTURE(i);
            CHECK(test[i] == block[i]);
        }
    }
}

TEST_CASE("demo") {
    aes_state state;

    const uint8_t KEY[] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
    const uint8_t PLAINTEXT[] = { 0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34 };
    const uint8_t CIPHERTEXT[] = { 0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32 };

    uint8_t out[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init(&state, KEY, 128));
    REQUIRE(state.key_size == 4);
    REQUIRE(state.block_size == 4);
    REQUIRE(state.num_rounds == 10);

    // check that key was expanded properly
    CHECK(state.key[ 0] == 0x16157e2b);
    CHECK(state.key[ 1] == 0xa6d2ae28);
    CHECK(state.key[ 2] == 0x8815f7ab);
    CHECK(state.key[ 3] == 0x3c4fcf09);
    CHECK(state.key[ 4] == 0x17fefaa0);
    CHECK(state.key[ 5] == 0xb12c5488);
    CHECK(state.key[ 6] == 0x3939a323);
    CHECK(state.key[ 7] == 0x05766c2a);
    CHECK(state.key[ 8] == 0xf295c2f2);
    CHECK(state.key[ 9] == 0x43b9967a);
    CHECK(state.key[10] == 0x7a803559);
    CHECK(state.key[11] == 0x7ff65973);
    CHECK(state.key[12] == 0x7d47803d);
    CHECK(state.key[13] == 0x3efe1647);
    CHECK(state.key[14] == 0x447e231e);
    CHECK(state.key[15] == 0x3b887a6d);
    // ...
    CHECK(state.key[40] == 0xa8f914d0);
    CHECK(state.key[41] == 0x8925eec9);
    CHECK(state.key[42] == 0xc80c3fe1);
    CHECK(state.key[43] == 0xa60c63b6);

    CHECK(aes_encrypt(&state, PLAINTEXT, out, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CHECK(memcmp(CIPHERTEXT, out, sizeof(CIPHERTEXT)) == 0);
}

