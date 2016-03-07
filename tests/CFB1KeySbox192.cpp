#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

static inline std::string buf2str(const uint8_t *buf, size_t len) {
    std::ostringstream ss; ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(buf[i]) << ' ';
    }
    return ss.str();
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-0", "[CFB1][KeySbox][192][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0xe9,0xf0,0x65,0xd7,0xc1,0x35,0x73,0x58,0x7f,0x78,0x75,0x35,0x7d,0xfb,0xb1,0x6c,0x53,0x48,0x9f,0x6a,0x4b,0xd0,0xf7,0xcd };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-1", "[CFB1][KeySbox][192][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x15,0xd2,0x0f,0x6e,0xbc,0x7e,0x64,0x9f,0xd9,0x5b,0x76,0xb1,0x07,0xe6,0xda,0xba,0x96,0x7c,0x8a,0x94,0x84,0x79,0x7f,0x29 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-2", "[CFB1][KeySbox][192][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0xa8,0xa2,0x82,0xee,0x31,0xc0,0x3f,0xae,0x4f,0x8e,0x9b,0x89,0x30,0xd5,0x47,0x3c,0x2e,0xd6,0x95,0xa3,0x47,0xe8,0x8b,0x7c };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-3", "[CFB1][KeySbox][192][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0xcd,0x62,0x37,0x6d,0x5e,0xbb,0x41,0x49,0x17,0xf0,0xc7,0x8f,0x05,0x26,0x64,0x33,0xdc,0x91,0x92,0xa1,0xec,0x94,0x33,0x00 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-4", "[CFB1][KeySbox][192][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x50,0x2a,0x6a,0xb3,0x69,0x84,0xaf,0x26,0x8b,0xf4,0x23,0xc7,0xf5,0x09,0x20,0x52,0x07,0xfc,0x15,0x52,0xaf,0x4a,0x91,0xe5 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-5", "[CFB1][KeySbox][192][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x25,0xa3,0x9d,0xbf,0xd8,0x03,0x4f,0x71,0xa8,0x1f,0x9c,0xeb,0x55,0x02,0x6e,0x40,0x37,0xf8,0xf6,0xaa,0x30,0xab,0x44,0xce };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-6", "[CFB1][KeySbox][192][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0xe0,0x8c,0x15,0x41,0x17,0x74,0xec,0x4a,0x90,0x8b,0x64,0xea,0xdc,0x6a,0xc4,0x19,0x9c,0x7c,0xd4,0x53,0xf3,0xaa,0xef,0x53 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-7", "[CFB1][KeySbox][192][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x3b,0x37,0x5a,0x1f,0xf7,0xe8,0xd4,0x44,0x09,0x69,0x6e,0x63,0x26,0xec,0x9d,0xec,0x86,0x13,0x8e,0x2a,0xe0,0x10,0xb9,0x80 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-8", "[CFB1][KeySbox][192][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0x95,0x0b,0xb9,0xf2,0x2c,0xc3,0x5b,0xe6,0xfe,0x79,0xf5,0x2c,0x32,0x0a,0xf9,0x3d,0xec,0x5b,0xc9,0xc0,0xc2,0xf9,0xcd,0x53 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-9", "[CFB1][KeySbox][192][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x70,0x01,0xc4,0x87,0xcc,0x3e,0x57,0x2c,0xfc,0x92,0xf4,0xd0,0xe6,0x97,0xd9,0x82,0xe8,0x85,0x6f,0xdc,0xc9,0x57,0xda,0x40 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-10", "[CFB1][KeySbox][192][ENCRYPT][n10]") {
    const uint8_t KEY[] = { 0xf0,0x29,0xce,0x61,0xd4,0xe5,0xa4,0x05,0xb4,0x1e,0xad,0x0a,0x88,0x3c,0xc6,0xa7,0x37,0xda,0x2c,0xf5,0x0a,0x6c,0x92,0xae };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-11", "[CFB1][KeySbox][192][ENCRYPT][n11]") {
    const uint8_t KEY[] = { 0x61,0x25,0x71,0x34,0xa5,0x18,0xa0,0xd5,0x7d,0x9d,0x24,0x4d,0x45,0xf6,0x49,0x8c,0xbc,0x32,0xf2,0xba,0xfc,0x52,0x2d,0x79 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-12", "[CFB1][KeySbox][192][ENCRYPT][n12]") {
    const uint8_t KEY[] = { 0xb0,0xab,0x0a,0x6a,0x81,0x8b,0xae,0xf2,0xd1,0x1f,0xa3,0x3e,0xac,0x94,0x72,0x84,0xfb,0x7d,0x74,0x8c,0xfb,0x75,0xe5,0x70 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-13", "[CFB1][KeySbox][192][ENCRYPT][n13]") {
    const uint8_t KEY[] = { 0xee,0x05,0x3a,0xa0,0x11,0xc8,0xb4,0x28,0xcd,0xcc,0x36,0x36,0x31,0x3c,0x54,0xd6,0xa0,0x3c,0xac,0x01,0xc7,0x15,0x79,0xd6 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-14", "[CFB1][KeySbox][192][ENCRYPT][n14]") {
    const uint8_t KEY[] = { 0xd2,0x92,0x65,0x27,0xe0,0xaa,0x9f,0x37,0xb4,0x5e,0x2e,0xc2,0xad,0xe5,0x85,0x3e,0xf8,0x07,0x57,0x61,0x04,0xc7,0xac,0xe3 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-15", "[CFB1][KeySbox][192][ENCRYPT][n15]") {
    const uint8_t KEY[] = { 0x98,0x22,0x15,0xf4,0xe1,0x73,0xdf,0xa0,0xfc,0xff,0xe5,0xd3,0xda,0x41,0xc4,0x81,0x2c,0x7b,0xcc,0x8e,0xd3,0x54,0x0f,0x93 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-16", "[CFB1][KeySbox][192][ENCRYPT][n16]") {
    const uint8_t KEY[] = { 0x98,0xc6,0xb8,0xe0,0x1e,0x37,0x9f,0xbd,0x14,0xe6,0x1a,0xf6,0xaf,0x89,0x15,0x96,0x58,0x35,0x65,0xf2,0xa2,0x7d,0x59,0xe9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-17", "[CFB1][KeySbox][192][ENCRYPT][n17]") {
    const uint8_t KEY[] = { 0xb3,0xad,0x5c,0xea,0x1d,0xdd,0xc2,0x14,0xca,0x96,0x9a,0xc3,0x5f,0x37,0xda,0xe1,0xa9,0xa9,0xd1,0x52,0x8f,0x89,0xbb,0x35 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-18", "[CFB1][KeySbox][192][ENCRYPT][n18]") {
    const uint8_t KEY[] = { 0x45,0x89,0x93,0x67,0xc3,0x13,0x28,0x49,0x76,0x30,0x73,0xc4,0x35,0xa9,0x28,0x8a,0x76,0x6c,0x8b,0x9e,0xc2,0x30,0x85,0x16 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-19", "[CFB1][KeySbox][192][ENCRYPT][n19]") {
    const uint8_t KEY[] = { 0xec,0x25,0x0e,0x04,0xc3,0x90,0x3f,0x60,0x26,0x47,0xb8,0x5a,0x40,0x1a,0x1a,0xe7,0xca,0x2f,0x02,0xf6,0x7f,0xa4,0x25,0x3e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-20", "[CFB1][KeySbox][192][ENCRYPT][n20]") {
    const uint8_t KEY[] = { 0xd0,0x77,0xa0,0x3b,0xd8,0xa3,0x89,0x73,0x92,0x8c,0xca,0xfe,0x4a,0x9d,0x2f,0x45,0x51,0x30,0xbd,0x0a,0xf5,0xae,0x46,0xa9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-21", "[CFB1][KeySbox][192][ENCRYPT][n21]") {
    const uint8_t KEY[] = { 0xd1,0x84,0xc3,0x6c,0xf0,0xdd,0xdf,0xec,0x39,0xe6,0x54,0x19,0x50,0x06,0x02,0x22,0x37,0x87,0x1a,0x47,0xc3,0x3d,0x31,0x98 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-22", "[CFB1][KeySbox][192][ENCRYPT][n22]") {
    const uint8_t KEY[] = { 0x4c,0x69,0x94,0xff,0xa9,0xdc,0xdc,0x80,0x5b,0x60,0xc2,0xc0,0x09,0x53,0x34,0xc4,0x2d,0x95,0xa8,0xfc,0x0c,0xa5,0xb0,0x80 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-ENCRYPT-23", "[CFB1][KeySbox][192][ENCRYPT][n23]") {
    const uint8_t KEY[] = { 0xc8,0x8f,0x5b,0x00,0xa4,0xef,0x9a,0x68,0x40,0xe2,0xac,0xaf,0x33,0xf0,0x0a,0x3b,0xdc,0x4e,0x25,0x89,0x53,0x03,0xfa,0x72 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-0", "[CFB1][KeySbox][192][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0xe9,0xf0,0x65,0xd7,0xc1,0x35,0x73,0x58,0x7f,0x78,0x75,0x35,0x7d,0xfb,0xb1,0x6c,0x53,0x48,0x9f,0x6a,0x4b,0xd0,0xf7,0xcd };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-1", "[CFB1][KeySbox][192][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x15,0xd2,0x0f,0x6e,0xbc,0x7e,0x64,0x9f,0xd9,0x5b,0x76,0xb1,0x07,0xe6,0xda,0xba,0x96,0x7c,0x8a,0x94,0x84,0x79,0x7f,0x29 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-2", "[CFB1][KeySbox][192][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0xa8,0xa2,0x82,0xee,0x31,0xc0,0x3f,0xae,0x4f,0x8e,0x9b,0x89,0x30,0xd5,0x47,0x3c,0x2e,0xd6,0x95,0xa3,0x47,0xe8,0x8b,0x7c };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-3", "[CFB1][KeySbox][192][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0xcd,0x62,0x37,0x6d,0x5e,0xbb,0x41,0x49,0x17,0xf0,0xc7,0x8f,0x05,0x26,0x64,0x33,0xdc,0x91,0x92,0xa1,0xec,0x94,0x33,0x00 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-4", "[CFB1][KeySbox][192][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x50,0x2a,0x6a,0xb3,0x69,0x84,0xaf,0x26,0x8b,0xf4,0x23,0xc7,0xf5,0x09,0x20,0x52,0x07,0xfc,0x15,0x52,0xaf,0x4a,0x91,0xe5 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-5", "[CFB1][KeySbox][192][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0x25,0xa3,0x9d,0xbf,0xd8,0x03,0x4f,0x71,0xa8,0x1f,0x9c,0xeb,0x55,0x02,0x6e,0x40,0x37,0xf8,0xf6,0xaa,0x30,0xab,0x44,0xce };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-6", "[CFB1][KeySbox][192][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0xe0,0x8c,0x15,0x41,0x17,0x74,0xec,0x4a,0x90,0x8b,0x64,0xea,0xdc,0x6a,0xc4,0x19,0x9c,0x7c,0xd4,0x53,0xf3,0xaa,0xef,0x53 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-7", "[CFB1][KeySbox][192][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x3b,0x37,0x5a,0x1f,0xf7,0xe8,0xd4,0x44,0x09,0x69,0x6e,0x63,0x26,0xec,0x9d,0xec,0x86,0x13,0x8e,0x2a,0xe0,0x10,0xb9,0x80 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-8", "[CFB1][KeySbox][192][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0x95,0x0b,0xb9,0xf2,0x2c,0xc3,0x5b,0xe6,0xfe,0x79,0xf5,0x2c,0x32,0x0a,0xf9,0x3d,0xec,0x5b,0xc9,0xc0,0xc2,0xf9,0xcd,0x53 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-9", "[CFB1][KeySbox][192][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0x70,0x01,0xc4,0x87,0xcc,0x3e,0x57,0x2c,0xfc,0x92,0xf4,0xd0,0xe6,0x97,0xd9,0x82,0xe8,0x85,0x6f,0xdc,0xc9,0x57,0xda,0x40 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-10", "[CFB1][KeySbox][192][DECRYPT][n10]") {
    const uint8_t KEY[] = { 0xf0,0x29,0xce,0x61,0xd4,0xe5,0xa4,0x05,0xb4,0x1e,0xad,0x0a,0x88,0x3c,0xc6,0xa7,0x37,0xda,0x2c,0xf5,0x0a,0x6c,0x92,0xae };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-11", "[CFB1][KeySbox][192][DECRYPT][n11]") {
    const uint8_t KEY[] = { 0x61,0x25,0x71,0x34,0xa5,0x18,0xa0,0xd5,0x7d,0x9d,0x24,0x4d,0x45,0xf6,0x49,0x8c,0xbc,0x32,0xf2,0xba,0xfc,0x52,0x2d,0x79 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-12", "[CFB1][KeySbox][192][DECRYPT][n12]") {
    const uint8_t KEY[] = { 0xb0,0xab,0x0a,0x6a,0x81,0x8b,0xae,0xf2,0xd1,0x1f,0xa3,0x3e,0xac,0x94,0x72,0x84,0xfb,0x7d,0x74,0x8c,0xfb,0x75,0xe5,0x70 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-13", "[CFB1][KeySbox][192][DECRYPT][n13]") {
    const uint8_t KEY[] = { 0xee,0x05,0x3a,0xa0,0x11,0xc8,0xb4,0x28,0xcd,0xcc,0x36,0x36,0x31,0x3c,0x54,0xd6,0xa0,0x3c,0xac,0x01,0xc7,0x15,0x79,0xd6 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-14", "[CFB1][KeySbox][192][DECRYPT][n14]") {
    const uint8_t KEY[] = { 0xd2,0x92,0x65,0x27,0xe0,0xaa,0x9f,0x37,0xb4,0x5e,0x2e,0xc2,0xad,0xe5,0x85,0x3e,0xf8,0x07,0x57,0x61,0x04,0xc7,0xac,0xe3 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-15", "[CFB1][KeySbox][192][DECRYPT][n15]") {
    const uint8_t KEY[] = { 0x98,0x22,0x15,0xf4,0xe1,0x73,0xdf,0xa0,0xfc,0xff,0xe5,0xd3,0xda,0x41,0xc4,0x81,0x2c,0x7b,0xcc,0x8e,0xd3,0x54,0x0f,0x93 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-16", "[CFB1][KeySbox][192][DECRYPT][n16]") {
    const uint8_t KEY[] = { 0x98,0xc6,0xb8,0xe0,0x1e,0x37,0x9f,0xbd,0x14,0xe6,0x1a,0xf6,0xaf,0x89,0x15,0x96,0x58,0x35,0x65,0xf2,0xa2,0x7d,0x59,0xe9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-17", "[CFB1][KeySbox][192][DECRYPT][n17]") {
    const uint8_t KEY[] = { 0xb3,0xad,0x5c,0xea,0x1d,0xdd,0xc2,0x14,0xca,0x96,0x9a,0xc3,0x5f,0x37,0xda,0xe1,0xa9,0xa9,0xd1,0x52,0x8f,0x89,0xbb,0x35 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-18", "[CFB1][KeySbox][192][DECRYPT][n18]") {
    const uint8_t KEY[] = { 0x45,0x89,0x93,0x67,0xc3,0x13,0x28,0x49,0x76,0x30,0x73,0xc4,0x35,0xa9,0x28,0x8a,0x76,0x6c,0x8b,0x9e,0xc2,0x30,0x85,0x16 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-19", "[CFB1][KeySbox][192][DECRYPT][n19]") {
    const uint8_t KEY[] = { 0xec,0x25,0x0e,0x04,0xc3,0x90,0x3f,0x60,0x26,0x47,0xb8,0x5a,0x40,0x1a,0x1a,0xe7,0xca,0x2f,0x02,0xf6,0x7f,0xa4,0x25,0x3e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-20", "[CFB1][KeySbox][192][DECRYPT][n20]") {
    const uint8_t KEY[] = { 0xd0,0x77,0xa0,0x3b,0xd8,0xa3,0x89,0x73,0x92,0x8c,0xca,0xfe,0x4a,0x9d,0x2f,0x45,0x51,0x30,0xbd,0x0a,0xf5,0xae,0x46,0xa9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-21", "[CFB1][KeySbox][192][DECRYPT][n21]") {
    const uint8_t KEY[] = { 0xd1,0x84,0xc3,0x6c,0xf0,0xdd,0xdf,0xec,0x39,0xe6,0x54,0x19,0x50,0x06,0x02,0x22,0x37,0x87,0x1a,0x47,0xc3,0x3d,0x31,0x98 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-22", "[CFB1][KeySbox][192][DECRYPT][n22]") {
    const uint8_t KEY[] = { 0x4c,0x69,0x94,0xff,0xa9,0xdc,0xdc,0x80,0x5b,0x60,0xc2,0xc0,0x09,0x53,0x34,0xc4,0x2d,0x95,0xa8,0xfc,0x0c,0xa5,0xb0,0x80 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1KeySbox192-DECRYPT-23", "[CFB1][KeySbox][192][DECRYPT][n23]") {
    const uint8_t KEY[] = { 0xc8,0x8f,0x5b,0x00,0xa4,0xef,0x9a,0x68,0x40,0xe2,0xac,0xaf,0x33,0xf0,0x0a,0x3b,0xdc,0x4e,0x25,0x89,0x53,0x03,0xfa,0x72 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

