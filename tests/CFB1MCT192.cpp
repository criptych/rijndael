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

TEST_CASE("CFB1MCT192-ENCRYPT-0", "[CFB1][MCT][192][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0xbf,0x9f,0xd5,0xe8,0xfe,0x7b,0xb5,0x29,0xd7,0x60,0xfa,0xb9,0x4b,0xd5,0x62,0x6c,0xaf,0x72,0x75,0xbb,0x68,0x93,0x68,0x17 };
    const uint8_t IV[] = { 0x6a,0x70,0x7c,0xef,0x04,0xeb,0x73,0x16,0xaf,0xcc,0x6d,0x93,0x34,0x85,0xa2,0x10 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-1", "[CFB1][MCT][192][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x35,0xb4,0x60,0xe4,0x9c,0x45,0xb7,0x7d,0x29,0xde,0x17,0x3a,0xaf,0x04,0x61,0xe3,0x0b,0x52,0x20,0x48,0xe4,0xa0,0xf3,0x53 };
    const uint8_t IV[] = { 0xfe,0xbe,0xed,0x83,0xe4,0xd1,0x03,0x8f,0xa4,0x20,0x55,0xf3,0x8c,0x33,0x9b,0x44 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-2", "[CFB1][MCT][192][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x54,0x66,0x80,0xd7,0x0f,0x06,0x76,0xa4,0x6b,0x03,0x64,0xbf,0xac,0x64,0x7f,0x5d,0x2b,0xc3,0x96,0xb7,0x93,0x93,0xb6,0xf5 };
    const uint8_t IV[] = { 0x42,0xdd,0x73,0x85,0x03,0x60,0x1e,0xbe,0x20,0x91,0xb6,0xff,0x77,0x33,0x45,0xa6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-3", "[CFB1][MCT][192][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0xbb,0x63,0x69,0x49,0x86,0x39,0x9e,0x11,0x00,0xd4,0xe1,0xa2,0x33,0xf9,0x02,0xaf,0x8b,0x27,0x74,0x21,0x75,0xa7,0x0c,0x23 };
    const uint8_t IV[] = { 0x6b,0xd7,0x85,0x1d,0x9f,0x9d,0x7d,0xf2,0xa0,0xe4,0xe2,0x96,0xe6,0x34,0xba,0xd6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-4", "[CFB1][MCT][192][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0xa3,0x60,0x19,0xed,0xd1,0x1f,0x11,0x59,0xa0,0xaf,0x67,0xda,0x08,0x5a,0x77,0x18,0xc1,0x67,0x4b,0xe9,0x91,0xa5,0x61,0x1f };
    const uint8_t IV[] = { 0xa0,0x7b,0x86,0x78,0x3b,0xa3,0x75,0xb7,0x4a,0x40,0x3f,0xc8,0xe4,0x02,0x6d,0x3c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-5", "[CFB1][MCT][192][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0xb4,0xdc,0xcc,0x14,0x4d,0xee,0xd1,0xfd,0xac,0xc3,0x51,0xf3,0x65,0xfc,0x28,0x31,0xa9,0xd8,0x88,0x35,0x79,0x50,0xf4,0xf7 };
    const uint8_t IV[] = { 0x0c,0x6c,0x36,0x29,0x6d,0xa6,0x5f,0x29,0x68,0xbf,0xc3,0xdc,0xe8,0xf5,0x95,0xe8 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-6", "[CFB1][MCT][192][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0xb2,0x3a,0x14,0xe7,0x18,0xc3,0x4e,0xbd,0x6b,0x1c,0x31,0xee,0xfb,0xb5,0xbb,0xcc,0x43,0x51,0xe1,0x7c,0x20,0x03,0xaf,0xb9 };
    const uint8_t IV[] = { 0xc7,0xdf,0x60,0x1d,0x9e,0x49,0x93,0xfd,0xea,0x89,0x69,0x49,0x59,0x53,0x5b,0x4e };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-7", "[CFB1][MCT][192][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x14,0x9e,0x72,0x83,0xd8,0xf8,0x0d,0x38,0xf1,0x62,0x11,0xf4,0x7b,0x92,0xf1,0x87,0x8c,0x13,0x7d,0x06,0xa0,0xc0,0x95,0xce };
    const uint8_t IV[] = { 0x9a,0x7e,0x20,0x1a,0x80,0x27,0x4a,0x4b,0xcf,0x42,0x9c,0x7a,0x80,0xc3,0x3a,0x77 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-8", "[CFB1][MCT][192][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0xba,0xd2,0x83,0x50,0xf3,0xf5,0x0c,0x52,0x5e,0xb7,0x4d,0x0e,0x52,0xba,0xa2,0xf3,0xc1,0x38,0xcd,0x72,0xa2,0x90,0x0f,0x54 };
    const uint8_t IV[] = { 0xaf,0xd5,0x5c,0xfa,0x29,0x28,0x53,0x74,0x4d,0x2b,0xb0,0x74,0x02,0x50,0x9a,0x9a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-9", "[CFB1][MCT][192][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0xf8,0xd7,0x7a,0xf2,0x74,0xe5,0x2c,0xe7,0x57,0x61,0xd2,0x68,0x85,0xf2,0x15,0x1c,0x8e,0x67,0x4b,0x79,0x95,0xf3,0x3f,0xce };
    const uint8_t IV[] = { 0x09,0xd6,0x9f,0x66,0xd7,0x48,0xb7,0xef,0x4f,0x5f,0x86,0x0b,0x37,0x63,0x30,0x9a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-10", "[CFB1][MCT][192][ENCRYPT][n10]") {
    const uint8_t KEY[] = { 0x86,0xc6,0x83,0x96,0x0b,0x78,0xda,0x11,0x9e,0x23,0x0b,0xd5,0xec,0x34,0x76,0x62,0x56,0x38,0x61,0x4f,0x97,0xe8,0x3c,0xa5 };
    const uint8_t IV[] = { 0xc9,0x42,0xd9,0xbd,0x69,0xc6,0x63,0x7e,0xd8,0x5f,0x2a,0x36,0x02,0x1b,0x03,0x6b };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-11", "[CFB1][MCT][192][ENCRYPT][n11]") {
    const uint8_t KEY[] = { 0xdb,0x5c,0x63,0x8e,0x30,0x32,0x3a,0x23,0x6a,0xe2,0x35,0x1a,0xad,0x2d,0x79,0x6c,0xda,0xa3,0x84,0x2f,0x08,0x52,0x34,0x7e };
    const uint8_t IV[] = { 0xf4,0xc1,0x3e,0xcf,0x41,0x19,0x0f,0x0e,0x8c,0x9b,0xe5,0x60,0x9f,0xba,0x08,0xdb };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-12", "[CFB1][MCT][192][ENCRYPT][n12]") {
    const uint8_t KEY[] = { 0xb2,0xee,0x2b,0x34,0x37,0xb0,0xf6,0x4d,0x48,0xc4,0x0d,0xbb,0x72,0xeb,0xaa,0x94,0xe0,0x1d,0x0a,0x5e,0x91,0xaa,0x26,0x86 };
    const uint8_t IV[] = { 0x22,0x26,0x38,0xa1,0xdf,0xc6,0xd3,0xf8,0x3a,0xbe,0x8e,0x71,0x99,0xf8,0x12,0xf8 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-13", "[CFB1][MCT][192][ENCRYPT][n13]") {
    const uint8_t KEY[] = { 0x85,0xf7,0x6b,0x9b,0x6a,0xe9,0xf3,0x3b,0xe9,0xd5,0x46,0x10,0xa8,0x36,0xdb,0xff,0xa4,0x1a,0x1b,0xbe,0x1c,0x77,0xcf,0x57 };
    const uint8_t IV[] = { 0xa1,0x11,0x4b,0xab,0xda,0xdd,0x71,0x6b,0x44,0x07,0x11,0xe0,0x8d,0xdd,0xe9,0xd1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-14", "[CFB1][MCT][192][ENCRYPT][n14]") {
    const uint8_t KEY[] = { 0x7a,0x0c,0xe4,0xff,0x7e,0xa0,0xd4,0x48,0x97,0x46,0x50,0xa0,0x00,0xf6,0x05,0x00,0xf9,0xce,0xd5,0xf3,0x6c,0x22,0x34,0x3b };
    const uint8_t IV[] = { 0x7e,0x93,0x16,0xb0,0xa8,0xc0,0xde,0xff,0x5d,0xd4,0xce,0x4d,0x70,0x55,0xfb,0x6c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-15", "[CFB1][MCT][192][ENCRYPT][n15]") {
    const uint8_t KEY[] = { 0xff,0x19,0xef,0x0d,0x0d,0xe3,0x61,0xd2,0x9e,0xc9,0x18,0x34,0x29,0xc2,0x6e,0x4e,0xa1,0x9c,0xbe,0xad,0x68,0xb8,0xc7,0x77 };
    const uint8_t IV[] = { 0x09,0x8f,0x48,0x94,0x29,0x34,0x6b,0x4e,0x58,0x52,0x6b,0x5e,0x04,0x9a,0xf3,0x4c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-16", "[CFB1][MCT][192][ENCRYPT][n16]") {
    const uint8_t KEY[] = { 0xcd,0xb4,0xe1,0x6c,0xd6,0x97,0x4e,0x37,0x24,0x53,0x6c,0xd6,0xa3,0x7d,0x03,0x18,0x10,0x10,0xcd,0x59,0x85,0xac,0xfd,0x04 };
    const uint8_t IV[] = { 0xba,0x9a,0x74,0xe2,0x8a,0xbf,0x6d,0x56,0xb1,0x8c,0x73,0xf4,0xed,0x14,0x3a,0x73 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-17", "[CFB1][MCT][192][ENCRYPT][n17]") {
    const uint8_t KEY[] = { 0x22,0xf1,0xab,0x85,0x32,0x10,0x85,0x9e,0x6c,0x19,0x8c,0xf0,0x28,0x59,0xc5,0x10,0x15,0xa4,0x20,0x5c,0xde,0x80,0xe8,0xaa };
    const uint8_t IV[] = { 0x48,0x4a,0xe0,0x26,0x8b,0x24,0xc6,0x08,0x05,0xb4,0xed,0x05,0x5b,0x2c,0x15,0xae };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-18", "[CFB1][MCT][192][ENCRYPT][n18]") {
    const uint8_t KEY[] = { 0xc5,0xab,0xf2,0xb3,0x3f,0xdd,0xc4,0x14,0xd1,0x23,0xc1,0x80,0xcb,0xe6,0x30,0x6d,0xd2,0x93,0x3e,0xf6,0xd9,0xe3,0x2f,0x90 };
    const uint8_t IV[] = { 0xbd,0x3a,0x4d,0x70,0xe3,0xbf,0xf5,0x7d,0xc7,0x37,0x1e,0xaa,0x07,0x63,0xc7,0x3a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-19", "[CFB1][MCT][192][ENCRYPT][n19]") {
    const uint8_t KEY[] = { 0x30,0x2f,0x16,0xef,0x43,0xaf,0xc4,0xbe,0xa9,0xef,0x44,0xa4,0x5b,0x06,0xfc,0xf2,0x44,0xdd,0x4d,0xdb,0xbe,0x2a,0x8c,0x92 };
    const uint8_t IV[] = { 0x78,0xcc,0x85,0x24,0x90,0xe0,0xcc,0x9f,0x96,0x4e,0x73,0x2d,0x67,0xc9,0xa3,0x02 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-20", "[CFB1][MCT][192][ENCRYPT][n20]") {
    const uint8_t KEY[] = { 0x7b,0xe4,0xc5,0xab,0x0c,0x3d,0x05,0xea,0xf1,0xde,0x1e,0x3c,0x22,0xc9,0x45,0x7d,0x3d,0xb6,0x3c,0x53,0x38,0x98,0x1d,0x7a };
    const uint8_t IV[] = { 0x58,0x31,0x5a,0x98,0x79,0xcf,0xb9,0x8f,0x79,0x6b,0x71,0x88,0x86,0xb2,0x91,0xe8 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-21", "[CFB1][MCT][192][ENCRYPT][n21]") {
    const uint8_t KEY[] = { 0xd7,0xc7,0x16,0x68,0x57,0x38,0xb3,0x83,0x83,0xb0,0xc7,0xdc,0xd2,0x70,0xef,0x55,0xa4,0xbb,0x01,0x18,0x9a,0xc2,0xb6,0xc7 };
    const uint8_t IV[] = { 0x72,0x6e,0xd9,0xe0,0xf0,0xb9,0xaa,0x28,0x99,0x0d,0x3d,0x4b,0xa2,0x5a,0xab,0xbd };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-22", "[CFB1][MCT][192][ENCRYPT][n22]") {
    const uint8_t KEY[] = { 0xd4,0x0e,0x30,0xf7,0x97,0x30,0x2d,0x70,0x3c,0xbd,0x37,0x7b,0xd7,0x2c,0x1a,0x89,0x59,0x34,0x84,0x5e,0xbd,0x7d,0x5c,0xfd };
    const uint8_t IV[] = { 0xbf,0x0d,0xf0,0xa7,0x05,0x5c,0xf5,0xdc,0xfd,0x8f,0x85,0x46,0x27,0xbf,0xea,0x3a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-23", "[CFB1][MCT][192][ENCRYPT][n23]") {
    const uint8_t KEY[] = { 0x38,0x8f,0x30,0x23,0x02,0xce,0x53,0x41,0xaa,0xba,0x0b,0xa4,0x37,0xf1,0x91,0x31,0xfa,0x7f,0x09,0x2a,0x0e,0xc3,0x43,0x6e };
    const uint8_t IV[] = { 0x96,0x07,0x3c,0xdf,0xe0,0xdd,0x8b,0xb8,0xa3,0x4b,0x8d,0x74,0xb3,0xbe,0x1f,0x93 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-24", "[CFB1][MCT][192][ENCRYPT][n24]") {
    const uint8_t KEY[] = { 0x3e,0xa7,0xbb,0xa3,0x91,0x85,0x81,0xfd,0x92,0xe4,0x4f,0x73,0xd6,0x4a,0x4a,0x63,0x85,0x3f,0x6c,0x0c,0xa6,0x4e,0xd2,0x22 };
    const uint8_t IV[] = { 0x38,0x5e,0x44,0xd7,0xe1,0xbb,0xdb,0x52,0x7f,0x40,0x65,0x26,0xa8,0x8d,0x91,0x4c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-25", "[CFB1][MCT][192][ENCRYPT][n25]") {
    const uint8_t KEY[] = { 0x0a,0x19,0x27,0x1e,0xf6,0x05,0xa3,0x25,0xe9,0xf0,0x45,0xe6,0x60,0xa2,0x68,0x9d,0x99,0x4c,0xcd,0x15,0xb5,0xfa,0xd2,0x70 };
    const uint8_t IV[] = { 0x7b,0x14,0x0a,0x95,0xb6,0xe8,0x22,0xfe,0x1c,0x73,0xa1,0x19,0x13,0xb4,0x00,0x52 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-26", "[CFB1][MCT][192][ENCRYPT][n26]") {
    const uint8_t KEY[] = { 0x05,0xb5,0x28,0x07,0x13,0x78,0xa4,0x55,0xa6,0x9a,0x9e,0x92,0x33,0xcf,0xb4,0x7d,0xe1,0x76,0x13,0x2e,0xf4,0xd1,0x6e,0x84 };
    const uint8_t IV[] = { 0x4f,0x6a,0xdb,0x74,0x53,0x6d,0xdc,0xe0,0x78,0x3a,0xde,0x3b,0x41,0x2b,0xbc,0xf4 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-27", "[CFB1][MCT][192][ENCRYPT][n27]") {
    const uint8_t KEY[] = { 0x5e,0xe6,0xed,0xb4,0xb3,0x38,0xfc,0xb6,0x90,0xfe,0x65,0x33,0x5a,0x07,0xc0,0x68,0x07,0x68,0x20,0xb5,0xfe,0x9a,0x53,0x2b };
    const uint8_t IV[] = { 0x36,0x64,0xfb,0xa1,0x69,0xc8,0x74,0x15,0xe6,0x1e,0x33,0x9b,0x0a,0x4b,0x3d,0xaf };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-28", "[CFB1][MCT][192][ENCRYPT][n28]") {
    const uint8_t KEY[] = { 0xa4,0xfb,0x60,0xc5,0x83,0x3b,0x2a,0x6e,0xd9,0x9f,0x88,0x2c,0x2b,0xcf,0x5e,0xab,0x42,0xa5,0x10,0x65,0x1b,0xd0,0x06,0x1c };
    const uint8_t IV[] = { 0x49,0x61,0xed,0x1f,0x71,0xc8,0x9e,0xc3,0x45,0xcd,0x30,0xd0,0xe5,0x4a,0x55,0x37 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-29", "[CFB1][MCT][192][ENCRYPT][n29]") {
    const uint8_t KEY[] = { 0xca,0x39,0x08,0x9c,0x3b,0x88,0x23,0xb6,0x67,0x42,0x13,0x6e,0xd4,0x61,0x2e,0x97,0x31,0xab,0x3d,0xaf,0xbd,0xa7,0x91,0x96 };
    const uint8_t IV[] = { 0xbe,0xdd,0x9b,0x42,0xff,0xae,0x70,0x3c,0x73,0x0e,0x2d,0xca,0xa6,0x77,0x97,0x8a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-30", "[CFB1][MCT][192][ENCRYPT][n30]") {
    const uint8_t KEY[] = { 0x25,0x16,0xad,0x83,0x76,0x0e,0xca,0x89,0x87,0x68,0x05,0x1c,0x75,0xc4,0x0d,0xf9,0x5e,0xac,0x6f,0x93,0x7d,0x7a,0x27,0xbe };
    const uint8_t IV[] = { 0xe0,0x2a,0x16,0x72,0xa1,0xa5,0x23,0x6e,0x6f,0x07,0x52,0x3c,0xc0,0xdd,0xb6,0x28 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-31", "[CFB1][MCT][192][ENCRYPT][n31]") {
    const uint8_t KEY[] = { 0x6a,0x61,0xfb,0xd9,0xce,0xdb,0x35,0x74,0x55,0x4c,0x30,0xb1,0xe6,0x2e,0x58,0x6b,0x26,0x04,0xcb,0xbb,0x3a,0x06,0x95,0x65 };
    const uint8_t IV[] = { 0xd2,0x24,0x35,0xad,0x93,0xea,0x55,0x92,0x78,0xa8,0xa4,0x28,0x47,0x7c,0xb2,0xdb };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-32", "[CFB1][MCT][192][ENCRYPT][n32]") {
    const uint8_t KEY[] = { 0x28,0xa8,0x6c,0x89,0xa4,0x36,0xe3,0x38,0x7b,0x4d,0xf5,0xab,0xb4,0x2a,0x8b,0x02,0x53,0x0e,0xc6,0x6f,0xfd,0xb0,0x29,0x20 };
    const uint8_t IV[] = { 0x2e,0x01,0xc5,0x1a,0x52,0x04,0xd3,0x69,0x75,0x0a,0x0d,0xd4,0xc7,0xb6,0xbc,0x45 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-33", "[CFB1][MCT][192][ENCRYPT][n33]") {
    const uint8_t KEY[] = { 0x0c,0x9f,0x0f,0x39,0x9a,0xf3,0xdd,0x56,0xd7,0x9e,0x68,0x6d,0xda,0x5b,0x6a,0x19,0xb8,0x1b,0x50,0xa1,0x44,0x31,0x97,0x25 };
    const uint8_t IV[] = { 0xac,0xd3,0x9d,0xc6,0x6e,0x71,0xe1,0x1b,0xeb,0x15,0x96,0xce,0xb9,0x81,0xbe,0x05 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-34", "[CFB1][MCT][192][ENCRYPT][n34]") {
    const uint8_t KEY[] = { 0x44,0xcd,0x50,0xc0,0x93,0x22,0x2f,0x02,0xa5,0xca,0x95,0xbd,0xa2,0xf4,0xd7,0x88,0x19,0x74,0xc7,0xab,0x9b,0xbf,0xa4,0x75 };
    const uint8_t IV[] = { 0x72,0x54,0xfd,0xd0,0x78,0xaf,0xbd,0x91,0xa1,0x6f,0x97,0x0a,0xdf,0x8e,0x33,0x50 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-35", "[CFB1][MCT][192][ENCRYPT][n35]") {
    const uint8_t KEY[] = { 0x9a,0x8e,0x21,0x1f,0x5d,0xd9,0x3a,0x6e,0xd9,0x8f,0x55,0xa9,0x8d,0xba,0x54,0x7f,0x28,0xdf,0x8b,0x8f,0x2e,0x78,0xd6,0xf5 };
    const uint8_t IV[] = { 0x7c,0x45,0xc0,0x14,0x2f,0x4e,0x83,0xf7,0x31,0xab,0x4c,0x24,0xb5,0xc7,0x72,0x80 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-36", "[CFB1][MCT][192][ENCRYPT][n36]") {
    const uint8_t KEY[] = { 0x25,0xc4,0xe3,0xd9,0x88,0x48,0x3c,0x9d,0xcb,0xbf,0x33,0x02,0x75,0x36,0x23,0x0c,0x32,0x1b,0x5c,0xc3,0x62,0xb2,0xcd,0x3f };
    const uint8_t IV[] = { 0x12,0x30,0x66,0xab,0xf8,0x8c,0x77,0x73,0x1a,0xc4,0xd7,0x4c,0x4c,0xca,0x1b,0xca };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-37", "[CFB1][MCT][192][ENCRYPT][n37]") {
    const uint8_t KEY[] = { 0xc3,0xb4,0x29,0x98,0xbb,0x62,0xef,0xf2,0x1a,0x92,0xdf,0x8e,0xdc,0xbd,0xba,0xdc,0x2b,0x29,0x4a,0xf7,0x91,0x78,0x23,0x6c };
    const uint8_t IV[] = { 0xd1,0x2d,0xec,0x8c,0xa9,0x8b,0x99,0xd0,0x19,0x32,0x16,0x34,0xf3,0xca,0xee,0x53 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-38", "[CFB1][MCT][192][ENCRYPT][n38]") {
    const uint8_t KEY[] = { 0x7a,0x39,0xa1,0xf3,0x72,0x94,0x03,0x7b,0xee,0xdc,0xf0,0x8c,0x06,0x50,0x9c,0xc9,0xe1,0xd1,0xe2,0x2a,0x9a,0xb0,0x5f,0x7f };
    const uint8_t IV[] = { 0xf4,0x4e,0x2f,0x02,0xda,0xed,0x26,0x15,0xca,0xf8,0xa8,0xdd,0x0b,0xc8,0x7c,0x13 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-39", "[CFB1][MCT][192][ENCRYPT][n39]") {
    const uint8_t KEY[] = { 0x2f,0xae,0x46,0x95,0xd7,0x93,0x95,0xac,0xe9,0x14,0xf7,0x70,0x1b,0xac,0xb9,0x44,0x00,0xf6,0x7b,0x53,0x82,0x87,0x24,0x3a };
    const uint8_t IV[] = { 0x07,0xc8,0x07,0xfc,0x1d,0xfc,0x25,0x8d,0xe1,0x27,0x99,0x79,0x18,0x37,0x7b,0x45 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-40", "[CFB1][MCT][192][ENCRYPT][n40]") {
    const uint8_t KEY[] = { 0x8d,0xa4,0x49,0x21,0xdd,0x5e,0x51,0xa8,0x7a,0x8e,0x5c,0x80,0x41,0x39,0xa5,0xc7,0xe1,0xb9,0x43,0xda,0x63,0x24,0xe0,0x8c };
    const uint8_t IV[] = { 0x93,0x9a,0xab,0xf0,0x5a,0x95,0x1c,0x83,0xe1,0x4f,0x38,0x89,0xe1,0xa3,0xc4,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-41", "[CFB1][MCT][192][ENCRYPT][n41]") {
    const uint8_t KEY[] = { 0x1a,0xbc,0x79,0x9e,0xaf,0xea,0x36,0xf5,0x21,0xd7,0xb0,0x69,0x46,0x0a,0xda,0xaf,0x9e,0xb7,0x3d,0x5e,0x87,0x5b,0x46,0x1d };
    const uint8_t IV[] = { 0x5b,0x59,0xec,0xe9,0x07,0x33,0x7f,0x68,0x7f,0x0e,0x7e,0x84,0xe4,0x7f,0xa6,0x91 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-42", "[CFB1][MCT][192][ENCRYPT][n42]") {
    const uint8_t KEY[] = { 0x28,0x7c,0xe7,0x99,0xb9,0xfb,0x07,0x2d,0xe7,0x76,0xcf,0xf4,0xc4,0x7e,0x7f,0xa0,0xb8,0x3d,0x68,0x22,0xf3,0x93,0x52,0xb6 };
    const uint8_t IV[] = { 0xc6,0xa1,0x7f,0x9d,0x82,0x74,0xa5,0x0f,0x26,0x8a,0x55,0x7c,0x74,0xc8,0x14,0xab };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-43", "[CFB1][MCT][192][ENCRYPT][n43]") {
    const uint8_t KEY[] = { 0xa9,0x84,0x65,0x39,0xdd,0xa5,0x85,0x3d,0x14,0xd4,0x3e,0x37,0x58,0x54,0x80,0xcb,0x47,0x51,0xf0,0x9a,0xb9,0x27,0xeb,0x78 };
    const uint8_t IV[] = { 0xf3,0xa2,0xf1,0xc3,0x9c,0x2a,0xff,0x6b,0xff,0x6c,0x98,0xb8,0x4a,0xb4,0xb9,0xce };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-44", "[CFB1][MCT][192][ENCRYPT][n44]") {
    const uint8_t KEY[] = { 0xab,0xbe,0x06,0xda,0x5e,0x27,0xc6,0x26,0xd3,0x78,0x8e,0x8f,0x5c,0xbf,0x3d,0x2e,0x80,0xf3,0x55,0xb4,0x96,0x18,0xab,0xfe };
    const uint8_t IV[] = { 0xc7,0xac,0xb0,0xb8,0x04,0xeb,0xbd,0xe5,0xc7,0xa2,0xa5,0x2e,0x2f,0x3f,0x40,0x86 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-45", "[CFB1][MCT][192][ENCRYPT][n45]") {
    const uint8_t KEY[] = { 0x1f,0xff,0x2d,0xe2,0x33,0xfc,0x75,0x78,0x3b,0x9e,0xb6,0x9f,0x28,0x2e,0x93,0x8c,0xb7,0xd8,0xe1,0xce,0xee,0xef,0xbc,0xc7 };
    const uint8_t IV[] = { 0xe8,0xe6,0x38,0x10,0x74,0x91,0xae,0xa2,0x37,0x2b,0xb4,0x7a,0x78,0xf7,0x17,0x39 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-46", "[CFB1][MCT][192][ENCRYPT][n46]") {
    const uint8_t KEY[] = { 0xc5,0x36,0xf6,0x35,0x41,0x0d,0x84,0x15,0x1f,0xbf,0x9c,0x4d,0x2a,0x64,0x83,0x21,0x8b,0x18,0xae,0xfd,0xf2,0x99,0xd2,0x5b };
    const uint8_t IV[] = { 0x24,0x21,0x2a,0xd2,0x02,0x4a,0x10,0xad,0x3c,0xc0,0x4f,0x33,0x1c,0x76,0x6e,0x9c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-47", "[CFB1][MCT][192][ENCRYPT][n47]") {
    const uint8_t KEY[] = { 0xf6,0x5b,0x15,0xa5,0xbd,0x19,0xf3,0x32,0xb5,0xbc,0x45,0x25,0x20,0xa2,0x69,0xbe,0x30,0x80,0xe7,0xd4,0x5f,0x3a,0x3b,0x4e };
    const uint8_t IV[] = { 0xaa,0x03,0xd9,0x68,0x0a,0xc6,0xea,0x9f,0xbb,0x98,0x49,0x29,0xad,0xa3,0xe9,0x15 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-48", "[CFB1][MCT][192][ENCRYPT][n48]") {
    const uint8_t KEY[] = { 0xf8,0x10,0x27,0xd3,0x65,0xda,0xfa,0x34,0xa1,0x6f,0xf2,0x78,0xc2,0x1a,0x5d,0x20,0xe2,0xda,0xfe,0x8d,0x0e,0x81,0xb8,0x99 };
    const uint8_t IV[] = { 0x14,0xd3,0xb7,0x5d,0xe2,0xb8,0x34,0x9e,0xd2,0x5a,0x19,0x59,0x51,0xbb,0x83,0xd7 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-49", "[CFB1][MCT][192][ENCRYPT][n49]") {
    const uint8_t KEY[] = { 0x8d,0xc7,0x60,0x2a,0xaa,0x32,0xd3,0x5a,0x88,0x3d,0x75,0xb8,0x7c,0x48,0xca,0x83,0xe1,0xea,0xfa,0xd1,0x42,0x9e,0xd1,0x70 };
    const uint8_t IV[] = { 0x29,0x52,0x87,0xc0,0xbe,0x52,0x97,0xa3,0x03,0x30,0x04,0x5c,0x4c,0x1f,0x69,0xe9 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-50", "[CFB1][MCT][192][ENCRYPT][n50]") {
    const uint8_t KEY[] = { 0xa5,0xb7,0x90,0x2e,0x14,0xa4,0xcc,0xf4,0xa3,0x3c,0x4a,0x7e,0x0a,0x8c,0xc3,0xfd,0x53,0x2d,0xfd,0x5a,0xf9,0x37,0xb9,0x42 };
    const uint8_t IV[] = { 0x2b,0x01,0x3f,0xc6,0x76,0xc4,0x09,0x7e,0xb2,0xc7,0x07,0x8b,0xbb,0xa9,0x68,0x32 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-51", "[CFB1][MCT][192][ENCRYPT][n51]") {
    const uint8_t KEY[] = { 0x01,0x93,0x00,0x23,0x86,0x07,0xdb,0x87,0xc4,0xcc,0x18,0x28,0xa8,0x1e,0x29,0x4d,0xbe,0xdf,0xa5,0x2e,0x9e,0x81,0xd6,0x58 };
    const uint8_t IV[] = { 0x67,0xf0,0x52,0x56,0xa2,0x92,0xea,0xb0,0xed,0xf2,0x58,0x74,0x67,0xb6,0x6f,0x1a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-52", "[CFB1][MCT][192][ENCRYPT][n52]") {
    const uint8_t KEY[] = { 0xf2,0x8e,0x9e,0xcd,0x81,0x54,0xac,0x34,0x51,0xc3,0xfc,0xd6,0x09,0xbd,0x55,0x0a,0xcd,0x11,0xe3,0x69,0x3a,0x64,0xfb,0xe1 };
    const uint8_t IV[] = { 0x95,0x0f,0xe4,0xfe,0xa1,0xa3,0x7c,0x47,0x73,0xce,0x46,0x47,0xa4,0xe5,0x2d,0xb9 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-53", "[CFB1][MCT][192][ENCRYPT][n53]") {
    const uint8_t KEY[] = { 0xf1,0x1c,0xea,0xe8,0x39,0x5e,0x21,0x5b,0x5c,0xae,0x22,0x1b,0x4f,0xe7,0x1c,0x31,0x75,0xf8,0x05,0x58,0x50,0x87,0xbb,0x04 };
    const uint8_t IV[] = { 0x0d,0x6d,0xde,0xcd,0x46,0x5a,0x49,0x3b,0xb8,0xe9,0xe6,0x31,0x6a,0xe3,0x40,0xe5 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-54", "[CFB1][MCT][192][ENCRYPT][n54]") {
    const uint8_t KEY[] = { 0x40,0xa8,0xda,0x7b,0xa4,0x75,0xcb,0x44,0x17,0x1e,0xa7,0x7d,0xce,0x11,0xfd,0x90,0x84,0x16,0x0c,0x4a,0x55,0xdb,0x5d,0x67 };
    const uint8_t IV[] = { 0x4b,0xb0,0x85,0x66,0x81,0xf6,0xe1,0xa1,0xf1,0xee,0x09,0x12,0x05,0x5c,0xe6,0x63 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-55", "[CFB1][MCT][192][ENCRYPT][n55]") {
    const uint8_t KEY[] = { 0xed,0x06,0x30,0x15,0x75,0xea,0xc9,0x20,0x2f,0xa1,0xb1,0x58,0xdc,0xd2,0xc0,0x96,0x93,0x0e,0x4c,0xa9,0x3a,0xd5,0x27,0xc3 };
    const uint8_t IV[] = { 0x38,0xbf,0x16,0x25,0x12,0xc3,0x3d,0x06,0x17,0x18,0x40,0xe3,0x6f,0x0e,0x7a,0xa4 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-56", "[CFB1][MCT][192][ENCRYPT][n56]") {
    const uint8_t KEY[] = { 0x00,0xc3,0x15,0x52,0xf2,0x3a,0x1e,0xb4,0xd5,0xaa,0xb4,0x4a,0x81,0x9d,0xa5,0xe9,0xe0,0x10,0x76,0xe4,0xc8,0xb4,0x7a,0x57 };
    const uint8_t IV[] = { 0xfa,0x0b,0x05,0x12,0x5d,0x4f,0x65,0x7f,0x73,0x1e,0x3a,0x4d,0xf2,0x61,0x5d,0x94 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-57", "[CFB1][MCT][192][ENCRYPT][n57]") {
    const uint8_t KEY[] = { 0x0b,0x27,0x0c,0xe3,0x7b,0x6d,0xe9,0xa4,0x13,0x95,0x59,0x9d,0x74,0x0e,0x43,0x7f,0xbf,0x26,0x9a,0xd5,0x56,0xbd,0x4b,0x34 };
    const uint8_t IV[] = { 0xc6,0x3f,0xed,0xd7,0xf5,0x93,0xe6,0x96,0x5f,0x36,0xec,0x31,0x9e,0x09,0x31,0x63 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-58", "[CFB1][MCT][192][ENCRYPT][n58]") {
    const uint8_t KEY[] = { 0xa4,0x2f,0xc7,0xe3,0x1e,0x6e,0xc7,0xd6,0xb7,0xcd,0x4b,0x05,0xd7,0xeb,0x57,0x22,0x70,0x80,0x59,0x4a,0xcc,0xed,0xc3,0x5e };
    const uint8_t IV[] = { 0xa4,0x58,0x12,0x98,0xa3,0xe5,0x14,0x5d,0xcf,0xa6,0xc3,0x9f,0x9a,0x50,0x88,0x6a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-59", "[CFB1][MCT][192][ENCRYPT][n59]") {
    const uint8_t KEY[] = { 0xf9,0x95,0x74,0x94,0x5f,0xfc,0x20,0xc1,0xe6,0x02,0x60,0xa8,0x64,0xce,0x17,0xe1,0xd5,0x61,0xfb,0xe7,0x0c,0x01,0x65,0x72 };
    const uint8_t IV[] = { 0x51,0xcf,0x2b,0xad,0xb3,0x25,0x40,0xc3,0xa5,0xe1,0xa2,0xad,0xc0,0xec,0xa6,0x2c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-60", "[CFB1][MCT][192][ENCRYPT][n60]") {
    const uint8_t KEY[] = { 0x16,0xc0,0xe6,0x71,0x51,0xec,0xfc,0x46,0xcc,0x3e,0x13,0xa1,0x18,0x09,0xc4,0xb2,0x74,0xd8,0x12,0x12,0xc7,0x57,0xf5,0xb4 };
    const uint8_t IV[] = { 0x2a,0x3c,0x73,0x09,0x7c,0xc7,0xd3,0x53,0xa1,0xb9,0xe9,0xf5,0xcb,0x56,0x90,0xc6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-61", "[CFB1][MCT][192][ENCRYPT][n61]") {
    const uint8_t KEY[] = { 0x69,0x3e,0x05,0x36,0x73,0xe4,0x84,0xb0,0x17,0x02,0xb3,0x40,0x32,0x74,0x9a,0xe0,0x3b,0x88,0x9f,0x21,0x94,0x69,0x28,0xf8 };
    const uint8_t IV[] = { 0xdb,0x3c,0xa0,0xe1,0x2a,0x7d,0x5e,0x52,0x4f,0x50,0x8d,0x33,0x53,0x3e,0xdd,0x4c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-62", "[CFB1][MCT][192][ENCRYPT][n62]") {
    const uint8_t KEY[] = { 0xb3,0xb9,0x7a,0xfe,0x2b,0x55,0x6a,0xf5,0xa7,0x80,0x9d,0x92,0x7a,0x2c,0x36,0xd1,0x77,0xf1,0x8c,0x65,0xe3,0x94,0xfc,0x89 };
    const uint8_t IV[] = { 0xb0,0x82,0x2e,0xd2,0x48,0x58,0xac,0x31,0x4c,0x79,0x13,0x44,0x77,0xfd,0xd4,0x71 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-63", "[CFB1][MCT][192][ENCRYPT][n63]") {
    const uint8_t KEY[] = { 0x00,0x0a,0x1c,0x05,0x46,0x1b,0x5b,0xa3,0xa5,0xb0,0x37,0x87,0x01,0x48,0x88,0x25,0x03,0x12,0x30,0x0a,0x1d,0x83,0xea,0x6f };
    const uint8_t IV[] = { 0x02,0x30,0xaa,0x15,0x7b,0x64,0xbe,0xf4,0x74,0xe3,0xbc,0x6f,0xfe,0x17,0x16,0xe6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-64", "[CFB1][MCT][192][ENCRYPT][n64]") {
    const uint8_t KEY[] = { 0x1f,0xe9,0x59,0x88,0x9b,0xff,0x49,0xbe,0x69,0x1d,0x4a,0xad,0x8a,0xdd,0xeb,0xf3,0x44,0x80,0x2b,0xae,0x7d,0x1b,0xa7,0x6e };
    const uint8_t IV[] = { 0xcc,0xad,0x7d,0x2a,0x8b,0x95,0x63,0xd6,0x47,0x92,0x1b,0xa4,0x60,0x98,0x4d,0x01 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-65", "[CFB1][MCT][192][ENCRYPT][n65]") {
    const uint8_t KEY[] = { 0x5b,0x44,0x32,0x31,0x9f,0x3e,0x26,0xa1,0xf3,0xcc,0x07,0xa4,0x31,0x86,0x9d,0x06,0x11,0x84,0xdf,0x35,0xd1,0x6b,0x64,0xa7 };
    const uint8_t IV[] = { 0x9a,0xd1,0x4d,0x09,0xbb,0x5b,0x76,0xf5,0x55,0x04,0xf4,0x9b,0xac,0x70,0xc3,0xc9 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-66", "[CFB1][MCT][192][ENCRYPT][n66]") {
    const uint8_t KEY[] = { 0x9c,0xae,0x8e,0xe5,0xb9,0x93,0x28,0x00,0x07,0xdd,0xc1,0x4d,0xba,0xd3,0xe8,0x1d,0xad,0x46,0x7f,0xcb,0x9a,0x13,0xf7,0xed };
    const uint8_t IV[] = { 0xf4,0x11,0xc6,0xe9,0x8b,0x55,0x75,0x1b,0xbc,0xc2,0xa0,0xfe,0x4b,0x78,0x93,0x4a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-67", "[CFB1][MCT][192][ENCRYPT][n67]") {
    const uint8_t KEY[] = { 0xcb,0x80,0xd7,0x1e,0x73,0x05,0x75,0x5b,0xd1,0x38,0xac,0xaf,0xb3,0x77,0x85,0xb1,0x44,0xd8,0x0f,0x5e,0x0c,0x49,0x50,0xb7 };
    const uint8_t IV[] = { 0xd6,0xe5,0x6d,0xe2,0x09,0xa4,0x6d,0xac,0xe9,0x9e,0x70,0x95,0x96,0x5a,0xa7,0x5a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-68", "[CFB1][MCT][192][ENCRYPT][n68]") {
    const uint8_t KEY[] = { 0xdd,0xfe,0xcf,0x3b,0x7f,0x84,0x67,0x87,0x20,0x47,0xf3,0xdc,0x2d,0xa3,0x42,0x39,0x39,0x48,0xe1,0xc7,0xdb,0xe8,0xd2,0xc9 };
    const uint8_t IV[] = { 0xf1,0x7f,0x5f,0x73,0x9e,0xd4,0xc7,0x88,0x7d,0x90,0xee,0x99,0xd7,0xa1,0x82,0x7e };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-69", "[CFB1][MCT][192][ENCRYPT][n69]") {
    const uint8_t KEY[] = { 0x7f,0x52,0x86,0x18,0xfb,0xfa,0x84,0xd4,0x9d,0x6d,0x95,0xe9,0x4a,0x26,0x44,0x2d,0x9a,0xfd,0x3a,0xc6,0x0f,0xc3,0x79,0xa1 };
    const uint8_t IV[] = { 0xbd,0x2a,0x66,0x35,0x67,0x85,0x06,0x14,0xa3,0xb5,0xdb,0x01,0xd4,0x2b,0xab,0x68 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-70", "[CFB1][MCT][192][ENCRYPT][n70]") {
    const uint8_t KEY[] = { 0x15,0x23,0x94,0xf0,0x18,0x17,0xc8,0x79,0xde,0xeb,0xe1,0x4b,0x83,0xa8,0x77,0xe4,0x94,0x1d,0xcb,0x67,0xe3,0x2f,0xc1,0xdf };
    const uint8_t IV[] = { 0x43,0x86,0x74,0xa2,0xc9,0x8e,0x33,0xc9,0x0e,0xe0,0xf1,0xa1,0xec,0xec,0xb8,0x7e };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-71", "[CFB1][MCT][192][ENCRYPT][n71]") {
    const uint8_t KEY[] = { 0x0e,0x21,0x08,0x0b,0x02,0x1d,0xca,0xb7,0x4f,0x4a,0x45,0xf1,0xf1,0xb0,0xa7,0xa4,0xa7,0xaf,0xae,0x06,0xf9,0x1e,0x6a,0xb8 };
    const uint8_t IV[] = { 0x91,0xa1,0xa4,0xba,0x72,0x18,0xd0,0x40,0x33,0xb2,0x65,0x61,0x1a,0x31,0xab,0x67 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-72", "[CFB1][MCT][192][ENCRYPT][n72]") {
    const uint8_t KEY[] = { 0xe6,0xdc,0x23,0xb8,0xed,0x05,0x89,0xe1,0xc2,0x3b,0xc1,0x9b,0xe0,0x57,0x42,0x48,0xf7,0xe2,0xdd,0xb6,0xb5,0xc4,0x2f,0x22 };
    const uint8_t IV[] = { 0x8d,0x71,0x84,0x6a,0x11,0xe7,0xe5,0xec,0x50,0x4d,0x73,0xb0,0x4c,0xda,0x45,0x9a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-73", "[CFB1][MCT][192][ENCRYPT][n73]") {
    const uint8_t KEY[] = { 0xca,0x04,0x90,0x24,0x70,0x91,0xcd,0x2c,0x95,0xc7,0x6d,0xc8,0xb8,0xb5,0xf3,0x52,0x19,0x5d,0x50,0x0b,0xd9,0xd6,0x96,0xa3 };
    const uint8_t IV[] = { 0x57,0xfc,0xac,0x53,0x58,0xe2,0xb1,0x1a,0xee,0xbf,0x8d,0xbd,0x6c,0x12,0xb9,0x81 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-74", "[CFB1][MCT][192][ENCRYPT][n74]") {
    const uint8_t KEY[] = { 0xac,0x1a,0xa3,0xf7,0x8b,0xe3,0x55,0x9a,0xc2,0x68,0x2f,0xe6,0x44,0xc5,0x08,0xb6,0x25,0xa2,0x22,0x34,0xac,0x5a,0x2b,0x81 };
    const uint8_t IV[] = { 0x57,0xaf,0x42,0x2e,0xfc,0x70,0xfb,0xe4,0x3c,0xff,0x72,0x3f,0x75,0x8c,0xbd,0x22 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-75", "[CFB1][MCT][192][ENCRYPT][n75]") {
    const uint8_t KEY[] = { 0x55,0xe3,0xa1,0x2d,0x6a,0xef,0xe3,0x81,0x97,0x32,0x13,0xd2,0x61,0xeb,0xe6,0x5f,0xba,0xe5,0x1b,0x1d,0x20,0x61,0x51,0x88 };
    const uint8_t IV[] = { 0x55,0x5a,0x3c,0x34,0x25,0x2e,0xee,0xe9,0x9f,0x47,0x39,0x29,0x8c,0x3b,0x7a,0x09 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-76", "[CFB1][MCT][192][ENCRYPT][n76]") {
    const uint8_t KEY[] = { 0x5d,0x27,0x22,0x50,0xdb,0xb7,0xaf,0xbe,0xa3,0x67,0x8b,0x06,0x76,0x5a,0x01,0xd2,0xe7,0x92,0xdc,0x9f,0x99,0xfd,0xd3,0x2e };
    const uint8_t IV[] = { 0x34,0x55,0x98,0xd4,0x17,0xb1,0xe7,0x8d,0x5d,0x77,0xc7,0x82,0xb9,0x9c,0x82,0xa6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-77", "[CFB1][MCT][192][ENCRYPT][n77]") {
    const uint8_t KEY[] = { 0xa7,0xd6,0xdc,0xe1,0x07,0xe0,0x2a,0xd6,0x5b,0x2c,0xe0,0x19,0x4a,0xea,0xa2,0x73,0xec,0x2c,0x7f,0xa6,0x31,0x0d,0x4b,0x38 };
    const uint8_t IV[] = { 0xf8,0x4b,0x6b,0x1f,0x3c,0xb0,0xa3,0xa1,0x0b,0xbe,0xa3,0x39,0xa8,0xf0,0x98,0x16 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-78", "[CFB1][MCT][192][ENCRYPT][n78]") {
    const uint8_t KEY[] = { 0x93,0xb8,0xd7,0x61,0x79,0xbe,0xef,0x8c,0xf3,0xe6,0x03,0x93,0xa1,0x9b,0x4b,0x1f,0x67,0x5d,0x54,0x24,0xb2,0x07,0xaa,0xad };
    const uint8_t IV[] = { 0xa8,0xca,0xe3,0x8a,0xeb,0x71,0xe9,0x6c,0x8b,0x71,0x2b,0x82,0x83,0x0a,0xe1,0x95 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-79", "[CFB1][MCT][192][ENCRYPT][n79]") {
    const uint8_t KEY[] = { 0xdd,0x4d,0x9b,0x62,0x7e,0xa0,0xb9,0x05,0x7c,0x17,0xe7,0x95,0x9b,0xab,0x26,0x14,0xff,0xe1,0x70,0x66,0x8a,0xf2,0x65,0x28 };
    const uint8_t IV[] = { 0x8f,0xf1,0xe4,0x06,0x3a,0x30,0x6d,0x0b,0x98,0xbc,0x24,0x42,0x38,0xf5,0xcf,0x85 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-80", "[CFB1][MCT][192][ENCRYPT][n80]") {
    const uint8_t KEY[] = { 0xb6,0x1b,0x90,0x4d,0xdf,0xe3,0xd0,0xc1,0x33,0x43,0x30,0x4f,0x02,0x9b,0xcf,0x16,0x32,0x98,0x86,0xb6,0xb5,0x70,0xdc,0x9e };
    const uint8_t IV[] = { 0x4f,0x54,0xd7,0xda,0x99,0x30,0xe9,0x02,0xcd,0x79,0xf6,0xd0,0x3f,0x82,0xb9,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-81", "[CFB1][MCT][192][ENCRYPT][n81]") {
    const uint8_t KEY[] = { 0x79,0x9d,0x27,0x79,0x39,0x3f,0xde,0x09,0x2d,0x7d,0xd8,0x2d,0x9c,0xfe,0xf9,0x69,0xcf,0xf7,0x5f,0x1f,0xc6,0x40,0xe1,0x03 };
    const uint8_t IV[] = { 0x1e,0x3e,0xe8,0x62,0x9e,0x65,0x36,0x7f,0xfd,0x6f,0xd9,0xa9,0x73,0x30,0x3d,0x9d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-82", "[CFB1][MCT][192][ENCRYPT][n82]") {
    const uint8_t KEY[] = { 0x45,0xb9,0xd6,0x8b,0x9e,0xc7,0x71,0xd4,0x05,0x92,0xea,0xf0,0x8e,0xe2,0x83,0x62,0xe1,0xa4,0xf5,0x3c,0x34,0x8c,0x86,0x29 };
    const uint8_t IV[] = { 0x28,0xef,0x32,0xdd,0x12,0x1c,0x7a,0x0b,0x2e,0x53,0xaa,0x23,0xf2,0xcc,0x67,0x2a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-83", "[CFB1][MCT][192][ENCRYPT][n83]") {
    const uint8_t KEY[] = { 0x2e,0x92,0x0b,0x61,0xf0,0x96,0x86,0xa9,0x11,0xd9,0x72,0x4d,0x32,0x56,0x15,0x01,0x67,0xaf,0x5b,0x16,0x05,0xb2,0x70,0x2d };
    const uint8_t IV[] = { 0x14,0x4b,0x98,0xbd,0xbc,0xb4,0x96,0x63,0x86,0x0b,0xae,0x2a,0x31,0x3e,0xf6,0x04 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-84", "[CFB1][MCT][192][ENCRYPT][n84]") {
    const uint8_t KEY[] = { 0xcb,0x87,0x35,0xe3,0x5c,0x48,0x3c,0x42,0xfe,0x7e,0xda,0xaa,0xa4,0xc4,0xc7,0x7b,0xf6,0xc9,0x33,0x87,0x95,0x85,0x36,0x16 };
    const uint8_t IV[] = { 0xef,0xa7,0xa8,0xe7,0x96,0x92,0xd2,0x7a,0x91,0x66,0x68,0x91,0x90,0x37,0x46,0x3b };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-85", "[CFB1][MCT][192][ENCRYPT][n85]") {
    const uint8_t KEY[] = { 0x1f,0x2a,0xbe,0x19,0x02,0x35,0xd4,0x39,0x79,0x1c,0x1d,0xbd,0x3c,0xc6,0xc3,0x72,0x9c,0x2e,0x60,0x7c,0xe8,0x37,0xb3,0x45 };
    const uint8_t IV[] = { 0x87,0x62,0xc7,0x17,0x98,0x02,0x04,0x09,0x6a,0xe7,0x53,0xfb,0x7d,0xb2,0x85,0x53 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-86", "[CFB1][MCT][192][ENCRYPT][n86]") {
    const uint8_t KEY[] = { 0xcd,0xcf,0x5a,0x56,0x04,0x0c,0xa2,0xe7,0x63,0x4f,0xd3,0x03,0x54,0x63,0x4c,0x92,0x73,0xad,0xc8,0x34,0x73,0xb8,0xa6,0x49 };
    const uint8_t IV[] = { 0x1a,0x53,0xce,0xbe,0x68,0xa5,0x8f,0xe0,0xef,0x83,0xa8,0x48,0x9b,0x8f,0x15,0x0c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-87", "[CFB1][MCT][192][ENCRYPT][n87]") {
    const uint8_t KEY[] = { 0x1d,0x0c,0x23,0xda,0xcd,0xb8,0xda,0x62,0x1b,0x40,0x55,0x83,0x75,0xa8,0x55,0xc9,0xef,0xed,0x2f,0xea,0xe0,0x1c,0xbf,0xb1 };
    const uint8_t IV[] = { 0x78,0x0f,0x86,0x80,0x21,0xcb,0x19,0x5b,0x9c,0x40,0xe7,0xde,0x93,0xa4,0x19,0xf8 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-88", "[CFB1][MCT][192][ENCRYPT][n88]") {
    const uint8_t KEY[] = { 0x0c,0x30,0x7b,0x2f,0xd8,0x25,0x61,0x36,0x2f,0x8f,0x7f,0x25,0x3e,0x7a,0x38,0x30,0x62,0x44,0x98,0xa7,0x8f,0x59,0x11,0x42 };
    const uint8_t IV[] = { 0x34,0xcf,0x2a,0xa6,0x4b,0xd2,0x6d,0xf9,0x8d,0xa9,0xb7,0x4d,0x6f,0x45,0xae,0xf3 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-89", "[CFB1][MCT][192][ENCRYPT][n89]") {
    const uint8_t KEY[] = { 0x79,0x42,0xb8,0x31,0x3d,0x30,0xbb,0x13,0x4b,0x8c,0x5b,0x11,0x9e,0x6a,0x89,0xb4,0xd1,0xab,0xed,0x4c,0x3c,0x86,0xc3,0x44 };
    const uint8_t IV[] = { 0x64,0x03,0x24,0x34,0xa0,0x10,0xb1,0x84,0xb3,0xef,0x75,0xeb,0xb3,0xdf,0xd2,0x06 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-90", "[CFB1][MCT][192][ENCRYPT][n90]") {
    const uint8_t KEY[] = { 0xf7,0x7e,0x86,0x67,0xa4,0xa9,0xf6,0xe0,0x9a,0x3d,0x88,0xc0,0xc2,0x92,0x59,0x36,0x8c,0x5a,0xa1,0xe7,0xad,0x35,0xb8,0xd9 };
    const uint8_t IV[] = { 0xd1,0xb1,0xd3,0xd1,0x5c,0xf8,0xd0,0x82,0x5d,0xf1,0x4c,0xab,0x91,0xb3,0x7b,0x9d };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-91", "[CFB1][MCT][192][ENCRYPT][n91]") {
    const uint8_t KEY[] = { 0x83,0x8b,0x39,0xbb,0x10,0x0b,0xaf,0xc0,0x0f,0x79,0xaa,0x79,0x21,0x04,0x0d,0x61,0x09,0xfc,0xc5,0x7e,0xb7,0xd6,0x90,0xd6 };
    const uint8_t IV[] = { 0x95,0x44,0x22,0xb9,0xe3,0x96,0x54,0x57,0x85,0xa6,0x64,0x99,0x1a,0xe3,0x28,0x0f };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-92", "[CFB1][MCT][192][ENCRYPT][n92]") {
    const uint8_t KEY[] = { 0xe8,0x96,0xb4,0x25,0x60,0xf4,0xbb,0x3e,0xad,0xe8,0x19,0xbc,0x18,0xbe,0x3c,0xb1,0xc9,0x3a,0x51,0x17,0xb4,0x58,0x81,0xdb };
    const uint8_t IV[] = { 0xa2,0x91,0xb3,0xc5,0x39,0xba,0x31,0xd0,0xc0,0xc6,0x94,0x69,0x03,0x8e,0x11,0x0d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-93", "[CFB1][MCT][192][ENCRYPT][n93]") {
    const uint8_t KEY[] = { 0x00,0x6d,0x99,0xe0,0xdf,0x25,0x6c,0x64,0xeb,0x67,0x15,0x4b,0x66,0x5d,0xee,0x05,0x8c,0x12,0x6e,0x43,0x11,0x31,0x98,0x58 };
    const uint8_t IV[] = { 0x46,0x8f,0x0c,0xf7,0x7e,0xe3,0xd2,0xb4,0x45,0x28,0x3f,0x54,0xa5,0x69,0x19,0x83 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-94", "[CFB1][MCT][192][ENCRYPT][n94]") {
    const uint8_t KEY[] = { 0x9e,0x7a,0xdb,0x67,0x22,0x43,0xb4,0x17,0xb6,0x70,0xa5,0x0f,0xc6,0xdb,0x8c,0xae,0xaa,0x0b,0x39,0xa3,0xbe,0x82,0x1c,0x4a };
    const uint8_t IV[] = { 0x5d,0x17,0xb0,0x44,0xa0,0x86,0x62,0xab,0x26,0x19,0x57,0xe0,0xaf,0xb3,0x84,0x12 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-95", "[CFB1][MCT][192][ENCRYPT][n95]") {
    const uint8_t KEY[] = { 0x06,0x44,0xd1,0x57,0x84,0xed,0x90,0x3f,0x13,0xa1,0x54,0xd2,0xf4,0x03,0x8d,0x20,0xd6,0xec,0xf1,0xe8,0xae,0xbf,0xc9,0xfb };
    const uint8_t IV[] = { 0xa5,0xd1,0xf1,0xdd,0x32,0xd8,0x01,0x8e,0x7c,0xe7,0xc8,0x4b,0x10,0x3d,0xd5,0xb1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-96", "[CFB1][MCT][192][ENCRYPT][n96]") {
    const uint8_t KEY[] = { 0xd9,0x65,0xb2,0x58,0x36,0xe4,0xa8,0xd9,0x74,0xbd,0x79,0xec,0x92,0x8a,0x7f,0x0b,0xbb,0x9e,0x09,0xe4,0x93,0xa9,0xc9,0x3e };
    const uint8_t IV[] = { 0x67,0x1c,0x2d,0x3e,0x66,0x89,0xf2,0x2b,0x6d,0x72,0xf8,0x0c,0x3d,0x16,0x00,0xc5 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-97", "[CFB1][MCT][192][ENCRYPT][n97]") {
    const uint8_t KEY[] = { 0xcb,0x6c,0xba,0x2e,0x9b,0x91,0x25,0x82,0x72,0xaa,0x44,0x10,0x60,0x9b,0xfa,0x8a,0xab,0x86,0x3e,0xc1,0x1e,0x4d,0xbd,0x64 };
    const uint8_t IV[] = { 0x06,0x17,0x3d,0xfc,0xf2,0x11,0x85,0x81,0x10,0x18,0x37,0x25,0x8d,0xe4,0x74,0x5a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-98", "[CFB1][MCT][192][ENCRYPT][n98]") {
    const uint8_t KEY[] = { 0xa5,0x19,0x4a,0xf3,0x0c,0xb2,0x6e,0xe9,0x90,0xaa,0xc0,0x4b,0xa6,0x9a,0xe1,0x55,0xe6,0xbd,0xfd,0x05,0xb3,0x30,0x77,0x52 };
    const uint8_t IV[] = { 0xe2,0x00,0x84,0x5b,0xc6,0x01,0x1b,0xdf,0x4d,0x3b,0xc3,0xc4,0xad,0x7d,0xca,0x36 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-ENCRYPT-99", "[CFB1][MCT][192][ENCRYPT][n99]") {
    const uint8_t KEY[] = { 0xcb,0xb7,0x73,0x02,0x78,0x46,0x20,0x6d,0xb8,0x26,0x90,0x74,0x08,0x7b,0xe2,0xb0,0xd9,0x19,0x38,0x2b,0xd0,0xdd,0x81,0x74 };
    const uint8_t IV[] = { 0x28,0x8c,0x50,0x3f,0xae,0xe1,0x03,0xe5,0x3f,0xa4,0xc5,0x2e,0x63,0xed,0xf6,0x26 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-0", "[CFB1][MCT][192][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x48,0x9b,0x8a,0x78,0x2e,0x7b,0x76,0x54,0xf9,0x3e,0x04,0x63,0xdf,0x8f,0x44,0x47,0x8e,0xb7,0x6d,0x26,0x1d,0xbf,0x74,0xf5 };
    const uint8_t IV[] = { 0x79,0x44,0x69,0x9c,0x94,0xa6,0x72,0x3a,0xcc,0x05,0x82,0xbf,0x5a,0x46,0x3f,0x4c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-1", "[CFB1][MCT][192][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x9d,0x8d,0x77,0x82,0xd8,0x0e,0xc0,0x77,0xb2,0xc5,0x16,0x81,0x25,0x09,0x13,0xeb,0x19,0x4f,0x68,0xfe,0x19,0x95,0x3c,0x7f };
    const uint8_t IV[] = { 0x4b,0xfb,0x12,0xe2,0xfa,0x86,0x57,0xac,0x97,0xf8,0x05,0xd8,0x04,0x2a,0x48,0x8a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-2", "[CFB1][MCT][192][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0xb0,0x8f,0x7d,0x6a,0x32,0x10,0x7d,0x75,0x47,0xf0,0x3b,0x18,0xa8,0xbd,0x7c,0x8b,0xb6,0x61,0x62,0x1f,0x46,0x20,0x17,0xa8 };
    const uint8_t IV[] = { 0xf5,0x35,0x2d,0x99,0x8d,0xb4,0x6f,0x60,0xaf,0x2e,0x0a,0xe1,0x5f,0xb5,0x2b,0xd7 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-3", "[CFB1][MCT][192][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0xa7,0xca,0x44,0xc0,0xd8,0xa9,0x18,0x36,0x6a,0x15,0x11,0xc3,0xf9,0xd8,0x74,0xe8,0xea,0x38,0x4a,0x9f,0x14,0x73,0xaf,0xe2 };
    const uint8_t IV[] = { 0x2d,0xe5,0x2a,0xdb,0x51,0x65,0x08,0x63,0x5c,0x59,0x28,0x80,0x52,0x53,0xb8,0x4a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-4", "[CFB1][MCT][192][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x7a,0xfb,0xfe,0x8f,0xb2,0xb8,0x30,0x35,0x87,0x1d,0x00,0x06,0xe5,0x93,0xa3,0x8e,0x47,0x9c,0x39,0xa3,0xa4,0x37,0x6e,0x41 };
    const uint8_t IV[] = { 0xed,0x08,0x11,0xc5,0x1c,0x4b,0xd7,0x66,0xad,0xa4,0x73,0x3c,0xb0,0x44,0xc1,0xa3 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-5", "[CFB1][MCT][192][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0x78,0x9a,0xc3,0x92,0xe3,0x32,0xcc,0x48,0x88,0x35,0x7b,0x00,0xc4,0x08,0xc0,0x1a,0x26,0x11,0xcc,0xf9,0xa3,0x95,0x9d,0x28 };
    const uint8_t IV[] = { 0x0f,0x28,0x7b,0x06,0x21,0x9b,0x63,0x94,0x61,0x8d,0xf5,0x5a,0x07,0xa2,0xf3,0x69 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-6", "[CFB1][MCT][192][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0xf6,0xd6,0x64,0xea,0x64,0x3c,0xb8,0x14,0x62,0x47,0x01,0x9c,0xbe,0x6f,0x1e,0x79,0x8e,0x2a,0x89,0xa3,0xa0,0x3a,0x49,0x93 };
    const uint8_t IV[] = { 0xea,0x72,0x7a,0x9c,0x7a,0x67,0xde,0x63,0xa8,0x3b,0x45,0x5a,0x03,0xaf,0xd4,0xbb };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-7", "[CFB1][MCT][192][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0xaf,0xac,0xa2,0x53,0x7c,0x3f,0x8b,0x22,0xd2,0xb3,0x8e,0xdf,0x3d,0xe2,0x1d,0x97,0x3d,0x06,0xb0,0xb4,0xb8,0xa9,0x09,0xd2 };
    const uint8_t IV[] = { 0xb0,0xf4,0x8f,0x43,0x83,0x8d,0x03,0xee,0xb3,0x2c,0x39,0x17,0x18,0x93,0x40,0x41 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-8", "[CFB1][MCT][192][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0xcb,0x34,0x78,0x11,0xc1,0xfe,0x71,0x2f,0x71,0x18,0x2c,0x9d,0x07,0x12,0x8b,0x5f,0xd2,0x03,0xc9,0xd6,0x96,0xf3,0xcc,0xef };
    const uint8_t IV[] = { 0xa3,0xab,0xa2,0x42,0x3a,0xf0,0x96,0xc8,0xef,0x05,0x79,0x62,0x2e,0x5a,0xc5,0x3d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-9", "[CFB1][MCT][192][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0x03,0x92,0x35,0x12,0x3d,0x90,0xc1,0xa9,0xad,0xc5,0x01,0xc8,0x9d,0x0d,0xc6,0xeb,0x58,0x1b,0x4b,0xf3,0x3c,0xb6,0x69,0x37 };
    const uint8_t IV[] = { 0xdc,0xdd,0x2d,0x55,0x9a,0x1f,0x4d,0xb4,0x8a,0x18,0x82,0x25,0xaa,0x45,0xa5,0xd8 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-10", "[CFB1][MCT][192][DECRYPT][n10]") {
    const uint8_t KEY[] = { 0xe1,0x3a,0x01,0xc7,0xbb,0x48,0xa7,0xc8,0xbf,0x9f,0xa3,0x3d,0x95,0xf4,0x4f,0x73,0x9b,0x5a,0xe1,0x54,0x25,0x58,0x47,0x3c };
    const uint8_t IV[] = { 0x12,0x5a,0xa2,0xf5,0x08,0xf9,0x89,0x98,0xc3,0x41,0xaa,0xa7,0x19,0xee,0x2e,0x0b };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-11", "[CFB1][MCT][192][DECRYPT][n11]") {
    const uint8_t KEY[] = { 0xfa,0x50,0xd7,0x7a,0x6d,0x2e,0x97,0x9e,0x83,0x6f,0x48,0x34,0x9f,0xbe,0x68,0x05,0x23,0x08,0x2d,0x93,0x9d,0x1e,0xe7,0x6b };
    const uint8_t IV[] = { 0x3c,0xf0,0xeb,0x09,0x0a,0x4a,0x27,0x76,0xb8,0x52,0xcc,0xc7,0xb8,0x46,0xa0,0x57 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-12", "[CFB1][MCT][192][DECRYPT][n12]") {
    const uint8_t KEY[] = { 0x33,0x86,0x3f,0x46,0x26,0x3d,0xfe,0xfe,0x2a,0xb9,0xb1,0xa0,0x55,0x82,0x2f,0xad,0x9e,0xc9,0x42,0x23,0xeb,0xa6,0x10,0x53 };
    const uint8_t IV[] = { 0xa9,0xd6,0xf9,0x94,0xca,0x3c,0x47,0xa8,0xbd,0xc1,0x6f,0xb0,0x76,0xb8,0xf7,0x38 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-13", "[CFB1][MCT][192][DECRYPT][n13]") {
    const uint8_t KEY[] = { 0x07,0xb2,0xb4,0x75,0xce,0x40,0xba,0x3a,0x30,0x81,0x55,0xa8,0xf9,0x4b,0xf9,0xf0,0x65,0xf7,0xb9,0xbe,0x53,0x3c,0x97,0xc2 };
    const uint8_t IV[] = { 0x1a,0x38,0xe4,0x08,0xac,0xc9,0xd6,0x5d,0xfb,0x3e,0xfb,0x9d,0xb8,0x9a,0x87,0x91 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-14", "[CFB1][MCT][192][DECRYPT][n14]") {
    const uint8_t KEY[] = { 0x4c,0x56,0xd9,0x25,0x88,0x1b,0xe7,0xe7,0x2a,0xf8,0x01,0x4c,0x57,0x8b,0x90,0x8e,0x02,0x60,0xc9,0x03,0x66,0x3b,0xdc,0xe5 };
    const uint8_t IV[] = { 0x1a,0x79,0x54,0xe4,0xae,0xc0,0x69,0x7e,0x67,0x97,0x70,0xbd,0x35,0x07,0x4b,0x27 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-15", "[CFB1][MCT][192][DECRYPT][n15]") {
    const uint8_t KEY[] = { 0x8d,0x3e,0x16,0x8b,0xff,0xd3,0xf3,0xea,0x29,0x3c,0xb1,0x88,0x2f,0xa9,0x85,0xcf,0x26,0xe4,0xa9,0x45,0x2b,0x8a,0x5a,0x80 };
    const uint8_t IV[] = { 0x03,0xc4,0xb0,0xc4,0x78,0x22,0x15,0x41,0x24,0x84,0x60,0x46,0x4d,0xb1,0x86,0x65 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-16", "[CFB1][MCT][192][DECRYPT][n16]") {
    const uint8_t KEY[] = { 0xf2,0xc6,0xc4,0xa9,0xd0,0x7b,0x19,0x93,0x2d,0xbd,0xff,0x02,0x49,0x00,0x2a,0xf0,0xf6,0xb9,0x86,0x84,0xed,0x0b,0xa3,0xaf };
    const uint8_t IV[] = { 0x04,0x81,0x4e,0x8a,0x66,0xa9,0xaf,0x3f,0xd0,0x5d,0x2f,0xc1,0xc6,0x81,0xf9,0x2f };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-17", "[CFB1][MCT][192][DECRYPT][n17]") {
    const uint8_t KEY[] = { 0x87,0x4f,0x6f,0x8d,0xda,0xb6,0xbc,0xd9,0x15,0x64,0xa3,0xef,0x50,0xc0,0xa5,0x40,0x99,0x88,0x5d,0xe7,0xb6,0x55,0xc7,0x19 };
    const uint8_t IV[] = { 0x38,0xd9,0x5c,0xed,0x19,0xc0,0x8f,0xb0,0x6f,0x31,0xdb,0x63,0x5b,0x5e,0x64,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-18", "[CFB1][MCT][192][DECRYPT][n18]") {
    const uint8_t KEY[] = { 0xe6,0x22,0xf8,0xb6,0x7f,0xb2,0x74,0x4b,0x94,0x82,0xe3,0x9a,0xe0,0xec,0x98,0xef,0xe7,0x48,0x46,0x95,0x6a,0xb1,0xe0,0x89 };
    const uint8_t IV[] = { 0x81,0xe6,0x40,0x75,0xb0,0x2c,0x3d,0xaf,0x7e,0xc0,0x1b,0x72,0xdc,0xe4,0x27,0x90 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-19", "[CFB1][MCT][192][DECRYPT][n19]") {
    const uint8_t KEY[] = { 0x28,0x1d,0xc5,0xb0,0x51,0x72,0x23,0x3b,0xf0,0xdf,0x91,0x78,0x5d,0x88,0xb5,0x8a,0xd7,0x90,0x68,0x33,0xaa,0xfe,0xd8,0xb8 };
    const uint8_t IV[] = { 0x64,0x5d,0x72,0xe2,0xbd,0x64,0x2d,0x65,0x30,0xd8,0x2e,0xa6,0xc0,0x4f,0x38,0x31 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-20", "[CFB1][MCT][192][DECRYPT][n20]") {
    const uint8_t KEY[] = { 0x85,0x27,0x33,0x3e,0xc8,0xba,0x7f,0x3a,0x99,0xa0,0x98,0x08,0x2a,0xb7,0x18,0x23,0x42,0xd2,0x5c,0x4b,0xfc,0xe8,0xed,0x37 };
    const uint8_t IV[] = { 0x69,0x7f,0x09,0x70,0x77,0x3f,0xad,0xa9,0x95,0x42,0x34,0x78,0x56,0x16,0x35,0x8f };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-21", "[CFB1][MCT][192][DECRYPT][n21]") {
    const uint8_t KEY[] = { 0x5f,0x8c,0xc0,0xb3,0x49,0x57,0x90,0xcd,0xbd,0xe6,0xac,0xec,0x70,0x53,0x56,0x28,0x4f,0xae,0x1b,0xa7,0x3e,0x6b,0x55,0x24 };
    const uint8_t IV[] = { 0x24,0x46,0x34,0xe4,0x5a,0xe4,0x4e,0x0b,0x0d,0x7c,0x47,0xec,0xc2,0x83,0xb8,0x13 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-22", "[CFB1][MCT][192][DECRYPT][n22]") {
    const uint8_t KEY[] = { 0xd5,0xa5,0xde,0x9d,0x9f,0x57,0x82,0x84,0x0a,0xd9,0xf1,0x5e,0x6b,0xf0,0x88,0x25,0x25,0x57,0xdf,0x87,0x2b,0xc7,0xf4,0x9f };
    const uint8_t IV[] = { 0xb7,0x3f,0x5d,0xb2,0x1b,0xa3,0xde,0x0d,0x6a,0xf9,0xc4,0x20,0x15,0xac,0xa1,0xbb };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-23", "[CFB1][MCT][192][DECRYPT][n23]") {
    const uint8_t KEY[] = { 0x64,0xa5,0xd0,0x0c,0xa4,0xdf,0xf1,0xfb,0xff,0x33,0x94,0x2b,0x66,0xb0,0xe8,0x84,0x8d,0xa3,0xcc,0x31,0xbb,0xc1,0x17,0x08 };
    const uint8_t IV[] = { 0xf5,0xea,0x65,0x75,0x0d,0x40,0x60,0xa1,0xa8,0xf4,0x13,0xb6,0x90,0x06,0xe3,0x97 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-24", "[CFB1][MCT][192][DECRYPT][n24]") {
    const uint8_t KEY[] = { 0x80,0x5d,0x49,0xc7,0xd2,0xce,0x10,0xbf,0x3a,0xff,0x62,0xa3,0x0a,0x00,0x76,0xdd,0x24,0x43,0xff,0x1b,0x2d,0x26,0x58,0xb4 };
    const uint8_t IV[] = { 0xc5,0xcc,0xf6,0x88,0x6c,0xb0,0x9e,0x59,0xa9,0xe0,0x33,0x2a,0x96,0xe7,0x4f,0xbc };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-25", "[CFB1][MCT][192][DECRYPT][n25]") {
    const uint8_t KEY[] = { 0x38,0x29,0x80,0xf0,0x0c,0xb4,0xe6,0x1b,0xd9,0xfa,0x81,0x42,0x84,0x8f,0x97,0x91,0x01,0x46,0xa3,0x99,0x24,0xc5,0x3d,0xe2 };
    const uint8_t IV[] = { 0xe3,0x05,0xe3,0xe1,0x8e,0x8f,0xe1,0x4c,0x25,0x05,0x5c,0x82,0x09,0xe3,0x65,0x56 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-26", "[CFB1][MCT][192][DECRYPT][n26]") {
    const uint8_t KEY[] = { 0x53,0x37,0xbb,0x84,0xb2,0x8d,0xa7,0xf8,0xe6,0xc5,0xe7,0x27,0x19,0xd1,0x8f,0x55,0x10,0xa8,0x37,0x29,0x6d,0x6e,0x94,0xd5 };
    const uint8_t IV[] = { 0x3f,0x3f,0x66,0x65,0x9d,0x5e,0x18,0xc4,0x11,0xee,0x94,0xb0,0x49,0xab,0xa9,0x37 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-27", "[CFB1][MCT][192][DECRYPT][n27]") {
    const uint8_t KEY[] = { 0xc6,0xc6,0xc5,0xdb,0x17,0xb9,0xb5,0x0c,0x17,0x84,0x43,0xef,0xf8,0x9a,0xd0,0x7f,0xd4,0x77,0x9a,0xe3,0x65,0x64,0xee,0x42 };
    const uint8_t IV[] = { 0xf1,0x41,0xa4,0xc8,0xe1,0x4b,0x5f,0x2a,0xc4,0xdf,0xad,0xca,0x08,0x0a,0x7a,0x97 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-28", "[CFB1][MCT][192][DECRYPT][n28]") {
    const uint8_t KEY[] = { 0xe9,0xd6,0x30,0xcb,0x7d,0x98,0x1d,0x16,0x41,0xc4,0x33,0x14,0x25,0x27,0x27,0xc7,0x88,0xe3,0xfc,0x89,0x0e,0xdd,0xd3,0x0e };
    const uint8_t IV[] = { 0x56,0x40,0x70,0xfb,0xdd,0xbd,0xf7,0xb8,0x5c,0x94,0x66,0x6a,0x6b,0xb9,0x3d,0x4c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-29", "[CFB1][MCT][192][DECRYPT][n29]") {
    const uint8_t KEY[] = { 0x86,0x52,0x76,0x9a,0xc7,0xd9,0xba,0x41,0x2f,0xdf,0xd1,0x11,0x12,0xda,0x68,0x4f,0xa4,0xaa,0xd3,0xaf,0x30,0xec,0xf6,0x29 };
    const uint8_t IV[] = { 0x6e,0x1b,0xe2,0x05,0x37,0xfd,0x4f,0x88,0x2c,0x49,0x2f,0x26,0x3e,0x31,0x25,0x27 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-30", "[CFB1][MCT][192][DECRYPT][n30]") {
    const uint8_t KEY[] = { 0x76,0x2e,0xc3,0x6e,0xf2,0x67,0xf9,0xb0,0x74,0xe0,0x46,0x22,0x93,0xd9,0x18,0x43,0x21,0x73,0xf8,0x4d,0x27,0x8c,0x7a,0x00 };
    const uint8_t IV[] = { 0x5b,0x3f,0x97,0x33,0x81,0x03,0x70,0x0c,0x85,0xd9,0x2b,0xe2,0x17,0x60,0x8c,0x29 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-31", "[CFB1][MCT][192][DECRYPT][n31]") {
    const uint8_t KEY[] = { 0xac,0xf6,0x4f,0x46,0xdb,0x2d,0x91,0xde,0xb1,0xdc,0xe2,0x3c,0x74,0x83,0x71,0x9a,0x86,0x5a,0x55,0x15,0xa5,0xdd,0x35,0x9b };
    const uint8_t IV[] = { 0xc5,0x3c,0xa4,0x1e,0xe7,0x5a,0x69,0xd9,0xa7,0x29,0xad,0x58,0x82,0x51,0x4f,0x9b };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-32", "[CFB1][MCT][192][DECRYPT][n32]") {
    const uint8_t KEY[] = { 0x77,0x5e,0x87,0x69,0x58,0xe0,0x26,0x40,0xb8,0xcf,0x7c,0x2e,0xfc,0xb3,0x4f,0x5b,0x24,0xaf,0x55,0x6c,0xca,0x70,0x9a,0xff };
    const uint8_t IV[] = { 0x09,0x13,0x9e,0x12,0x88,0x30,0x3e,0xc1,0xa2,0xf5,0x00,0x79,0x6f,0xad,0xaf,0x64 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-33", "[CFB1][MCT][192][DECRYPT][n33]") {
    const uint8_t KEY[] = { 0x39,0x42,0x38,0xc0,0x16,0xfc,0x47,0x15,0x45,0x5d,0xcf,0x97,0x57,0xcc,0xeb,0xc4,0x48,0x83,0xe1,0xd7,0xfd,0xf3,0x36,0xfd };
    const uint8_t IV[] = { 0xfd,0x92,0xb3,0xb9,0xab,0x7f,0xa4,0x9f,0x6c,0x2c,0xb4,0xbb,0x37,0x83,0xac,0x02 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-34", "[CFB1][MCT][192][DECRYPT][n34]") {
    const uint8_t KEY[] = { 0x53,0x8d,0x90,0x8e,0x9e,0xb3,0x39,0x6c,0xb7,0x39,0x00,0xbb,0xf3,0xaa,0xe6,0x6e,0xd9,0x7e,0xe5,0x6b,0x71,0x64,0xd0,0xb6 };
    const uint8_t IV[] = { 0xf2,0x64,0xcf,0x2c,0xa4,0x66,0x0d,0xaa,0x91,0xfd,0x04,0xbc,0x8c,0x97,0xe6,0x4b };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-35", "[CFB1][MCT][192][DECRYPT][n35]") {
    const uint8_t KEY[] = { 0x24,0xd3,0xa8,0x63,0x39,0xeb,0x47,0x7b,0xf2,0x18,0xc9,0xae,0x58,0x43,0xe0,0xc2,0x84,0xdf,0xca,0x8d,0xc1,0xb3,0x89,0x23 };
    const uint8_t IV[] = { 0x45,0x21,0xc9,0x15,0xab,0xe9,0x06,0xac,0x5d,0xa1,0x2f,0xe6,0xb0,0xd7,0x59,0x95 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-36", "[CFB1][MCT][192][DECRYPT][n36]") {
    const uint8_t KEY[] = { 0xa1,0x14,0x03,0xa2,0x22,0xe3,0xdf,0x64,0x83,0xa4,0x00,0xee,0x4c,0x78,0x60,0xaf,0x85,0x2f,0x7f,0x47,0x2e,0x67,0x2f,0xc7 };
    const uint8_t IV[] = { 0x71,0xbc,0xc9,0x40,0x14,0x3b,0x80,0x6d,0x01,0xf0,0xb5,0xca,0xef,0xd4,0xa6,0xe4 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-37", "[CFB1][MCT][192][DECRYPT][n37]") {
    const uint8_t KEY[] = { 0x41,0x1f,0x82,0xa2,0x85,0x6e,0x14,0x75,0xf3,0xb1,0xa9,0xf7,0xd0,0x6a,0x01,0xba,0x2c,0x85,0x96,0x73,0xc0,0xd8,0x90,0xe4 };
    const uint8_t IV[] = { 0x70,0x15,0xa9,0x19,0x9c,0x12,0x61,0x15,0xa9,0xaa,0xe9,0x34,0xee,0xbf,0xbf,0x23 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-38", "[CFB1][MCT][192][DECRYPT][n38]") {
    const uint8_t KEY[] = { 0x5a,0x77,0x3a,0xba,0xe3,0x27,0xb2,0x0c,0xa2,0x6e,0xea,0xb0,0xc3,0xc8,0x73,0xb6,0xce,0x0d,0xb3,0xff,0x61,0x26,0x25,0xf2 };
    const uint8_t IV[] = { 0x51,0xdf,0x43,0x47,0x13,0xa2,0x72,0x0c,0xe2,0x88,0x25,0x8c,0xa1,0xfe,0xb5,0x16 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-39", "[CFB1][MCT][192][DECRYPT][n39]") {
    const uint8_t KEY[] = { 0xa2,0x8f,0x21,0x31,0xad,0x21,0x70,0xdb,0x50,0x18,0xd6,0xeb,0xcb,0x95,0x6e,0xcf,0x88,0x2b,0x39,0x46,0x5f,0xaa,0x86,0xea };
    const uint8_t IV[] = { 0xf2,0x76,0x3c,0x5b,0x08,0x5d,0x1d,0x79,0x46,0x26,0x8a,0xb9,0x3e,0x8c,0xa3,0x18 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-40", "[CFB1][MCT][192][DECRYPT][n40]") {
    const uint8_t KEY[] = { 0x47,0x22,0x73,0x9c,0x99,0x9f,0xb8,0x4c,0x34,0x10,0x13,0x55,0x25,0x03,0x20,0x09,0xcd,0x5e,0x4a,0x94,0x44,0xd2,0xdb,0xf4 };
    const uint8_t IV[] = { 0x64,0x08,0xc5,0xbe,0xee,0x96,0x4e,0xc6,0x45,0x75,0x73,0xd2,0x1b,0x78,0x5d,0x1e };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-41", "[CFB1][MCT][192][DECRYPT][n41]") {
    const uint8_t KEY[] = { 0x81,0x8a,0x72,0xb5,0x9d,0x72,0x8b,0x6f,0x01,0xb6,0x68,0x74,0x20,0x82,0x85,0x0d,0xa9,0xe7,0xd6,0x75,0xbf,0xea,0x1e,0x47 };
    const uint8_t IV[] = { 0x35,0xa6,0x7b,0x21,0x05,0x81,0xa5,0x04,0x64,0xb9,0x9c,0xe1,0xfb,0x38,0xc5,0xb3 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-42", "[CFB1][MCT][192][DECRYPT][n42]") {
    const uint8_t KEY[] = { 0xa8,0x07,0xff,0x29,0x88,0x59,0x4f,0xcd,0x5d,0xeb,0x1d,0xa8,0xd1,0xed,0x94,0x1d,0xd6,0xc3,0xf4,0xb7,0x9d,0x87,0x7d,0x23 };
    const uint8_t IV[] = { 0x5c,0x5d,0x75,0xdc,0xf1,0x6f,0x11,0x10,0x7f,0x24,0x22,0xc2,0x22,0x6d,0x63,0x64 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-43", "[CFB1][MCT][192][DECRYPT][n43]") {
    const uint8_t KEY[] = { 0x18,0xf8,0xda,0x35,0x27,0xf1,0x4f,0xcc,0x19,0x2c,0x2c,0xe9,0xc5,0x64,0x2a,0x14,0x52,0xb1,0x31,0xfe,0x2e,0x97,0xe1,0x07 };
    const uint8_t IV[] = { 0x44,0xc7,0x31,0x41,0x14,0x89,0xbe,0x09,0x84,0x72,0xc5,0x49,0xb3,0x10,0x9c,0x24 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-44", "[CFB1][MCT][192][DECRYPT][n44]") {
    const uint8_t KEY[] = { 0x6b,0x40,0x81,0x7a,0x17,0x63,0x48,0xa1,0x28,0xa9,0x2c,0x00,0xa2,0xff,0x27,0x48,0x29,0x8e,0x28,0x36,0x0d,0x35,0x57,0x9b };
    const uint8_t IV[] = { 0x31,0x85,0x00,0xe9,0x67,0x9b,0x0d,0x5c,0x7b,0x3f,0x19,0xc8,0x23,0xa2,0xb6,0x9c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-45", "[CFB1][MCT][192][DECRYPT][n45]") {
    const uint8_t KEY[] = { 0xe6,0x7a,0xd6,0xd0,0x85,0xe0,0xe6,0xaa,0xa8,0x0e,0xb1,0x2e,0x1c,0x4d,0x48,0x0c,0x70,0x79,0x4b,0xcf,0x6d,0x93,0xed,0x86 };
    const uint8_t IV[] = { 0x80,0xa7,0x9d,0x2e,0xbe,0xb2,0x6f,0x44,0x59,0xf7,0x63,0xf9,0x60,0xa6,0xba,0x1d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-46", "[CFB1][MCT][192][DECRYPT][n46]") {
    const uint8_t KEY[] = { 0x00,0x1a,0x99,0x4d,0x95,0x53,0x82,0x18,0xf5,0x75,0x1f,0xd3,0x35,0x4e,0x92,0x41,0x3c,0x8e,0x2e,0xac,0x81,0x3e,0xab,0x34 };
    const uint8_t IV[] = { 0x5d,0x7b,0xae,0xfd,0x29,0x03,0xda,0x4d,0x4c,0xf7,0x65,0x63,0xec,0xad,0x46,0xb2 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-47", "[CFB1][MCT][192][DECRYPT][n47]") {
    const uint8_t KEY[] = { 0x2a,0x4c,0x4a,0x8e,0x68,0x43,0x2d,0x9d,0x82,0x0a,0x71,0x46,0x7f,0xa5,0xa4,0x2b,0x02,0x4e,0x45,0x29,0x1a,0x47,0x6b,0x0d };
    const uint8_t IV[] = { 0x77,0x7f,0x6e,0x95,0x4a,0xeb,0x36,0x6a,0x3e,0xc0,0x6b,0x85,0x9b,0x79,0xc0,0x39 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-48", "[CFB1][MCT][192][DECRYPT][n48]") {
    const uint8_t KEY[] = { 0x4c,0x5b,0xa7,0x47,0x5c,0xa3,0x88,0x7e,0xf8,0x91,0x92,0x91,0xff,0x90,0x67,0x30,0x8e,0xc7,0xb7,0x18,0xca,0x23,0x7d,0xf5 };
    const uint8_t IV[] = { 0x7a,0x9b,0xe3,0xd7,0x80,0x35,0xc3,0x1b,0x8c,0x89,0xf2,0x31,0xd0,0x64,0x16,0xf8 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-49", "[CFB1][MCT][192][DECRYPT][n49]") {
    const uint8_t KEY[] = { 0xe5,0x40,0x98,0x15,0x50,0xef,0xe8,0xbc,0xa8,0xbe,0x92,0xfa,0xdb,0xeb,0xa2,0xea,0xed,0x8d,0xc3,0x56,0xf9,0xc0,0x47,0x36 };
    const uint8_t IV[] = { 0x50,0x2f,0x00,0x6b,0x24,0x7b,0xc5,0xda,0x63,0x4a,0x74,0x4e,0x33,0xe3,0x3a,0xc3 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-50", "[CFB1][MCT][192][DECRYPT][n50]") {
    const uint8_t KEY[] = { 0x63,0x53,0xdf,0x1a,0x06,0xa0,0xaa,0x1c,0x66,0xbb,0xf9,0x2c,0xbf,0x5a,0x24,0x28,0x75,0xcd,0xf5,0xe1,0x7e,0x61,0x95,0x96 };
    const uint8_t IV[] = { 0xce,0x05,0x6b,0xd6,0x64,0xb1,0x86,0xc2,0x98,0x40,0x36,0xb7,0x87,0xa1,0xd2,0xa0 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-51", "[CFB1][MCT][192][DECRYPT][n51]") {
    const uint8_t KEY[] = { 0xd5,0x2f,0xa1,0x18,0xd4,0x3d,0x3c,0xa0,0x6a,0x7d,0xca,0x88,0x83,0x01,0x45,0xc8,0x49,0x5d,0x5c,0xb3,0x7d,0x04,0x7d,0x51 };
    const uint8_t IV[] = { 0x0c,0xc6,0x33,0xa4,0x3c,0x5b,0x61,0xe0,0x3c,0x90,0xa9,0x52,0x03,0x65,0xe8,0xc7 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-52", "[CFB1][MCT][192][DECRYPT][n52]") {
    const uint8_t KEY[] = { 0xff,0x42,0xe9,0x68,0x0f,0x3b,0x05,0xf8,0x6b,0x18,0x93,0x35,0x7b,0x6a,0x74,0xf1,0x12,0xbb,0x2c,0xfd,0x6e,0x2d,0x13,0x67 };
    const uint8_t IV[] = { 0x01,0x65,0x59,0xbd,0xf8,0x6b,0x31,0x39,0x5b,0xe6,0x70,0x4e,0x13,0x29,0x6e,0x36 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-53", "[CFB1][MCT][192][DECRYPT][n53]") {
    const uint8_t KEY[] = { 0xfa,0x77,0x4b,0xa3,0x4b,0x6d,0x5d,0xdb,0x1e,0x30,0x1a,0x70,0x61,0x4d,0xe4,0xb4,0xc2,0x02,0x4c,0x93,0xfe,0x25,0x66,0xb5 };
    const uint8_t IV[] = { 0x75,0x28,0x89,0x45,0x1a,0x27,0x90,0x45,0xd0,0xb9,0x60,0x6e,0x90,0x08,0x75,0xd2 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-54", "[CFB1][MCT][192][DECRYPT][n54]") {
    const uint8_t KEY[] = { 0x18,0x2d,0xf6,0xa1,0xb0,0x29,0x1c,0x7f,0xf1,0x57,0x07,0xc9,0x4f,0x71,0x28,0x5a,0x8a,0x17,0x4c,0x4f,0x0a,0x3a,0x73,0x31 };
    const uint8_t IV[] = { 0xef,0x67,0x1d,0xb9,0x2e,0x3c,0xcc,0xee,0x48,0x15,0x00,0xdc,0xf4,0x1f,0x15,0x84 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-55", "[CFB1][MCT][192][DECRYPT][n55]") {
    const uint8_t KEY[] = { 0x44,0xa5,0x4c,0x7d,0xeb,0x77,0x80,0x23,0x8f,0x1b,0xb0,0xdb,0x0e,0x6f,0x7a,0x0f,0x6c,0xa2,0x7b,0xdb,0xf0,0xf9,0x10,0x62 };
    const uint8_t IV[] = { 0x7e,0x4c,0xb7,0x12,0x41,0x1e,0x52,0x55,0xe6,0xb5,0x37,0x94,0xfa,0xc3,0x63,0x53 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-56", "[CFB1][MCT][192][DECRYPT][n56]") {
    const uint8_t KEY[] = { 0xb8,0x69,0x2a,0x9d,0xd1,0x18,0x89,0xb9,0x68,0x6d,0x3b,0xbc,0xd4,0x16,0xa8,0x76,0x95,0x42,0x28,0x9b,0x36,0xaa,0x8a,0x4b };
    const uint8_t IV[] = { 0xe7,0x76,0x8b,0x67,0xda,0x79,0xd2,0x79,0xf9,0xe0,0x53,0x40,0xc6,0x53,0x9a,0x29 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-57", "[CFB1][MCT][192][DECRYPT][n57]") {
    const uint8_t KEY[] = { 0xa8,0xb0,0xa4,0xdd,0xc7,0x04,0x31,0x3e,0xe7,0x1a,0xe0,0x7e,0xfe,0x2f,0xff,0x61,0xed,0x1c,0x63,0x95,0x05,0x3d,0xc0,0xa3 };
    const uint8_t IV[] = { 0x8f,0x77,0xdb,0xc2,0x2a,0x39,0x57,0x17,0x78,0x5e,0x4b,0x0e,0x33,0x97,0x4a,0xe8 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-58", "[CFB1][MCT][192][DECRYPT][n58]") {
    const uint8_t KEY[] = { 0x5d,0xe6,0x0e,0x73,0xc6,0x43,0xb8,0x7a,0xa1,0x0c,0x60,0x8b,0x8e,0xdc,0x16,0x2f,0x93,0x0a,0x41,0xff,0xfd,0x40,0x11,0x18 };
    const uint8_t IV[] = { 0x46,0x16,0x80,0xf5,0x70,0xf3,0xe9,0x4e,0x7e,0x16,0x22,0x6a,0xf8,0x7d,0xd1,0xbb };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-59", "[CFB1][MCT][192][DECRYPT][n59]") {
    const uint8_t KEY[] = { 0x72,0x26,0xc1,0xac,0x31,0x4a,0x22,0x56,0x11,0x6f,0x32,0x87,0xcc,0xf5,0x09,0x80,0xcd,0x29,0xd5,0xda,0xdb,0x7c,0xfb,0x16 };
    const uint8_t IV[] = { 0xb0,0x63,0x52,0x0c,0x42,0x29,0x1f,0xaf,0x5e,0x23,0x94,0x25,0x26,0x3c,0xea,0x0e };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-60", "[CFB1][MCT][192][DECRYPT][n60]") {
    const uint8_t KEY[] = { 0x6c,0xb7,0xfa,0xff,0xde,0xd7,0xec,0x24,0x48,0x28,0x4b,0x9b,0x38,0x13,0x43,0xb1,0xc8,0x61,0x2d,0x4c,0x64,0x32,0xef,0x7e };
    const uint8_t IV[] = { 0x59,0x47,0x79,0x1c,0xf4,0xe6,0x4a,0x31,0x05,0x48,0xf8,0x96,0xbf,0x4e,0x14,0x68 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-61", "[CFB1][MCT][192][DECRYPT][n61]") {
    const uint8_t KEY[] = { 0x88,0x63,0x2d,0xb6,0xfb,0xb3,0xed,0x14,0x54,0x5e,0x3e,0x62,0x31,0xce,0x78,0x84,0xdb,0x44,0x0a,0x9a,0x21,0x09,0xfb,0xce };
    const uint8_t IV[] = { 0x1c,0x76,0x75,0xf9,0x09,0xdd,0x3b,0x35,0x13,0x25,0x27,0xd6,0x45,0x3b,0x14,0xb0 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-62", "[CFB1][MCT][192][DECRYPT][n62]") {
    const uint8_t KEY[] = { 0x48,0xcf,0x57,0x41,0x7d,0xbc,0x92,0x28,0x7b,0xbf,0x4c,0xa3,0xd4,0xc1,0x94,0xa6,0xd7,0x47,0x50,0xfc,0xf4,0xca,0xb1,0xd0 };
    const uint8_t IV[] = { 0x2f,0xe1,0x72,0xc1,0xe5,0x0f,0xec,0x22,0x0c,0x03,0x5a,0x66,0xd5,0xc3,0x4a,0x1e };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-63", "[CFB1][MCT][192][DECRYPT][n63]") {
    const uint8_t KEY[] = { 0x84,0xf5,0xd6,0xfa,0x84,0xce,0xf4,0x6f,0x83,0x2c,0x5f,0x4c,0xeb,0x62,0x8e,0x58,0xde,0x5b,0x24,0x8f,0xe0,0xe8,0x61,0xd2 };
    const uint8_t IV[] = { 0xf8,0x93,0x13,0xef,0x3f,0xa3,0x1a,0xfe,0x09,0x1c,0x74,0x73,0x14,0x22,0xd0,0x02 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-64", "[CFB1][MCT][192][DECRYPT][n64]") {
    const uint8_t KEY[] = { 0x9c,0xc4,0x70,0xe8,0x64,0x94,0x2c,0xb3,0x83,0x7d,0x12,0xe8,0x41,0x5d,0xd1,0xc6,0x31,0x23,0x1a,0xb7,0xf1,0x7e,0x0b,0xc8 };
    const uint8_t IV[] = { 0x00,0x51,0x4d,0xa4,0xaa,0x3f,0x5f,0x9e,0xef,0x78,0x3e,0x38,0x11,0x96,0x6a,0x1a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-65", "[CFB1][MCT][192][DECRYPT][n65]") {
    const uint8_t KEY[] = { 0x1f,0x21,0x6a,0x1a,0x17,0x26,0x81,0x7b,0x1f,0xc3,0x56,0x3e,0xa2,0x34,0x7f,0xf8,0x39,0x0f,0x28,0x6d,0x60,0xd7,0xff,0xaf };
    const uint8_t IV[] = { 0x9c,0xbe,0x44,0xd6,0xe3,0x69,0xae,0x3e,0x08,0x2c,0x32,0xda,0x91,0xa9,0xf4,0x67 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-66", "[CFB1][MCT][192][DECRYPT][n66]") {
    const uint8_t KEY[] = { 0x0b,0x63,0x6c,0xbc,0x0d,0x4b,0x5b,0x5e,0x81,0xc1,0x3e,0x0e,0x97,0x8d,0x7a,0x3b,0xa0,0x9a,0xba,0xa5,0x65,0xe0,0x42,0x6f };
    const uint8_t IV[] = { 0x9e,0x02,0x68,0x30,0x35,0xb9,0x05,0xc3,0x99,0x95,0x92,0xc8,0x05,0x37,0xbd,0xc0 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-67", "[CFB1][MCT][192][DECRYPT][n67]") {
    const uint8_t KEY[] = { 0xbd,0x59,0xbc,0x01,0x21,0xf3,0xb6,0x24,0xc7,0x09,0x4f,0x4f,0xd6,0x3d,0x3e,0x56,0x67,0x7b,0x3c,0x32,0x48,0xb8,0x32,0x97 };
    const uint8_t IV[] = { 0x46,0xc8,0x71,0x41,0x41,0xb0,0x44,0x6d,0xc7,0xe1,0x86,0x97,0x2d,0x58,0x70,0xf8 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-68", "[CFB1][MCT][192][DECRYPT][n68]") {
    const uint8_t KEY[] = { 0xf5,0xcb,0xc5,0x76,0xb7,0xb8,0x66,0x7d,0x3d,0x55,0x79,0x39,0x90,0x26,0x63,0xf2,0x26,0xb6,0x00,0xe5,0x41,0x76,0x0a,0x17 };
    const uint8_t IV[] = { 0xfa,0x5c,0x36,0x76,0x46,0x1b,0x5d,0xa4,0x41,0xcd,0x3c,0xd7,0x09,0xce,0x38,0x80 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-69", "[CFB1][MCT][192][DECRYPT][n69]") {
    const uint8_t KEY[] = { 0xdf,0x89,0xb8,0x22,0xc7,0x84,0xce,0xf9,0x4c,0x72,0x81,0xb4,0x02,0x40,0x3f,0x91,0xd7,0xa5,0x5a,0xb7,0xc2,0x04,0xe4,0xa5 };
    const uint8_t IV[] = { 0x71,0x27,0xf8,0x8d,0x92,0x66,0x5c,0x63,0xf1,0x13,0x5a,0x52,0x83,0x72,0xee,0xb2 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-70", "[CFB1][MCT][192][DECRYPT][n70]") {
    const uint8_t KEY[] = { 0x3e,0x3e,0x53,0xaa,0x36,0x2e,0x6e,0x1c,0x58,0xd9,0x6c,0xa7,0xdc,0x1c,0x11,0x53,0xb2,0x04,0xe2,0x1c,0x65,0xc0,0xfb,0x0f };
    const uint8_t IV[] = { 0x14,0xab,0xed,0x13,0xde,0x5c,0x2e,0xc2,0x65,0xa1,0xb8,0xab,0xa7,0xc4,0x1f,0xaa };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-71", "[CFB1][MCT][192][DECRYPT][n71]") {
    const uint8_t KEY[] = { 0xd9,0xf7,0x1f,0x93,0x7c,0xbf,0x35,0x51,0x58,0x55,0x9a,0xf6,0x98,0x6c,0x27,0xb6,0xb7,0x55,0x41,0x1d,0xb9,0xc0,0x28,0x89 };
    const uint8_t IV[] = { 0x00,0x8c,0xf6,0x51,0x44,0x70,0x36,0xe5,0x05,0x51,0xa3,0x01,0xdc,0x00,0xd3,0x86 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-72", "[CFB1][MCT][192][DECRYPT][n72]") {
    const uint8_t KEY[] = { 0x73,0xb7,0xbe,0x69,0x7a,0xc6,0xa7,0x33,0xc9,0x28,0x47,0xfa,0x21,0x26,0x23,0x3f,0xff,0x19,0x01,0xdb,0xbf,0x77,0x52,0x13 };
    const uint8_t IV[] = { 0x91,0x7d,0xdd,0x0c,0xb9,0x4a,0x04,0x89,0x48,0x4c,0x40,0xc6,0x06,0xb7,0x7a,0x9a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-73", "[CFB1][MCT][192][DECRYPT][n73]") {
    const uint8_t KEY[] = { 0x42,0x9a,0x2a,0x4f,0xf3,0x58,0x54,0x95,0x1c,0x78,0x80,0x6f,0x28,0x7f,0x27,0x38,0x56,0x24,0xde,0xa1,0x53,0x57,0x30,0xfc };
    const uint8_t IV[] = { 0xd5,0x50,0xc7,0x95,0x09,0x59,0x04,0x07,0xa9,0x3d,0xdf,0x7a,0xec,0x20,0x62,0xef };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-74", "[CFB1][MCT][192][DECRYPT][n74]") {
    const uint8_t KEY[] = { 0xe8,0xd0,0x98,0x0f,0x79,0xe1,0x56,0x4f,0x71,0xa8,0xbf,0xef,0xdf,0x48,0xe1,0x7b,0xd0,0xeb,0x7a,0x21,0xd1,0x5c,0x7f,0x4a };
    const uint8_t IV[] = { 0x6d,0xd0,0x3f,0x80,0xf7,0x37,0xc6,0x43,0x86,0xcf,0xa4,0x80,0x82,0x0b,0x4f,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-75", "[CFB1][MCT][192][DECRYPT][n75]") {
    const uint8_t KEY[] = { 0x55,0xaf,0xe5,0x91,0x9e,0x4a,0x5c,0x00,0xf5,0x28,0xe0,0x18,0xbb,0xc0,0x6a,0x88,0x04,0x22,0xdd,0xb3,0xc0,0x72,0x2c,0xd9 };
    const uint8_t IV[] = { 0x84,0x80,0x5f,0xf7,0x64,0x88,0x8b,0xf3,0xd4,0xc9,0xa7,0x92,0x11,0x2e,0x53,0x93 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-76", "[CFB1][MCT][192][DECRYPT][n76]") {
    const uint8_t KEY[] = { 0xb0,0x31,0xeb,0x74,0x8d,0xb3,0xad,0xfa,0xa7,0x75,0xaf,0x89,0x70,0xf6,0x49,0xac,0xa0,0xb1,0x5b,0x1b,0x5e,0xcd,0xc6,0x69 };
    const uint8_t IV[] = { 0x52,0x5d,0x4f,0x91,0xcb,0x36,0x23,0x24,0xa4,0x93,0x86,0xa8,0x9e,0xbf,0xea,0xb0 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-77", "[CFB1][MCT][192][DECRYPT][n77]") {
    const uint8_t KEY[] = { 0xa8,0x6e,0x05,0x4b,0xc8,0x74,0x6d,0xe3,0x36,0xbf,0x5c,0x60,0x07,0xe7,0xa5,0x26,0x88,0x62,0x7a,0xad,0x89,0xfb,0x0e,0xb7 };
    const uint8_t IV[] = { 0x91,0xca,0xf3,0xe9,0x77,0x11,0xec,0x8a,0x28,0xd3,0x21,0xb6,0xd7,0x36,0xc8,0xde };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-78", "[CFB1][MCT][192][DECRYPT][n78]") {
    const uint8_t KEY[] = { 0x4b,0x80,0xa2,0x33,0x13,0x8a,0x14,0xb5,0xa4,0x2b,0x9c,0x76,0x76,0x0f,0x0f,0x01,0x5b,0x05,0x82,0x2b,0xd7,0x98,0xf3,0xa6 };
    const uint8_t IV[] = { 0x92,0x94,0xc0,0x16,0x71,0xe8,0xaa,0x27,0xd3,0x67,0xf8,0x86,0x5e,0x63,0xfd,0x11 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-79", "[CFB1][MCT][192][DECRYPT][n79]") {
    const uint8_t KEY[] = { 0xab,0x8e,0xe4,0xcb,0x6a,0x17,0x6e,0x9a,0xaf,0x46,0x2b,0x1e,0x9d,0x7f,0x2c,0x00,0x96,0xc8,0x56,0x43,0xbe,0x14,0x4c,0x9a };
    const uint8_t IV[] = { 0x0b,0x6d,0xb7,0x68,0xeb,0x70,0x23,0x01,0xcd,0xcd,0xd4,0x68,0x69,0x8c,0xbf,0x3c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-80", "[CFB1][MCT][192][DECRYPT][n80]") {
    const uint8_t KEY[] = { 0xed,0x61,0xe3,0x32,0x23,0x95,0x0a,0x3d,0x3d,0xff,0x70,0x1f,0xab,0xa1,0x02,0x89,0xe4,0xc8,0xfd,0x6d,0xc5,0xe4,0xf6,0xf5 };
    const uint8_t IV[] = { 0x92,0xb9,0x5b,0x01,0x36,0xde,0x2e,0x89,0x72,0x00,0xab,0x2e,0x7b,0xf0,0xba,0x6f };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-81", "[CFB1][MCT][192][DECRYPT][n81]") {
    const uint8_t KEY[] = { 0x8f,0x7b,0xf0,0x73,0x51,0xc3,0xed,0xa9,0xb7,0xb2,0xa0,0x62,0x5e,0x61,0xb9,0x05,0x9f,0x96,0x76,0xe8,0xa3,0x54,0xae,0xbd };
    const uint8_t IV[] = { 0x8a,0x4d,0xd0,0x7d,0xf5,0xc0,0xbb,0x8c,0x7b,0x5e,0x8b,0x85,0x66,0xb0,0x58,0x48 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-82", "[CFB1][MCT][192][DECRYPT][n82]") {
    const uint8_t KEY[] = { 0x9e,0x7f,0x7a,0x54,0xf8,0x0e,0x58,0xbb,0x9c,0xc4,0x89,0x4f,0x1e,0x73,0xe4,0xf7,0xeb,0x4a,0x5c,0x9e,0x6b,0xfd,0x41,0xa5 };
    const uint8_t IV[] = { 0x2b,0x76,0x29,0x2d,0x40,0x12,0x5d,0xf2,0x74,0xdc,0x2a,0x76,0xc8,0xa9,0xef,0x18 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-83", "[CFB1][MCT][192][DECRYPT][n83]") {
    const uint8_t KEY[] = { 0xff,0x9d,0x0b,0x4c,0x49,0x3f,0xf4,0x9e,0xee,0x72,0xf6,0x35,0x61,0xb0,0x36,0x23,0x81,0x01,0xd3,0xd8,0x06,0x3a,0x35,0x2a };
    const uint8_t IV[] = { 0x72,0xb6,0x7f,0x7a,0x7f,0xc3,0xd2,0xd4,0x6a,0x4b,0x8f,0x46,0x6d,0xc7,0x74,0x8f };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-84", "[CFB1][MCT][192][DECRYPT][n84]") {
    const uint8_t KEY[] = { 0xe3,0x6c,0x4d,0x8b,0xc7,0x09,0x73,0x56,0xb8,0x7b,0x3d,0xc4,0xc1,0x25,0x29,0x7c,0xa9,0x44,0x8b,0xc3,0x67,0x15,0xf7,0x16 };
    const uint8_t IV[] = { 0x56,0x09,0xcb,0xf1,0xa0,0x95,0x1f,0x5f,0x28,0x45,0x58,0x1b,0x61,0x2f,0xc2,0x3c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-85", "[CFB1][MCT][192][DECRYPT][n85]") {
    const uint8_t KEY[] = { 0x9b,0x8f,0x44,0x8d,0x94,0xcc,0xf8,0x35,0x08,0x98,0x3a,0xaa,0xab,0xf2,0xa8,0x57,0xcf,0x2e,0xad,0x55,0x08,0xa4,0xae,0xfd };
    const uint8_t IV[] = { 0xb0,0xe3,0x07,0x6e,0x6a,0xd7,0x81,0x2b,0x66,0x6a,0x26,0x96,0x6f,0xb1,0x59,0xeb };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-86", "[CFB1][MCT][192][DECRYPT][n86]") {
    const uint8_t KEY[] = { 0x12,0xc4,0xd7,0x4a,0x9d,0x6b,0x21,0x83,0x05,0xce,0xc9,0x4f,0x90,0x45,0xd4,0xd2,0x01,0xed,0xcb,0x77,0x3c,0xac,0x45,0xea };
    const uint8_t IV[] = { 0x0d,0x56,0xf3,0xe5,0x3b,0xb7,0x7c,0x85,0xce,0xc3,0x66,0x22,0x34,0x08,0xeb,0x17 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-87", "[CFB1][MCT][192][DECRYPT][n87]") {
    const uint8_t KEY[] = { 0xd6,0x54,0x02,0xf4,0x95,0x22,0x53,0xf0,0x69,0x8a,0x88,0x10,0xd7,0x03,0xe0,0x7d,0x69,0xbc,0x2a,0x8b,0x45,0x04,0x58,0xad };
    const uint8_t IV[] = { 0x6c,0x44,0x41,0x5f,0x47,0x46,0x34,0xaf,0x68,0x51,0xe1,0xfc,0x79,0xa8,0x1d,0x47 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-88", "[CFB1][MCT][192][DECRYPT][n88]") {
    const uint8_t KEY[] = { 0xbb,0xc3,0xbf,0xb6,0x84,0x21,0xec,0x87,0x93,0xb6,0x01,0x48,0xe0,0xfa,0x37,0xa8,0x06,0xaf,0x7a,0x26,0x63,0xbd,0x6a,0xd7 };
    const uint8_t IV[] = { 0xfa,0x3c,0x89,0x58,0x37,0xf9,0xd7,0xd5,0x6f,0x13,0x50,0xad,0x26,0xb9,0x32,0x7a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-89", "[CFB1][MCT][192][DECRYPT][n89]") {
    const uint8_t KEY[] = { 0xe5,0x2b,0x15,0x19,0x39,0x8b,0xf2,0x63,0x74,0x6e,0xe5,0x29,0x80,0xcb,0x9e,0x8d,0x3e,0xcb,0x20,0xf1,0xd6,0x6d,0x51,0x87 };
    const uint8_t IV[] = { 0xe7,0xd8,0xe4,0x61,0x60,0x31,0xa9,0x25,0x38,0x64,0x5a,0xd7,0xb5,0xd0,0x3b,0x50 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-90", "[CFB1][MCT][192][DECRYPT][n90]") {
    const uint8_t KEY[] = { 0xc2,0x62,0xff,0xaa,0x58,0x68,0x3d,0x77,0x6a,0x4b,0x89,0xbc,0x43,0x52,0xab,0xa6,0x57,0xd9,0x29,0x6a,0x07,0xe6,0xb3,0xb4 };
    const uint8_t IV[] = { 0x1e,0x25,0x6c,0x95,0xc3,0x99,0x35,0x2b,0x69,0x12,0x09,0x9b,0xd1,0x8b,0xe2,0x33 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-91", "[CFB1][MCT][192][DECRYPT][n91]") {
    const uint8_t KEY[] = { 0x63,0x21,0xa2,0x63,0x6a,0xb0,0xa7,0x6b,0xf7,0x18,0x12,0xd3,0x80,0xd3,0x5b,0x07,0x6f,0xeb,0x63,0x9c,0x13,0x8f,0x95,0xb0 };
    const uint8_t IV[] = { 0x9d,0x53,0x9b,0x6f,0xc3,0x81,0xf0,0xa1,0x38,0x32,0x4a,0xf6,0x14,0x69,0x26,0x04 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-92", "[CFB1][MCT][192][DECRYPT][n92]") {
    const uint8_t KEY[] = { 0xac,0xca,0x5a,0xb4,0x49,0x79,0x7b,0x67,0xf1,0x5e,0x68,0xbd,0x9e,0x04,0x6d,0x23,0xc2,0x80,0xb4,0x29,0x26,0xe0,0xa8,0x5c };
    const uint8_t IV[] = { 0x06,0x46,0x7a,0x6e,0x1e,0xd7,0x36,0x24,0xad,0x6b,0xd7,0xb5,0x35,0x6f,0x3d,0xec };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-93", "[CFB1][MCT][192][DECRYPT][n93]") {
    const uint8_t KEY[] = { 0xa6,0xc0,0xff,0x9a,0x4e,0xb3,0xe8,0xdc,0x60,0xa4,0x19,0x49,0x9c,0xda,0xea,0x9a,0x27,0x19,0x79,0xdc,0xca,0x5e,0x3b,0x06 };
    const uint8_t IV[] = { 0x91,0xfa,0x71,0xf4,0x02,0xde,0x87,0xb9,0xe5,0x99,0xcd,0xf5,0xec,0xbe,0x93,0x5a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-94", "[CFB1][MCT][192][DECRYPT][n94]") {
    const uint8_t KEY[] = { 0x74,0x8f,0xb5,0x91,0x54,0xaa,0x60,0x9b,0xfb,0xa1,0x4e,0x74,0x10,0x50,0xc1,0x07,0xb1,0x34,0xe3,0x4e,0x96,0x3e,0x74,0x7b };
    const uint8_t IV[] = { 0x9b,0x05,0x57,0x3d,0x8c,0x8a,0x2b,0x9d,0x96,0x2d,0x9a,0x92,0x5c,0x60,0x4f,0x7d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-95", "[CFB1][MCT][192][DECRYPT][n95]") {
    const uint8_t KEY[] = { 0x69,0x01,0x41,0x64,0xbe,0x50,0xa7,0xc8,0xec,0x64,0x8b,0xbe,0xa4,0xa2,0x09,0xda,0xa8,0x60,0x84,0x81,0x14,0x58,0x3d,0x53 };
    const uint8_t IV[] = { 0x17,0xc5,0xc5,0xca,0xb4,0xf2,0xc8,0xdd,0x19,0x54,0x67,0xcf,0x82,0x66,0x49,0x28 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-96", "[CFB1][MCT][192][DECRYPT][n96]") {
    const uint8_t KEY[] = { 0x79,0x1b,0xbc,0x1d,0x11,0x65,0x3c,0x44,0xd8,0x94,0x55,0x6a,0x65,0x60,0xc8,0x7f,0xa8,0x3f,0x5e,0x02,0xbb,0x71,0xee,0xd4 };
    const uint8_t IV[] = { 0x34,0xf0,0xde,0xd4,0xc1,0xc2,0xc1,0xa5,0x00,0x5f,0xda,0x83,0xaf,0x29,0xd3,0x87 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-97", "[CFB1][MCT][192][DECRYPT][n97]") {
    const uint8_t KEY[] = { 0xcc,0x42,0x62,0x10,0x83,0xc9,0x3a,0xca,0xa2,0x2b,0x04,0xa2,0xf7,0x67,0x62,0xa4,0x68,0xd1,0x06,0xa8,0xe5,0x43,0xa8,0xa3 };
    const uint8_t IV[] = { 0x7a,0xbf,0x51,0xc8,0x92,0x07,0xaa,0xdb,0xc0,0xee,0x58,0xaa,0x5e,0x32,0x46,0x77 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-98", "[CFB1][MCT][192][DECRYPT][n98]") {
    const uint8_t KEY[] = { 0x96,0x82,0x14,0xd3,0x49,0x35,0x17,0xb9,0x2f,0x66,0xd6,0x1b,0x15,0xa6,0x93,0x31,0xdc,0x7f,0x6b,0xa0,0x2d,0x63,0x1e,0x45 };
    const uint8_t IV[] = { 0x8d,0x4d,0xd2,0xb9,0xe2,0xc1,0xf1,0x95,0xb4,0xae,0x6d,0x08,0xc8,0x20,0xb6,0xe6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT192-DECRYPT-99", "[CFB1][MCT][192][DECRYPT][n99]") {
    const uint8_t KEY[] = { 0x3d,0x53,0x6c,0x68,0x4a,0x44,0xae,0xc6,0xb5,0xde,0x47,0x68,0x09,0x9f,0x26,0x07,0xa5,0x15,0xe3,0x11,0xa1,0x23,0xf8,0xa1 };
    const uint8_t IV[] = { 0x9a,0xb8,0x91,0x73,0x1c,0x39,0xb5,0x36,0x79,0x6a,0x88,0xb1,0x8c,0x40,0xe6,0xe4 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

