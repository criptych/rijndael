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

TEST_CASE("CFB1MMT128-ENCRYPT-0", "[CFB1][MMT][128][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0xca,0x70,0x5e,0xe6,0x84,0x7b,0xcf,0x17,0xa6,0x39,0x6f,0xec,0x47,0x31,0x35,0xcf };
    const uint8_t IV[] = { 0xc8,0x1b,0x8a,0x75,0xc1,0xa4,0xd5,0x24,0x3c,0xd8,0x89,0x54,0x0c,0x8e,0x36,0x22 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-1", "[CFB1][MMT][128][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0xcd,0xef,0x9d,0x06,0x61,0xba,0xe4,0x73,0x8d,0x1a,0x58,0xa2,0xa6,0x22,0x8b,0x66 };
    const uint8_t IV[] = { 0x4d,0xbb,0xdc,0xaa,0x59,0xf3,0x63,0xc9,0x2a,0x3b,0x98,0x43,0xad,0x20,0xe2,0xb7 };
    const uint8_t PLAINTEXT[] = { 0x11 };
    const uint8_t CIPHERTEXT[] = { 0x00 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-2", "[CFB1][MMT][128][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x1e,0x3b,0x6e,0x22,0x4a,0x79,0xa5,0xe4,0x0e,0x4a,0x1c,0x08,0x4b,0xda,0xd9,0xcb };
    const uint8_t IV[] = { 0x4c,0x55,0xa0,0xba,0xe9,0x9a,0xb9,0xf4,0xe9,0xcd,0xcb,0x02,0x38,0xb8,0xc5,0x25 };
    const uint8_t PLAINTEXT[] = { 0x11,0x1 };
    const uint8_t CIPHERTEXT[] = { 0x10,0x1 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-3", "[CFB1][MMT][128][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0x8a,0x31,0x58,0x7e,0x6b,0xf4,0x1d,0x46,0x08,0x7b,0xa8,0x80,0x0f,0x91,0x2f,0xd6 };
    const uint8_t IV[] = { 0x09,0x05,0x77,0x9f,0x9d,0x72,0xf3,0x22,0x72,0x1b,0xc4,0x8a,0xe7,0xef,0xee,0x5a };
    const uint8_t PLAINTEXT[] = { 0x11,0x01 };
    const uint8_t CIPHERTEXT[] = { 0x00,0x10 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-4", "[CFB1][MMT][128][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x5c,0x11,0x3f,0x7f,0x55,0x44,0x8f,0x19,0x29,0x24,0x1f,0x18,0x5c,0x31,0x40,0x19 };
    const uint8_t IV[] = { 0x42,0x61,0x3b,0xf6,0x1f,0x0b,0xbe,0x30,0x66,0x8e,0x69,0xd4,0xd0,0x94,0xd1,0x71 };
    const uint8_t PLAINTEXT[] = { 0x10,0x00,0x0 };
    const uint8_t CIPHERTEXT[] = { 0x10,0x11,0x0 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-5", "[CFB1][MMT][128][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x25,0x8c,0xc0,0xda,0xa1,0x7c,0x0a,0xf0,0xc1,0x37,0xc8,0x2c,0xea,0x60,0x9f,0xee };
    const uint8_t IV[] = { 0x60,0x4c,0xcd,0xed,0x57,0xa6,0x42,0x43,0x75,0x2e,0x4d,0x80,0xe5,0xac,0x9e,0x65 };
    const uint8_t PLAINTEXT[] = { 0x11,0x01,0x01 };
    const uint8_t CIPHERTEXT[] = { 0x11,0x01,0x01 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-6", "[CFB1][MMT][128][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x5a,0x22,0xf2,0xb7,0xb9,0xf1,0xfc,0x73,0x37,0xa1,0xac,0x62,0xae,0xb6,0x48,0x42 };
    const uint8_t IV[] = { 0x62,0xb1,0x0f,0xc4,0x29,0x9c,0xcc,0x50,0x75,0x27,0x24,0xa5,0xa9,0x34,0x3b,0xde };
    const uint8_t PLAINTEXT[] = { 0x01,0x00,0x10,0x0 };
    const uint8_t CIPHERTEXT[] = { 0x00,0x01,0x10,0x1 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-7", "[CFB1][MMT][128][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x25,0x0d,0x3c,0xe7,0x6f,0xae,0x19,0x53,0x61,0x71,0x43,0xba,0xc2,0xd0,0xdf,0xfa };
    const uint8_t IV[] = { 0xc1,0x35,0x61,0xf6,0xd9,0x78,0x34,0xe5,0x15,0xee,0x99,0xa4,0x51,0x0f,0xf4,0x94 };
    const uint8_t PLAINTEXT[] = { 0x00,0x10,0x00,0x10 };
    const uint8_t CIPHERTEXT[] = { 0x00,0x00,0x10,0x11 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-8", "[CFB1][MMT][128][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0xfb,0x79,0xde,0x45,0xbf,0xef,0x77,0xcc,0x72,0x3f,0x91,0x9d,0xe2,0x8b,0x19,0x00 };
    const uint8_t IV[] = { 0xe2,0x60,0x66,0xc5,0x89,0x06,0xe3,0x41,0x73,0x6c,0x85,0x24,0xb5,0x25,0x21,0x37 };
    const uint8_t PLAINTEXT[] = { 0x10,0x11,0x00,0x01,0x0 };
    const uint8_t CIPHERTEXT[] = { 0x11,0x00,0x11,0x00,0x1 };
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

TEST_CASE("CFB1MMT128-ENCRYPT-9", "[CFB1][MMT][128][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x68,0xde,0xdc,0x2e,0x02,0x19,0x4f,0xb0,0x34,0x9d,0xb1,0xfa,0x43,0xec,0x92,0x32 };
    const uint8_t IV[] = { 0x56,0x39,0x91,0x32,0x41,0x6f,0x42,0x65,0x16,0xe8,0x33,0xbf,0xc7,0xd7,0x9b,0x25 };
    const uint8_t PLAINTEXT[] = { 0x11,0x00,0x00,0x00,0x11 };
    const uint8_t CIPHERTEXT[] = { 0x01,0x01,0x11,0x01,0x11 };
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

TEST_CASE("CFB1MMT128-DECRYPT-0", "[CFB1][MMT][128][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x09,0x62,0x25,0xa6,0x38,0xf3,0x62,0x62,0xe9,0x70,0x7b,0xa8,0xa4,0xd2,0xd6,0x54 };
    const uint8_t IV[] = { 0xa9,0x34,0xec,0xac,0xea,0x22,0x4e,0x41,0x36,0x58,0x9d,0xc0,0xb3,0x34,0x4f,0x17 };
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

TEST_CASE("CFB1MMT128-DECRYPT-1", "[CFB1][MMT][128][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x89,0x75,0x03,0x56,0x99,0x8f,0x21,0xfe,0xd9,0x5d,0x44,0x29,0xe2,0xeb,0xdf,0xcb };
    const uint8_t IV[] = { 0x11,0x2a,0x65,0x8d,0x3c,0xaa,0x1e,0xfb,0x65,0x13,0x76,0x75,0xb0,0x47,0xdd,0x7b };
    const uint8_t PLAINTEXT[] = { 0x10 };
    const uint8_t CIPHERTEXT[] = { 0x00 };
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

TEST_CASE("CFB1MMT128-DECRYPT-2", "[CFB1][MMT][128][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0x1c,0x81,0x13,0x0e,0x3b,0xcb,0x86,0x05,0xa6,0xd6,0xb9,0xad,0x2a,0x12,0xee,0x90 };
    const uint8_t IV[] = { 0xd8,0xce,0x9b,0x56,0x33,0x22,0xb2,0x14,0x2b,0xe1,0xbd,0x66,0x1f,0x84,0x97,0xc6 };
    const uint8_t PLAINTEXT[] = { 0x10,0x1 };
    const uint8_t CIPHERTEXT[] = { 0x11,0x0 };
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

TEST_CASE("CFB1MMT128-DECRYPT-3", "[CFB1][MMT][128][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0xd6,0x5a,0xea,0x13,0x77,0x61,0x55,0x8d,0x1b,0x84,0x00,0x95,0x2c,0x15,0x40,0x37 };
    const uint8_t IV[] = { 0xfc,0x82,0x6c,0x2f,0x95,0xc7,0xb1,0x61,0x3c,0x59,0xa7,0xc0,0x9a,0x10,0x50,0x99 };
    const uint8_t PLAINTEXT[] = { 0x01,0x11 };
    const uint8_t CIPHERTEXT[] = { 0x11,0x10 };
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

TEST_CASE("CFB1MMT128-DECRYPT-4", "[CFB1][MMT][128][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x0c,0xc5,0x6e,0x69,0x47,0x32,0x10,0x07,0x22,0xbf,0x50,0xd2,0x5d,0x7b,0x0e,0xfd };
    const uint8_t IV[] = { 0xc8,0x8d,0x92,0x36,0x1e,0x1b,0x72,0x35,0x87,0xef,0x0a,0x70,0x0d,0xfa,0x59,0x7b };
    const uint8_t PLAINTEXT[] = { 0x01,0x11,0x0 };
    const uint8_t CIPHERTEXT[] = { 0x00,0x11,0x1 };
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

TEST_CASE("CFB1MMT128-DECRYPT-5", "[CFB1][MMT][128][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0x42,0xf3,0x26,0x69,0xfd,0x5b,0x5e,0xaf,0x9e,0x61,0xd5,0xef,0x32,0xe9,0xaf,0x4a };
    const uint8_t IV[] = { 0x3f,0xf4,0x6b,0x35,0x77,0x3d,0xf9,0x8f,0x9c,0x7b,0x7c,0x8c,0x54,0x86,0xfe,0x5e };
    const uint8_t PLAINTEXT[] = { 0x00,0x10,0x01 };
    const uint8_t CIPHERTEXT[] = { 0x01,0x01,0x11 };
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

TEST_CASE("CFB1MMT128-DECRYPT-6", "[CFB1][MMT][128][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0xbf,0x84,0xd9,0x9e,0xf4,0x31,0x2b,0xd9,0xef,0x79,0xe8,0x28,0xb0,0x6d,0xa9,0x4f };
    const uint8_t IV[] = { 0xcb,0x7b,0xe6,0xe4,0x1d,0x0a,0xe7,0x13,0x37,0xfd,0x86,0x0b,0x0a,0x95,0xd1,0x39 };
    const uint8_t PLAINTEXT[] = { 0x00,0x10,0x11,0x1 };
    const uint8_t CIPHERTEXT[] = { 0x11,0x10,0x01,0x1 };
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

TEST_CASE("CFB1MMT128-DECRYPT-7", "[CFB1][MMT][128][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x0b,0x3a,0x69,0x58,0x05,0xc4,0xa8,0x47,0x75,0xf5,0xc8,0x05,0x1b,0xa5,0x17,0x3f };
    const uint8_t IV[] = { 0x4a,0xce,0x89,0xf7,0x80,0x57,0xad,0x8b,0x00,0x63,0x27,0x88,0x0a,0x83,0x50,0xb1 };
    const uint8_t PLAINTEXT[] = { 0x11,0x11,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x10,0x01,0x10,0x10 };
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

TEST_CASE("CFB1MMT128-DECRYPT-8", "[CFB1][MMT][128][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0x49,0x35,0x09,0xb5,0x6a,0x92,0xf1,0x40,0x40,0xeb,0x9b,0x66,0xa1,0x88,0xbc,0x57 };
    const uint8_t IV[] = { 0x72,0x51,0xc5,0xe5,0xfd,0x76,0x3b,0x10,0x16,0xa1,0x98,0x9a,0xd2,0xa0,0x45,0xda };
    const uint8_t PLAINTEXT[] = { 0x11,0x00,0x11,0x01,0x1 };
    const uint8_t CIPHERTEXT[] = { 0x11,0x00,0x00,0x11,0x0 };
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

TEST_CASE("CFB1MMT128-DECRYPT-9", "[CFB1][MMT][128][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0x82,0x2f,0x39,0x96,0x00,0x6d,0x92,0x91,0x3f,0x6a,0xba,0x05,0x61,0xc7,0x99,0xc9 };
    const uint8_t IV[] = { 0xe2,0x11,0x2d,0x0f,0x3b,0xed,0x28,0xb3,0xcc,0x05,0xbd,0x97,0x75,0x49,0x72,0x3a };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x11,0x01,0x11 };
    const uint8_t CIPHERTEXT[] = { 0x10,0x11,0x11,0x10,0x11 };
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

