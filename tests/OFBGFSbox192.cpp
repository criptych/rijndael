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

TEST_CASE("OFBGFSbox192-ENCRYPT-0", "[OFB][GFSbox][192][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x1b,0x07,0x7a,0x6a,0xf4,0xb7,0xf9,0x82,0x29,0xde,0x78,0x6d,0x75,0x16,0xb6,0x39 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x27,0x5c,0xfc,0x04,0x13,0xd8,0xcc,0xb7,0x05,0x13,0xc3,0x85,0x9b,0x1d,0x0f,0x72 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ofb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-ENCRYPT-1", "[OFB][GFSbox][192][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x9c,0x2d,0x88,0x42,0xe5,0xf4,0x8f,0x57,0x64,0x82,0x05,0xd3,0x9a,0x23,0x9a,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xc9,0xb8,0x13,0x5f,0xf1,0xb5,0xad,0xc4,0x13,0xdf,0xd0,0x53,0xb2,0x1b,0xd9,0x6d };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ofb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-ENCRYPT-2", "[OFB][GFSbox][192][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xbf,0xf5,0x25,0x10,0x09,0x5f,0x51,0x8e,0xcc,0xa6,0x0a,0xf4,0x20,0x54,0x44,0xbb };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4a,0x36,0x50,0xc3,0x37,0x1c,0xe2,0xeb,0x35,0xe3,0x89,0xa1,0x71,0x42,0x74,0x40 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ofb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-ENCRYPT-3", "[OFB][GFSbox][192][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x51,0x71,0x97,0x83,0xd3,0x18,0x5a,0x53,0x5b,0xd7,0x5a,0xdc,0x65,0x07,0x1c,0xe1 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4f,0x35,0x45,0x92,0xff,0x7c,0x88,0x47,0xd2,0xd0,0x87,0x0c,0xa9,0x48,0x1b,0x7c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ofb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-ENCRYPT-4", "[OFB][GFSbox][192][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x26,0xaa,0x49,0xdc,0xfe,0x76,0x29,0xa8,0x90,0x1a,0x69,0xa9,0x91,0x4e,0x6d,0xfd };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xd5,0xe0,0x8b,0xf9,0xa1,0x82,0xe8,0x57,0xcf,0x40,0xb3,0xa3,0x6e,0xe2,0x48,0xcc };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ofb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-ENCRYPT-5", "[OFB][GFSbox][192][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x94,0x1a,0x47,0x73,0x05,0x82,0x24,0xe1,0xef,0x66,0xd1,0x0e,0x0a,0x6e,0xe7,0x82 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x06,0x7c,0xd9,0xd3,0x74,0x92,0x07,0x79,0x18,0x41,0x56,0x25,0x07,0xfa,0x96,0x26 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ofb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-DECRYPT-0", "[OFB][GFSbox][192][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x1b,0x07,0x7a,0x6a,0xf4,0xb7,0xf9,0x82,0x29,0xde,0x78,0x6d,0x75,0x16,0xb6,0x39 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x27,0x5c,0xfc,0x04,0x13,0xd8,0xcc,0xb7,0x05,0x13,0xc3,0x85,0x9b,0x1d,0x0f,0x72 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ofb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-DECRYPT-1", "[OFB][GFSbox][192][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x9c,0x2d,0x88,0x42,0xe5,0xf4,0x8f,0x57,0x64,0x82,0x05,0xd3,0x9a,0x23,0x9a,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xc9,0xb8,0x13,0x5f,0xf1,0xb5,0xad,0xc4,0x13,0xdf,0xd0,0x53,0xb2,0x1b,0xd9,0x6d };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ofb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-DECRYPT-2", "[OFB][GFSbox][192][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xbf,0xf5,0x25,0x10,0x09,0x5f,0x51,0x8e,0xcc,0xa6,0x0a,0xf4,0x20,0x54,0x44,0xbb };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4a,0x36,0x50,0xc3,0x37,0x1c,0xe2,0xeb,0x35,0xe3,0x89,0xa1,0x71,0x42,0x74,0x40 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ofb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-DECRYPT-3", "[OFB][GFSbox][192][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x51,0x71,0x97,0x83,0xd3,0x18,0x5a,0x53,0x5b,0xd7,0x5a,0xdc,0x65,0x07,0x1c,0xe1 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4f,0x35,0x45,0x92,0xff,0x7c,0x88,0x47,0xd2,0xd0,0x87,0x0c,0xa9,0x48,0x1b,0x7c };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ofb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-DECRYPT-4", "[OFB][GFSbox][192][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x26,0xaa,0x49,0xdc,0xfe,0x76,0x29,0xa8,0x90,0x1a,0x69,0xa9,0x91,0x4e,0x6d,0xfd };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xd5,0xe0,0x8b,0xf9,0xa1,0x82,0xe8,0x57,0xcf,0x40,0xb3,0xa3,0x6e,0xe2,0x48,0xcc };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ofb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("OFBGFSbox192-DECRYPT-5", "[OFB][GFSbox][192][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x94,0x1a,0x47,0x73,0x05,0x82,0x24,0xe1,0xef,0x66,0xd1,0x0e,0x0a,0x6e,0xe7,0x82 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x06,0x7c,0xd9,0xd3,0x74,0x92,0x07,0x79,0x18,0x41,0x56,0x25,0x07,0xfa,0x96,0x26 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ofb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

