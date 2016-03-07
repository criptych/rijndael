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

TEST_CASE("CFB8MMT128-ENCRYPT-0", "[CFB8][MMT][128][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0xc5,0x7d,0x69,0x9d,0x89,0xdf,0x7c,0xfb,0xef,0x71,0xc0,0x80,0xa6,0xb1,0x0a,0xc3 };
    const uint8_t IV[] = { 0xfc,0xb2,0xbc,0x4c,0x00,0x6b,0x87,0x48,0x39,0x78,0x79,0x6a,0x2a,0xe2,0xc4,0x2e };
    const uint8_t PLAINTEXT[] = { 0x61 };
    const uint8_t CIPHERTEXT[] = { 0x24 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-1", "[CFB8][MMT][128][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x0d,0x8f,0x3d,0xc3,0xed,0xee,0x60,0xdb,0x65,0x8b,0xb9,0x7f,0xaf,0x46,0xfb,0xa3 };
    const uint8_t IV[] = { 0xe4,0x81,0xfd,0xc4,0x2e,0x60,0x6b,0x96,0xa3,0x83,0xc0,0xa1,0xa5,0x52,0x0e,0xbb };
    const uint8_t PLAINTEXT[] = { 0xaa,0xcd };
    const uint8_t CIPHERTEXT[] = { 0x50,0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-2", "[CFB8][MMT][128][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0xc8,0xfe,0x9b,0xf7,0x7b,0x93,0x0f,0x46,0xd2,0x07,0x8b,0x8c,0x0e,0x65,0x7c,0xd4 };
    const uint8_t IV[] = { 0xf4,0x75,0xc6,0x49,0x91,0xb2,0x0e,0xae,0xe1,0x83,0xa2,0x26,0x29,0xe2,0x1e,0x22 };
    const uint8_t PLAINTEXT[] = { 0xc9,0x06,0x35 };
    const uint8_t CIPHERTEXT[] = { 0xd2,0x76,0x91 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-3", "[CFB8][MMT][128][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0x28,0x0c,0xf8,0x1a,0xf5,0xcc,0x7e,0x73,0x63,0x57,0x9c,0x1d,0xa0,0x33,0x90,0xe6 };
    const uint8_t IV[] = { 0x5d,0x6c,0xf4,0x72,0x2d,0x0e,0x21,0xf1,0xd9,0xce,0xd5,0x3a,0x0e,0x36,0xc3,0x42 };
    const uint8_t PLAINTEXT[] = { 0xb2,0xa2,0x2c,0xed };
    const uint8_t CIPHERTEXT[] = { 0x73,0xf3,0xae,0xbf };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-4", "[CFB8][MMT][128][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x5d,0x5e,0x7f,0x20,0xe0,0xa6,0x6d,0x3e,0x09,0xe0,0xe5,0xa9,0x91,0x2f,0x8a,0x46 };
    const uint8_t IV[] = { 0x05,0x2d,0x7e,0xa0,0xad,0x1f,0x29,0x56,0xa2,0x3b,0x27,0xaf,0xe1,0xd8,0x7b,0x6b };
    const uint8_t PLAINTEXT[] = { 0xb8,0x4a,0x90,0xfc,0x6d };
    const uint8_t CIPHERTEXT[] = { 0x1a,0x9a,0x61,0xc3,0x07 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-5", "[CFB8][MMT][128][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0xec,0x89,0xfb,0x34,0x87,0x87,0xcf,0x90,0x2c,0xa9,0x73,0xc4,0x70,0x81,0x43,0x8d };
    const uint8_t IV[] = { 0x52,0x8f,0xe9,0x5c,0x71,0x1b,0xd1,0x3f,0x37,0xbc,0x52,0xcc,0x9e,0x96,0xd4,0x5c };
    const uint8_t PLAINTEXT[] = { 0x14,0x25,0x34,0x72,0xe9,0x9d };
    const uint8_t CIPHERTEXT[] = { 0xcf,0xc2,0x47,0xe3,0x3a,0x3b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-6", "[CFB8][MMT][128][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x66,0x07,0x98,0x7c,0x35,0x48,0x09,0xcb,0xa8,0x18,0x63,0x9d,0xcd,0x18,0x51,0x47 };
    const uint8_t IV[] = { 0x55,0x2c,0x10,0x1a,0x0b,0x7c,0x0c,0xa1,0x43,0xaf,0x25,0x84,0x53,0x93,0x7f,0xa3 };
    const uint8_t PLAINTEXT[] = { 0x9b,0x1a,0x5a,0x13,0x69,0x16,0x6e };
    const uint8_t CIPHERTEXT[] = { 0xb7,0xab,0x2a,0x4c,0xc7,0x19,0x04 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-7", "[CFB8][MMT][128][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0xc0,0x28,0xe6,0xbf,0x2b,0x74,0x9f,0xfa,0x86,0x75,0x9f,0x2f,0x84,0xe9,0x3c,0xb0 };
    const uint8_t IV[] = { 0x28,0x8c,0x75,0x2d,0x9f,0xac,0xcf,0x36,0x7e,0x5d,0x0c,0xca,0x1f,0xa6,0xec,0x3b };
    const uint8_t PLAINTEXT[] = { 0x32,0x40,0x15,0x87,0x8c,0xdc,0x82,0xbf };
    const uint8_t CIPHERTEXT[] = { 0x87,0x32,0x50,0x15,0x2f,0xc6,0xa5,0xbb };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-8", "[CFB8][MMT][128][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0xd0,0x1d,0xa9,0x5d,0x2c,0x2a,0x61,0xda,0x06,0xea,0x78,0xcf,0xba,0x59,0xcc,0x30 };
    const uint8_t IV[] = { 0xf9,0xa3,0x93,0xad,0x90,0x81,0x4f,0xaf,0x26,0x2e,0x3a,0x5b,0x1d,0x97,0x59,0x2e };
    const uint8_t PLAINTEXT[] = { 0x57,0xc1,0xa3,0x0e,0x48,0x16,0x6d,0x96,0x40 };
    const uint8_t CIPHERTEXT[] = { 0xe9,0xa8,0xc3,0xb7,0x76,0xed,0xd3,0x9e,0x3d };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-ENCRYPT-9", "[CFB8][MMT][128][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x3a,0x6f,0x91,0x59,0x26,0x3f,0xa6,0xce,0xf2,0xa0,0x75,0xca,0xfa,0xce,0x58,0x17 };
    const uint8_t IV[] = { 0x0f,0xc2,0x36,0x62,0xb7,0xdb,0xf7,0x38,0x27,0xf0,0xc7,0xde,0x32,0x1c,0xa3,0x6e };
    const uint8_t PLAINTEXT[] = { 0x87,0xef,0xeb,0x8d,0x55,0x9e,0xd3,0x36,0x77,0x28 };
    const uint8_t CIPHERTEXT[] = { 0x8e,0x9c,0x50,0x42,0x56,0x14,0xd5,0x40,0xce,0x11 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-0", "[CFB8][MMT][128][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x03,0xed,0xfe,0x08,0x25,0x50,0xbd,0x5a,0xc8,0xdd,0xf6,0x4f,0x42,0xa0,0x54,0x7f };
    const uint8_t IV[] = { 0x52,0xac,0xd8,0xda,0xb6,0x2c,0x98,0x1d,0xa0,0x8e,0x51,0x93,0x9c,0xc0,0x8d,0xab };
    const uint8_t PLAINTEXT[] = { 0x09 };
    const uint8_t CIPHERTEXT[] = { 0x21 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-1", "[CFB8][MMT][128][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x38,0xcf,0x77,0x67,0x50,0x16,0x2e,0xdc,0x63,0xc3,0xb5,0xdb,0xe3,0x11,0xab,0x9f };
    const uint8_t IV[] = { 0x98,0xfb,0xbd,0x28,0x88,0x72,0xc4,0x0f,0x19,0x26,0xb1,0x6e,0xca,0xec,0x15,0x61 };
    const uint8_t PLAINTEXT[] = { 0xeb,0x24 };
    const uint8_t CIPHERTEXT[] = { 0x48,0x78 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-2", "[CFB8][MMT][128][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0xc9,0x05,0x3c,0x87,0xc3,0xe5,0x6b,0xc5,0xe5,0x2b,0xd3,0x1f,0x65,0x45,0xf9,0x91 };
    const uint8_t IV[] = { 0xb8,0xf9,0x64,0x0d,0x09,0x23,0xda,0x13,0xfe,0x6e,0xb8,0x7b,0x01,0xf0,0xcf,0xa0 };
    const uint8_t PLAINTEXT[] = { 0x91,0x09,0x49 };
    const uint8_t CIPHERTEXT[] = { 0xae,0xb6,0xd2 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-3", "[CFB8][MMT][128][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0xe9,0x67,0x71,0xf5,0xf2,0x0a,0x89,0xee,0x87,0x12,0x61,0xd2,0xd1,0x8e,0x1e,0x46 };
    const uint8_t IV[] = { 0x6e,0x86,0x40,0x3e,0x33,0x39,0x66,0x55,0x90,0x7a,0xe0,0x6e,0xf1,0x92,0x26,0x2f };
    const uint8_t PLAINTEXT[] = { 0x3b,0x7f,0x1f,0x1c };
    const uint8_t CIPHERTEXT[] = { 0x83,0xca,0xb2,0xf3 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-4", "[CFB8][MMT][128][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x92,0xad,0x13,0xec,0xb6,0x0b,0xde,0x1b,0xb3,0xb3,0x4c,0xe0,0x78,0x67,0x67,0x2b };
    const uint8_t IV[] = { 0xf9,0x5a,0x40,0x60,0xb8,0xf8,0x0e,0x3f,0x83,0x9d,0x4c,0x3c,0xa3,0x3d,0xad,0x94 };
    const uint8_t PLAINTEXT[] = { 0x17,0xb9,0xb9,0xe1,0x6d };
    const uint8_t CIPHERTEXT[] = { 0x49,0xf7,0x3e,0x65,0x2b };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-5", "[CFB8][MMT][128][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0xeb,0x57,0xb8,0xdd,0x07,0x6e,0x7b,0xbb,0x33,0xd4,0xbf,0xc4,0xd7,0xec,0xb2,0x7e };
    const uint8_t IV[] = { 0x51,0x13,0x59,0x97,0xa0,0x67,0xdc,0xd2,0xe0,0x16,0xc5,0x71,0x34,0xc5,0xfa,0x52 };
    const uint8_t PLAINTEXT[] = { 0xca,0x98,0x9f,0xa4,0xe8,0x18 };
    const uint8_t CIPHERTEXT[] = { 0xb0,0xea,0xcb,0xf2,0xca,0x46 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-6", "[CFB8][MMT][128][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0x70,0xab,0xc4,0x8b,0xb1,0xbe,0x49,0x01,0x83,0xf0,0xfe,0x3d,0xf5,0x61,0x95,0xff };
    const uint8_t IV[] = { 0xe2,0x51,0xf1,0x79,0x17,0x4b,0x71,0xee,0x1e,0x48,0x8a,0xb3,0xdd,0x20,0x04,0x83 };
    const uint8_t PLAINTEXT[] = { 0x54,0x05,0xda,0x11,0x86,0xb7,0xe0 };
    const uint8_t CIPHERTEXT[] = { 0x08,0xfb,0xef,0x9b,0x2a,0x36,0x9a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-7", "[CFB8][MMT][128][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x12,0x73,0xb8,0xe0,0xee,0xe1,0xa1,0xca,0x82,0x70,0x59,0xb4,0xd0,0xa3,0xa5,0x5d };
    const uint8_t IV[] = { 0x62,0x2c,0xab,0x49,0x09,0x2d,0x02,0x6f,0x55,0x4d,0xd9,0x8a,0x64,0x41,0xdc,0x26 };
    const uint8_t PLAINTEXT[] = { 0xd4,0x97,0xdf,0x73,0xaf,0xb9,0x78,0x7c };
    const uint8_t CIPHERTEXT[] = { 0xb3,0xcb,0x9d,0x88,0x92,0x42,0x3a,0xeb };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-8", "[CFB8][MMT][128][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0x49,0x43,0x7e,0x06,0xb6,0xfa,0xa5,0xf2,0x0f,0xd9,0x8b,0xf7,0x1f,0x8f,0xf5,0x54 };
    const uint8_t IV[] = { 0x63,0xc8,0x18,0xe0,0xd3,0xcb,0x5b,0x70,0x54,0xef,0x3e,0x1e,0x87,0xdf,0x0e,0x12 };
    const uint8_t PLAINTEXT[] = { 0xf2,0x03,0xbc,0xd4,0x02,0xb6,0x59,0x19,0xda };
    const uint8_t CIPHERTEXT[] = { 0x01,0x99,0x2a,0x98,0x62,0x79,0xc3,0x68,0x5e };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MMT128-DECRYPT-9", "[CFB8][MMT][128][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0x63,0x99,0xc1,0xdc,0x06,0x8b,0xa3,0x50,0x98,0x45,0x62,0x8f,0xa9,0xed,0x1a,0x96 };
    const uint8_t IV[] = { 0x11,0x57,0xc2,0x76,0x6c,0x86,0xb7,0x54,0xdf,0x48,0x5b,0xe9,0xdd,0x58,0x51,0xdf };
    const uint8_t PLAINTEXT[] = { 0xfe,0xff,0x4e,0x2e,0x24,0x58,0xad,0xdf,0x2a,0x54 };
    const uint8_t CIPHERTEXT[] = { 0xc9,0xc2,0x84,0xe9,0xab,0xbf,0xe6,0xfb,0x11,0xfe };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

