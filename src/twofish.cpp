/**
 * @file twofish.cpp
 * @brief Twofish encryption algorithm implementation
 * 
 * This file contains the implementation of the Twofish encryption algorithm class,
 * including key schedule generation, encryption, and decryption operations.
 * 
 * @author OpenixIMG Contributors
 * @version 1.0
 */
#include <cstdint>
#include <array>
#include <vector>
#include <string>

#include "twofish.hpp"

/**
 * @brief Constants for the Twofish algorithm
 * 
 * G_M is the generator polynomial, G_MOD is the modulus polynomial for
 * finite field arithmetic in GF(2^8).
 */
constexpr uint32_t G_M = 0x0169;
constexpr uint32_t G_MOD = 0x0000014d;

// Lookup tables for finite field arithmetic
constexpr std::array<uint8_t, 4> tab_5b = {0, G_M >> 2, G_M >> 1, (G_M >> 1) ^ (G_M >> 2)};
constexpr std::array<uint8_t, 4> tab_ef = {0, (G_M >> 1) ^ (G_M >> 2), G_M >> 1, G_M >> 2};

// Lookup tables for S-box functions
constexpr std::array<std::array<uint8_t, 16>, 2> qt0 = {
    {
        {8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4},
        {2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5}
    }
};

constexpr std::array<std::array<uint8_t, 16>, 2> qt1 = {
    {
        {14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13},
        {1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8}
    }
};

constexpr std::array<std::array<uint8_t, 16>, 2> qt2 = {
    {
        {11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1},
        {4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15}
    }
};

constexpr std::array<std::array<uint8_t, 16>, 2> qt3 = {
    {
        {13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10},
        {11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10}
    }
};

constexpr std::array<uint8_t, 16> ror4 = {0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15};
constexpr std::array<uint8_t, 16> ashx = {0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7};

// Circular rotate of 32-bit values
constexpr uint32_t rotr(const uint32_t x, const int n) {
    return ((x >> n) | (x << (32 - n)));
}

constexpr uint32_t rotl(const uint32_t x, const int n) {
    return ((x << n) | (x >> (32 - n)));
}

// Invert byte order in a 32-bit variable
constexpr uint32_t bswap(const uint32_t x) {
    return (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00);
}

// Extract byte from a 32-bit quantity (little endian notation)
constexpr uint8_t byte(const uint32_t x, const int n) {
    return static_cast<uint8_t>((x) >> (8 * n));
}

// Create a 32-bit value from four bytes (little endian)
constexpr uint32_t make_uint32(const uint8_t b0, const uint8_t b1, const uint8_t b2, const uint8_t b3) {
    return static_cast<uint32_t>(b0) |
           static_cast<uint32_t>(b1) << 8 |
           static_cast<uint32_t>(b2) << 16 |
           static_cast<uint32_t>(b3) << 24;
}

/**
 * @brief Convert a uint8_t array to a uint32_t array (little endian)
 * 
 * This helper function converts a 16-byte array into a 4-word array
 * using little-endian byte ordering.
 * 
 * @param in_blk Input byte array (16 bytes)
 * @param out_blk Output word array (4 words)
 */
void bytes_to_words(const std::array<uint8_t, 16> &in_blk, std::array<uint32_t, 4> &out_blk) {
    for (int i = 0; i < 4; ++i) {
        out_blk[i] = make_uint32(
            in_blk[i * 4],
            in_blk[i * 4 + 1],
            in_blk[i * 4 + 2],
            in_blk[i * 4 + 3]
        );
    }
}

/**
 * @brief Convert a uint32_t array to a uint8_t array (little endian)
 * 
 * This helper function converts a 4-word array into a 16-byte array
 * using little-endian byte ordering.
 * 
 * @param in_blk Input word array (4 words)
 * @param out_blk Output byte array (16 bytes)
 */
void words_to_bytes(const std::array<uint32_t, 4> &in_blk, std::array<uint8_t, 16> &out_blk) {
    for (int i = 0; i < 4; ++i) {
        out_blk[i * 4] = byte(in_blk[i], 0);
        out_blk[i * 4 + 1] = byte(in_blk[i], 1);
        out_blk[i * 4 + 2] = byte(in_blk[i], 2);
        out_blk[i * 4 + 3] = byte(in_blk[i], 3);
    }
}

/**
 * @brief Twofish constructor
 * 
 * Initializes the Twofish cipher with a default test key schedule.
 * The key length is set to 2 (128 bits) by default.
 */
Twofish::Twofish() : k_len(2) {
    // Initialize key schedule with default values (for testing)
    l_key = {
        0x4f1a3415, 0xbf541f51, 0x86fdce14, 0xe354f4a1,
        0x616aadf9, 0xf310ee3f, 0xac74403f, 0xc562a030,
        0xb76ff9f8, 0xe9b06896, 0x70c408a2, 0xfe3aedac,
        0x5fa06e5e, 0x61fee97a, 0xa15cba01, 0x3583fafa,
        0xcdb4985a, 0xe7172864, 0x7c003d57, 0xbf9f1b71,
        0xcff1f4ab, 0xbdff4376, 0x57bc905d, 0xe3131a0e,
        0x1007c7ea, 0x4d054e0e, 0x76baa279, 0x35aeb6c0,
        0x398f5e03, 0x3a2c1d70, 0xd6dfbcf8, 0xcaf94cf4,
        0xf67c3460, 0xc808ecd0, 0xd4360d82, 0x5168cf37,
        0xf7a02dbf, 0xdf8968af, 0x27135ef4, 0x41234d48
    };
}

/**
 * @brief Initialize the key schedule from a user-supplied key (uint8_t version)
 * 
 * Converts the uint8_t key to uint32_t format and calls the main initialize method.
 * 
 * @param in_key User-provided key as a vector of uint8_t values
 * @param key_len_bits Length of the key in bits (128, 192, or 256)
 */
void Twofish::initialize(const std::vector<uint8_t> &in_key, const uint32_t key_len_bits) {
    // Convert uint8_t key to uint32_t key
    std::vector<uint32_t> key_words;
    key_words.reserve(in_key.size() / 4);

    for (size_t i = 0; i < in_key.size(); i += 4) {
        uint32_t word = make_uint32(
            in_key[i],
            in_key[i + 1],
            in_key[i + 2],
            in_key[i + 3]
        );
        key_words.push_back(word);
    }

    // Call the original initialize function
    initialize(key_words, key_len_bits);
}

/**
 * @brief Initialize the key schedule from a user-supplied key (uint32_t version)
 * 
 * Generates the key schedule for encryption and decryption operations based on
 * the provided key. Supports key lengths of 128, 192, or 256 bits.
 * 
 * @param in_key User-provided key as a vector of uint32_t values
 * @param key_len_bits Length of the key in bits (128, 192, or 256)
 */
void Twofish::initialize(const std::vector<uint32_t> &in_key, const uint32_t key_len_bits) {
    k_len = key_len_bits / 64; // 2, 3, or 4 for 128, 192, or 256 bits

    std::array<uint32_t, 4> me_key = {0};
    std::array<uint32_t, 4> mo_key = {0};

    for (size_t i = 0; i < k_len; ++i) {
        const uint32_t a = in_key[i * 2];
        const uint32_t b = in_key[i * 2 + 1];
        me_key[i] = a;
        mo_key[i] = b;
        s_key[k_len - i - 1] = mds_rem(a, b);
    }

    // Generate the key schedule
    for (size_t i = 0; i < 40; i += 2) {
        uint32_t a = 0x01010101 * i;
        uint32_t b = a + 0x01010101;
        a = h_fun(a, me_key);
        b = rotl(h_fun(b, mo_key), 8);
        l_key[i] = a + b;
        l_key[i + 1] = rotl(a + 2 * b, 9);
    }
}

/**
 * @brief Encrypt a block of text (uint32_t version)
 * 
 * Encrypts a 128-bit block of plaintext using the Twofish algorithm.
 * The encryption process includes an initial whitening step, 8 rounds of
 * encryption, and a final whitening step.
 * 
 * @param in_blk Input plaintext block as an array of 4 uint32_t values
 * @param out_blk Output ciphertext block as an array of 4 uint32_t values
 */
void Twofish::encrypt(const std::array<uint32_t, 4> &in_blk, std::array<uint32_t, 4> &out_blk) const {
    std::array<uint32_t, 4> blk{};

    blk[0] = in_blk[0] ^ l_key[0];
    blk[1] = in_blk[1] ^ l_key[1];
    blk[2] = in_blk[2] ^ l_key[2];
    blk[3] = in_blk[3] ^ l_key[3];

    // Perform 8 rounds of encryption
    for (int rnd = 0; rnd < 8; ++rnd) {
        uint32_t t1 = g1_fun(blk[1]);
        uint32_t t0 = g0_fun(blk[0]);
        blk[2] = rotr(blk[2] ^ (t0 + t1 + l_key[4 * rnd + 8]), 1);
        blk[3] = rotl(blk[3], 1) ^ (t0 + 2 * t1 + l_key[4 * rnd + 9]);

        t1 = g1_fun(blk[3]);
        t0 = g0_fun(blk[2]);
        blk[0] = rotr(blk[0] ^ (t0 + t1 + l_key[4 * rnd + 10]), 1);
        blk[1] = rotl(blk[1], 1) ^ (t0 + 2 * t1 + l_key[4 * rnd + 11]);
    }

    out_blk[0] = blk[2] ^ l_key[4];
    out_blk[1] = blk[3] ^ l_key[5];
    out_blk[2] = blk[0] ^ l_key[6];
    out_blk[3] = blk[1] ^ l_key[7];
}

/**
 * @brief Encrypt a block of text (uint8_t version)
 * 
 * Encrypts a 128-bit block of plaintext using the Twofish algorithm.
 * This method converts the input bytes to words, calls the word-based encrypt
 * method, and then converts the result back to bytes.
 * 
 * @param in_blk Input plaintext block as an array of 16 uint8_t values
 * @param out_blk Output ciphertext block as an array of 16 uint8_t values
 */
void Twofish::encrypt(const std::array<uint8_t, 16> &in_blk, std::array<uint8_t, 16> &out_blk) const {
    std::array<uint32_t, 4> in_words{};
    std::array<uint32_t, 4> out_words{};

    // Convert input from bytes to words
    bytes_to_words(in_blk, in_words);

    // Use the existing encrypt function
    encrypt(in_words, out_words);

    // Convert output back to bytes
    words_to_bytes(out_words, out_blk);
}

/**
 * @brief Decrypt a block of text (uint8_t version)
 * 
 * Decrypts a 128-bit block of ciphertext using the Twofish algorithm.
 * This method converts the input bytes to words, calls the word-based decrypt
 * method, and then converts the result back to bytes.
 * 
 * @param in_blk Input ciphertext block as an array of 16 uint8_t values
 * @param out_blk Output plaintext block as an array of 16 uint8_t values
 */
void Twofish::decrypt(const std::array<uint8_t, 16> &in_blk, std::array<uint8_t, 16> &out_blk) const {
    std::array<uint32_t, 4> in_words{};
    std::array<uint32_t, 4> out_words{};

    // Convert input from bytes to words
    bytes_to_words(in_blk, in_words);

    // Use the existing decrypt function
    decrypt(in_words, out_words);

    // Convert output back to bytes
    words_to_bytes(out_words, out_blk);
}

/**
 * @brief Decrypt a block of text (uint32_t version)
 * 
 * Decrypts a 128-bit block of ciphertext using the Twofish algorithm.
 * The decryption process includes an initial whitening step, 8 rounds of
 * decryption (performed in reverse order of encryption), and a final whitening step.
 * 
 * @param in_blk Input ciphertext block as an array of 4 uint32_t values
 * @param out_blk Output plaintext block as an array of 4 uint32_t values
 */
void Twofish::decrypt(const std::array<uint32_t, 4> &in_blk, std::array<uint32_t, 4> &out_blk) const {
    std::array<uint32_t, 4> blk{};

    blk[0] = in_blk[0] ^ l_key[4];
    blk[1] = in_blk[1] ^ l_key[5];
    blk[2] = in_blk[2] ^ l_key[6];
    blk[3] = in_blk[3] ^ l_key[7];

    // Perform 8 rounds of decryption (in reverse order)
    for (int rnd = 7; rnd >= 0; --rnd) {
        uint32_t t1 = g1_fun(blk[1]);
        uint32_t t0 = g0_fun(blk[0]);
        blk[2] = rotl(blk[2], 1) ^ (t0 + t1 + l_key[4 * rnd + 10]);
        blk[3] = rotr(blk[3] ^ (t0 + 2 * t1 + l_key[4 * rnd + 11]), 1);

        t1 = g1_fun(blk[3]);
        t0 = g0_fun(blk[2]);
        blk[0] = rotl(blk[0], 1) ^ (t0 + t1 + l_key[4 * rnd + 8]);
        blk[1] = rotr(blk[1] ^ (t0 + 2 * t1 + l_key[4 * rnd + 9]), 1);
    }

    out_blk[0] = blk[2] ^ l_key[0];
    out_blk[1] = blk[3] ^ l_key[1];
    out_blk[2] = blk[0] ^ l_key[2];
    out_blk[3] = blk[1] ^ l_key[3];
}

/**
 * @brief Finite field multiplication by 01 in GF(2^8)
 * 
 * Implements multiplication by 01 (identity function) in the finite field GF(2^8).
 * 
 * @param x Input byte
 * @return Result of multiplication
 */
constexpr uint8_t Twofish::ffm_01(const uint8_t x) {
    return x;
}

/**
 * @brief Finite field multiplication by 5B in GF(2^8)
 * 
 * Implements multiplication by 5B in the finite field GF(2^8) using lookup tables.
 * 
 * @param x Input byte
 * @return Result of multiplication
 */
constexpr uint8_t Twofish::ffm_5b(const uint8_t x) {
    return (x ^ (x >> 2) ^ tab_5b[x & 3]);
}

/**
 * @brief Finite field multiplication by EF in GF(2^8)
 * 
 * Implements multiplication by EF in the finite field GF(2^8) using lookup tables.
 * 
 * @param x Input byte
 * @return Result of multiplication
 */
constexpr uint8_t Twofish::ffm_ef(const uint8_t x) {
    return (x ^ (x >> 1) ^ (x >> 2) ^ tab_ef[x & 3]);
}

/**
 * @brief S-box function implementation
 * 
 * Implements the Twofish S-box substitution using lookup tables and affine transformations.
 * 
 * @param n S-box number (0 or 1)
 * @param x Input byte
 * @return Result of S-box substitution
 */
constexpr uint8_t Twofish::qp(const int n, const uint8_t x) {
    uint8_t a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, b0 = 0, b1 = 0, b2 = 0, b3 = 0, b4 = 0;

    a0 = x >> 4;
    b0 = x & 15;
    a1 = a0 ^ b0;
    b1 = ror4[b0] ^ ashx[a0];
    a2 = qt0[n][a1];
    b2 = qt1[n][b1];
    a3 = a2 ^ b2;
    b3 = ror4[b2] ^ ashx[a2];
    a4 = qt2[n][a3];
    b4 = qt3[n][b3];
    return (b4 << 4) | a4;
}

/**
 * @brief MDS matrix multiplication
 * 
 * Implements the MDS (Maximum Distance Separable) matrix multiplication
 * used in the Twofish algorithm's diffusion layer.
 * 
 * @param n Matrix index (0-3)
 * @param x Input byte
 * @return Result of matrix multiplication as a 32-bit word
 */
uint32_t Twofish::mds(const int n, const uint8_t x) {
    uint32_t f01, f5b, fef;

    switch (n) {
        case 0:
            f01 = q(1, x);
            f5b = ffm_5b(f01);
            fef = ffm_ef(f01);
            return f01 + (f5b << 8) + (fef << 16) + (fef << 24);
        case 1:
            f01 = q(0, x);
            f5b = ffm_5b(f01);
            fef = ffm_ef(f01);
            return fef + (fef << 8) + (f5b << 16) + (f01 << 24);
        case 2:
            f01 = q(1, x);
            f5b = ffm_5b(f01);
            fef = ffm_ef(f01);
            return f5b + (fef << 8) + (f01 << 16) + (fef << 24);
        case 3:
            f01 = q(0, x);
            f5b = ffm_5b(f01);
            fef = ffm_ef(f01);
            return f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
        default:
            return 0;
    }
}

/**
 * @brief H function for key schedule generation
 * 
 * Implements the H function used in the Twofish key schedule generation.
 * The function applies S-box substitutions and finite field operations to
 * generate subkeys from the user-provided key.
 * 
 * @param x Input word
 * @param key Key array
 * @return Result of the H function as a 32-bit word
 */
uint32_t Twofish::h_fun(const uint32_t x, const std::array<uint32_t, 4> &key) const {
    uint8_t b0 = byte(x, 0);
    uint8_t b1 = byte(x, 1);
    uint8_t b2 = byte(x, 2);
    uint8_t b3 = byte(x, 3);

    switch (k_len) {
        case 4:
            b0 = q(1, b0) ^ byte(key[3], 0);
            b1 = q(0, b1) ^ byte(key[3], 1);
            b2 = q(0, b2) ^ byte(key[3], 2);
            b3 = q(1, b3) ^ byte(key[3], 3);
        case 3:
            b0 = q(1, b0) ^ byte(key[2], 0);
            b1 = q(1, b1) ^ byte(key[2], 1);
            b2 = q(0, b2) ^ byte(key[2], 2);
            b3 = q(0, b3) ^ byte(key[2], 3);
        case 2:
            b0 = q(0, q(0, b0) ^ byte(key[1], 0)) ^ byte(key[0], 0);
            b1 = q(0, q(1, b1) ^ byte(key[1], 1)) ^ byte(key[0], 1);
            b2 = q(1, q(0, b2) ^ byte(key[1], 2)) ^ byte(key[0], 2);
            b3 = q(1, q(1, b3) ^ byte(key[1], 3)) ^ byte(key[0], 3);
        default:
            ;
    }

    b0 = q(1, b0);
    b1 = q(0, b1);
    b2 = q(1, b2);
    b3 = q(0, b3);
    const uint32_t m5b_b0 = ffm_5b(b0);
    const uint32_t m5b_b1 = ffm_5b(b1);
    const uint32_t m5b_b2 = ffm_5b(b2);
    const uint32_t m5b_b3 = ffm_5b(b3);
    const uint32_t mef_b0 = ffm_ef(b0);
    const uint32_t mef_b1 = ffm_ef(b1);
    const uint32_t mef_b2 = ffm_ef(b2);
    const uint32_t mef_b3 = ffm_ef(b3);

    b0 ^= mef_b1 ^ m5b_b2 ^ m5b_b3;
    b3 ^= m5b_b0 ^ mef_b1 ^ mef_b2;
    b2 ^= mef_b0 ^ m5b_b1 ^ mef_b3;
    b1 ^= mef_b0 ^ mef_b2 ^ m5b_b3;

    return b0 | (b3 << 8) | (b2 << 16) | (b1 << 24);
}

/**
 * @brief G0 function for encryption rounds
 * 
 * Implements the G0 function used in the Twofish encryption rounds.
 * This function is a wrapper around the H function with the S-key.
 * 
 * @param x Input word
 * @return Result of the G0 function as a 32-bit word
 */
uint32_t Twofish::g0_fun(const uint32_t x) const {
    return h_fun(x, s_key);
}

/**
 * @brief G1 function for encryption rounds
 * 
 * Implements the G1 function used in the Twofish encryption rounds.
 * This function is a wrapper around the H function with a rotated input word.
 * 
 * @param x Input word
 * @return Result of the G1 function as a 32-bit word
 */
uint32_t Twofish::g1_fun(const uint32_t x) const {
    return h_fun(rotl(x, 8), s_key);
}

/**
 * @brief Reed-Solomon code remainder calculation
 * 
 * Implements the Reed-Solomon code remainder calculation used in
 * the Twofish key schedule generation for deriving the S-box keys.
 * 
 * @param p0 First polynomial coefficient
 * @param p1 Second polynomial coefficient
 * @return Remainder of polynomial division as a 32-bit word
 */
uint32_t Twofish::mds_rem(uint32_t p0, uint32_t p1) {
    for (int i = 0; i < 8; ++i) {
        const uint32_t t = p1 >> 24; // Get most significant coefficient
        p1 = (p1 << 8) | (p0 >> 24);
        p0 <<= 8; // Shift others up

        // Multiply t by a (the primitive element - i.e. left shift)
        uint32_t u = (t << 1);
        if (t & 0x80) {
            // Subtract modular polynomial on overflow
            u ^= G_MOD;
        }

        p1 ^= t ^ (u << 16); // Remove t * (a * x^2 + 1)
        u ^= (t >> 1); // Form u = a * t + t / a = t * (a + 1 / a);

        if (t & 0x01) {
            // Add the modular polynomial on underflow
            u ^= G_MOD >> 1;
        }

        p1 ^= (u << 24) | (u << 8); // Remove t * (a + 1/a) * (x^3 + x)
    }

    return p1;
}

/**
 * @brief Wrapper for the q function
 * 
 * Provides a convenient wrapper for the qp function used in the Twofish algorithm.
 * 
 * @param n S-box number (0 or 1)
 * @param x Input byte
 * @return Result of S-box substitution
 */
constexpr uint8_t Twofish::q(const int n, const uint8_t x) {
    return qp(n, x);
}
