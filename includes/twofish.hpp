/**
 * @file twofish.hpp
 * @brief Twofish encryption algorithm implementation
 * 
 * This file contains the declaration of the Twofish encryption algorithm class,
 * which supports both uint32_t and uint8_t interfaces for encryption and decryption.
 * Twofish is a symmetric key block cipher with a block size of 128 bits and key sizes
 * of 128, 192, or 256 bits.
 * 
 * @author OpenixIMG Contributors
 * @version 1.0
 */
#ifndef TWOFISH_HPP
#define TWOFISH_HPP

#include <cstdint>
#include <array>
#include <vector>

/**
 * @class Twofish
 * @brief Implements the Twofish symmetric key block cipher
 * 
 * This class provides methods for initializing the cipher with a key, and
 * encrypting and decrypting data blocks. It supports both uint32_t and uint8_t
 * interfaces for convenience.
 */
class Twofish {
    // Lookup tables and key schedule
    std::array<uint32_t, 40> l_key{}; //!< Key schedule for encryption and decryption rounds
    std::array<uint32_t, 4> s_key{};  //!< S-box key derived from the user key
    uint32_t k_len;                   //!< Key length (2, 3, or 4 for 128, 192, or 256 bits)

        /**
         * @brief Finite field multiplication by 01 in GF(2^8)
         * @param x Input byte
         * @return Result of multiplication
         */
        [[nodiscard]] static constexpr uint8_t ffm_01(uint8_t x);

        /**
         * @brief Finite field multiplication by 5B in GF(2^8)
         * @param x Input byte
         * @return Result of multiplication
         */
        [[nodiscard]] static constexpr uint8_t ffm_5b(uint8_t x);

        /**
         * @brief Finite field multiplication by EF in GF(2^8)
         * @param x Input byte
         * @return Result of multiplication
         */
        [[nodiscard]] static constexpr uint8_t ffm_ef(uint8_t x);

        /**
         * @brief S-box function implementation
         * @param n S-box number (0 or 1)
         * @param x Input byte
         * @return Result of S-box substitution
         */
        [[nodiscard]] static constexpr uint8_t qp(int n, uint8_t x);

        /**
         * @brief Wrapper for the S-box function
         * @param n S-box number (0 or 1)
         * @param x Input byte
         * @return Result of S-box substitution
         */
        [[nodiscard]] static constexpr uint8_t q(int n, uint8_t x);

        /**
         * @brief MDS matrix multiplication
         * @param n Matrix index
         * @param x Input byte
         * @return Result of matrix multiplication
         */
        [[nodiscard]] static uint32_t mds(int n, uint8_t x);

        /**
         * @brief H function for key schedule generation
         * @param x Input word
         * @param key Key array
         * @return Result of the H function
         */
        [[nodiscard]] uint32_t h_fun(uint32_t x, const std::array<uint32_t, 4> &key) const;

        /**
         * @brief G0 function for encryption rounds
         * @param x Input word
         * @return Result of the G0 function
         */
        [[nodiscard]] uint32_t g0_fun(uint32_t x) const;

        /**
         * @brief G1 function for encryption rounds
         * @param x Input word
         * @return Result of the G1 function
         */
        [[nodiscard]] uint32_t g1_fun(uint32_t x) const;

        /**
         * @brief Reed-Solomon code remainder calculation
         * @param p0 First polynomial coefficient
         * @param p1 Second polynomial coefficient
         * @return Remainder of polynomial division
         */
        [[nodiscard]] static uint32_t mds_rem(uint32_t p0, uint32_t p1);

    public:
        /**
         * @brief Constructor that initializes with default key values
         * 
         * Creates a Twofish instance with a default test key schedule.
         * The key can be changed later using the initialize methods.
         */
        Twofish();

        /**
         * @brief Initialize the key schedule from a user-supplied key (uint32_t version)
         * @param in_key User-provided key as a vector of uint32_t values
         * @param key_len_bits Length of the key in bits (128, 192, or 256)
         */
        void initialize(const std::vector<uint32_t> &in_key, uint32_t key_len_bits);

        /**
         * @brief Initialize the key schedule from a user-supplied key (uint8_t version)
         * @param in_key User-provided key as a vector of uint8_t values
         * @param key_len_bits Length of the key in bits (128, 192, or 256)
         */
        void initialize(const std::vector<uint8_t> &in_key, uint32_t key_len_bits);

        /**
         * @brief Encrypt a block of text (uint32_t version)
         * @param in_blk Input plaintext block as an array of 4 uint32_t values
         * @param out_blk Output ciphertext block as an array of 4 uint32_t values
         */
        void encrypt(const std::array<uint32_t, 4> &in_blk, std::array<uint32_t, 4> &out_blk) const;

        /**
         * @brief Decrypt a block of text (uint32_t version)
         * @param in_blk Input ciphertext block as an array of 4 uint32_t values
         * @param out_blk Output plaintext block as an array of 4 uint32_t values
         */
        void decrypt(const std::array<uint32_t, 4> &in_blk, std::array<uint32_t, 4> &out_blk) const;

        /**
         * @brief Encrypt a block of text (uint8_t version)
         * @param in_blk Input plaintext block as an array of 16 uint8_t values
         * @param out_blk Output ciphertext block as an array of 16 uint8_t values
         */
        void encrypt(const std::array<uint8_t, 16> &in_blk, std::array<uint8_t, 16> &out_blk) const;

        /**
         * @brief Decrypt a block of text (uint8_t version)
         * @param in_blk Input ciphertext block as an array of 16 uint8_t values
         * @param out_blk Output plaintext block as an array of 16 uint8_t values
         */
        void decrypt(const std::array<uint8_t, 16> &in_blk, std::array<uint8_t, 16> &out_blk) const;
    };

#endif // TWOFISH_HPP
