// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_CHACHA20_H
#define BITCOIN_CRYPTO_CHACHA20_H

#include <array>
#include <cstddef>
#include <stdint.h>
#include <stdlib.h>

/** A class for ChaCha20 256-bit stream cipher developed by Daniel J. Bernstein
    https://cr.yp.to/chacha/chacha-20080128.pdf */
class ChaCha20
{
private:
    uint32_t input[16];
    uint8_t prev_block_bytes[64];
    uint8_t prev_block_start_pos{0};
    bool is_rfc8439{false};

public:
    ChaCha20();
    ChaCha20(const unsigned char* key, size_t keylen);
    void SetKey(const unsigned char* key, size_t keylen); //!< set key with flexible keylength; 256bit recommended */
    void SetIV(uint64_t iv); // set the 64bit nonce
    void Seek(uint64_t pos); // set the 64bit block counter

    void SetRFC8439Nonce(const std::array<std::byte, 12>& nonce);
    void SeekRFC8439(uint32_t pos);

    /** outputs the keystream of size <bytes> into <c> */
    void Keystream(unsigned char* c, size_t bytes);

    /** enciphers the message <input> of length <bytes> and write the enciphered representation into <output>
     *  Used for encryption and decryption (XOR)
     */
    void Crypt(const unsigned char* input, unsigned char* output, size_t bytes);
};

#endif // BITCOIN_CRYPTO_CHACHA20_H
