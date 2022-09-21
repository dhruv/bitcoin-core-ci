// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_CHACHA20_H
#define BITCOIN_CRYPTO_CHACHA20_H

#include <cstdlib>
#include <stdint.h>

// classes for ChaCha20 256-bit stream cipher developed by Daniel J. Bernstein
// https://cr.yp.to/chacha/chacha-20080128.pdf */

/** ChaCha20 cipher that only operates on multiples of 64 bytes. */
class ChaCha20Aligned
{
private:
    uint32_t input[16];

public:
    ChaCha20Aligned();

    /** Initialize a cipher with specified key (see SetKey for arguments). */
    ChaCha20Aligned(const unsigned char* key, size_t keylen);

    /** set key with flexible keylength (16 or 32 bytes; 32 recommended). */
    void SetKey(const unsigned char* key, size_t keylen);

    /** set the 64-bit nonce. */
    void SetIV(uint64_t iv);

    /** set the 64bit block counter (pos seeks to byte position 64*pos). */
    void Seek(uint64_t pos);

    /** outputs the keystream of size <64*blocks> into <c> */
    void Keystream64(unsigned char* c, size_t blocks);

    /** enciphers the message <input> of length <64*blocks> and write the enciphered representation into <output>
     *  Used for encryption and decryption (XOR)
     */
    void Crypt64(const unsigned char* input, unsigned char* output, size_t blocks);
};

/** Unrestricted ChaCha20 cipher. Seeks forward to a multiple of 64 bytes after every operation. */
class ChaCha20
{
private:
    ChaCha20Aligned m_aligned;

public:
    ChaCha20() = default;

    /** Initialize a cipher with specified key (see SetKey for arguments). */
    ChaCha20(const unsigned char* key, size_t keylen) : m_aligned(key, keylen) {}

    /** set key with flexible keylength (16 or 32 bytes; 32 recommended). */
    void SetKey(const unsigned char* key, size_t keylen) { m_aligned.SetKey(key, keylen); }

    /** set the 64-bit nonce. */
    void SetIV(uint64_t iv) { m_aligned.SetIV(iv); }

    /** set the 64bit block counter (pos seeks to byte position 64*pos). */
    void Seek(uint64_t pos) { m_aligned.Seek(pos); }

    /** outputs the keystream of size <bytes> into <c> */
    void Keystream(unsigned char* c, size_t bytes);

    /** enciphers the message <input> of length <bytes> and write the enciphered representation into <output>
     *  Used for encryption and decryption (XOR)
     */
    void Crypt(const unsigned char* input, unsigned char* output, size_t bytes);
};

#endif // BITCOIN_CRYPTO_CHACHA20_H
