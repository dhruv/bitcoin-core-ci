// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_RFC8439_H
#define BITCOIN_CRYPTO_RFC8439_H

#include <crypto/chacha20.h>
#include <crypto/poly1305.h>
#include <span.h>

#include <array>
#include <cstddef>
#include <vector>

constexpr static size_t RFC8439_KEYLEN = 32;
constexpr static size_t RFC8439_TAGLEN = POLY1305_TAGLEN;

struct RFC8439Encrypted {
    std::vector<std::byte> ciphertext;
    std::array<std::byte, RFC8439_TAGLEN> tag;
};

struct RFC8439Decrypted {
    bool success;
    std::vector<std::byte> plaintext;
};

std::array<std::byte, RFC8439_TAGLEN> ComputeRFC8439Tag(const std::array<std::byte, POLY1305_KEYLEN>& polykey,
                                                        Span<const std::byte> aad, Span<const std::byte> ciphertext);

std::array<std::byte, POLY1305_KEYLEN> GetPoly1305Key(ChaCha20& c20);

RFC8439Encrypted RFC8439Encrypt(Span<const std::byte> aad, Span<const std::byte> key, const std::array<std::byte, 12>& nonce, const std::vector<Span<const std::byte>>& plaintexts);

RFC8439Decrypted RFC8439Decrypt(Span<const std::byte> aad, Span<const std::byte> key, const std::array<std::byte, 12>& nonce, const RFC8439Encrypted& encrypted);
#endif // BITCOIN_CRYPTO_RFC8439_H
