// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <pubkey.h>
#include <random.h>

#include <array>

EllSwiftPubKey GetRandomEllSwift()
{
    EllSwiftPubKey encoded_pubkey;

    // GetRandBytes can only give us up to 32 bytes at a time
    GetRandBytes({encoded_pubkey.data(), 32});
    GetRandBytes({encoded_pubkey.data() + 32, 32});

    return encoded_pubkey;
}

static void EllSwiftEncode(benchmark::Bench& bench)
{
    std::array<uint8_t, 32> rnd32;
    GetRandBytes(rnd32);

    // Any 64 bytes are a valid encoding for a public key.
    EllSwiftPubKey encoded_pubkey = GetRandomEllSwift();
    CPubKey pubkey{encoded_pubkey};
    bench.batch(1).unit("pubkey").run([&] {
        pubkey.EllSwiftEncode(rnd32);
    });
}

static void EllSwiftDecode(benchmark::Bench& bench)
{
    // Any 64 bytes are a valid encoding for a public key.
    EllSwiftPubKey encoded_pubkey = GetRandomEllSwift();
    bench.batch(1).unit("pubkey").run([&] {
        CPubKey pubkey{encoded_pubkey};
    });
}

BENCHMARK(EllSwiftEncode);
BENCHMARK(EllSwiftDecode);
