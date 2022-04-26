// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <key.h>
#include <pubkey.h>
#include <random.h>

#include <vector>

CKey GetRandomKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

static void ECDH(benchmark::Bench& bench)
{
    ECC_Start();
    auto privkey = GetRandomKey();
    auto other_privkey = GetRandomKey();
    auto other_pubkey = other_privkey.GetPubKey();

    std::vector<uint8_t> ellsq_bytes;
    ellsq_bytes.resize(64);
    GetRandBytes(ellsq_bytes.data(), 32);
    GetRandBytes(ellsq_bytes.data() + 32, 32);

    std::vector<uint8_t> other_ellsq_bytes;
    other_ellsq_bytes.resize(64);
    GetRandBytes(other_ellsq_bytes.data(), 32);
    GetRandBytes(other_ellsq_bytes.data() + 32, 32);

    ECDHSecret ecdh_secret;
    bench.batch(1).unit("ecdh").run([&] {
        privkey.ComputeBIP324ECDHSecret(other_pubkey, ellsq_bytes, other_ellsq_bytes, ecdh_secret);
    });
    ECC_Stop();
}

BENCHMARK(ECDH);
