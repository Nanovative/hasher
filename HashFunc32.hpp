#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <openssl/sha.h>

#include "./hash-suite/MurmurHash3.h"
#include "./hash-suite/xxh3.h"
#include "./hash-suite/siphash.c"

// NOTE!!: Ported from Hashes.cpp in smhasher to temporarily avoid conflict

// Dedicated to Pippip, the main character in the 'Das Totenschiff' roman, actually the B.Traven himself, his real name was Hermann Albert Otto Maksymilian Feige.
// CAUTION: Add 8 more bytes to the buffer being hashed, usually malloc(...+8) - to prevent out of boundary reads!
// Many thanks go to Yurii 'Hordi' Hordiienko, he lessened with 3 instructions the original 'Pippip', thus:
// objsize: 0x1090-0x1123: 147
uint32_t
FNV1A_Pippip_Yurii(const char *key, int wrdlen, uint32_t seed)
{
#define _PADr_KAZE(x, n) (((x) << (n)) >> (n))
    const char *str = (char *)key;
    const uint32_t PRIME = 591798841;
    uint32_t hash32;
    uint64_t hash64 = (uint64_t)seed ^ UINT64_C(14695981039346656037);
    size_t Cycles, NDhead;
    if (wrdlen > 8)
    {
        Cycles = ((wrdlen - 1) >> 4) + 1;
        NDhead = wrdlen - (Cycles << 3);
#pragma nounroll
        for (; Cycles--; str += 8)
        {
            hash64 = (hash64 ^ (*(uint64_t *)(str))) * PRIME;
            hash64 = (hash64 ^ (*(uint64_t *)(str + NDhead))) * PRIME;
        }
    }
    else
    {
        hash64 = (hash64 ^ _PADr_KAZE(*(uint64_t *)(str + 0), (8 - wrdlen) << 3)) *
                 PRIME;
    }
    hash32 = (uint32_t)(hash64 ^ (hash64 >> 32));
    return hash32 ^ (hash32 >> 16);
#undef _PADr_KAZE
} // Last update: 2019-Oct-30, 14 C lines strong, Kaze.

namespace Hash32
{
    constexpr char ALGO_MURMUR3_32[] = "murmur3_32";
    constexpr char ALGO_MURMUR3_128[] = "murmur3_128";
    constexpr char ALGO_SHA256[] = "sha256";
    constexpr char ALGO_XXH3[] = "xxh3";
    constexpr char ALGO_FNV1A[] = "fnv1a";
    constexpr char ALGO_SIPHASH[] = "siphash";

    unsigned char *sipHashKey = nullptr;

    using keyType = const std::vector<uint8_t>;
    constexpr size_t SHA256_NUM_32BIT_WORDS = SHA256_DIGEST_LENGTH / sizeof(uint32_t);

    uint32_t HashBytesToUInt32(keyType &hashBytes, int offset = 0)
    {
        // Ensure offset is within bounds
        if (offset * 4 + 4 > hashBytes.size())
        {
            throw std::out_of_range("Offset exceeds hashBytes size");
        }

        // Combine 4 bytes into a 32-bit integer
        return hashBytes[offset * 4 + 0] |
               (static_cast<uint32_t>(hashBytes[offset * 4 + 1]) << 8) |
               (static_cast<uint32_t>(hashBytes[offset * 4 + 2]) << 16) |
               (static_cast<uint32_t>(hashBytes[offset * 4 + 3]) << 24);
    }

    std::vector<uint32_t> HashMurmur3_x86_32(keyType &data, uint32_t seed = 0)
    {
        uint32_t hash;
        MurmurHash3_x86_32(data.data(), data.size(), seed, &hash);
        return {hash};
    }

    std::vector<uint32_t> HashMurmur3_x86_128(keyType &data, uint32_t seed = 0)
    {
        uint32_t hashArray[4];
        MurmurHash3_x86_128(data.data(), data.size(), seed, &hashArray);
        return {hashArray[0], hashArray[1], hashArray[2], hashArray[3]};
    }

    std::vector<uint8_t> HashSHA256_8(keyType &data, uint32_t seed = 0)
    {
        std::vector<uint8_t> seededData(data);
        if (seed != 0)
        {
            // Mix the seed into the data by appending its bytes
            for (int i = 0; i < 4; ++i)
            {
                seededData.push_back(static_cast<uint8_t>((seed >> (i * 8)) & 0xFF));
            }
        }

        // Compute SHA256
        std::vector<uint8_t> hashBytes(SHA256_DIGEST_LENGTH);
        SHA256(seededData.data(), seededData.size(), hashBytes.data());

        return hashBytes;
    }

    std::vector<uint32_t> HashSHA256_32(keyType &data, uint32_t seed = 0)
    {
        std::vector<uint8_t> hashBytes = HashSHA256_8(data, seed);

        // Convert hash bytes into 32-bit integers
        std::vector<uint32_t> hashArray;
        for (size_t i = 0; i < SHA256_NUM_32BIT_WORDS; ++i)
        {
            uint32_t h = HashBytesToUInt32(hashBytes, i);
            hashArray.push_back(h);
        }

        return hashArray;
    }

    std::vector<uint32_t> HashXXH3_32(keyType &data, uint32_t seed = 0)
    {
        uint32_t hash = static_cast<uint32_t>(XXH32(data.data(), data.size(), seed));
        return {hash};
    }

    std::vector<uint32_t> HashHalfSipHash_32(keyType &data, uint32_t seed = 0)
    {
        if (sipHashKey == nullptr)
        {
            std::string __sipHashKeyStr = "this is a siphash secret key for testing purpose: not secure";
            std::vector<uint8_t> __sipHashKey = HashSHA256_8(
                std::vector<uint8_t>(
                    __sipHashKeyStr.begin(),
                    __sipHashKeyStr.end()),
                0);
            sipHashKey = new unsigned char[16];
            std::copy(__sipHashKey.begin(), __sipHashKey.begin() + std::min(__sipHashKey.size(), size_t(16)), sipHashKey);
        }
        uint32_t hash = halfsiphash(sipHashKey, data.data(), data.size());
        return {hash};
    }

    std::vector<uint32_t> HashFNV1a_32(keyType &data, uint32_t seed = 0)
    {
        uint32_t hash = FNV1A_Pippip_Yurii(
            reinterpret_cast<const char *>(data.data()),
            data.size(),
            0);
        return {hash};
    }

    std::vector<uint32_t> Generate(keyType &data, const std::string &algorithm = "sha256", uint32_t seed = 0)
    {
        if (algorithm == ALGO_MURMUR3_32)
        {
            return HashMurmur3_x86_32(data, seed);
        }
        if (algorithm == ALGO_MURMUR3_128)
        {
            return HashMurmur3_x86_128(data, seed);
        }
        if (algorithm == ALGO_SHA256)
        {
            return HashSHA256_32(data, seed);
        }
        if (algorithm == ALGO_XXH3)
        {
            return HashXXH3_32(data, seed);
        }
        if (algorithm == ALGO_FNV1A)
        {
            return HashFNV1a_32(data, seed);
        }
        if (algorithm == ALGO_SIPHASH)
        {
            return HashHalfSipHash_32(data, seed);
        }
        throw std::invalid_argument("Invalid algorithm");
    }
}
