#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <openssl/sha.h>

#include "./hash-suite/MurmurHash3.h"
#include "./hash-suite/xxh3.h"

namespace Hash32
{
    constexpr char ALGO_MURMUR3_32[] = "murmur3_32";
    constexpr char ALGO_MURMUR3_128[] = "murmur3_128";
    constexpr char ALGO_SHA256[] = "sha256";
    constexpr char ALGO_XXH3[] = "xxh3";

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

    std::vector<uint32_t> HashSHA256_32(keyType &data, uint32_t seed = 0)
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
        throw std::invalid_argument("Invalid algorithm");
    }
}
