#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/sha.h>

#include "./hash-suite/MurmurHash3.h"
#include "./hash-suite/xxh3.h"

namespace Hash64
{
    constexpr char ALGO_MURMUR3_128[] = "murmur3_128";
    constexpr char ALGO_SHA256[] = "sha256";
    constexpr char ALGO_XXH3[] = "xxh3";

    using keyType = const std::vector<uint8_t>;
    constexpr size_t SHA256_NUM_64BIT_WORDS = SHA256_DIGEST_LENGTH / sizeof(uint64_t);

    uint64_t HashBytesToUInt64(keyType &hashBytes, int offset = 0)
    {
        // Ensure offset is within bounds
        if (offset * 8 + 8 > hashBytes.size())
        {
            throw std::out_of_range("Offset exceeds hashBytes size");
        }

        // Combine 8 bytes into a 64-bit integer
        uint8_t h1 = hashBytes[offset * 4 + 0];
        uint8_t h2 = hashBytes[offset * 4 + 1];
        uint8_t h3 = hashBytes[offset * 4 + 2];
        uint8_t h4 = hashBytes[offset * 4 + 3];

        uint8_t h5 = hashBytes[offset * 4 + 4];
        uint8_t h6 = hashBytes[offset * 4 + 5];
        uint8_t h7 = hashBytes[offset * 4 + 6];
        uint8_t h8 = hashBytes[offset * 4 + 7];

        uint64_t h = h1 |
                     (static_cast<uint64_t>(h2) << 8) |
                     (static_cast<uint64_t>(h3) << 16) |
                     (static_cast<uint64_t>(h4) << 24) |
                     (static_cast<uint64_t>(h5) << 32) |
                     (static_cast<uint64_t>(h6) << 40) |
                     (static_cast<uint64_t>(h7) << 48) |
                     (static_cast<uint64_t>(h8) << 56);

        return h;
    }

    std::vector<uint64_t> HashMurmur3_x64_128(keyType &data, uint64_t seed = 0)
    {
        uint64_t hashArray[2];
        MurmurHash3_x64_128(data.data(), data.size(), seed, &hashArray);
        return {hashArray[0], hashArray[1]};
    }

    std::vector<uint64_t> HashSHA256_64(keyType &data, uint64_t seed = 0)
    {
        std::vector<uint8_t> seededData(data);
        if (seed != 0)
        {
            // Mix the seed into the data by appending its bytes
            for (int i = 0; i < 8; ++i)
            {
                seededData.push_back(static_cast<uint8_t>((seed >> (i * 8)) & 0xFF));
            }
        }

        // Compute SHA256
        std::vector<uint8_t> hashBytes(SHA256_DIGEST_LENGTH);
        SHA256(seededData.data(), seededData.size(), hashBytes.data());

        // Convert hash bytes into 64-bit integers
        std::vector<uint64_t> hashArray;
        for (size_t i = 0; i < SHA256_NUM_64BIT_WORDS; ++i)
        {
            hashArray.push_back(HashBytesToUInt64(hashBytes, i));
        }

        return hashArray;
    }

    std::vector<uint64_t> HashXXH3_64(keyType &data, uint64_t seed = 0)
    {
        uint64_t hash = XXH3_64bits_withSeed(data.data(), data.size(), seed);
        return {hash}; // XXH3 produces a single 64-bit hash.
    }

    std::vector<uint64_t> Generate(keyType &data, const std::string &algorithm = "sha256", uint64_t seed = 0)
    {
        if (algorithm == ALGO_MURMUR3_128)
        {
            return HashMurmur3_x64_128(data, seed);
        }
        if (algorithm == ALGO_SHA256)
        {
            return HashSHA256_64(data, seed);
        }
        if (algorithm == ALGO_XXH3)
        {
            return HashXXH3_64(data, seed);
        }
        throw std::invalid_argument("Invalid algorithm");
    }
}