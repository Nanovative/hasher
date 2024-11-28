#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include "HashFunc32.hpp"

namespace Hash32
{
    constexpr char SCHEME_SERIAL[] = "serial";
    constexpr char SCHEME_PARALLEL[] = "parellel";
    constexpr char SCHEME_KIRSCH_MITZENMACHER[] = "kir-mitz";
    constexpr char SCHEME_ENHANCED_DOUBLE_HASHING[] = "edh";

    class HashGen
    {
    public:
        HashGen(int k = 1, uint32_t maxRange = 0) : k_(k), maxRange_(maxRange) {}

        std::vector<uint32_t> *Serial(
            const std::vector<uint8_t> &data,
            const std::string &algorithm,
            std::vector<uint32_t> *hashes = nullptr)
        {
            if (hashes == nullptr)
            {
                std::vector<uint32_t> vec = std::vector<uint32_t>();
                hashes = &vec;
            }

            for (int i = 0; i < k_; ++i)
            {
                std::vector<uint32_t> hashArray = Hash32::Generate(data, algorithm, i);
                hashes->push_back(this->moduloHash(hashArray[0]));
            }

            return hashes;
        }

        std::vector<uint32_t> *KirMitz(
            const std::vector<uint8_t> &data,
            const std::string &algorithm,
            std::vector<uint32_t> *hashes = nullptr)
        {
            if (hashes == nullptr)
            {
                std::vector<uint32_t> vec = std::vector<uint32_t>();
                hashes = &vec;
            }
            std::vector<uint32_t> hashArray = Hash32::Generate(data, algorithm);
            hashes->push_back(this->moduloHash(hashArray[0]));

            for (int i = 1; i < k_; ++i)
            {
                uint32_t h1 = hashArray[0];
                uint32_t h2 = i;

                if (hashArray.size() > 1)
                {
                    h2 *= hashArray[1];
                }

                uint32_t hash = h1 + h2;
                hashes->push_back(this->moduloHash(hash));
            }

            return hashes;
        }

        std::vector<uint32_t> *EDH(
            const std::vector<uint8_t> &data,
            const std::string &algorithm,
            std::vector<uint32_t> *hashes = nullptr)
        {
            if (hashes == nullptr)
            {
                std::vector<uint32_t> vec = std::vector<uint32_t>();
                hashes = &vec;
            }
            std::vector<uint32_t> hashArray = Hash32::Generate(data, algorithm);
            hashes->push_back(hashArray[0]);

            for (int i = 1; i < k_; ++i)
            {
                uint32_t newSeed = i + 3;
                if (hashArray.size() > 1)
                {
                    hashArray[0] = this->moduloHash(hashArray[0] + hashArray[1]);
                    hashArray[1] = this->moduloHash(hashArray[1] + newSeed);
                }
                else
                {
                    hashArray[0] = this->moduloHash(hashArray[0] + newSeed);
                }
                hashes->push_back(hashArray[0]);
            }
            return hashes;
        }

        std::vector<uint32_t> *Execute(
            const std::vector<uint8_t> &data,
            const std::string &algorithm,
            const std::string &scheme = SCHEME_SERIAL,
            std::vector<uint32_t> *hashes = nullptr)
        {
            if (scheme == SCHEME_SERIAL)
            {
                return this->Serial(data, algorithm);
            }
            if (scheme == SCHEME_KIRSCH_MITZENMACHER)
            {
                return this->KirMitz(data, algorithm);
            }
            if (scheme == SCHEME_ENHANCED_DOUBLE_HASHING)
            {
                return this->EDH(data, algorithm);
            }
            return nullptr;
        }

    private:
        int k_;        // Number of hash functions
        uint32_t maxRange_; // Maximum range for the hashes
        uint32_t moduloHash(uint32_t rawHash)
        {
            if (maxRange_ < 1)
            {
                return rawHash;
            }
            return rawHash % maxRange_;
        }
    };

}
