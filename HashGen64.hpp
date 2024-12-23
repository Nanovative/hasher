#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <iostream>
#include "HashFunc64.hpp" // Assuming you have a 64-bit version of the Hash32 class

namespace Hash64
{
    constexpr char SCHEME_SERIAL[] = "serial";
    constexpr char SCHEME_PARALLEL[] = "parellel";
    constexpr char SCHEME_KIRSCH_MITZENMACHER[] = "kir-mitz";
    constexpr char SCHEME_ENHANCED_DOUBLE_HASHING[] = "edh";

    class HashGen
    {
    public:
        HashGen(uint64_t k = 1, uint64_t maxRange = 0) : k_(k), maxRange_(maxRange) {
            std::cout << "Hash range of Hash Gen = " << maxRange_ << std::endl;
        }

        std::vector<uint64_t> Serial(
            const std::vector<uint8_t> &data,
            const std::string &algorithm)
        {
            std::vector<uint64_t> vec;

            for (int i = 0; i < k_; ++i)
            {
                std::vector<uint64_t> hashArray = Hash64::Generate(data, algorithm, i);
                vec.push_back(this->moduloHash(hashArray[0]));
            }

            return vec;
        }

        std::vector<uint64_t> KirMitz(
            const std::vector<uint8_t> &data,
            const std::string &algorithm)
        {
            std::vector<uint64_t> vec;

            std::vector<uint64_t> hashArray = Hash64::Generate(data, algorithm);
            vec.push_back(this->moduloHash(hashArray[0]));

            for (int i = 1; i < k_; ++i)
            {
                uint64_t h1 = hashArray[0];
                uint64_t h2 = i;

                if (hashArray.size() > 1)
                {
                    h2 *= hashArray[1];
                }

                uint64_t hash = h1 + h2;
                vec.push_back(this->moduloHash(hash));
            }

            return vec;
        }

        std::vector<uint64_t> EDH(
            const std::vector<uint8_t> &data,
            const std::string &algorithm)
        {
            std::vector<uint64_t> vec;

            std::vector<uint64_t> hashArray = Hash64::Generate(data, algorithm);
            vec.push_back(this->moduloHash(hashArray[0]));

            for (int i = 1; i < k_; ++i)
            {
                uint64_t newSeed = i + 3;
                if (hashArray.size() > 1)
                {
                    hashArray[0] = this->moduloHash(hashArray[0] + hashArray[1]);
                    hashArray[1] = this->moduloHash(hashArray[1] + newSeed);
                }
                else
                {
                    hashArray[0] = this->moduloHash(hashArray[0] + newSeed);
                }
                vec.push_back(hashArray[0]);
            }

            return vec;
        }

        std::vector<uint64_t> Execute(
            const std::vector<uint8_t> &data,
            const std::string &algorithm,
            const std::string &scheme = SCHEME_SERIAL)
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
            return {};
        }

        uint64_t MaxRange() {
            return maxRange_;
        }

    private:
        uint64_t k_;        // Number of hash functions
        uint64_t maxRange_; // Maximum range for the hashes

        uint64_t moduloHash(uint64_t rawHash)
        {
            if (maxRange_ < 1)
            {
                return rawHash;
            }
            return rawHash % maxRange_;
        }
    };

}
