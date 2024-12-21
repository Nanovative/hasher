#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <iostream>
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
        HashGen(uint32_t k = 1, uint32_t maxRange = 0) : k_(k), maxRange_(maxRange)
        {
            std::cout << "Hash range of Hash Gen = " << maxRange_ << std::endl;
        }

        std::vector<uint32_t> Serial(
            const std::vector<uint8_t> &data,
            const std::string &algorithm)
        {
            std::vector<uint32_t> vec;

            for (int i = 0; i < k_; ++i)
            {
                std::vector<uint32_t> hashArray = Hash32::Generate(data, algorithm, i);
                vec.push_back(this->moduloHash(hashArray[0]));
            }

            return vec;
        }

        std::vector<uint32_t> KirMitz(
            const std::vector<uint8_t> &data,
            const std::string &algorithm)
        {
            std::vector<uint32_t> vec;
            uint32_t baseSeed = 0;
            uint32_t altSeed = baseSeed + data.size();

            std::vector<uint32_t> hashArray = Hash32::Generate(data, algorithm, baseSeed);

            if (hashArray.size() <= 1)
            {
                std::vector<uint32_t> subHashArray = Hash32::Generate(data, algorithm, altSeed);
                hashArray.push_back(subHashArray[0]);
            }

            vec.push_back(this->moduloHash(hashArray[0]));

            for (int i = 1; i < k_; ++i)
            {
                uint32_t h1 = hashArray[0];
                uint32_t h2 = i;

                h2 *= hashArray[1];

                uint32_t hash = h1 + h2;
                vec.push_back(this->moduloHash(hash));
            }

            return vec;
        }

        std::vector<uint32_t> EDH(
            const std::vector<uint8_t> &data,
            const std::string &algorithm)
        {
            std::vector<uint32_t> vec;
            uint32_t baseSeed = 0;
            uint32_t altSeed = baseSeed + data.size();
            std::vector<uint32_t> hashArray = Hash32::Generate(data, algorithm);

            if (hashArray.size() <= 1)
            {
                std::vector<uint32_t> subHashArray = Hash32::Generate(data, algorithm, altSeed);
                hashArray.push_back(subHashArray[0]);
            }

            vec.push_back(this->moduloHash(hashArray[0]));

            for (int i = 1; i < k_; ++i)
            {
                uint32_t newSeed = i + 3;
                hashArray[0] = this->moduloHash(hashArray[0] + hashArray[1]);
                hashArray[1] = this->moduloHash(hashArray[1] + newSeed);
                vec.push_back(hashArray[0]);
            }
            return vec;
        }

        std::vector<uint32_t> Execute(
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

        uint32_t MaxRange()
        {
            return maxRange_;
        }

    private:
        uint32_t k_;        // Number of hash functions
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
