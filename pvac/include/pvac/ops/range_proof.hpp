#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <thread>
#include <algorithm>

#include "../core/types.hpp"
#include "verify_zero.hpp"
#include "verify_zero_circuit.hpp"
#include "arithmetic.hpp"
#include "encrypt.hpp"
#include "commit.hpp"

namespace pvac {

static constexpr size_t RANGE_BITS = 64;

struct RangeProof {

    std::vector<Cipher> ct_bit;

    std::vector<ZeroProof> bit_proofs;

    ZeroProof lc_proof;
};

inline RangeProof make_range_proof(
    const PubKey& pk,
    const SecKey& sk,
    const Cipher& ct_value,
    uint64_t value
) {
    RangeProof rp;
    rp.ct_bit.resize(RANGE_BITS);
    rp.bit_proofs.resize(RANGE_BITS);

    unsigned hw = std::thread::hardware_concurrency();
    unsigned n_threads = (hw > 1) ? std::min(hw, (unsigned)RANGE_BITS) : 1;

    if (n_threads <= 1) {
        for (size_t i = 0; i < RANGE_BITS; ++i) {
            uint64_t b_i = (value >> i) & 1;
            rp.ct_bit[i] = enc_value(pk, sk, b_i);
            auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
            uint8_t mul_seed[32];
            for (int k = 0; k < 32; ++k)
                mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
            auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
            rp.bit_proofs[i] = make_zero_proof(pk, sk, ct_check);
        }
    } else {
        auto worker = [&](size_t from, size_t to) {
            for (size_t i = from; i < to; ++i) {
                uint64_t b_i = (value >> i) & 1;
                rp.ct_bit[i] = enc_value(pk, sk, b_i);
                auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
                uint8_t mul_seed[32];
                for (int k = 0; k < 32; ++k)
                    mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
                auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
                rp.bit_proofs[i] = make_zero_proof(pk, sk, ct_check);
            }
        };

        std::vector<std::thread> threads;
        size_t chunk = (RANGE_BITS + n_threads - 1) / n_threads;
        for (unsigned t = 0; t < n_threads; ++t) {
            size_t from = t * chunk;
            size_t to = std::min(from + chunk, RANGE_BITS);
            if (from < to)
                threads.emplace_back(worker, from, to);
        }
        for (auto& th : threads)
            th.join();
    }

    Cipher ct_sum = rp.ct_bit[0];

    for (size_t i = 1; i < RANGE_BITS; ++i) {

        Fp power_of_two;
        if (i < 64) {
            power_of_two = fp_from_u64(1ULL << i);
        } else {

            power_of_two = fp_from_words(0, 1ULL << (i - 64));
        }

        auto scaled = ct_scale(pk, rp.ct_bit[i], power_of_two);
        ct_sum = ct_add(pk, ct_sum, scaled);
    }

    auto ct_lc_diff = ct_sub(pk, ct_sum, ct_value);

    rp.lc_proof = make_zero_proof(pk, sk, ct_lc_diff);

    return rp;
}

inline bool verify_range(
    const PubKey& pk,
    const Cipher& ct_value,
    const RangeProof& rp
) {

    if (rp.ct_bit.size() != RANGE_BITS) return false;
    if (rp.bit_proofs.size() != RANGE_BITS) return false;

    unsigned hw = std::thread::hardware_concurrency();
    unsigned n_threads = (hw > 1) ? std::min(hw, (unsigned)RANGE_BITS) : 1;
    std::vector<bool> results(RANGE_BITS, false);

    if (n_threads <= 1) {
        for (size_t i = 0; i < RANGE_BITS; ++i) {
            auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
            uint8_t mul_seed[32];
            for (int k = 0; k < 32; ++k)
                mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
            auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
            if (!verify_zero(pk, ct_check, rp.bit_proofs[i]))
                return false;
        }
    } else {
        auto worker = [&](size_t from, size_t to) {
            for (size_t i = from; i < to; ++i) {
                auto ct_b_m1 = ct_sub_const(pk, rp.ct_bit[i], (uint64_t)1);
                uint8_t mul_seed[32];
                for (int k = 0; k < 32; ++k)
                    mul_seed[k] = (uint8_t)((i * 37 + k * 13 + 0xA0) & 0xFF);
                auto ct_check = ct_mul_seeded(pk, rp.ct_bit[i], ct_b_m1, mul_seed);
                results[i] = verify_zero(pk, ct_check, rp.bit_proofs[i]);
            }
        };

        std::vector<std::thread> threads;
        size_t chunk = (RANGE_BITS + n_threads - 1) / n_threads;
        for (unsigned t = 0; t < n_threads; ++t) {
            size_t from = t * chunk;
            size_t to = std::min(from + chunk, RANGE_BITS);
            if (from < to)
                threads.emplace_back(worker, from, to);
        }
        for (auto& th : threads)
            th.join();

        for (size_t i = 0; i < RANGE_BITS; ++i) {
            if (!results[i]) return false;
        }
    }

    Cipher ct_sum = rp.ct_bit[0];

    for (size_t i = 1; i < RANGE_BITS; ++i) {
        Fp power_of_two;
        if (i < 64) {
            power_of_two = fp_from_u64(1ULL << i);
        } else {
            power_of_two = fp_from_words(0, 1ULL << (i - 64));
        }

        auto scaled = ct_scale(pk, rp.ct_bit[i], power_of_two);
        ct_sum = ct_add(pk, ct_sum, scaled);
    }

    auto ct_lc_diff = ct_sub(pk, ct_sum, ct_value);

    if (!verify_zero(pk, ct_lc_diff, rp.lc_proof)) {
        return false;
    }

    return true;
}

}