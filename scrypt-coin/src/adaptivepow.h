// Copyright (c) 2024-2026 The Scrypt Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCRYPT_ADAPTIVEPOW_H
#define SCRYPT_ADAPTIVEPOW_H

#include "uint256.h"
#include "consensus/params.h"
#include <vector>
#include <cstdint>
#include <memory>

/**
 * AdaptivePow - Novel GPU Mining Algorithm
 *
 * Combines:
 * - Shared DAG model (like Ethash) for GPU efficiency
 * - Random program execution (like KawPow) for ASIC resistance
 * - Time-based memory growth (like YaCoin N-factor) for longevity
 */

// Algorithm constants
static const uint32_t ADAPTIVEPOW_HASH_BYTES = 64;
static const uint32_t ADAPTIVEPOW_MIX_BYTES = 256;
static const uint32_t ADAPTIVEPOW_DAG_LOADS = 64;
static const uint32_t ADAPTIVEPOW_MATH_OPS = 16;
static const uint32_t ADAPTIVEPOW_CACHE_ROUNDS = 3;
static const uint32_t ADAPTIVEPOW_DAG_PARENTS = 256;

// FNV constants
static const uint32_t FNV_PRIME = 0x01000193;
static const uint32_t FNV_OFFSET = 0x811c9dc5;

/**
 * DAG (Directed Acyclic Graph) for AdaptivePow
 * Shared dataset stored in memory, used for random lookups during mining
 */
class AdaptivePowDAG {
public:
    AdaptivePowDAG();
    ~AdaptivePowDAG();

    // Generate DAG for given epoch
    bool Generate(uint32_t epoch, const Consensus::Params& params);

    // Get DAG item at index
    void GetItem(uint32_t index, uint32_t* out) const;

    // Get current epoch
    uint32_t GetEpoch() const { return m_epoch; }

    // Get DAG size in bytes
    uint64_t GetSize() const { return m_size; }

    // Check if DAG is valid for epoch
    bool IsValid(uint32_t epoch) const { return m_valid && m_epoch == epoch; }

    // Get seed hash for epoch
    static uint256 GetSeedHash(uint32_t epoch);

private:
    // Generate cache from seed
    void GenerateCache(const uint256& seed, uint64_t cacheSize);

    // Generate single DAG item from cache
    void CalcDAGItem(uint32_t index, uint32_t* out) const;

    uint32_t m_epoch;
    uint64_t m_size;
    uint64_t m_cacheSize;
    std::vector<uint32_t> m_cache;
    std::vector<uint32_t> m_dag;
    bool m_valid;
};

/**
 * AdaptivePow hash result
 */
struct AdaptivePowResult {
    uint256 hashMix;    // Mix hash for quick verification
    uint256 hashFinal;  // Final hash to compare against target
};

/**
 * Compute AdaptivePow hash
 *
 * @param headerHash  Hash of block header (without nonce/mixHash)
 * @param nonce       64-bit nonce
 * @param dag         Pointer to DAG (can be nullptr for light verification)
 * @param dagSize     Size of DAG in bytes
 * @param epoch       Current epoch
 * @param params      Consensus parameters
 * @return            Hash result containing mixHash and final hash
 */
AdaptivePowResult AdaptivePowHash(
    const uint256& headerHash,
    uint64_t nonce,
    const AdaptivePowDAG* dag,
    const Consensus::Params& params
);

/**
 * Light verification of AdaptivePow (without full DAG)
 * Slower but uses less memory - for SPV clients
 *
 * @param headerHash  Hash of block header
 * @param nonce       64-bit nonce
 * @param mixHash     Mix hash from block
 * @param epoch       Current epoch
 * @param params      Consensus parameters
 * @return            Final hash
 */
uint256 AdaptivePowLightVerify(
    const uint256& headerHash,
    uint64_t nonce,
    const uint256& mixHash,
    uint32_t epoch,
    const Consensus::Params& params
);

/**
 * Check if AdaptivePow proof is valid
 *
 * @param headerHash  Hash of block header
 * @param nonce       Nonce from block
 * @param mixHash     Mix hash from block
 * @param target      Target difficulty
 * @param epoch       Current epoch
 * @param params      Consensus parameters
 * @param dag         Optional DAG for fast verification
 * @return            True if valid
 */
bool CheckAdaptivePow(
    const uint256& headerHash,
    uint64_t nonce,
    const uint256& mixHash,
    const uint256& target,
    uint32_t epoch,
    const Consensus::Params& params,
    const AdaptivePowDAG* dag = nullptr
);

/**
 * Get epoch from block timestamp
 */
uint32_t GetAdaptivePowEpoch(int64_t nTime, int64_t nGenesisTime, const Consensus::Params& params);

/**
 * Get DAG size for epoch
 */
uint64_t GetAdaptivePowDAGSize(uint32_t epoch, const Consensus::Params& params);

/**
 * Get cache size for epoch
 */
uint64_t GetAdaptivePowCacheSize(uint32_t epoch, const Consensus::Params& params);

// Helper functions
inline uint32_t fnv1a(uint32_t a, uint32_t b) {
    return (a ^ b) * FNV_PRIME;
}

inline uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// Global DAG instance (one per node)
extern std::unique_ptr<AdaptivePowDAG> g_adaptivePowDAG;

// Initialize/update global DAG
bool InitAdaptivePowDAG(uint32_t epoch, const Consensus::Params& params);

#endif // SCRYPT_ADAPTIVEPOW_H
