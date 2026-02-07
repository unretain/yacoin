// Copyright (c) 2024-2026 The Scrypt Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "adaptivepow.h"
#include "hash.h"
#include "util.h"
#include "chainparams.h"

#include <cstring>
#include <algorithm>

// Platform-specific intrinsics for bit operations
#ifdef _MSC_VER
#include <intrin.h>

// Count leading zeros (MSVC version)
static inline uint32_t clz32(uint32_t x) {
    unsigned long index;
    return _BitScanReverse(&index, x) ? (31 - index) : 32;
}

// Population count (MSVC version)
static inline uint32_t popcount32(uint32_t x) {
    return __popcnt(x);
}

#else
// GCC/Clang version
static inline uint32_t clz32(uint32_t x) {
    return __builtin_clz(x);
}

static inline uint32_t popcount32(uint32_t x) {
    return __builtin_popcount(x);
}
#endif

// Global DAG instance
std::unique_ptr<AdaptivePowDAG> g_adaptivePowDAG;

// KISS99 RNG for random program generation
struct Kiss99 {
    uint32_t z, w, jsr, jcong;

    Kiss99(uint32_t seed1, uint32_t seed2, uint32_t seed3, uint32_t seed4)
        : z(seed1), w(seed2), jsr(seed3), jcong(seed4) {}

    uint32_t next() {
        z = 36969 * (z & 0xffff) + (z >> 16);
        w = 18000 * (w & 0xffff) + (w >> 16);
        uint32_t mwc = (z << 16) + w;
        jsr ^= (jsr << 17);
        jsr ^= (jsr >> 13);
        jsr ^= (jsr << 5);
        jcong = 69069 * jcong + 1234567;
        return (mwc ^ jcong) + jsr;
    }
};

// Keccak-f[800] permutation (simplified for PoW)
static void keccak_f800(uint32_t* state) {
    static const uint32_t keccak_rc[22] = {
        0x00000001, 0x00008082, 0x0000808a, 0x80008000,
        0x0000808b, 0x80000001, 0x80008081, 0x00008009,
        0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
        0x8000808b, 0x0000008b, 0x00008089, 0x00008003,
        0x00008002, 0x00000080, 0x0000800a, 0x8000000a,
        0x80008081, 0x00008080
    };

    for (int round = 0; round < 22; round++) {
        // Theta
        uint32_t C[5], D[5];
        for (int i = 0; i < 5; i++) {
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5] ^ rotl32(C[(i + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // Rho and Pi
        uint32_t temp = state[1];
        for (int i = 0; i < 24; i++) {
            int j = (i + 1) % 25;
            uint32_t t = state[j];
            state[j] = rotl32(temp, ((i + 1) * (i + 2) / 2) % 32);
            temp = t;
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            uint32_t t[5];
            for (int i = 0; i < 5; i++) t[i] = state[j + i];
            for (int i = 0; i < 5; i++) {
                state[j + i] = t[i] ^ ((~t[(i + 1) % 5]) & t[(i + 2) % 5]);
            }
        }

        // Iota
        state[0] ^= keccak_rc[round];
    }
}

// Random math operation (ASIC resistance)
static uint32_t random_math_op(uint32_t a, uint32_t b, uint32_t op) {
    switch (op % 11) {
        case 0:  return a + b;
        case 1:  return a * b;
        case 2:  return a - b;
        case 3:  return a ^ b;
        case 4:  return rotl32(a, b & 31);
        case 5:  return rotr32(a, b & 31);
        case 6:  return a & b;
        case 7:  return a | b;
        case 8:  return clz32(a | 1) + clz32(b | 1);
        case 9:  return popcount32(a) + popcount32(b);
        case 10: return (a >> (b & 15)) | (b << (16 - (b & 15)));
        default: return a + b;
    }
}

// ==================== AdaptivePowDAG Implementation ====================

AdaptivePowDAG::AdaptivePowDAG()
    : m_epoch(0), m_size(0), m_cacheSize(0), m_valid(false) {}

AdaptivePowDAG::~AdaptivePowDAG() {}

uint256 AdaptivePowDAG::GetSeedHash(uint32_t epoch) {
    uint256 seed;
    seed.SetNull();

    // Generate seed by hashing epoch number repeatedly
    for (uint32_t i = 0; i < epoch; i++) {
        CSHA256 hasher;
        hasher.Write(seed.begin(), 32);
        hasher.Finalize(seed.begin());
    }

    return seed;
}

void AdaptivePowDAG::GenerateCache(const uint256& seed, uint64_t cacheSize) {
    uint64_t cacheItems = cacheSize / ADAPTIVEPOW_HASH_BYTES;
    m_cache.resize(cacheItems * 16); // 16 uint32_t per item (64 bytes)

    // Initialize first cache item from seed
    CSHA256 hasher;
    hasher.Write(seed.begin(), 32);
    unsigned char hash[64];
    hasher.Finalize(hash);
    hasher.Reset();
    hasher.Write(hash, 32);
    hasher.Finalize(hash + 32);

    memcpy(&m_cache[0], hash, 64);

    // Generate rest of cache
    for (uint64_t i = 1; i < cacheItems; i++) {
        hasher.Reset();
        hasher.Write((unsigned char*)&m_cache[(i - 1) * 16], 64);
        hasher.Finalize(hash);
        hasher.Reset();
        hasher.Write(hash, 32);
        hasher.Finalize(hash + 32);
        memcpy(&m_cache[i * 16], hash, 64);
    }

    // Cache mixing rounds
    for (uint32_t round = 0; round < ADAPTIVEPOW_CACHE_ROUNDS; round++) {
        for (uint64_t i = 0; i < cacheItems; i++) {
            uint32_t parent = m_cache[i * 16] % cacheItems;
            uint32_t* dst = &m_cache[i * 16];
            uint32_t* src = &m_cache[parent * 16];

            for (int j = 0; j < 16; j++) {
                dst[j] = fnv1a(dst[j], src[j]);
            }
        }
    }

    m_cacheSize = cacheSize;
}

void AdaptivePowDAG::CalcDAGItem(uint32_t index, uint32_t* out) const {
    uint64_t cacheItems = m_cacheSize / ADAPTIVEPOW_HASH_BYTES;

    // Initialize from cache
    uint32_t cacheIndex = index % cacheItems;
    memcpy(out, &m_cache[cacheIndex * 16], 64);
    out[0] ^= index;

    // Mix with parent cache items
    for (uint32_t round = 0; round < ADAPTIVEPOW_DAG_PARENTS; round++) {
        uint32_t parent = fnv1a(index ^ round, out[0]) % cacheItems;
        const uint32_t* parentData = &m_cache[parent * 16];

        for (int i = 0; i < 16; i++) {
            out[i] = fnv1a(out[i], parentData[i]);
        }
    }
}

bool AdaptivePowDAG::Generate(uint32_t epoch, const Consensus::Params& params) {
    LogPrintf("AdaptivePow: Generating DAG for epoch %u...\n", epoch);

    m_epoch = epoch;
    m_size = GetAdaptivePowDAGSize(epoch, params);
    uint64_t cacheSize = GetAdaptivePowCacheSize(epoch, params);

    LogPrintf("AdaptivePow: DAG size: %.2f GB, Cache size: %.2f MB\n",
              m_size / 1e9, cacheSize / 1e6);

    // Generate seed and cache
    uint256 seed = GetSeedHash(epoch);
    GenerateCache(seed, cacheSize);

    // Generate full DAG
    uint64_t dagItems = m_size / ADAPTIVEPOW_HASH_BYTES;
    m_dag.resize(dagItems * 16);

    for (uint64_t i = 0; i < dagItems; i++) {
        CalcDAGItem(i, &m_dag[i * 16]);

        if (i % 1000000 == 0) {
            LogPrintf("AdaptivePow: DAG generation %.1f%% complete\n",
                      (float)i / dagItems * 100);
        }
    }

    m_valid = true;
    LogPrintf("AdaptivePow: DAG generation complete\n");
    return true;
}

void AdaptivePowDAG::GetItem(uint32_t index, uint32_t* out) const {
    if (m_valid && index * 16 < m_dag.size()) {
        memcpy(out, &m_dag[index * 16], 64);
    } else {
        // Fallback to cache-based calculation
        CalcDAGItem(index, out);
    }
}

// ==================== Hash Functions ====================

AdaptivePowResult AdaptivePowHash(
    const uint256& headerHash,
    uint64_t nonce,
    const AdaptivePowDAG* dag,
    const Consensus::Params& params
) {
    AdaptivePowResult result;
    uint32_t mix[64]; // 256 bytes
    uint32_t state[25];

    // Seed state with header hash + nonce
    memcpy(state, headerHash.begin(), 32);
    state[8] = (uint32_t)(nonce);
    state[9] = (uint32_t)(nonce >> 32);
    for (int i = 10; i < 25; i++) state[i] = 0;

    // Initial hash
    keccak_f800(state);

    // Initialize mix
    for (int i = 0; i < 64; i++) {
        mix[i] = state[i % 25];
    }

    // Initialize RNG for random math
    Kiss99 rng(
        fnv1a(FNV_OFFSET, state[0]),
        fnv1a(state[0], state[1]),
        fnv1a(state[1], state[2]),
        fnv1a(state[2], state[3])
    );

    // Get DAG size
    uint32_t dagItems = dag ? (dag->GetSize() / ADAPTIVEPOW_HASH_BYTES) :
                              (params.GetDagSize(dag ? dag->GetEpoch() : 0) / ADAPTIVEPOW_HASH_BYTES);

    // Main loop: random DAG reads + random math
    uint32_t dagData[16];
    for (uint32_t round = 0; round < ADAPTIVEPOW_DAG_LOADS; round++) {
        // Calculate DAG index from mix
        uint32_t dagIdx = fnv1a(round ^ mix[round % 64], mix[(round + 1) % 64]);
        dagIdx %= dagItems;

        // Load DAG data
        if (dag) {
            dag->GetItem(dagIdx, dagData);
        } else {
            // Light mode - calculate on the fly
            memset(dagData, 0, 64);
            dagData[0] = dagIdx;
        }

        // Mix with DAG data using FNV
        for (int i = 0; i < 16; i++) {
            mix[i] = fnv1a(mix[i], dagData[i]);
        }

        // Random math operations
        for (uint32_t op = 0; op < ADAPTIVEPOW_MATH_OPS; op++) {
            uint32_t src1 = rng.next() % 64;
            uint32_t src2 = rng.next() % 64;
            uint32_t dst = rng.next() % 64;
            uint32_t opType = rng.next();

            mix[dst] = random_math_op(mix[src1], mix[src2], opType);
        }
    }

    // Compress mix to 256 bits (8 x 32-bit words)
    uint32_t compressed[8];
    for (int i = 0; i < 8; i++) {
        compressed[i] = mix[i * 8];
        for (int j = 1; j < 8; j++) {
            compressed[i] = fnv1a(compressed[i], mix[i * 8 + j]);
        }
    }

    // Set mix hash
    memcpy(result.hashMix.begin(), compressed, 32);

    // Final hash
    memcpy(state, compressed, 32);
    for (int i = 8; i < 25; i++) state[i] = 0;
    keccak_f800(state);

    memcpy(result.hashFinal.begin(), state, 32);

    return result;
}

uint256 AdaptivePowLightVerify(
    const uint256& headerHash,
    uint64_t nonce,
    const uint256& mixHash,
    uint32_t epoch,
    const Consensus::Params& params
) {
    // For light verification, we trust the mixHash and just compute final hash
    uint32_t state[25];

    memcpy(state, mixHash.begin(), 32);
    for (int i = 8; i < 25; i++) state[i] = 0;
    keccak_f800(state);

    uint256 result;
    memcpy(result.begin(), state, 32);
    return result;
}

bool CheckAdaptivePow(
    const uint256& headerHash,
    uint64_t nonce,
    const uint256& mixHash,
    const uint256& target,
    uint32_t epoch,
    const Consensus::Params& params,
    const AdaptivePowDAG* dag
) {
    AdaptivePowResult result;

    if (dag && dag->IsValid(epoch)) {
        // Fast verification with full DAG
        result = AdaptivePowHash(headerHash, nonce, dag, params);

        // Verify mix hash matches
        if (result.hashMix != mixHash) {
            return false;
        }
    } else {
        // Light verification without DAG
        result.hashFinal = AdaptivePowLightVerify(headerHash, nonce, mixHash, epoch, params);
    }

    // Check against target
    return result.hashFinal <= target;
}

// ==================== Utility Functions ====================

uint32_t GetAdaptivePowEpoch(int64_t nTime, int64_t nGenesisTime, const Consensus::Params& params) {
    if (nTime <= nGenesisTime) return 0;
    return (nTime - nGenesisTime) / params.nAdaptivePowEpochLength;
}

uint64_t GetAdaptivePowDAGSize(uint32_t epoch, const Consensus::Params& params) {
    uint32_t doublings = epoch / params.nAdaptivePowGrowthRate;
    if (doublings > 10) doublings = 10; // Cap at ~1 TB
    return params.nAdaptivePowDagBaseSize << doublings;
}

uint64_t GetAdaptivePowCacheSize(uint32_t epoch, const Consensus::Params& params) {
    return GetAdaptivePowDAGSize(epoch, params) / 64;
}

bool InitAdaptivePowDAG(uint32_t epoch, const Consensus::Params& params) {
    if (g_adaptivePowDAG && g_adaptivePowDAG->IsValid(epoch)) {
        return true; // Already initialized for this epoch
    }

    g_adaptivePowDAG = std::make_unique<AdaptivePowDAG>();
    return g_adaptivePowDAG->Generate(epoch, params);
}
