// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2024-2026 The Scrypt Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCRYPT_CONSENSUS_PARAMS_H
#define SCRYPT_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>
#include <limits>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout to indicate no timeout. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;

    /** Block height at which BIP34 becomes active */
    int BIP34Height;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which BIP68 becomes active */
    int BIP68Height;

    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];

    /** Proof of work parameters */
    arith_uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }

    /**
     * AdaptivePow parameters - GPU-mineable algorithm with growing memory
     */
    uint64_t nAdaptivePowDagBaseSize;   // Base DAG size in bytes (e.g., 1 GB)
    uint32_t nAdaptivePowEpochLength;    // Epoch length in seconds (e.g., 180 days)
    uint32_t nAdaptivePowGrowthRate;     // Epochs before DAG size doubles

    /**
     * Calculate DAG size for a given epoch
     */
    uint64_t GetDagSize(uint32_t epoch) const {
        uint32_t doublings = epoch / nAdaptivePowGrowthRate;
        if (doublings > 10) doublings = 10;  // Cap at ~1 TB
        return nAdaptivePowDagBaseSize << doublings;
    }

    /**
     * Calculate epoch from timestamp
     */
    uint32_t GetEpoch(int64_t nTime, int64_t nGenesisTime) const {
        if (nTime <= nGenesisTime) return 0;
        return (nTime - nGenesisTime) / nAdaptivePowEpochLength;
    }
};

} // namespace Consensus

#endif // SCRYPT_CONSENSUS_PARAMS_H
