// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2024-2026 The YaCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "primitives/transaction.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>

#include "chainparamsseeds.h"

// Multi-threaded genesis block mining helper
static std::atomic<bool> g_found{false};
static std::atomic<uint32_t> g_foundNonce{0};
static uint256 g_foundHash;
static std::mutex g_mutex;

static void MineGenesisThread(CBlock genesis, const arith_uint256& bnTarget, uint32_t startNonce, uint32_t step, int threadId)
{
    uint32_t nNonce = startNonce;
    uint64_t attempts = 0;

    while (!g_found.load()) {
        genesis.nNonce = nNonce;
        uint256 hash = genesis.GetHash();

        if (UintToArith256(hash) <= bnTarget) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (!g_found.load()) {
                g_found.store(true);
                g_foundNonce.store(nNonce);
                g_foundHash = hash;
            }
            return;
        }

        attempts++;
        if (threadId == 0 && attempts % 10000 == 0) {
            printf("Thread 0: Tried %llu nonces (current: %u)\r", (unsigned long long)attempts, nNonce);
            fflush(stdout);
        }

        nNonce += step;
        if (nNonce < startNonce) {  // Wrapped
            return;
        }
    }
}

static void MineGenesisBlock(CBlock& genesis, const arith_uint256& bnTarget)
{
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4;

    printf("Mining genesis block with %u threads...\n", numThreads);
    printf("Target: %s\n", bnTarget.GetHex().c_str());

    g_found.store(false);

    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < numThreads; i++) {
        threads.emplace_back(MineGenesisThread, genesis, bnTarget, i, numThreads, i);
    }

    for (auto& t : threads) {
        t.join();
    }

    if (g_found.load()) {
        genesis.nNonce = g_foundNonce.load();
        printf("\n=== GENESIS BLOCK MINED ===\n");
        printf("nNonce: %u\n", genesis.nNonce);
        printf("Hash: %s\n", g_foundHash.GetHex().c_str());
        printf("Merkle Root: %s\n", genesis.hashMerkleRoot.GetHex().c_str());
        printf("\nUpdate chainparams.cpp with these values:\n");
        printf("static uint256 hashGenesisBlock = uint256S(\"0x%s\");\n", g_foundHash.GetHex().c_str());
        printf("static uint32_t nGenesisNonce = %u;\n", genesis.nNonce);
        printf("static uint256 hashGenesisMerkleRoot = uint256S(\"0x%s\");\n", genesis.hashMerkleRoot.GetHex().c_str());
        printf("===========================\n");
    } else {
        printf("Nonce space exhausted! Need to change timestamp.\n");
    }
}

//
// YACOIN - GPU-mineable cryptocurrency with AdaptivePow
//
// Features:
// - GPU-mineable (shared DAG model)
// - Time-based memory growth (N-factor concept)
// - ASIC-resistant (random program execution)
// - Native token/NFT support
//

// Genesis block parameters - TO BE MINED
static const char* pszTimestamp = "YaCoin Reborn - GPU Mining for Everyone - Feb 2026";
static const uint32_t nGenesisTime = 1738886400;  // Feb 7, 2026 00:00:00 UTC

// Genesis block - MINED
static uint256 hashGenesisBlock = uint256S("0x2622b6ce9f145ff57e3d3b50f16e7484532cadb8f53cb48feee3f94cf006b00e");
static uint32_t nGenesisNonce = 1;
static uint256 hashGenesisMerkleRoot = uint256S("0xdbabf37706207412eb24d6903d5cc5c1f667b465c9b26e3e774986e0560fb75a");

// AdaptivePow parameters
static const uint64_t ADAPTIVEPOW_DAG_BASE_SIZE = 1ULL << 30;  // 1 GB
static const uint32_t ADAPTIVEPOW_EPOCH_LENGTH = 180 * 24 * 60 * 60;  // 180 days
static const uint32_t ADAPTIVEPOW_GROWTH_RATE = 4;  // DAG doubles every 4 epochs

static CBlock CreateGenesisBlock(const char* pszTimestamp, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = nTime;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(CTransaction(txNew));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    return CreateGenesisBlock(pszTimestamp, nTime, nNonce, nBits, nVersion);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        // AdaptivePow consensus parameters - easy for instant genesis mining
        consensus.powLimit = UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.nPowTargetTimespan = 60 * 60;  // 1 hour
        consensus.nPowTargetSpacing = 60;  // 1 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916;  // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016;

        // AdaptivePow specific
        consensus.nAdaptivePowDagBaseSize = ADAPTIVEPOW_DAG_BASE_SIZE;
        consensus.nAdaptivePowEpochLength = ADAPTIVEPOW_EPOCH_LENGTH;
        consensus.nAdaptivePowGrowthRate = ADAPTIVEPOW_GROWTH_RATE;

        // Proof of stake parameters
        consensus.nStakeMinAge = 8 * 60 * 60;      // 8 hours minimum stake age
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60; // 30 days maximum stake age
        consensus.nModifierInterval = 6 * 60 * 60;  // 6 hour stake modifier interval

        // BIP activation heights (from genesis)
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.BIP68Height = 0;
        consensus.HeliopolisHardforkHeight = 0;

        // Deployment
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        /**
         * Network magic bytes - YaCoin
         * "YACN" in hex
         */
        pchMessageStart[0] = 0x59;  // Y
        pchMessageStart[1] = 0x41;  // A
        pchMessageStart[2] = 0x43;  // C
        pchMessageStart[3] = 0x4e;  // N
        nDefaultPort = 9333;
        nPruneAfterHeight = 100000;

        // Genesis block - easy difficulty for instant mining
        genesis = CreateGenesisBlock(nGenesisTime, nGenesisNonce, 0x207fffff, 1);

        consensus.hashGenesisBlock = genesis.GetHash();

        // Verify genesis block
        assert(consensus.hashGenesisBlock == hashGenesisBlock);
        assert(genesis.hashMerkleRoot == hashGenesisMerkleRoot);

        // Seed nodes
        vSeeds.clear();
        vSeeds.emplace_back("76.13.31.72", true);  // Main seed node

        // Address prefixes
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 63);   // S
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 125);  // s
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 191);  //
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // Fixed seeds - to be added after launch
        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        // Checkpoints - empty for new chain
        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            nGenesisTime,  // Time of genesis
            0,             // Transactions
            0              // Tx rate
        };

    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.powLimit = UintToArith256(uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.nPowTargetTimespan = 60 * 60;
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512;
        consensus.nMinerConfirmationWindow = 2016;

        // AdaptivePow specific - smaller DAG for testing
        consensus.nAdaptivePowDagBaseSize = 256ULL << 20;  // 256 MB for testnet
        consensus.nAdaptivePowEpochLength = 7 * 24 * 60 * 60;  // 7 days
        consensus.nAdaptivePowGrowthRate = 2;

        // Proof of stake parameters (shorter for testnet)
        consensus.nStakeMinAge = 1 * 60 * 60;       // 1 hour minimum stake age
        consensus.nStakeMaxAge = 7 * 24 * 60 * 60;  // 7 days maximum stake age
        consensus.nModifierInterval = 60 * 60;      // 1 hour stake modifier interval

        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.BIP68Height = 0;
        consensus.HeliopolisHardforkHeight = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Testnet magic
        pchMessageStart[0] = 0x74;  // t
        pchMessageStart[1] = 0x59;  // Y
        pchMessageStart[2] = 0x41;  // A
        pchMessageStart[3] = 0x43;  // C
        nDefaultPort = 19333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(nGenesisTime, 0, 0x1e0fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125);  // s
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            nGenesisTime,
            0,
            0
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        consensus.powLimit = UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.nPowTargetTimespan = 60 * 60;
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;

        // Tiny DAG for regtest
        consensus.nAdaptivePowDagBaseSize = 16ULL << 20;  // 16 MB
        consensus.nAdaptivePowEpochLength = 60 * 60;  // 1 hour
        consensus.nAdaptivePowGrowthRate = 1;

        // Proof of stake parameters (minimal for regtest)
        consensus.nStakeMinAge = 60;             // 1 minute minimum stake age
        consensus.nStakeMaxAge = 60 * 60;        // 1 hour maximum stake age
        consensus.nModifierInterval = 60;        // 1 minute stake modifier interval

        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.BIP68Height = 0;
        consensus.HeliopolisHardforkHeight = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        pchMessageStart[0] = 0x72;  // r
        pchMessageStart[1] = 0x59;  // Y
        pchMessageStart[2] = 0x41;  // A
        pchMessageStart[3] = 0x43;  // C
        nDefaultPort = 29333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(nGenesisTime, 0, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();

        vSeeds.clear();
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 125);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

// AdaptivePow helper functions
uint32_t GetAdaptivePowEpoch(int64_t nTime, const Consensus::Params& params)
{
    int64_t nGenesisTime = 0;  // Will be set from genesis block
    if (nTime <= nGenesisTime) return 0;
    return (nTime - nGenesisTime) / params.nAdaptivePowEpochLength;
}

uint64_t GetAdaptivePowDagSize(uint32_t nEpoch, const Consensus::Params& params)
{
    uint32_t nDoublings = nEpoch / params.nAdaptivePowGrowthRate;
    if (nDoublings > 10) nDoublings = 10;  // Cap at 1TB
    return params.nAdaptivePowDagBaseSize << nDoublings;
}
