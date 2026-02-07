/*
 * YaCoin GPU Miner - Core Header
 */

#ifndef YACMINER_H
#define YACMINER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// YaCoin block header structure (80 bytes)
typedef struct {
    int32_t  nVersion;          // 4 bytes
    uint8_t  hashPrevBlock[32]; // 32 bytes
    uint8_t  hashMerkleRoot[32];// 32 bytes
    uint32_t nTime;             // 4 bytes (or 8 bytes for v7+ blocks)
    uint32_t nBits;             // 4 bytes
    uint32_t nNonce;            // 4 bytes
} BlockHeader;

// Mining job from stratum or node
typedef struct {
    char     jobId[64];
    uint8_t  prevHash[32];
    uint8_t  merkleRoot[32];
    uint32_t nTime;
    uint32_t nBits;
    uint8_t  Nfactor;
    uint32_t targetHigh;       // High 32 bits of target for quick check
    uint8_t  target[32];       // Full 256-bit target
    bool     cleanJobs;
} MiningJob;

// Mining result
typedef struct {
    char     jobId[64];
    uint32_t nonce;
    uint8_t  hash[32];
    bool     found;
} MiningResult;

// GPU device info
typedef struct {
    int      id;
    char     name[256];
    size_t   memory;
    int      computeUnits;
    bool     available;
} GPUDevice;

// Miner statistics
typedef struct {
    double   hashrate;         // Hashes per second
    uint64_t totalHashes;
    uint64_t acceptedShares;
    uint64_t rejectedShares;
    double   uptime;
} MinerStats;

// Function declarations

// Get current N-factor from timestamp
uint8_t get_nfactor(int64_t timestamp);

// Calculate memory requirement per thread
size_t get_memory_per_thread(uint8_t Nfactor);

// GPU enumeration
int enumerate_gpus(GPUDevice *devices, int maxDevices);

// Initialize miner on specific GPU
int miner_init_gpu(int deviceId, uint8_t Nfactor, uint32_t threads);

// Process a mining job
int miner_process_job(const MiningJob *job, MiningResult *result);

// Get mining statistics
void miner_get_stats(MinerStats *stats);

// Cleanup
void miner_shutdown(void);

// Utility functions
void target_to_diff(const uint8_t *target, double *difficulty);
void diff_to_target(double difficulty, uint8_t *target);

#ifdef __cplusplus
}
#endif

#endif // YACMINER_H
