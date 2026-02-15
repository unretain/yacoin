/*
 * YaCoin GPU Miner - Utility Functions
 */

#include "miner.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>

// YaCoin chain start time (May 8, 2013)
#define CHAIN_START_TIME 1367991200

// N-factor limits
#define MIN_NFACTOR 4
#define MAX_NFACTOR 25

// Calculate N-factor from block timestamp
// This matches YaCoin's GetNfactor() function exactly
uint8_t get_nfactor(int64_t nTimestamp)
{
    if (nTimestamp <= CHAIN_START_TIME) {
        return MIN_NFACTOR;
    }

    int64_t nAge = nTimestamp - CHAIN_START_TIME;
    int nBitCount = 0;

    // Count how many times we can divide by 2 while > 3
    while ((nAge >> 1) > 3) {
        nBitCount++;
        nAge >>= 1;
    }

    nAge &= 0x03;  // Low 2 bits

    // Calculate N using the formula
    int n = ((nBitCount * 170) + (nAge * 25) - 2320) / 100;

    if (n < 0) n = 0;

    uint8_t N = (uint8_t)n;

    // Clamp to valid range
    if (N < MIN_NFACTOR) N = MIN_NFACTOR;
    if (N > MAX_NFACTOR) N = MAX_NFACTOR;

    return N;
}

// Calculate memory requirement per thread
// Memory = (N + 2) * 128 bytes for r=1, p=1
size_t get_memory_per_thread(uint8_t Nfactor)
{
    uint32_t N = 1 << (Nfactor + 1);
    return (size_t)(N + 2) * 128;
}

// Convert target to difficulty
void target_to_diff(const uint8_t *target, double *difficulty)
{
    // Bitcoin-style difficulty calculation
    // diff = max_target / target

    // Max target for YaCoin (difficulty 1)
    static const uint8_t maxTarget[32] = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    // Find first non-zero byte in target
    int i;
    for (i = 0; i < 32 && target[i] == 0; i++);

    if (i >= 32) {
        *difficulty = 0;
        return;
    }

    // Calculate difficulty
    double dMax = 0, dTarget = 0;
    for (int j = 0; j < 8; j++) {
        dMax = dMax * 256.0 + maxTarget[j];
        dTarget = dTarget * 256.0 + target[j];
    }

    *difficulty = dMax / dTarget;
}

// Convert difficulty to target
void diff_to_target(double difficulty, uint8_t *target)
{
    memset(target, 0xff, 32);

    if (difficulty <= 0) {
        return;
    }

    // Calculate target = max_target / difficulty
    uint64_t k = (uint64_t)(0x0000ffff00000000ULL / difficulty);

    target[0] = 0;
    target[1] = 0;
    target[2] = 0;
    target[3] = 0;
    target[4] = (k >> 24) & 0xff;
    target[5] = (k >> 16) & 0xff;
    target[6] = (k >> 8) & 0xff;
    target[7] = k & 0xff;
}

// Hex string to bytes
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t maxLen)
{
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    if (len / 2 > maxLen) return -1;

    for (size_t i = 0; i < len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)byte;
    }

    return len / 2;
}

// Bytes to hex string
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

// Reverse byte order (for hash display)
void reverse_bytes(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t tmp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = tmp;
    }
}

// Print memory requirements table
void print_nfactor_table(void)
{
    printf("\nYaCoin N-factor Memory Requirements:\n");
    printf("=====================================\n");
    printf("Nfactor |     N      | Memory/Thread | Total (1K threads)\n");
    printf("--------|------------|---------------|-------------------\n");

    for (int nf = 10; nf <= 25; nf++) {
        uint32_t N = 1 << (nf + 1);
        size_t memPerThread = get_memory_per_thread(nf);
        size_t totalMem = memPerThread * 1024;

        printf("   %2d   | %10u | %8.1f MB   | %8.1f GB\n",
               nf, N,
               memPerThread / (1024.0 * 1024.0),
               totalMem / (1024.0 * 1024.0 * 1024.0));
    }
    printf("\n");
}

// Estimate current N-factor based on current time
void print_current_nfactor(void)
{
    time_t now = time(NULL);
    uint8_t nf = get_nfactor(now);
    uint32_t N = 1 << (nf + 1);
    size_t memPerThread = get_memory_per_thread(nf);

    printf("Current YaCoin N-factor: %d\n", nf);
    printf("  N = %u\n", N);
    printf("  Memory per thread: %.1f MB\n", memPerThread / (1024.0 * 1024.0));
    printf("  Recommended GPU memory: %.1f GB+ (for 1K threads)\n",
           (memPerThread * 1024) / (1024.0 * 1024.0 * 1024.0));
}
