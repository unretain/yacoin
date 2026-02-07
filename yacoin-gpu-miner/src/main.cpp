/*
 * YaCoin GPU Miner - Main Entry Point
 *
 * A modern GPU miner for YaCoin's Scrypt-Jane algorithm
 * Supports CUDA (NVIDIA) and OpenCL (AMD)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #define sleep(x) Sleep((x) * 1000)
#else
    #include <unistd.h>
#endif

#include "core/miner.h"
#include "core/stratum.h"

// Version
#define YACMINER_VERSION "1.0.0"

// Global state
static volatile bool g_running = true;
static StratumClient g_stratum;
static MinerStats g_stats;

// Configuration
typedef struct {
    char url[256];
    char user[256];
    char pass[256];
    int  deviceId;
    int  threads;
    int  intensity;
    bool benchmark;
    bool solo;
} Config;

// Signal handler
void signal_handler(int sig)
{
    printf("\nShutting down...\n");
    g_running = false;
}

// Print usage
void print_usage(const char *program)
{
    printf("YaCoin GPU Miner v%s\n", YACMINER_VERSION);
    printf("Usage: %s [options]\n\n", program);
    printf("Options:\n");
    printf("  -o, --url <url>       Pool URL (stratum+tcp://host:port)\n");
    printf("  -u, --user <user>     Username or wallet address\n");
    printf("  -p, --pass <pass>     Password (default: x)\n");
    printf("  -d, --device <id>     GPU device ID (default: 0)\n");
    printf("  -t, --threads <n>     Number of GPU threads\n");
    printf("  -i, --intensity <n>   Mining intensity (8-25)\n");
    printf("  --solo                Solo mining mode\n");
    printf("  --benchmark           Run benchmark only\n");
    printf("  -h, --help            Show this help\n");
    printf("\nExamples:\n");
    printf("  Pool mining:\n");
    printf("    %s -o stratum+tcp://pool.yacoin.org:3333 -u YWalletAddress -p x\n", program);
    printf("  Solo mining:\n");
    printf("    %s --solo -o http://127.0.0.1:7688 -u rpcuser -p rpcpass\n", program);
}

// Parse command line arguments
int parse_args(int argc, char **argv, Config *config)
{
    // Defaults
    memset(config, 0, sizeof(Config));
    strcpy(config->pass, "x");
    config->deviceId = 0;
    config->threads = 0;  // Auto
    config->intensity = 0;  // Auto

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--url") == 0) {
            if (++i >= argc) return -1;
            strncpy(config->url, argv[i], sizeof(config->url) - 1);
        }
        else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) {
            if (++i >= argc) return -1;
            strncpy(config->user, argv[i], sizeof(config->user) - 1);
        }
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pass") == 0) {
            if (++i >= argc) return -1;
            strncpy(config->pass, argv[i], sizeof(config->pass) - 1);
        }
        else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--device") == 0) {
            if (++i >= argc) return -1;
            config->deviceId = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) {
            if (++i >= argc) return -1;
            config->threads = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--intensity") == 0) {
            if (++i >= argc) return -1;
            config->intensity = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "--solo") == 0) {
            config->solo = true;
        }
        else if (strcmp(argv[i], "--benchmark") == 0) {
            config->benchmark = true;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

// Run benchmark
int run_benchmark(Config *config)
{
    printf("\n=== YaCoin GPU Miner Benchmark ===\n\n");

    // Enumerate GPUs
    GPUDevice devices[8];
    int numDevices = enumerate_gpus(devices, 8);

    if (numDevices <= 0) {
        fprintf(stderr, "No GPU devices found!\n");
        return -1;
    }

    printf("Found %d GPU(s):\n", numDevices);
    for (int i = 0; i < numDevices; i++) {
        printf("  [%d] %s (%.0f MB)\n", i, devices[i].name,
               devices[i].memory / (1024.0 * 1024.0));
    }
    printf("\n");

    // Test different N-factors
    uint8_t testNfactors[] = {16, 17, 18, 19, 20};
    int numTests = sizeof(testNfactors) / sizeof(testNfactors[0]);

    printf("Testing N-factors (higher = more memory required):\n\n");

    for (int t = 0; t < numTests; t++) {
        uint8_t nf = testNfactors[t];
        uint32_t N = 1 << (nf + 1);
        size_t memPerThread = get_memory_per_thread(nf);

        printf("N-factor %d (N=%u, %.1f MB/thread):\n", nf, N,
               memPerThread / (1024.0 * 1024.0));

        // Determine thread count based on GPU memory
        uint32_t threads = config->threads;
        if (threads == 0) {
            // Auto-calculate based on memory
            size_t availMem = devices[config->deviceId].memory * 0.8;  // Use 80%
            threads = availMem / memPerThread;
            if (threads > 65536) threads = 65536;
            if (threads < 256) threads = 256;
        }

        printf("  Threads: %u\n", threads);
        printf("  Memory: %.1f MB\n", (threads * memPerThread) / (1024.0 * 1024.0));

        // Initialize miner
        if (miner_init_gpu(config->deviceId, nf, threads) != 0) {
            printf("  ERROR: Failed to initialize (not enough memory?)\n\n");
            continue;
        }

        // Create fake job
        MiningJob job = {0};
        job.Nfactor = nf;
        job.nTime = (uint32_t)time(NULL);
        job.nBits = 0x1d00ffff;

        // Run benchmark for 10 seconds
        time_t startTime = time(NULL);
        uint64_t totalHashes = 0;
        int iterations = 0;

        while (time(NULL) - startTime < 10) {
            MiningResult result;
            miner_process_job(&job, &result);
            totalHashes += threads;
            iterations++;
        }

        double elapsed = (double)(time(NULL) - startTime);
        double hashrate = totalHashes / elapsed;

        printf("  Hashrate: %.2f H/s (%.2f KH/s)\n", hashrate, hashrate / 1000.0);
        printf("\n");

        miner_shutdown();
    }

    printf("Benchmark complete!\n");
    return 0;
}

// Main mining loop
int mining_loop(Config *config)
{
    // Initialize stratum
    StratumConfig stratumConfig;
    strncpy(stratumConfig.url, config->url, sizeof(stratumConfig.url));
    strncpy(stratumConfig.user, config->user, sizeof(stratumConfig.user));
    strncpy(stratumConfig.pass, config->pass, sizeof(stratumConfig.pass));

    if (stratum_init(&g_stratum, &stratumConfig) != 0) {
        fprintf(stderr, "Failed to initialize stratum client\n");
        return -1;
    }

    // Connect to pool
    if (stratum_connect(&g_stratum) != 0) {
        fprintf(stderr, "Failed to connect to pool\n");
        return -1;
    }

    // Subscribe and authorize
    if (stratum_subscribe(&g_stratum) != 0 ||
        stratum_authorize(&g_stratum) != 0) {
        fprintf(stderr, "Failed to authenticate with pool\n");
        return -1;
    }

    // Wait for first job
    printf("Waiting for work from pool...\n");
    while (g_running && !g_stratum.hasJob) {
        stratum_poll(&g_stratum);
        sleep(1);
    }

    if (!g_stratum.hasJob) {
        fprintf(stderr, "No job received\n");
        return -1;
    }

    // Get N-factor from job timestamp
    uint8_t nfactor = get_nfactor(g_stratum.currentJob.nTime);
    printf("Current N-factor: %d\n", nfactor);

    // Initialize GPU miner
    uint32_t threads = config->threads;
    if (threads == 0) {
        // Auto-detect
        GPUDevice devices[8];
        int numDevices = enumerate_gpus(devices, 8);
        if (numDevices > config->deviceId) {
            size_t memPerThread = get_memory_per_thread(nfactor);
            size_t availMem = devices[config->deviceId].memory * 0.8;
            threads = availMem / memPerThread;
            if (threads > 65536) threads = 65536;
            if (threads < 256) threads = 256;
        } else {
            threads = 4096;  // Fallback
        }
    }

    printf("Starting miner with %u threads...\n", threads);
    if (miner_init_gpu(config->deviceId, nfactor, threads) != 0) {
        fprintf(stderr, "Failed to initialize GPU miner\n");
        return -1;
    }

    // Main loop
    time_t lastStatTime = time(NULL);
    uint64_t lastHashes = 0;
    uint32_t nonce = 0;

    while (g_running) {
        // Check for new jobs
        stratum_poll(&g_stratum);

        // Process current job
        MiningResult result;
        if (miner_process_job(&g_stratum.currentJob, &result) == 0) {
            if (result.found) {
                printf("*** SHARE FOUND! Nonce: %08x ***\n", result.nonce);
                stratum_submit(&g_stratum, &result);
            }
        }

        // Update stats periodically
        time_t now = time(NULL);
        if (now - lastStatTime >= 10) {
            miner_get_stats(&g_stats);
            double hashrate = (g_stats.totalHashes - lastHashes) / (double)(now - lastStatTime);

            printf("Hashrate: %.2f H/s | Shares: %lu/%lu | Uptime: %.0fs\n",
                   hashrate, g_stats.acceptedShares,
                   g_stats.acceptedShares + g_stats.rejectedShares,
                   g_stats.uptime);

            lastStatTime = now;
            lastHashes = g_stats.totalHashes;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    printf("YaCoin GPU Miner v%s\n", YACMINER_VERSION);
    printf("Scrypt-Jane (ChaCha20/8) with variable N-factor\n\n");

    // Parse arguments
    Config config;
    if (parse_args(argc, argv, &config) != 0) {
        print_usage(argv[0]);
        return 1;
    }

    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int result = 0;

    if (config.benchmark) {
        result = run_benchmark(&config);
    }
    else if (strlen(config.url) == 0) {
        fprintf(stderr, "Error: Pool URL required (-o)\n");
        print_usage(argv[0]);
        result = 1;
    }
    else if (strlen(config.user) == 0) {
        fprintf(stderr, "Error: Username/wallet required (-u)\n");
        print_usage(argv[0]);
        result = 1;
    }
    else {
        result = mining_loop(&config);
    }

    // Cleanup
    miner_shutdown();
    stratum_cleanup(&g_stratum);

    printf("Goodbye!\n");
    return result;
}
