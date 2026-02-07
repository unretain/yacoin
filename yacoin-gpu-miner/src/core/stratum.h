/*
 * YaCoin GPU Miner - Stratum Protocol Client
 */

#ifndef STRATUM_H
#define STRATUM_H

#include <stdint.h>
#include <stdbool.h>
#include "miner.h"

#ifdef __cplusplus
extern "C" {
#endif

// Stratum connection states
typedef enum {
    STRATUM_DISCONNECTED,
    STRATUM_CONNECTING,
    STRATUM_SUBSCRIBING,
    STRATUM_AUTHORIZING,
    STRATUM_MINING
} StratumState;

// Stratum client configuration
typedef struct {
    char     url[256];
    char     user[256];
    char     pass[256];
    int      port;
    bool     useTLS;
} StratumConfig;

// Stratum client context
typedef struct {
    StratumConfig config;
    StratumState  state;
    int           socket;
    char          sessionId[64];
    char          extraNonce1[16];
    int           extraNonce2Size;
    MiningJob     currentJob;
    bool          hasJob;
    uint64_t      sharesSent;
    uint64_t      sharesAccepted;
    uint64_t      sharesRejected;
} StratumClient;

// Initialize stratum client
int stratum_init(StratumClient *client, const StratumConfig *config);

// Connect to pool
int stratum_connect(StratumClient *client);

// Subscribe to mining notifications
int stratum_subscribe(StratumClient *client);

// Authorize worker
int stratum_authorize(StratumClient *client);

// Poll for new jobs (non-blocking)
int stratum_poll(StratumClient *client);

// Submit share
int stratum_submit(StratumClient *client, const MiningResult *result);

// Disconnect
void stratum_disconnect(StratumClient *client);

// Cleanup
void stratum_cleanup(StratumClient *client);

// Get connection state string
const char* stratum_state_str(StratumState state);

#ifdef __cplusplus
}
#endif

#endif // STRATUM_H
