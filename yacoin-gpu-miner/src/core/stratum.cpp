/*
 * YaCoin GPU Miner - Stratum Protocol Client Implementation
 */

#include "stratum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #define closesocket close
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

#include "json_minimal.h"

// Internal buffer for receiving data
#define RECV_BUFFER_SIZE 4096

static char recvBuffer[RECV_BUFFER_SIZE];
static int recvBufferLen = 0;

// JSON-RPC ID counter
static int rpcId = 1;

// Helper: Parse URL into host/port
static int parse_url(const char *url, char *host, int *port, bool *useTLS)
{
    *useTLS = false;
    *port = 3333;  // Default stratum port

    const char *p = url;

    // Check protocol
    if (strncmp(p, "stratum+ssl://", 14) == 0) {
        *useTLS = true;
        p += 14;
    } else if (strncmp(p, "stratum+tcp://", 14) == 0) {
        p += 14;
    } else if (strncmp(p, "stratum://", 10) == 0) {
        p += 10;
    }

    // Find port separator
    const char *colon = strchr(p, ':');
    if (colon) {
        size_t hostLen = colon - p;
        strncpy(host, p, hostLen);
        host[hostLen] = '\0';
        *port = atoi(colon + 1);
    } else {
        strcpy(host, p);
    }

    return 0;
}

// Helper: Send JSON-RPC request
static int send_json(StratumClient *client, const char *method, const char *params)
{
    char buffer[1024];
    int len = snprintf(buffer, sizeof(buffer),
        "{\"id\":%d,\"method\":\"%s\",\"params\":%s}\n",
        rpcId++, method, params);

    int sent = send(client->socket, buffer, len, 0);
    if (sent != len) {
        fprintf(stderr, "Stratum: Failed to send: %s\n", strerror(errno));
        return -1;
    }

    printf("Stratum TX: %s", buffer);
    return 0;
}

// Message buffer for received JSON
static char msgBuffer[RECV_BUFFER_SIZE];

// Helper: Receive JSON response (returns pointer to static buffer or NULL)
static const char* recv_json(StratumClient *client)
{
    // Receive more data if needed
    int received = recv(client->socket, recvBuffer + recvBufferLen,
                        RECV_BUFFER_SIZE - recvBufferLen - 1, 0);
    if (received > 0) {
        recvBufferLen += received;
        recvBuffer[recvBufferLen] = '\0';
    }

    // Look for newline (end of JSON message)
    char *newline = strchr(recvBuffer, '\n');
    if (!newline) {
        return NULL;  // No complete message yet
    }

    // Extract message
    size_t msgLen = newline - recvBuffer;
    strncpy(msgBuffer, recvBuffer, msgLen);
    msgBuffer[msgLen] = '\0';

    // Shift buffer
    memmove(recvBuffer, newline + 1, recvBufferLen - msgLen - 1);
    recvBufferLen -= (int)(msgLen + 1);

    printf("Stratum RX: %s\n", msgBuffer);

    return msgBuffer;
}

// Helper: Parse mining.notify parameters into MiningJob
static int parse_notify(StratumClient *client, const char *params)
{
    int arrayLen = json_array_length(params);
    if (arrayLen < 8) {
        return -1;
    }

    MiningJob *job = &client->currentJob;

    // params[0] = job_id
    char jobId[64];
    if (json_array_get_string(params, 0, jobId, sizeof(jobId)) == 0) {
        strncpy(job->jobId, jobId, sizeof(job->jobId) - 1);
    }

    // params[1] = prevhash (hex)
    // Convert hex to bytes (implementation needed)

    // params[2] = coinbase1
    // params[3] = coinbase2
    // params[4] = merkle_branch (array)
    // params[5] = version
    // params[6] = nbits
    char nBits[32];
    if (json_array_get_string(params, 6, nBits, sizeof(nBits)) == 0) {
        job->nBits = strtoul(nBits, NULL, 16);
    }

    // params[7] = ntime
    char nTime[32];
    if (json_array_get_string(params, 7, nTime, sizeof(nTime)) == 0) {
        job->nTime = strtoul(nTime, NULL, 16);
    }

    // params[8] = clean_jobs
    int cleanJobs = 0;
    if (json_array_get_bool(params, 8, &cleanJobs) == 0) {
        job->cleanJobs = cleanJobs ? true : false;
    }

    client->hasJob = true;
    return 0;
}

// Initialize stratum client
int stratum_init(StratumClient *client, const StratumConfig *config)
{
    memset(client, 0, sizeof(StratumClient));
    memcpy(&client->config, config, sizeof(StratumConfig));
    client->state = STRATUM_DISCONNECTED;
    client->socket = INVALID_SOCKET;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Stratum: WSAStartup failed\n");
        return -1;
    }
#endif

    return 0;
}

// Connect to pool
int stratum_connect(StratumClient *client)
{
    char host[256];
    int port;
    bool useTLS;

    if (parse_url(client->config.url, host, &port, &useTLS) != 0) {
        fprintf(stderr, "Stratum: Invalid URL\n");
        return -1;
    }

    printf("Stratum: Connecting to %s:%d...\n", host, port);
    client->state = STRATUM_CONNECTING;

    // Resolve hostname
    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "Stratum: Failed to resolve %s\n", host);
        return -1;
    }

    // Create socket
    client->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client->socket == INVALID_SOCKET) {
        fprintf(stderr, "Stratum: Failed to create socket\n");
        return -1;
    }

    // Connect
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(client->socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Stratum: Connection failed\n");
        closesocket(client->socket);
        client->socket = INVALID_SOCKET;
        return -1;
    }

    printf("Stratum: Connected!\n");
    return 0;
}

// Subscribe to mining notifications
int stratum_subscribe(StratumClient *client)
{
    client->state = STRATUM_SUBSCRIBING;

    // Send mining.subscribe
    if (send_json(client, "mining.subscribe", "[\"scptminer/1.0.0\"]") != 0) {
        return -1;
    }

    // Wait for response
    const char *response = NULL;
    while (!response) {
        response = recv_json(client);
    }

    // Parse response - find "result" array
    const char *result = json_find_key(response, "result");
    if (result) {
        // result[1] = extranonce1
        // result[2] = extranonce2_size
        char extraNonce1[64];
        int extraNonce2Size = 0;

        if (json_array_get_string(result, 1, extraNonce1, sizeof(extraNonce1)) == 0) {
            strncpy(client->extraNonce1, extraNonce1, sizeof(client->extraNonce1) - 1);
        }
        if (json_array_get_int(result, 2, &extraNonce2Size) == 0) {
            client->extraNonce2Size = extraNonce2Size;
        }

        printf("Stratum: Subscribed - extraNonce1=%s, extraNonce2Size=%d\n",
               client->extraNonce1, client->extraNonce2Size);
    }

    return 0;
}

// Authorize worker
int stratum_authorize(StratumClient *client)
{
    client->state = STRATUM_AUTHORIZING;

    char params[512];
    snprintf(params, sizeof(params), "[\"%s\",\"%s\"]",
             client->config.user, client->config.pass);

    if (send_json(client, "mining.authorize", params) != 0) {
        return -1;
    }

    // Wait for response
    const char *response = NULL;
    while (!response) {
        response = recv_json(client);
    }

    // Check result
    int result = 0;
    if (json_get_bool(response, "result", &result) == 0) {
        if (result) {
            printf("Stratum: Authorized as %s\n", client->config.user);
            client->state = STRATUM_MINING;
        } else {
            fprintf(stderr, "Stratum: Authorization failed\n");
            return -1;
        }
    }

    return 0;
}

// Poll for new jobs (non-blocking)
int stratum_poll(StratumClient *client)
{
    // Set socket to non-blocking temporarily
    // (platform-specific implementation)

    const char *msg = recv_json(client);
    if (!msg) {
        return 0;  // No message
    }

    // Check if it's a notification
    char methodStr[64];
    if (json_get_string(msg, "method", methodStr, sizeof(methodStr)) == 0) {
        if (strcmp(methodStr, "mining.notify") == 0) {
            const char *params = json_find_key(msg, "params");
            if (params) {
                parse_notify(client, params);
                printf("Stratum: New job %s\n", client->currentJob.jobId);
            }
        } else if (strcmp(methodStr, "mining.set_difficulty") == 0) {
            const char *params = json_find_key(msg, "params");
            if (params) {
                double diff = 0;
                json_array_get_double(params, 0, &diff);
                printf("Stratum: Difficulty set to %.4f\n", diff);
            }
        }
    }

    return client->hasJob ? 1 : 0;
}

// Submit share
int stratum_submit(StratumClient *client, const MiningResult *result)
{
    char params[512];
    snprintf(params, sizeof(params),
        "[\"%s\",\"%s\",\"%s\",\"%08x\",\"%08x\"]",
        client->config.user,
        result->jobId,
        "0000",  // extranonce2
        client->currentJob.nTime,
        (uint32_t)result->nonce);

    if (send_json(client, "mining.submit", params) != 0) {
        return -1;
    }

    client->sharesSent++;

    // Wait for response
    const char *response = NULL;
    while (!response) {
        response = recv_json(client);
    }

    int resultVal = 0;
    if (json_get_bool(response, "result", &resultVal) == 0) {
        if (resultVal) {
            client->sharesAccepted++;
            printf("Stratum: Share accepted! (%lu/%lu)\n",
                   (unsigned long)client->sharesAccepted, (unsigned long)client->sharesSent);
        } else {
            client->sharesRejected++;
            printf("Stratum: Share rejected! (%lu rejected)\n",
                   (unsigned long)client->sharesRejected);
        }
    }

    return 0;
}

// Disconnect
void stratum_disconnect(StratumClient *client)
{
    if (client->socket != INVALID_SOCKET) {
        closesocket(client->socket);
        client->socket = INVALID_SOCKET;
    }
    client->state = STRATUM_DISCONNECTED;
    client->hasJob = false;
}

// Cleanup
void stratum_cleanup(StratumClient *client)
{
    stratum_disconnect(client);
#ifdef _WIN32
    WSACleanup();
#endif
}

// Get connection state string
const char* stratum_state_str(StratumState state)
{
    switch (state) {
        case STRATUM_DISCONNECTED: return "Disconnected";
        case STRATUM_CONNECTING:   return "Connecting";
        case STRATUM_SUBSCRIBING:  return "Subscribing";
        case STRATUM_AUTHORIZING:  return "Authorizing";
        case STRATUM_MINING:       return "Mining";
        default:                   return "Unknown";
    }
}
